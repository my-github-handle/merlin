package staging

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Assemble writes the staged blobs into a valid OCI image layout under
// scratchDir/oci (consumable by `trivy image --input`) and extracts the layered
// root filesystem into scratchDir/rootfs (for the base-image os-release check).
//
// A real Docker/OCI push references a JSON config blob plus tar+gzip filesystem
// layers. The config is placed in the OCI layout verbatim and is NOT tar-
// extracted; each layer is gunzipped (if gzip-compressed) before tar extraction.
func (s *Store) Assemble(ctx context.Context, mr ManifestRef, scratchDir string) (policy.StagedImage, error) {
	ociPath := filepath.Join(scratchDir, "oci")
	rootfs := filepath.Join(scratchDir, "rootfs")
	for _, d := range []string{ociPath, rootfs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return policy.StagedImage{}, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// The config blob (when present) goes into the OCI layout verbatim — it is
	// JSON, not a filesystem layer, so it must never be tar-extracted.
	if mr.ConfigDigest != "" {
		raw, err := s.fetchVerified(ctx, mr.ConfigDigest)
		if err != nil {
			return policy.StagedImage{}, err
		}
		if err := writeOCIBlob(ociPath, mr.ConfigDigest, raw); err != nil {
			return policy.StagedImage{}, err
		}
	}

	// Write each layer blob into the OCI layout and extract it into rootfs.
	for _, dg := range mr.LayerDigests {
		raw, err := s.fetchVerified(ctx, dg)
		if err != nil {
			return policy.StagedImage{}, err
		}
		// Persist the layer into the OCI layout's blobs/sha256 dir (verbatim,
		// still compressed — the layout records the compressed-blob digest).
		if err := writeOCIBlob(ociPath, dg, raw); err != nil {
			return policy.StagedImage{}, err
		}
		// Decompress gzip layers before tar extraction (real layers are tar+gzip).
		tarBytes, err := maybeGunzip(raw)
		if err != nil {
			return policy.StagedImage{}, fmt.Errorf("decompress layer %s: %w", dg, err)
		}
		if err := extractTar(tarBytes, rootfs); err != nil {
			return policy.StagedImage{}, fmt.Errorf("extract layer %s: %w", dg, err)
		}
	}

	// Persist the manifest as an OCI blob and reference it from index.json, so
	// the directory is a valid OCI image layout.
	manifestDigest, err := sha256Digest(mr.Manifest)
	if err != nil {
		return policy.StagedImage{}, err
	}
	if err := writeOCIBlob(ociPath, manifestDigest, mr.Manifest); err != nil {
		return policy.StagedImage{}, err
	}
	if err := writeOCILayout(ociPath, manifestDigest, len(mr.Manifest), mr.Ref, manifestMediaType(mr.Manifest)); err != nil {
		return policy.StagedImage{}, err
	}

	return policy.StagedImage{
		Repo:    mr.Repo,
		Tag:     mr.Ref,
		OCIPath: ociPath,
		FSPath:  rootfs,
	}, nil
}

// fetchVerified reads a staged blob and re-verifies its digest. With the shared
// Azure backend a blob could be corrupted or overwritten between CompleteBlob
// and Assemble, so the digest is checked again here.
func (s *Store) fetchVerified(ctx context.Context, digest string) ([]byte, error) {
	rc, err := s.blobs.Get(ctx, blobKey(digest))
	if err != nil {
		return nil, fmt.Errorf("get blob %s: %w", digest, err)
	}
	raw, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("read blob %s: %w", digest, err)
	}
	if err := VerifyDigest(bytes.NewReader(raw), digest); err != nil {
		return nil, fmt.Errorf("assemble: blob %s failed digest re-verification: %w", digest, err)
	}
	return raw, nil
}

// maybeGunzip decompresses raw if it is gzip-compressed (magic bytes 0x1f 0x8b),
// otherwise returns it unchanged. Docker layers are typically tar+gzip, but
// uncompressed tar layers are also valid.
func maybeGunzip(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return raw, nil
	}
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// sha256Digest returns the "sha256:<hex>" digest of b.
func sha256Digest(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// manifestMediaType extracts the manifest's declared mediaType, defaulting to the
// OCI image manifest type when absent. The index descriptor MUST carry the actual
// type (Docker schema 2 vs OCI) or go-containerregistry pushes the manifest under
// the wrong Content-Type and the registry rejects it with MANIFEST_INVALID.
func manifestMediaType(manifest []byte) string {
	var m struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(manifest, &m); err == nil && m.MediaType != "" {
		return m.MediaType
	}
	return "application/vnd.oci.image.manifest.v1+json"
}

// writeOCILayout writes the oci-layout marker and an index.json referencing the
// image manifest, completing a minimal valid OCI image layout. manifestMediaType
// is the descriptor media type for the referenced manifest.
func writeOCILayout(ociPath, manifestDigest string, manifestSize int, ref, manifestMediaType string) error {
	if err := os.WriteFile(filepath.Join(ociPath, "oci-layout"),
		[]byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		return fmt.Errorf("write oci-layout: %w", err)
	}
	index := map[string]any{
		"schemaVersion": 2,
		"manifests": []map[string]any{{
			"mediaType": manifestMediaType,
			"digest":    manifestDigest,
			"size":      manifestSize,
			"annotations": map[string]string{
				"org.opencontainers.image.ref.name": ref,
			},
		}},
	}
	raw, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("marshal index.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(ociPath, "index.json"), raw, 0o644); err != nil {
		return fmt.Errorf("write index.json: %w", err)
	}
	return nil
}

func writeOCIBlob(ociPath, digest string, raw []byte) error {
	dir := filepath.Join(ociPath, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir oci blobs: %w", err)
	}
	// digest is "sha256:<hex>"; file name is the hex part.
	name := digest
	if len(digest) > 7 && digest[:7] == "sha256:" {
		name = digest[7:]
	}
	return os.WriteFile(filepath.Join(dir, name), raw, 0o644)
}

func extractTar(raw []byte, dest string) error {
	tr := tar.NewReader(bytesReader(raw))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, filepath.Clean("/"+hdr.Name))
		// Explicit containment guard: ensure target stays within dest.
		cleanDest := filepath.Clean(dest)
		if target != cleanDest && !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry %q escapes extraction root", hdr.Name)
		}

		// Handle entry types intentionally: only reproduce directories and regular files.
		// Symlinks, hardlinks, and device nodes are skipped because the assembled rootfs
		// is only used for read-only policy scanning (os-release + Trivy), and reproducing
		// them would add escape surface.
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Skip symlinks and hardlinks intentionally.
		default:
			// Skip other special types (devices, FIFOs, etc.).
		}
	}
}

// Cleanup removes the scratch dir and staged blobs for a finished push.
func (s *Store) Cleanup(ctx context.Context, mr ManifestRef, scratchDir string) error {
	digests := append([]string{}, mr.LayerDigests...)
	if mr.ConfigDigest != "" {
		digests = append(digests, mr.ConfigDigest)
	}
	for _, dg := range digests {
		// Release this push's reference; delete the bytes only when no other push
		// still references the digest (content-addressed ref-counting). This avoids
		// a finished push deleting a blob a concurrent push still needs (TODO I-3).
		remaining, err := s.sessions.DecBlobRef(ctx, dg)
		if err != nil || remaining <= 0 {
			_ = s.blobs.Delete(ctx, blobKey(dg))
		}
	}
	return os.RemoveAll(scratchDir)
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
