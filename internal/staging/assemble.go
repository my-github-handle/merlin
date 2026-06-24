package staging

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/merlin-gate/merlin/internal/policy"
)

// Assemble writes the staged blobs into an OCI layout under scratchDir/oci and
// extracts the layered root filesystem into scratchDir/rootfs.
func (s *Store) Assemble(ctx context.Context, mr ManifestRef, scratchDir string) (policy.StagedImage, error) {
	ociPath := filepath.Join(scratchDir, "oci")
	rootfs := filepath.Join(scratchDir, "rootfs")
	for _, d := range []string{ociPath, rootfs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return policy.StagedImage{}, fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	// Write each layer blob into the OCI layout and extract it into rootfs.
	for _, dg := range mr.LayerDigests {
		rc, err := s.blobs.Get(ctx, blobKey(dg))
		if err != nil {
			return policy.StagedImage{}, fmt.Errorf("get blob %s: %w", dg, err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return policy.StagedImage{}, fmt.Errorf("read blob %s: %w", dg, err)
		}
		// Re-verify the digest: with the shared Azure backend a blob could be
		// corrupted or overwritten between CompleteBlob and Assemble.
		if err := VerifyDigest(bytes.NewReader(raw), dg); err != nil {
			return policy.StagedImage{}, fmt.Errorf("assemble: layer %s failed digest re-verification: %w", dg, err)
		}
		// Persist the blob into the OCI layout's blobs/sha256 dir.
		if err := writeOCIBlob(ociPath, dg, raw); err != nil {
			return policy.StagedImage{}, err
		}
		if err := extractTar(raw, rootfs); err != nil {
			return policy.StagedImage{}, fmt.Errorf("extract layer %s: %w", dg, err)
		}
	}
	// Persist the manifest into the OCI layout.
	if err := os.WriteFile(filepath.Join(ociPath, "manifest.json"), mr.Manifest, 0o644); err != nil {
		return policy.StagedImage{}, fmt.Errorf("write manifest: %w", err)
	}
	return policy.StagedImage{
		Repo:    mr.Repo,
		Tag:     mr.Ref,
		OCIPath: ociPath,
		FSPath:  rootfs,
	}, nil
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
	for _, dg := range mr.LayerDigests {
		_ = s.blobs.Delete(ctx, blobKey(dg))
	}
	return os.RemoveAll(scratchDir)
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
