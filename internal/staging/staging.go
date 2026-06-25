package staging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
)

var (
	ErrOutOfOrder     = errors.New("staging: out-of-order chunk")
	ErrIncompletePush = errors.New("staging: not all blobs complete")
)

// ManifestRef identifies a staged manifest and its referenced blobs. The config
// blob (JSON image config) is tracked separately from the filesystem layers
// because only layers are tar+gzip archives to be extracted into the rootfs; the
// config must be placed in the OCI layout verbatim, never tar-extracted.
type ManifestRef struct {
	Repo         string
	Ref          string
	Manifest     []byte
	ConfigDigest string
	LayerDigests []string
}

// Store orchestrates blob staging and image assembly.
type Store struct {
	blobs    BlobStore
	sessions SessionStore
	idgen    func() string
}

// New builds a Store over the given backends. idgen issues unique upload IDs.
func New(bs BlobStore, ss SessionStore, idgen func() string) *Store {
	return &Store{blobs: bs, sessions: ss, idgen: idgen}
}

func (s *Store) BeginUpload(ctx context.Context, _ string) (string, error) {
	id := s.idgen()
	if err := s.sessions.Begin(ctx, id); err != nil {
		return "", fmt.Errorf("begin upload: %w", err)
	}
	return id, nil
}

func uploadKey(uploadID string) string { return "upload/" + uploadID }
func blobKey(digest string) string     { return "blob/" + digest }

// WriteChunk appends a chunk to an in-progress upload at the given offset.
// Per the Docker v2 protocol (spec §9), chunked PATCH for a single upload is
// sequential with a single in-flight writer; the offset CAS serializes ordering,
// and the per-upload blob read-modify-write assumes that single-writer invariant.
// TODO(hardening): offset-addressed writes would remove the implicit assumption.
func (s *Store) WriteChunk(ctx context.Context, uploadID string, offset int64, r io.Reader) (int64, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("read chunk: %w", err)
	}
	next := offset + int64(len(buf))
	ok, err := s.sessions.CompareAndSetOffset(ctx, uploadID, offset, next)
	if err != nil {
		return 0, fmt.Errorf("offset cas: %w", err)
	}
	if !ok {
		return 0, ErrOutOfOrder
	}
	// Append to the in-progress upload blob.
	existing, err := s.readIfExists(ctx, uploadKey(uploadID))
	if err != nil {
		return 0, err
	}
	combined := append(existing, buf...)
	if err := s.blobs.Put(ctx, uploadKey(uploadID), bytes.NewReader(combined)); err != nil {
		return 0, fmt.Errorf("store chunk: %w", err)
	}
	return next, nil
}

func (s *Store) readIfExists(ctx context.Context, key string) ([]byte, error) {
	rc, err := s.blobs.Get(ctx, key)
	if err != nil {
		return nil, nil // treat missing as empty
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func (s *Store) CompleteBlob(ctx context.Context, uploadID, digest string, r io.Reader) error {
	// 1. Read optional final chunk from the completion PUT body
	finalChunk, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read final chunk: %w", err)
	}

	// 2. Append final chunk to accumulated staged data
	existing, err := s.readIfExists(ctx, uploadKey(uploadID))
	if err != nil {
		return err
	}
	accumulated := append(existing, finalChunk...)

	// 3. Verify the FULL accumulated data against claimed digest
	if err := VerifyDigest(bytes.NewReader(accumulated), digest); err != nil {
		return err
	}

	// 4. Store the verified accumulated data under the digest key
	if err := s.blobs.Put(ctx, blobKey(digest), bytes.NewReader(accumulated)); err != nil {
		return fmt.Errorf("store blob: %w", err)
	}

	// 5. Mark complete and clean up the temporary upload blob
	if err := s.sessions.MarkComplete(ctx, uploadID, digest); err != nil {
		return fmt.Errorf("mark complete: %w", err)
	}
	// 6. Reference-count the content blob: each completing push holds one reference
	// so a finished push's Cleanup cannot delete a blob a concurrent push (e.g. a
	// shared base layer, or the image + attestation of one buildx push) still needs.
	if _, err := s.sessions.IncBlobRef(ctx, digest); err != nil {
		return fmt.Errorf("inc blob ref: %w", err)
	}
	_ = s.blobs.Delete(ctx, uploadKey(uploadID))
	return nil
}

// PutManifest verifies all referenced blobs (config + layers) have completed
// staging, then returns the assembled ManifestRef. configDigest is the image
// config blob; layerDigests are the filesystem layers. configDigest may be empty
// for manifests that reference no config (e.g. test fixtures).
// GetStagedBlob returns the bytes of a completed blob by digest, re-verifying the
// digest. Used to forward an attestation manifest's referenced blobs (config +
// in-toto layers) to ACR before forwarding the manifest itself.
func (s *Store) GetStagedBlob(ctx context.Context, digest string) ([]byte, error) {
	return s.fetchVerified(ctx, digest)
}

func (s *Store) PutManifest(ctx context.Context, repo, ref string, manifest []byte, configDigest string, layerDigests []string) (ManifestRef, error) {
	required := layerDigests
	if configDigest != "" {
		required = append([]string{configDigest}, layerDigests...)
	}
	all, err := s.sessions.AllComplete(ctx, required)
	if err != nil {
		return ManifestRef{}, fmt.Errorf("check completeness: %w", err)
	}
	if !all {
		return ManifestRef{}, ErrIncompletePush
	}
	return ManifestRef{Repo: repo, Ref: ref, Manifest: manifest, ConfigDigest: configDigest, LayerDigests: layerDigests}, nil
}
