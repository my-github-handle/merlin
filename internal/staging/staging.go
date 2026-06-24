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

// ManifestRef identifies a staged manifest and its referenced layers.
type ManifestRef struct {
	Repo         string
	Ref          string
	Manifest     []byte
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
	_ = s.blobs.Delete(ctx, uploadKey(uploadID))
	return nil
}

func (s *Store) PutManifest(ctx context.Context, repo, ref string, manifest []byte, layerDigests []string) (ManifestRef, error) {
	all, err := s.sessions.AllComplete(ctx, layerDigests)
	if err != nil {
		return ManifestRef{}, fmt.Errorf("check completeness: %w", err)
	}
	if !all {
		return ManifestRef{}, ErrIncompletePush
	}
	return ManifestRef{Repo: repo, Ref: ref, Manifest: manifest, LayerDigests: layerDigests}, nil
}
