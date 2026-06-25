// Package staging buffers in-flight push blobs and assembles complete images.
package staging

import (
	"context"
	"io"
)

// BlobStore stores opaque blob payloads keyed by an arbitrary string.
type BlobStore interface {
	Put(ctx context.Context, key string, r io.Reader) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// SessionStore tracks per-upload session state (offsets, completion).
type SessionStore interface {
	Begin(ctx context.Context, uploadID string) error
	// CompareAndSetOffset atomically advances the offset from expected to next.
	// Returns false if the current offset != expected (out-of-order chunk).
	CompareAndSetOffset(ctx context.Context, uploadID string, expected, next int64) (bool, error)
	MarkComplete(ctx context.Context, uploadID, digest string) error
	AllComplete(ctx context.Context, digests []string) (bool, error)
	Clear(ctx context.Context, uploadID string) error
	// IncBlobRef increments the reference count for a content digest (one per push
	// that completes it) and returns the new count.
	IncBlobRef(ctx context.Context, digest string) (int64, error)
	// DecBlobRef decrements the reference count for a content digest and returns
	// the remaining count. The caller deletes the blob bytes only when this hits 0,
	// so a finished push never removes a blob a concurrent push still needs.
	DecBlobRef(ctx context.Context, digest string) (int64, error)
}
