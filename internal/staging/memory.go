package staging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
)

type memBlobStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

// NewMemoryBlobStore returns an in-memory BlobStore for tests.
func NewMemoryBlobStore() BlobStore {
	return &memBlobStore{data: make(map[string][]byte)}
}

func (m *memBlobStore) Put(_ context.Context, key string, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = b
	return nil
}

func (m *memBlobStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[key]
	if !ok {
		return nil, fmt.Errorf("blob %q not found", key)
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memBlobStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

type memSession struct {
	offset    int64
	completed map[string]bool
}

type memSessionStore struct {
	mu       sync.Mutex
	sessions map[string]*memSession
	complete map[string]bool  // global digest -> complete
	refs     map[string]int64 // global digest -> reference count
}

// NewMemorySessionStore returns an in-memory SessionStore for tests.
func NewMemorySessionStore() SessionStore {
	return &memSessionStore{
		sessions: make(map[string]*memSession),
		complete: make(map[string]bool),
		refs:     make(map[string]int64),
	}
}

func (m *memSessionStore) Begin(_ context.Context, uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[uploadID] = &memSession{completed: make(map[string]bool)}
	return nil
}

func (m *memSessionStore) CompareAndSetOffset(_ context.Context, uploadID string, expected, next int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[uploadID]
	if !ok {
		return false, fmt.Errorf("upload %q not found", uploadID)
	}
	if s.offset != expected {
		return false, nil
	}
	s.offset = next
	return true, nil
}

func (m *memSessionStore) MarkComplete(_ context.Context, uploadID, digest string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.complete[digest] = true
	return nil
}

func (m *memSessionStore) AllComplete(_ context.Context, digests []string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, d := range digests {
		if !m.complete[d] {
			return false, nil
		}
	}
	return true, nil
}

func (m *memSessionStore) Clear(_ context.Context, uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, uploadID)
	return nil
}

func (m *memSessionStore) IncBlobRef(_ context.Context, digest string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refs[digest]++
	return m.refs[digest], nil
}

func (m *memSessionStore) DecBlobRef(_ context.Context, digest string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refs[digest] > 0 {
		m.refs[digest]--
	}
	n := m.refs[digest]
	if n == 0 {
		delete(m.refs, digest)
	}
	return n, nil
}
