package staging

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestParseImageCreated(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    time.Time
		wantErr bool
	}{
		{
			name:   "rfc3339",
			config: `{"created":"2026-04-20T10:31:00Z","architecture":"amd64"}`,
			want:   time.Date(2026, 4, 20, 10, 31, 0, 0, time.UTC),
		},
		{
			name:   "rfc3339nano",
			config: `{"created":"2026-04-20T10:31:00.123456789Z"}`,
			want:   time.Date(2026, 4, 20, 10, 31, 0, 123456789, time.UTC),
		},
		{name: "missing created field", config: `{"architecture":"amd64"}`, wantErr: true},
		{name: "empty created", config: `{"created":""}`, wantErr: true},
		{name: "malformed json", config: `{not json`, wantErr: true},
		{name: "unparseable timestamp", config: `{"created":"not-a-time"}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseImageCreated([]byte(tt.config))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (time=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAssembleSetsCreated(t *testing.T) {
	created := "2026-05-01T12:00:00Z"
	config := []byte(`{"created":"` + created + `","architecture":"amd64","rootfs":{"type":"layers","diff_ids":[]}}`)
	cfgDigest := digestOf(config)

	store, mr, scratch := newAssembleFixture(t, config, cfgDigest)
	img, err := store.Assemble(context.Background(), mr, scratch)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	want := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	if !img.Created.Equal(want) {
		t.Fatalf("Created = %v, want %v", img.Created, want)
	}
}

// newAssembleFixture builds a minimal in-memory staging store with a config blob
// staged under the digest key that Assemble will read. Returns the store, a
// ManifestRef pointing to the config, and a scratch dir for assembly.
func newAssembleFixture(t *testing.T, config []byte, cfgDigest string) (*Store, ManifestRef, string) {
	t.Helper()
	s := newTestStore()
	ctx := context.Background()

	// Stage the config blob in the blob store using the standard upload flow
	// so it's available when Assemble calls fetchVerified.
	up, err := s.BeginUpload(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteBlob(ctx, up, cfgDigest, bytes.NewReader(config)); err != nil {
		t.Fatal(err)
	}

	// Build a ManifestRef with the config digest and no layers (minimal valid image).
	mr, err := s.PutManifest(ctx, "app", "v1", []byte(`{"schemaVersion":2}`), cfgDigest, []string{})
	if err != nil {
		t.Fatal(err)
	}

	return s, mr, t.TempDir()
}
