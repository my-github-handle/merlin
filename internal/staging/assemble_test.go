package staging

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// makeLayerTar builds a tar layer containing etc/os-release with the given ID.
func makeLayerTar(t *testing.T, osID string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("ID=" + osID + "\n")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAssembleExtractsRootFS(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	layer := makeLayerTar(t, "rhel")
	dg := digestOf(layer)

	up, _ := s.BeginUpload(ctx, "repo")
	if err := s.CompleteBlob(ctx, up, dg, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), []string{dg})
	if err != nil {
		t.Fatal(err)
	}

	scratch := t.TempDir()
	img, err := s.Assemble(ctx, mr, scratch)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(img.FSPath, "etc", "os-release"))
	if err != nil {
		t.Fatalf("read assembled os-release: %v", err)
	}
	if string(got) != "ID=rhel\n" {
		t.Errorf("os-release = %q", got)
	}
	if img.OCIPath == "" {
		t.Error("OCIPath should be set")
	}
}
