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
	if err := tw.WriteHeader(&tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
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

func TestAssembleContainsPathTraversal(t *testing.T) {
	// build a layer with an entry whose name attempts traversal
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("pwned")
	_ = tw.WriteHeader(&tar.Header{Name: "../../etc/evil", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	layer := buf.Bytes()
	dg := digestOf(layer)

	s := newTestStore()
	ctx := context.Background()
	up, _ := s.BeginUpload(ctx, "repo")
	if err := s.CompleteBlob(ctx, up, dg, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, _ := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), []string{dg})
	scratch := t.TempDir()
	img, err := s.Assemble(ctx, mr, scratch)
	if err != nil {
		// erroring on the suspicious entry is also acceptable; if so, that's a pass
		return
	}
	// If it didn't error, the file must be CONTAINED within rootfs, not at scratch/etc or higher.
	escaped := filepath.Join(scratch, "etc", "evil") // sibling of rootfs => escape
	if _, statErr := os.Stat(escaped); statErr == nil {
		t.Fatalf("path traversal escaped rootfs: wrote %s", escaped)
	}
	_ = img
}

func TestAssembleMultiLayerOrderingOverwrites(t *testing.T) {
	mk := func(content string) []byte {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		body := []byte(content)
		_ = tw.WriteHeader(&tar.Header{Name: "etc/os-release", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))})
		_, _ = tw.Write(body)
		_ = tw.Close()
		return b.Bytes()
	}
	l1 := mk("ID=first\n")
	l2 := mk("ID=second\n")
	s := newTestStore()
	ctx := context.Background()
	up1, _ := s.BeginUpload(ctx, "repo")
	_ = s.CompleteBlob(ctx, up1, digestOf(l1), bytes.NewReader(l1))
	up2, _ := s.BeginUpload(ctx, "repo")
	_ = s.CompleteBlob(ctx, up2, digestOf(l2), bytes.NewReader(l2))
	mr, _ := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), []string{digestOf(l1), digestOf(l2)})
	img, err := s.Assemble(ctx, mr, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(img.FSPath, "etc", "os-release"))
	if string(got) != "ID=second\n" {
		t.Errorf("later layer should overwrite; got %q", got)
	}
}

func TestAssembleSkipsSymlinkEntries(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	_ = tw.WriteHeader(&tar.Header{Name: "etc/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777})
	_ = tw.Close()
	layer := b.Bytes()
	s := newTestStore()
	ctx := context.Background()
	up, _ := s.BeginUpload(ctx, "repo")
	_ = s.CompleteBlob(ctx, up, digestOf(layer), bytes.NewReader(layer))
	mr, _ := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), []string{digestOf(layer)})
	img, err := s.Assemble(ctx, mr, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// the symlink must NOT exist as a symlink (we skip such entries)
	fi, statErr := os.Lstat(filepath.Join(img.FSPath, "etc", "link"))
	if statErr == nil && fi.Mode()&os.ModeSymlink != 0 {
		t.Error("symlink entry should not be reproduced as a symlink")
	}
}

func TestAssembleRejectsTamperedBlob(t *testing.T) {
	// Build the store manually so we hold a reference to the BlobStore for tampering.
	bs := NewMemoryBlobStore()
	ss := NewMemorySessionStore()
	n := 0
	s := New(bs, ss, func() string {
		n++
		return "upload-" + string(rune('0'+n))
	})
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

	// Tamper: overwrite the stored blob with different content under the same key.
	if err := bs.Put(ctx, blobKey(dg), bytes.NewReader([]byte("tampered-bytes"))); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Assemble(ctx, mr, t.TempDir()); err == nil {
		t.Fatal("assembly must reject a blob that no longer matches its digest")
	}
}

func TestCleanupRemovesScratchAndBlobs(t *testing.T) {
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
	if _, err := s.Assemble(ctx, mr, scratch); err != nil {
		t.Fatal(err)
	}
	// scratch/oci should now exist
	if _, err := os.Stat(filepath.Join(scratch, "oci")); err != nil {
		t.Fatalf("expected oci layout before cleanup: %v", err)
	}
	// Cleanup must remove the scratch dir.
	if err := s.Cleanup(ctx, mr, scratch); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Errorf("scratch dir should be removed after cleanup, stat err=%v", err)
	}
}
