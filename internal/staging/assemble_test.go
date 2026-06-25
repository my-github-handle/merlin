package staging

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
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

// gzipBytes gzip-compresses raw, matching a real Docker tar+gzip layer.
func gzipBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestAssembleRealImageShape mirrors a real Docker push: a JSON config blob plus
// a gzip-compressed tar layer. The config must NOT be tar-extracted, the layer
// must be gunzipped before extraction, and the OCI layout must be valid.
func TestAssembleRealImageShape(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()

	config := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`)
	configDg := digestOf(config)
	layer := gzipBytes(t, makeLayerTar(t, "rhel"))
	layerDg := digestOf(layer)
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)

	for _, b := range [][]byte{config, layer} {
		up, _ := s.BeginUpload(ctx, "repo")
		if err := s.CompleteBlob(ctx, up, digestOf(b), bytes.NewReader(b)); err != nil {
			t.Fatal(err)
		}
	}

	mr, err := s.PutManifest(ctx, "repo", "v1", manifest, configDg, []string{layerDg})
	if err != nil {
		t.Fatalf("put manifest: %v", err)
	}

	scratch := t.TempDir()
	img, err := s.Assemble(ctx, mr, scratch)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	// rootfs: the gzip layer must be decompressed and extracted.
	got, err := os.ReadFile(filepath.Join(img.FSPath, "etc", "os-release"))
	if err != nil {
		t.Fatalf("read os-release from gunzipped layer: %v", err)
	}
	if string(got) != "ID=rhel\n" {
		t.Errorf("os-release = %q, want ID=rhel", got)
	}

	// OCI layout: oci-layout marker, index.json, and all three blobs present.
	if b, err := os.ReadFile(filepath.Join(img.OCIPath, "oci-layout")); err != nil {
		t.Errorf("missing oci-layout: %v", err)
	} else if !bytes.Contains(b, []byte("imageLayoutVersion")) {
		t.Errorf("oci-layout = %q", b)
	}

	idxRaw, err := os.ReadFile(filepath.Join(img.OCIPath, "index.json"))
	if err != nil {
		t.Fatalf("missing index.json: %v", err)
	}
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		t.Fatalf("index.json invalid: %v", err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("index.json manifests = %d, want 1", len(idx.Manifests))
	}
	wantManifestDg := digestOf(manifest)
	if idx.Manifests[0].Digest != wantManifestDg {
		t.Errorf("index manifest digest = %q, want %q", idx.Manifests[0].Digest, wantManifestDg)
	}

	// config, layer, and manifest blobs must all be in blobs/sha256/<hex>.
	for _, dg := range []string{configDg, layerDg, wantManifestDg} {
		hex := dg[len("sha256:"):]
		if _, err := os.Stat(filepath.Join(img.OCIPath, "blobs", "sha256", hex)); err != nil {
			t.Errorf("missing OCI blob %s: %v", dg, err)
		}
	}
}

// TestAssembleIndexUsesManifestMediaType verifies the OCI index descriptor's
// mediaType reflects the actual manifest media type (Docker schema 2 vs OCI), not
// a hardcoded value. A mismatch makes go-containerregistry push the manifest under
// the wrong Content-Type, and ACR rejects it with MANIFEST_INVALID.
func TestAssembleIndexUsesManifestMediaType(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()

	// A Docker schema 2 manifest (as produced by `docker push` of many base images).
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{},"layers":[]}`)
	layer := gzipBytes(t, makeLayerTar(t, "rhel"))
	up, _ := s.BeginUpload(ctx, "repo")
	if err := s.CompleteBlob(ctx, up, digestOf(layer), bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, err := s.PutManifest(ctx, "repo", "v1", manifest, "", []string{digestOf(layer)})
	if err != nil {
		t.Fatal(err)
	}
	img, err := s.Assemble(ctx, mr, t.TempDir())
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	idxRaw, err := os.ReadFile(filepath.Join(img.OCIPath, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx struct {
		Manifests []struct {
			MediaType string `json:"mediaType"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		t.Fatal(err)
	}
	want := "application/vnd.docker.distribution.manifest.v2+json"
	if len(idx.Manifests) != 1 || idx.Manifests[0].MediaType != want {
		t.Errorf("index mediaType = %v, want %q", idx.Manifests, want)
	}
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
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{dg})
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
	mr, _ := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{dg})
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
	mr, _ := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{digestOf(l1), digestOf(l2)})
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
	mr, _ := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{digestOf(layer)})
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
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{dg})
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

// TestCleanupSharedBlobNotDeletedWhileInUse reproduces the shared-blob cleanup
// race (TODO I-3): two pushes reference the same blob digest; when the first push
// cleans up, the blob must survive because the second push still needs it. Only
// when the last referencing push cleans up is the blob deleted.
func TestCleanupSharedBlobNotDeletedWhileInUse(t *testing.T) {
	s := newTestStore()
	ctx := context.Background()
	layer := makeLayerTar(t, "rhel")
	dgst := digestOf(layer)

	// Push A and push B both upload (complete) the SAME blob digest.
	upA, _ := s.BeginUpload(ctx, "repoA")
	if err := s.CompleteBlob(ctx, upA, dgst, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	upB, _ := s.BeginUpload(ctx, "repoB")
	if err := s.CompleteBlob(ctx, upB, dgst, bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}

	mrA, _ := s.PutManifest(ctx, "repoA", "v1", []byte(`{}`), "", []string{dgst})
	mrB, _ := s.PutManifest(ctx, "repoB", "v1", []byte(`{}`), "", []string{dgst})

	// Push A finishes and cleans up. The shared blob must STILL be assemblable by B.
	if err := s.Cleanup(ctx, mrA, t.TempDir()); err != nil {
		t.Fatalf("cleanup A: %v", err)
	}
	if _, err := s.Assemble(ctx, mrB, t.TempDir()); err != nil {
		t.Fatalf("push B must still assemble the shared blob after A cleaned up: %v", err)
	}

	// Now B cleans up too — last reference gone, blob may be deleted.
	if err := s.Cleanup(ctx, mrB, t.TempDir()); err != nil {
		t.Fatalf("cleanup B: %v", err)
	}
	// A fresh push referencing the digest without re-uploading must fail (blob gone).
	mrC, _ := s.PutManifest(ctx, "repoC", "v1", []byte(`{}`), "", []string{dgst})
	if _, err := s.Assemble(ctx, mrC, t.TempDir()); err == nil {
		t.Error("after the last referencing push cleaned up, the blob should be gone")
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
	mr, err := s.PutManifest(ctx, "repo", "v1", []byte(`{}`), "", []string{dg})
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
