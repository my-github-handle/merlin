package acr

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// acrPusher's three methods — Push, PushManifest, PushBlob — were at 0.0%: the whole
// publish half of the gate was covered only by the live E2E run against a real ACR. They
// are testable hermetically against go-containerregistry's own in-process registry, which
// is in a module this package already requires, so this adds no dependency and no network.
//
// The property worth the most here is the ordering one PushManifest's doc comment claims:
// an index PUT whose referenced manifests are absent must FAIL. That is what stops a
// rejected image from being published by reference, and until now nothing asserted it.

// testRegistry starts an in-process OCI registry and returns its host:port.
func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// ociLayoutWithImage writes a single-image OCI layout to a temp dir, as the assemble step
// produces, and returns the path plus the image.
func ociLayoutWithImage(t *testing.T) (string, v1.Image) {
	t.Helper()
	img, err := random.Image(256, 2)
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	dir := t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatalf("init layout: %v", err)
	}
	if err := p.AppendImage(img); err != nil {
		t.Fatalf("append image: %v", err)
	}
	return dir, img
}

// A push lands the image, and it is byte-identical: the digest the registry serves back
// must be the digest the gate scanned. Anything else means the gate approved one image and
// published another.
func TestPushPublishesTheLayoutImageByDigest(t *testing.T) {
	host := testRegistry(t)
	dir, img := ociLayoutWithImage(t)
	want, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	target := host + "/team/app:v1"
	if err := NewACRPusher(host).Push(context.Background(), dir, target); err != nil {
		t.Fatalf("Push: %v", err)
	}

	ref, err := name.ParseReference(target)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Get(ref)
	if err != nil {
		t.Fatalf("target not published: %v", err)
	}
	if desc.Digest != want {
		t.Errorf("published digest %s, want %s: the published image is not the scanned one", desc.Digest, want)
	}
}

func TestPushRejectsAnUnusableLayoutOrTarget(t *testing.T) {
	host := testRegistry(t)
	okDir, _ := ociLayoutWithImage(t)

	for _, tc := range []struct {
		name    string
		dir     string
		target  string
		wantErr string
	}{
		{
			name: "no layout at that path", dir: t.TempDir(),
			target: host + "/team/app:v1", wantErr: "read oci layout",
		},
		{
			name: "layout with no image in it", dir: emptyLayout(t),
			target: host + "/team/app:v1", wantErr: "no image in oci layout",
		},
		{
			name: "unparsable target", dir: okDir,
			target: "NOT A REF", wantErr: "parse target",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := NewACRPusher(host).Push(context.Background(), tc.dir, tc.target)
			if err == nil {
				t.Fatal("Push succeeded on an input it cannot publish")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q, so it does not say which input was wrong", err, tc.wantErr)
			}
		})
	}
}

// emptyLayout writes a valid OCI layout containing no images — what an assemble that
// filtered out every manifest leaves behind.
func emptyLayout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := layout.Write(dir, empty.Index); err != nil {
		t.Fatalf("init empty layout: %v", err)
	}
	return dir
}

// THE ordering property. An index referencing a manifest that was never pushed — which is
// exactly the state after the gate rejects the image an index points at — must fail its
// PUT. If the registry accepted it, a rejected image would be published by reference and
// the gate would have been bypassed without a single error anywhere.
func TestPushManifestRefusesAnIndexWhoseImageWasNeverPushed(t *testing.T) {
	host := testRegistry(t)
	idx, err := random.Index(256, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := idx.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	mt, err := idx.MediaType()
	if err != nil {
		t.Fatal(err)
	}

	err = NewACRPusher(host).PushManifest(context.Background(), raw, string(mt), host+"/team/app:v1")
	if err == nil {
		t.Fatal("an index whose sub-manifests are absent was accepted: a rejected image is now published by reference")
	}
}

// The same index succeeds once its images are present, and the bytes are preserved: the
// index digest a client computed locally must be the digest the registry stores, or
// `docker pull by digest` fails for a push that reported success.
func TestPushManifestPreservesTheIndexBytesOnceItsImagesExist(t *testing.T) {
	host := testRegistry(t)
	pusher := NewACRPusher(host)
	ctx := context.Background()

	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img})

	// The gate's own order: the image first, then the index that points at it.
	imgDigest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	imgRaw, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	imgMT, err := img.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	pushLayers(t, pusher, img, host+"/team/app")
	if err := pusher.PushManifest(ctx, imgRaw, string(imgMT), host+"/team/app@"+imgDigest.String()); err != nil {
		t.Fatalf("push sub-manifest: %v", err)
	}

	idxRaw, err := idx.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	idxMT, err := idx.MediaType()
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := idx.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := pusher.PushManifest(ctx, idxRaw, string(idxMT), host+"/team/app:v1"); err != nil {
		t.Fatalf("push index: %v", err)
	}

	ref, err := name.ParseReference(host + "/team/app:v1")
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Get(ref)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Digest != wantDigest {
		t.Errorf("stored index digest %s, want %s: the bytes were rewritten in flight", desc.Digest, wantDigest)
	}
}

// An empty media type defaults rather than failing. Callers forward whatever Content-Type
// the client sent, and Docker clients do omit it.
func TestPushManifestDefaultsAnEmptyMediaType(t *testing.T) {
	host := testRegistry(t)
	pusher := NewACRPusher(host)
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	pushLayers(t, pusher, img, host+"/team/app")
	raw, err := img.RawManifest()
	if err != nil {
		t.Fatal(err)
	}

	if err := pusher.PushManifest(context.Background(), raw, "", host+"/team/app:v1"); err != nil {
		t.Fatalf("PushManifest with no media type: %v", err)
	}
}

func TestPushManifestAndPushBlobRejectUnparsableTargets(t *testing.T) {
	pusher := NewACRPusher("localhost:1")
	ctx := context.Background()

	if err := pusher.PushManifest(ctx, []byte("{}"), "", "NOT A REF"); err == nil ||
		!strings.Contains(err.Error(), "parse target") {
		t.Errorf("PushManifest error = %v, want one naming the unparsable target", err)
	}
	if err := pusher.PushBlob(ctx, []byte("x"), "", "NOT A REF"); err == nil ||
		!strings.Contains(err.Error(), "parse repo") {
		t.Errorf("PushBlob error = %v, want one naming the unparsable repo", err)
	}
}

// A blob is addressed by its own content digest, not by the repo reference it was pushed
// under: this is what lets the attestation path seed blobs before the manifest that names
// them.
func TestPushBlobMakesTheBlobFetchableByItsDigest(t *testing.T) {
	host := testRegistry(t)
	raw := []byte(`{"schemaVersion":2,"note":"attestation config"}`)

	if err := NewACRPusher(host).PushBlob(context.Background(), raw, string(types.OCIConfigJSON), host+"/team/app"); err != nil {
		t.Fatalf("PushBlob: %v", err)
	}

	digest, _, err := v1.SHA256(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.NewDigest(host + "/team/app@" + digest.String())
	if err != nil {
		t.Fatal(err)
	}
	l, err := remote.Layer(ref)
	if err != nil {
		t.Fatalf("blob not fetchable by digest: %v", err)
	}
	got, err := l.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got != digest {
		t.Errorf("stored blob digest %s, want %s", got, digest)
	}
}

// pushLayers seeds an image's config and layers so a manifest referencing them is accepted.
func pushLayers(t *testing.T, p Pusher, img v1.Image, repo string) {
	t.Helper()
	cfg, err := img.RawConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PushBlob(context.Background(), cfg, string(types.OCIConfigJSON), repo); err != nil {
		t.Fatalf("push config blob: %v", err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, rc); err != nil {
			t.Fatalf("read layer %d: %v", i, err)
		}
		_ = rc.Close()
		if err := p.PushBlob(context.Background(), buf.Bytes(), string(types.OCILayer), repo); err != nil {
			t.Fatalf("push layer %d: %v", i, err)
		}
	}
}
