package acr

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type acrPusher struct {
	registry string
	auth     authn.Authenticator
}

// NewACRPusher builds a Pusher targeting the given ACR registry host. In
// production the authenticator is backed by Azure Managed Identity; the default
// uses the ambient keychain.
func NewACRPusher(registry string) Pusher {
	return &acrPusher{registry: registry, auth: authn.Anonymous}
}

// NewACRPusherWithCredential builds a Pusher using DefaultAzureCredential
// (AKS Workload Identity federated token in production) to authenticate with ACR.
func NewACRPusherWithCredential(registry string) (Pusher, error) {
	if registry == "" {
		return nil, fmt.Errorf("acr: registry is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("acr default credential: %w", err)
	}
	return &acrPusher{registry: registry, auth: &acrCredAuthenticator{registry: registry, cred: cred}}, nil
}

func (p *acrPusher) Push(ctx context.Context, ociPath, target string) error {
	idx, err := layout.ImageIndexFromPath(ociPath)
	if err != nil {
		return fmt.Errorf("read oci layout: %w", err)
	}
	mfst, err := idx.IndexManifest()
	if err != nil {
		return fmt.Errorf("index manifest: %w", err)
	}
	ref, err := name.ParseReference(target)
	if err != nil {
		return fmt.Errorf("parse target %q: %w", target, err)
	}
	var img v1.Image
	for _, desc := range mfst.Manifests {
		if img, err = idx.Image(desc.Digest); err == nil {
			break
		}
	}
	if img == nil {
		return fmt.Errorf("no image in oci layout %s", ociPath)
	}
	return remote.Write(ref, img,
		remote.WithAuth(p.auth),
		remote.WithContext(ctx))
}

// rawManifest forwards a manifest (or index) to a registry verbatim, satisfying
// go-containerregistry's remote.Taggable (RawManifest) + withMediaType so the
// exact bytes — and thus the content digest — are preserved on the wire.
type rawManifest struct {
	raw       []byte
	mediaType types.MediaType
}

func (m rawManifest) RawManifest() ([]byte, error)        { return m.raw, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return m.mediaType, nil }

// PushManifest uploads a raw manifest/index verbatim. The referenced sub-manifests
// and blobs must already exist in the target registry (the registry rejects a
// manifest whose references are absent); for an image index this is what enforces
// gate ordering — a rejected image's manifest is never present, so its index PUT
// fails rather than publishing an ungated image by reference.
func (p *acrPusher) PushManifest(ctx context.Context, raw []byte, mediaType, target string) error {
	ref, err := name.ParseReference(target)
	if err != nil {
		return fmt.Errorf("parse target %q: %w", target, err)
	}
	mt := types.MediaType(mediaType)
	if mt == "" {
		mt = types.OCIManifestSchema1
	}
	return remote.Put(ref, rawManifest{raw: raw, mediaType: mt},
		remote.WithAuth(p.auth),
		remote.WithContext(ctx))
}

// PushBlob uploads a single content blob (config or layer) to repo, addressed by
// its content digest. static.NewLayer wraps the raw bytes so go-containerregistry
// uploads them verbatim; the registry verifies the digest. This seeds the blobs an
// attestation manifest references so the subsequent PushManifest can succeed.
func (p *acrPusher) PushBlob(ctx context.Context, raw []byte, mediaType, repo string) error {
	ref, err := name.ParseReference(repo)
	if err != nil {
		return fmt.Errorf("parse repo %q: %w", repo, err)
	}
	mt := types.MediaType(mediaType)
	if mt == "" {
		mt = types.OCILayer
	}
	return remote.WriteLayer(ref.Context(), static.NewLayer(raw, mt),
		remote.WithAuth(p.auth),
		remote.WithContext(ctx))
}
