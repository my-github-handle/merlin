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
