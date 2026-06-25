// Package acr pushes assembled images to Azure Container Registry.
package acr

import "context"

// Pusher uploads images and raw manifests to a target registry reference.
type Pusher interface {
	// Push uploads a gated image from a local OCI layout to target.
	Push(ctx context.Context, ociPath, target string) error
	// PushManifest uploads a raw manifest (or image index) verbatim to target,
	// preserving its exact bytes (and therefore its content digest). Used to
	// forward buildx attestation manifests and image indexes that carry no
	// scannable filesystem. mediaType is the manifest's own media type.
	PushManifest(ctx context.Context, raw []byte, mediaType, target string) error
	// PushBlob uploads a single content blob (config or layer) to repo, addressed
	// by its content digest. Used to seed the blobs an attestation manifest
	// references before PushManifest forwards the manifest itself. repo is the
	// registry repository (e.g. myacr.azurecr.io/app); mediaType is the blob's type.
	PushBlob(ctx context.Context, raw []byte, mediaType, repo string) error
}
