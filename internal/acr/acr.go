// Package acr pushes assembled images to Azure Container Registry.
package acr

import "context"

// Pusher uploads a local OCI layout to a target registry reference.
type Pusher interface {
	Push(ctx context.Context, ociPath, target string) error
}
