// Package tenant maps an inbound request host to the ACR tenant that serves it.
package tenant

import (
	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/auth"
)

// Tenant bundles everything that was single-valued in the single-registry design:
// the resolved ACR host, its outbound push identity, and its inbound auth surface.
type Tenant struct {
	Prefix   string
	Registry string
	Pusher   acr.Pusher
	Authn    auth.Authenticator
}
