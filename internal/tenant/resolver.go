package tenant

import (
	"errors"
	"strings"
)

// ErrUnknownTenant is returned when a host's prefix matches no configured tenant.
var ErrUnknownTenant = errors.New("tenant: unknown registry prefix")

// Resolver maps a request host to its Tenant.
type Resolver interface {
	ForHost(host string) (*Tenant, error)
}

type staticResolver struct {
	baseDomain string
	byPrefix   map[string]*Tenant
}

// NewStaticResolver builds a Resolver from a prefix-keyed tenant map, fixed at startup.
func NewStaticResolver(baseDomain string, tenants map[string]*Tenant) Resolver {
	return &staticResolver{baseDomain: strings.ToLower(baseDomain), byPrefix: tenants}
}

func (s *staticResolver) ForHost(host string) (*Tenant, error) {
	prefix := PrefixFromHost(host, s.baseDomain)
	if prefix == "" {
		return nil, ErrUnknownTenant
	}
	t, ok := s.byPrefix[prefix]
	if !ok {
		return nil, ErrUnknownTenant
	}
	return t, nil
}

// PrefixFromHost extracts the single leading label of host relative to baseDomain.
// It lowercases, strips an optional ":port", and requires exactly "<label>.<baseDomain>".
// Returns "" when host is the bare base domain, has a different base, or has a
// multi-label prefix.
func PrefixFromHost(host, baseDomain string) string {
	host = strings.ToLower(host)
	baseDomain = strings.ToLower(baseDomain)
	if i := strings.IndexByte(host, ':'); i != -1 {
		host = host[:i]
	}
	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}
