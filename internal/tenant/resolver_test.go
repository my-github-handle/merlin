package tenant

import (
	"errors"
	"testing"
)

func TestPrefixFromHost(t *testing.T) {
	cases := []struct{ host, base, want string }{
		{"c3dev.c3ci.cloud", "c3ci.cloud", "c3dev"},
		{"c3prod.c3ci.cloud:443", "c3ci.cloud", "c3prod"},
		{"C3DEV.C3CI.CLOUD", "c3ci.cloud", "c3dev"},
		{"x.c3ci.cloud", "C3CI.CLOUD", "x"},
		{"c3ci.cloud", "c3ci.cloud", ""},       // bare base domain, no prefix
		{"evil.example.com", "c3ci.cloud", ""}, // wrong base domain
		{"a.b.c3ci.cloud", "c3ci.cloud", ""},   // multi-label prefix not allowed
	}
	for _, c := range cases {
		if got := PrefixFromHost(c.host, c.base); got != c.want {
			t.Errorf("PrefixFromHost(%q,%q) = %q, want %q", c.host, c.base, got, c.want)
		}
	}
}

func TestStaticResolverForHost(t *testing.T) {
	dev := &Tenant{Prefix: "c3dev", Registry: "c3devacr.azurecr.io"}
	r := NewStaticResolver("c3ci.cloud", map[string]*Tenant{"c3dev": dev})

	got, err := r.ForHost("c3dev.c3ci.cloud")
	if err != nil {
		t.Fatalf("ForHost: %v", err)
	}
	if got != dev {
		t.Errorf("got %+v, want dev tenant", got)
	}

	if _, err := r.ForHost("c3prod.c3ci.cloud"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("unknown prefix err = %v, want ErrUnknownTenant", err)
	}
	if _, err := r.ForHost("c3ci.cloud"); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("bare base domain err = %v, want ErrUnknownTenant", err)
	}
}
