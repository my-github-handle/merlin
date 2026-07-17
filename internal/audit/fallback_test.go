package audit

import "testing"

// The report-by-ref lookups fall back to "newest push for the repo" when no exact
// match is found. That fallback is only correct for a DIGEST ref (a buildx/attested
// push records the image by digest, and the human tag lives only on the un-scanned
// index). For a TAG ref with no exact match, the fallback silently serves a
// different image's scan under the requested tag — a correctness bug on a security
// gate. refAllowsRepoFallback gates that behavior.
func TestRefAllowsRepoFallback(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want bool
	}{
		{name: "digest ref allows fallback", ref: "sha256:abc123", want: true},
		{name: "plain tag does not allow fallback", ref: "2.19.6-r3-202607161139", want: false},
		{name: "semver tag does not allow fallback", ref: "v1", want: false},
		{name: "empty ref does not allow fallback", ref: "", want: false},
		{name: "tag that merely contains sha256 substring does not allow fallback", ref: "sha256-flavored", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := refAllowsRepoFallback(tt.ref); got != tt.want {
				t.Errorf("refAllowsRepoFallback(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}
