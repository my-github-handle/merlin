package alert

import "testing"

func TestSignatureCollapsesPerPushNoise(t *testing.T) {
	// Each pair is two error_detail strings from DIFFERENT pushes that describe the
	// SAME failure. If they do not collapse to one signature, every push becomes its
	// own "novel" error and the novelty detector alerts on all of them.
	pairs := []struct {
		name string
		a, b string
	}{
		{
			name: "image digest",
			a:    "gate: scan sha256:9f2c1b0e5d4a3f6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d failed",
			b:    "gate: scan sha256:0011223344556677889900aabbccddeeff00112233445566778899aabbccddeeff failed",
		},
		{
			name: "push id",
			a:    "promote 6f0d5c4b-3a29-4d18-9e07-1f2a3b4c5d6e: queue claim failed",
			b:    "promote 11112222-3333-4444-5555-666677778888: queue claim failed",
		},
		{
			name: "scratch dir",
			a:    "assemble image: open /tmp/merlin/merlin-assemble-2841937465/blobs: no such file or directory",
			b:    "assemble image: open /tmp/merlin/merlin-assemble-9917263540/blobs: no such file or directory",
		},
		{
			name: "attempt count",
			a:    "acr promotion abandoned after 3 attempts: connection refused",
			b:    "acr promotion abandoned after 7 attempts: connection refused",
		},
		{
			name: "registry url path carries repo and tag",
			a:    "PUT https://c3devops.azurecr.io/v2/team-a/api/manifests/v1.2.3: MANIFEST_INVALID",
			b:    "PUT https://c3devops.azurecr.io/v2/team-b/worker/manifests/latest: MANIFEST_INVALID",
		},
		{
			name: "byte counts and durations",
			a:    "upload exceeded budget: 1073741824 bytes after 12.418s",
			b:    "upload exceeded budget: 536870912 bytes after 3.902s",
		},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			sa, sb := Signature(p.a), Signature(p.b)
			if sa != sb {
				t.Errorf("same failure produced two signatures:\n  %q\n  %q", sa, sb)
			}
			if sa == "" {
				t.Error("signature is empty")
			}
		})
	}
}

func TestSignatureKeepsDiagnosticTokens(t *testing.T) {
	// The opposite failure mode: normalizing so hard that distinct causes merge, so
	// the detector reports "nothing new" while a new cause is in fact firing. Exit
	// status, signal name and HTTP status are exactly the tokens that separate an OOM
	// kill from a bad credential.
	distinct := []string{
		"run grype: signal: killed",
		"run grype: exit status 1",
		"run grype: exit status 2",
		"acr push: unexpected status 401",
		"acr push: unexpected status 404",
	}
	seen := make(map[string]string, len(distinct))
	for _, d := range distinct {
		sig := Signature(d)
		if prev, ok := seen[sig]; ok {
			t.Errorf("distinct causes collapsed to one signature %q:\n  %q\n  %q", sig, prev, d)
		}
		seen[sig] = d
	}
}

func TestSignatureIsStableAndBounded(t *testing.T) {
	const detail = "run grype: exit status 1: 1 error occurred: failed to catalog"
	if Signature(detail) != Signature(detail) {
		t.Fatal("Signature is not deterministic")
	}
	// A signature is a ClickHouse ORDER BY key and a Slack line; an unbounded one
	// would let a single pathological stderr dump define the table's row size.
	long := ""
	for len(long) < 4000 {
		long += "failed to resolve dependency graph for package alpha-beta-gamma; "
	}
	if got := len(Signature(long)); got > maxSignatureLen {
		t.Errorf("signature length %d exceeds cap %d", got, maxSignatureLen)
	}
}

func TestSignatureNormalizesWhitespaceAndEmpty(t *testing.T) {
	if got := Signature("  run grype:\n\texit status 1  "); got != "run grype: exit status 1" {
		t.Errorf("whitespace not normalized: %q", got)
	}
	if got := Signature("   "); got != "" {
		t.Errorf("blank detail should have no signature, got %q", got)
	}
}
