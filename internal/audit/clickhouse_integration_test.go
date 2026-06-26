//go:build integration

package audit

import (
	"context"
	"os"
	"testing"

	"github.com/merlin-gate/merlin/internal/policy"
)

func TestClickHouseReverseLookups(t *testing.T) {
	dsn := os.Getenv("MERLIN_CLICKHOUSE_DSN")
	if dsn == "" {
		t.Skip("set MERLIN_CLICKHOUSE_DSN to run")
	}
	w, err := NewClickHouseWriter(dsn, 30)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dec := Decision{PushID: "00000000-0000-0000-0000-000000000001", Repo: "app", Digest: "sha256:abc", Identity: "alice", Passed: false}
	if err := w.WriteDecision(ctx, dec); err != nil {
		t.Fatal(err)
	}
	finds := []policy.Finding{{CVE: "CVE-2024-1", Severity: "CRITICAL", Pkg: "openssl", Version: "1.1.1"}}
	if err := w.WriteFindings(ctx, dec, finds); err != nil {
		t.Fatal(err)
	}

	r := &Reader{conn: w.(*clickhouseWriter).conn}
	imgs, err := r.ImagesByCVE(ctx, "CVE-2024-1") // A
	if err != nil || len(imgs) == 0 {
		t.Fatalf("ImagesByCVE: imgs=%v err=%v", imgs, err)
	}
	if imgs[0] != dec.Digest {
		t.Errorf("ImagesByCVE returned %q, want digest %q (findings must carry image_digest)", imgs[0], dec.Digest)
	}
	decs, err := r.DecisionsByDigest(ctx, "sha256:abc") // B
	if err != nil || len(decs) == 0 {
		t.Errorf("DecisionsByDigest: decs=%v err=%v", decs, err)
	}
}
