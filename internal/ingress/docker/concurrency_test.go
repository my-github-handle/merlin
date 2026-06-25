package docker

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

// TestConcurrentManifestPushesNoRace fires many manifest PUTs concurrently
// through ONE shared handler (shared Outcome, shared trivy.Policy, Pool size 4)
// and asserts each response matches its OWN expected outcome.
//
// "good" repos push a UBI (rhel) layer → the base-image policy passes and the
// scan is clean → expect 201 + ACR push. "bad" repos push an alpine layer →
// the base-image policy rejects it → expect 400 and NO push.
//
// Before the request-local refactor, Outcome.last and trivy.Policy.lastReport
// were shared singleton fields written per request, so under concurrency one
// request could read another request's decision/findings — the -race detector
// fires and statuses cross. After the fix, decisions and findings flow back
// through the call stack, so this is clean under -race.
// layerWithOSIDUnique builds a layer whose os-release carries the given OS ID
// plus a per-request unique marker, so each request's layer has a distinct
// content digest (and thus a distinct shared-blob key).
func layerWithOSIDUnique(t *testing.T, id string, uniq int) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	body := []byte(fmt.Sprintf("ID=%s\nMERLIN_TEST_UNIQ=%d\n", id, uniq))
	_ = tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	return b.Bytes()
}

func TestConcurrentManifestPushesNoRace(t *testing.T) {
	n := 0
	var nameMu sync.Mutex
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), func() string {
		nameMu.Lock()
		defer nameMu.Unlock()
		n++
		return fmt.Sprintf("u%d", n)
	})
	// Clean trivy report for all images; the verdict difference comes from the
	// base-image policy so we can map repo -> expected status deterministically.
	tp := trivy.New(staticRunner{report: trivy.Report{DBVersion: "db-test"}}, "CRITICAL")
	bp := baseimage.New([]string{"rhel", "wolfi", "chainguard"})
	rt := router.New(policy.NewEngine(tp, bp))
	pool := router.NewPool(rt, 4)
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp, ReportBaseURL: "/reports"}
	h := NewHandler(fakeAuth{ok: true}, st, rt, o, "myreg.azurecr.io", nil)
	h.SetPool(pool)
	h.SetGateTimeout(10 * time.Second)

	const total = 16 // 8 good + 8 bad, interleaved
	type expect struct {
		repo       string
		wantStatus int
	}
	cases := make([]expect, total)
	for i := 0; i < total; i++ {
		if i%2 == 0 {
			cases[i] = expect{repo: fmt.Sprintf("good%d", i), wantStatus: http.StatusCreated}
		} else {
			cases[i] = expect{repo: fmt.Sprintf("bad%d", i), wantStatus: http.StatusBadRequest}
		}
	}

	// Pre-upload all layers (serially) so the concurrent section only gates.
	// Each request gets a layer with a DISTINCT digest (unique marker line) so
	// that one finished request's blob Cleanup cannot remove a blob another
	// concurrent request still needs to Assemble. The os-release ID (rhel vs
	// alpine) determines the expected verdict.
	digests := make([]string, total)
	for i, c := range cases {
		osID := "alpine"
		if c.wantStatus == http.StatusCreated {
			osID = "rhel"
		}
		layer := layerWithOSIDUnique(t, osID, i)
		digests[i] = uploadLayer(t, h, c.repo, layer)
	}

	type result struct {
		idx    int
		status int
	}
	results := make([]result, total)
	var wg sync.WaitGroup
	for i, c := range cases {
		wg.Add(1)
		go func(i int, c expect) {
			defer wg.Done()
			manifest := map[string]interface{}{
				"schemaVersion": 2,
				"config":        map[string]interface{}{"digest": digests[i]},
				"layers":        []map[string]interface{}{{"digest": digests[i]}},
			}
			manifestBytes, _ := json.Marshal(manifest)
			req := httptest.NewRequest(http.MethodPut, "/v2/"+c.repo+"/manifests/v1", bytes.NewReader(manifestBytes))
			req.Header.Set("Authorization", "Bearer good")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			results[i] = result{idx: i, status: rec.Code}
		}(i, c)
	}
	wg.Wait()

	// Each response must match its OWN expected outcome.
	goodCount := 0
	for i, c := range cases {
		if results[i].status != c.wantStatus {
			t.Errorf("repo %q: status = %d, want %d (verdict crossed requests?)", c.repo, results[i].status, c.wantStatus)
		}
		if c.wantStatus == http.StatusCreated {
			goodCount++
		}
	}
	// Exactly the good (UBI) images must have been pushed to ACR.
	if len(fp.Pushed) != goodCount {
		t.Errorf("ACR pushes = %d, want %d (only clean/approved images push)", len(fp.Pushed), goodCount)
	}
}
