package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/merlin-gate/merlin/internal/acr"
	"github.com/merlin-gate/merlin/internal/policies/baseimage"
	"github.com/merlin-gate/merlin/internal/policies/trivy"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/merlin-gate/merlin/internal/router"
	"github.com/merlin-gate/merlin/internal/staging"
)

func layerWithOSID(t *testing.T, id string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	body := []byte("ID=" + id + "\n")
	_ = tw.WriteHeader(&tar.Header{Name: "etc/os-release", Mode: 0o644, Size: int64(len(body))})
	_, _ = tw.Write(body)
	_ = tw.Close()
	return b.Bytes()
}

func dg(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// buildGate assembles a handler with in-memory staging and a fake Trivy runner.
func buildGate(t *testing.T, trivyReport trivy.Report) (*Handler, *acr.FakePusher, *staging.Store) {
	t.Helper()
	n := 0
	st := staging.New(staging.NewMemoryBlobStore(), staging.NewMemorySessionStore(), func() string {
		n++
		return "u" + string(rune('0'+n))
	})
	tp := trivy.New(staticRunner{report: trivyReport}, "CRITICAL")
	bp := baseimage.New([]string{"rhel", "wolfi", "chainguard"})
	rt := router.New(policy.NewEngine(tp, bp))
	fp := &acr.FakePusher{}
	o := &Outcome{Pusher: fp, ReportBaseURL: "/reports"}
	h := NewHandler(fakeAuth{ok: true}, st, rt, o, "myreg.azurecr.io", nil)
	return h, fp, st
}

type staticRunner struct{ report trivy.Report }

func (s staticRunner) Scan(context.Context, string) (trivy.Report, error) { return s.report, nil }

// drivePush simulates docker's blob upload + manifest PUT against the handler,
// then assembles + gates in-process via a helper exposed for the test.
func TestPushGoodUBIForwarded(t *testing.T) {
	layer := layerWithOSID(t, "rhel")
	h, fp, st := buildGate(t, trivy.Report{}) // no findings
	ctx := context.Background()

	// Upload the layer through the staging store (handler upload path is thin).
	up, _ := st.BeginUpload(ctx, "app")
	if err := st.CompleteBlob(ctx, up, dg(layer), bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, err := st.PutManifest(ctx, "app", "v1", []byte(`{}`), []string{dg(layer)})
	if err != nil {
		t.Fatal(err)
	}
	img, err := st.Assemble(ctx, mr, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gotOSR, rerr := os.ReadFile(filepath.Join(img.FSPath, "etc", "os-release"))
	if rerr != nil {
		t.Fatalf("assembled rootfs missing os-release (Assemble did not extract the layer): %v", rerr)
	}
	if !strings.Contains(string(gotOSR), "ID=rhel") {
		t.Errorf("assembled os-release = %q, want it to contain ID=rhel", gotOSR)
	}
	req := router.GateRequest{Source: "docker", Image: img, Target: "myreg.azurecr.io/app:v1"}
	res, gateErr := h.router.Gate(ctx, req)
	d, _ := h.outcome.Apply(ctx, req, res, gateErr)
	if d.StatusCode != 201 {
		t.Errorf("status = %d, want 201 (summary=%q)", d.StatusCode, d.Summary)
	}
	if len(fp.Pushed) != 1 {
		t.Errorf("expected forward to ACR, pushed=%v", fp.Pushed)
	}
}

func TestPushCriticalCVERejected(t *testing.T) {
	layer := layerWithOSID(t, "rhel")
	report := trivy.Report{Findings: []policy.Finding{{CVE: "CVE-2024-1", Severity: "CRITICAL", Pkg: "openssl", Version: "1.1.1"}}}
	h, fp, st := buildGate(t, report)
	ctx := context.Background()
	up, err := st.BeginUpload(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteBlob(ctx, up, dg(layer), bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, err := st.PutManifest(ctx, "app", "v1", []byte(`{}`), []string{dg(layer)})
	if err != nil {
		t.Fatal(err)
	}
	img, err := st.Assemble(ctx, mr, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := router.GateRequest{Image: img, Target: "myreg.azurecr.io/app:v1"}
	res, gateErr := h.router.Gate(ctx, req)
	d, _ := h.outcome.Apply(ctx, req, res, gateErr)
	if d.StatusCode != 400 {
		t.Errorf("status = %d, want 400", d.StatusCode)
	}
	if len(fp.Pushed) != 0 {
		t.Error("must not forward a rejected image")
	}
}

func TestPushAlpineRejectedByBasePolicy(t *testing.T) {
	layer := layerWithOSID(t, "alpine")
	h, fp, st := buildGate(t, trivy.Report{})
	ctx := context.Background()
	up, err := st.BeginUpload(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteBlob(ctx, up, dg(layer), bytes.NewReader(layer)); err != nil {
		t.Fatal(err)
	}
	mr, err := st.PutManifest(ctx, "app", "v1", []byte(`{}`), []string{dg(layer)})
	if err != nil {
		t.Fatal(err)
	}
	img, err := st.Assemble(ctx, mr, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	req := router.GateRequest{Image: img, Target: "myreg.azurecr.io/app:v1"}
	res, gateErr := h.router.Gate(ctx, req)
	d, _ := h.outcome.Apply(ctx, req, res, gateErr)
	if d.StatusCode != 400 {
		t.Errorf("status = %d, want 400 (alpine base)", d.StatusCode)
	}
	if len(fp.Pushed) != 0 {
		t.Error("must not forward a non-approved base image")
	}
}
