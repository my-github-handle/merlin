package dashboard

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
)

func TestParseRangeFallback(t *testing.T) {
	now := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in   string
		want Range
		ago  time.Duration
	}{
		{"1d", Range1d, 24 * time.Hour},
		{"7d", Range7d, 7 * 24 * time.Hour},
		{"30d", Range30d, 30 * 24 * time.Hour},
		{"bogus", Range1d, 24 * time.Hour},
		{"", Range1d, 24 * time.Hour},
	} {
		gotR, gotSince := ParseRange(tc.in, now)
		if gotR != tc.want || !gotSince.Equal(now.Add(-tc.ago)) {
			t.Errorf("ParseRange(%q) = (%s,%v), want (%s,%v)", tc.in, gotR, gotSince, tc.want, now.Add(-tc.ago))
		}
	}
}

func TestPassRate(t *testing.T) {
	if got := PassRate(0, 0); got != 0 {
		t.Errorf("PassRate(0,0)=%v want 0", got)
	}
	if got := PassRate(78, 100); got != 78 {
		t.Errorf("PassRate(78,100)=%v want 78", got)
	}
}

type fakeReader struct {
	stats audit.DecisionStats
	cves  []audit.CVECount
	hdr   audit.DecisionHeader
	finds []policy.Finding
	err   error
}

func (f fakeReader) RecentDecisions(context.Context, int) ([]audit.DecisionSummary, error) {
	return []audit.DecisionSummary{{Repo: "a/b", Tag: "v1", Passed: true}}, f.err
}
func (f fakeReader) DecisionStatsSince(context.Context, time.Time) (audit.DecisionStats, error) {
	return f.stats, f.err
}
func (f fakeReader) TopCVEs(context.Context, time.Time, int) ([]audit.CVECount, error) {
	return f.cves, f.err
}
func (f fakeReader) TopPackages(context.Context, time.Time, int) ([]audit.LabeledCount, error) {
	return nil, f.err
}
func (f fakeReader) SeverityTotalsSince(context.Context, time.Time) (audit.SeverityTotals, error) {
	return audit.SeverityTotals{Critical: 1}, f.err
}
func (f fakeReader) FixAvailabilitySince(context.Context, time.Time, int) (audit.FixAvailability, error) {
	return audit.FixAvailability{BySeverity: []audit.FixAvailabilityRow{{Severity: "CRITICAL", Total: 2, Fixable: 1}}}, f.err
}
func (f fakeReader) BaseImagePosture(context.Context, time.Time) ([]audit.BaseImageStat, error) {
	return []audit.BaseImageStat{{BaseImageID: "ubi9", Total: 3, Passed: 2}}, f.err
}
func (f fakeReader) ByIdentity(context.Context, time.Time, int) ([]audit.IdentityStat, error) {
	return []audit.IdentityStat{{Identity: "ci", Total: 3, Passed: 3}}, f.err
}
func (f fakeReader) ByRepo(context.Context, time.Time, int) ([]audit.RepoStat, error) {
	return []audit.RepoStat{{Repo: "a/b", Total: 3, Passed: 2}}, f.err
}
func (f fakeReader) DecisionHeaderByRef(context.Context, string, string) (audit.DecisionHeader, error) {
	return f.hdr, f.err
}
func (f fakeReader) DecisionHeaderByPush(context.Context, string) (audit.DecisionHeader, error) {
	return f.hdr, f.err
}
func (f fakeReader) FindingsByPush(context.Context, string) ([]policy.Finding, error) {
	return f.finds, f.err
}
func (f fakeReader) FindingsByImageRef(context.Context, string, string) ([]policy.Finding, error) {
	return f.finds, f.err
}
func (f fakeReader) ImagesPage(_ context.Context, _ time.Time, _ audit.ImageFilter, limit, offset int) (audit.ImagePage, error) {
	if f.err != nil {
		return audit.ImagePage{}, f.err
	}
	return audit.ImagePage{
		Total: 1,
		Rows:  []audit.ImageRow{{Repo: "a/b", Tag: "v1", Identity: "ci", Passed: false, Crit: 1, High: 2}},
	}, nil
}

func newTestService(fr audit.DashboardReader) *Service {
	return newTestServiceWithMetrics(fr, true)
}

func newTestServiceWithMetrics(fr audit.DashboardReader, withMetrics bool) *Service {
	reg := prometheus.NewRegistry()
	if withMetrics {
		g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "merlin_trivy_db_age_days", Help: "x"})
		g.Set(4)
		reg.MustRegister(g)
		cOk := prometheus.NewCounter(prometheus.CounterOpts{Name: "merlin_acr_push_total", Help: "x", ConstLabels: prometheus.Labels{"result": "ok"}})
		cOk.Add(95)
		reg.MustRegister(cOk)
		cErr := prometheus.NewCounter(prometheus.CounterOpts{Name: "merlin_acr_push_total", Help: "x", ConstLabels: prometheus.Labels{"result": "error"}})
		cErr.Add(5)
		reg.MustRegister(cErr)
	}
	now := func() time.Time { return time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC) }
	return NewService(fr, reg, now)
}

func TestActivityViewModel(t *testing.T) {
	svc := newTestService(fakeReader{stats: audit.DecisionStats{Total: 10, Passed: 8, Rejected: 2}})
	vm, err := svc.Activity(context.Background(), Range1d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Stats.PassRate != 80 {
		t.Errorf("PassRate=%v want 80", vm.Stats.PassRate)
	}
	if len(vm.Recent) == 0 {
		t.Error("expected recent decisions")
	}
}

func TestReportViewModelNotFound(t *testing.T) {
	svc := newTestService(fakeReader{hdr: audit.DecisionHeader{Found: false}})
	vm, err := svc.Report(context.Background(), "a/b", "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Found {
		t.Error("expected Found=false for missing report")
	}
}

func TestReportViewModelWithFindings(t *testing.T) {
	hdr := audit.DecisionHeader{
		Found:          true,
		PushID:         "push123",
		Repo:           "a/b",
		Tag:            "v1",
		Digest:         "sha256:abc",
		Identity:       "ci",
		Passed:         false,
		FailedPolicies: []string{"cve-policy"},
		Reasons:        []string{"CRITICAL CVE found"},
		BaseImageID:    "ubi9",
		TrivyDBVersion: "2.0",
		Ts:             time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC),
	}
	findings := []policy.Finding{
		{CVE: "CVE-2024-2", Severity: "HIGH", Pkg: "pkg-b", Version: "1.0", FixedVersion: "1.1"},
		{CVE: "CVE-2024-1", Severity: "CRITICAL", Pkg: "pkg-a", Version: "1.0", FixedVersion: "2.0"},
		{CVE: "CVE-2024-3", Severity: "MEDIUM", Pkg: "pkg-c", Version: "1.0", FixedVersion: ""},
	}
	svc := newTestService(fakeReader{hdr: hdr, finds: findings})
	vm, err := svc.Report(context.Background(), "a/b", "v1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !vm.Found {
		t.Fatal("expected Found=true")
	}
	if vm.Counts.Critical != 1 {
		t.Errorf("Critical count=%v want 1", vm.Counts.Critical)
	}
	if vm.Counts.High != 1 {
		t.Errorf("High count=%v want 1", vm.Counts.High)
	}
	if vm.Counts.Medium != 1 {
		t.Errorf("Medium count=%v want 1", vm.Counts.Medium)
	}
	// Verify sort: severity desc, then CVE asc
	if len(vm.Findings) != 3 {
		t.Fatalf("findings count=%v want 3", len(vm.Findings))
	}
	if vm.Findings[0].CVE != "CVE-2024-1" {
		t.Errorf("first finding CVE=%v want CVE-2024-1", vm.Findings[0].CVE)
	}
	if vm.Findings[1].CVE != "CVE-2024-2" {
		t.Errorf("second finding CVE=%v want CVE-2024-2", vm.Findings[1].CVE)
	}
}

func TestReportViewModelByPushID(t *testing.T) {
	hdr := audit.DecisionHeader{
		Found:  true,
		PushID: "push456",
		Repo:   "x/y",
		Tag:    "v2",
	}
	svc := newTestService(fakeReader{hdr: hdr})
	vm, err := svc.Report(context.Background(), "", "", "push456")
	if err != nil {
		t.Fatal(err)
	}
	if !vm.Found {
		t.Fatal("expected Found=true")
	}
	if vm.PushID != "push456" {
		t.Errorf("PushID=%v want push456", vm.PushID)
	}
}

func TestHealthViewModel(t *testing.T) {
	svc := newTestService(fakeReader{stats: audit.DecisionStats{Total: 100, Passed: 95, Rejected: 5}})
	vm, err := svc.Health(context.Background(), Range7d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Range != Range7d {
		t.Errorf("Range=%v want 7d", vm.Range)
	}
	if vm.Stats.PassRate != 95 {
		t.Errorf("PassRate=%v want 95", vm.Stats.PassRate)
	}
	if vm.TrivyDBAgeDays != 4 {
		t.Errorf("TrivyDBAgeDays=%v want 4", vm.TrivyDBAgeDays)
	}
	if len(vm.BaseImages) == 0 {
		t.Error("expected base images")
	}
	if vm.BaseImages[0].PassRate != 66.66666666666666 {
		t.Errorf("BaseImages[0].PassRate=%v want ~66.67", vm.BaseImages[0].PassRate)
	}
}

func TestVulnerabilitiesViewModel(t *testing.T) {
	svc := newTestService(fakeReader{
		cves: []audit.CVECount{
			{CVE: "CVE-2024-1", Severity: "CRITICAL", Pkg: "pkg-a", FixedVersion: "2.0", ImageCount: 10},
		},
	})
	vm, err := svc.Vulnerabilities(context.Background(), Range30d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Range != Range30d {
		t.Errorf("Range=%v want 30d", vm.Range)
	}
	if vm.Severity.Critical != 1 {
		t.Errorf("Severity.Critical=%v want 1", vm.Severity.Critical)
	}
	if len(vm.TopCVEs) != 1 {
		t.Fatalf("TopCVEs count=%v want 1", len(vm.TopCVEs))
	}
	if vm.TopCVEs[0].CVE != "CVE-2024-1" {
		t.Errorf("TopCVEs[0].CVE=%v want CVE-2024-1", vm.TopCVEs[0].CVE)
	}
	if len(vm.Fix.BySeverity) != 1 {
		t.Fatalf("Fix.BySeverity count=%v want 1", len(vm.Fix.BySeverity))
	}
	if vm.Fix.BySeverity[0].Pct != 50 {
		t.Errorf("Fix.BySeverity[0].Pct=%v want 50", vm.Fix.BySeverity[0].Pct)
	}
}

func TestIdentitiesViewModel(t *testing.T) {
	svc := newTestService(fakeReader{})
	vm, err := svc.Identities(context.Background(), Range1d)
	if err != nil {
		t.Fatal(err)
	}
	if len(vm.Identities) != 1 {
		t.Fatalf("Identities count=%v want 1", len(vm.Identities))
	}
	if vm.Identities[0].Name != "ci" {
		t.Errorf("Identities[0].Name=%v want ci", vm.Identities[0].Name)
	}
	if vm.Identities[0].PassRate != 100 {
		t.Errorf("Identities[0].PassRate=%v want 100", vm.Identities[0].PassRate)
	}
	if len(vm.Repos) != 1 {
		t.Fatalf("Repos count=%v want 1", len(vm.Repos))
	}
	if vm.Repos[0].PassRate != 66.66666666666666 {
		t.Errorf("Repos[0].PassRate=%v want ~66.67", vm.Repos[0].PassRate)
	}
}

func TestGracefulDegradation(t *testing.T) {
	// Verify that per-panel errors set Errored=true but don't fail the entire request
	svc := newTestService(fakeReader{err: context.DeadlineExceeded})
	vm, err := svc.Activity(context.Background(), Range1d)
	if err != nil {
		t.Fatal("Activity should not error on reader failure")
	}
	if !vm.Errored {
		t.Error("expected Errored=true when reader fails")
	}
}

func TestPrometheusCounters(t *testing.T) {
	svc := newTestServiceWithMetrics(fakeReader{}, true)
	vm, err := svc.Health(context.Background(), Range1d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.ACRPushSuccess != 95 {
		t.Errorf("ACRPushSuccess=%v want 95", vm.ACRPushSuccess)
	}
}

func TestPrometheusMetricsMissing(t *testing.T) {
	// Empty registry should return zero values, not error
	svc := newTestServiceWithMetrics(fakeReader{}, false)
	vm, err := svc.Health(context.Background(), Range1d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.TrivyDBAgeDays != 0 {
		t.Errorf("TrivyDBAgeDays=%v want 0 when metric absent", vm.TrivyDBAgeDays)
	}
	if vm.ACRPushSuccess != 0 {
		t.Errorf("ACRPushSuccess=%v want 0 when metric absent", vm.ACRPushSuccess)
	}
}

func TestSeverityRankUnknown(t *testing.T) {
	// Verify unknown severity gets lowest rank
	findings := []policy.Finding{
		{CVE: "CVE-1", Severity: "UNKNOWN", Pkg: "a", Version: "1", FixedVersion: ""},
		{CVE: "CVE-2", Severity: "LOW", Pkg: "b", Version: "1", FixedVersion: ""},
	}
	hdr := audit.DecisionHeader{Found: true, PushID: "p1"}
	svc := newTestService(fakeReader{hdr: hdr, finds: findings})
	vm, err := svc.Report(context.Background(), "", "", "p1")
	if err != nil {
		t.Fatal(err)
	}
	// LOW (rank 1) should sort before UNKNOWN (rank 0)
	if vm.Findings[0].Severity != "LOW" {
		t.Errorf("First finding severity=%v want LOW", vm.Findings[0].Severity)
	}
	if vm.Counts.Unknown != 1 {
		t.Errorf("Unknown count=%v want 1", vm.Counts.Unknown)
	}
}

func TestOverviewViewModel(t *testing.T) {
	svc := newTestService(fakeReader{stats: audit.DecisionStats{Total: 10, Passed: 8, Rejected: 2}})
	vm, err := svc.Overview(context.Background(), Range7d)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Stats.PassRate != 80 {
		t.Errorf("PassRate=%v want 80", vm.Stats.PassRate)
	}
	if len(vm.Images) != 1 || vm.Images[0].Repo != "a/b" {
		t.Errorf("expected one image row, got %+v", vm.Images)
	}
	if vm.Total != 1 || vm.Page != 1 {
		t.Errorf("pagination meta wrong: total=%d page=%d", vm.Total, vm.Page)
	}
}

func TestImagesPagination(t *testing.T) {
	svc := newTestService(fakeReader{})
	vm, err := svc.Images(context.Background(), Range1d, audit.ImageFilter{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if vm.Page != 1 || vm.PerPage != 10 {
		t.Errorf("page=%d perPage=%d want 1/10", vm.Page, vm.PerPage)
	}
	if len(vm.Images) != 1 {
		t.Errorf("want 1 row, got %d", len(vm.Images))
	}
}

func TestImagesDegradesOnError(t *testing.T) {
	svc := newTestService(fakeReader{err: errors.New("ch down")})
	vm, err := svc.Images(context.Background(), Range1d, audit.ImageFilter{}, 1)
	if err != nil {
		t.Fatalf("Images must not return error on backend failure: %v", err)
	}
	if !vm.Errored {
		t.Error("expected Errored=true when reader fails")
	}
}
