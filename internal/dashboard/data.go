// Package dashboard serves Merlin's built-in observability UI.
package dashboard

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/merlin-gate/merlin/internal/audit"
	"github.com/merlin-gate/merlin/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const imagesPerPage = 10

// Service turns the audit Reader + Prometheus gatherer into view models.
type Service struct {
	r   audit.DashboardReader
	g   prometheus.Gatherer
	now func() time.Time
}

// NewService builds the data service. now defaults to time.Now when nil.
func NewService(r audit.DashboardReader, g prometheus.Gatherer, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{r: r, g: g, now: now}
}

func (s *Service) sinceFor(rng Range) time.Time {
	switch rng {
	case Range7d:
		return s.now().Add(-7 * 24 * time.Hour)
	case Range30d:
		return s.now().Add(-30 * 24 * time.Hour)
	default:
		return s.now().Add(-24 * time.Hour)
	}
}

func toStatsVM(st audit.DecisionStats) StatsVM {
	vm := StatsVM{
		Total: st.Total, Passed: st.Passed, Rejected: st.Rejected,
		PassRate: PassRate(st.Passed, st.Total),
		P50:      st.Latency.P50, P95: st.Latency.P95, P99: st.Latency.P99,
	}
	for _, rr := range st.RejectReasons {
		pct := 0.0
		if st.Rejected > 0 {
			pct = float64(rr.Count) / float64(st.Rejected) * 100
		}
		vm.RejectReasons = append(vm.RejectReasons, LabeledVM{Label: rr.Label, Count: rr.Count, Pct: pct})
	}
	return vm
}

// Report builds the per-image scan report. Provide either pushID, or repo+ref.
func (s *Service) Report(ctx context.Context, repo, ref, pushID string) (ReportVM, error) {
	var (
		hdr      audit.DecisionHeader
		findings []policy.Finding
		err      error
	)
	if pushID != "" {
		hdr, err = s.r.DecisionHeaderByPush(ctx, pushID)
		if err == nil && hdr.Found {
			findings, err = s.r.FindingsByPush(ctx, hdr.PushID)
		}
	} else {
		hdr, err = s.r.DecisionHeaderByRef(ctx, repo, ref)
		if err == nil && hdr.Found {
			findings, err = s.r.FindingsByImageRef(ctx, repo, ref)
		}
	}
	if err != nil {
		return ReportVM{}, err
	}
	if !hdr.Found {
		return ReportVM{Found: false}, nil
	}
	vm := ReportVM{
		Found: true, PushID: hdr.PushID, Repo: hdr.Repo, Tag: hdr.Tag, Digest: hdr.Digest,
		Identity: hdr.Identity, Passed: hdr.Passed, FailedPolicies: hdr.FailedPolicies,
		Reasons: hdr.Reasons, BaseImageID: hdr.BaseImageID, TrivyDBVersion: hdr.TrivyDBVersion, Ts: hdr.Ts,
	}
	for _, f := range findings {
		vm.Findings = append(vm.Findings, FindingVM{
			CVE: f.CVE, Severity: f.Severity, Pkg: f.Pkg, Version: f.Version, FixedVersion: f.FixedVersion})
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			vm.Counts.Critical++
		case "HIGH":
			vm.Counts.High++
		case "MEDIUM":
			vm.Counts.Medium++
		case "LOW":
			vm.Counts.Low++
		default:
			vm.Counts.Unknown++
		}
	}
	// Stable order: severity desc, then CVE.
	sort.SliceStable(vm.Findings, func(i, j int) bool {
		si, sj := sevRank(vm.Findings[i].Severity), sevRank(vm.Findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return vm.Findings[i].CVE < vm.Findings[j].CVE
	})
	return vm, nil
}

func sevRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// gaugeValue reads the newest sample of a gauge metric family (0 if absent).
func (s *Service) gaugeValue(name string) float64 {
	mfs, err := s.g.Gather()
	if err != nil {
		return 0
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	return 0
}

// counterValue reads a counter with a matching label pair (0 if absent).
func (s *Service) counterValue(name, label, value string) float64 {
	mfs, err := s.g.Gather()
	if err != nil {
		return 0
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matchLabel(m, label, value) {
				if c := m.GetCounter(); c != nil {
					return c.GetValue()
				}
			}
		}
	}
	return 0
}

func matchLabel(m *dto.Metric, label, value string) bool {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == label && lp.GetValue() == value {
			return true
		}
	}
	return false
}

func (s *Service) Images(ctx context.Context, rng Range, f audit.ImageFilter, page int) (ImagesVM, error) {
	if page < 1 {
		page = 1
	}
	vm := ImagesVM{Range: rng, PageMeta: PageMeta{Page: page, PerPage: imagesPerPage}}
	pg, err := s.r.ImagesPage(ctx, s.sinceFor(rng), f, imagesPerPage, (page-1)*imagesPerPage)
	if err != nil {
		vm.Errored = true
		return vm, nil
	}
	vm.Total = pg.Total
	vm.HasPrev = page > 1
	vm.HasNext = uint64(page*imagesPerPage) < pg.Total
	for _, ir := range pg.Rows {
		vm.Images = append(vm.Images, ImageVM(ir))
	}
	return vm, nil
}

func (s *Service) Overview(ctx context.Context, rng Range) (OverviewVM, error) {
	vm := OverviewVM{Range: rng, PageMeta: PageMeta{Page: 1, PerPage: imagesPerPage}}
	if st, err := s.r.DecisionStatsSince(ctx, s.sinceFor(rng)); err != nil {
		vm.Errored = true
	} else {
		vm.Stats = toStatsVM(st)
	}
	vm.TrivyDBAgeDays = s.gaugeValue("merlin_trivy_db_age_days")
	ok := s.counterValue("merlin_acr_push_total", "result", "ok")
	errc := s.counterValue("merlin_acr_push_total", "result", "error")
	if ok+errc > 0 {
		vm.ACRPushSuccess = ok / (ok + errc) * 100
	}
	img, _ := s.Images(ctx, rng, audit.ImageFilter{}, 1)
	if img.Errored {
		vm.Errored = true
	}
	vm.Images = img.Images
	vm.Total = img.Total
	vm.HasPrev = img.HasPrev
	vm.HasNext = img.HasNext
	return vm, nil
}
