// Package dashboard serves Merlin's built-in observability UI.
package dashboard

import (
	"context"
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

// Report builds the per-image scan report. Provide either pushID, or repo+ref.
//
// The three outcomes are distinct on purpose and the caller renders each differently: an
// error is retryable ("report unavailable"), !Found is settled ("no scan exists"), and a
// found report is the report.
func (s *Service) Report(ctx context.Context, repo, ref, pushID string) (ReportVM, error) {
	hdr, findings, err := s.fetchReport(ctx, repo, ref, pushID)
	if err != nil {
		return ReportVM{}, err
	}
	if !hdr.Found {
		return ReportVM{Found: false}, nil
	}
	return newReportVM(hdr, findings), nil
}

// fetchReport resolves a report by push ID, or by repo+ref when no push ID is given.
//
// Findings are only fetched for a header that exists: by-ref lookups arrive from
// user-supplied query strings, and a second query for a repo:tag nobody ever pushed is a
// full-scan of the findings table on a miss.
func (s *Service) fetchReport(ctx context.Context, repo, ref, pushID string) (audit.DecisionHeader, []policy.Finding, error) {
	if pushID != "" {
		hdr, err := s.r.DecisionHeaderByPush(ctx, pushID)
		if err != nil || !hdr.Found {
			return hdr, nil, err
		}
		// By hdr.PushID, not the argument: the header is the authority on its own ID.
		findings, err := s.r.FindingsByPush(ctx, hdr.PushID)
		return hdr, findings, err
	}
	hdr, err := s.r.DecisionHeaderByRef(ctx, repo, ref)
	if err != nil || !hdr.Found {
		return hdr, nil, err
	}
	findings, err := s.r.FindingsByImageRef(ctx, repo, ref)
	return hdr, findings, err
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

// counterSumWhere totals every series of a counter whose label equals value
// (equal=true) or differs from it (equal=false). It does not stop at the first match, so
// it stays correct for counters that carry a dimension the caller is not selecting on —
// e.g. summing across registries.
//
// It replaced a counterValue helper that returned only the FIRST matching series, which
// reported one tenant's registry as if it were the fleet. That helper is gone; nothing
// called it after the fix.
func (s *Service) counterSumWhere(name, label, value string, equal bool) float64 {
	mfs, err := s.g.Gather()
	if err != nil {
		return 0
	}
	var total float64
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if matchLabel(m, label, value) != equal {
				continue
			}
			if c := m.GetCounter(); c != nil {
				total += c.GetValue()
			}
		}
	}
	return total
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
	vm.ScannerDBAgeDays = s.gaugeValue("merlin_scanner_db_age_days")
	// Sum across registries, and treat every non-"ok" result as a failure. Both matter
	// since merlin_acr_push_total gained a registry label and split its failures into
	// causes: reading a single series would report one tenant's pushes as if they were all
	// of them, and there is no longer any series labelled result="error" to find.
	ok := s.counterSumWhere("merlin_acr_push_total", "result", "ok", true)
	failed := s.counterSumWhere("merlin_acr_push_total", "result", "ok", false)
	vm.ACRPushSuccess = pct(ok, ok+failed)
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
