package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// StaticFS returns the embedded static assets rooted at "static".
func StaticFS() fs.FS {
	sub, _ := fs.Sub(staticFS, "static")
	return sub
}

// pageData is the wrapper passed to every page template: it carries the nav/range
// chrome plus the page-specific view model under .VM.
type pageData struct {
	Page   string
	Action string
	Range  Range
	Ranges []Range
	VM     any
}

// Renderer holds the parsed templates (layout + one page each).
type Renderer struct {
	pages map[string]*template.Template
}

var pageActions = map[string]string{
	"activity": "/", "health": "/health",
	"vulnerabilities": "/vulnerabilities", "identities": "/identities", "report": "/report",
}

// NewRenderer parses layout.html with each page template into a set keyed by page.
func NewRenderer() (*Renderer, error) {
	pages := map[string]*template.Template{}
	for _, page := range []string{"activity", "health", "vulnerabilities", "identities", "report"} {
		t, err := template.New("layout").ParseFS(templateFS, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", page, err)
		}
		pages[page] = t
	}
	return &Renderer{pages: pages}, nil
}

// Render writes the named page (e.g. "activity") wrapping vm as .VM.
func (r *Renderer) Render(w io.Writer, page string, vm any) error {
	t, ok := r.pages[page]
	if !ok {
		return fmt.Errorf("unknown page %q", page)
	}
	rng := rangeOf(vm)
	return t.ExecuteTemplate(w, "layout", pageData{
		Page: page, Action: pageActions[page], Range: rng,
		Ranges: []Range{Range1d, Range7d, Range30d}, VM: vm,
	})
}

// rangeOf extracts the Range field from a view model (defaults to 1d).
func rangeOf(vm any) Range {
	switch v := vm.(type) {
	case ActivityVM:
		return v.Range
	case HealthVM:
		return v.Range
	case VulnVM:
		return v.Range
	case IdentitiesVM:
		return v.Range
	default:
		return Range1d
	}
}
