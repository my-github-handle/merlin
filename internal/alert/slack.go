package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxSlackBody caps the serialized payload. Slack rejects oversized posts, and a
// rejection is indistinguishable from "nothing fired" from the channel's point of
// view, so the cap is applied here rather than discovered there.
const maxSlackBody = 8 << 10

// maxEvidenceLen bounds the raw error_detail excerpt. grype's stderr is the reason
// this is needed: it can run to kilobytes for one failed catalog.
const maxEvidenceLen = 1200

// Slack posts findings to an incoming webhook.
//
// The webhook URL is a CREDENTIAL — anyone holding it can post to the channel — so
// it is never logged and never included in a returned error. Go's own transport
// errors embed the request URL, which is why failures here are rebuilt rather than
// wrapped.
type Slack struct {
	url  string
	env  string // deployment name, e.g. "merlin-opsadmin"; one channel serves several
	http *http.Client
}

// NewSlack builds a webhook notifier. env labels the deployment in every message.
func NewSlack(webhookURL, env string) *Slack {
	return &Slack{
		url: webhookURL,
		env: env,
		// Bounded on purpose: this runs on a ticker inside the gate's process, and an
		// unbounded POST to a hung webhook would pin the goroutine indefinitely.
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// icon marks severity without a config knob. A killed scan and a rate step change
// are service-level; a novel signature is "look at this when you can".
func icon(detector string) string {
	switch detector {
	case DetectorKilledScan, DetectorInfraErrorRate:
		return ":rotating_light:"
	default:
		return ":mag:"
	}
}

// Message renders a finding as the Slack text body. Exported for tests and for any
// future sink that wants the same wording.
func (s *Slack) Message(f Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s *%s* `%s`\n%s\n", icon(f.Detector), s.env, f.Detector, f.Summary)
	fmt.Fprintf(&b, "• signature: `%s`\n", f.Signature)
	fmt.Fprintf(&b, "• occurrences: %d\n", f.Count)
	if !f.FirstSeen.IsZero() {
		fmt.Fprintf(&b, "• first seen: %s\n", f.FirstSeen.UTC().Format(time.RFC3339))
	}
	if !f.LastSeen.IsZero() {
		fmt.Fprintf(&b, "• last seen: %s\n", f.LastSeen.UTC().Format(time.RFC3339))
	}
	if ev := strings.TrimSpace(f.Evidence); ev != "" {
		if len(ev) > maxEvidenceLen {
			ev = ev[:maxEvidenceLen] + "…"
		}
		// The raw, unnormalized detail: the signature says what class this is, the
		// evidence says which push to go and look at.
		fmt.Fprintf(&b, "```%s```\n", ev)
	}
	return b.String()
}

func (s *Slack) Notify(ctx context.Context, f Finding) error {
	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: s.Message(f)})
	if err != nil {
		return fmt.Errorf("encode slack payload: %w", err)
	}
	if len(body) > maxSlackBody {
		// Re-encode from a trimmed message rather than truncating the JSON, which
		// would produce a body Slack cannot parse.
		trimmed := f
		trimmed.Evidence = ""
		body, err = json.Marshal(struct {
			Text string `json:"text"`
		}{Text: s.Message(trimmed) + "_(evidence omitted: message too large)_"})
		if err != nil {
			return fmt.Errorf("encode slack payload: %w", err)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		// Not wrapped: http.NewRequest errors quote the URL.
		return fmt.Errorf("slack notify: invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		// Deliberately drops the underlying error's text: *url.Error embeds the
		// webhook URL, so wrapping it would write the credential to the pod log on
		// every transient failure. The context cause is preserved because callers
		// distinguish cancellation from a real failure.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("slack notify: %w", ctxErr)
		}
		return fmt.Errorf("slack notify: request failed (webhook URL redacted)")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Slack puts the reason in the body ("invalid_payload", "no_service"), which is
		// the only diagnosable part and contains no credential.
		reason, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("slack notify: status %d: %s", resp.StatusCode, strings.TrimSpace(string(reason)))
	}
	return nil
}
