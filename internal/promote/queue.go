// Package promote holds the durable queue of ACR promotions that outlive the
// manifest PUT that produced them.
//
// A passed image must reach ACR even if the handler has already answered the
// client. A bare goroutine cannot promise that: on a pod restart (an OOMKill runs
// no defers) every in-flight promotion vanishes, leaving an image that the gate
// approved, the audit row reports, and ACR never received. The queue is
// Valkey-backed because Valkey is already a hard dependency — internal/staging
// keeps blob ref-counts and upload sessions there.
package promote

import (
	"context"
	"time"
)

// Job is one unit of deferred promotion work.
//
// The JSON tags are part of the wire format: jobs are persisted as JSON so a
// schema change stays backward-readable, and the Valkey queue's Lua reads
// push_id out of the payload to key its claim. Renaming a tag is a data-format
// change, not a refactor.
type Job struct {
	PushID string `json:"push_id"` // pre-generated; shared with the report URL and audit row
	// Tenant is the tenant prefix (tenant.Tenant.Prefix) the worker resolves the ACR
	// pusher from. A repo name does not identify a tenant under the multi-ACR config,
	// and the request host the prefix came from is gone by the time the worker runs.
	Tenant string `json:"tenant"`
	Repo   string `json:"repo"`
	// Tag and Digest mirror the audited image identity. They are carried separately
	// from Ref because the audit row needs both: a promotion that is abandoned is
	// recorded as a new gate_decisions row, and that row is sorted by image_digest
	// and rendered on the dashboard by repo/tag. Deriving them from Ref at that
	// point is impossible — Ref is whichever ONE of the two the client used.
	Tag        string   `json:"tag"`
	Digest     string   `json:"digest"`
	Ref        string   `json:"ref"`         // tag or sha256:... digest, exactly as the client addressed it
	Target     string   `json:"target"`      // fully-qualified ACR ref
	OCIPath    string   `json:"oci_path"`    // local OCI layout produced by Assemble
	ScratchDir string   `json:"scratch_dir"` // parent dir to remove after promotion
	Layers     []string `json:"layers"`      // staged layer digests, for ref-count release
	ConfigDig  string   `json:"config_dig"`
	// Manifest is the exact bytes the client PUT. It is carried because OCIPath is
	// only valid on the pod that assembled the image — scratch is a per-pod emptyDir
	// while this queue is shared — so a sibling replica that claims the job must be
	// able to re-Assemble the layout from the shared blob store, and Assemble needs
	// the manifest to write index.json. See Worker.Localize.
	Manifest []byte `json:"manifest"`
	Identity string `json:"identity"`
	Attempts uint8  `json:"attempts"`
}

// Queue is the durable hand-off between the request path and the promotion worker.
//
// Claim/Ack is at-least-once, not exactly-once: a worker that dies after pushing
// to ACR but before Ack will have its job recovered and pushed again. That is the
// safe direction only because re-pushing an identical digest is a no-op in a
// registry — see the note on Recover.
type Queue interface {
	Enqueue(ctx context.Context, j Job) error
	Claim(ctx context.Context) (Job, bool, error) // false when empty
	Ack(ctx context.Context, pushID string) error
	// Recover re-queues jobs claimed longer ago than olderThan — claims held by a
	// worker that died. A zero olderThan reclaims every outstanding claim, which is
	// the correct behaviour at process start: this process holds no claims yet, so
	// any claim present belongs to a dead predecessor.
	//
	// Recovery may re-promote an image that was already pushed. That is safe:
	// acr.Push uses go-containerregistry's remote.Write, which skips blobs already
	// present and re-PUTs byte-identical manifest bytes, so a duplicate push is
	// wasted bandwidth rather than a correctness problem — while stranding an
	// approved image unpublished forever is not recoverable at all.
	//
	// The one hazard is a TAG target: if another push claimed the same tag between
	// the first promotion and the recovery, re-promoting moves the tag back to the
	// older image. Digest targets (what buildx pushes) cannot suffer this. Bounding
	// the retry window (worker recovery interval) is what keeps it narrow.
	Recover(ctx context.Context, olderThan time.Duration) ([]Job, error)
	// Depth is the number of jobs waiting to be claimed. Claimed jobs are excluded:
	// they are already draining, and the caller uses this to decide whether to admit
	// MORE work.
	//
	// It exists because every pending job pins an OCI layout on a per-pod emptyDir
	// while its client has already been told 201. Without a readable backlog the only
	// thing bounding local disk is the worker's drain rate.
	Depth(ctx context.Context) (int, error)
}
