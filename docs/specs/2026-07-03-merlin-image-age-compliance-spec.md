# Merlin Service — Image-Age Compliance Policy Spec

**Date:** 2026-07-03
**Audience:** Merlin service team (implementing this as a native gate policy)
**Origin:** ports the behavior of the c3aiops local `imageComplianceReport` tool
(`cmd/imageComplianceReport/`) into Merlin so the local CI job can be retired.

## 1. Purpose

Add an **image-age policy** to Merlin's in-band manifest-PUT gate, alongside the existing
Trivy CVE check and base-image policy. The gate rejects an image whose build/creation date
is older than a configurable freshness threshold. This catches stale base images and
long-unrebuilt dependencies that CVE scanning alone does not flag.

This is a **per-push policy on the image being published** — not a fleet/BOM sweep. It is
evaluated at the same point as the CVE and base-image checks: when the client issues the
manifest PUT.

## 2. Behavior being ported (current local tool)

For fidelity, the existing local behavior is:

| Aspect | Current local tool |
|--------|--------------------|
| Threshold | `> 60 days` old = non-compliant (constant `ComplianceThresholdDays = 60`, "2 months") |
| Age source | image `.Created` timestamp via `docker inspect`, parsed as RFC3339 / RFC3339Nano |
| Age computation | `AgeInDays = floor(now - Created, in days)`; compliant iff `AgeInDays <= 60` |
| Scope | ~30 BOM images from `.c3release.yaml` `images:` list, tag resolved via `values.yaml` path |
| Verdict | all-or-nothing: fails if ANY image exceeds threshold |
| Output | CSV (`image-compliance-report.csv`) + markdown report + non-zero exit on failure |

Merlin reframes "scope" from a BOM sweep to the single image on the wire, and "verdict"
from all-or-nothing to a per-image pass/reject consistent with the rest of the gate.

## 3. Requirements

### 3.1 Age determination
- Compute the pushed image's creation date from the **image config's `created` field**
  (the OCI/Docker image config JSON, RFC3339 / RFC3339Nano). This is the same value
  `docker inspect -f '{{.Created}}'` returns — Merlin already has the manifest + config in
  hand during the gate, so no extra pull is needed.
- `age_days = floor((now_utc - created_utc) / 24h)`.
- For a **multi-arch image index**, evaluate the `created` of each child manifest that is
  gated; the image's effective age is the **oldest** child (most conservative). Attestation
  / SLSA manifests in the index are ignored for age purposes.

### 3.2 Policy verdict
- **Pass** iff `age_days <= threshold_days`.
- **Reject** (manifest PUT → **400 Bad Request**) iff `age_days > threshold_days`.
- Reject body reason MUST be machine-parseable and human-readable, consistent with the CVE
  reject format. Suggested:
  `rejected: image age 74d exceeds max 60d (created 2026-04-20T10:31:00Z)`
- Age failures and CVE failures are **independent**: an image can be rejected for either or
  both. When both fail, the body SHOULD list both reasons.

### 3.3 Configurability
- `threshold_days` MUST be configurable per Merlin deployment / tenant prefix. Default **60**.
- Provide a way to **disable** the age policy per tenant (some prefixes may not want it),
  independent of the CVE/base-image policies.
- OPTIONAL: allow a per-repository override (e.g. slow-moving vendor mirrors may warrant a
  longer threshold). If implemented, most-specific (repo) wins over tenant default.

### 3.4 Report integration
- The age result MUST be included in the scan report retrievable at
  `GET /reports/<ref>` (the same report that carries Trivy findings), so a 400 reject is
  explainable without re-running. Suggested fields per image:
  `{ created, age_days, threshold_days, compliant }`.
- If Merlin returns `X-Merlin-Scan-Report-URL` on the manifest PUT, the age result MUST be
  present in that report too.

### 3.5 Error semantics (do not conflate with policy verdict)
- A **400** is reserved for a real policy verdict (too old / CVE / bad base). If Merlin
  cannot read the image `created` field (malformed config, missing field), that is a
  **configuration/infra condition**, not "image too old" — surface it distinctly (5xx or a
  clearly-worded 400 that is unambiguously not an age verdict). Never silently pass an image
  whose age could not be determined; **fail-closed** (reject with a "could not determine
  age" reason) is preferred over fail-open.

### 3.6 Trust boundary (age is self-attested, computed server-side)
- Merlin computes age **entirely server-side**: it reads `created` from the image config blob
  it fetched into staging and **digest-verified** (`fetchVerified` → `VerifyDigest`) before
  the gate runs. The policy consumes only that server-derived value — it reads **no**
  request-time client input (no header, query param, or client-asserted age). A client cannot
  influence the verdict by anything other than the image bytes it pushes.
- BUT `created` is **self-attested by whoever built the image**. Digest verification proves the
  config bytes match the digest the pusher supplied — it does **not** prove the pusher was
  honest about the contents. A builder can set `created` (via `docker build`, a crafted config,
  or `SOURCE_DATE_EPOCH`) to any value, and the digest still verifies because it hashes the
  claimed value. Every timestamp inside the artifact is in the same trust class — `created`,
  `history[].created`, and layer file mtimes are all builder-controlled — so gating on a
  different in-image field does **not** close this gap.
- Consequence: this policy is a **freshness control, not an anti-tamper control**. It reliably
  catches the real-world case it exists for — images that were genuinely not rebuilt (a team
  forgot; a base drifted) — but it does **not** stop a motivated pusher who forges `created`.
- The only un-forgeable age signals live **outside** the image and are explicit non-goals here
  (see §4): (a) **registry receive-time** — server-authoritative, but measures "age since first
  pushed to Merlin", not build age; (b) **signed provenance** (SLSA / in-toto / cosign) — a
  trusted builder cryptographically attests the real build time, verified against a trust root.
  Adopt one of those only if a threat model requires adversary-grade guarantees.

## 4. Non-goals
- Merlin does **not** sweep the `.c3release.yaml` BOM or read `values.yaml`. Age is evaluated
  only on the image currently being pushed. (The fleet-wide freshness view, if still wanted,
  is a separate concern outside the gate.)
- Merlin does **not** verify build-time authenticity: it trusts the self-attested `created`
  timestamp (see §3.6). Registry receive-time gating and signed-provenance verification are
  out of scope for this policy.
- No CSV/markdown artifact generation inside Merlin — the JSON report at `/reports/<ref>` is
  the single source; CI archives it.

## 5. Acceptance criteria
1. Pushing an image whose config `created` is ≤ threshold days old → **201**, report shows
   `compliant: true`.
2. Pushing an image older than threshold → **400** with an age reason in the body; report
   shows `compliant: false` with `created` / `age_days`.
3. Threshold is deployment-configurable; default 60; age policy can be disabled per tenant.
4. Multi-arch index uses the oldest gated child manifest's `created`.
5. An image whose `created` cannot be read is rejected (fail-closed) with a distinct,
   non-age-verdict reason.
6. Age result appears in `GET /reports/<ref>` alongside CVE findings.

## 6. Reference — source being retired
- `cmd/imageComplianceReport/main.go` — orchestration, CSV/markdown/exit-code.
- `cmd/imageComplianceReport/helper/compliance.go` — `ComplianceThresholdDays = 60`,
  `GetImageAge`, `getImageCreationDate` (docker inspect `.Created`), `CalculateAgeInDays`,
  compliance verdict.
- Config model: `cmd/updateContainerImage/helper/config.go` (`ImageDefinition`,
  `C3ReleaseConfig`) + `.c3release.yaml` `images:` list — the BOM scope that Merlin
  intentionally does NOT replicate.
