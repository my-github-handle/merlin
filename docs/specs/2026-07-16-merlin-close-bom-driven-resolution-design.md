# INFOSEC Merlin Close — BOM-Driven Develop Resolution

**Date:** 2026-07-16
**Component:** em-pm `/infosec-merlin-close` skill (`data/merlin_close*.py`, `data/bom_loader.py`, `data/merlin_gate.py`)
**Audience:** Infra EM tooling maintainer
**Status:** Approved design — pending implementation plan

## 1. Purpose

`/infosec-merlin-close` auto-closes open INFOSEC 8.10/8.11 tickets proven fixed on
c3aiops `develop`. Today it only resolves a develop version for images that appear
as **container components** in the develop BOM (`helm/c3aiops/files/bom.cdx.json`),
and it *guesses* each image's Merlin repo as `c3.ai/<image>` (with a small hand-maintained
`image_aliases` override map). That produces two defects:

1. **Repo-guess false negatives.** Images whose real registry path is not `c3.ai/<image>`
   (e.g. `grafana/grafana`, `webdevops/azure-metrics-exporter`) are scanned at the wrong
   ref, so an existing clean scan is reported as `NO_SCAN` and the ticket stays open.
2. **Umbrella image invisible.** The top-level `c3aiops` image is not a component in its
   own BOM, so tickets against it (e.g. INFOSEC-8386) fall to `NOT_IN_BOM` and are never
   even categorized as "on develop."

This design makes the **develop-branch BOM the single source of truth for both the
version and the repo of every develop image**, and uses **Merlin solely to check whether
that exact `repo:version` scan is clean**. No git-version heuristics, no repo guessing,
no alias map.

## 2. Guiding decisions (from brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Where does the develop version come from? | **The develop-branch BOM** (git), never the scanner | BOM is the authoritative "what ships on develop" manifest. |
| Where does the Merlin repo come from? | **The BOM component's `properties.source_image`** | Every one of the 36 container components carries it; it is the real registry path. |
| Merlin's role | **Scan-check only** (`report_for(repo:version)`) | Merlin answers "is this exact ref clean?" — it is not a version source. |
| Match policy | **Exact-tag only** (unchanged) | Never close on a differently-tagged build. Conservative for an auto-closer of security tickets. |
| Merlin-side changes | **Out of scope** — documented as future follow-ups | The our-side refactor closes real tickets today with no external dependency. |

## 3. Findings that ground the design

Verified against `c3-e/c3aiops@develop` BOM and the live Merlin catalog on 2026-07-16:

- The develop BOM has **36 container components**, and **all 36** carry
  `properties.source_image` (the true registry path, e.g. `grafana/grafana`,
  `webdevops/azure-metrics-exporter`, `c3.ai/c3-opensearch`, `tigera/operator`).
- The BOM's `metadata.component` describes the **umbrella image**: `name: c3aiops`,
  `version: 2.13.36`, `type: application`. This is the develop version of the top-level image.
- Both current `image_aliases` entries are already covered by `source_image`
  (`yet-another-cloudwatch-exporter → c3.ai/prometheus-yet-another-cloudwatch-exporter`,
  `operator/tigera-operator → tigera/operator`), so the alias map is fully redundant.
- **Neither** the BOM (0/36) **nor** Merlin (0/70) populates a digest, so the only
  possible BOM→scan join key is the `repo:version` string.
- grafana `7.5.4-7` and azure-metrics-exporter `25.12.0` exist as **exact** Merlin tags
  under their `source_image` repos — so fixing repo resolution closes those tickets with
  no other change.
- `c3aiops` BOM version `2.13.36` has **no bare `2.13.36` scan** in Merlin (only
  `2.13.36-PLAT-152135`, `2.13.37-*`). Under exact-tag matching it becomes `NO_SCAN` —
  correctly categorized, but still not closable until a bare develop scan exists.
- istio-*-fips, ingress-nginx-controller-fips, chainguard are **absent from Merlin
  entirely** — no develop scan exists, so no version-resolution change can close them.

## 4. Architecture

### 4.1 `bom_loader.py` — richer BOM model

`parse_bom` currently returns `dict[str, str]` = `{name: version}`. Change it to return a
mapping from image name to a small immutable record carrying **both version and repo**, and
to **also register the umbrella component** from `metadata.component`.

```python
@dataclass(frozen=True)
class BomImage:
    name: str
    version: str
    repo: str   # from properties.source_image; falls back to `name` when absent

def parse_bom(text: str) -> dict[str, BomImage]: ...
```

Rules:
- For each `type: container` component: `repo` = `properties.source_image` value; if that
  property is missing, fall back to the bare component `name`.
- Register `metadata.component` (the umbrella) as an entry keyed by its `name` (`c3aiops`),
  with its `version`, and `repo` = bare name (no `source_image` — Merlin tags it `c3aiops:<tag>`).
  If `metadata.component` is absent or lacks a version, skip it silently (do not fail the load).
- `EmptyBomError` still fires only when **zero** container components parse (unchanged guard;
  the umbrella entry does not count toward this).

### 4.2 `merlin_gate.py` — BOM supplies the repo

- **Delete `resolve_repo`** (the `c3.ai/<image>` guess) and the `aliases` parameter.
- `classify` reads the repo directly from the matched `BomImage`.
- Rename verdict `NOT_IN_BOM` → **`NOT_IN_DEVELOP`** (the BOM is now the develop manifest,
  not merely a component list). Update the constant, all references, the report renderer,
  and tests.
- Match policy unchanged: build `ref = f"{bom_image.repo}:{bom_image.version}"`, call
  `report_for(ref)`, and keep the exact three-state outcome
  (`None`→`NO_SCAN`, `set()`→`FIXED`, CVE present→`STILL_VULN`).
- Verdict precedence unchanged: `RETIRED` → `NO_CVE` → `NOT_IN_DEVELOP` → scan-based.

### 4.3 `merlin_close_config.json` / `merlin_close_config.py` — retire `image_aliases`

- Remove the `image_aliases` key from the JSON config and the field/parsing in the config
  loader. It is superseded by `source_image`. `retired_images`, `assignee_account_ids`,
  `affects_versions`, `transition_id`, and BOM/Merlin URLs are unchanged.

### 4.4 `merlin_close.py` orchestrator

- Drop the `aliases=cfg.image_aliases` argument from the `classify(...)` call.
- No other flow change. Merlin is still consulted only via `report_for`.

### 4.5 Report + skill doc

- `merlin_close_report.py`: rename the `NOT_IN_BOM` section heading to **"Not in develop"**
  and update the summary-table verdict label.
- `.claude/commands/infosec-merlin-close.md`: update the "Not in develop BOM" wording and the
  semantics notes to reflect BOM-as-develop-manifest and `source_image`-driven repos.

## 5. Net effect on the current 14 non-closable tickets

| Group | Before | After |
|---|---|---|
| grafana ×2, azure-metrics-exporter ×2 | false `NO_SCAN` | exact scan found → **FIXED and closed** (if clean) / `STILL_VULN` |
| c3aiops (INFOSEC-8386) | `NOT_IN_BOM` | `NO_SCAN` — correctly categorized; stays open (no bare `2.13.36` scan) |
| istio-*, ingress-*, chainguard (9) | `NOT_IN_BOM` | `NOT_IN_DEVELOP` — not on develop; stays open |

The refactor closes the 4 grafana/azure tickets, correctly reclassifies INFOSEC-8386, and is
honest that the remaining 9 images are not scanned on develop.

## 6. Error handling & invariants

- **Fail-loud preserved.** BOM fetch/parse, Merlin catalog, and Jira-auth failures still abort
  before any close and leave the prior report in place (existing `main()` exception ladder).
- **Exact-tag safety preserved.** A ticket closes only when Merlin has scanned the *exact*
  `repo:version` from the develop BOM and that scan is clean. No prefix/fuzzy matching.
- **Non-closable tickets are never written.** Only `FIXED` and `RETIRED` verdicts touch Jira.
- **Immutability.** `BomImage` is a frozen dataclass; parsing builds new records, never mutates.

## 7. Test plan

- `bom_loader`: container component with `source_image` → repo is that value; component
  missing `source_image` → repo falls back to name; `metadata.component` present → umbrella
  entry registered with its version and bare-name repo; `metadata.component` absent → no
  umbrella entry, no error; zero containers → `EmptyBomError`.
- `merlin_gate`: repo now comes from the `BomImage` (grafana → `grafana/grafana`, not
  `c3.ai/grafana`); `NOT_IN_DEVELOP` returned for an image absent from the BOM; exact-tag
  three-state outcomes unchanged; `RETIRED`/`NO_CVE` precedence unchanged.
- `merlin_close_config`: config with no `image_aliases` key loads cleanly; loader no longer
  exposes an aliases field.
- `merlin_close` (orchestrator): end-to-end fixture where grafana resolves to an exact clean
  scan → closed; c3aiops resolves to `NO_SCAN`; an istio image resolves to `NOT_IN_DEVELOP`.
- `merlin_close_report`: renders the renamed "Not in develop" section and summary label.
- Coverage target ≥ 80% on changed modules; TDD (red→green) for the new `BomImage` shape and
  the repo-source change.

## 8. Future: Merlin service enhancements (out of scope)

These raise the closing ceiling but are **not** dependencies of this refactor. File as
separate Merlin service requests:

1. **Per-scan branch/ref field** (e.g. `"branch": "develop"`) — highest leverage. Lets the
   skill ask Merlin directly for the develop scan of a repo instead of inferring develop-ness
   from tag suffixes. This is what would unblock the c3aiops (INFOSEC-8386) class, where the
   BOM version `2.13.36` never appears as a bare Merlin tag.
2. **Populated `Digest` on both BOM and scan records** — enables a content-hash join immune to
   `-PLAT-*`/build-suffix tag drift. Requires both the BOM generator and Merlin to emit digests.
3. **Develop scan coverage for the fips/chainguard images** (istio-*, ingress-nginx-*,
   chainguard) — pure coverage gap; the only thing that ever makes those 9 tickets verifiable.

## 9. Out of scope

- Prefix / fuzzy / semver tag matching (explicitly rejected — exact-tag only).
- Reading the develop version from git `Chart.yaml` (superseded by BOM `metadata.component`).
- Any change to the retired-images flow, assignee scope, or Jira close mechanics.
