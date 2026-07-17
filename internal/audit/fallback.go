package audit

import "strings"

// refAllowsRepoFallback reports whether a report-by-ref lookup that found no exact
// match may fall back to "the most recent push for the repo".
//
// The fallback exists for buildx/attested pushes: the image manifest is recorded by
// DIGEST (the human tag lives only on the un-scanned index), so a by-digest ref that
// misses can still resolve to the one image in flight for the repo. For a TAG ref,
// however, a miss means that exact tag was never scanned — falling back would serve
// a DIFFERENT image's scan mislabeled as the requested tag, which is a correctness
// and trust bug on a security gate. So only digest refs are allowed to fall back.
func refAllowsRepoFallback(ref string) bool {
	return strings.HasPrefix(ref, "sha256:")
}
