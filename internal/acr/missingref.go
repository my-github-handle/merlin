package acr

import (
	"errors"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// IsMissingReference reports whether err is a registry refusing a manifest because
// something the manifest POINTS AT is not in the registry yet.
//
// It exists to separate "not yet" from "no". A registry validates a manifest's
// references at PUT time, and Merlin relies on that: an image index whose gated image
// was rejected can never be published, because the rejected image's manifest is not
// there to reference. The same 400 also appears while a *passing* image is still
// working through the promotion queue — same error, opposite meaning — and only the
// caller's own state (did anything get enqueued) distinguishes them. Callers wait on
// this class, and on nothing else.
//
// The narrowness is deliberate:
//   - MANIFEST_BLOB_UNKNOWN / BLOB_UNKNOWN name a referenced object. Waitable.
//   - MANIFEST_UNKNOWN is a miss on the TARGET, not a reference — a wrong repo or a
//     deleted tag. Waiting cannot make a wrong target right.
//   - MANIFEST_INVALID, UNAUTHORIZED, DENIED and the rest are faults in what we sent
//     or who we are. Retrying them only delays a clear failure.
func IsMissingReference(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}
	for _, d := range terr.Errors {
		switch d.Code {
		case transport.ManifestBlobUnknownErrorCode, transport.BlobUnknownErrorCode:
			return true
		}
	}
	return false
}
