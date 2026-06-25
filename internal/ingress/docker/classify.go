package docker

import "encoding/json"

// manifestKind classifies an inbound manifest so the handler can decide whether to
// run the gate (filesystem image) or forward it to ACR verbatim (index/attestation).
type manifestKind int

const (
	// kindImage is a normal image manifest with a config + filesystem layers. It is
	// assembled and run through the policy gate.
	kindImage manifestKind = iota
	// kindIndex is an image index / manifest list (references sub-manifests by
	// digest). It carries no filesystem; forwarded to ACR verbatim.
	kindIndex
	// kindAttestation is an image manifest whose layers are all non-filesystem
	// (e.g. SLSA provenance: application/vnd.in-toto+json). It carries no runnable
	// filesystem to scan; forwarded to ACR verbatim.
	kindAttestation
)

// parsedManifest is the minimal view of a Docker/OCI manifest or index needed for
// classification and blob/sub-manifest enumeration.
type parsedManifest struct {
	MediaType string `json:"mediaType"`
	Config    struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"layers"`
	// Manifests is populated only for an image index / manifest list.
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
	} `json:"manifests"`
}

// indexMediaTypes are the manifest media types that denote an image index / list.
var indexMediaTypes = map[string]bool{
	"application/vnd.oci.image.index.v1+json":                   true,
	"application/vnd.docker.distribution.manifest.list.v2+json": true,
}

// nonFilesystemLayerTypes are layer media types known to carry NO extractable
// filesystem (build attestations). A manifest whose every layer is one of these
// is an attestation manifest, forwarded to ACR without scanning.
var nonFilesystemLayerTypes = map[string]bool{
	"application/vnd.in-toto+json": true,
}

// classifyManifest parses a manifest body and classifies it. A parse error is
// reported so the caller can reject with 400. Classification rules:
//   - has manifests[] or an index media type -> kindIndex
//   - has layers AND every layer is a known non-filesystem type -> kindAttestation
//   - otherwise -> kindImage (the gated path)
//
// The attestation rule requires layers to be EXPLICITLY known non-filesystem types
// (e.g. in-toto). A missing or unrecognized layer media type falls through to
// kindImage so it is scanned — the gate must never be bypassed by an unknown type.
func classifyManifest(body []byte) (parsedManifest, manifestKind, error) {
	var m parsedManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return parsedManifest{}, kindImage, err
	}
	if len(m.Manifests) > 0 || indexMediaTypes[m.MediaType] {
		return m, kindIndex, nil
	}
	if len(m.Layers) > 0 {
		allNonFS := true
		for _, l := range m.Layers {
			if !nonFilesystemLayerTypes[l.MediaType] {
				allNonFS = false
				break
			}
		}
		if allNonFS {
			return m, kindAttestation, nil
		}
	}
	return m, kindImage, nil
}
