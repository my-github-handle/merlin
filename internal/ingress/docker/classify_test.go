package docker

import "testing"

func TestClassifyManifest(t *testing.T) {
	tests := []struct {
		name string
		body string
		want manifestKind
	}{
		{
			name: "normal image (config + tar+gzip layers)",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:c"},
				"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:l"}]}`,
			want: kindImage,
		},
		{
			name: "docker schema 2 image (rootfs.diff layer)",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json",
				"config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:c"},
				"layers":[{"mediaType":"application/vnd.docker.image.rootfs.diff.tar.gzip","digest":"sha256:l"}]}`,
			want: kindImage,
		},
		{
			name: "SLSA attestation manifest (in-toto layer, no filesystem)",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:b6"},
				"layers":[{"mediaType":"application/vnd.in-toto+json","digest":"sha256:a1",
					"annotations":{"in-toto.io/predicate-type":"https://slsa.dev/provenance/v0.2"}}]}`,
			want: kindAttestation,
		},
		{
			name: "layers with missing mediaType -> image (must be scanned, never bypassed)",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"config":{"digest":"sha256:c"},
				"layers":[{"digest":"sha256:l"}]}`,
			want: kindImage,
		},
		{
			name: "layers with unknown mediaType -> image (fail-safe: scan it)",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"config":{"digest":"sha256:c"},
				"layers":[{"mediaType":"application/x-some-future-type","digest":"sha256:l"}]}`,
			want: kindImage,
		},
		{
			name: "OCI image index",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json",
				"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:fc"}]}`,
			want: kindIndex,
		},
		{
			name: "docker manifest list",
			body: `{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json",
				"manifests":[{"mediaType":"application/vnd.docker.distribution.manifest.v2+json","digest":"sha256:fc"}]}`,
			want: kindIndex,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, got, err := classifyManifest([]byte(tc.body))
			if err != nil {
				t.Fatalf("classifyManifest: %v", err)
			}
			if got != tc.want {
				t.Errorf("kind = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestClassifyManifestRejectsBadJSON(t *testing.T) {
	if _, _, err := classifyManifest([]byte("not json")); err == nil {
		t.Error("expected parse error for invalid JSON")
	}
}
