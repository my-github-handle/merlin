package staging

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// VerifyDigest reads r and checks its sha256 against the claimed "sha256:<hex>".
func VerifyDigest(r io.Reader, claimed string) error {
	algo, want, ok := strings.Cut(claimed, ":")
	if !ok || algo != "sha256" {
		return fmt.Errorf("unsupported digest %q (want sha256:...)", claimed)
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return fmt.Errorf("hash blob: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("digest mismatch: got sha256:%s, want %s", got, claimed)
	}
	return nil
}
