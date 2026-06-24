package staging

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyDigestMatch(t *testing.T) {
	data := []byte("layer-bytes")
	sum := sha256.Sum256(data)
	claimed := "sha256:" + hex.EncodeToString(sum[:])
	if err := VerifyDigest(bytes.NewReader(data), claimed); err != nil {
		t.Errorf("expected match, got %v", err)
	}
}

func TestVerifyDigestMismatch(t *testing.T) {
	if err := VerifyDigest(bytes.NewReader([]byte("x")), "sha256:deadbeef"); err == nil {
		t.Error("expected mismatch error")
	}
}

func TestVerifyDigestMalformed(t *testing.T) {
	if err := VerifyDigest(bytes.NewReader([]byte("x")), "md5:abc"); err == nil {
		t.Error("expected error for non-sha256 digest")
	}
}
