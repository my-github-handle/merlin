package baseimage

import "testing"

func TestParseOSReleaseExtractsID(t *testing.T) {
	in := `NAME="Red Hat Enterprise Linux"
ID="rhel"
PLATFORM_ID="platform:el9"`
	osr := ParseOSRelease(in)
	if osr.ID != "rhel" {
		t.Errorf("ID = %q, want rhel", osr.ID)
	}
	if osr.Fields["PLATFORM_ID"] != "platform:el9" {
		t.Errorf("PLATFORM_ID = %q", osr.Fields["PLATFORM_ID"])
	}
}

func TestParseOSReleaseWolfi(t *testing.T) {
	osr := ParseOSRelease("ID=wolfi\nNAME=\"Wolfi\"")
	if osr.ID != "wolfi" {
		t.Errorf("ID = %q, want wolfi", osr.ID)
	}
}

func TestParseOSReleaseEmpty(t *testing.T) {
	if ParseOSRelease("").ID != "" {
		t.Error("empty input should yield empty ID")
	}
}
