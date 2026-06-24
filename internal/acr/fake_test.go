package acr

import (
	"context"
	"errors"
	"testing"
)

func TestFakePusherRecordsTarget(t *testing.T) {
	f := &FakePusher{}
	if err := f.Push(context.Background(), "/oci", "myreg.azurecr.io/app:v1"); err != nil {
		t.Fatal(err)
	}
	if len(f.Pushed) != 1 || f.Pushed[0] != "myreg.azurecr.io/app:v1" {
		t.Errorf("pushed = %v", f.Pushed)
	}
}

func TestFakePusherReturnsErr(t *testing.T) {
	f := &FakePusher{Err: errors.New("boom")}
	if err := f.Push(context.Background(), "/oci", "t"); err == nil {
		t.Error("expected error")
	}
}
