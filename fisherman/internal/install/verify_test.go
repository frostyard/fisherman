package install_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/install"
)

func TestVerifyAndPinImageSkipsLocalSources(t *testing.T) {
	install.CosignVerifyFn = func(imgref, keyPath string) error {
		t.Fatalf("cosign must not run for local source, got %s", imgref)
		return nil
	}
	t.Cleanup(func() { install.CosignVerifyFn = install.DefaultCosignVerify })

	for _, ref := range []string{
		"containers-storage:ghcr.io/frostyard/snow:latest",
		"oci:/run/fisherman/oci-cache",
		"dir:/some/path",
	} {
		got, err := install.VerifyAndPinImage(ref, "/etc/pki/cosign.pub")
		if err != nil {
			t.Fatalf("VerifyAndPinImage(%q): %v", ref, err)
		}
		if got != ref {
			t.Fatalf("VerifyAndPinImage(%q) = %q, want unchanged", ref, got)
		}
	}
}

func TestVerifyAndPinImagePinsVerifiedDigest(t *testing.T) {
	const digest = "sha256:9f0971584a73a98bfdc421eecba1b0c974105bbe2f6ef6136f73a727f7ed99a8"

	install.SkopeoInspectFn = func(args ...string) ([]byte, error) {
		if len(args) != 1 || args[0] != "docker://ghcr.io/frostyard/snow:latest" {
			t.Fatalf("unexpected skopeo args: %v", args)
		}
		return []byte(`{"Digest": "` + digest + `"}`), nil
	}
	var verified string
	install.CosignVerifyFn = func(imgref, keyPath string) error {
		verified = imgref
		if keyPath != "/etc/pki/cosign.pub" {
			t.Fatalf("unexpected key path %q", keyPath)
		}
		return nil
	}
	t.Cleanup(func() {
		install.SkopeoInspectFn = install.DefaultSkopeoInspect
		install.CosignVerifyFn = install.DefaultCosignVerify
	})

	got, err := install.VerifyAndPinImage("docker://ghcr.io/frostyard/snow:latest", "/etc/pki/cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	want := "ghcr.io/frostyard/snow@" + digest
	if got != want {
		t.Fatalf("pinned ref = %q, want %q", got, want)
	}
	if verified != want {
		t.Fatalf("cosign verified %q, want the pinned digest ref %q", verified, want)
	}
}

func TestVerifyAndPinImageKeepsVerifiedDigestPinned(t *testing.T) {
	oldInspect, oldVerify := install.SkopeoInspectFn, install.CosignVerifyFn
	t.Cleanup(func() { install.SkopeoInspectFn, install.CosignVerifyFn = oldInspect, oldVerify })
	install.SkopeoInspectFn = func(_ ...string) ([]byte, error) {
		t.Fatal("already pinned image must not be resolved through a tag")
		return nil, nil
	}
	var verified string
	install.CosignVerifyFn = func(image, _ string) error { verified = image; return nil }
	const pinned = "ghcr.io/frostyard/cayo@sha256:verified"
	got, err := install.VerifyAndPinImage(pinned, "/keys/cosign.pub")
	if err != nil || got != pinned || verified != pinned {
		t.Fatalf("VerifyAndPinImage() = %q, %q, %v", got, verified, err)
	}
}

func TestVerifyAndPinImageFailsClosed(t *testing.T) {
	install.SkopeoInspectFn = func(args ...string) ([]byte, error) {
		return []byte(`{"Digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}`), nil
	}
	install.CosignVerifyFn = func(imgref, keyPath string) error {
		return errors.New("no matching signatures")
	}
	t.Cleanup(func() {
		install.SkopeoInspectFn = install.DefaultSkopeoInspect
		install.CosignVerifyFn = install.DefaultCosignVerify
	})

	_, err := install.VerifyAndPinImage("ghcr.io/frostyard/snow:latest", "/etc/pki/cosign.pub")
	if err == nil || !strings.Contains(err.Error(), "no matching signatures") {
		t.Fatalf("want verification failure to propagate, got %v", err)
	}
}

func TestVerifyAndPinImageRegistryPortIsNotATag(t *testing.T) {
	const digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	install.SkopeoInspectFn = func(args ...string) ([]byte, error) {
		return []byte(`{"Digest": "` + digest + `"}`), nil
	}
	install.CosignVerifyFn = func(imgref, keyPath string) error { return nil }
	t.Cleanup(func() {
		install.SkopeoInspectFn = install.DefaultSkopeoInspect
		install.CosignVerifyFn = install.DefaultCosignVerify
	})

	got, err := install.VerifyAndPinImage("registry.example.com:5000/snow", "/k.pub")
	if err != nil {
		t.Fatal(err)
	}
	want := "registry.example.com:5000/snow@" + digest
	if got != want {
		t.Fatalf("pinned ref = %q, want %q (registry port must not be stripped as a tag)", got, want)
	}
}
