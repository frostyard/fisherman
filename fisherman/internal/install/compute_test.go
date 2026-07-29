package install

import (
	"errors"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

func TestComputeSecureComposefsDigest(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	const image = "ghcr.io/frostyard/cayo@sha256:verified"
	valid := strings.Repeat("a", 128)
	runner.OutputFn = func(name string, args ...string) ([]byte, error) {
		want := []string{"--root", "/store", "--storage-driver", "overlay", "run", "--rm", "--pull=never", image, "bootc", "container", "compute-composefs-digest-from-storage", image}
		if name != "podman" || strings.Join(args, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("command = %s %q", name, args)
		}
		return []byte(valid + "\n"), nil
	}
	if got, err := computeSecureComposefsDigest(image, "/store", "overlay"); err != nil || got != valid {
		t.Fatalf("digest = %q, %v", got, err)
	}

	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return []byte("bad\n"), nil }
	if _, err := computeSecureComposefsDigest(image, "/store", "overlay"); err == nil {
		t.Fatal("malformed digest accepted")
	}
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return nil, errors.New("podman failed") }
	if _, err := computeSecureComposefsDigest(image, "/store", "overlay"); err == nil {
		t.Fatal("command failure accepted")
	}
}
