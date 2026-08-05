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
		want := []string{"--root", "/store", "--runroot", "/runstore", "--storage-driver", "overlay", "run", "--rm", "--pull=never", image, "bootc", "container", "compute-composefs-digest-from-storage", image}
		if name != "podman" || strings.Join(args, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("command = %s %q", name, args)
		}
		return []byte(valid + "\n"), nil
	}
	if got, err := computeSecureComposefsDigest(image, "/store", "/runstore", "overlay"); err != nil || got != valid {
		t.Fatalf("digest = %q, %v", got, err)
	}

	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return []byte("bad\n"), nil }
	if _, err := computeSecureComposefsDigest(image, "/store", "/runstore", "overlay"); err == nil {
		t.Fatal("malformed digest accepted")
	}
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return nil, errors.New("podman failed") }
	if _, err := computeSecureComposefsDigest(image, "/store", "/runstore", "overlay"); err == nil {
		t.Fatal("command failure accepted")
	}
}

func TestPodmanPullArgsIncludeSecurePolicyAndRedirectedStore(t *testing.T) {
	got := podmanPullArgs("ghcr.io/frostyard/cayo@sha256:verified", "/store", "/runstore", "overlay", "/policy.json")
	// --signature-policy must follow `pull`: it is a subcommand flag, not a
	// global podman option. This expectation previously asserted the opposite
	// order, so the test passed while the command line it locked in could not
	// execute at all -- podman exits 125 with "unknown flag". Since policyPath
	// is set only on the secure install path, that broke every secure install
	// and nothing else, which is why it went unnoticed.
	want := []string{"--root", "/store", "--runroot", "/runstore", "--storage-driver", "overlay", "pull", "--signature-policy", "/policy.json", "ghcr.io/frostyard/cayo@sha256:verified"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("pull args = %q, want %q", got, want)
	}
}

// The subcommand must precede its flags, and the image must come last.
func TestPodmanPullArgsPutSubcommandBeforeItsFlags(t *testing.T) {
	got := podmanPullArgs("img", "", "", "", "/policy.json")
	pull, policy := -1, -1
	for i, a := range got {
		switch a {
		case "pull":
			pull = i
		case "--signature-policy":
			policy = i
		}
	}
	if pull == -1 || policy == -1 || policy < pull {
		t.Fatalf("--signature-policy must follow pull, got %q", got)
	}
	if got[len(got)-1] != "img" {
		t.Fatalf("image must be the final argument, got %q", got)
	}
}
