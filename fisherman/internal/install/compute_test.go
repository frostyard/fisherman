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
		// --privileged and the store bind mount are both required: bootc reads
		// the store from inside the container, where --root means nothing.
		// This expectation previously omitted both and so passed against an
		// invocation that fails against any real image.
		want := []string{"--root", "/store", "--runroot", "/runstore", "--storage-driver", "overlay", "run", "--rm", "--pull=never", "--privileged", "-v", "/store:/var/lib/containers/storage", image, "bootc", "container", "compute-composefs-digest-from-storage", image}
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

// bootc reads the store from inside the container, where --root means nothing:
// it resolves the in-container default path and mounts the overlay itself.
// Verified directly against a real image -- --privileged alone still fails with
// "reference [overlay@...] not known"; --privileged plus this bind mount
// returns the digest.
func TestComputeSecureComposefsDigestGrantsPrivilegeAndMountsTheStore(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	var got []string
	runner.OutputFn = func(_ string, args ...string) ([]byte, error) {
		got = args
		return []byte(strings.Repeat("a", 128)), nil
	}
	if _, err := computeSecureComposefsDigest("img", "/store", "/runstore", "overlay"); err != nil {
		t.Fatalf("digest: %v", err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--privileged") {
		t.Fatalf("must run privileged or bootc cannot mount the overlay: %q", got)
	}
	if !strings.Contains(joined, "-v /store:/var/lib/containers/storage") {
		t.Fatalf("must bind the store to the in-container default path: %q", got)
	}
}

// With no explicit --root, the host default store still has to be mounted:
// the in-container path resolves to the image's own empty store otherwise.
func TestComputeSecureComposefsDigestMountsDefaultStoreWhenRootUnset(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	var got []string
	runner.OutputFn = func(_ string, args ...string) ([]byte, error) {
		got = args
		return []byte(strings.Repeat("a", 128)), nil
	}
	if _, err := computeSecureComposefsDigest("img", "", "", ""); err != nil {
		t.Fatalf("digest: %v", err)
	}
	if !strings.Contains(strings.Join(got, " "), "-v /var/lib/containers/storage:/var/lib/containers/storage") {
		t.Fatalf("default store must still be mounted: %q", got)
	}
}
