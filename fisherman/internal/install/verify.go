package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/tuna-os/fisherman/internal/runner"
)

// DefaultCosignVerify runs `cosign verify --key <keyPath> <imgref>`.
// Output is relayed to stdout so the verification result is visible in logs.
func DefaultCosignVerify(imgref, keyPath string) error {
	name, hargs := runner.HostArgs("cosign", []string{"verify", "--key", keyPath, imgref})
	fmt.Fprintf(os.Stdout, "+ %s %s\n", name, strings.Join(hargs, " "))
	out, err := exec.Command(name, hargs...).CombinedOutput()
	fmt.Fprintf(os.Stdout, "%s", out)
	if err != nil {
		return fmt.Errorf("cosign verify %s: %w", imgref, err)
	}
	return nil
}

// CosignVerifyFn is the function used to verify an image signature.
// Replace in tests to avoid network calls.
var CosignVerifyFn = DefaultCosignVerify

// isRegistryRef reports whether imgref is a plain registry reference that can
// be resolved and verified against its registry. Local transports
// (containers-storage:, oci:, dir:, docker-archive:, ...) are not registry
// refs; their provenance was established when they were created (e.g. at
// live-media build time), so signature verification does not apply.
func isRegistryRef(imgref string) bool {
	rest, ok := strings.CutPrefix(imgref, "docker://")
	if ok {
		return rest != ""
	}
	// Any other transport prefix means a local source.
	if prefix, _, ok := strings.Cut(imgref, ":"); ok {
		switch prefix {
		case "containers-storage", "oci", "oci-archive", "dir", "docker-archive":
			return false
		}
	}
	return imgref != ""
}

// VerifyAndPinImage resolves a registry image reference to its manifest
// digest, verifies that immutable digest reference against the given cosign
// public key, and returns the digest-pinned reference ("name@sha256:...").
// Resolving the tag FIRST and verifying/using the digest closes the window
// where the tag could move to an unverified image between verification and
// pull. Non-registry references are returned unchanged without verification.
func VerifyAndPinImage(imgref, keyPath string) (string, error) {
	if !isRegistryRef(imgref) {
		fmt.Fprintf(os.Stdout, "Skipping signature verification for local image source %s\n", imgref)
		return imgref, nil
	}

	bare := bareImageRef(imgref)
	if strings.Contains(bare, "@sha256:") {
		if err := CosignVerifyFn(bare, keyPath); err != nil {
			return "", err
		}
		return bare, nil
	}

	out, err := SkopeoInspectFn("docker://" + bare)
	if err != nil {
		return "", fmt.Errorf("resolving digest for %s: %w", bare, err)
	}
	var manifest struct {
		Digest string `json:"Digest"`
	}
	if err := json.Unmarshal(out, &manifest); err != nil {
		return "", fmt.Errorf("parsing skopeo inspect output for %s: %w", bare, err)
	}
	if !strings.HasPrefix(manifest.Digest, "sha256:") {
		return "", fmt.Errorf("unexpected digest %q for %s", manifest.Digest, bare)
	}

	// Verify the digest ref, not the tag: the digest is what gets installed.
	name := bare
	if i := strings.LastIndex(bare, ":"); i > strings.LastIndex(bare, "/") {
		name = bare[:i]
	}
	pinned := name + "@" + manifest.Digest

	if err := CosignVerifyFn(pinned, keyPath); err != nil {
		return "", err
	}
	return pinned, nil
}
