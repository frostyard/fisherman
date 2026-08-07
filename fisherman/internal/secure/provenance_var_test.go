package secure

import (
	"os"
	"path/filepath"
	"testing"
)

// A composefs deployment's persistent /var is the stateroot's, not <root>/var.
// Measured on a real installed target: the booted system writes into
// state/os/default/var, and <root>/var is a separate directory nothing mounts.
// Provenance written to the wrong one is unreadable and fails Task 9's check.
func TestWriteProvenanceTargetsTheStaterootVar(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "state/os/default/var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteProvenance(root, Provenance{OCIRef: "ghcr.io/x@sha256:abc"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	stateroot := filepath.Join(root, "state/os/default/var/lib/snosi/bootc-secure-install.json")
	if _, err := os.Stat(stateroot); err != nil {
		t.Fatalf("provenance not written to the stateroot var: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/snosi/bootc-secure-install.json")); err == nil {
		t.Fatal("provenance written to <root>/var, which no booted system mounts")
	}
}

// Without a stateroot there is nothing composefs-shaped to target, and the
// plain layout must keep working.
func TestWriteProvenanceFallsBackToRootVar(t *testing.T) {
	root := t.TempDir()
	if err := WriteProvenance(root, Provenance{OCIRef: "ghcr.io/x@sha256:abc"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/snosi/bootc-secure-install.json")); err != nil {
		t.Fatalf("fallback did not write to <root>/var: %v", err)
	}
}

// Two stateroots is ambiguous; guessing which one boots would be worse than
// the documented fallback.
func TestWriteProvenanceFallsBackWhenStaterootIsAmbiguous(t *testing.T) {
	root := t.TempDir()
	for _, s := range []string{"default", "other"} {
		if err := os.MkdirAll(filepath.Join(root, "state/os", s, "var"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteProvenance(root, Provenance{OCIRef: "ghcr.io/x@sha256:abc"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/snosi/bootc-secure-install.json")); err != nil {
		t.Fatalf("ambiguous stateroot did not fall back: %v", err)
	}
}
