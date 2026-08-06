package secure

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

func espFixture(t *testing.T) (root, imageRoot string) {
	t.Helper()
	root, imageRoot = t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "boot/efi/EFI/BOOT"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{imageShim, imageMokManager, imageSecondStage, "usr/lib/snosi/mok.crt"} {
		p := filepath.Join(imageRoot, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content-of-"+filepath.Base(f)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, imageRoot
}

func TestStageESPChainWritesAllThreeComponents(t *testing.T) {
	old := runner.RunFn
	t.Cleanup(func() { runner.RunFn = old })
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }

	root, imageRoot := espFixture(t)
	if err := StageESPChain(root, imageRoot, "/usr/lib/snosi/mok.crt"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	boot := filepath.Join(root, "boot/efi/EFI/BOOT")
	for name, wantSource := range map[string]string{
		"BOOTX64.EFI": "shimx64.efi",         // firmware entry point is shim, NOT systemd-boot
		"grubx64.efi": "systemd-bootx64.efi", // what shim chainloads
		"mmx64.efi":   "mmx64.efi",
	} {
		got, err := os.ReadFile(filepath.Join(boot, name))
		if err != nil {
			t.Fatalf("%s not staged: %v", name, err)
		}
		if string(got) != "content-of-"+wantSource {
			t.Fatalf("%s = %q, want the contents of %s", name, got, wantSource)
		}
	}
}

// A complete chain must be left alone: this runs on installs that already have
// one, and rewriting the firmware entry point there would be gratuitous risk.
func TestStageESPChainIsIdempotent(t *testing.T) {
	root, imageRoot := espFixture(t)
	boot := filepath.Join(root, "boot/efi/EFI/BOOT")
	for _, name := range []string{"BOOTX64.EFI", "grubx64.efi", "mmx64.efi"} {
		if err := os.WriteFile(filepath.Join(boot, name), []byte("existing"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// No runner stub: a no-op must not even reach sbverify.
	if err := StageESPChain(root, imageRoot, "/usr/lib/snosi/mok.crt"); err != nil {
		t.Fatalf("stage on a complete chain: %v", err)
	}
	for _, name := range []string{"BOOTX64.EFI", "grubx64.efi", "mmx64.efi"} {
		got, _ := os.ReadFile(filepath.Join(boot, name))
		if string(got) != "existing" {
			t.Fatalf("%s was rewritten on a complete chain", name)
		}
	}
}

// An unverifiable second stage must stop the whole staging, leaving the ESP as
// bootc left it rather than half-converted.
func TestStageESPChainRefusesUnverifiedSecondStage(t *testing.T) {
	old := runner.RunFn
	t.Cleanup(func() { runner.RunFn = old })
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error {
		return os.ErrPermission
	}
	root, imageRoot := espFixture(t)
	if err := StageESPChain(root, imageRoot, "/usr/lib/snosi/mok.crt"); err == nil {
		t.Fatal("unverified second stage staged")
	}
	if _, err := os.Stat(filepath.Join(root, "boot/efi/EFI/BOOT/BOOTX64.EFI")); err == nil {
		t.Fatal("shim staged despite an unverified second stage")
	}
}
