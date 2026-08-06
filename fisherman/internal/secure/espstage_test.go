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

// stubSigned makes sbverify --list report a signature for every binary, which
// is the normal case. Tests that care about the unsigned case override it.
func stubSigned(t *testing.T) {
	t.Helper()
	oldRun, oldOut := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = oldRun, oldOut })
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) {
		return []byte("signature 1\nimage signature issuers:\n - /CN=Example\n"), nil
	}
}

func TestStageESPChainWritesAllThreeComponents(t *testing.T) {
	stubSigned(t)

	root, imageRoot := espFixture(t)
	if err := StageESPChain(root, imageRoot, "/usr/lib/snosi/mok.crt"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	boot := filepath.Join(root, "boot/efi/EFI/BOOT")
	for name, wantSource := range map[string]string{
		// The firmware entry point is shim, NOT systemd-boot, and it is the
		// SIGNED shim: Debian ships an unsigned shimx64.efi in the same
		// directory, and staging that one is refused by firmware with
		// EFI_ACCESS_DENIED before shim ever runs.
		"BOOTX64.EFI": "shimx64.efi.signed",
		"grubx64.efi": "systemd-bootx64.efi", // what shim chainloads
		"mmx64.efi":   "mmx64.efi.signed",
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
	stubSigned(t)
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

// Regression: fisherman#21 staged usr/lib/shim/shimx64.efi, the UNSIGNED
// binary Debian's shim-unsigned installs alongside the signed one. The install
// reported success and the target then failed to boot with nothing on the
// console but
//
//	BdsDxe: failed to load Boot0001 "UEFI Misc Device": Access Denied
//
// — firmware rejecting the first hop, so shim never ran and never printed the
// "Security Violation" the secure-install harness watches for. Staging an
// unsigned component must fail loudly instead, and must fail before shim lands
// on the ESP.
func TestStageESPChainRefusesUnsignedComponents(t *testing.T) {
	for _, unsigned := range []string{imageShim, imageMokManager} {
		t.Run(filepath.Base(unsigned), func(t *testing.T) {
			stubSigned(t)
			target := unsigned
			runner.OutputFn = func(_ string, args ...string) ([]byte, error) {
				if len(args) > 0 && filepath.Base(args[len(args)-1]) == filepath.Base(target) {
					return []byte("No signature table present\n"), nil
				}
				return []byte("signature 1\nimage signature issuers:\n - /CN=Example\n"), nil
			}
			root, imageRoot := espFixture(t)
			err := StageESPChain(root, imageRoot, "/usr/lib/snosi/mok.crt")
			if err == nil {
				t.Fatalf("staged unsigned %s", filepath.Base(target))
			}
			if _, err := os.Stat(filepath.Join(root, "boot/efi/EFI/BOOT/BOOTX64.EFI")); err == nil {
				t.Fatal("shim staged despite an unsigned component")
			}
		})
	}
}
