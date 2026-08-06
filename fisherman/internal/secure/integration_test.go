package secure_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/install"
	"github.com/tuna-os/fisherman/internal/runner"
	"github.com/tuna-os/fisherman/internal/secure"
)

func TestValidateDiskSizeRejectsDiskBelowContractFloor(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return []byte("32212254719\n"), nil }
	if err := secure.ValidateDiskSize("/dev/test"); err == nil {
		t.Fatal("undersized secure target accepted")
	}
}

// stackOutput stubs the three version probes.
func stackOutput(bootc, cosign, systemd string) func(string, ...string) ([]byte, error) {
	return func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "bootc":
			return []byte("bootc " + bootc + "\n"), nil
		case "cosign":
			return []byte("GitVersion: v" + cosign + "\n"), nil
		default:
			return []byte(systemd + "\n"), nil
		}
	}
}

func TestValidateVersionsRejectsWrongSecureInstallerStack(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return []byte("0.0.0\n"), nil }
	if _, err := secure.ValidateVersions(); err == nil {
		t.Fatal("unsupported secure installer versions accepted")
	}
}

func TestValidateVersionsRejectsSubstringVersionMatches(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = stackOutput("1.16.30", "2.6.1", "261.1-3")
	if _, err := secure.ValidateVersions(); err == nil {
		t.Fatal("substring bootc version accepted")
	}
}

// bootc keeps an EXACT pin: its integration depends on observed,
// non-upstream-stable behaviour, so a newer release is the thing most likely to
// break it silently.
func TestValidateVersionsRejectsNewerBootc(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = stackOutput("1.17.0", "2.6.1", "261.1-3")
	if _, err := secure.ValidateVersions(); err == nil {
		t.Fatal("newer bootc accepted against an exact pin")
	}
}

func TestValidateVersionsRejectsSystemdBelowFloor(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = stackOutput("1.16.3", "2.6.1", "261.1-2")
	if _, err := secure.ValidateVersions(); err == nil {
		t.Fatal("systemd below the contract floor accepted")
	}
}

func TestValidateVersionsAcceptsValidatedStackSilently(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = stackOutput("1.16.3", "2.6.1", "261.1-3")
	result, err := secure.ValidateVersions()
	if err != nil {
		t.Fatalf("validated stack rejected: %v", err)
	}
	if len(result.Warnings) != 0 {
		t.Fatalf("validated stack warned: %v", result.Warnings)
	}
	if result.Detected["systemd"] != "261.1-3" || result.Detected["bootc"] != "1.16.3" {
		t.Fatalf("detected versions not reported: %v", result.Detected)
	}
}

// The case that motivated the change: media rebuilt onto a newer systemd in the
// same family. It must install, and it must say so loudly.
func TestValidateVersionsWarnsAboveFloorButUnvalidated(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = stackOutput("1.16.3", "2.6.1", "261.2-1")
	result, err := secure.ValidateVersions()
	if err != nil {
		t.Fatalf("systemd above the floor rejected: %v", err)
	}
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "261.2-1") {
		t.Fatalf("above-floor unvalidated systemd did not warn: %v", result.Warnings)
	}
	if result.Detected["systemd"] != "261.2-1" {
		t.Fatalf("provenance recorded the floor rather than what ran: %v", result.Detected)
	}
}

func TestVerifyInstalledRejectsComposefsMismatch(t *testing.T) {
	root := installedFixture(t, "?"+strings.Repeat("a", 128))
	if _, err := secure.VerifyInstalled(root, root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, strings.Repeat("b", 128)); err == nil {
		t.Fatal("mismatched composefs digest accepted")
	}
}

func TestVerifyInstalledRequiresCanonicalComposefsDigests(t *testing.T) {
	valid := strings.Repeat("a", 128)
	for name, test := range map[string]struct{ expected, observed string }{
		"uppercase expected": {strings.Repeat("A", 128), "?" + strings.Repeat("A", 128)},
		"short expected":     {strings.Repeat("a", 127), "?" + strings.Repeat("a", 127)},
		"uppercase observed": {valid, "?" + strings.Repeat("A", 128)},
		"double marker":      {valid, "??" + valid},
	} {
		t.Run(name, func(t *testing.T) {
			root := installedFixture(t, test.observed)
			if _, err := secure.VerifyInstalled(root, root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, test.expected); err == nil {
				t.Fatal("malformed composefs digest accepted")
			}
		})
	}
	root := installedFixture(t, "?"+valid)
	artifacts, err := secure.VerifyInstalled(root, root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, valid)
	if err != nil || artifacts.ComposefsID != valid {
		t.Fatalf("ComposefsID = %q, %v", artifacts.ComposefsID, err)
	}
}

func TestAcceptImagePinsDigestAndRequiresSecureCapability(t *testing.T) {
	oldInspect, oldVerify := install.SkopeoInspectFn, install.CosignVerifyFn
	t.Cleanup(func() { install.SkopeoInspectFn, install.CosignVerifyFn = oldInspect, oldVerify })
	install.SkopeoInspectFn = func(_ ...string) ([]byte, error) {
		return []byte(`{"Digest":"sha256:verified","Labels":{"io.snosi.bootc.secureboot-capable":"true"}}`), nil
	}
	install.CosignVerifyFn = func(_, _ string) error { return nil }
	got, err := secure.AcceptImage("ghcr.io/frostyard/cayo:stable", "/keys/cosign.pub")
	if err != nil {
		t.Fatal(err)
	}
	if got != "ghcr.io/frostyard/cayo@sha256:verified" {
		t.Fatalf("accepted image = %q", got)
	}
}

func TestVerifyInstalledExtractsInstalledPCRKeyAndRejectsRawBLS(t *testing.T) {
	root := installedFixture(t, "?"+strings.Repeat("a", 128))
	contract := &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}
	if _, err := secure.VerifyInstalled(root, root, contract, strings.Repeat("a", 128)); err != nil {
		t.Fatal(err)
	}
}

func installedFixture(t *testing.T, composefs string) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{
		"usr/lib/snosi", "boot/efi/loader/entries", "boot/efi/EFI/Linux", "boot/efi/EFI/BOOT",
	} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/snosi/pcr.pub"), []byte("expected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/loader/entries/snosi.conf"), []byte("efi /EFI/Linux/snosi.efi\noptions rw composefs="+composefs+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A real PE: VerifyInstalled parses the UKI's .pcrpkey section rather than
	// shelling out, so a placeholder string is no longer a usable fixture.
	pe := secure.WriteTestPE(t, map[string]string{".pcrpkey": "expected"})
	uki, err := os.ReadFile(pe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/Linux/snosi.efi"), uki, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BOOTX64.EFI", "mmx64.efi", "grubx64.efi"} {
		if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/BOOT", name), []byte("efi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldRun, oldOut := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = oldRun, oldOut })
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }
	// The installed UKI must report as signed; an unsigned one is now refused
	// outright, which is the behaviour this fixture is not trying to test.
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) {
		return []byte("signature 1\nimage signature issuers:\n - /CN=snosi\n"), nil
	}
	return root
}

// installedBootcFixture reproduces what bootc actually writes: a BLS entry with
// a `uki` directive and NO options line, with the composefs identity living in
// the UKI's signed .cmdline section. installedFixture models an `options`-style
// entry, which no real install produces -- so every existing test here has been
// exercising the fallback rather than the live path.
func installedBootcFixture(t *testing.T, cmdline string) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{
		"usr/lib/snosi", "boot/efi/loader/entries", "boot/efi/EFI/Linux", "boot/efi/EFI/BOOT",
	} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/snosi/pcr.pub"), []byte("expected"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := "title Cayo Linux 13\nversion 13\nuki /EFI/Linux/snosi.efi\nsort-key bootc-cayo-0\n"
	if err := os.WriteFile(filepath.Join(root, "boot/efi/loader/entries/bootc_cayo-13-1.conf"), []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	// A real PE carrying both sections VerifyInstalled reads. The composefs
	// identity lives in .cmdline exactly as a signed UKI carries it.
	pe := secure.WriteTestPE(t, map[string]string{".pcrpkey": "expected", ".cmdline": cmdline})
	uki, err := os.ReadFile(pe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/Linux/snosi.efi"), uki, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BOOTX64.EFI", "mmx64.efi", "grubx64.efi"} {
		if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/BOOT", name), []byte("efi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldRun, oldOut := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = oldRun, oldOut })
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) {
		return []byte("signature 1\nimage signature issuers:\n - /CN=snosi\n"), nil
	}
	return root
}

func TestVerifyInstalledReadsComposefsFromTheUKICmdline(t *testing.T) {
	digest := strings.Repeat("a", 128)
	root := installedBootcFixture(t, "rw composefs=?"+digest)
	artifacts, err := secure.VerifyInstalled(root, root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, digest)
	if err != nil {
		t.Fatalf("VerifyInstalled() on the entry bootc writes: %v", err)
	}
	if artifacts.ComposefsID != digest {
		t.Fatalf("ComposefsID = %q, want %q", artifacts.ComposefsID, digest)
	}
}

// A UKI whose baked-in command line names a different deployment must be
// refused: that is the check standing between a verified digest and whatever
// actually boots.
func TestVerifyInstalledRefusesAMismatchedUKICmdline(t *testing.T) {
	root := installedBootcFixture(t, "rw composefs=?"+strings.Repeat("b", 128))
	if _, err := secure.VerifyInstalled(root, root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, strings.Repeat("a", 128)); err == nil {
		t.Fatal("mismatched composefs identity in .cmdline accepted")
	}
}

// An unsigned UKI on the ESP of a secure install cannot boot under enforced
// Secure Boot, and the firmware reports only `Invalid parameter` with no
// bootable option. VerifyInstalled must refuse it while the install can still
// fail loudly, rather than leaving it for the first reboot to discover.
func TestVerifyInstalledRefusesAnUnsignedUKI(t *testing.T) {
	digest := strings.Repeat("a", 128)
	root := installedBootcFixture(t, "rw composefs=?"+digest)
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) {
		return []byte("No signature table present\n"), nil
	}
	if _, err := secure.VerifyInstalled(root, root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, digest); err == nil {
		t.Fatal("an unsigned installed UKI was accepted")
	}
}
