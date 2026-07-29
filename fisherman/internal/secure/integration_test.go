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

func TestValidateVersionsRejectsWrongSecureInstallerStack(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) { return []byte("0.0.0\n"), nil }
	if err := secure.ValidateVersions(); err == nil {
		t.Fatal("unsupported secure installer versions accepted")
	}
}

func TestValidateVersionsRejectsSubstringVersionMatches(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	runner.OutputFn = func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "bootc":
			return []byte("bootc 1.16.30\n"), nil
		case "cosign":
			return []byte("GitVersion: v2.6.1\n"), nil
		default:
			return []byte("261.1-3\n"), nil
		}
	}
	if err := secure.ValidateVersions(); err == nil {
		t.Fatal("substring bootc version accepted")
	}
}

func TestVerifyInstalledRejectsComposefsMismatch(t *testing.T) {
	root := installedFixture(t, "?"+strings.Repeat("a", 128))
	if _, err := secure.VerifyInstalled(root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, strings.Repeat("b", 128)); err == nil {
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
			if _, err := secure.VerifyInstalled(root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, test.expected); err == nil {
				t.Fatal("malformed composefs digest accepted")
			}
		})
	}
	root := installedFixture(t, "?"+valid)
	artifacts, err := secure.VerifyInstalled(root, &secure.Contract{PCRPublicKey: "/usr/lib/snosi/pcr.pub"}, valid)
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
	if _, err := secure.VerifyInstalled(root, contract, strings.Repeat("a", 128)); err != nil {
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
	if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/Linux/snosi.efi"), []byte("uki"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"BOOTX64.EFI", "mmx64.efi", "grubx64.efi"} {
		if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/BOOT", name), []byte("efi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := runner.RunFn
	t.Cleanup(func() { runner.RunFn = old })
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		if name == "objcopy" {
			for _, arg := range args {
				if strings.HasPrefix(arg, ".pcrpkey=") {
					return os.WriteFile(strings.TrimPrefix(arg, ".pcrpkey="), []byte("expected"), 0o600)
				}
			}
		}
		return nil
	}
	return root
}
