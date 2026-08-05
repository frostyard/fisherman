package secure_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
	"github.com/tuna-os/fisherman/internal/secure"
)

func TestRestageMOKOnlyStagesCertificate(t *testing.T) {
	old, oldOutput := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = old, oldOutput })
	var calls []string
	root := t.TempDir()
	recovery := filepath.Join(root, "recovery")
	if err := os.WriteFile(recovery, []byte("recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/lib/snosi"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/snosi/mok.crt"), []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	mokPassword := filepath.Join(root, "mok-password")
	if err := os.WriteFile(mokPassword, []byte("MokPassw0rd"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.OutputFn = func(name string, args ...string) ([]byte, error) {
		if name != "mokutil" || len(args) != 1 {
			t.Fatalf("unexpected hash command %s %q", name, args)
		}
		return []byte("hash\n"), nil
	}
	if err := secure.RestageMOK(root, &secure.Contract{MOKCertificate: "/usr/lib/snosi/mok.crt"}, recovery, mokPassword, "/dev/sda2"); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || !strings.HasPrefix(calls[2], "mokutil --import ") {
		t.Fatalf("restage calls = %q", calls)
	}
	for _, call := range calls {
		if strings.Contains(call, "sfdisk") || strings.Contains(call, "mkfs") || strings.Contains(call, "bootc install") {
			t.Fatalf("restage altered installation: %q", call)
		}
	}
}

func TestRestageMOKUsesContractCertificatePath(t *testing.T) {
	old, oldOutput := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = old, oldOutput })
	var certificateInput string
	root := t.TempDir()
	recovery := filepath.Join(root, "recovery")
	if err := os.WriteFile(recovery, []byte("recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		if name == "openssl" {
			certificateInput = args[2]
		}
		return nil
	}
	runner.OutputFn = func(name string, args ...string) ([]byte, error) {
		if name != "mokutil" || len(args) != 1 {
			t.Fatalf("unexpected hash command %s %q", name, args)
		}
		return []byte("hash\n"), nil
	}
	path := filepath.Join(root, "usr/lib/snosi/keys/custom-mok.crt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	mokPassword := filepath.Join(root, "mok-password")
	if err := os.WriteFile(mokPassword, []byte("MokPassw0rd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secure.RestageMOK(root, &secure.Contract{MOKCertificate: "/usr/lib/snosi/keys/custom-mok.crt"}, recovery, mokPassword, "/dev/sda2"); err != nil {
		t.Fatal(err)
	}
	if certificateInput != path {
		t.Fatalf("certificate input = %q, want %q", certificateInput, path)
	}
}

func TestWriteProvenanceExcludesRecoveryCredential(t *testing.T) {
	root := t.TempDir()
	if err := secure.WriteProvenance(root, secure.Provenance{
		OCIRef:      "ghcr.io/frostyard/cayo@sha256:verified",
		TrackingRef: "ghcr.io/frostyard/cayo:stable",
		UKIHash:     "hash",
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "var/lib/snosi/bootc-secure-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "recovery") || !strings.Contains(string(data), "sha256:verified") {
		t.Fatalf("unsafe or incomplete provenance: %s", data)
	}
}

func TestRepairESPOnlyReplacesVerifiedSecondStage(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"usr/lib/snosi/bootc", "usr/lib/snosi/custom", "boot/efi/EFI/BOOT", "boot/efi/EFI/Linux", "boot/efi/loader/entries"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"usr/lib/snosi/custom/mok.crt", "usr/lib/snosi/bootc/systemd-bootx64.efi", "boot/efi/EFI/BOOT/BOOTX64.EFI", "boot/efi/EFI/BOOT/mmx64.efi", "boot/efi/EFI/BOOT/grubx64.efi"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("efi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/Linux/snosi.efi"), []byte("uki"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/loader/entries/snosi.conf"), []byte("efi /EFI/Linux/snosi.efi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := runner.RunFn
	t.Cleanup(func() { runner.RunFn = old })
	var verifies int
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		if name != "sbverify" {
			t.Fatalf("unexpected repair command %q", name)
		}
		if len(args) != 3 || args[1] != filepath.Join(root, "usr/lib/snosi/custom/mok.crt") {
			t.Fatalf("sbverify args = %q", args)
		}
		verifies++
		return nil
	}
	if err := secure.RepairESP(root, root, "/usr/lib/snosi/custom/mok.crt"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(root, "boot/efi/EFI/BOOT/grubx64.efi")); err != nil || string(data) != "efi" {
		t.Fatalf("second stage was not repaired: %q, %v", data, err)
	}
	if verifies != 2 {
		t.Fatalf("sbverify calls = %d, want source and temporary replacement", verifies)
	}
}

func TestRepairESPKeepsPriorStageWhenMutatedTemporaryCopyFailsVerification(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"usr/lib/snosi/bootc", "boot/efi/EFI/BOOT", "boot/efi/EFI/Linux", "boot/efi/loader/entries"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{
		"usr/lib/snosi/mok.crt":                   "cert",
		"usr/lib/snosi/bootc/systemd-bootx64.efi": "new",
		"boot/efi/EFI/BOOT/BOOTX64.EFI":           "shim",
		"boot/efi/EFI/BOOT/mmx64.efi":             "mokmanager",
		"boot/efi/EFI/BOOT/grubx64.efi":           "old",
		"boot/efi/EFI/Linux/snosi.efi":            "uki",
		"boot/efi/loader/entries/snosi.conf":      "efi /EFI/Linux/snosi.efi\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := runner.RunFn
	t.Cleanup(func() { runner.RunFn = old })
	checks := 0
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		if name != "sbverify" {
			t.Fatalf("unexpected command %q", name)
		}
		checks++
		if checks == 2 {
			if err := os.WriteFile(args[2], []byte("mutated"), 0o644); err != nil {
				t.Fatal(err)
			}
			return os.ErrPermission
		}
		return nil
	}
	if err := secure.RepairESP(root, root, "/usr/lib/snosi/mok.crt"); err == nil {
		t.Fatal("temporary replacement verification failure accepted")
	}
	data, err := os.ReadFile(filepath.Join(root, "boot/efi/EFI/BOOT/grubx64.efi"))
	if err != nil || string(data) != "old" {
		t.Fatalf("prior stage changed after failed verification: %q, %v", data, err)
	}
}
