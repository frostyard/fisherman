package secure

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

func TestWriteProvenanceRecordsImmutableAndTrackingReferencesSeparately(t *testing.T) {
	root := t.TempDir()
	accepted := "ghcr.io/frostyard/cayo@sha256:accepted"
	tracking := "ghcr.io/frostyard/cayo:stable"
	if err := WriteProvenance(root, Provenance{OCIRef: accepted, TrackingRef: tracking}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "var/lib/snosi/bootc-secure-install.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record["oci_ref"] != accepted {
		t.Fatalf("oci_ref = %#v, want %q", record["oci_ref"], accepted)
	}
	if record["tracking_ref"] != tracking {
		t.Fatalf("tracking_ref = %#v, want %q", record["tracking_ref"], tracking)
	}
}

func TestRepairESPKeepsPriorStageWhenReplacementSyncFails(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"usr/lib/snosi/bootc", "boot/efi/EFI/BOOT", "boot/efi/EFI/Linux", "boot/efi/loader/entries"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"usr/lib/snosi/mok.crt", "usr/lib/snosi/bootc/systemd-bootx64.efi", "boot/efi/EFI/BOOT/BOOTX64.EFI", "boot/efi/EFI/BOOT/mmx64.efi", "boot/efi/EFI/Linux/snosi.efi"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/loader/entries/snosi.conf"), []byte("efi /EFI/Linux/snosi.efi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "boot/efi/EFI/BOOT/grubx64.efi")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, oldRun := syncFile, runner.RunFn
	syncFile = func(*os.File) error { return errors.New("sync failed") }
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }
	t.Cleanup(func() { syncFile, runner.RunFn = old, oldRun })
	if err := RepairESP(root, "/usr/lib/snosi/mok.crt"); err == nil {
		t.Fatal("replacement sync failure was accepted")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "old" {
		t.Fatalf("replacement escaped failed sync: %q, %v", data, err)
	}
}

func TestRepairESPRestoresPriorStageAfterPostRenameSyncFailure(t *testing.T) {
	root := repairFixture(t, "old", "new")
	target := filepath.Join(root, "boot/efi/EFI/BOOT/grubx64.efi")
	oldSync, oldRun := syncFile, runner.RunFn
	var calls []string
	syncFile = func(file *os.File) error {
		calls = append(calls, file.Name())
		if len(calls) == 2 {
			return errors.New("post-rename sync failed")
		}
		return nil
	}
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }
	t.Cleanup(func() { syncFile, runner.RunFn = oldSync, oldRun })
	if err := RepairESP(root, "/usr/lib/snosi/mok.crt"); err == nil {
		t.Fatal("post-rename sync failure accepted")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "old" {
		t.Fatalf("restored stage = %q, %v", data, err)
	}
	if len(calls) != 4 {
		t.Fatalf("sync calls = %d, want replacement, failed directory, restore, directory", len(calls))
	}
}

func TestRepairESPReportsRestoreFailureAfterPostRenameSyncFailure(t *testing.T) {
	root := repairFixture(t, "old", "new")
	oldSync, oldRun := syncFile, runner.RunFn
	call := 0
	syncFile = func(*os.File) error {
		call++
		if call == 2 {
			return errors.New("post-rename sync failed")
		}
		if call == 3 {
			return errors.New("restore sync failed")
		}
		return nil
	}
	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return nil }
	t.Cleanup(func() { syncFile, runner.RunFn = oldSync, oldRun })
	err := RepairESP(root, "/usr/lib/snosi/mok.crt")
	if err == nil || !strings.Contains(err.Error(), "restoring previous systemd-boot stage") {
		t.Fatalf("error = %v", err)
	}
}

func repairFixture(t *testing.T, old, new string) string {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"usr/lib/snosi/bootc", "boot/efi/EFI/BOOT", "boot/efi/EFI/Linux", "boot/efi/loader/entries"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{"usr/lib/snosi/mok.crt", "boot/efi/EFI/BOOT/BOOTX64.EFI", "boot/efi/EFI/BOOT/mmx64.efi", "boot/efi/EFI/Linux/snosi.efi"} {
		if err := os.WriteFile(filepath.Join(root, path), []byte("efi"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/snosi/bootc/systemd-bootx64.efi"), []byte(new), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/EFI/BOOT/grubx64.efi"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "boot/efi/loader/entries/snosi.conf"), []byte("efi /EFI/Linux/snosi.efi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}
