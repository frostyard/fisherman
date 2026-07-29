package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/install"
	"github.com/tuna-os/fisherman/internal/post"
	"github.com/tuna-os/fisherman/internal/recipe"
)

func TestAcceptSecureImagePinsOnlyInstallSource(t *testing.T) {
	oldInspect, oldVerify := install.SkopeoInspectFn, install.CosignVerifyFn
	t.Cleanup(func() { install.SkopeoInspectFn, install.CosignVerifyFn = oldInspect, oldVerify })
	install.SkopeoInspectFn = func(_ ...string) ([]byte, error) {
		return []byte(`{"Digest":"sha256:accepted","Labels":{"io.snosi.bootc.secureboot-capable":"true"}}`), nil
	}
	install.CosignVerifyFn = func(_, _ string) error { return nil }

	r := &recipe.Recipe{
		Image:        "ghcr.io/frostyard/cayo:20260729000000",
		TargetImgref: "ghcr.io/frostyard/cayo:stable",
		CosignPubKey: "/keys/cosign.pub",
	}
	if err := acceptSecureImage(r); err != nil {
		t.Fatal(err)
	}
	if r.Image != "ghcr.io/frostyard/cayo@sha256:accepted" {
		t.Fatalf("image = %q", r.Image)
	}
	if r.TargetImgref != "ghcr.io/frostyard/cayo:stable" {
		t.Fatalf("targetImgref = %q", r.TargetImgref)
	}
}

func TestTargetImgrefForInstallKeepsGenericDedupAndSecureTrackingTag(t *testing.T) {
	image := "ghcr.io/frostyard/cayo:stable"
	if got := targetImgrefForInstall(&recipe.Recipe{Image: image, TargetImgref: image}); got != "" {
		t.Fatalf("generic targetImgref = %q, want empty", got)
	}
	if got := targetImgrefForInstall(&recipe.Recipe{Image: "ghcr.io/frostyard/cayo@sha256:accepted", TargetImgref: image, SecureInstall: &recipe.SecureInstall{}}); got != image {
		t.Fatalf("secure targetImgref = %q, want %q", got, image)
	}
}

// TestExpandPath_AddsSbinDirs verifies that expandPath always ensures the
// standard sbin directories are present in PATH even when pkexec has stripped
// them.
func TestExpandPath_AddsSbinDirs(t *testing.T) {
	orig := os.Getenv("PATH")
	t.Cleanup(func() { os.Setenv("PATH", orig) })

	os.Setenv("PATH", "/usr/bin:/bin") // minimal pkexec PATH
	expandPath()

	got := os.Getenv("PATH")
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin"} {
		if !strings.Contains(got, dir) {
			t.Errorf("expected %q in PATH after expandPath, got: %s", dir, got)
		}
	}
}

// TestExpandPath_PreservesExisting verifies that existing PATH entries are
// kept (not dropped) after expandPath.
func TestExpandPath_PreservesExisting(t *testing.T) {
	orig := os.Getenv("PATH")
	t.Cleanup(func() { os.Setenv("PATH", orig) })

	os.Setenv("PATH", "/custom/bin")
	expandPath()

	if got := os.Getenv("PATH"); !strings.Contains(got, "/custom/bin") {
		t.Errorf("expected /custom/bin to be preserved in PATH, got: %s", got)
	}
}

// TestCheckRequiredTools_AllPresent verifies no error when all tools exist.
func TestCheckRequiredTools_AllPresent(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }

	r := &recipe.Recipe{Filesystem: "xfs"}
	if err := checkRequiredTools(r); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestCheckRequiredTools_MissingXfs verifies a clear error when mkfs.xfs is
// absent and the recipe requests XFS.
func TestCheckRequiredTools_MissingXfs(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) {
		if file == "mkfs.xfs" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}

	r := &recipe.Recipe{Filesystem: "xfs"}
	err := checkRequiredTools(r)
	if err == nil {
		t.Fatal("expected error for missing mkfs.xfs, got nil")
	}
	if !strings.Contains(err.Error(), "mkfs.xfs") {
		t.Errorf("error should mention mkfs.xfs, got: %v", err)
	}
	if !strings.Contains(err.Error(), "xfsprogs") {
		t.Errorf("error should mention xfsprogs package, got: %v", err)
	}
}

// TestCheckRequiredTools_MissingBtrfs verifies a clear error when mkfs.btrfs
// is absent and the recipe requests btrfs.
func TestCheckRequiredTools_MissingBtrfs(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) {
		if file == "mkfs.btrfs" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}

	r := &recipe.Recipe{Filesystem: "btrfs"}
	err := checkRequiredTools(r)
	if err == nil {
		t.Fatal("expected error for missing mkfs.btrfs, got nil")
	}
	if !strings.Contains(err.Error(), "mkfs.btrfs") {
		t.Errorf("error should mention mkfs.btrfs, got: %v", err)
	}
	if !strings.Contains(err.Error(), "btrfs-progs") {
		t.Errorf("error should mention btrfs-progs package, got: %v", err)
	}
}

// TestCheckRequiredTools_BtrfsNotCheckedForXfs verifies that mkfs.btrfs is
// not required when the recipe uses xfs.
func TestCheckRequiredTools_BtrfsNotCheckedForXfs(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) {
		if file == "mkfs.btrfs" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}

	r := &recipe.Recipe{Filesystem: "xfs"}
	if err := checkRequiredTools(r); err != nil {
		t.Errorf("mkfs.btrfs should not be checked for xfs recipe, got: %v", err)
	}
}

// TestPrepareScratchDir_LiveISORegistersCleanup verifies that live ISO scratch
// directories are bound on the target disk and registered for cleanup.
func TestPrepareScratchDir_LiveISORegistersCleanup(t *testing.T) {
	oldCleanup := cleanup
	cleanup = &post.Cleanup{}
	t.Cleanup(func() { cleanup = oldCleanup })

	oldBindMount := bindMount
	bindMount = func(src, dst string) error { return nil }
	t.Cleanup(func() { bindMount = oldBindMount })

	oldRemoveAll := post.RemoveAllFn
	var removed []string
	post.RemoveAllFn = func(path string) error {
		removed = append(removed, path)
		return nil
	}
	t.Cleanup(func() { post.RemoveAllFn = oldRemoveAll })

	targetRoot := filepath.Join(t.TempDir(), "fisherman-target")
	scratchDir, err := prepareScratchDir(targetRoot, true)
	if err != nil {
		t.Fatalf("prepareScratchDir returned error: %v", err)
	}
	if scratchDir != filepath.Join(targetRoot, ".fisherman-scratch") {
		t.Fatalf("scratchDir = %q, want target-backed scratch path", scratchDir)
	}

	cleanup.Run()
	if len(removed) != 1 || removed[0] != scratchDir {
		t.Fatalf("removeAll calls = %v, want [%q]", removed, scratchDir)
	}
}

// TestCheckRequiredTools_MissingCryptsetupForLUKS verifies that cryptsetup is
// required when a LUKS passphrase encryption type is selected.
func TestCheckRequiredTools_MissingCryptsetupForLUKS(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) {
		if file == "cryptsetup" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}

	r := &recipe.Recipe{
		Filesystem: "xfs",
		Encryption: recipe.Encryption{Type: "luks-passphrase", Passphrase: "hunter2"},
	}
	err := checkRequiredTools(r)
	if err == nil {
		t.Fatal("expected error for missing cryptsetup, got nil")
	}
	if !strings.Contains(err.Error(), "cryptsetup") {
		t.Errorf("error should mention cryptsetup, got: %v", err)
	}
}

// TestCheckRequiredTools_MissingSystemdCryptenrollForTPM2 verifies that
// systemd-cryptenroll is required for TPM2 encryption types, and that the
// check fires before any disk is touched.
func TestCheckRequiredTools_MissingSystemdCryptenrollForTPM2(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) {
		if file == "systemd-cryptenroll" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}

	for _, encType := range []string{"tpm2-luks", "tpm2-luks-passphrase"} {
		r := &recipe.Recipe{
			Filesystem: "xfs",
			Encryption: recipe.Encryption{Type: encType, Passphrase: "hunter2"},
		}
		err := checkRequiredTools(r)
		if err == nil {
			t.Fatalf("encType=%s: expected error for missing systemd-cryptenroll, got nil", encType)
		}
		if !strings.Contains(err.Error(), "systemd-cryptenroll") {
			t.Errorf("encType=%s: error should mention systemd-cryptenroll, got: %v", encType, err)
		}
		if !strings.Contains(err.Error(), "systemd") {
			t.Errorf("encType=%s: error should mention systemd package, got: %v", encType, err)
		}
	}
}

// TestCheckRequiredTools_SystemdCryptenrollNotCheckedForPlainLUKS verifies that
// systemd-cryptenroll is NOT required for plain luks-passphrase (no TPM2).
func TestCheckRequiredTools_SystemdCryptenrollNotCheckedForPlainLUKS(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	lookPath = func(file string) (string, error) {
		if file == "systemd-cryptenroll" {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}

	r := &recipe.Recipe{
		Filesystem: "xfs",
		Encryption: recipe.Encryption{Type: "luks-passphrase", Passphrase: "hunter2"},
	}
	if err := checkRequiredTools(r); err != nil {
		t.Errorf("systemd-cryptenroll should not be checked for luks-passphrase, got: %v", err)
	}
}

func TestSecureRecoveryKeyValidatesExternalFileWithoutReadingSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recovery")
	if err := os.WriteFile(path, []byte("exact-recovery-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &recipe.Recipe{SecureInstall: &recipe.SecureInstall{RecoveryKeyFile: path}}
	if err := validateSecureRecoveryKey(r); err != nil {
		t.Fatalf("validateSecureRecoveryKey() = %v", err)
	}
}

func TestCheckRequiredTools_SecureInstallRequiresArtifactAndEnrollmentTools(t *testing.T) {
	orig := lookPath
	t.Cleanup(func() { lookPath = orig })
	for _, missing := range []string{"objcopy", "sbverify", "mokutil", "systemd-cryptenroll", "openssl", "blkid", "blockdev", "findmnt"} {
		t.Run(missing, func(t *testing.T) {
			lookPath = func(file string) (string, error) {
				if file == missing {
					return "", errors.New("not found")
				}
				return "/usr/bin/" + file, nil
			}
			r := &recipe.Recipe{Filesystem: "btrfs", Encryption: recipe.Encryption{Type: "luks-passphrase"}, SecureInstall: &recipe.SecureInstall{}}
			if err := checkRequiredTools(r); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("missing %s was accepted: %v", missing, err)
			}
		})
	}
}

func TestPartitionDiskUsesSecureDPSLayoutForEncryptedSecureRecipe(t *testing.T) {
	r := &recipe.Recipe{SecureInstall: &recipe.SecureInstall{}, Filesystem: "btrfs", Disk: "/dev/test"}
	called := false
	old := partitionSecureSystemdBoot
	partitionSecureSystemdBoot = func(string) error { called = true; return nil }
	t.Cleanup(func() { partitionSecureSystemdBoot = old })
	if err := partitionDisk(r, true, true); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("secure encrypted recipe did not select DPS systemd layout")
	}
}
