package disk_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/disk"
	"github.com/tuna-os/fisherman/internal/runner"
)

// ── FormatEFI ─────────────────────────────────────────────────────────────

func TestFormatEFI(t *testing.T) {
	rec := setupRecorder(t)
	if err := disk.FormatEFI("/dev/sda1"); err != nil {
		t.Fatalf("FormatEFI: %v", err)
	}
	assertSingleCall(t, rec, "mkfs.fat", []string{"-F32", "-n", "EFI-SYSTEM", "/dev/sda1"})
}

// ── FormatBoot ────────────────────────────────────────────────────────────

func TestFormatBoot(t *testing.T) {
	rec := setupRecorder(t)
	if err := disk.FormatBoot("/dev/sda2"); err != nil {
		t.Fatalf("FormatBoot: %v", err)
	}
	assertSingleCall(t, rec, "mkfs.ext4", []string{"-L", "boot", "-F", "/dev/sda2"})
}

// ── FormatVar ─────────────────────────────────────────────────────────────

// TestFormatVar is a regression test for the two-disk /var install: a disk
// reused from a previous full install still carries a GPT partition table
// (the backup header sits at the end of the disk, out of mkfs.xfs's reach),
// so FormatVar must wipe all signatures before formatting.
func TestFormatVar(t *testing.T) {
	rec := setupRecorder(t)
	if err := disk.FormatVar("/dev/vdb"); err != nil {
		t.Fatalf("FormatVar: %v", err)
	}
	if len(rec.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %+v", len(rec.calls), rec.calls)
	}
	if rec.calls[0].name != "wipefs" || !equalSlice(rec.calls[0].args, []string{"-a", "/dev/vdb"}) {
		t.Errorf("call 0 = %s %v, want wipefs [-a /dev/vdb]", rec.calls[0].name, rec.calls[0].args)
	}
	if rec.calls[1].name != "mkfs.xfs" || !equalSlice(rec.calls[1].args, []string{"-f", "-L", "var", "/dev/vdb"}) {
		t.Errorf("call 1 = %s %v, want mkfs.xfs [-f -L var /dev/vdb]", rec.calls[1].name, rec.calls[1].args)
	}
}

// ── FSType ────────────────────────────────────────────────────────────────

// TestFSType covers the keepExisting preflight: a whole-disk filesystem
// reports its TYPE; a partitioned disk (blkid emits only PTTYPE, so the TYPE
// query returns nothing) and a blank disk (blkid exits non-zero) both yield "".
func TestFSType(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
		want string
	}{
		{name: "whole-disk xfs", out: "xfs\n", want: "xfs"},
		{name: "partitioned disk", out: "", want: ""},
		{name: "blank disk", err: fmt.Errorf("blkid: exit status 2"), want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := runner.OutputFn
			runner.OutputFn = func(name string, args ...string) ([]byte, error) {
				if name != "blkid" {
					t.Errorf("command = %q, want blkid", name)
				}
				if !equalSlice(args, []string{"-s", "TYPE", "-o", "value", "/dev/vdb"}) {
					t.Errorf("args = %v, want [-s TYPE -o value /dev/vdb]", args)
				}
				return []byte(tt.out), tt.err
			}
			t.Cleanup(func() { runner.OutputFn = old })

			if got := disk.FSType("/dev/vdb"); got != tt.want {
				t.Errorf("FSType = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── FormatRoot ────────────────────────────────────────────────────────────

func TestFormatRoot(t *testing.T) {
	tests := []struct {
		name       string
		filesystem string
		wantName   string
		wantArgs   []string
		wantErr    bool
	}{
		{
			name:       "xfs",
			filesystem: "xfs",
			wantName:   "mkfs.xfs",
			wantArgs:   []string{"-f", "-L", "root", "/dev/sda3"},
		},
		{
			name:       "ext4",
			filesystem: "ext4",
			wantName:   "mkfs.ext4",
			wantArgs:   []string{"-F", "-L", "root", "-O", "verity", "/dev/sda3"},
		},
		{
			name:       "btrfs",
			filesystem: "btrfs",
			wantName:   "mkfs.btrfs",
			wantArgs:   []string{"-f", "-L", "root", "/dev/sda3"},
		},
		{
			name:       "unsupported empty",
			filesystem: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := setupRecorder(t)
			err := disk.FormatRoot("/dev/sda3", tt.filesystem)
			if tt.wantErr {
				if err == nil {
					t.Errorf("FormatRoot(%q): expected error, got nil", tt.filesystem)
				}
				return
			}
			if err != nil {
				t.Fatalf("FormatRoot: %v", err)
			}
			assertSingleCall(t, rec, tt.wantName, tt.wantArgs)
		})
	}
}

// ── SetupBtrfsSubvolumes ──────────────────────────────────────────────────

func TestSetupBtrfsSubvolumes(t *testing.T) {
	rec := setupRecorder(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "target")

	if err := disk.SetupBtrfsSubvolumes("/dev/sda3", target); err != nil {
		t.Fatalf("SetupBtrfsSubvolumes: %v", err)
	}

	// Collect btrfs subvolume create and set-default calls.
	var subvolCalls []execCall
	var setDefaultCalls []execCall
	for _, c := range rec.calls {
		if c.name != "btrfs" {
			continue
		}
		if len(c.args) >= 2 && c.args[1] == "set-default" {
			setDefaultCalls = append(setDefaultCalls, c)
		} else {
			subvolCalls = append(subvolCalls, c)
		}
	}

	if len(subvolCalls) != 3 {
		t.Fatalf("expected 3 btrfs subvolume create calls, got %d (all calls: %+v)", len(subvolCalls), rec.calls)
	}

	// Must be created in order: @, @home, @snapshots.
	wantSubvols := []string{"@", "@home", "@snapshots"}
	for i, sv := range wantSubvols {
		c := subvolCalls[i]
		wantArgs := []string{"subvolume", "create", target + "/" + sv}
		if !equalSlice(c.args, wantArgs) {
			t.Errorf("subvol call %d args = %v, want %v", i, c.args, wantArgs)
		}
	}

	// @ must be set as the default subvolume so systemd GPT auto-discovery
	// mounts it at boot instead of the btrfs top-level. Without this the
	// install-time bug relocates to first boot (state/deploy not found).
	if len(setDefaultCalls) != 1 {
		t.Fatalf("expected 1 btrfs subvolume set-default call, got %d (all calls: %+v)", len(setDefaultCalls), rec.calls)
	}
	wantSetDefault := []string{"subvolume", "set-default", target + "/@"}
	if !equalSlice(setDefaultCalls[0].args, wantSetDefault) {
		t.Errorf("set-default args = %v, want %v", setDefaultCalls[0].args, wantSetDefault)
	}

	// Final mount must use subvol=@ and zstd compression.
	var finalMount *execCall
	for i := len(rec.calls) - 1; i >= 0; i-- {
		c := rec.calls[i]
		if c.name == "mount" && !contains(c.args, "--bind") && !contains(c.args, "-R") {
			finalMount = &rec.calls[i]
			break
		}
	}
	if finalMount == nil {
		t.Fatal("no final mount call found")
	}
	opts := ""
	for i, arg := range finalMount.args {
		if arg == "-o" && i+1 < len(finalMount.args) {
			opts = finalMount.args[i+1]
			break
		}
	}
	if !strings.Contains(opts, "subvol=@") {
		t.Errorf("final mount opts %q missing subvol=@", opts)
	}
	if !strings.Contains(opts, "compress=zstd:1") {
		t.Errorf("final mount opts %q missing compress=zstd:1", opts)
	}
}

// ── RemountRoot ───────────────────────────────────────────────────────────

// TestRemountRoot is a regression test for the btrfs-subvolume install that
// aborted at 99% ("finding composefs deploy etc: reading composefs deploy base
// …/state/deploy: no such file or directory"). After retagging the root GPT
// type for systemd-boot GPT auto-discovery, the root partition is remounted;
// for btrfs subvolume installs it MUST be remounted with subvol=@ so post-install
// writes reach the @ subvolume where the composefs deployment lives. A bare
// remount exposes the btrfs top-level, where state/deploy does not exist.
func TestRemountRoot(t *testing.T) {
	tests := []struct {
		name         string
		btrfsSubvols bool
		wantOpts     bool // whether -o <opts> should be present
	}{
		{name: "btrfs subvolumes preserves subvol=@", btrfsSubvols: true, wantOpts: true},
		{name: "non-subvolume remounts bare", btrfsSubvols: false, wantOpts: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := setupRecorder(t)
			if err := disk.RemountRoot("/dev/nvme0n1", 2, "/mnt/fisherman-target", tt.btrfsSubvols); err != nil {
				t.Fatalf("RemountRoot: %v", err)
			}
			if len(rec.calls) != 1 {
				t.Fatalf("expected 1 call, got %d: %+v", len(rec.calls), rec.calls)
			}
			c := rec.calls[0]
			if c.name != "mount" {
				t.Errorf("name = %q, want mount", c.name)
			}
			if c.args[len(c.args)-2] != "/dev/nvme0n1p2" {
				t.Errorf("device arg = %q, want /dev/nvme0n1p2", c.args[len(c.args)-2])
			}
			if c.args[len(c.args)-1] != "/mnt/fisherman-target" {
				t.Errorf("target arg = %q, want /mnt/fisherman-target", c.args[len(c.args)-1])
			}
			opts := ""
			for i, arg := range c.args {
				if arg == "-o" && i+1 < len(c.args) {
					opts = c.args[i+1]
					break
				}
			}
			if tt.wantOpts {
				if !strings.Contains(opts, "subvol=@") {
					t.Errorf("btrfs remount opts %q missing subvol=@", opts)
				}
				if !strings.Contains(opts, "compress=zstd:1") {
					t.Errorf("btrfs remount opts %q missing compress=zstd:1", opts)
				}
			} else if opts != "" {
				t.Errorf("non-subvolume remount should have no -o opts, got %q", opts)
			}
		})
	}
}

// ── BindMount / scratch space ─────────────────────────────────────────────

// TestBindMount verifies that BindMount calls mount --bind with the correct args.
func TestBindMount(t *testing.T) {
	rec := setupRecorder(t)

	dir := t.TempDir()
	src := "/var/fisherman-tmp"
	dst := filepath.Join(dir, "var", "tmp")

	if err := disk.BindMount(src, dst); err != nil {
		t.Fatalf("BindMount: %v", err)
	}

	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 call, got %d: %+v", len(rec.calls), rec.calls)
	}
	c := rec.calls[0]
	if c.name != "mount" {
		t.Errorf("name = %q, want mount", c.name)
	}
	wantArgs := []string{"--bind", src, dst}
	if !equalSlice(c.args, wantArgs) {
		t.Errorf("args = %v, want %v", c.args, wantArgs)
	}
}

// TestBindMount_ScratchSpacePath is a regression test for the scratch-space
// location. The bind mount source must be under /var/ (disk-backed), not /run/
// (tmpfs, ~50% RAM, too small for large bootc image blobs like 3.7 GB images).
func TestBindMount_ScratchSpacePath(t *testing.T) {
	rec := setupRecorder(t)

	dir := t.TempDir()
	// These are the exact values used in cmd/fisherman/main.go.
	scratchDir := "/var/fisherman-tmp"
	bindDst := filepath.Join(dir, "var", "tmp") // substitute temp dir for /var/tmp

	if err := disk.BindMount(scratchDir, bindDst); err != nil {
		t.Fatalf("BindMount: %v", err)
	}

	c := rec.calls[0]

	// src must be /var/fisherman-tmp, not /run/fisherman-tmp or similar.
	if c.args[1] != scratchDir {
		t.Errorf("bind src = %q, want %q", c.args[1], scratchDir)
	}
	if strings.HasPrefix(c.args[1], "/run/") {
		t.Errorf("scratch dir %q must not be under /run/ (tmpfs, too small); must be under /var/", c.args[1])
	}
	if !strings.HasPrefix(c.args[1], "/var/") {
		t.Errorf("scratch dir %q should be under /var/ (disk-backed)", c.args[1])
	}
}

// ── helpers ───────────────────────────────────────────────────────────────

func assertSingleCall(t *testing.T, rec *recorder, wantName string, wantArgs []string) {
	t.Helper()
	if len(rec.calls) != 1 {
		t.Fatalf("expected 1 call, got %d: %+v", len(rec.calls), rec.calls)
	}
	c := rec.calls[0]
	if c.name != wantName {
		t.Errorf("name = %q, want %q", c.name, wantName)
	}
	if !equalSlice(c.args, wantArgs) {
		t.Errorf("args = %v, want %v", c.args, wantArgs)
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
