package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tuna-os/fisherman/internal/disk"
	"github.com/tuna-os/fisherman/internal/install"
	"github.com/tuna-os/fisherman/internal/luks"
	"github.com/tuna-os/fisherman/internal/post"
	"github.com/tuna-os/fisherman/internal/progress"
	"github.com/tuna-os/fisherman/internal/recipe"
	"github.com/tuna-os/fisherman/internal/secure"
	"github.com/tuna-os/fisherman/internal/slurp"
)

const (
	defaultTargetMount = "/mnt/fisherman-target"
	defaultLuksMapper  = "fisherman-root"
)

// These are resolved from the recipe in main(); package-level vars rather than
// constants so the rest of this file (which references them by short name)
// stays readable. Tests don't touch these directly — they exercise the helper
// functions in disk/, luks/, post/ which take the paths as arguments.
var (
	targetMount                = defaultTargetMount
	luksMapper                 = defaultLuksMapper
	partitionSecureSystemdBoot = disk.PartitionSecureSystemdBoot
)

func partitionDisk(r *recipe.Recipe, systemdBoot, encrypted bool) error {
	if r.SecureInstall != nil {
		return partitionSecureSystemdBoot(r.Disk)
	}
	if r.Filesystem == "zfs" {
		return disk.PartitionZFS(r.Disk)
	}
	if systemdBoot {
		return disk.PartitionSystemdBoot(r.Disk)
	}
	if encrypted {
		return disk.PartitionEncrypted(r.Disk)
	}
	return disk.Partition(r.Disk)
}

// cleanup is global so fatal() can tear everything down on any error path.
var cleanup = &post.Cleanup{}

// bindMount is disk.BindMount by default; tests replace it to avoid real mounts.
var bindMount = disk.BindMount

type stepProfile struct {
	cumulativePct int
	weightPct     int
}

// buildProfile returns per-step weight profiles based on timing data from a
// yellowfin gnome-hwe loop-device install (264s uncached, ~111s cached).
// Weights sum to 100. cumulativePct is the bar position at step start.
func buildProfile(needsPull, hasLUKS, hasTPM2enrolment, hasVarDiskFormat bool) []stepProfile {
	osWeight := 87
	flatpakWeight := 11
	if !needsPull {
		osWeight = 68
		flatpakWeight = 29
	}
	if hasLUKS {
		osWeight--
	}
	if hasTPM2enrolment {
		osWeight--
	}

	weights := []int{0, 1} // partition, format EFI
	if hasLUKS {
		weights = append(weights, 1) // LUKS setup
	}
	weights = append(weights, 0, 0) // format root, mount
	if hasVarDiskFormat {
		weights = append(weights, 0) // format /var disk (fast)
	}
	weights = append(weights, osWeight) // install OS
	if hasTPM2enrolment {
		weights = append(weights, 1) // TPM2 enrolment
	}
	weights = append(weights, flatpakWeight, 0) // flatpaks, configure
	sum := 0
	for _, w := range weights {
		sum += w
	}
	weights = append(weights, 100-sum) // finalize

	profile := make([]stepProfile, len(weights))
	cumulative := 0
	for i, w := range weights {
		profile[i] = stepProfile{cumulative, w}
		cumulative += w
	}
	return profile
}

func fatal(format string, args ...any) {
	cleanup.Run()
	fmt.Fprintf(os.Stderr, "fisherman: fatal: "+format+"\n", args...)
	os.Exit(1)
}

// lookPath is exec.LookPath by default; replaced in tests.
var lookPath = exec.LookPath

// isSpaceConstrained reports whether the given path is on a filesystem that is
// too small for multi-gigabyte scratch I/O. This covers:
//   - tmpfs: RAM-backed, used by some live ISOs for /var
//   - overlayfs: used by dmsquash-live (dracut) live ISOs where / and /var
//     are an overlay on top of a squashfs; the writable upper layer has only
//     a few GiB available
func isSpaceConstrained(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	const (
		tmpfsMagic   = 0x01021994
		overlayMagic = 0x794c7630
	)
	return st.Type == tmpfsMagic || st.Type == overlayMagic
}

func prepareScratchDir(activeTargetMount string, liveISO bool) (string, error) {
	scratchDir := "/var/fisherman-tmp"
	if liveISO {
		scratchDir = filepath.Join(activeTargetMount, ".fisherman-scratch")
		progress.Info("Live environment detected (/var is space-constrained) — using target disk for scratch I/O")
	}
	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		return "", err
	}
	if liveISO {
		// Self-bind so bootc sees a mount point, not a plain directory.
		if err := bindMount(scratchDir, scratchDir); err != nil {
			return "", err
		}
		cleanup.AddMount(scratchDir)
		// Removal is registered as a post-removal so it runs *after* the
		// unmount above and after the LUKS close — and crucially it still
		// fires on the fatal() error path, where os.Exit(1) would otherwise
		// skip a deferred RemoveAll and leak the OCI cache on the target disk.
		cleanup.AddPostRemoval(scratchDir)
	}
	return scratchDir, nil
}

// expandPath prepends standard sbin directories and any tools staged alongside
// this binary to PATH.  pkexec strips the user's PATH to a minimal safe set
// that omits /usr/sbin and /sbin on many immutable distros (e.g. GnomeOS).
func expandPath() {
	current := os.Getenv("PATH")
	// Build candidate prefix: staged tools dir (sibling of this binary) first,
	// then the standard sbin locations that pkexec commonly strips.
	prefix := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if exe, err := os.Executable(); err == nil {
		toolsDir := filepath.Join(filepath.Dir(exe), "tools")
		if info, err := os.Stat(toolsDir); err == nil && info.IsDir() {
			prefix = toolsDir + ":" + prefix
		}
	}
	if current != "" {
		prefix = prefix + ":" + current
	}
	os.Setenv("PATH", prefix)
}

func validateSecureRecoveryKey(r *recipe.Recipe) error {
	if r.SecureInstall == nil {
		return nil
	}
	if err := secure.ValidatePrivateRegularFile(r.SecureInstall.RecoveryKeyFile); err != nil {
		return fmt.Errorf("validating secure recovery key: %w", err)
	}
	info, err := os.Lstat(r.SecureInstall.RecoveryKeyFile)
	if err != nil {
		return fmt.Errorf("stating secure recovery key: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("secure recovery key is empty")
	}
	return nil
}

// acceptSecureImage pins only the image used during installation. The
// validated targetImgref remains the day-2 update reference passed to bootc.
func acceptSecureImage(r *recipe.Recipe) error {
	pinned, err := secure.AcceptImage(r.Image, r.CosignPubKey)
	if err != nil {
		return err
	}
	r.Image = pinned
	return nil
}

func targetImgrefForInstall(r *recipe.Recipe) string {
	if r.SecureInstall == nil && r.TargetImgref == r.Image {
		return ""
	}
	return r.TargetImgref
}

// checkRequiredTools verifies that every host binary needed by this recipe
// is reachable on PATH before we touch any disks, and returns a clear error
// naming the missing tool and the package that provides it.
func checkRequiredTools(r *recipe.Recipe) error {
	type requirement struct {
		tool string
		pkg  string
		when bool
	}
	reqs := []requirement{
		{"sfdisk", "util-linux", true},
		{"mkfs.fat", "dosfstools", true},
		{"mkfs.ext4", "e2fsprogs", true},
		{"mkfs.xfs", "xfsprogs", r.Filesystem == "xfs"},
		{"mkfs.btrfs", "btrfs-progs", r.Filesystem == "btrfs"},
		{"zpool", "zfsutils-linux", r.Filesystem == "zfs"},
		{"zfs", "zfsutils-linux", r.Filesystem == "zfs"},
		{"cryptsetup", "cryptsetup", r.Encryption.Type != "" && r.Encryption.Type != "none"},
		// systemd-cryptenroll is required for TPM2 auto-unlock enrolment.
		// Check before touching any disks — a missing tool at step 9 (after
		// partitioning and OS install) would leave the disk partially modified.
		{"systemd-cryptenroll", "systemd", r.Encryption.Type == "tpm2-luks" || r.Encryption.Type == "tpm2-luks-passphrase"},
		{"systemd-cryptenroll", "systemd", r.SecureInstall != nil},
		{"sbverify", "sbsigntool", r.SecureInstall != nil},
		{"mokutil", "mokutil", r.SecureInstall != nil},
		{"openssl", "openssl", r.SecureInstall != nil},
		{"blkid", "util-linux", r.SecureInstall != nil},
		{"blockdev", "util-linux", r.SecureInstall != nil},
		{"findmnt", "util-linux", r.SecureInstall != nil},
		{"skopeo", "skopeo", true},
		{"podman", "podman", true},
	}
	for _, req := range reqs {
		if !req.when {
			continue
		}
		if _, err := lookPath(req.tool); err != nil {
			return fmt.Errorf("%q not found in PATH — install the %q package on the host", req.tool, req.pkg)
		}
	}
	return nil
}

var version = "dev"

func printHelp() {
	fmt.Printf(`fisherman — bootc disk installer backend

Usage:
  fisherman <recipe.json>          run an installation from a recipe file
  fisherman validate <recipe.json> validate a recipe without installing
  fisherman images [<query>]       list or search the image catalog
  fisherman scan <disk>            scan disk for Windows data available to migrate
  fisherman secure-restage-mok <target-root> <recovery-key-file> <mok-password-file>
                                  restage only MOK enrollment for an installed secure system
  fisherman secure-repair-esp <target-root> <recovery-key-file>
                                  repair only the secure ESP second stage
  fisherman version                print version information
  fisherman help                   show this help

Options for 'images':
  --file <path>   use a specific images.json instead of auto-detecting
  --plain         plain text output (no ANSI color or tree characters)

Examples:
  fisherman /tmp/recipe.json
  fisherman validate /tmp/recipe.json
  fisherman images
  fisherman images Bluefin
  fisherman images "GNOME 50"
  fisherman images --plain yellowfin
  fisherman scan /dev/nvme0n1
`)
}

func runSecureOperation(operation string, args []string) {
	want := 2
	if operation == "secure-restage-mok" {
		want = 3
	}
	if len(args) != want {
		if operation == "secure-restage-mok" {
			fatal("usage: fisherman %s <target-root> <recovery-key-file> <mok-password-file>", operation)
		}
		fatal("usage: fisherman %s <target-root> <recovery-key-file>", operation)
	}
	root, recovery := args[0], args[1]
	contract, err := secure.LoadInstalledContract(root)
	if err != nil {
		fatal("validating installed secure state: %v", err)
	}
	backing, err := secure.ResolveTargetRootBackingDevice(root)
	if err != nil {
		fatal("resolving secure LUKS backing device: %v", err)
	}
	if operation == "secure-restage-mok" {
		if err := secure.RestageMOK(root, contract, recovery, args[2], backing); err != nil {
			fatal("secure MOK restage: %v", err)
		}
		return
	}
	if err := secure.AuthenticateRecovery(recovery, backing); err != nil {
		fatal("authenticating secure ESP repair: %v", err)
	}
	// The recovery operations run against an already-installed system, where no
	// source image is available: target root serves as both roots. This carries
	// the same composefs limitation noted on RestageMOK.
	if err := secure.RepairESP(root, root, contract.MOKCertificate); err != nil {
		fatal("secure ESP repair: %v", err)
	}
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		printHelp()
		return
	case "version", "--version":
		fmt.Printf("fisherman %s\n", version)
		return
	case "images":
		runImages(os.Args[2:])
		return
	case "validate":
		runValidate(os.Args[2:])
		return
	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fisherman scan <disk>\n")
			os.Exit(1)
		}
		output, err := slurp.ScanJSON(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(output)
		return
	case "secure-restage-mok", "secure-repair-esp":
		runSecureOperation(os.Args[1], os.Args[2:])
		return
	}

	r, err := recipe.Load(os.Args[1])
	if err != nil {
		fatal("loading recipe: %v", err)
	}
	if err := r.Validate(); err != nil {
		fatal("invalid recipe: %v", err)
	}
	if err := validateSecureRecoveryKey(r); err != nil {
		fatal("invalid secure recovery credential: %v", err)
	}
	// Declared here so the detected versions survive to the provenance record
	// written much later in this function.
	var secureVersions secure.VersionResult
	// Destination for the image's usr/lib/snosi and usr/lib/shim subtrees. main
	// owns the directory's lifetime; BootcInstall fills it, because only that
	// package knows the store paths the extraction needs.
	//
	// EVERYTHING the secure path reads from under /usr must come from here, not
	// from activeTargetMount: a composefs deployment exposes no /usr tree on the
	// target. That is the contract, the PCR public key, the MOK certificate, the
	// signed second stage, shim and MokManager. Only boot/efi and var are
	// genuinely on the target. This has now been got wrong twice -- the MOK
	// certificate reads were missed when the rest were converted -- so check
	// this list before adding a read.
	var secureImageRoot string
	if r.SecureInstall != nil {
		secureImageRoot, err = os.MkdirTemp("", "fisherman-secure-image-")
		if err != nil {
			fatal("staging secure artifact root: %v", err)
		}
		// Public artifacts only -- contract, MOK certificate, PCR public key,
		// signed second stage. No secret ever lands here.
		defer os.RemoveAll(secureImageRoot)
	}
	if r.SecureInstall != nil {
		luksMapper = "root"
		if err := secure.ValidateDiskSize(r.Disk); err != nil {
			fatal("secure target capacity: %v", err)
		}
		secureVersions, err = secure.ValidateVersions()
		if err != nil {
			fatal("secure installer prerequisites: %v", err)
		}
		// Above-floor but unvalidated combinations install and warn. Silence
		// here would mean the relaxation from exact pins to floors quietly
		// removed the signal that the stack moved.
		for _, warning := range secureVersions.Warnings {
			fmt.Fprintf(os.Stderr, "fisherman: warning: %s\n", warning)
			progress.Secure("version_unvalidated", warning)
		}
		if _, err := os.Stat("/etc/containers/policy.json"); err != nil {
			fatal("secure OCI policy: %v", err)
		}
		if err := acceptSecureImage(r); err != nil {
			fatal("secure image acceptance: %v", err)
		}
		progress.Secure("oci_acceptance", "passed")
	}

	// Recipe-level overrides for the otherwise-shared global mount paths.
	// Keeps two parallel installs on the same host from colliding.
	if r.TargetMount != "" {
		targetMount = r.TargetMount
	}
	if r.LuksMapperName != "" {
		luksMapper = r.LuksMapperName
	}

	// Log fisherman version for CI diagnostics
	fmt.Fprintf(os.Stderr, "[fisherman] version: %s\n", version)

	// Expand PATH to cover all standard sbin locations and any tools staged
	// alongside this binary (e.g. by the tuna-installer Flatpak).  pkexec
	// strips the calling user's PATH to a minimal safe set which often omits
	// /usr/sbin and /sbin on some immutable distros.
	expandPath()

	// Pre-flight: verify that every host tool required for this recipe is
	// present before we touch any disks.
	if err := checkRequiredTools(r); err != nil {
		fatal("missing required host tool: %v", err)
	}

	hasEncryption := r.Encryption.Type != "" && r.Encryption.Type != "none"
	hasTPM2 := r.Encryption.Type == "tpm2-luks" || r.Encryption.Type == "tpm2-luks-passphrase"
	isManual := len(r.CustomMounts) > 0
	isSystemdBoot := r.Bootloader == "systemd" || r.Filesystem == "zfs"

	// ── Pre-flight: check image cache ─────────────────────────────────────────
	var imageCheck install.ImageCheck
	if r.Image != "" {
		progress.Info("Checking image cache...")
		imageCheck = install.CheckImage(r.Image)
		if imageCheck.NeedsPull {
			progress.Info(fmt.Sprintf("Image pull required (%d layers)", imageCheck.LayerCount))
		} else if imageCheck.Offline {
			progress.Info("Offline: registry unreachable, using locally cached image")
		} else {
			progress.Info("Image already up to date in local cache")
		}
	}

	profile := buildProfile(imageCheck.NeedsPull, hasEncryption, hasTPM2, r.VarDisk != nil && !r.VarDisk.KeepExisting)
	pi := 0 // profile index, incremented at each progress.Step call

	// Compute total step count up front so the GUI can show accurate progress.
	// Manual layouts collapse the 4 auto disk-setup steps into a single step.
	totalSteps := 8
	if isManual {
		totalSteps -= 3 // partition + format EFI + format root collapse into one step
	}
	if hasEncryption && !isManual {
		totalSteps++ // extra step for LUKS setup (auto mode only)
	}
	if hasTPM2 {
		totalSteps++ // extra step for TPM2 enrolment (both tpm2-luks and tpm2-luks-passphrase)
	}
	hasVarDisk := r.VarDisk != nil
	if hasVarDisk && !r.VarDisk.KeepExisting {
		totalSteps++ // extra step to format the /var disk
	}
	step := 1

	// Preflight: keepExisting mounts the raw /var device as-is, which only
	// works when the disk carries a whole-disk filesystem. A disk holding a
	// partition table (e.g. a previous full install) has nothing mountable at
	// the raw device, and the mount at step 5.5 would fail AFTER the system
	// disk has already been wiped. Fail here instead, before anything
	// destructive happens.
	if hasVarDisk && r.VarDisk.KeepExisting {
		if fstype := disk.FSType(r.VarDisk.Disk); fstype == "" {
			fatal("varDisk: keepExisting is set but %s has no whole-disk filesystem (it holds a partition table or is blank) — format the /var disk or disable keep-existing", r.VarDisk.Disk)
		}
	}

	// ── Immediate: Apply friendly audio names to live session ─────────────
	// Detect hardware, rename ugly ALSA names, hide S/PDIF etc. Takes effect
	// immediately via WirePlumber restart. Non-fatal.
	if err := post.ApplyAudioConfigLive(); err != nil {
		progress.Info(fmt.Sprintf("Live audio config skipped: %v", err))
	}

	// ── Pre-partition: Wallpaper slurp (easter egg) ──────────────────────────
	// Extract Windows wallpapers from any NTFS partition on the target disk
	// before partitioning destroys them. Held in RAM (/run). Entirely non-fatal.
	var wallpaperResult *slurp.WallpaperResult
	var dataResult *slurp.DataSlurpResult

	if r.Slurp != nil && !isManual {
		// Full data slurp: user selected specific categories in the GUI
		progress.Info("Migrating Windows user data before partitioning...")
		cfg := &slurp.SlurpConfig{
			SourcePartition: r.Slurp.SourcePartition,
		}
		for _, u := range r.Slurp.Users {
			cfg.Users = append(cfg.Users, slurp.SlurpUserConfig{
				Name:       u.Name,
				Categories: u.Categories,
			})
		}
		result, err := slurp.ExtractData(cfg)
		if err != nil {
			progress.Info(fmt.Sprintf("Data migration skipped: %v", err))
		} else {
			dataResult = result
		}
	} else if r.SlurpWallpapers && !isManual {
		// Wallpaper-only easter egg (no explicit slurp config)
		progress.Info("Checking for Windows wallpapers to migrate...")
		ntfsPartitions, err := slurp.DetectNTFS(r.Disk)
		if err != nil {
			progress.Info(fmt.Sprintf("NTFS detection skipped: %v", err))
		} else if len(ntfsPartitions) > 0 {
			progress.Info(fmt.Sprintf("Found %d NTFS partition(s), extracting wallpapers", len(ntfsPartitions)))
			for _, part := range ntfsPartitions {
				result, err := slurp.ExtractWallpapers(part)
				if err != nil {
					progress.Info(fmt.Sprintf("Wallpaper extraction from %s skipped: %v", part, err))
					continue
				}
				if result.Found {
					wallpaperResult = result
					break // take first successful extraction
				}
			}
		}
		if wallpaperResult == nil {
			progress.Info("No Windows wallpapers found — continuing normally")
		}
	}

	var activeTargetMount string
	var activeEfiPart string
	var activeRootPart string  // only used for TPM2 enrolment, empty in manual mode
	var activeLuksUUID string  // LUKS partition UUID for boot entry injection; empty if no encryption
	var luksRecoveryKey string // random passphrase for tpm2-luks (emitted as recovery key)

	if isManual {
		// ── Step 1 (manual): Format and mount user-specified partitions ────────
		progress.Step(step, totalSteps, "Preparing disk", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		specs := make([]disk.MountSpec, 0, len(r.CustomMounts))
		for _, cm := range r.CustomMounts {
			specs = append(specs, disk.MountSpec{
				Partition: cm.Partition,
				Target:    cm.Target,
				Fstype:    cm.Fstype,
			})
		}

		var mountedPaths []string
		var applyErr error
		activeTargetMount, activeEfiPart, mountedPaths, applyErr = disk.ApplyCustomLayout(specs, targetMount)
		if applyErr != nil {
			fatal("manual disk layout: %v", applyErr)
		}
		for _, p := range mountedPaths {
			cleanup.AddMount(p)
		}
	} else {
		// ── Step 1: Partition disk ────────────────────────────────────────────
		progress.Step(step, totalSteps, "Partitioning disk", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if err := partitionDisk(r, isSystemdBoot, hasEncryption); err != nil {
			fatal("partitioning disk: %v", err)
		}

		var efiPart, bootPart, rootPart string
		if isSystemdBoot {
			// 2-partition layout: p1=EFI (1 GiB FAT32), p2=root (or ZFS pool).
			// No separate ext4 /boot needed — systemd-boot reads directly from
			// the FAT32 ESP. LUKS (if any) wraps p2.
			efiPart = disk.PartName(r.Disk, 1)
			rootPart = disk.PartName(r.Disk, 2)
		} else {
			// 3-partition layout: p1=EFI, p2=/boot (ext4), p3=root.
			// The separate ext4 /boot keeps GRUB away from modern XFS features.
			efiPart = disk.PartName(r.Disk, 1)
			bootPart = disk.PartName(r.Disk, 2)
			rootPart = disk.PartName(r.Disk, 3)
		}
		rootDev := rootPart // may be replaced by /dev/mapper/fisherman-root if LUKS
		activeRootPart = rootPart
		poolName := disk.PoolName(r.ZFSPoolName) // only used when r.Filesystem == "zfs"

		// ── Step 2: Format EFI ───────────────────────────────────────────────
		progress.Step(step, totalSteps, "Formatting EFI partition", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if r.SecureInstall != nil {
			if err := secure.ValidateESPSize(efiPart); err != nil {
				fatal("secure ESP capacity: %v", err)
			}
		}
		if err := disk.FormatEFI(efiPart); err != nil {
			fatal("formatting EFI: %v", err)
		}
		// grub2 installs need a separate ext4 /boot so GRUB never has to parse
		// XFS (GRUB's built-in XFS driver lacks support for modern XFS features).
		// systemd-boot reads the FAT32 ESP directly, so no separate /boot needed.
		if !isSystemdBoot {
			if err := disk.FormatBoot(bootPart); err != nil {
				fatal("formatting /boot: %v", err)
			}
		}

		// ── Step 3: Disk encryption (optional) ──────────────────────────────
		if hasEncryption {
			progress.Step(step, totalSteps, "Setting up disk encryption", profile[pi].cumulativePct, profile[pi].weightPct)
			pi++
			step++

			var passphrase string
			switch r.Encryption.Type {
			case "luks-passphrase", "tpm2-luks-passphrase":
				passphrase = r.Encryption.Passphrase
			case "tpm2-luks":
				passphrase = luks.RandomPassphrase()
				luksRecoveryKey = passphrase // emitted later so user can write it down
				progress.Info("TPM2-LUKS: generated random recovery passphrase; TPM2 will be enrolled after install")
			}

			// A previous interrupted run may have left the mapper open. Close it
			// before formatting so luksFormat and luksOpen succeed cleanly.
			if _, err := os.Stat(luks.MapperPath(luksMapper)); err == nil {
				progress.Info(fmt.Sprintf("Closing stale mapper %s from previous run", luksMapper))
				_ = luks.Close(luksMapper)
			}

			var formatErr error
			if r.SecureInstall != nil {
				formatErr = luks.FormatWithKeyFile(rootPart, r.SecureInstall.RecoveryKeyFile)
			} else {
				formatErr = luks.Format(rootPart, passphrase)
			}
			if err := formatErr; err != nil {
				fatal("LUKS format: %v", err)
			}
			var openErr error
			if r.SecureInstall != nil {
				openErr = luks.OpenWithKeyFile(rootPart, r.SecureInstall.RecoveryKeyFile, luksMapper)
			} else {
				openErr = luks.Open(rootPart, passphrase, luksMapper)
			}
			if err := openErr; err != nil {
				fatal("LUKS open: %v", err)
			}
			cleanup.SetLUKS(luksMapper)
			rootDev = luks.MapperPath(luksMapper)
			activeLuksUUID = luks.UUID(rootPart)
			if r.SecureInstall != nil && activeLuksUUID == "" {
				fatal("reading secure LUKS UUID")
			}
		}

		// ── Step 4: Format root filesystem ──────────────────────────────────
		progress.Step(step, totalSteps, "Formatting root filesystem", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if r.Filesystem == "zfs" {
			if err := disk.CreateZFSPool(poolName, rootPart, targetMount); err != nil {
				fatal("creating ZFS pool: %v", err)
			}
			if err := disk.CreateZFSRootDataset(poolName); err != nil {
				fatal("creating ZFS root dataset: %v", err)
			}
		} else {
			if err := disk.FormatRoot(rootDev, r.Filesystem); err != nil {
				fatal("formatting root filesystem: %v", err)
			}
		}

		// ── Step 5: Mount filesystem ─────────────────────────────────────────
		progress.Step(step, totalSteps, "Mounting filesystem", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if err := os.MkdirAll(targetMount, 0o755); err != nil {
			fatal("creating mount point %s: %v", targetMount, err)
		}

		if r.Filesystem == "zfs" {
			// Pool is already imported with -R altroot; root dataset is already
			// mounted. Ensure the mount point exists and call MountZFSRoot in
			// case the automount didn't fire (e.g. in a container environment).
			if err := disk.MountZFSRoot(poolName, targetMount); err != nil {
				fatal("mounting ZFS root: %v", err)
			}
		} else if r.BtrfsSubvolumes {
			if err := disk.SetupBtrfsSubvolumes(rootDev, targetMount); err != nil {
				fatal("setting up btrfs subvolumes: %v", err)
			}
		} else {
			if err := disk.MountType(rootDev, targetMount, r.Filesystem, ""); err != nil {
				fatal("mounting root: %v", err)
			}
		}
		cleanup.AddMount(targetMount)

		// Mount the unencrypted /boot partition before the EFI partition.
		// bootupctl reads /boot's block device UUID from the raw partition.
		// Not needed for systemd-boot installs (no separate /boot partition).
		if !isSystemdBoot {
			if err := disk.MountBoot(targetMount, bootPart); err != nil {
				fatal("mounting /boot: %v", err)
			}
			cleanup.AddMount(targetMount + "/boot")
		}

		// Mount the EFI partition at /boot/efi inside the target.
		if err := disk.MountEFI(targetMount, efiPart); err != nil {
			fatal("mounting EFI: %v", err)
		}
		cleanup.AddMount(targetMount + "/boot/efi")

		activeTargetMount = targetMount
		activeEfiPart = efiPart
	}

	// ── Step 5.5: Mount /var disk (optional) ─────────────────────────────────
	// Must happen before bootc install so bootc populates /var on the right disk.
	if hasVarDisk {
		varDir := filepath.Join(activeTargetMount, "var")
		if err := os.MkdirAll(varDir, 0o755); err != nil {
			fatal("creating /var mount point: %v", err)
		}
		if !r.VarDisk.KeepExisting {
			progress.Step(step, totalSteps, "Formatting data disk (/var)", profile[pi].cumulativePct, profile[pi].weightPct)
			pi++
			step++
			if err := disk.FormatVar(r.VarDisk.Disk); err != nil {
				fatal("formatting /var disk: %v", err)
			}
		} else {
			progress.Info(fmt.Sprintf("Keeping existing data on /var disk %s", r.VarDisk.Disk))
		}
		if err := disk.Mount(r.VarDisk.Disk, varDir, ""); err != nil {
			fatal("mounting /var disk: %v", err)
		}
		cleanup.AddMount(varDir)
		progress.Info(fmt.Sprintf("Mounted /var disk %s at /var", r.VarDisk.Disk))
	}

	// Bind-mount a host-side scratch directory at /var/tmp so bootc has
	// disk-backed space for layer blobs. We deliberately use a path OUTSIDE
	// the target tree so bootc's "empty rootfs" check doesn't find stray
	// directories inside /mnt/fisherman-target.
	//
	// On installed (ostree/conventional) systems /var is always disk-backed,
	// so /var/fisherman-tmp gives us plenty of space. On live ISOs, however,
	// /var lives on a tmpfs that is far too small for multi-gigabyte image
	// blobs. Detect that case and place scratch on the already-formatted
	// target disk instead. A self-bind mount makes bootc's empty-rootdir
	// check see a mount point (which it tolerates) rather than a plain
	// directory (which it rejects).
	liveISO := isSpaceConstrained("/var") && activeTargetMount != ""
	scratchDir, err := prepareScratchDir(activeTargetMount, liveISO)
	if err != nil {
		fatal("preparing scratch dir: %v", err)
	}
	// Note: bootc container gets this directory mounted at /var/tmp via -v flag in podman call.
	// The container runs in its own mount namespace, so the host-level /var/tmp mount is not
	// necessary. We skip it here to avoid conflicts when /var/tmp is already a separate
	// filesystem on the host.
	//
	// For the live-ISO path scratchDir is on the target disk and removal is
	// handled by cleanup.AddPostRemoval (registered in prepareScratchDir),
	// which also fires on the fatal() error path. For the non-live path the
	// directory is /var/fisherman-tmp on the host and is cleaned up here
	// AND via cleanup.AddPostRemoval so it also fires on fatal() paths
	// (os.Exit bypasses defers).
	if !liveISO {
		cleanup.AddPostRemoval(scratchDir)
		defer os.RemoveAll(scratchDir)
	}

	// ── Step 6: Install OS ────────────────────────────────────────────────────
	progress.Step(step, totalSteps, "Installing OS", profile[pi].cumulativePct, profile[pi].weightPct)
	pi++
	step++

	// Secure recipes retain their validated registry tag for day-2 updates while
	// every source operation consumes the accepted digest.
	targetImgref := targetImgrefForInstall(r)

	// ZFS installs must use composefs-backend because bootc's ostree path checks
	// the filesystem type and rejects ZFS; composefs-native bypasses that check.
	composeFsBackend := r.ComposeFsBackend
	if r.Filesystem == "zfs" {
		composeFsBackend = true
	}

	var expectedComposefs string
	cosignKey := r.CosignPubKey
	if r.SecureInstall != nil {
		cosignKey = ""
	}
	if err := install.BootcInstall(install.Options{
		SourceImgref:          r.Image,
		TargetImgref:          targetImgref,
		SelinuxDisabled:       r.SelinuxDisabled,
		CosignKeyPath:         cosignKey,
		UnifiedStorage:        r.UnifiedStorage,
		ComposeFsBackend:      composeFsBackend,
		GenericImage:          r.GenericImage,
		Bootloader:            r.Bootloader,
		Target:                activeTargetMount,
		ScratchDir:            scratchDir,
		NeedsPull:             imageCheck.NeedsPull,
		LayerCount:            imageCheck.LayerCount,
		AdditionalImageStores: r.AdditionalImageStores,
		SecureInstall:         r.SecureInstall != nil,
		SecurePolicyPath:      map[bool]string{true: "/etc/containers/policy.json"}[r.SecureInstall != nil],
		SecureComposefsDigest: map[bool]*string{true: &expectedComposefs}[r.SecureInstall != nil],
		SecureImageRoot:       map[bool]*string{true: &secureImageRoot}[r.SecureInstall != nil],
	}); err != nil {
		fatal("bootc install: %v", err)
	}
	var secureContract *secure.Contract
	var secureArtifacts *secure.InstalledArtifacts
	if r.SecureInstall != nil {
		// The contract and the identities it names live under /usr, which a
		// composefs deployment does not expose as a directory tree on the
		// target. They come from the image instead -- pinned to the deployment
		// by the composefs digest verified during the install above.
		secureContract, err = secure.LoadInstalledContract(secureImageRoot)
		if err != nil {
			fatal("validating deployed secure contract: %v", err)
		}
		// bootc leaves an ESP with plain systemd-boot and no shim, so the
		// Secure Boot chain has to be staged before anything can validate or
		// repair it. RepairESP requires all three components to exist.
		if err := secure.StageESPChain(activeTargetMount, secureImageRoot, secureContract.MOKCertificate); err != nil {
			fatal("staging secure ESP boot chain: %v", err)
		}
		progress.Secure("esp_chain", "staged")
		if err := secure.RepairESP(activeTargetMount, secureImageRoot, secureContract.MOKCertificate); err != nil {
			fatal("installing verified secure ESP second stage: %v", err)
		}
		if expectedComposefs == "" {
			fatal("computing verified deployment composefs identity")
		}
		secureArtifacts, err = secure.VerifyInstalled(activeTargetMount, secureImageRoot, secureContract, expectedComposefs)
		if err != nil {
			fatal("validating installed secure artifacts: %v", err)
		}
		progress.Secure("contract_validation", "passed")
		if err := secure.EnrollTPMBytes(r.SecureInstall.RecoveryKeyFile, secureArtifacts.PCRPublicKey, activeRootPart); err != nil {
			fatal("enrolling secure TPM unlock: %v", err)
		}
		// From the image root, not the target: a composefs deployment exposes no
		// /usr tree under the target mount. Same reason as the contract, the PCR
		// key and the ESP second stage.
		if err := secure.StageMOK(filepath.Join(secureImageRoot, strings.TrimPrefix(secureContract.MOKCertificate, "/")), r.SecureInstall.MOKPasswordFile); err != nil {
			fatal("staging secure MOK enrollment: %v", err)
		}
	}

	// systemd-boot composefs installs rely on GPT auto-discovery for the root
	// filesystem. Keep the auto-partitioned root on the architecture-specific
	// Linux root GUID so the installed system can find /sysroot on first boot.
	if !isManual && isSystemdBoot && !hasEncryption && r.ComposeFsBackend {
		progress.Info("Retagging root partition for systemd GPT auto-discovery")

		// Ensure BOOTX64.EFI is on the ESP before we touch the mount stack.
		// Newer bootctl (e.g. arch-bootc systemd ≥ v255) enables --graceful when
		// running in a container and silently skips writing to the ESP. Copying
		// directly from the ostree deployment is a reliable fallback and a no-op
		// when bootctl ran correctly (EFI/BOOT/BOOTX64.EFI already present).
		if err := install.InstallSystemdBoot(activeTargetMount); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not ensure systemd-boot EFI binary: %v", err))
		}

		// Unmount the EFI partition explicitly so the FAT32 state is flushed to
		// the page cache before the root lazy-unmount below orphans the submount.
		if err := disk.UnmountPartition(r.Disk, 1); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not unmount EFI partition before retag: %v\n", err)
		}

		// Release kernel and userspace references to the root partition before
		// modifying its GPT type. bootc install may have left active references.
		if err := disk.UnmountPartition(r.Disk, 2); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fully clean partition references: %v\n", err)
		}
		if err := disk.SetPartitionType(r.Disk, 2, disk.GPTPartTypeLinuxRootX86_64); err != nil {
			fatal("retagging root partition: %v", err)
		}
		// Remount root so finalization and post-install writes can proceed.
		// udisksctl unmount (used by UnmountPartition above) removes the
		// mountpoint directory it manages, and disk.Mount — unlike
		// MountTmpfs/BindMount — does not create its target, so recreate it
		// or the plain `mount` syscall below fails with ENOENT.
		if err := os.MkdirAll(activeTargetMount, 0o755); err != nil {
			fatal("recreating target mountpoint before remount: %v", err)
		}
		rootPart := disk.PartName(r.Disk, 2)
		if err := disk.Mount(rootPart, activeTargetMount, ""); err != nil {
			fatal("remounting root partition after retagging: %v", err)
		}
		// Remount EFI so that Plymouth/LUKS arg writes land on the real ESP
		// instead of the empty /boot/efi directory in the XFS root.
		if err := disk.MountEFI(activeTargetMount, activeEfiPart); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remount EFI partition after retag: %v\n", err)
		}
	}

	// ── TPM2 enrolment ────────────────────────────────────────────────────────
	// Both tpm2-luks and tpm2-luks-passphrase add a TPM2 auto-unlock token so
	// the system boots without a passphrase prompt. The difference:
	//   tpm2-luks:            random passphrase (recovery key) + TPM2
	//   tpm2-luks-passphrase: user passphrase (fallback) + TPM2
	if hasTPM2 && activeRootPart != "" {
		progress.Step(step, totalSteps, "Enrolling TPM2 auto-unlock", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		unlockPassphrase := r.Encryption.Passphrase
		if r.Encryption.Type == "tpm2-luks" {
			unlockPassphrase = luksRecoveryKey
		}
		// Enroll TPM2 on the FIRST BOOT of the installed system, not here:
		// --tpm2-pcrs=7 seals against PCR 7 as measured in the live
		// installer, but the installed system boots a different chain and
		// measures a different PCR 7 — so an install-time enrollment can
		// never unseal on first boot. Staging a first-boot oneshot captures
		// the correct PCR 7. The recovery/passphrase key unlocks until then.
		if err := luks.StageFirstBootEnrollment(activeTargetMount, activeLuksUUID, unlockPassphrase); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not stage first-boot TPM2 enrollment (recovery key unlock still works): %v", err))
		} else {
			progress.Info("TPM2 auto-unlock will be enrolled on first boot")
		}

		// For tpm2-luks the user never chose a passphrase, so we emit the
		// random one as a recovery key they must save before rebooting.
		if luksRecoveryKey != "" {
			progress.RecoveryKey(luksRecoveryKey)
		}
	}

	// ── Step 7: Copy system flatpaks ──────────────────────────────────────────
	progress.Step(step, totalSteps, "Copying system Flatpaks", profile[pi].cumulativePct, profile[pi].weightPct)
	pi++
	step++

	if err := post.CopyFlatpaks(activeTargetMount, r.Flatpaks, r.FlatpakVarPath); err != nil {
		// Non-fatal — the system will work without pre-installed flatpaks.
		progress.Info(fmt.Sprintf("Warning: could not copy flatpaks: %v", err))
	}

	// ── Step 8: Post-install configuration ───────────────────────────────────
	progress.Step(step, totalSteps, "Configuring installed system", profile[pi].cumulativePct, profile[pi].weightPct)
	pi++
	step++

	progress.Info(fmt.Sprintf("Writing hostname: %s", r.Hostname))
	if err := post.WriteHostname(activeTargetMount, r.Hostname); err != nil {
		fatal("writing hostname: %v", err)
	}

	// Write /var fstab entry if a separate /var disk was used.
	if hasVarDisk {
		varUUID := disk.UUID(r.VarDisk.Disk)
		if varUUID == "" {
			progress.Info(fmt.Sprintf("Warning: could not determine UUID for /var disk %s — skipping fstab entry", r.VarDisk.Disk))
		} else {
			if err := post.AppendFstabEntry(activeTargetMount, varUUID, "/var", "xfs", "defaults"); err != nil {
				progress.Info(fmt.Sprintf("Warning: could not write /var fstab entry: %v", err))
			} else {
				progress.Info(fmt.Sprintf("Added /var fstab entry (UUID=%s)", varUUID))
			}
		}
	}

	// Create a user account if the recipe requests one (e.g. Bazzite has no OOBE).
	if r.User.Username != "" {
		progress.Info(fmt.Sprintf("Creating user: %s", r.User.Username))
		if err := post.CreateUser(activeTargetMount, post.UserConfig{
			Username: r.User.Username,
			Fullname: r.User.Fullname,
			Password: r.User.Password,
			Groups:   r.User.Groups,
		}); err != nil {
			fatal("creating user: %v", err)
		}
	}

	// Ensure rhgb and quiet are in every BLS loader entry so Plymouth shows
	// the graphical boot splash. Non-fatal: the system boots fine without it.
	if r.SecureInstall == nil {
		n, err := post.EnsurePlymouthArgs(activeTargetMount)
		if err != nil {
			progress.Info(fmt.Sprintf("Warning: could not set Plymouth kernel args: %v", err))
		} else if n > 0 {
			progress.Info(fmt.Sprintf("Added Plymouth boot args to %d loader entr%s", n, map[bool]string{true: "y", false: "ies"}[n == 1]))
		}
	}

	// Inject rd.luks.name=<UUID>=root into every BLS entry so the initrd
	// unlocks the LUKS container and maps it to /dev/mapper/root before
	// mounting the root filesystem. bootc install to-filesystem only sees the
	// open mapper device and never writes LUKS parameters itself.
	if activeLuksUUID != "" && r.SecureInstall == nil {
		n, err := post.EnsureLuksArgs(activeTargetMount, activeLuksUUID)
		if err != nil {
			progress.Info(fmt.Sprintf("Warning: could not inject LUKS boot args: %v", err))
		} else if n > 0 {
			progress.Info(fmt.Sprintf("Injected rd.luks.name into %d boot entr%s", n, map[bool]string{true: "y", false: "ies"}[n == 1]))
		}
	}

	// Copy Bluetooth pairings from live session so paired keyboards/mice
	// reconnect on first boot without re-pairing. Non-fatal.
	if err := post.CopyBluetoothPairings(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not copy Bluetooth pairings: %v", err))
	}

	// Copy WiFi connections from live session so network reconnects on first boot. Non-fatal.
	if err := post.CopyWiFiConnections(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not copy WiFi connections: %v", err))
	}

	// Generate friendly audio device names and hide useless outputs (S/PDIF,
	// Pro Audio, monitor loopbacks). Writes WirePlumber rules to /etc/ so no
	// GNOME extensions are needed. Non-fatal.
	if err := post.GenerateAudioConfig(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not configure audio devices: %v", err))
	}

	// Inject slurped Windows data into the installed system. Non-fatal.
	if dataResult != nil && dataResult.Found {
		composefs := post.IsComposeFsNativeExported(activeTargetMount)
		if err := slurp.InjectData(activeTargetMount, dataResult, composefs); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not inject user data: %v", err))
		}
	}
	if wallpaperResult != nil && wallpaperResult.Found {
		composefs := post.IsComposeFsNativeExported(activeTargetMount)
		if err := slurp.InjectWallpapers(activeTargetMount, wallpaperResult, composefs); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not inject wallpapers: %v", err))
		}
	}
	// Cleanup scratch space (both data and wallpaper slurps use /run/fisherman-slurp)
	if dataResult != nil || wallpaperResult != nil {
		slurp.CleanupScratch()
	}

	// Pre-generate thumbnails for ALL wallpapers (system + user-injected) so
	// the GNOME wallpaper capplet opens instantly on first boot. Non-fatal.
	{
		composefs := post.IsComposeFsNativeExported(activeTargetMount)
		progress.Substep("Pre-generating wallpaper thumbnails")
		n, err := slurp.GenerateSystemThumbnails(activeTargetMount, composefs)
		if err != nil {
			progress.Info(fmt.Sprintf("Warning: could not generate wallpaper thumbnails: %v", err))
		}
		if n > 0 {
			progress.Info(fmt.Sprintf("Pre-generated %d wallpaper thumbnail(s)", n))
		}
	}

	// Detect OEM hardware (ASUS, Framework) and queue vendor-specific packages
	// for first-login install via brew. Also enables required system services. Non-fatal.
	if err := post.InstallOEMPackages(activeTargetMount, r.DistroID, r.BrewTap); err != nil {
		progress.Info(fmt.Sprintf("Warning: OEM package setup: %v", err))
	}

	// Enable print auto-discovery services (cups-browsed, avahi-daemon, ipp-usb)
	// so USB and network printers are found on first boot without configuration.
	// Non-fatal: services are skipped if their unit files are absent from the image.
	post.EnablePrintServices(activeTargetMount)

	if r.SecureInstall != nil {
		espPartUUID, err := secure.PartitionUUID(activeEfiPart)
		if err != nil {
			fatal("recording secure ESP identity: %v", err)
		}
		tokenID, err := secure.TPMTokenIdentity(activeRootPart)
		if err != nil {
			fatal("recording secure TPM token identity: %v", err)
		}
		// Image root, for the same reason as the staging read above.
		mokCertificate, err := os.ReadFile(filepath.Join(secureImageRoot, strings.TrimPrefix(secureContract.MOKCertificate, "/")))
		if err != nil {
			fatal("reading secure MOK certificate: %v", err)
		}
		if !strings.Contains(r.Image, "@sha256:") {
			fatal("recording secure OCI provenance: immutable digest missing")
		}
		if err := secure.WriteProvenance(activeTargetMount, secure.Provenance{
			OCIRef: r.Image, TrackingRef: r.TargetImgref,
			Capability: secure.CapabilityLabel + "=" + secure.CapabilityValue, Schema: secureContract.Schema,
			Assembly: secureContract.Assembly.Compatibility, Composefs: secureArtifacts.ComposefsID, UKIHash: secureArtifacts.UKIHash,
			MOKHash: secure.PublicFingerprint(mokCertificate), PCRHash: secure.PublicFingerprint(secureArtifacts.PCRPublicKey),
			ESPPartUUID: espPartUUID, LUKSUUID: activeLuksUUID, TPMToken: tokenID,
			// DETECTED versions, not the contract's declared floors. Recording
			// the floors meant provenance answered "what did the contract ask
			// for", which is already in the contract; the question worth being
			// able to answer afterwards is "what actually ran".
			Versions:  secureVersions.Detected,
			Completed: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			fatal("writing secure install provenance: %v", err)
		}
		progress.Secure("provenance", "written")
	}

	// Warm all system caches (fonts, icons, schemas, pixbuf, ldconfig, man-db,
	// flatpak appstream) so first boot is instant. Non-fatal.
	progress.Substep("Pre-warming system caches for first boot")
	post.WarmCaches(activeTargetMount)

	// ── Step 9: Finalize ─────────────────────────────────────────────────────
	// bootc's --skip-finalize kept the target writable for post-install writes.
	// Now replicate what bootc's finalize_filesystem() does internally:
	//   1. fstrim  — discard unused blocks (SSD optimization)
	//   2. remount ro — flush writeback, lock the deployment read-only
	//   3. fsfreeze/thaw — flush the journal for a clean first boot
	// ZFS handles this internally; fstrim/remount-ro/fsfreeze do not apply.
	progress.Step(step, totalSteps, "Finalizing installation", profile[pi].cumulativePct, profile[pi].weightPct)
	if r.Filesystem != "zfs" {
		if err := disk.FinalizeFilesystem(activeTargetMount); err != nil {
			fatal("finalizing target filesystem: %v", err)
		}
	}

	// ZFS post-install: write host ID and zpool.cache so the installed system
	// can import the pool at boot. Must be done before unmounting.
	if r.Filesystem == "zfs" {
		poolName := disk.PoolName(r.ZFSPoolName)
		progress.Info("ZFS post-install: writing hostid and zpool.cache")
		if err := disk.WriteHostID(activeTargetMount); err != nil {
			progress.Info(fmt.Sprintf("Warning: ZFS host ID: %v", err))
		}
		if err := disk.SetZFSCachefile(poolName, activeTargetMount); err != nil {
			progress.Info(fmt.Sprintf("Warning: ZFS cachefile: %v", err))
		}
	}

	// Tear down mounts and LUKS before declaring success.
	cleanup.Run()

	// Find the EFI boot entry so the frontend can set BootNext before rebooting.
	// Non-fatal: on VMs or systems without efibootmgr this may return empty.
	bootID, err := post.FindBootNextID(activeEfiPart)
	if err != nil {
		progress.Info(fmt.Sprintf("Warning: could not determine EFI boot entry: %v", err))
		bootID = ""
	} else if bootID != "" {
		progress.Info(fmt.Sprintf("EFI boot entry for installed system: Boot%s", bootID))
	}

	progress.Complete("Installation complete!", bootID)
}
