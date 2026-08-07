package secure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/tuna-os/fisherman/internal/install"
	"github.com/tuna-os/fisherman/internal/runner"
)

var syncFile = func(file *os.File) error { return file.Sync() }

// Provenance is the non-secret record retained in the encrypted root after a
// successful secure install.
// Provenance is the record docs/bootc-secure-install-contract.md defines, and
// the field names here are that contract rather than a local choice. It names
// fifteen required keys and fixes two of their types:
//
//	oci_ref tracking_ref repository secure_capability contract_schema
//	assembly_compatibility composefs_id uki_sha256 mok_fingerprint
//	pcr_fingerprint esp_partuuid luks_uuid tpm_token_id installer_versions
//	completed_at
//
//	"secure_capability is JSON boolean true; contract_schema is JSON integer 1"
//
// Four keys were previously spelled differently and one was never written at
// all, so a correct install produced a record the contract check rejected.
// omitempty is deliberately absent from the required keys: a missing key must
// fail loudly rather than silently produce a record that validates as
// incomplete.
type Provenance struct {
	OCIRef      string `json:"oci_ref"`
	TrackingRef string `json:"tracking_ref"`
	Repository  string `json:"repository"`
	Capability  bool   `json:"secure_capability"`
	Schema      int    `json:"contract_schema"`
	Assembly    string `json:"assembly_compatibility"`
	Composefs   string `json:"composefs_id"`
	UKIHash     string `json:"uki_sha256"`
	MOKHash     string `json:"mok_fingerprint"`
	PCRHash     string `json:"pcr_fingerprint"`
	ESPPartUUID string `json:"esp_partuuid"`
	LUKSUUID    string `json:"luks_uuid"`
	TPMToken    string `json:"tpm_token_id"`
	// installer_versions answers "what produced this system". Only fisherman
	// is knowable at install time: the medium carries no identifier for the
	// bootc-installer Flatpak or the Dakota ISO build, and the live
	// environment deliberately sets VERSION_ID=latest. The contract originally
	// named all three; the other two are a design gap tracked separately
	// rather than a value to invent here.
	Versions map[string]string `json:"installer_versions"`
	// validated_versions is the floor-policy audit trail -- the dependency
	// versions DETECTED on the medium, which is what makes "this install
	// proceeded on an above-floor, unvalidated systemd" answerable afterwards.
	// Distinct from installer_versions: these are what the installer checked,
	// not what did the installing.
	Validated map[string]string `json:"validated_versions"`
	Completed string            `json:"completed_at"`
}

// VersionPolicy selects how a pinned tool version is enforced.
type VersionPolicy int

const (
	// PolicyExact permits one version and nothing else. Reserved for tools
	// whose integration depends on observed, non-upstream-stable behaviour,
	// where a NEWER release is precisely what breaks it silently.
	PolicyExact VersionPolicy = iota
	// PolicyFloor permits the pinned version or anything newer. A version above
	// the floor that is not in validated still installs, but warns: the
	// combination has not been proven end to end.
	PolicyFloor
)

// VersionResult reports what was actually detected on the medium, plus any
// non-fatal compatibility warnings.
type VersionResult struct {
	Detected map[string]string
	Warnings []string
}

// versionChecks is the schema-1 compatibility stack.
//
// bootc is pinned EXACTLY and deliberately, despite living under the contract's
// MinimumVersions field: the assembly path depends on bootc 1.16.3's observed
// hidden storage-digest command and two-pass ukify behaviour, which upstream
// does not guarantee. A newer bootc is the exact thing that would break it
// without saying so.
//
// systemd and cosign are floors. What the systemd pin guards at install time is
// tooling behaviour (systemd-cryptenroll TPM sealing, bootctl, repart); the
// INSTALLED system's systemd family is pinned separately at image build time
// and validated there. An exact pin here breaks on every routine media rebuild,
// which creates standing pressure to edit the number rather than validate the
// change — and a check people are trained to defeat protects nothing.
var versionChecks = []struct {
	name      string
	args      []string
	required  string
	policy    VersionPolicy
	validated []string
}{
	{"bootc", []string{"--version"}, "1.16.3", PolicyExact, nil},
	{"cosign", []string{"version"}, "2.6.1", PolicyFloor, []string{"2.6.1"}},
	{"dpkg-query", []string{"-W", "-f=${Version}", "systemd"}, "261.1-3", PolicyFloor, []string{"261.1-3"}},
}

// ValidateVersions rejects an installer medium that does not carry the schema-1
// compatibility stack, and reports what it found.
func ValidateVersions() (VersionResult, error) {
	result := VersionResult{Detected: map[string]string{}}
	for _, check := range versionChecks {
		out, err := runner.Output(check.name, check.args...)
		if err != nil {
			return result, fmt.Errorf("secure install requires %s version %s", check.name, check.required)
		}
		detected, ok := parseVersion(check.name, string(out))
		if !ok {
			return result, fmt.Errorf("secure install requires %s version %s", check.name, check.required)
		}
		result.Detected[versionKey(check.name)] = detected

		switch check.policy {
		case PolicyExact:
			if detected != check.required {
				return result, fmt.Errorf("secure install requires %s version %s", check.name, check.required)
			}
		case PolicyFloor:
			if DebCompare(detected, check.required) < 0 {
				return result, fmt.Errorf("secure install requires %s version %s or newer, found %s",
					check.name, check.required, detected)
			}
			if !contains(check.validated, detected) {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"%s %s is above the %s floor but has not been validated end to end; "+
						"re-run the secure install harness before relying on this combination",
					versionKey(check.name), detected, check.required))
			}
		}
	}
	return result, nil
}

// versionKey names the tool as provenance records it: the systemd check runs
// through dpkg-query, but what it reports is systemd's version.
func versionKey(tool string) string {
	if tool == "dpkg-query" {
		return "systemd"
	}
	return tool
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

// parseVersion extracts the bare version from each tool's output shape. It
// rejects anything with embedded whitespace so a substring cannot pass as a
// whole version.
func parseVersion(tool, output string) (string, bool) {
	output = strings.TrimSpace(output)
	switch tool {
	case "bootc":
		rest, ok := strings.CutPrefix(output, "bootc ")
		if !ok || rest == "" || strings.ContainsAny(rest, " \t\n") {
			return "", false
		}
		return rest, true
	case "cosign":
		match := regexp.MustCompile(`(?m)^GitVersion:\s*v?([^\s]+)\s*$`).FindStringSubmatch(output)
		if len(match) != 2 {
			return "", false
		}
		return match[1], true
	default:
		if output == "" || strings.ContainsAny(output, " \t\n") {
			return "", false
		}
		return output, true
	}
}

// PublicFingerprint returns a non-secret stable fingerprint for provenance.
func PublicFingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// PartitionUUID and TPMTokenIdentity obtain public identifiers for provenance.
func PartitionUUID(device string) (string, error) {
	out, err := runner.Output("blkid", "-s", "PARTUUID", "-o", "value", device)
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "", fmt.Errorf("reading ESP PARTUUID: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func TPMTokenIdentity(backingDevice string) (string, error) {
	out, err := runner.Output("cryptsetup", "luksDump", "--dump-json-metadata", backingDevice)
	if err != nil {
		return "", fmt.Errorf("reading TPM token metadata: %w", err)
	}
	return PublicFingerprint(out), nil
}

// ResolveRootBackingDevice derives exactly one LUKS backing device from the
// active root mapper and verifies its LUKS header without modifying it.
func ResolveRootBackingDevice() (string, error) {
	out, err := runner.Output("cryptsetup", "status", "root")
	if err != nil {
		return "", fmt.Errorf("reading root mapper status: %w", err)
	}
	var device string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "device:" {
			if device != "" || !strings.HasPrefix(fields[1], "/dev/") {
				return "", fmt.Errorf("ambiguous root LUKS backing device")
			}
			device = fields[1]
		}
	}
	if device == "" {
		return "", fmt.Errorf("root mapper has no LUKS backing device")
	}
	if err := runner.Run("cryptsetup", "isLuks", device); err != nil {
		return "", fmt.Errorf("validating root LUKS backing device: %w", err)
	}
	return device, nil
}

// ResolveTargetRootBackingDevice derives the LUKS backing device from the
// filesystem mounted at root, never from the installer's active host root.
func ResolveTargetRootBackingDevice(root string) (string, error) {
	out, err := runner.Output("findmnt", "-n", "-o", "SOURCE", "--target", root)
	if err != nil {
		return "", fmt.Errorf("reading target root mount source: %w", err)
	}
	var mapper string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if index := strings.IndexByte(line, '['); index >= 0 {
			line = line[:index]
		}
		if (strings.HasPrefix(line, "/dev/mapper/") || strings.HasPrefix(line, "/dev/dm-")) && mapper == "" {
			mapper = line
			continue
		}
		return "", fmt.Errorf("target root must have exactly one /dev/mapper or /dev/dm source")
	}
	if mapper == "" {
		return "", fmt.Errorf("target root must have exactly one /dev/mapper or /dev/dm source")
	}
	return resolveMapperBackingDevice(mapper)
}

func resolveMapperBackingDevice(mapper string) (string, error) {
	out, err := runner.Output("cryptsetup", "status", mapper)
	if err != nil {
		return "", fmt.Errorf("reading target root mapper status: %w", err)
	}
	var device string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "device:" {
			if device != "" || !strings.HasPrefix(fields[1], "/dev/") {
				return "", fmt.Errorf("ambiguous target root LUKS backing device")
			}
			device = fields[1]
		}
	}
	if device == "" {
		return "", fmt.Errorf("target root mapper has no LUKS backing device")
	}
	if err := runner.Run("cryptsetup", "isLuks", device); err != nil {
		return "", fmt.Errorf("validating target root LUKS backing device: %w", err)
	}
	return device, nil
}

// ValidatePrivateRegularFile accepts only an operator-controlled single-link
// mode-0600 regular file. Lstat intentionally rejects symlinks before use.
func ValidatePrivateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("must be a regular non-symlink file")
	}
	if info.Mode().Perm() != 0o600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("must have mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("must have exactly one link")
	}
	return nil
}

// InstalledArtifacts is the verified state bound to TPM enrollment and
// provenance. It intentionally contains only public paths and digests.
type InstalledArtifacts struct {
	UKIPath      string
	UKIHash      string
	PCRPublicKey []byte
	ComposefsID  string
}

// ValidateDiskSize requires the secure online-install capacity before any
// partitioning can begin.
func ValidateDiskSize(device string) error {
	out, err := runner.Output("blockdev", "--getsize64", device)
	if err != nil {
		return fmt.Errorf("reading target disk capacity: %w", err)
	}
	var size uint64
	if _, err := fmt.Sscan(strings.TrimSpace(string(out)), &size); err != nil || size < MinimumDiskBytes {
		return fmt.Errorf("secure install requires a target disk of at least %d bytes", MinimumDiskBytes)
	}
	return nil
}

// ValidateESPSize checks the actual created ESP rather than relying on its
// intended sfdisk script size.
func ValidateESPSize(device string) error {
	out, err := runner.Output("blockdev", "--getsize64", device)
	if err != nil {
		return fmt.Errorf("reading ESP capacity: %w", err)
	}
	var size uint64
	if _, err := fmt.Sscan(strings.TrimSpace(string(out)), &size); err != nil || size < MinimumESPBytes {
		return fmt.Errorf("secure install requires an ESP of at least %d bytes", MinimumESPBytes)
	}
	return nil
}

// AcceptImage resolves, verifies, and inspects one immutable registry digest.
// Its returned reference must be used for every later pull and bootc handoff.
func AcceptImage(reference, cosignKey string) (string, error) {
	if cosignKey == "" {
		return "", fmt.Errorf("secure install requires a Cosign public key")
	}
	pinned, err := install.VerifyAndPinImage(reference, cosignKey)
	if err != nil {
		return "", fmt.Errorf("verifying secure OCI image: %w", err)
	}
	if !strings.Contains(pinned, "@sha256:") {
		return "", fmt.Errorf("secure OCI image did not resolve to an immutable digest")
	}
	out, err := install.SkopeoInspectFn("docker://" + pinned)
	if err != nil {
		return "", fmt.Errorf("inspecting verified secure OCI image: %w", err)
	}
	var image struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal(out, &image); err != nil {
		return "", fmt.Errorf("parsing verified secure OCI labels: %w", err)
	}
	if image.Labels[CapabilityLabel] != CapabilityValue {
		return "", fmt.Errorf("verified secure OCI image lacks %s=%s", CapabilityLabel, CapabilityValue)
	}
	return pinned, nil
}

// VerifyInstalled validates every installed BLS entry, extracts the PCR public
// key from its Type #2 UKI, and compares it to the immutable contract key.
// VerifyInstalled validates the installed secure artifacts. It reads two roots
// deliberately: boot/efi and var really are on the installed target, while the
// contract-referenced identities (PCR public key, MOK certificate) live under
// usr/ and therefore come from imageRoot -- a composefs deployment presents no
// merged root under the target mount. See ExtractSecureImageRoot.
func VerifyInstalled(root, imageRoot string, contract *Contract, expectedComposefs string) (*InstalledArtifacts, error) {
	if !install.ValidComposefsDigest(expectedComposefs) {
		return nil, fmt.Errorf("verified deployment has an invalid composefs identity")
	}
	entries, err := filepath.Glob(filepath.Join(root, "boot/efi/loader/entries/*.conf"))
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("finding installed type #2 BLS entries")
	}
	for _, required := range []string{"BOOTX64.EFI", "mmx64.efi", "grubx64.efi"} {
		if _, err := os.Stat(filepath.Join(root, "boot/efi/EFI/BOOT", required)); err != nil {
			return nil, fmt.Errorf("required ESP binary %s: %w", required, err)
		}
	}
	rootfsKey, err := os.ReadFile(filepath.Join(imageRoot, strings.TrimPrefix(contract.PCRPublicKey, "/")))
	if err != nil {
		return nil, fmt.Errorf("reading contract PCR public key: %w", err)
	}
	var result *InstalledArtifacts
	for _, entry := range entries {
		data, err := os.ReadFile(entry)
		if err != nil {
			return nil, err
		}
		efi, err := ValidateType2BLS(data)
		if err != nil {
			return nil, fmt.Errorf("validating %s: %w", entry, err)
		}
		uki := filepath.Join(root, "boot/efi", strings.TrimPrefix(efi, "/"))
		// Fail here rather than at the next boot. An unsigned UKI on the ESP of
		// a secure install is unbootable under enforced Secure Boot, and the
		// only symptom the firmware offers is `Invalid parameter` with no
		// bootable option -- which cost several rounds to trace back once.
		// Checking it where the install can still fail loudly is cheap.
		if err := assertPESigned(uki); err != nil {
			return nil, err
		}
		key, err := peSection(uki, ".pcrpkey")
		if err != nil {
			return nil, fmt.Errorf("extracting installed UKI PCR key: %w", err)
		}
		if err := ComparePCRPublicKey(key, rootfsKey); err != nil {
			return nil, err
		}
		ukiBytes, err := os.ReadFile(uki)
		if err != nil {
			return nil, fmt.Errorf("reading installed Type #2 UKI: %w", err)
		}
		hash := sha256.Sum256(ukiBytes)
		// The composefs identity lives in the UKI's own .cmdline section, not in
		// the BLS entry. A Type #2 UKI has its command line baked in and signed
		// -- which is exactly why bootc refuses --karg against one -- so the
		// entries it writes carry no `options` line at all:
		//
		//   title Cayo Linux 13
		//   version 13
		//   uki /EFI/Linux/bootc/bootc_composefs-<id>.efi
		//   sort-key bootc-cayo-0
		//
		// Reading only `options` therefore found nothing on every real install.
		// .cmdline is also the authoritative source: it is what actually boots,
		// and it is covered by the UKI's signature, whereas an `options` line is
		// not. The BLS fallback is kept for a non-UKI entry shape.
		composefs, err := composefsIdentityFromUKI(uki)
		if err != nil {
			return nil, err
		}
		if composefs == "" {
			for _, line := range strings.Split(string(data), "\n") {
				if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "options" {
					for _, option := range fields[1:] {
						if strings.HasPrefix(option, "composefs=") {
							composefs = strings.TrimPrefix(option, "composefs=")
						}
					}
				}
			}
		}
		if composefs == "" {
			return nil, fmt.Errorf("installed Type #2 UKI carries no composefs identity in .cmdline or its BLS entry")
		}
		observed := strings.TrimPrefix(composefs, "?")
		if observed == composefs || !install.ValidComposefsDigest(observed) {
			return nil, fmt.Errorf("installed Type #2 UKI BLS entry has an invalid composefs identity")
		}
		if observed != expectedComposefs {
			return nil, fmt.Errorf("installed Type #2 UKI composefs identity does not match the verified deployment")
		}
		candidate := &InstalledArtifacts{UKIPath: uki, UKIHash: hex.EncodeToString(hash[:]), PCRPublicKey: key, ComposefsID: observed}
		if result != nil && result.UKIHash != candidate.UKIHash {
			return nil, fmt.Errorf("multiple installed Type #2 UKIs require explicit boot selection")
		}
		result = candidate
	}
	return result, nil
}

// composefsIdentityFromUKI reads composefs=<id> out of a UKI's signed .cmdline
// section. Returns "" when the section carries no such option, which lets the
// caller fall back to a BLS options line.
func composefsIdentityFromUKI(uki string) (string, error) {
	data, err := peSection(uki, ".cmdline")
	if err != nil {
		return "", fmt.Errorf("extracting installed UKI command line: %w", err)
	}
	// The section is NUL-padded.
	for _, field := range strings.Fields(strings.TrimRight(string(data), "\x00")) {
		if strings.HasPrefix(field, "composefs=") {
			return strings.TrimPrefix(field, "composefs="), nil
		}
	}
	return "", nil
}

// RestageMOK verifies the recovery credential before staging only the public
// MOK certificate. It never formats, partitions, or runs bootc.
func RestageMOK(root string, contract *Contract, recoveryKey, mokPasswordFile, backingDevice string) error {
	if err := AuthenticateRecovery(recoveryKey, backingDevice); err != nil {
		return fmt.Errorf("verifying recovery credential: %w", err)
	}
	if contract == nil || contract.MOKCertificate == "" {
		return fmt.Errorf("validating installed MOK certificate path")
	}
	// NOTE: this reads from the installed target, which works only for a
	// merged-root layout. On a composefs deployment /usr is not a directory
	// tree under the target, so this has the same limitation the install path
	// hit -- it would need an image root the same way. Left as-is because this
	// is the standalone `secure-restage-mok` recovery operation, not the
	// install path, and changing its interface belongs with a fix that can be
	// tested against a real installed system.
	certificate := filepath.Join(root, strings.TrimPrefix(contract.MOKCertificate, "/"))
	if _, err := os.Stat(certificate); err != nil {
		return fmt.Errorf("validating installed MOK certificate: %w", err)
	}
	return StageMOK(certificate, mokPasswordFile)
}

// RepairESP reconstructs only the MOK-signed systemd-boot second stage from
// the authenticated deployment. Shim and MokManager are deliberately checked,
// never replaced.
// RepairESP replaces the ESP second stage. The ESP is on the installed target;
// the MOK certificate and the signed second-stage source live under usr/ and so
// come from imageRoot. See ExtractSecureImageRoot.
func RepairESP(root, imageRoot, mokCertificate string) error {
	boot := filepath.Join(root, "boot/efi/EFI/BOOT")
	for _, name := range []string{"BOOTX64.EFI", "mmx64.efi"} {
		if _, err := os.Stat(filepath.Join(boot, name)); err != nil {
			return fmt.Errorf("validating installed %s: %w", name, err)
		}
	}
	entries, err := filepath.Glob(filepath.Join(root, "boot/efi/loader/entries/*.conf"))
	if err != nil || len(entries) == 0 {
		return fmt.Errorf("finding installed type #2 BLS entries")
	}
	for _, entry := range entries {
		data, err := os.ReadFile(entry)
		if err != nil {
			return err
		}
		efi, err := ValidateType2BLS(data)
		if err != nil {
			return fmt.Errorf("validating %s: %w", entry, err)
		}
		if _, err := os.Stat(filepath.Join(root, "boot/efi", strings.TrimPrefix(efi, "/"))); err != nil {
			return fmt.Errorf("validating installed Type #2 UKI: %w", err)
		}
	}
	if mokCertificate == "" || !strings.HasPrefix(mokCertificate, "/") {
		return fmt.Errorf("validating installed MOK certificate path")
	}
	certificate := filepath.Join(imageRoot, strings.TrimPrefix(mokCertificate, "/"))
	source := filepath.Join(imageRoot, "usr/lib/snosi/bootc/systemd-bootx64.efi")
	if err := runner.Run("sbverify", "--cert", certificate, source); err != nil {
		return fmt.Errorf("verifying MOK-signed systemd-boot source: %w", err)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("reading verified systemd-boot source: %w", err)
	}
	target := filepath.Join(boot, "grubx64.efi")
	previous, err := os.ReadFile(target)
	if err != nil {
		return fmt.Errorf("reading existing systemd-boot second stage: %w", err)
	}
	previousInfo, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stating existing systemd-boot second stage: %w", err)
	}
	tmp, err := os.CreateTemp(boot, ".grubx64.efi-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := syncFile(tmp); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing replacement systemd-boot stage: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := runner.Run("sbverify", "--cert", certificate, name); err != nil {
		return fmt.Errorf("verifying replacement systemd-boot stage: %w", err)
	}
	if err := os.Rename(name, target); err != nil {
		return fmt.Errorf("replacing systemd-boot second stage: %w", err)
	}
	dir, err := os.Open(boot)
	if err != nil {
		return fmt.Errorf("opening ESP directory for sync: %w", err)
	}
	defer dir.Close()
	if err := syncFile(dir); err != nil {
		if restoreErr := restoreSecondStage(boot, target, previous, previousInfo.Mode()); restoreErr != nil {
			return fmt.Errorf("syncing ESP directory: %w; restoring previous systemd-boot stage: %v", err, restoreErr)
		}
		return fmt.Errorf("syncing ESP directory: %w", err)
	}
	return nil
}

func restoreSecondStage(boot, target string, previous []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(boot, ".grubx64.efi-restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(previous); err != nil {
		tmp.Close()
		return err
	}
	if err := syncFile(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, target); err != nil {
		return err
	}
	dir, err := os.Open(boot)
	if err != nil {
		return err
	}
	defer dir.Close()
	return syncFile(dir)
}

// persistentVarDir returns the /var the booted system will actually mount.
//
// A composefs deployment does not use <root>/var. The persistent /var lives in
// the stateroot, at state/os/<stateroot>/var, and <root>/var is a different
// directory that nothing ever mounts. Measured on an installed target:
//
//	<root>/var/lib/snosi/                    6 entries, written by the installer
//	<root>/state/os/default/var/lib/snosi/   95k entries, and the RUNNING system
//	                                         wrote enablement-manifest.applied here
//
// Writing provenance to <root>/var therefore produced a file no booted system
// could read, and snosi's Task 9 check failed with "No such file or directory"
// on an otherwise healthy install.
//
// Falls back to <root>/var when there is no stateroot, which keeps any
// non-composefs caller working; the secure path is composefs by contract, so
// that branch should not be reached there.
func persistentVarDir(root string) string {
	matches, err := filepath.Glob(filepath.Join(root, "state/os/*/var"))
	if err == nil && len(matches) == 1 {
		return matches[0]
	}
	return filepath.Join(root, "var")
}

// WriteProvenance writes only public installation facts into encrypted /var.
func WriteProvenance(root string, provenance Provenance) error {
	if provenance.Completed == "" {
		provenance.Completed = "completed"
	}
	data, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding secure install provenance: %w", err)
	}
	dir := filepath.Join(persistentVarDir(root), "lib/snosi")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bootc-secure-install.json"), append(data, '\n'), 0o600)
}
