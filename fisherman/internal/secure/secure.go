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
type Provenance struct {
	OCIRef      string            `json:"oci_ref"`
	TrackingRef string            `json:"tracking_ref"`
	Capability  string            `json:"secure_capability"`
	Schema      int               `json:"contract_schema"`
	Assembly    string            `json:"assembly_compatibility"`
	Composefs   string            `json:"composefs_id,omitempty"`
	UKIHash     string            `json:"uki_sha256"`
	MOKHash     string            `json:"mok_public_key_sha256,omitempty"`
	PCRHash     string            `json:"pcr_public_key_sha256,omitempty"`
	ESPPartUUID string            `json:"esp_partuuid,omitempty"`
	LUKSUUID    string            `json:"luks_uuid,omitempty"`
	TPMToken    string            `json:"tpm_token,omitempty"`
	Versions    map[string]string `json:"installer_versions,omitempty"`
	Completed   string            `json:"completed_at"`
}

// ValidateVersions rejects an installer medium that does not carry the pinned
// schema-1 compatibility stack.
func ValidateVersions() error {
	for _, check := range []struct {
		name string
		args []string
		want string
	}{
		{"bootc", []string{"--version"}, "1.16.3"},
		{"cosign", []string{"version"}, "2.6.1"},
		{"dpkg-query", []string{"-W", "-f=${Version}", "systemd"}, "261.1-3"},
	} {
		out, err := runner.Output(check.name, check.args...)
		if err != nil || !exactVersion(check.name, string(out), check.want) {
			return fmt.Errorf("secure install requires %s version %s", check.name, check.want)
		}
	}
	return nil
}

func exactVersion(tool, output, want string) bool {
	output = strings.TrimSpace(output)
	switch tool {
	case "bootc":
		return output == "bootc "+want
	case "cosign":
		match := regexp.MustCompile(`(?m)^GitVersion:\s*v?([^\s]+)\s*$`).FindStringSubmatch(output)
		return len(match) == 2 && match[1] == want
	default:
		return output == want
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
func VerifyInstalled(root string, contract *Contract, expectedComposefs string) (*InstalledArtifacts, error) {
	if !install.ValidComposefsDigest(expectedComposefs) {
		return nil, fmt.Errorf("verified deployment has an invalid composefs identity")
	}
	entries, err := filepath.Glob(filepath.Join(root, "boot/efi/loader/entries/*.conf"))
	if err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("finding installed Type #2 BLS entries")
	}
	for _, required := range []string{"BOOTX64.EFI", "mmx64.efi", "grubx64.efi"} {
		if _, err := os.Stat(filepath.Join(root, "boot/efi/EFI/BOOT", required)); err != nil {
			return nil, fmt.Errorf("required ESP binary %s: %w", required, err)
		}
	}
	rootfsKey, err := os.ReadFile(filepath.Join(root, strings.TrimPrefix(contract.PCRPublicKey, "/")))
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
		keyFile, err := os.CreateTemp("", "fisherman-pcrpkey-*")
		if err != nil {
			return nil, err
		}
		keyPath := keyFile.Name()
		keyFile.Close()
		if err := runner.Run("objcopy", "--dump-section", ".pcrpkey="+keyPath, uki); err != nil {
			os.Remove(keyPath)
			return nil, fmt.Errorf("extracting installed UKI PCR key: %w", err)
		}
		key, err := os.ReadFile(keyPath)
		os.Remove(keyPath)
		if err != nil {
			return nil, fmt.Errorf("reading installed UKI PCR key: %w", err)
		}
		if err := ComparePCRPublicKey(key, rootfsKey); err != nil {
			return nil, err
		}
		ukiBytes, err := os.ReadFile(uki)
		if err != nil {
			return nil, fmt.Errorf("reading installed Type #2 UKI: %w", err)
		}
		hash := sha256.Sum256(ukiBytes)
		composefs := ""
		for _, line := range strings.Split(string(data), "\n") {
			if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "options" {
				for _, option := range fields[1:] {
					if strings.HasPrefix(option, "composefs=") {
						composefs = strings.TrimPrefix(option, "composefs=")
					}
				}
			}
		}
		if composefs == "" {
			return nil, fmt.Errorf("installed Type #2 UKI BLS entry lacks composefs identity")
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

// RestageMOK verifies the recovery credential before staging only the public
// MOK certificate. It never formats, partitions, or runs bootc.
func RestageMOK(root string, contract *Contract, recoveryKey, mokPasswordFile, backingDevice string) error {
	if err := AuthenticateRecovery(recoveryKey, backingDevice); err != nil {
		return fmt.Errorf("verifying recovery credential: %w", err)
	}
	if contract == nil || contract.MOKCertificate == "" {
		return fmt.Errorf("validating installed MOK certificate path")
	}
	certificate := filepath.Join(root, strings.TrimPrefix(contract.MOKCertificate, "/"))
	if _, err := os.Stat(certificate); err != nil {
		return fmt.Errorf("validating installed MOK certificate: %w", err)
	}
	return StageMOK(certificate, mokPasswordFile)
}

// RepairESP reconstructs only the MOK-signed systemd-boot second stage from
// the authenticated deployment. Shim and MokManager are deliberately checked,
// never replaced.
func RepairESP(root, mokCertificate string) error {
	boot := filepath.Join(root, "boot/efi/EFI/BOOT")
	for _, name := range []string{"BOOTX64.EFI", "mmx64.efi"} {
		if _, err := os.Stat(filepath.Join(boot, name)); err != nil {
			return fmt.Errorf("validating installed %s: %w", name, err)
		}
	}
	entries, err := filepath.Glob(filepath.Join(root, "boot/efi/loader/entries/*.conf"))
	if err != nil || len(entries) == 0 {
		return fmt.Errorf("finding installed Type #2 BLS entries")
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
	certificate := filepath.Join(root, strings.TrimPrefix(mokCertificate, "/"))
	source := filepath.Join(root, "usr/lib/snosi/bootc/systemd-bootx64.efi")
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

// WriteProvenance writes only public installation facts into encrypted /var.
func WriteProvenance(root string, provenance Provenance) error {
	if provenance.Completed == "" {
		provenance.Completed = "completed"
	}
	data, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding secure install provenance: %w", err)
	}
	dir := filepath.Join(root, "var/lib/snosi")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "bootc-secure-install.json"), append(data, '\n'), 0o600)
}
