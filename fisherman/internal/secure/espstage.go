package secure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tuna-os/fisherman/internal/runner"
)

// ESP chain component paths, relative to the image root.
const (
	imageShim        = "usr/lib/shim/shimx64.efi"
	imageMokManager  = "usr/lib/shim/mmx64.efi"
	imageSecondStage = "usr/lib/snosi/bootc/systemd-bootx64.efi"
)

// StageESPChain writes the Secure Boot chain onto a freshly installed ESP.
//
// `bootc install --bootloader systemd` writes plain systemd-boot as
// EFI/BOOT/BOOTX64.EFI and knows nothing about shim, so a secure install ends
// with an ESP that firmware will not accept. The chain the secure design needs
// is the one the native A/B image already ships:
//
//	EFI/BOOT/BOOTX64.EFI   shim, Microsoft-signed -- what firmware runs
//	EFI/BOOT/grubx64.efi   MOK-signed systemd-boot -- what shim chainloads
//	EFI/BOOT/mmx64.efi     MokManager -- enrolls the MOK on first boot
//
// This is the step that was missing entirely. RepairESP *repairs* that chain --
// it requires all three to exist and replaces only the second stage -- and the
// Task 7 runtime reconciler likewise never modifies shim or MokManager. Both
// assumed an install step that placed them, which on the native A/B path is
// done by mkosi/repart and on the bootc path was done by nobody.
//
// Idempotent: an ESP that already carries the chain is left alone, so this is
// safe to call on an existing install.
func StageESPChain(root, imageRoot, mokCertificate string) error {
	boot := filepath.Join(root, "boot/efi/EFI/BOOT")
	if _, err := os.Stat(boot); err != nil {
		return fmt.Errorf("locating installed ESP boot directory: %w", err)
	}

	staged := 0
	for _, name := range []string{"BOOTX64.EFI", "grubx64.efi", "mmx64.efi"} {
		if _, err := os.Stat(filepath.Join(boot, name)); err == nil {
			staged++
		}
	}
	if staged == 3 {
		return nil
	}

	// The second stage is the only component this verifies, and deliberately so.
	// It is the binary snosi signs with its own MOK, so the MOK certificate is
	// the right check for it. shim and MokManager come from Debian and are
	// Microsoft-signed; verifying them against snosi's MOK would fail, and
	// their trust is established by firmware at boot, not here. What this does
	// rely on is that all three came out of an image whose signature was
	// verified at pull time.
	if mokCertificate == "" || !strings.HasPrefix(mokCertificate, "/") {
		return fmt.Errorf("validating MOK certificate path for ESP staging")
	}
	certificate := filepath.Join(imageRoot, strings.TrimPrefix(mokCertificate, "/"))
	secondStage := filepath.Join(imageRoot, imageSecondStage)
	if err := runner.Run("sbverify", "--cert", certificate, secondStage); err != nil {
		return fmt.Errorf("verifying MOK-signed second stage before staging: %w", err)
	}

	// shim LAST: until it is in place the firmware entry point is still bootc's
	// plain systemd-boot, which at least boots without Secure Boot. Writing
	// shim before its chainload target exists would leave an ESP that cannot
	// boot at all if this is interrupted.
	for _, component := range []struct{ source, target string }{
		{imageSecondStage, "grubx64.efi"},
		{imageMokManager, "mmx64.efi"},
		{imageShim, "BOOTX64.EFI"},
	} {
		if err := copyESPComponent(filepath.Join(imageRoot, component.source), filepath.Join(boot, component.target)); err != nil {
			return err
		}
	}
	return nil
}

// copyESPComponent writes one binary to the ESP and flushes it. The ESP is FAT
// on a disk about to be rebooted into; an unflushed write is a brick.
func copyESPComponent(source, target string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("reading ESP component %s: %w", filepath.Base(source), err)
	}
	if len(data) == 0 {
		return fmt.Errorf("refusing to stage empty ESP component %s", filepath.Base(source))
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("opening ESP component %s: %w", filepath.Base(target), err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("writing ESP component %s: %w", filepath.Base(target), err)
	}
	if err := syncFile(file); err != nil {
		file.Close()
		return fmt.Errorf("flushing ESP component %s: %w", filepath.Base(target), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("closing ESP component %s: %w", filepath.Base(target), err)
	}
	return nil
}
