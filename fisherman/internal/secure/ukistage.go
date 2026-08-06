package secure

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tuna-os/fisherman/internal/runner"
)

// imageUKIDir is where snosi's build leaves the MOK-signed UKI inside the
// image, written and signature-verified by shared/bootc-secure/assemble-uki.sh.
const imageUKIDir = "boot/EFI/Linux"

// installedUKIDir is the ESP subtree bootc writes its UKI into, relative to the
// target mount. bootc nests one level further (EFI/Linux/bootc/), hence a walk
// rather than a directory read.
const installedUKIDir = "boot/efi/EFI/Linux"

// StageSignedUKI replaces the UKI bootc wrote with the signed one from the
// image.
//
// `bootc install` does not preserve the UKI's Authenticode signature. It writes
// a UKI whose sections are identical in name and size to the image's, carrying
// the same .cmdline, .pcrsig and .pcrpkey, but rebuilt as a fresh PE -- roughly
// 20 KiB smaller than the image's UKI even after that one's signature is
// stripped, so this is a rewrite and not a copy. The rewrite drops the
// signature, and with Secure Boot enforced the result cannot boot:
//
//	Error loading EFI binary \EFI\Linux\bootc\bootc_composefs-<id>.efi:
//	Invalid parameter
//	BdsDxe: No bootable option or device was found.
//
// Re-signing is not an option and is not wanted: the MOK private key must never
// be present during an install. Since the bytes differ, the image's existing
// signature cannot be re-attached to bootc's file either. Installing the
// already-signed artifact is the only move that needs no key.
//
// This is safe because the two UKIs are the same kernel, initrd and command
// line: the composefs identity is checked to match on both sides, and that
// identity pins the deployment bootc just wrote. Swapping in the signed build
// changes the signature and nothing that boots.
//
// Idempotent: an installed UKI that already carries a signature is left alone,
// so a future bootc that preserves it needs no change here.
func StageSignedUKI(root, imageRoot, mokCertificate string) error {
	installed, err := findUKIs(filepath.Join(root, installedUKIDir))
	if err != nil {
		return err
	}
	if len(installed) != 1 {
		return fmt.Errorf("expected exactly one installed UKI under %s, found %d", installedUKIDir, len(installed))
	}
	target := installed[0]

	// Already signed: nothing to do, and nothing to risk.
	if err := assertPESigned(target); err == nil {
		return nil
	}

	source, err := findUKIs(filepath.Join(imageRoot, imageUKIDir))
	if err != nil {
		return err
	}
	if len(source) != 1 {
		return fmt.Errorf("expected exactly one signed UKI under the image's %s, found %d", imageUKIDir, len(source))
	}

	// The image UKI must carry snosi's own MOK signature. shim verifies it
	// against the enrolled MOK at boot; verifying it here means a mis-signed
	// image fails the install instead of producing an unbootable disk.
	if mokCertificate == "" || !strings.HasPrefix(mokCertificate, "/") {
		return fmt.Errorf("validating MOK certificate path for UKI staging")
	}
	certificate := filepath.Join(imageRoot, strings.TrimPrefix(mokCertificate, "/"))
	if err := runner.Run("sbverify", "--cert", certificate, source[0]); err != nil {
		return fmt.Errorf("verifying MOK-signed UKI before staging: %w", err)
	}

	// The composefs identity is what makes this a substitution rather than a
	// replacement: it pins the UKI to the exact deployment bootc wrote. If the
	// image's UKI names a different one, these are not the same boot and the
	// install must stop rather than produce a target that boots the wrong root.
	installedID, err := composefsIdentityFromUKI(target)
	if err != nil {
		return err
	}
	sourceID, err := composefsIdentityFromUKI(source[0])
	if err != nil {
		return err
	}
	if installedID == "" || sourceID == "" {
		return fmt.Errorf("refusing to stage a UKI without a composefs identity on both sides")
	}
	if installedID != sourceID {
		return fmt.Errorf("refusing to stage the image UKI: composefs identity %q does not match the installed %q", sourceID, installedID)
	}

	// Same flush-before-reboot reasoning as the ESP chain: this is FAT on a
	// disk about to be booted.
	return copyESPComponent(source[0], target)
}

// findUKIs returns every *.efi under dir, recursively. A missing directory is
// not an error here -- the caller's count check reports it with more context
// than a bare ENOENT would.
func findUKIs(dir string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !entry.IsDir() && strings.EqualFold(filepath.Ext(path), ".efi") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning %s for UKIs: %w", dir, err)
	}
	return found, nil
}
