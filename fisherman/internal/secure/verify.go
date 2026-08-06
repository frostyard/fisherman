package secure

import (
	"bytes"
	"fmt"
	"strings"
)

// ValidateType2BLS verifies a BLS entry references exactly one Type #2 UKI
// and cannot fall back to raw kernel or initrd entries.
func ValidateType2BLS(entry []byte) (string, error) {
	var efi string
	for _, line := range strings.Split(string(entry), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "linux", "initrd":
			return "", fmt.Errorf("type #2 BLS entry contains forbidden %s directive", fields[0])
		// `uki` is what bootc actually writes, and `efi` is the generic
		// EFI-binary directive; both designate the same thing here, a Type #2
		// UKI under /EFI/Linux. Accepting only `efi` rejected every entry bootc
		// produces:
		//
		//   validating .../bootc_cayo-13-1.conf: type #2 BLS entry has no efi
		//   directive
		//
		// snosi's note that "bootc writes a BLS efi= entry" was an observation
		// of one build and has since gone stale. The constraints that matter --
		// exactly one such directive, path under /EFI/Linux, .efi suffix, and no
		// raw linux/initrd -- are unchanged.
		case "efi", "uki":
			if len(fields) != 2 || efi != "" || !strings.HasPrefix(fields[1], "/EFI/Linux/") || !strings.HasSuffix(fields[1], ".efi") {
				return "", fmt.Errorf("type #2 BLS entry has an invalid %s directive", fields[0])
			}
			efi = fields[1]
		}
	}
	if efi == "" {
		return "", fmt.Errorf("type #2 BLS entry has no efi or uki directive")
	}
	return efi, nil
}

// ComparePCRPublicKey refuses a TPM enrollment unless the installed UKI's
// extracted .pcrpkey is byte-for-byte identical to the immutable rootfs key.
func ComparePCRPublicKey(installed, rootfs []byte) error {
	if len(installed) == 0 || len(rootfs) == 0 || !bytes.Equal(installed, rootfs) {
		return fmt.Errorf("installed UKI .pcrpkey does not match the immutable rootfs public key")
	}
	return nil
}
