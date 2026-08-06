package secure_test

import (
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/secure"
)

func TestValidateType2BLSRequiresEFIOnly(t *testing.T) {
	efi, err := secure.ValidateType2BLS([]byte("title Snosi\nefi /EFI/Linux/bootc.efi\noptions rw composefs=?abc\n"))
	if err != nil {
		t.Fatalf("ValidateType2BLS() error = %v", err)
	}
	if efi != "/EFI/Linux/bootc.efi" {
		t.Fatalf("EFI path = %q", efi)
	}
	for name, entry := range map[string]string{
		"raw linux":  "efi /EFI/Linux/bootc.efi\nlinux /vmlinuz\n",
		"raw initrd": "efi /EFI/Linux/bootc.efi\ninitrd /initrd\n",
		"no efi":     "title Snosi\noptions rw\n",
		"two efi":    "efi /EFI/Linux/one.efi\nefi /EFI/Linux/two.efi\n",
		"two uki":    "uki /EFI/Linux/one.efi\nuki /EFI/Linux/two.efi\n",
		// Ambiguous rather than merely redundant: nothing says which one boots.
		"efi and uki":            "efi /EFI/Linux/one.efi\nuki /EFI/Linux/two.efi\n",
		"uki outside /EFI/Linux": "uki /EFI/other.efi\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := secure.ValidateType2BLS([]byte(entry)); err == nil || !strings.Contains(err.Error(), "type #2") {
				t.Fatalf("ValidateType2BLS() error = %v", err)
			}
		})
	}
}

// The shape bootc actually writes. Accepting only `efi` rejected every entry it
// produces, which is what blocker 11 was.
func TestValidateType2BLSAcceptsTheUKIDirectiveBootcWrites(t *testing.T) {
	entry := "title Cayo Linux 13\nversion 13\n" +
		"uki /EFI/Linux/bootc/bootc_composefs-7284737ba131387625d6c296.efi\n" +
		"sort-key bootc-cayo-0\n"
	efi, err := secure.ValidateType2BLS([]byte(entry))
	if err != nil {
		t.Fatalf("ValidateType2BLS() rejected the entry bootc writes: %v", err)
	}
	if efi != "/EFI/Linux/bootc/bootc_composefs-7284737ba131387625d6c296.efi" {
		t.Fatalf("EFI path = %q", efi)
	}
}

func TestComparePCRPublicKeyRequiresExactBytes(t *testing.T) {
	if err := secure.ComparePCRPublicKey([]byte("installed"), []byte("installed")); err != nil {
		t.Fatalf("ComparePCRPublicKey() error = %v", err)
	}
	if err := secure.ComparePCRPublicKey([]byte("installed"), []byte("rootfs")); err == nil {
		t.Fatal("different PCR public keys accepted")
	}
}
