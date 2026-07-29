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
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := secure.ValidateType2BLS([]byte(entry)); err == nil || !strings.Contains(err.Error(), "type #2") {
				t.Fatalf("ValidateType2BLS() error = %v", err)
			}
		})
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
