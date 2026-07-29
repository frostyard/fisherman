package secure_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tuna-os/fisherman/internal/secure"
)

func TestLoadInstalledContractReadsTargetRoot(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "usr/lib/snosi")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "bootc-secure.json"), []byte(validContract), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := secure.LoadInstalledContract(root); err != nil {
		t.Fatalf("LoadInstalledContract() error = %v", err)
	}
}
