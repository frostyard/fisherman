package secure_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
	"github.com/tuna-os/fisherman/internal/secure"
)

func TestEnrollTPMUsesRecoveryCredentialAndSignedPCR11(t *testing.T) {
	oldRun := runner.RunFn
	t.Cleanup(func() { runner.RunFn = oldRun })
	var name string
	var args []string
	runner.RunFn = func(_ io.Reader, gotName string, gotArgs ...string) error {
		name, args = gotName, gotArgs
		return nil
	}
	recovery := filepath.Join(t.TempDir(), "recovery")
	if err := os.WriteFile(recovery, []byte("recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secure.EnrollTPM(recovery, "/run/installed.pcrpkey", "/dev/nvme0n1p2"); err != nil {
		t.Fatalf("EnrollTPM() error = %v", err)
	}
	if name != "systemd-cryptenroll" {
		t.Fatalf("command = %q", name)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--unlock-key-file=" + recovery, "--tpm2-device=auto", "--tpm2-pcrs=", "--tpm2-public-key=/run/installed.pcrpkey", "--tpm2-public-key-pcrs=11", "--tpm2-pcrlock=", "/dev/nvme0n1p2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
}

func TestStageMOKUsesPrivateHashAndDERCertificate(t *testing.T) {
	oldRun, oldOutput := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = oldRun, oldOutput })
	dir := t.TempDir()
	password := filepath.Join(dir, "mok-password")
	if err := os.WriteFile(password, []byte("MokPassw0rd"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	runner.OutputFn = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name != "mokutil" || len(args) != 1 || args[0] != "--generate-hash=MokPassw0rd" {
			t.Fatalf("hash command = %s %q", name, args)
		}
		return []byte("hash\n"), nil
	}
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch name {
		case "openssl":
			if len(args) != 7 || args[0] != "x509" || args[1] != "-in" || args[3] != "-outform" || args[4] != "DER" || args[5] != "-out" || args[6] == "" {
				t.Fatalf("openssl args = %q", args)
			}
		case "mokutil":
			if len(args) != 3 || args[0] != "--import" || args[2] == "" || !strings.HasPrefix(args[2], "--hash-file=") {
				t.Fatalf("import args = %q", args)
			}
		default:
			t.Fatalf("unexpected command %q", name)
		}
		return nil
	}
	if err := secure.StageMOK("/target/usr/lib/snosi/mok.crt", password); err != nil {
		t.Fatalf("StageMOK() error = %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls = %q", calls)
	}
}

func TestStageMOKRejectsUnsafePasswordFile(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		contents string
		mode     os.FileMode
	}{
		"empty":   {"", 0o600},
		"newline": {"MokPassw0rd\n", 0o600},
		"short":   {"short", 0o600},
		"mode":    {"MokPassw0rd", 0o644},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(tc.contents), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := secure.StageMOK("/certificate", path); err == nil {
				t.Fatal("unsafe MOK password accepted")
			}
		})
	}
}
