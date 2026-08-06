package secure

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

// cmdlineDumpTarget mirrors how composefsIdentityFromUKI actually invokes
// objcopy: `--dump-section` and `.cmdline=<path>` are SEPARATE argv elements,
// not one `--dump-section=.cmdline=<path>` string. Getting this wrong makes the
// stub silently produce no cmdline, which reads as "the UKI has no composefs
// identity" rather than as a broken test.
func cmdlineDumpTarget(args []string) (string, bool) {
	for _, arg := range args {
		if rest, ok := strings.CutPrefix(arg, ".cmdline="); ok {
			return rest, true
		}
	}
	return "", false
}

// ukiFixture builds a target whose ESP carries bootc's UKI and an image root
// carrying the signed one, mirroring the real layout: bootc nests its UKI one
// level deeper, under EFI/Linux/bootc/.
func ukiFixture(t *testing.T) (root, imageRoot, installed string) {
	t.Helper()
	root, imageRoot = t.TempDir(), t.TempDir()
	installed = filepath.Join(root, installedUKIDir, "bootc", "bootc_composefs-abc.efi")
	source := filepath.Join(imageRoot, imageUKIDir, "7.1.3+deb13-amd64.efi")
	for path, content := range map[string]string{
		installed: "bootc-rewritten-unsigned",
		source:    "image-signed-uki",
		filepath.Join(imageRoot, "usr/lib/snosi/mok.crt"): "cert",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, imageRoot, installed
}

// stubUKI makes sbverify report the installed UKI unsigned and everything else
// signed, and gives both UKIs the same composefs identity — the normal case.
func stubUKI(t *testing.T, installed string) {
	t.Helper()
	oldRun, oldOut := runner.RunFn, runner.OutputFn
	t.Cleanup(func() { runner.RunFn, runner.OutputFn = oldRun, oldOut })
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		// composefsIdentityFromUKI shells out to objcopy --dump-section.
		if name == "objcopy" {
			if dest, ok := cmdlineDumpTarget(args); ok {
				return os.WriteFile(dest, []byte("rw composefs=?deadbeef\x00\x00"), 0o644)
			}
		}
		return nil
	}
	runner.OutputFn = func(_ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[len(args)-1] == installed {
			return []byte("No signature table present\n"), nil
		}
		return []byte("signature 1\nimage signature issuers:\n - /CN=snosi\n"), nil
	}
}

func TestStageSignedUKIReplacesTheUnsignedOne(t *testing.T) {
	root, imageRoot, installed := ukiFixture(t)
	stubUKI(t, installed)

	if err := StageSignedUKI(root, imageRoot, "/usr/lib/snosi/mok.crt"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	got, err := os.ReadFile(installed)
	if err != nil {
		t.Fatal(err)
	}
	// The signed build must land at bootc's path, keeping the filename the BLS
	// entry references.
	if string(got) != "image-signed-uki" {
		t.Fatalf("installed UKI = %q, want the image's signed one", got)
	}
}

// A future bootc that preserves the signature must not have its UKI touched.
func TestStageSignedUKILeavesASignedUKIAlone(t *testing.T) {
	root, imageRoot, installed := ukiFixture(t)
	stubUKI(t, installed)
	runner.OutputFn = func(_ string, _ ...string) ([]byte, error) {
		return []byte("signature 1\nimage signature issuers:\n - /CN=snosi\n"), nil
	}

	if err := StageSignedUKI(root, imageRoot, "/usr/lib/snosi/mok.crt"); err != nil {
		t.Fatalf("stage: %v", err)
	}
	got, _ := os.ReadFile(installed)
	if string(got) != "bootc-rewritten-unsigned" {
		t.Fatal("an already-signed installed UKI was replaced")
	}
}

// The composefs identity is what makes this a substitution of the same boot
// rather than a swap to a different one. A mismatch must stop the install
// instead of producing a target that boots the wrong root.
func TestStageSignedUKIRefusesAComposefsMismatch(t *testing.T) {
	root, imageRoot, installed := ukiFixture(t)
	stubUKI(t, installed)
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		if name != "objcopy" {
			return nil
		}
		dest, ok := cmdlineDumpTarget(args)
		if !ok {
			return nil
		}
		id := "?deadbeef"
		// The image's UKI names a different deployment.
		if strings.Contains(args[len(args)-1], imageUKIDir) {
			id = "?feedface"
		}
		return os.WriteFile(dest, []byte("rw composefs="+id+"\x00"), 0o644)
	}

	err := StageSignedUKI(root, imageRoot, "/usr/lib/snosi/mok.crt")
	if err == nil {
		t.Fatal("staged a UKI naming a different composefs deployment")
	}
	if !strings.Contains(err.Error(), "composefs identity") {
		t.Fatalf("error did not name the mismatch: %v", err)
	}
	got, _ := os.ReadFile(installed)
	if string(got) != "bootc-rewritten-unsigned" {
		t.Fatal("installed UKI was replaced despite the mismatch")
	}
}

// An image UKI that fails MOK verification must fail the install rather than
// land on the ESP, where it would only be discovered as an unbootable disk.
func TestStageSignedUKIRefusesAnUnverifiableImageUKI(t *testing.T) {
	root, imageRoot, installed := ukiFixture(t)
	stubUKI(t, installed)
	runner.RunFn = func(_ io.Reader, name string, _ ...string) error {
		if name == "sbverify" {
			return os.ErrPermission
		}
		return nil
	}

	if err := StageSignedUKI(root, imageRoot, "/usr/lib/snosi/mok.crt"); err == nil {
		t.Fatal("staged a UKI that failed MOK verification")
	}
	got, _ := os.ReadFile(installed)
	if string(got) != "bootc-rewritten-unsigned" {
		t.Fatal("installed UKI was replaced despite failed verification")
	}
}
