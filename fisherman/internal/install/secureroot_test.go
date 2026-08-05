package install

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

func tarball(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for name, body := range entries {
		if err := w.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractSecureImageRootWritesTheSubtree(t *testing.T) {
	old := runner.OutputFn
	t.Cleanup(func() { runner.OutputFn = old })
	var got []string
	runner.OutputFn = func(_ string, args ...string) ([]byte, error) {
		got = args
		return tarball(t, map[string]string{
			"usr/lib/snosi/bootc-secure.json":         `{"schema":1}`,
			"usr/lib/snosi/bootc/systemd-bootx64.efi": "EFI",
		}), nil
	}
	dest := t.TempDir()
	if err := ExtractSecureImageRoot("img", "/store", "/runstore", "overlay", dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"usr/lib/snosi/bootc-secure.json", "usr/lib/snosi/bootc/systemd-bootx64.efi"} {
		if _, err := os.Stat(filepath.Join(dest, want)); err != nil {
			t.Fatalf("%s not extracted: %v", want, err)
		}
	}
	// Same reason as the composefs digest probe: bootc/podman must mount the
	// image from inside the container.
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--privileged") || !strings.Contains(joined, "-v /store:/var/lib/containers/storage") {
		t.Fatalf("extraction must be privileged with the store mounted: %q", got)
	}
}

// The archive comes from an image we control, but a traversal entry must never
// be able to write outside the extraction root.
func TestExtractSecureImageRootRefusesPathTraversal(t *testing.T) {
	for _, name := range []string{"../escape", "usr/../../escape", "/absolute"} {
		old := runner.OutputFn
		runner.OutputFn = func(_ string, _ ...string) ([]byte, error) {
			return tarball(t, map[string]string{name: "x"}), nil
		}
		err := ExtractSecureImageRoot("img", "", "", "", t.TempDir())
		runner.OutputFn = old
		if err == nil {
			t.Fatalf("traversal entry %q accepted", name)
		}
	}
}
