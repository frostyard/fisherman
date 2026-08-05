package install

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tuna-os/fisherman/internal/runner"
)

// SecureArtifactSubtree is the single tree holding every artifact the secure
// post-install validation needs from the image: the schema-1 contract, the MOK
// certificate, the PCR public key, and the MOK-signed second stage.
const SecureArtifactSubtree = "usr/lib/snosi"

// ExtractSecureImageRoot materialises SecureArtifactSubtree out of the image
// into dest, producing a directory that can be read with the same relative
// paths the contract uses.
//
// Why this exists: a composefs deployment does not present a merged root under
// the target mount. Its writable /etc is at state/deploy/<hash>/etc and /usr
// comes from the composefs image, which is not a directory tree on the target
// at all — so reading <target>/usr/lib/snosi/... cannot work, and the secure
// install is composefs by contract.
//
// Reading from the image instead is sound rather than merely convenient: the
// deployment's composefs digest is computed and verified immediately before
// this, and bootc pins the deployment to that digest. Source and deployment are
// therefore identical by construction, not by assumption. If that digest check
// were ever removed, this would become an assumption and would need revisiting.
func ExtractSecureImageRoot(image, root, runRoot, driver, dest string) error {
	args := []string{}
	storePath := "/var/lib/containers/storage"
	if root != "" {
		args = append(args, "--root", root, "--runroot", runRoot, "--storage-driver", driver)
		storePath = root
	}
	// Same shape the composefs digest probe needs, and for the same reason:
	// bootc/podman must mount the image from inside the container.
	args = append(args, "run", "--rm", "--pull=never", "--privileged",
		"-v", storePath+":/var/lib/containers/storage",
		image, "tar", "-cf", "-", "-C", "/", SecureArtifactSubtree)

	out, err := runner.Output("podman", args...)
	if err != nil {
		return fmt.Errorf("extracting %s from the verified image: %w", SecureArtifactSubtree, err)
	}
	return untarInto(bytes.NewReader(out), dest)
}

// untarInto extracts a tar stream into dest, refusing entries that would escape
// it. The archive comes from an image we control, but path traversal is cheap
// to rule out and expensive to discover later.
func untarInto(r io.Reader, dest string) error {
	reader := tar.NewReader(r)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading secure artifact archive: %w", err)
		}
		name := filepath.Clean(header.Name)
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("refusing secure artifact path outside the extraction root: %q", header.Name)
		}
		target := filepath.Join(dest, name)
		if rel, relErr := filepath.Rel(dest, target); relErr != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("refusing secure artifact path outside the extraction root: %q", header.Name)
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, reader); err != nil {
				file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		}
		// Other entry types (symlinks, devices) are not part of this subtree
		// and are deliberately skipped rather than reproduced.
	}
}
