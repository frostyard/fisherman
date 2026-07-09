package post

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tuna-os/fisherman/internal/runner"
)

// UserConfig describes a user account to create in the installed system.
type UserConfig struct {
	Username string
	Fullname string
	Password string
	Groups   []string // additional groups beyond the primary group
}

// CreateUser creates a user account inside the installed system rooted at sysroot.
//
// For ostree/bootc deployments, the deployment directory (found via DeploymentDirFn)
// is used as the --root for useradd so that the image's /etc/passwd, /etc/shadow,
// and /etc/group are updated. The sysroot root itself does not contain these files.
//
// For composefs-native deployments, the OS tree lives in a read-only EROFS
// image; the only real /etc on disk is the pristine copy under
// state/deploy/<id>/etc, so that state dir is the useradd --root. Its var
// symlink (../../os/default/var) dangles inside the chroot, so the home
// directory is created host-side in the shared var instead of via
// --create-home, and chpasswd gets an explicit crypt method because the
// etc-only chroot has no PAM modules to load.
//
// Returns nil if Username is empty (no-op).
func CreateUser(sysroot string, u UserConfig) error {
	if u.Username == "" {
		return nil
	}

	var root string
	composefs := isComposeFsNative(sysroot)
	if composefs {
		etcDir, err := ComposeFsDeployEtcDirFn(sysroot)
		if err != nil {
			return fmt.Errorf("finding composefs deploy etc: %w", err)
		}
		root = filepath.Dir(etcDir)
	} else {
		deployDir, err := DeploymentDirFn(sysroot)
		if err != nil {
			return fmt.Errorf("finding deployment dir: %w", err)
		}
		root = deployDir

		// On ostree/bootc, /home inside the deployment is a symlink to
		// var/home (the stateroot var). Pre-create the stateroot home dir so
		// that useradd --create-home has a real directory to populate.
		staterootHome := filepath.Join(sysroot, "ostree", "deploy", "default", "var", "home")
		if err := runner.Run("mkdir", "-p", staterootHome); err != nil {
			return fmt.Errorf("mkdir stateroot home: %w", err)
		}
	}

	// Build useradd arguments.
	args := []string{
		"--root", root,
		"--shell", loginShell(root),
	}
	if !composefs {
		args = append(args, "--create-home")
	}
	if u.Fullname != "" {
		args = append(args, "--comment", u.Fullname)
	}
	if len(u.Groups) > 0 {
		args = append(args, "--groups", strings.Join(u.Groups, ","))
	}
	args = append(args, u.Username)

	if err := runner.Run("useradd", args...); err != nil {
		return fmt.Errorf("useradd: %w", err)
	}

	if composefs {
		if err := createComposeFsHome(root, u.Username); err != nil {
			return fmt.Errorf("creating home: %w", err)
		}
	}

	// Set the password via chpasswd stdin to avoid it appearing in ps output.
	if u.Password != "" {
		input := fmt.Sprintf("%s:%s\n", u.Username, u.Password)
		chpasswdArgs := []string{"--root", root}
		if composefs {
			chpasswdArgs = append(chpasswdArgs, "--crypt-method", "SHA512")
		}
		if err := runner.RunWithStdin(bytes.NewBufferString(input), "chpasswd", chpasswdArgs...); err != nil {
			return fmt.Errorf("chpasswd: %w", err)
		}
	}

	fmt.Printf("  created user %q in installed system\n", u.Username)
	return nil
}

// createComposeFsHome creates the user's home directory for a composefs-native
// deployment. The home path recorded by useradd (normally /var/home/<user>,
// from the image's /etc/default/useradd) is resolved through the state dir's
// var symlink, which on the host points at the shared var
// (state/os/default/var) — the tree that is mounted at /var on the booted
// system. Skel files are copied from the pristine etc and ownership is taken
// from the passwd entry useradd just wrote.
func createComposeFsHome(stateDir, username string) error {
	home, uid, gid, err := passwdEntry(filepath.Join(stateDir, "etc", "passwd"), username)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(home, "/var/") {
		fmt.Printf("  warning: home %q is not under /var, skipping home creation\n", home)
		return nil
	}

	dest := filepath.Join(stateDir, home)
	if err := runner.Run("mkdir", "-p", dest); err != nil {
		return fmt.Errorf("mkdir %s: %w", dest, err)
	}
	skel := filepath.Join(stateDir, "etc", "skel")
	if _, err := os.Stat(skel); err == nil {
		if err := runner.Run("cp", "-aT", skel, dest); err != nil {
			return fmt.Errorf("copying skel: %w", err)
		}
	}
	if err := runner.Run("chown", "-R", fmt.Sprintf("%s:%s", uid, gid), dest); err != nil {
		return fmt.Errorf("chown %s: %w", dest, err)
	}
	if err := runner.Run("chmod", "700", dest); err != nil {
		return fmt.Errorf("chmod %s: %w", dest, err)
	}
	return nil
}

// passwdEntry returns the home directory, uid, and gid recorded for username
// in the passwd file at path.
func passwdEntry(path, username string) (home, uid, gid string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", fmt.Errorf("reading %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 6 && fields[0] == username {
			return fields[5], fields[2], fields[3], nil
		}
	}
	return "", "", "", fmt.Errorf("user %q not found in %s", username, path)
}

// loginShell picks the login shell for the created user, validating each
// candidate against the installed system's root rather than the live
// environment. A candidate is accepted if it is listed in the root's
// /etc/shells (the image's own list — on composefs targets no binaries exist
// under the root to stat) or if it exists and is executable under the root.
// /usr/bin/bash comes first: on merged-/usr images /bin is a symlink that may
// not resolve in every mount context. If nothing validates, /usr/bin/bash is
// still returned so the account is created with a sane value (useradd itself
// only warns).
func loginShell(root string) string {
	candidates := []string{"/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh"}
	listed := readEtcShells(filepath.Join(root, "etc", "shells"))
	for _, shell := range candidates {
		if listed[shell] {
			return shell
		}
		fi, err := os.Stat(filepath.Join(root, shell))
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0111 != 0 {
			return shell
		}
	}
	fmt.Printf("  warning: no login shell found under %s, defaulting to /usr/bin/bash\n", root)
	return "/usr/bin/bash"
}

// readEtcShells parses an /etc/shells file into a set. Returns an empty set
// if the file cannot be read.
func readEtcShells(path string) map[string]bool {
	shells := map[string]bool{}
	f, err := os.Open(path)
	if err != nil {
		return shells
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		shells[line] = true
	}
	return shells
}
