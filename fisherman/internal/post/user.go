package post

import (
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
// Returns nil if Username is empty (no-op).
func CreateUser(sysroot string, u UserConfig) error {
	if u.Username == "" {
		return nil
	}

	var root string
	if isComposeFsNative(sysroot) {
		root = sysroot
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
		"--create-home",
		"--shell", loginShell(root),
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

	// Set the password via chpasswd stdin to avoid it appearing in ps output.
	if u.Password != "" {
		input := fmt.Sprintf("%s:%s\n", u.Username, u.Password)
		chpasswdArgs := []string{"--root", root}
		if err := runner.RunWithStdin(bytes.NewBufferString(input), "chpasswd", chpasswdArgs...); err != nil {
			return fmt.Errorf("chpasswd: %w", err)
		}
	}

	fmt.Printf("  created user %q in installed system\n", u.Username)
	return nil
}

// loginShell picks the login shell for the created user, validating each
// candidate against the installed system's root rather than the live
// environment. /usr/bin/bash comes first: on merged-/usr images /bin is a
// symlink that may not resolve in every mount context, so the canonical path
// is the safe choice. If nothing validates, /usr/bin/bash is still returned
// so the account is created with a sane value (useradd itself only warns).
func loginShell(root string) string {
	candidates := []string{"/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh"}
	for _, shell := range candidates {
		fi, err := os.Stat(filepath.Join(root, shell))
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0111 != 0 {
			return shell
		}
	}
	fmt.Printf("  warning: no login shell found under %s, defaulting to /usr/bin/bash\n", root)
	return "/usr/bin/bash"
}
