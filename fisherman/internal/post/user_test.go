package post_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuna-os/fisherman/internal/post"
	"github.com/tuna-os/fisherman/internal/runner"
)

// captureRuns replaces runner.RunFn with a recorder and restores it on cleanup.
func captureRuns(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	runner.RunFn = func(stdin io.Reader, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { runner.RunFn = runner.DefaultRun })
	return &calls
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// composefsRoot builds a composefs-native sysroot: a state/deploy/<hash>
// dir whose etc/ is a pristine copy of the image /etc (as written by
// bootc's composefs backend), plus the shared var. ComposeFsDeployEtcDirFn
// is overridden to resolve it, mirroring production behaviour.
func composefsRoot(t *testing.T) (sysroot, stateDir string) {
	t.Helper()
	sysroot = t.TempDir()
	stateDir = filepath.Join(sysroot, "state", "deploy", "abc123")

	// Pristine etc copy: passwd already contains the created user because
	// useradd is mocked in these tests.
	writeFile(t, filepath.Join(stateDir, "etc", "passwd"),
		"root:x:0:0:root:/root:/usr/bin/bash\n"+
			"alice:x:1000:1000:Alice:/var/home/alice:/usr/bin/bash\n", 0o644)
	writeFile(t, filepath.Join(stateDir, "etc", "shells"),
		"# /etc/shells: valid login shells\n/bin/bash\n/usr/bin/bash\n/usr/bin/sh\n", 0o644)
	writeFile(t, filepath.Join(stateDir, "etc", "skel", ".bashrc"), "# skel\n", 0o644)

	// Shared var plus the deployment's relative var symlink, as laid out by
	// write_composefs_state.
	sharedVar := filepath.Join(sysroot, "state", "os", "default", "var")
	if err := os.MkdirAll(sharedVar, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../os/default/var", filepath.Join(stateDir, "var")); err != nil {
		t.Fatal(err)
	}

	post.ComposeFsDeployEtcDirFn = func(target string) (string, error) {
		return filepath.Join(stateDir, "etc"), nil
	}
	t.Cleanup(func() { post.ComposeFsDeployEtcDirFn = post.DefaultComposeFsDeployEtcDir })
	return sysroot, stateDir
}

// ostreeRoot builds an ostree/bootc sysroot with a deployment dir containing
// a full tree (executable shells present on disk).
func ostreeRoot(t *testing.T, shells ...string) (sysroot, deployDir string) {
	t.Helper()
	sysroot = t.TempDir()
	deployDir = filepath.Join(sysroot, "ostree", "deploy", "default", "deploy", "hash.0")
	// An OS-name dir under ostree/deploy marks the sysroot as ostree-based.
	if err := os.MkdirAll(deployDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, s := range shells {
		writeFile(t, filepath.Join(deployDir, s), "#!/bin/sh\n", 0o755)
	}
	post.DeploymentDirFn = func(target string) (string, error) { return deployDir, nil }
	t.Cleanup(func() { post.DeploymentDirFn = post.DefaultDeploymentDir })
	return sysroot, deployDir
}

// findCall returns the first recorded invocation of name, or nil.
func findCall(calls [][]string, name string) []string {
	for _, c := range calls {
		if c[0] == name {
			return c
		}
	}
	return nil
}

// argAfter returns the argument following flag in call, or "".
func argAfter(call []string, flag string) string {
	for i, a := range call {
		if a == flag && i+1 < len(call) {
			return call[i+1]
		}
	}
	return ""
}

func TestCreateUserComposeFsUsesStateDirAsRoot(t *testing.T) {
	calls := captureRuns(t)
	sysroot, stateDir := composefsRoot(t)

	if err := post.CreateUser(sysroot, post.UserConfig{Username: "alice", Password: "secret"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	ua := findCall(*calls, "useradd")
	if ua == nil {
		t.Fatal("useradd was not invoked")
	}
	if got := argAfter(ua, "--root"); got != stateDir {
		t.Errorf("useradd --root = %q, want %q", got, stateDir)
	}
	// The state dir's var symlink dangles inside the chroot, so useradd
	// must not be asked to create the home directory.
	for _, a := range ua {
		if a == "--create-home" {
			t.Error("useradd must not use --create-home on composefs targets")
		}
	}
	// Shell comes from the pristine etc/shells (no binaries exist under the
	// state dir to stat).
	if got := argAfter(ua, "--shell"); got != "/usr/bin/bash" {
		t.Errorf("useradd --shell = %q, want /usr/bin/bash", got)
	}
}

func TestCreateUserComposeFsCreatesHomeInSharedVar(t *testing.T) {
	calls := captureRuns(t)
	sysroot, stateDir := composefsRoot(t)

	if err := post.CreateUser(sysroot, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Home is created through the state dir's var symlink, which resolves on
	// the host to the shared var.
	wantHome := filepath.Join(stateDir, "var", "home", "alice")
	mk := findCall(*calls, "mkdir")
	if mk == nil || mk[len(mk)-1] != wantHome {
		t.Errorf("mkdir call = %v, want target %q", mk, wantHome)
	}
	cp := findCall(*calls, "cp")
	if cp == nil || cp[len(cp)-1] != wantHome || cp[len(cp)-2] != filepath.Join(stateDir, "etc", "skel") {
		t.Errorf("cp call = %v, want skel -> %q", cp, wantHome)
	}
	ch := findCall(*calls, "chown")
	if ch == nil || ch[len(ch)-1] != wantHome {
		t.Errorf("chown call = %v, want target %q", ch, wantHome)
	}
	found := false
	for _, a := range ch {
		if a == "1000:1000" {
			found = true
		}
	}
	if ch != nil && !found {
		t.Errorf("chown call = %v, want uid:gid 1000:1000 from passwd", ch)
	}
}

func TestCreateUserComposeFsChpasswdAvoidsPAM(t *testing.T) {
	calls := captureRuns(t)
	sysroot, _ := composefsRoot(t)

	if err := post.CreateUser(sysroot, post.UserConfig{Username: "alice", Password: "secret"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cp := findCall(*calls, "chpasswd")
	if cp == nil {
		t.Fatal("chpasswd was not invoked")
	}
	// The etc-only chroot has no PAM modules; an explicit crypt method makes
	// chpasswd hash the password itself.
	if got := argAfter(cp, "--crypt-method"); got == "" {
		t.Errorf("chpasswd call %v lacks --crypt-method (PAM would fail in etc-only chroot)", cp)
	}
}

func TestCreateUserOstreeKeepsCreateHome(t *testing.T) {
	calls := captureRuns(t)
	sysroot, deployDir := ostreeRoot(t, "usr/bin/bash", "bin/bash")

	if err := post.CreateUser(sysroot, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	ua := findCall(*calls, "useradd")
	if ua == nil {
		t.Fatal("useradd was not invoked")
	}
	if got := argAfter(ua, "--root"); got != deployDir {
		t.Errorf("useradd --root = %q, want %q", got, deployDir)
	}
	hasCreateHome := false
	for _, a := range ua {
		if a == "--create-home" {
			hasCreateHome = true
		}
	}
	if !hasCreateHome {
		t.Error("useradd must keep --create-home on ostree targets")
	}
	if got := argAfter(ua, "--shell"); got != "/usr/bin/bash" {
		t.Errorf("useradd --shell = %q, want /usr/bin/bash", got)
	}
}

func TestCreateUserOstreeShellFallsBackToBinBash(t *testing.T) {
	calls := captureRuns(t)
	sysroot, _ := ostreeRoot(t, "bin/bash")

	if err := post.CreateUser(sysroot, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	ua := findCall(*calls, "useradd")
	if got := argAfter(ua, "--shell"); got != "/bin/bash" {
		t.Errorf("useradd --shell = %q, want /bin/bash", got)
	}
}

func TestCreateUserOstreeShellDefaultsWhenNothingFound(t *testing.T) {
	calls := captureRuns(t)
	sysroot, _ := ostreeRoot(t) // no shells on disk, no etc/shells

	if err := post.CreateUser(sysroot, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	ua := findCall(*calls, "useradd")
	if got := argAfter(ua, "--shell"); got != "/usr/bin/bash" {
		t.Errorf("useradd --shell = %q, want /usr/bin/bash", got)
	}
}
