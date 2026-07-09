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

// fakeRoot creates a composefs-native sysroot (no ostree/deploy) containing
// the given executable shell paths.
func fakeRoot(t *testing.T, shells ...string) string {
	t.Helper()
	root := t.TempDir()
	for _, s := range shells {
		p := filepath.Join(root, s)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// useraddShell extracts the value passed after --shell in the recorded
// useradd invocation, failing the test if useradd was never run.
func useraddShell(t *testing.T, calls [][]string) string {
	t.Helper()
	for _, call := range calls {
		if call[0] != "useradd" {
			continue
		}
		for i, arg := range call {
			if arg == "--shell" && i+1 < len(call) {
				return call[i+1]
			}
		}
		t.Fatalf("useradd invoked without --shell: %v", call)
	}
	t.Fatal("useradd was not invoked")
	return ""
}

func TestCreateUserPrefersUsrBinBash(t *testing.T) {
	calls := captureRuns(t)
	root := fakeRoot(t, "usr/bin/bash", "bin/bash")

	if err := post.CreateUser(root, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got := useraddShell(t, *calls); got != "/usr/bin/bash" {
		t.Errorf("shell = %q, want /usr/bin/bash", got)
	}
}

func TestCreateUserFallsBackToBinBash(t *testing.T) {
	calls := captureRuns(t)
	root := fakeRoot(t, "bin/bash")

	if err := post.CreateUser(root, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got := useraddShell(t, *calls); got != "/bin/bash" {
		t.Errorf("shell = %q, want /bin/bash", got)
	}
}

func TestCreateUserFallsBackToShWhenNoBash(t *testing.T) {
	calls := captureRuns(t)
	root := fakeRoot(t, "usr/bin/sh")

	if err := post.CreateUser(root, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got := useraddShell(t, *calls); got != "/usr/bin/sh" {
		t.Errorf("shell = %q, want /usr/bin/sh", got)
	}
}

func TestCreateUserDefaultsWhenNoShellFound(t *testing.T) {
	calls := captureRuns(t)
	root := fakeRoot(t) // no shells at all

	if err := post.CreateUser(root, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got := useraddShell(t, *calls); got != "/usr/bin/bash" {
		t.Errorf("shell = %q, want /usr/bin/bash", got)
	}
}

func TestCreateUserIgnoresNonExecutableShell(t *testing.T) {
	calls := captureRuns(t)
	root := fakeRoot(t, "bin/bash")
	// usr/bin/bash exists but is not executable — must be skipped.
	p := filepath.Join(root, "usr/bin/bash")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("not a shell"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := post.CreateUser(root, post.UserConfig{Username: "alice"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if got := useraddShell(t, *calls); got != "/bin/bash" {
		t.Errorf("shell = %q, want /bin/bash", got)
	}
}
