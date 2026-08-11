package e2e_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildFisherman(t *testing.T) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "fisherman")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/fisherman")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fisherman: %v\n%s", err, output)
	}
	return bin
}

func writeRecipe(t *testing.T, fields map[string]any) string {
	t.Helper()

	contents, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "recipe.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateCommandAcceptsValidRecipe(t *testing.T) {
	bin := buildFisherman(t)
	disk := filepath.Join(t.TempDir(), "disk")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recipe := writeRecipe(t, map[string]any{
		"disk":       disk,
		"filesystem": "xfs",
		"encryption": map[string]any{"type": "none"},
		"image":      "ghcr.io/frostyard/cayo:stable",
		"hostname":   "fisherman-e2e",
	})

	output, err := exec.Command(bin, "validate", recipe).CombinedOutput()
	if err != nil {
		t.Fatalf("validate valid recipe: %v\n%s", err, output)
	}
	for _, want := range []string{"is valid", "fisherman-e2e", "xfs"} {
		if !strings.Contains(string(output), want) {
			t.Errorf("output %q does not contain %q", output, want)
		}
	}
}

func TestValidateCommandRejectsInvalidRecipe(t *testing.T) {
	bin := buildFisherman(t)
	recipe := writeRecipe(t, map[string]any{
		"filesystem": "xfs",
		"hostname":   "fisherman-e2e",
	})

	output, err := exec.Command(bin, "validate", recipe).CombinedOutput()
	if err == nil {
		t.Fatalf("invalid recipe unexpectedly passed:\n%s", output)
	}
	if !strings.Contains(string(output), "disk is required") {
		t.Fatalf("unexpected validation failure:\n%s", output)
	}
}
