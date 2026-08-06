package secure

import "testing"

// WriteTestPE exposes the in-package PE builder to the secure_test package.
//
// The UKI fixtures there used to be the three bytes "uki", which was fine while
// section reads shelled out to a stubbed objcopy. Section reads now parse the
// file, so a fixture has to be a real PE -- and that is the point: the fixtures
// exercise the same parser the installer runs.
func WriteTestPE(t *testing.T, sections map[string]string) string {
	t.Helper()
	return writeTestPE(t, sections)
}
