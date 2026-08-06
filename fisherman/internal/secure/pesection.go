package secure

import (
	"debug/pe"
	"fmt"
	"io"
)

// peSection returns the contents of one PE section.
//
// This replaces `objcopy --dump-section <name>=<out> <uki>`, which was the
// wrong tool in a way that destroyed the thing the secure install exists to
// protect. objcopy's synopsis is `objcopy [options] infile [outfile]`, and
// with outfile omitted it rewrites INFILE IN PLACE -- even when the only
// requested operation is to dump a section out. The rewrite preserves every
// section, so the extracted bytes looked correct, but it does not carry the
// Authenticode certificate table across. Reading the UKI silently unsigned it:
//
//	shimx64.efi.signed   1036152 bytes  ->  objcopy --dump-section  ->  1016789
//	shimx64.efi          1016789 bytes  (Debian's UNSIGNED variant, exactly)
//
// On the installed ESP that turned a MOK-signed UKI into an unsigned one
// between the install completing and the machine rebooting, and the target then
// failed Secure Boot with `Invalid parameter` and no bootable option. bootc was
// blamed for it for several rounds; bootc copies the UKI byte for byte.
//
// Reading the section here rather than shelling out fixes the root cause and
// removes the class: nothing can mutate a file we only open for reading. It
// also avoids writing a ~100 MiB temporary copy per call, which is what the
// objcopy form cost for a UKI.
func peSection(path, name string) ([]byte, error) {
	file, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s as a PE image: %w", path, err)
	}
	defer file.Close()

	section := file.Section(name)
	if section == nil {
		return nil, nil
	}
	data, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("reading section %s: %w", name, err)
	}
	// SizeOfRawData is rounded up to the file alignment, so a section can read
	// back longer than its VirtualSize with the remainder zero-filled. Trim to
	// the declared size when it is the smaller of the two; callers additionally
	// tolerate NUL padding, but they should not have to.
	if size := int(section.VirtualSize); size > 0 && size < len(data) {
		data = data[:size]
	}
	return data, nil
}

// Compile-time assurance that peSection's reader never writes: pe.Open takes a
// path and returns a read-only view, and section.Data() is io.ReaderAt-backed.
var _ io.ReaderAt = (*pe.Section)(nil)
