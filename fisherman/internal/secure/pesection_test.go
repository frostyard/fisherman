package secure

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// A minimal but real PE32+ image with two named sections, built by hand so the
// test needs no toolchain and no fixture binary on disk.
func writeTestPE(t *testing.T, sections map[string]string) string {
	t.Helper()
	const (
		peOffset     = 0x40
		sectionAlign = 0x200
	)
	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	// Deterministic order: map iteration would otherwise vary the layout.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}

	headerLen := peOffset + 4 + 20 + 240 + 40*len(names)
	dataStart := (headerLen + sectionAlign - 1) / sectionAlign * sectionAlign

	image := make([]byte, dataStart)
	image[0], image[1] = 'M', 'Z'
	put32 := func(offset int, value uint32) {
		image[offset] = byte(value)
		image[offset+1] = byte(value >> 8)
		image[offset+2] = byte(value >> 16)
		image[offset+3] = byte(value >> 24)
	}
	put16 := func(offset int, value uint16) {
		image[offset] = byte(value)
		image[offset+1] = byte(value >> 8)
	}
	put32(0x3c, peOffset)
	copy(image[peOffset:], []byte{'P', 'E', 0, 0})

	coff := peOffset + 4
	put16(coff, 0x8664)               // Machine: amd64
	put16(coff+2, uint16(len(names))) // NumberOfSections
	put16(coff+16, 240)               // SizeOfOptionalHeader
	put16(coff+18, 0x0002)            // Characteristics: EXECUTABLE_IMAGE
	optional := coff + 20
	put16(optional, 0x20b) // PE32+ magic
	// SizeOfOptionalHeader 240 == 112 standard PE32+ bytes + 16 data
	// directories of 8 bytes. debug/pe cross-checks the two and rejects the
	// image if NumberOfRvaAndSizes does not account for the difference.
	put32(optional+108, 16)

	table := optional + 240
	offset := dataStart
	for i, name := range names {
		entry := table + 40*i
		copy(image[entry:entry+8], name)
		body := []byte(sections[name])
		put32(entry+8, uint32(len(body)))     // VirtualSize
		put32(entry+12, uint32(0x1000*(i+1))) // VirtualAddress
		// SizeOfRawData is alignment-rounded, which is exactly the padding
		// peSection has to trim back off.
		raw := (len(body) + sectionAlign - 1) / sectionAlign * sectionAlign
		put32(entry+16, uint32(raw))
		put32(entry+20, uint32(offset))
		image = append(image, make([]byte, raw)...)
		copy(image[offset:], body)
		offset += raw
	}

	path := filepath.Join(t.TempDir(), "test.efi")
	if err := os.WriteFile(path, image, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPESectionReadsContentsAndTrimsPadding(t *testing.T) {
	path := writeTestPE(t, map[string]string{
		".cmdline": "rw composefs=?deadbeef",
		".pcrpkey": "-----BEGIN PUBLIC KEY-----",
	})
	for name, want := range map[string]string{
		".cmdline": "rw composefs=?deadbeef",
		".pcrpkey": "-----BEGIN PUBLIC KEY-----",
	} {
		got, err := peSection(path, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestPESectionReportsAMissingSectionAsEmpty(t *testing.T) {
	path := writeTestPE(t, map[string]string{".cmdline": "rw"})
	got, err := peSection(path, ".pcrsig")
	if err != nil {
		t.Fatalf("missing section: %v", err)
	}
	if got != nil {
		t.Fatalf("missing section returned %q, want nil", got)
	}
}

// The regression this whole file exists for. Reading a section used to be
// `objcopy --dump-section <name>=<out> <uki>` with no output file, which
// rewrites the input IN PLACE and drops its Authenticode certificate table --
// silently unsigning the UKI on the ESP of a secure install, which then could
// not boot. Reading must never modify the file it reads.
func TestPESectionDoesNotModifyTheImage(t *testing.T) {
	path := writeTestPE(t, map[string]string{
		".cmdline": "rw composefs=?deadbeef",
		".pcrpkey": "key",
	})
	digest := func() [32]byte {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(data)
	}
	before := digest()
	for _, name := range []string{".cmdline", ".pcrpkey", ".pcrsig", ".absent"} {
		if _, err := peSection(path, name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if digest() != before {
		t.Fatal("reading sections modified the image; a signed UKI would have been unsigned")
	}
}
