package recipe_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/recipe"
)

func TestValidate(t *testing.T) {
	// Create a real file to satisfy os.Stat in Validate.
	dir := t.TempDir()
	diskPath := filepath.Join(dir, "fake-disk")
	if err := os.WriteFile(diskPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		r       recipe.Recipe
		wantErr string // substring; empty means no error expected
	}{
		// ── Valid recipes ──────────────────────────────────────────────────────
		{
			name: "valid xfs",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "host1"},
		},
		{
			name: "valid btrfs",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "btrfs", Hostname: "host1"},
		},
		{
			name: "valid btrfs subvolumes",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "btrfs", BtrfsSubvolumes: true, Hostname: "host1"},
		},
		{
			name: "valid encryption none",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h", Encryption: recipe.Encryption{Type: "none"}},
		},
		{
			name: "valid empty encryption type",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h"},
		},
		{
			name: "valid luks-passphrase",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "xfs", Hostname: "h",
				Encryption: recipe.Encryption{Type: "luks-passphrase", Passphrase: "secret"},
			},
		},
		{
			name: "valid tpm2-luks (no passphrase required)",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "xfs", Hostname: "h",
				Encryption: recipe.Encryption{Type: "tpm2-luks"},
			},
		},
		{
			name: "valid tpm2-luks-passphrase",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "xfs", Hostname: "h",
				Encryption: recipe.Encryption{Type: "tpm2-luks-passphrase", Passphrase: "secret"},
			},
		},
		{
			name: "valid composefs_backend true",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "btrfs", Hostname: "h", ComposeFsBackend: true},
		},
		{
			name: "valid composefs_backend with luks-passphrase",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "btrfs", Hostname: "h",
				ComposeFsBackend: true,
				Encryption:       recipe.Encryption{Type: "luks-passphrase", Passphrase: "secret"},
			},
		},
		{
			name: "valid composefs_backend with btrfs",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "btrfs", Hostname: "h", ComposeFsBackend: true},
		},
		{
			name: "valid composefs_backend with xfs",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h", ComposeFsBackend: true},
		},
		{
			name: "valid bootloader empty (default grub2)",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h"},
		},
		{
			name: "valid bootloader grub2",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "btrfs", Hostname: "h", Bootloader: "grub2"},
		},
		{
			name: "valid bootloader systemd",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "btrfs", Hostname: "h", Bootloader: "systemd"},
		},

		// ── Invalid: disk ─────────────────────────────────────────────────────
		{
			name:    "empty disk",
			r:       recipe.Recipe{Filesystem: "xfs", Hostname: "h"},
			wantErr: "disk is required",
		},
		{
			name:    "nonexistent disk",
			r:       recipe.Recipe{Disk: "/dev/definitely-does-not-exist-xyzzy", Filesystem: "xfs", Hostname: "h"},
			wantErr: "disk /dev/definitely-does-not-exist-xyzzy",
		},

		// ── Invalid: filesystem ───────────────────────────────────────────────
		{
			name:    "empty filesystem",
			r:       recipe.Recipe{Disk: diskPath, Hostname: "h"},
			wantErr: `filesystem must be`,
		},
		{
			name: "ext4 filesystem valid",
			r:    recipe.Recipe{Disk: diskPath, Filesystem: "ext4", Hostname: "h"},
		},
		{
			name:    "btrfsSubvolumes without btrfs",
			r:       recipe.Recipe{Disk: diskPath, Filesystem: "xfs", BtrfsSubvolumes: true, Hostname: "h"},
			wantErr: "btrfsSubvolumes requires filesystem=btrfs",
		},
		// ── Invalid: imageType ────────────────────────────────────────────────
		{
			name:    "imageType ostree not yet supported",
			r:       recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h", ImageType: "ostree"},
			wantErr: "imageType \"ostree\" is not yet supported",
		},
		{
			name:    "imageType unknown value",
			r:       recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h", ImageType: "flatpak"},
			wantErr: "imageType must be",
		},

		// ── Invalid: bootloader ───────────────────────────────────────────────
		{
			name:    "bootloader unknown value",
			r:       recipe.Recipe{Disk: diskPath, Filesystem: "xfs", Hostname: "h", Bootloader: "lilo"},
			wantErr: "bootloader must be",
		},

		// ── Invalid: encryption ───────────────────────────────────────────────
		{
			name: "luks-passphrase empty passphrase",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "xfs", Hostname: "h",
				Encryption: recipe.Encryption{Type: "luks-passphrase"},
			},
			wantErr: "passphrase required",
		},
		{
			name: "tpm2-luks-passphrase empty passphrase",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "xfs", Hostname: "h",
				Encryption: recipe.Encryption{Type: "tpm2-luks-passphrase"},
			},
			wantErr: "passphrase required",
		},
		{
			name: "unknown encryption type",
			r: recipe.Recipe{
				Disk: diskPath, Filesystem: "xfs", Hostname: "h",
				Encryption: recipe.Encryption{Type: "invalid-type"},
			},
			wantErr: "encryption.type must be",
		},

		// ── Invalid: hostname ─────────────────────────────────────────────────
		{
			name:    "empty hostname",
			r:       recipe.Recipe{Disk: diskPath, Filesystem: "xfs"},
			wantErr: "hostname is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %q, want containing %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid JSON", func(t *testing.T) {
		r := &recipe.Recipe{
			Disk:       "/dev/sda",
			Filesystem: "xfs",
			Hostname:   "myhost",
			Flatpaks:   []string{"org.mozilla.firefox"},
		}
		data, _ := json.Marshal(r)
		path := filepath.Join(dir, "recipe.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}

		loaded, err := recipe.Load(path)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if loaded.Disk != "/dev/sda" {
			t.Errorf("Disk = %q, want /dev/sda", loaded.Disk)
		}
		if loaded.Filesystem != "xfs" {
			t.Errorf("Filesystem = %q, want xfs", loaded.Filesystem)
		}
		if loaded.Hostname != "myhost" {
			t.Errorf("Hostname = %q, want myhost", loaded.Hostname)
		}
		if len(loaded.Flatpaks) != 1 || loaded.Flatpaks[0] != "org.mozilla.firefox" {
			t.Errorf("Flatpaks = %v, want [org.mozilla.firefox]", loaded.Flatpaks)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := recipe.Load(filepath.Join(dir, "nonexistent.json"))
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if !strings.Contains(err.Error(), "reading recipe") {
			t.Errorf("error = %q, want containing 'reading recipe'", err.Error())
		}
	})

	t.Run("additional image stores + mount overrides round-trip", func(t *testing.T) {
		body := []byte(`{
            "disk": "/dev/sda",
            "filesystem": "xfs",
            "hostname": "h",
            "additionalImageStores": ["/var/lib/superiso-store", "/srv/extra"],
            "targetMount": "/mnt/altroot",
            "luksMapperName": "altmapper"
        }`)
		path := filepath.Join(dir, "stores.json")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := recipe.Load(path)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if got := loaded.AdditionalImageStores; len(got) != 2 ||
			got[0] != "/var/lib/superiso-store" || got[1] != "/srv/extra" {
			t.Errorf("AdditionalImageStores = %v, want [/var/lib/superiso-store /srv/extra]", got)
		}
		if loaded.TargetMount != "/mnt/altroot" {
			t.Errorf("TargetMount = %q, want /mnt/altroot", loaded.TargetMount)
		}
		if loaded.LuksMapperName != "altmapper" {
			t.Errorf("LuksMapperName = %q, want altmapper", loaded.LuksMapperName)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		path := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := recipe.Load(path)
		if err == nil {
			t.Fatal("expected error for malformed JSON")
		}
		if !strings.Contains(err.Error(), "parsing recipe") {
			t.Errorf("error = %q, want containing 'parsing recipe'", err.Error())
		}
	})
}

func TestSecureInstallRequiresExplicitCompatibleRecipe(t *testing.T) {
	dir := t.TempDir()
	diskPath := filepath.Join(dir, "disk")
	recoveryKey := filepath.Join(dir, "recovery")
	mokPassword := filepath.Join(dir, "mok-password")
	cosignKey := filepath.Join(dir, "cosign.pub")
	if err := os.WriteFile(diskPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recoveryKey, []byte("recovery"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mokPassword, []byte("MokPassw0rd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cosignKey, []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}

	valid := recipe.Recipe{
		Disk:             diskPath,
		Filesystem:       "btrfs",
		ComposeFsBackend: true,
		Bootloader:       "systemd",
		Encryption:       recipe.Encryption{Type: "luks-passphrase"},
		Hostname:         "secure-host",
		Image:            "ghcr.io/frostyard/cayo:20260729000000",
		TargetImgref:     "ghcr.io/frostyard/cayo:stable",
		CosignPubKey:     cosignKey,
		SecureInstall:    &recipe.SecureInstall{RecoveryKeyFile: recoveryKey, MOKPasswordFile: mokPassword},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid secure recipe rejected: %v", err)
	}

	for name, mutate := range map[string]func(*recipe.Recipe){
		"composefs required":          func(r *recipe.Recipe) { r.ComposeFsBackend = false },
		"systemd bootloader required": func(r *recipe.Recipe) { r.Bootloader = "grub2" },
		"btrfs required":              func(r *recipe.Recipe) { r.Filesystem = "xfs" },
		"fresh layout required":       func(r *recipe.Recipe) { r.CustomMounts = []recipe.CustomMount{{Partition: diskPath, Target: "/"}} },
		"root mapper required":        func(r *recipe.Recipe) { r.LuksMapperName = "other" },
		"recovery key file required":  func(r *recipe.Recipe) { r.SecureInstall.RecoveryKeyFile = "" },
		"MOK password file required":  func(r *recipe.Recipe) { r.SecureInstall.MOKPasswordFile = "" },
		"tracking ref required":       func(r *recipe.Recipe) { r.TargetImgref = "" },
		"tracking ref digest forbidden": func(r *recipe.Recipe) {
			r.TargetImgref = "ghcr.io/frostyard/cayo@sha256:deadbeef"
		},
		"tracking ref transport forbidden": func(r *recipe.Recipe) {
			r.TargetImgref = "docker://ghcr.io/frostyard/cayo:stable"
		},
		"tracking ref local forbidden": func(r *recipe.Recipe) {
			r.TargetImgref = "containers-storage:ghcr.io/frostyard/cayo:stable"
		},
		"tracking ref localhost forbidden": func(r *recipe.Recipe) {
			r.Image = "localhost/frostyard/cayo:20260729000000"
			r.TargetImgref = "localhost/frostyard/cayo:stable"
		},
		"tracking ref repository must match source": func(r *recipe.Recipe) {
			r.TargetImgref = "ghcr.io/frostyard/snow:stable"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := valid
			r.SecureInstall = &recipe.SecureInstall{RecoveryKeyFile: recoveryKey, MOKPasswordFile: mokPassword}
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("secure recipe unexpectedly validated")
			}
		})
	}
}

func TestSecureInstallRejectsUnsafeCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	disk, cosign := filepath.Join(dir, "disk"), filepath.Join(dir, "cosign.pub")
	for _, path := range []string{disk, cosign} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	credential := filepath.Join(dir, "credential")
	if err := os.WriteFile(credential, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := func() recipe.Recipe {
		return recipe.Recipe{Disk: disk, Filesystem: "btrfs", ComposeFsBackend: true, Bootloader: "systemd", Encryption: recipe.Encryption{Type: "luks-passphrase"}, Hostname: "h", Image: "ghcr.io/frostyard/cayo:build", TargetImgref: "ghcr.io/frostyard/cayo:stable", CosignPubKey: cosign, SecureInstall: &recipe.SecureInstall{RecoveryKeyFile: credential, MOKPasswordFile: credential}}
	}
	for name, prepare := range map[string]func(*recipe.Recipe){
		"symlink": func(r *recipe.Recipe) {
			link := filepath.Join(dir, "credential-link")
			if err := os.Symlink(credential, link); err != nil {
				t.Fatal(err)
			}
			r.SecureInstall.RecoveryKeyFile = link
		},
		"multiple links": func(r *recipe.Recipe) {
			if err := os.Link(credential, filepath.Join(dir, "credential-hardlink")); err != nil {
				t.Fatal(err)
			}
		},
		"wrong mode": func(r *recipe.Recipe) {
			if err := os.Chmod(credential, 0o640); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := valid()
			prepare(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("unsafe credential file accepted")
			}
		})
	}
}

func TestSecureTrackingReferencesRejectMalformedOCIComponents(t *testing.T) {
	dir := t.TempDir()
	disk, recovery, key := filepath.Join(dir, "disk"), filepath.Join(dir, "recovery"), filepath.Join(dir, "key")
	for _, path := range []string{disk, recovery, key} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	valid := recipe.Recipe{Disk: disk, Filesystem: "btrfs", ComposeFsBackend: true, Bootloader: "systemd", Encryption: recipe.Encryption{Type: "luks-passphrase"}, Hostname: "h", Image: "ghcr.io/frostyard/cayo:build", TargetImgref: "ghcr.io/frostyard/cayo:stable", CosignPubKey: key, SecureInstall: &recipe.SecureInstall{RecoveryKeyFile: recovery, MOKPasswordFile: recovery}}
	for name, mutate := range map[string]func(*recipe.Recipe){
		"empty repository component": func(r *recipe.Recipe) { r.TargetImgref = "ghcr.io//cayo:stable" },
		"empty tag":                  func(r *recipe.Recipe) { r.TargetImgref = "ghcr.io/frostyard/cayo:" },
		"ambiguous port":             func(r *recipe.Recipe) { r.TargetImgref = "ghcr.io:5000:bad/cayo:stable" },
		"uppercase digest": func(r *recipe.Recipe) {
			r.Image = "ghcr.io/frostyard/cayo@sha256:" + strings.Repeat("A", 64)
			r.TargetImgref = "ghcr.io/frostyard/cayo:stable"
		},
		"empty digest": func(r *recipe.Recipe) {
			r.Image = "ghcr.io/frostyard/cayo@sha256:"
			r.TargetImgref = "ghcr.io/frostyard/cayo:stable"
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := valid
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatal("malformed reference accepted")
			}
		})
	}
	valid.Image = "ghcr.io:5000/frostyard/cayo:build"
	valid.TargetImgref = "ghcr.io:5000/frostyard/cayo:stable"
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid registry port rejected: %v", err)
	}
}
