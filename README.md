# ⚠️ This repository has moved

**fisherman now lives at [projectbluefin/fisherman](https://github.com/projectbluefin/fisherman)**

Please update your remotes:

```bash
git remote set-url origin https://github.com/projectbluefin/fisherman.git
```

---
# fisherman

A universal bootc installer backend, designed to be driven by a frontend such as [tuna-installer](https://github.com/tuna-os/tuna-installer).

fisherman handles disk partitioning, formatting, LUKS encryption, and `bootc install to-filesystem` image installation. It works with any bootc-compatible image regardless of distro.

## Architecture

fisherman is a Go CLI that reads a JSON recipe and executes a 9-step install pipeline:

| Step | Action |
|------|--------|
| 1 | Partition disk — layout depends on bootloader (see below) |
| 2 | Format EFI (`mkfs.fat -F32`) and `/boot` (`mkfs.ext4`) |
| 3 | Set up LUKS (optional: `cryptsetup luksFormat` + open) |
| 4 | Format root filesystem (`mkfs.xfs` or `mkfs.btrfs`) |
| 5 | Mount everything at `/mnt/fisherman-target` |
| 6 | `bootc install to-filesystem` via `podman run --privileged` |
| 7 | Copy system Flatpaks from host to target |
| 8 | Write `/etc/hostname` into the deployment |
| 9 | Inject `rd.luks.uuid` + Plymouth args into BLS boot entries, then finalize (fstrim → remount ro → fsfreeze) |

The separate ext4 `/boot` partition is required for GRUB because GRUB cannot read modern XFS features (`nrext64`, `exchange`, `rmapbt`). For composefs/systemd-boot images the EFI partition holds the kernel and initrd directly.

### Partition layouts

| Bootloader | Layout | EFI | /boot | Notes |
|---|---|---|---|---|
| `grub2` (bluefin, lts) | 3-partition GPT | **2 GiB** FAT32 | **2 GiB** ext4 | GRUB reads kernel from ext4 /boot |
| `systemd` (dakota) | 2-partition GPT | **2 GiB** FAT32 | — | systemd-boot reads kernel directly from FAT32 ESP |

All fleet images use a **2 GiB ESP** for consistency. Each kernel+initrd pair is 200–400 MiB; 2 GiB accommodates the booted entry, rollback, and a staged upgrade without running out of space.

When running inside a Flatpak sandbox, fisherman automatically wraps host subprocess calls via `flatpak-spawn --host`.

## Usage

```bash
sudo fisherman <recipe.json>
```

## Snosi secure installs

The explicit `secureInstall` recipe path installs only Snosi schema-1 secure
OCI images. It is not inferred from an image name and refuses manual layouts,
separate `/var`, non-Btrfs filesystems, non-systemd bootloaders, non-LUKS root,
undersized disks (30 GiB), undersized ESPs (2 GiB), unsupported installer
versions, unsigned images, mutable tags, and images without
`io.snosi.bootc.secureboot-capable=true`.
It also requires the restrictive `/etc/containers/policy.json` from the
secure installer medium and passes that policy to the digest-pinned Podman
pull; it never falls back to a permissive policy.

```json
{
  "disk": "/dev/nvme0n1",
  "filesystem": "btrfs",
  "composeFsBackend": true,
  "bootloader": "systemd",
  "encryption": {"type": "luks-passphrase"},
  "image": "ghcr.io/frostyard/cayo:20260729000000",
  "targetImgref": "ghcr.io/frostyard/cayo:stable",
  "cosignPubKey": "/usr/lib/snosi/cosign.pub",
  "hostname": "cayo",
  "secureInstall": {
    "recoveryKeyFile": "/run/snosi-recovery-key",
    "mokPasswordFile": "/run/snosi-mok-password"
  }
}
```

Both secure credential files must be operator-owned, regular non-symlink files
with exactly one hard link and mode `0600`. The recovery credential is read from
the external file, is never accepted in `encryption.passphrase`, and is removed
only by the operator. Fisherman never prints, records, or copies it to the
target. The MOK password is read as raw bytes and must be 8-16 printable,
non-whitespace ASCII bytes with no newline. Fisherman uses mokutil's hash-file
flow; mokutil requires the password in the `--generate-hash=<password>` process
argument, an upstream limitation that can be visible to privileged local process
inspection. Fisherman does not log, emit, or persist that argument, its hash, or
the password. The secure branch uses the
schema-1 bootc Type #2 invocation without `--karg`, does not mutate BLS entries
for Plymouth or LUKS, verifies the installed UKI `.pcrpkey`, enrolls the TPM
against signed PCR 11, and records public provenance at
`/var/lib/snosi/bootc-secure-install.json`.
The secure source is resolved and verified once to an immutable digest; the
required `targetImgref` is a bare tag for the exact same repository and is
passed only to bootc as `--target-imgref` for future policy-enforced updates.
Provenance stores these separately as `oci_ref` and `tracking_ref`; Fisherman
does not infer either from a product name or fetch the tag after verification.

Recovery files use raw whole-file bytes for LUKS formatting, open, verification,
and TPM enrollment: a trailing newline is a credential byte, never trimmed.
Bootc lays down shim and MokManager; Fisherman validates them and owns only the
MOK-signed systemd-boot second-stage repair.

Recovery commands operate only on an already mounted, authenticated deployment:

```bash
sudo fisherman secure-restage-mok /mnt/target /run/snosi-recovery-key /run/snosi-mok-password
sudo fisherman secure-repair-esp /mnt/target /run/snosi-recovery-key
```

Neither command partitions, formats, installs an OCI image, changes LUKS
metadata, or writes deployment `/etc` or `/var`. ESP repair verifies the
immutable MOK-signed second-stage source and its same-filesystem temporary copy
immediately before atomically replacing only `EFI/BOOT/grubx64.efi`. Recovery
authentication derives the sole LUKS mapper mounted at the supplied target root;
it never uses the installer's active host root mapper.

## Recipe format

```json
{
  "disk": "/dev/sda",
  "filesystem": "xfs",
  "composeFsBackend": false,
  "unifiedStorage": false,
  "selinuxDisabled": false,
  "encryption": {
    "type": "none"
  },
  "image": "ghcr.io/tuna-os/yellowfin:gnome50",
  "hostname": "myhost",
  "flatpaks": ["org.mozilla.firefox"]
}
```

**Encryption types:** `none`, `luks-passphrase`, `tpm2-luks`, `tpm2-luks-passphrase`

For `luks-passphrase` and `tpm2-luks-passphrase`, add `"passphrase": "hunter2"` inside the `encryption` object.

## Image catalog

`data/images.json` is a recursive JSON tree of distro groups and leaf images consumed by tuna-installer's image picker. It can be overridden at runtime:

| Path | Purpose |
|------|---------|
| `/etc/tuna-installer/images.json` | System-wide override |
| `$XDG_CONFIG_HOME/tuna-installer/images.json` | Per-user override |

## Building

```bash
go build ./cmd/fisherman/   # build binary
go vet ./...                # lint
go test ./...               # unit tests
```

## CI / Bootcrew integration tests

The nightly CI runs a full install + QEMU boot test for each image in `tests/bootcrew-matrix.yaml`:

| Image | Filesystem | composefs |
|-------|-----------|-----------|
| bluefin:lts | xfs | no |
| yellowfin:gnome50 | xfs | no |
| ubuntu-bootc | xfs | yes |
| opensuse-bootc | xfs | yes |
| arch-bootc | xfs | yes |
| debian-bootc | xfs | yes |
| frostyard/snow | btrfs | yes |

Fast CI (PR gate) runs a subset. Add new images to `tests/bootcrew-matrix.yaml` to include them in both workflows automatically.

The Frostyard fork's SSH-fixture build workflow publishes under
`ghcr.io/frostyard/fisherman/<image>:ssh-enabled`; Bootcrew continues to use
the existing public upstream fixtures until that namespace has been
bootstrapped. Hosted-runner Bootcrew PR jobs explicitly select the runner-bundled
`runc`; Ubuntu runner image 20260726's Podman 5.8.4 default `crun` rejects the
generated OCI runtime version. The Bootcrew lint gate runs
`tests/check-ci-workflows.sh` to preserve both workflow contracts. Nightly
tests install Ubuntu's apt-provided Podman instead of using the runner-bundled
version.

## License

GPL-3.0-only
