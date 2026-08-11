#!/bin/bash
# Verify installation partitions and basic structure
# Usage: ./verify-installation.sh LOOPDEV [COMPOSEFS] [LUKS_PASSPHRASE] [BTRFS_SUBVOLUMES]
# Uses dynamic tool discovery for CI and local environments

set -e

# Source tool discovery helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./find-tools.sh
source "$SCRIPT_DIR/find-tools.sh"

LOOPDEV="${1}"
COMPOSEFS="${2:-false}"
LUKS_PASSPHRASE="${3:-}"  # optional; if set, opens the LUKS root container before mounting
BTRFS_SUBVOLUMES="${4:-false}"  # optional; if true, mount the root with subvol=@

# For btrfs subvolume installs the installed system lives inside the @ subvolume
# (state/deploy, ostree). A bare mount exposes the btrfs top-level (@, @home,
# @snapshots) where state/deploy does not exist, so verification would falsely
# fail. Mount subvol=@ to inspect the same tree the booted system sees.
ROOT_MOUNT_OPTS=()
if [ "$BTRFS_SUBVOLUMES" = "true" ]; then
  ROOT_MOUNT_OPTS=(-o subvol=@)
fi

if [ -z "$LOOPDEV" ]; then
  echo "❌ Usage: $0 LOOPDEV [COMPOSEFS]"
  exit 1
fi

# Find required tools
MOUNT_BIN=$(find_mount) || {
  echo "❌ Mount command not found"
  show_tool_info
  exit 1
}

SUDO_BIN=$(find_sudo) || {
  echo "❌ Sudo not found"
  show_tool_info
  exit 1
}

echo "=== Verifying installation ==="

# Show partition table with type GUIDs (useful for debugging UEFI boot issues)
echo "--- Partition table ---"
sudo sfdisk --dump "$LOOPDEV" 2>/dev/null || sudo fdisk -l "$LOOPDEV" || true

# 1. Check partition layout (2 or 3 partitions depending on bootloader)
# - Composefs systemd-boot: 2 partitions (EFI + root)
# - GRUB: 3 partitions (EFI + /boot + root)
PART_COUNT=$(sudo lsblk "$LOOPDEV" -o NAME -nr | grep -c "^${LOOPDEV##*/}p" || true)
if [ "$PART_COUNT" -lt 2 ] || [ "$PART_COUNT" -gt 3 ]; then
  echo "FAIL: expected 2-3 partitions, got $PART_COUNT"
  sudo lsblk -o NAME,SIZE,FSTYPE,LABEL "$LOOPDEV"
  exit 1
fi

echo "✅ Partition layout correct ($PART_COUNT partitions)"

# 2. Mount and verify partitions
# For 2-partition layout (systemd-boot composefs):
#   p1 = EFI, p2 = root (or LUKS(root))
# For 3-partition layout (GRUB):
#   p1 = EFI, p2 = /boot, p3 = root (or LUKS(root))
if [ "$PART_COUNT" -eq 2 ]; then
  BOOT_PART="${LOOPDEV}p1"  # This is just EFI for 2-partition
  ROOT_PART="${LOOPDEV}p2"
else
  BOOT_PART="${LOOPDEV}p2"
  ROOT_PART="${LOOPDEV}p3"
fi

LUKS_MAPPER="fisherman-verify-$$"
LUKS_OPENED=0

# Cleanup trap: unmount and close LUKS container on any exit.
cleanup_verify() {
  $SUDO_BIN umount "$ROOT_DIR"  2>/dev/null || true
  $SUDO_BIN umount "$VERIFY_DIR" 2>/dev/null || true
  $SUDO_BIN umount "$EFI_DIR"   2>/dev/null || true
  if [ "$LUKS_OPENED" -eq 1 ]; then
    $SUDO_BIN cryptsetup luksClose "$LUKS_MAPPER" 2>/dev/null || true
  fi
  rmdir "$ROOT_DIR"  2>/dev/null || true
  rmdir "$VERIFY_DIR" 2>/dev/null || true
  rmdir "$EFI_DIR"   2>/dev/null || true
}
trap cleanup_verify EXIT

# Always verify the EFI partition (p1) for BOOTX64.EFI, regardless of layout.
EFI_PART="${LOOPDEV}p1"
EFI_DIR=$(mktemp -d)
sudo "$MOUNT_BIN" "$EFI_PART" "$EFI_DIR"

if [ ! -f "$EFI_DIR/EFI/BOOT/BOOTX64.EFI" ]; then
  echo "FAIL: EFI/BOOT/BOOTX64.EFI not found on EFI partition $EFI_PART"
  echo "--- EFI partition contents ---"
  find "$EFI_DIR" -type f 2>/dev/null || true
  exit 1
fi
echo "✅ EFI/BOOT/BOOTX64.EFI present on EFI partition"

# Show all EFI partition files so we can verify boot entries are present
echo "--- EFI partition contents ---"
find "$EFI_DIR" -type f | sort | while read -r f; do
  size=$(stat -c%s "$f" 2>/dev/null || echo "?")
  echo "  ${f#$EFI_DIR/} (${size} bytes)"
done

# Check for boot entries (UKIs in EFI/Linux/ or loader entries)
BOOT_ENTRIES=$(find "$EFI_DIR/EFI/Linux" "$EFI_DIR/loader/entries" -name "*.efi" -o -name "*.conf" 2>/dev/null | wc -l)
if [ "$BOOT_ENTRIES" -eq 0 ]; then
  echo "⚠️  WARNING: No boot entries found (no UKIs in EFI/Linux/ and no loader/entries/*.conf)"
  echo "   systemd-boot will have nothing to boot from"
else
  echo "✅ Found $BOOT_ENTRIES boot entry/entries"
fi

$SUDO_BIN umount "$EFI_DIR"

VERIFY_DIR=$(mktemp -d)
sudo "$MOUNT_BIN" "$BOOT_PART" "$VERIFY_DIR"

ROOT_DIR=$(mktemp -d)

# Open LUKS container if passphrase is provided, otherwise mount directly.
if [ -n "$LUKS_PASSPHRASE" ]; then
  LUKS_TYPE=$(sudo blkid -s TYPE -o value "$ROOT_PART" 2>/dev/null || true)
  if [ "$LUKS_TYPE" = "crypto_LUKS" ]; then
    echo "=== Opening LUKS container on $ROOT_PART ==="
    echo -n "$LUKS_PASSPHRASE" | $SUDO_BIN cryptsetup luksOpen "$ROOT_PART" "$LUKS_MAPPER" --key-file=-
    LUKS_OPENED=1
    echo "✅ LUKS container opened at /dev/mapper/$LUKS_MAPPER"
    sudo "$MOUNT_BIN" "${ROOT_MOUNT_OPTS[@]}" "/dev/mapper/$LUKS_MAPPER" "$ROOT_DIR"
  else
    echo "⚠️  LUKS_PASSPHRASE provided but $ROOT_PART is not crypto_LUKS (type: $LUKS_TYPE) — mounting directly"
    sudo "$MOUNT_BIN" "${ROOT_MOUNT_OPTS[@]}" "$ROOT_PART" "$ROOT_DIR"
  fi
else
  sudo "$MOUNT_BIN" "${ROOT_MOUNT_OPTS[@]}" "$ROOT_PART" "$ROOT_DIR"
fi

# Verify the btrfs subvolume layout: SetupBtrfsSubvolumes must create @, @home,
# and @snapshots, and set @ as the default subvolume so systemd GPT
# auto-discovery mounts @ (not the top-level) at boot. We mounted subvol=@
# above, but `btrfs subvolume list` reports every subvolume in the filesystem
# regardless of which one is mounted, so all three must appear here.
if [ "$BTRFS_SUBVOLUMES" = "true" ]; then
  echo "--- btrfs subvolume layout ---"
  SUBVOL_LIST=$($SUDO_BIN btrfs subvolume list "$ROOT_DIR" 2>/dev/null || true)
  echo "$SUBVOL_LIST"
  MISSING=""
  for sv in @ @home @snapshots; do
    # Match the trailing "path <sv>" column exactly to avoid @ matching @home.
    if ! echo "$SUBVOL_LIST" | grep -qE "[[:space:]]path[[:space:]]+${sv}\$"; then
      MISSING="$MISSING $sv"
    fi
  done
  if [ -n "$MISSING" ]; then
    echo "FAIL: btrfs subvolume(s) missing:$MISSING (expected @, @home, @snapshots)"
    exit 1
  fi
  echo "✅ btrfs subvolumes present: @, @home, @snapshots"

  # @ must be the default subvolume for boot-time root selection.
  DEFAULT_SUBVOL=$($SUDO_BIN btrfs subvolume get-default "$ROOT_DIR" 2>/dev/null || true)
  echo "default subvolume: $DEFAULT_SUBVOL"
  if ! echo "$DEFAULT_SUBVOL" | grep -qE "[[:space:]]path[[:space:]]+@\$"; then
    echo "FAIL: btrfs default subvolume is not @ (get-default: $DEFAULT_SUBVOL)"
    echo "      systemd GPT auto-discovery would mount the btrfs top-level at boot,"
    echo "      hiding state/deploy — the install-time bug relocated to first boot."
    exit 1
  fi
  echo "✅ btrfs default subvolume is @"
fi

# Debug: show root structure
echo "--- Root directory structure ---"
$SUDO_BIN ls -F "$ROOT_DIR"
if [ -d "$ROOT_DIR/ostree" ]; then
  echo "--- Ostree structure ---"
  $SUDO_BIN ls -R "$ROOT_DIR/ostree" | head -n 20
fi

# Verify hostname
if [ "$COMPOSEFS" = "true" ]; then
  # composefs-native has no top-level /etc: the writable /etc lives at
  # state/deploy/<COMPOSEFS_HASH>/etc/ (see internal/post/post.go
  # DefaultComposeFsDeployEtcDir). A fresh install has exactly one
  # deployment, so just take whichever etc/ dir exists under state/deploy/.
  ETC_DIR=$($SUDO_BIN find "$ROOT_DIR/state/deploy" -mindepth 2 -maxdepth 2 -type d -name etc 2>/dev/null | head -n1)
  if [ -z "$ETC_DIR" ] || [ ! -f "$ETC_DIR/hostname" ]; then
    echo "FAIL: composefs-native writable /etc (state/deploy/<hash>/etc/hostname) not found"
    echo "--- state/deploy contents ---"
    $SUDO_BIN find "$ROOT_DIR/state/deploy" 2>/dev/null | head -n 50
    exit 1
  fi
  echo "✅ composefs-native hostname at $ETC_DIR/hostname"
else
  echo "✅ ostree-based installation verified"
fi

# Verify no installer Flatpak app dirs exist on the installed system.
# CopyFlatpaks (PR #1) must strip these regardless of the install backend.
INSTALLER_IDS="org.bootcinstaller.Installer org.bootcinstaller.Installer.Devel org.tunaos.Installer org.tunaos.Installer.Devel"

# Locate the flatpak app dir: composefs-native vs ostree layout.
if [ "$COMPOSEFS" = "true" ]; then
  FLATPAK_APP_DIR="$ROOT_DIR/state/os/default/var/lib/flatpak/app"
else
  FLATPAK_APP_DIR="$ROOT_DIR/ostree/deploy/default/var/lib/flatpak/app"
fi

if [ -d "$FLATPAK_APP_DIR" ]; then
  INSTALLER_FOUND=""
  for APPID in $INSTALLER_IDS; do
    if [ -d "$FLATPAK_APP_DIR/$APPID" ]; then
      INSTALLER_FOUND="$INSTALLER_FOUND $APPID"
    fi
  done
  if [ -n "$INSTALLER_FOUND" ]; then
    echo "FAIL: installer Flatpak app(s) found on target — must not be present after install:"
    echo "  $INSTALLER_FOUND"
    exit 1
  fi
  echo "✅ No installer Flatpak apps found in target ($FLATPAK_APP_DIR)"
else
  echo "ℹ️  No flatpak/app dir at $FLATPAK_APP_DIR — skip installer-app absence check"
fi

$SUDO_BIN umount "$ROOT_DIR"
if [ "$LUKS_OPENED" -eq 1 ]; then
  $SUDO_BIN cryptsetup luksClose "$LUKS_MAPPER"
  LUKS_OPENED=0
fi
$SUDO_BIN umount "$VERIFY_DIR"
rmdir "$ROOT_DIR"
rmdir "$VERIFY_DIR"
echo "✅ Installation verification passed"
