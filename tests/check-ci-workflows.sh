#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ssh_workflow="$repo_root/.github/workflows/build-ssh-images.yml"
boot_workflow="$repo_root/.github/workflows/bootcrew-vm.yml"
boot_matrix="$repo_root/tests/bootcrew-matrix.yaml"
justfile="$repo_root/justfile"

if ! grep -q 'tests/check-ci-workflows.sh' "$boot_workflow"; then
  echo "CI workflow contract check must run in CI" >&2
  exit 1
fi

if grep -q 'ghcr.io/tuna-os/fisherman' "$ssh_workflow"; then
  echo "SSH image publisher must use the current repository namespace" >&2
  exit 1
fi

if ! grep -q 'IMAGE_NAMESPACE:.*frostyard/fisherman' "$ssh_workflow"; then
  echo "SSH image workflow must declare the Frostyard package namespace" >&2
  exit 1
fi

if [ "$(grep -c 'runtime = "runc"' "$boot_workflow")" -ne 2 ]; then
  echo "required and advisory Bootcrew jobs must select runc" >&2
  exit 1
fi

if [ "$(grep -c "podman info --format.*Host.OCIRuntime.Name" "$boot_workflow")" -ne 2 ] ||
   [ "$(grep -Fc "[[ \$runtime == runc ]]" "$boot_workflow")" -ne 2 ]; then
  echo "required and advisory Bootcrew jobs must verify runc selection" >&2
  exit 1
fi

python3 - "$boot_matrix" <<'PY'
import pathlib
import sys

entries = pathlib.Path(sys.argv[1]).read_text().split("\n  - name: ")[1:]
if not any(
    "filesystem: btrfs" in entry
    and "btrfs_subvolumes: true" in entry
    and "vm_boot: true" in entry
    and "required: true" in entry
    for entry in entries
):
    raise SystemExit("a required VM canary must exercise btrfs subvolumes")
PY

if ! grep -Fq ".btrfs_subvolumes // false" "$justfile" ||
   ! grep -Fq '"btrfsSubvolumes": $BTRFS_SUBVOLUMES' "$justfile"; then
  echo "Bootcrew recipe generation must propagate btrfs_subvolumes" >&2
  exit 1
fi

echo "CI workflow contracts passed"
