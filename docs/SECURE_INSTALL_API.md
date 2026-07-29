# Secure Install API

Fisherman exposes the Snosi schema-1 secure-install backend only through an
explicit recipe object. Parent frontends must not infer this path from a product
name or image reference.

## Recipe

```json
{
	"image": "ghcr.io/frostyard/cayo:20260729000000",
	"targetImgref": "ghcr.io/frostyard/cayo:stable",
	"secureInstall": {
     "recoveryKeyFile": "/run/operator-controlled-recovery-key",
     "mokPasswordFile": "/run/operator-controlled-mok-password"
  },
  "cosignPubKey": "/usr/lib/snosi/cosign.pub"
}
```

Secure recipes require automatic layout, `filesystem: "btrfs"`,
`composeFsBackend: true`, `bootloader: "systemd"`, and
`encryption.type: "luks-passphrase"`. `encryption.passphrase` is forbidden.
They also require `targetImgref`: a bare registry tag for exactly the same
repository as `image`. It must not be a digest or local/transport-qualified
reference. Fisherman resolves, verifies, capability-checks, and installs only
the immutable source digest; it passes the validated tracking tag only as
bootc's `--target-imgref` for future policy-enforced updates.
The frontend creates both credential files as regular, non-symlink, single-link
files with exact mode `0600`, passes only their paths, and retains/removes them
after Fisherman exits. The recovery credential remains raw whole-file data. The
MOK password is raw, untrimmed 8-16 byte printable non-whitespace ASCII data;
newlines are rejected. Fisherman must show that the disk will be erased and that
MokManager approval is required on the next boot.

MOK staging converts the immutable PEM certificate to a private temporary DER
file, captures `mokutil --generate-hash=<password>` output in a private temporary
hash file, then calls `mokutil --import <DER> --hash-file <HASH>`. The password
is never logged, emitted, or persisted. `mokutil` accepts the password only as a
command-line argument for hash generation, so privileged local process
inspection can observe it; this upstream limitation is documented rather than
hidden.

The secure installer medium must expose the restrictive
`/etc/containers/policy.json`. Fisherman passes it as Podman's
`--signature-policy` for the immutable digest pull; frontends must not expose
an override or a skip-fetch option.

## Provenance

`/var/lib/snosi/bootc-secure-install.json` records `oci_ref` as the accepted
immutable source digest and `tracking_ref` as the validated registry tag.
Neither value is inferred from a product name. The installer never re-fetches
the tracking tag after source verification.

## Events

Fisherman emits newline-delimited JSON on stdout. Secure lifecycle events use:

```json
{"type":"secure_install","action":"oci_acceptance","status":"passed"}
```

Current actions are `oci_acceptance`, `contract_validation`,
`tpm_enrollment`, `mok_enrollment`, and `provenance`. `status` is a
non-secret lifecycle value such as `passed`, `staged`, or `written`. Consumers
must ignore unknown actions and must never display a recovery credential from
logs or events.

## Recovery operations

`secure-restage-mok <target-root> <recovery-key-file> <mok-password-file>`
validates the installed schema-1 contract and recovery credential, then stages
the immutable public MOK certificate. `secure-repair-esp <target-root>
<recovery-key-file>` performs
the same authentication and replaces only `EFI/BOOT/grubx64.efi` from the
authenticated deployment after `sbverify` validation. Both commands refuse an
invalid target and contain no partitioning, formatting, or bootc-install path.

Recovery files are raw whole-file credentials across every secure operation;
frontends must not trim trailing newlines. Recovery commands derive the sole
mapper mounted at `target-root` with `findmnt`, then derive and validate its one
LUKS backing device with `cryptsetup`; they never inspect the active host root.
Bootc lays down shim and MokManager, while Fisherman validates those binaries and
repairs only `grubx64.efi`. ESP repair verifies both the immutable source and the
same-filesystem temporary replacement immediately before rename.
