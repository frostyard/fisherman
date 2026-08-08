# Composefs Plaintext Password Implementation Plan

**Issue:** https://github.com/frostyard/fisherman/issues/34

**Goal:** Make plaintext user passwords work on composefs-native deployments without PAM while preserving pre-hashed and ostree behavior.

**Architecture:** Keep password handling in `post.CreateUser`. Pre-hashed passwords use `chpasswd -e`; plaintext composefs passwords use `chpasswd --crypt-method SHA512`; plaintext ostree passwords retain the existing target-chroot behavior. Passwords remain stdin-only.

**Tech Stack:** Go, shadow-utils `chpasswd`, existing `runner.RunFn` test seam.

## Constraints

- Do not change the recipe schema or frontend behavior.
- Do not hash passwords in Go or invoke another hashing command.
- Do not change composefs detection, user creation, or home-directory handling.
- Preserve the current `$` prefix detection for pre-hashed passwords.
- Never place plaintext passwords in process arguments or logs.
- Use SHA512 as required by issue #34.
- Keep ostree behavior unchanged.

## Task 1: Add Regression Coverage

**Files:** `fisherman/internal/post/user_test.go`

- [ ] Add `TestCreateUserComposeFsPlaintextPassword` for an etc-only composefs deployment root.
- [ ] Assert the plaintext invocation is `chpasswd --root <deploy-root> --crypt-method SHA512`, without `-e`, and receives stdin.
- [ ] Add `TestCreateUserComposeFsHashedPassword` and assert `chpasswd --root <deploy-root> -e`, without `--crypt-method`, and receives stdin.
- [ ] Preserve the existing ostree assertion that the target `chpasswd` runs through `chroot`.
- [ ] Use non-secret sentinels and do not include password stdin in assertion failures.

## Task 2: Bypass PAM for Composefs Plaintext Passwords

**Files:** `fisherman/internal/post/user.go`

- [ ] Select `-e` for pre-hashed passwords, `--crypt-method SHA512` for composefs plaintext passwords, and no extra argument for ostree plaintext passwords.
- [ ] Keep composefs as host `chpasswd --root <root>` and ostree as `chroot <root> chpasswd`.
- [ ] Keep password input on stdin and error wrapping unchanged.
- [ ] Explain that explicit crypt selection avoids PAM for the etc-only composefs root.

## Task 3: Document the Password Contract

**Files:** `fisherman/internal/recipe/recipe.go`, `README.md`, `CHANGELOG.md`

- [ ] Document that `user.password` accepts plaintext or a modular-crypt value.
- [ ] Document that plaintext is hashed during installation and `$`-prefixed values are passed to `chpasswd -e` unchanged.
- [ ] Do not claim full modular-crypt validation because detection remains prefix-based.
- [ ] Add an Unreleased bug-fix entry.

## Task 4: Verification

- [ ] Run `gofmt` on modified Go files.
- [ ] Run focused post tests, then `go test ./...`, `go test -race ./...`, and `go vet ./...` from `fisherman/`.
- [ ] Inspect `git diff --check`, the final diff, and worktree status.
- [ ] If a disposable composefs install environment is available, re-run the issue recipe and verify user creation and authentication.
