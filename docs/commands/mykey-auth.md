# `mykey-auth`

## Purpose

`mykey-auth` is MyKey’s local-auth command surface.

It manages:

- guided auth-first MyKey setup
- MyKey PAM takeover points
- login-manager integration
- biometric setup scaffolding
- local-auth status inspection

Security-key enrollment lives in the separate `mykey-security-key` command
surface, but `mykey-auth` now participates in live security-key runtime auth
when daemon policy selects that backend.

## Current Commands

### `sudo mykey-auth setup`

Runs the guided auth-first setup flow.

Current order:

- verify that `mykey-daemon` is already active and reachable
- offer MyKey PIN setup
- if a PIN exists, optionally offer security-key enrollment
- if a PIN exists, optionally offer biometric enrollment
- always write MyKey into supported base PAM targets
- detect login and unlock targets, then ask whether MyKey should manage them

If the user declines PIN setup, MyKey stays on the Linux account password
fallback path for supported base PAM targets and skips the security-key and
biometric setup stages.

### `sudo mykey-auth enable`

Enables MyKey-managed base PAM targets.

Current intent:

- `sudo`
- `polkit-1`

This command is the lower-level base-target action underneath
`sudo mykey-auth setup`.

If no MyKey PIN is configured yet, supported prompts stay on a MyKey-managed
Linux password fallback path until `mykey-pin set`.

### `sudo mykey-auth disable`

Disables MyKey-managed base PAM targets and then walks the user through login
target teardown.

### `sudo mykey-auth login`

Detects supported login and unlock PAM targets present on the machine and lets
the user choose which ones MyKey should manage.

### `sudo mykey-auth logout`

Removes MyKey-managed login and unlock PAM targets selected by the user.

### `mykey-auth status`

Shows:

- local-auth configuration summary
- normal password-fallback policy
- whether elevated MyKey actions still require password
- biometric attempt limit when biometric-first policy is active
- ordered auth-chain state plus the active biometric backend set
- base PAM integration state
- login PAM integration state

### `sudo mykey-auth biometrics`

Current scaffold for biometric setup.

It can:

- drive `fprintd` enrollment
- drive `Howdy` enrollment
- record TPM-sealed MyKey metadata for the current Linux account
- use the staged daemon policy model while still selecting one active biometric
  backend today
- require Linux account password verification for enroll, unenroll, and policy
  changes through `mykey-elevated-auth`

## Runtime Caveat

Setup and policy now reach the live PAM path too.

`pam_mykey.so` and `mykey-auth` now follow daemon local-auth policy at runtime:
users without a configured MyKey PIN stay on a MyKey-managed Linux password
fallback path, pin-only users stay on MyKey PIN, and the current staged runtime
can now follow `biometric group -> security key -> pin`. The biometric stage
races all configured `fprintd` and `Howdy` providers, accepts the first success,
and still enforces capped biometric attempts before the chain moves on.
Security-key auth still goes through the dedicated
`mykey-security-key-auth` / `pam_u2f` path before MyKey PIN fallback.
Biometric verifier processes are now bounded by explicit timeout/cancellation
behavior so a stalled provider cannot hang the MyKey chain indefinitely.

The remaining caveat is host validation, not missing runtime wiring. The setup
flow now exists, but MyKey still needs a broad host-installed calibration pass
across supported PAM surfaces before this path should be treated as fully
hardened.

## Design Rules

- MyKey should manage its own PAM placement
- login takeover must be explicit and opt-in
- fallback to the next PAM method should remain safe when MyKey is absent or
  intentionally disabled
- when no MyKey PIN is configured yet, Linux password fallback should still be
  mediated by MyKey on supported PAM targets
- elevated management actions should stay on a dedicated password-only path
  outside biometric-only auth
- security-key runtime support now follows that same explicit model through the
  separate `mykey-security-key` command plus dedicated PAM services
