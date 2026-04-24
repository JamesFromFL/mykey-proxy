# `mykey-auth`

## Purpose

`mykey-auth/` contains MyKey’s local-authentication subsystem.

Today that means:

- PAM integration
- MyKey PIN setup and verification
- guided auth-first setup
- biometric enrollment and runtime orchestration
- security-key management and runtime support

## Current Subtree

- `mykey-pam`
  - `pam_mykey.so`
  - `mykey-auth`
  - `mykey-elevated-auth`
  - PAM target inspection and managed edits
- `mykey-pin`
  - PIN setup, reset, and status helpers
- `mykey-biometrics`
  - planned backend-specific biometric tooling
- `mykey-security-key`
  - security-key/FIDO2 enrollment, status, test, and unenroll helper area

## PAM Management Model

MyKey now owns its PAM placement through commands instead of expecting the user
to patch files by hand.

### Base targets

Managed by:

- `sudo mykey-auth enable`
- `sudo mykey-auth disable`

Current intent:

- manage `sudo`
- manage `polkit-1`
- leave shared include files such as `system-auth` alone

### Login and unlock targets

Managed by:

- `sudo mykey-auth login`
- `sudo mykey-auth logout`

This path is explicit and opt-in so MyKey does not silently take over desktop
login or unlock behavior.

## Current Runtime Auth Behavior

The runtime path behind `pam_mykey.so` is now daemon-policy-driven.

Important nuance:

- when no MyKey PIN is configured, supported PAM prompts now use a MyKey-managed
  Linux password fallback path instead of dropping through to downstream PAM
  password modules
- PIN-only auth still works as the simplest MyKey local-auth mode
- biometric setup exists
- biometric backend selection exists
- daemon-owned staged local-auth policy exists
- when biometric-first policy is active, `mykey-auth` now drives the selected
  upstream backend for up to the daemon-configured biometric attempt limit
  before falling back to MyKey PIN
- those upstream biometric checks now run under explicit MyKey timeout and
  cancellation control
- when security-key-first policy is active, `mykey-auth` now drives the
  dedicated `mykey-security-key-auth` / `pam_u2f` path before falling back to
  MyKey PIN
- the current runtime now preserves `biometric group -> security key -> pin`,
  with the biometric stage racing all configured providers and accepting the
  first success
- biometric failures do not touch the MyKey PIN lockout counter unless PIN
  fallback is actually attempted
- security-key failures follow the same rule and do not touch the MyKey PIN
  lockout counter unless PIN fallback is actually attempted

So “biometrics support” now means setup, policy, and a first live
biometric-first PAM runtime path, not just scaffolding.

## Elevated Management Auth

High-risk MyKey management actions are intentionally separate from normal
`pam_mykey.so` runtime auth.

Today that means:

- first-time PIN setup and PIN reset use `mykey-elevated-auth`
- biometric enroll, unenroll, and policy-changing actions use the same helper
- security-key enroll and unenroll use the same helper
- the helper authenticates through a dedicated `mykey-elevated-auth` PAM
  service that is meant to stay password-only
- that service should not point at `system-auth`, `system-local-login`,
  fingerprint, `Howdy`, or `pam_mykey.so`

## `mykey-auth` Commands

### `mykey-auth setup`

- verifies that `mykey-daemon` is already active and reachable
- offers PIN setup first
- only offers security-key and biometric enrollment if PIN fallback exists
- always enables MyKey-managed base PAM targets
- then offers opt-in login and unlock takeover

### `mykey-auth enable`

- enables MyKey-managed base PAM targets
- shows local-auth summary
- if no MyKey PIN is configured yet, supported prompts stay on MyKey-managed
  Linux password fallback until `mykey-pin set`
- exists as the lower-level base-target action underneath `mykey-auth setup`

### `mykey-auth disable`

- removes MyKey-managed base PAM targets
- then walks the user into login-target teardown

### `mykey-auth login`

- detects supported login and unlock targets present on the machine
- lets the user opt into managing selected targets

### `mykey-auth logout`

- removes MyKey-managed login and unlock targets selected by the user

### `mykey-auth status`

Shows:

- MyKey local-auth summary
- whether the current runtime is still in password-fallback-only mode
- normal password-fallback policy
- whether elevated MyKey actions still require password
- biometric attempt limit when biometric-first policy is active
- ordered auth-chain state plus the active biometric backend set
- base PAM integration state
- login PAM integration state

### `mykey-auth biometrics`

Current scaffold:

- drives `fprintd` and `Howdy` setup
- stores TPM-sealed MyKey metadata for biometric registrations
- tracks one Linux account per registry
- uses the staged daemon policy model and keeps the full active biometric
  provider set in policy
- requires Linux account password verification for management actions through
  the dedicated elevated-auth helper

Current limitations:

- biometric runtime still needs broad host-installed calibration across the
  supported PAM surfaces MyKey manages
- `fprintd` tracking is limited by upstream backend semantics

## Security-Key Status

Security-key management and live runtime auth now exist.

`mykey-security-key` currently provides:

- `sudo mykey-security-key enroll [--nickname <name>]`
- `sudo mykey-security-key status`
- `sudo mykey-security-key unenroll`
- `mykey-security-key test`
- TPM-sealed per-user metadata for enrolled keys
- a shared MyKey-owned `pam_u2f` authfile at `/etc/mykey/security-keys.pam_u2f`
- a dedicated `mykey-security-key-auth` PAM service for test-time verification
- a security-key stage in daemon-owned local-auth policy that `pam_mykey.so`
  can use at runtime
- PIN fallback after unsuccessful security-key auth attempts

Current rules:

- enrollment requires a configured MyKey PIN fallback
- enroll and unenroll require Linux account password verification through
  `mykey-elevated-auth`
- enrolling a key now enables the security-key stage for that Linux account
- removing the last enrolled key falls back to PIN-only local auth
- MyKey stores nickname, enrolled timestamp, masked credential hint, and the
  provider mapping it needs to regenerate the shared authfile

What is still missing:

- broader host-installed validation of the `pam_u2f` runtime path
- support for more than the current `pam_u2f` security-key backend
