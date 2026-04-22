# `mykey-auth`

## Purpose

`mykey-auth/` contains MyKey’s local-authentication subsystem.

Today that means:

- PAM integration
- MyKey PIN setup and verification
- biometric enrollment scaffolding
- planned security-key support

## Current Subtree

- `mykey-pam`
  - `pam_mykey.so`
  - `mykey-auth`
  - PAM target inspection and managed edits
- `mykey-pin`
  - PIN setup, reset, and status helpers
- `mykey-biometrics`
  - planned backend-specific biometric tooling
- `mykey-security-key`
  - planned security-key/FIDO2 helper area

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

The current runtime backend behind `pam_mykey.so` is still the MyKey PIN.

Important nuance:

- biometric setup exists
- biometric backend selection exists
- daemon-owned biometric policy exists
- PAM auth itself still rejects non-PIN runtime backends today

So “biometrics support” currently means setup and policy scaffolding, not full
biometric-first PAM auth execution yet.

## `mykey-auth` Commands

### `mykey-auth enable`

- enables MyKey-managed base PAM targets
- shows local-auth summary
- offers login setup at the end

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
- base PAM integration state
- login PAM integration state

### `mykey-auth biometrics`

Current scaffold:

- drives `fprintd` and `Howdy` setup
- stores TPM-sealed MyKey metadata for biometric registrations
- tracks one Linux account per registry
- lets MyKey choose one active biometric backend in policy today

Current limitations:

- no security-key path yet
- no full biometric-first PAM auth execution yet
- `fprintd` tracking is limited by upstream backend semantics

## Security-Key Status

Security-key auth is still planned.

There is not yet:

- a `mykey-security-key` executable flow
- a daemon `SecurityKey` local-auth method
- a PAM runtime path that uses a security key

That work should follow the same pattern as biometrics:

- setup
- validation
- policy enablement
- status
- explicit teardown
