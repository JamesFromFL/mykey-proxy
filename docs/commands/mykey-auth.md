# `mykey-auth`

## Purpose

`mykey-auth` is MyKey’s local-auth command surface.

It manages:

- MyKey PAM takeover points
- login-manager integration
- biometric setup scaffolding
- local-auth status inspection

## Current Commands

### `sudo mykey-auth enable`

Enables MyKey-managed base PAM targets.

Current intent:

- `sudo`
- `polkit-1`

This command does not silently take over desktop login. It offers login setup
after the base auth targets are handled.

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
- base PAM integration state
- login PAM integration state

### `sudo mykey-auth biometrics`

Current scaffold for biometric setup.

It can:

- drive `fprintd` enrollment
- drive `Howdy` enrollment
- record TPM-sealed MyKey metadata for the current Linux account
- select one active biometric backend in daemon policy

## Runtime Caveat

Setup and policy are ahead of runtime execution right now.

The current PAM auth helper is still effectively PIN-backed. Biometric setup is
real, but full biometric-first PAM auth execution is not complete yet.

## Design Rules

- MyKey should manage its own PAM placement
- login takeover must be explicit and opt-in
- fallback to the next PAM method should remain safe when MyKey is absent or
  unconfigured
- future security-key support should follow the same explicit model
