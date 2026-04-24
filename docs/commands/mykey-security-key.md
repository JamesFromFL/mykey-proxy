# `mykey-security-key`

## Purpose

`mykey-security-key` is MyKey's first-wave security-key management command.

It currently handles:

- security-key enrollment through `pamu2fcfg`
- TPM-sealed MyKey metadata for enrolled keys
- a shared MyKey-owned `pam_u2f` authfile
- dedicated test-time verification through `pam_u2f`
- activation and teardown of the security-key stage in daemon policy for the current
  Linux account
- live `pam_mykey.so` runtime auth through the dedicated `pam_u2f` helper path

## Current Commands

### `sudo mykey-security-key enroll [--nickname <name>]`

- requires a configured MyKey PIN fallback
- requires Linux account password verification through `mykey-elevated-auth`
- runs `pamu2fcfg` for the current Linux account
- stores nickname, enrolled timestamp, masked credential hint, and provider
  mapping in a TPM-sealed per-user registry
- rewrites the shared `/etc/mykey/security-keys.pam_u2f` authfile for the
  current Linux account without disturbing other users' lines
- enables the security-key stage for the current Linux account

### `sudo mykey-security-key status`

Shows:

- enrolled keys for the current Linux account
- whether security keys are currently active in MyKey local auth
- the current MyKey local-auth mode
- MyKey key ID
- nickname if present
- enrolled timestamp
- backend
- masked credential hint

### `sudo mykey-security-key unenroll`

- requires Linux account password verification through `mykey-elevated-auth`
- presents the current account's enrolled keys as a menu
- removes the selected key from both the sealed MyKey registry and the shared
  `pam_u2f` authfile
- falls back to PIN-only local auth when the last enrolled key is removed

### `mykey-security-key test`

- uses the dedicated PAM service `mykey-security-key-auth`
- verifies through `pam_u2f.so` rather than through `pam_mykey.so`
- is intended as a direct provider sanity check after enrollment

## Current Files

- per-user sealed registry:
  `/etc/mykey/auth/<uid>/security-keys.registry.sealed`
- shared `pam_u2f` authfile:
  `/etc/mykey/security-keys.pam_u2f`
- dedicated PAM service:
  `/etc/pam.d/mykey-security-key-auth`

## Current Caveat

This command now reaches the live MyKey auth chain too. The remaining gap is
validation, not missing runtime wiring: the security-key stage now participates
in the live MyKey auth chain, but still needs a real hardware pass on a host
with `pam_u2f`.
