# mykey-security-key

First-wave MyKey security-key management and test surface.

Current scope:

- `sudo mykey-security-key enroll [--nickname <name>]`
- `sudo mykey-security-key status`
- `sudo mykey-security-key unenroll`
- `mykey-security-key test`
- TPM-sealed per-user metadata under `/etc/mykey/auth/<uid>/security-keys.registry.sealed`
- a shared MyKey-owned `pam_u2f` authfile at `/etc/mykey/security-keys.pam_u2f`
- elevated Linux-password verification for enroll and unenroll through `mykey-elevated-auth`

This crate intentionally uses existing system security-key tooling instead of
reimplementing verification in MyKey:

- `pamu2fcfg` for enrollment
- `pam_u2f` for test-time authentication

What is still not done:

- daemon-owned security-key policy
- `pam_mykey.so` runtime orchestration for security-key-first auth
- broader host-installed validation of the `pam_u2f` runtime path
