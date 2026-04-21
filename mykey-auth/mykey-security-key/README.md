# mykey-security-key

Planned home for MyKey security-key setup and management.

This module will eventually provide:

- setup, status, test, and reset flows for local security-key authentication
- integration with the existing system security-key/FIDO2 stack rather than a reimplementation of key verification inside MyKey
- backend validation before MyKey policy is enabled
- MyKey-managed security-key policy enablement behind `pam_mykey.so`

It is intentionally a placeholder for now while `mykey-pam` Phase A, daemon
local-auth policy, and the existing `mykey-pin` fallback backend continue to
stabilize.
