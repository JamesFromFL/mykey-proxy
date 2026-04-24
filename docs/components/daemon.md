# `mykey-daemon`

## Purpose

`mykey-daemon` is the privileged core of MyKey.

It owns the parts of the system that should not be delegated to user-session
services or ad hoc helper scripts.

## Responsibilities

The daemon currently owns:

- TPM-backed crypto helpers
- PIN verification and related auth state
- normal password-fallback rate limiting and status
- elevated-auth rate limiting and short-lived management grants
- daemon-owned local-auth policy
- caller validation
- privileged operations exposed over D-Bus

Other components should be thin in comparison.

## Service Role

`mykey-daemon` is a system service and should be enabled explicitly:

```bash
sudo systemctl enable --now mykey-daemon
```

The rest of MyKey depends on this service being available.

## Local Auth Policy

Local-auth state is daemon-owned.

This is where MyKey tracks things like:

- whether local auth is enabled
- the ordered local-auth chain
- which biometric backends are active inside the biometric stage
- whether normal password fallback is allowed
- whether elevated MyKey actions still require password
- how many biometric attempts are allowed before fallback

Current backends reflected in policy are:

- PIN
- biometric
- security key

## Normal Password Fallback

The daemon also owns the normal password-fallback backoff path used when
`pam_mykey.so` is active but no MyKey PIN is configured yet.

Current rules:

- only trusted runtime frontends such as `mykey-auth` may read or mutate this
  state
- the backoff path is separate from both MyKey PIN lockout and elevated
  password auth
- successful Linux password verification clears the fallback backoff state

## Elevated Management Auth

The daemon now owns a separate elevated-auth path for high-risk MyKey actions.

It currently covers:

- first-time PIN enrollment
- PIN reset
- biometric management actions
- security-key enroll and unenroll

Current rules:

- only the dedicated `mykey-elevated-auth` helper may grant elevated auth
- trusted frontends can read elevated-auth rate-limit state
- sensitive daemon methods consume one purpose-specific grant before mutating
  PIN, biometric, or security-key policy
- biometric management gets a longer-lived grant window than PIN setup/reset

## Caller Boundary

The daemon should be treated as the enforcement point for privileged actions.

That includes:

- local auth state inspection
- elevated-auth state inspection and grant consumption
- PIN setup/reset verification
- biometric backend policy changes
- security-key registry sealing and unsealing helpers used by
  `mykey-security-key`
- secret sealing and unsealing helpers used by other components

## Current Direction

The daemon is also where future MyKey authenticator work will have to anchor.

That future work should keep the same rule:

- high-trust operations belong here
- user-session tools should stay as orchestration and UI layers
