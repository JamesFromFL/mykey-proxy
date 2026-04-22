# `mykey-daemon`

## Purpose

`mykey-daemon` is the privileged core of MyKey.

It owns the parts of the system that should not be delegated to user-session
services or ad hoc helper scripts.

## Responsibilities

The daemon currently owns:

- TPM-backed crypto helpers
- PIN verification and related auth state
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
- which backend is considered primary
- whether PIN fallback is enabled

Current backends reflected in policy are:

- PIN
- biometric

Security-key policy is still planned.

## Caller Boundary

The daemon should be treated as the enforcement point for privileged actions.

That includes:

- local auth state inspection
- PIN setup/reset verification
- biometric backend policy changes
- secret sealing and unsealing helpers used by other components

## Current Direction

The daemon is also where future MyKey authenticator work will have to anchor.

That future work should keep the same rule:

- high-trust operations belong here
- user-session tools should stay as orchestration and UI layers
