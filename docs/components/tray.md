# `mykey-tray`

## Purpose

`mykey-tray` is an optional session-level status surface for MyKey.

It is intentionally small.

Current role:

- show basic MyKey status
- expose a simple enable/disable/status CLI
- later surface notifications such as new login-manager detection

## Commands

```bash
mykey-tray run
mykey-tray enable
mykey-tray disable
mykey-tray status
```

`run` is the foreground tray process.

`enable` and `disable` manage the user service.

`status` prints the same snapshot data the tray uses internally.

## Lifecycle

The tray is not required for MyKey to function.

Current behavior:

- tray startup is optional
- it should only run while `mykey-daemon` is active
- it should not be forced on by package install

## Why It Stays Small

The tray should not become the place where critical security behavior is
silently changed.

Security-sensitive actions still belong in explicit commands like:

- `mykey-auth ...`
- `mykey-pin ...`
- `mykey-migrate ...`

Future polish can make the tray more informative without turning it into a
second control plane.
