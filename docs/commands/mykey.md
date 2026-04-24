# `mykey`

`mykey` is the top-level terminal control surface for the project.

It exists to make installed MyKey workflows discoverable from one entrypoint
instead of expecting operators to memorize every individual binary name first.

## What It Does

`mykey` is intentionally thin.

It currently provides:

- `mykey --help` as the primary discovery surface
- `mykey help <topic>` for module-specific usage summaries
- routed subcommands that forward to the existing MyKey binaries
- short auth aliases such as `mykey enable` and `mykey status`

It does not replace the underlying tools.

It routes to them.

## Primary Topics

- `mykey help auth`
- `mykey help pin`
- `mykey help security-key`
- `mykey help tray`
- `mykey help secrets`
- `mykey help migrate`
- `mykey help daemon`
- `mykey help manager`

## Routed Commands

Module routes:

- `mykey auth ...` -> `mykey-auth ...`
- `mykey pin ...` -> `mykey-pin ...`
- `mykey security-key ...` -> `mykey-security-key ...`
- `mykey tray ...` -> `mykey-tray ...`
- `mykey secrets ...` -> `mykey-secrets ...`
- `mykey migrate ...` -> `mykey-migrate ...`
- `mykey daemon ...` -> `mykey-daemon ...`
- `mykey manager ...` -> `mykey-manager ...`

Common auth aliases:

- `mykey enable` -> `mykey-auth enable`
- `mykey disable` -> `mykey-auth disable`
- `mykey login` -> `mykey-auth login`
- `mykey logout` -> `mykey-auth logout`
- `mykey status` -> `mykey-auth status`
- `mykey biometrics` -> `mykey-auth biometrics`

## Examples

```bash
mykey --help
mykey help auth
sudo mykey auth setup
mykey status
mykey pin set
sudo mykey enable
sudo mykey biometrics
sudo mykey security-key enroll --nickname "Desk Key"
```

## Notes

- Use `sudo` for commands that modify PAM, enrollment state, or other elevated
  MyKey surfaces.
- `mykey-manager` is still a placeholder GUI binary. The terminal control
  surface is the primary operator-facing entrypoint for now.
