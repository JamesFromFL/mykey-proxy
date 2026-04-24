# Arch Packaging

## Status

MyKey is mid-pivot from script-driven installation to an Arch/AUR package model.

The package scaffold now exists under:

- [packaging/arch/PKGBUILD](../../packaging/arch/PKGBUILD)
- [packaging/arch/mykey.install](../../packaging/arch/mykey.install)
- [packaging/arch/mykey.sysusers](../../packaging/arch/mykey.sysusers)
- [packaging/arch/mykey.tmpfiles](../../packaging/arch/mykey.tmpfiles)
- [packaging/arch/TRANSITION.md](../../packaging/arch/TRANSITION.md)

## Packaging Rules

The package should own:

- binaries
- PAM modules
- dedicated PAM service definitions
- unit files
- D-Bus policy
- polkit actions
- sysusers/tmpfiles metadata

The package should not own:

- provider migration logic
- auth enrollment
- destructive uninstall cleanup of user state

The one service-side exception is `mykey-daemon`:

- installation should enable and start `mykey-daemon` before the operator runs
  any auth setup commands
- user-session services such as `mykey-secrets` and `mykey-tray` should still
  remain explicit user actions

## Post-Install Setup

The intended post-install setup path is:

```bash
mykey --help
sudo mykey-auth setup
mykey-migrate --enroll    # optional; only when you want MyKey to own Secret Service
mykey tray enable         # optional
```

The intended ordering is:

- package install should already leave `mykey-daemon` active
- auth-first setup comes before optional Secret Service takeover
- `mykey-migrate --enroll` is not part of the minimum local-auth bring-up path
- `mykey-secrets` should not be enabled manually before `mykey-migrate --enroll`

`mykey-auth setup` now owns the operator-facing auth bring-up order:

- PIN first
- optional security key
- optional biometrics
- required base PAM takeover
- optional login/unlock takeover

The package payload also needs to carry the dedicated elevated-management auth
surface, including `mykey-elevated-auth` and `/etc/pam.d/mykey-elevated-auth`,
so MyKey does not depend on a broad shared PAM stack for setup and reset work.

The current package payload also includes:

- `mykey-security-key`
- `mykey-security-key-auth`
- `/etc/pam.d/mykey-security-key-auth`

`pam-u2f` should stay an optional dependency because security-key management is
optional even though the package ships the dedicated PAM service.

## Current Blockers

The package direction is real, but not fully stable yet.

Important follow-up areas still include:

- `mykey-migrate` guardrails and uninstall recovery behavior
- daemon logging cleanup
- tighter polkit defaults
- final package-safe ownership of all MyKey state paths

For the current detailed split of package payload vs setup vs removed installer
behavior, use [TRANSITION.md](../../packaging/arch/TRANSITION.md).
