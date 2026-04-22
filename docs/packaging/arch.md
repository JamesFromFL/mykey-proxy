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
- unit files
- D-Bus policy
- polkit actions
- sysusers/tmpfiles metadata

The package should not own:

- provider migration logic
- auth enrollment
- service autostart as a side effect of installation
- destructive uninstall cleanup of user state

## Post-Install Setup

The intended post-install setup path is:

```bash
sudo systemctl enable --now mykey-daemon
mykey-migrate --enroll
mykey-pin set
sudo mykey-auth enable
mykey-tray enable   # optional
```

`mykey-auth login` remains a separate opt-in step for login and unlock targets.

## Current Blockers

The package direction is real, but not fully stable yet.

Important follow-up areas still include:

- `mykey-migrate` guardrails and uninstall recovery behavior
- daemon logging cleanup
- tighter polkit defaults
- final package-safe ownership of all MyKey state paths

For the current detailed split of package payload vs setup vs removed installer
behavior, use [TRANSITION.md](../../packaging/arch/TRANSITION.md).
