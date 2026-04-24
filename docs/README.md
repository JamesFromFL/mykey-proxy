# MyKey Documentation

This directory is the source of truth for MyKey’s project documentation.

Use these documents first:

- [Architecture](architecture.md)
- [Threat Model](threat-model.md)
- [Auth Component](components/auth.md)
- [Daemon Component](components/daemon.md)
- [Secrets Component](components/secrets.md)
- [Tray Component](components/tray.md)
- [mykey Command](commands/mykey.md)
- [mykey-auth Command](commands/mykey-auth.md)
- [mykey-security-key Command](commands/mykey-security-key.md)
- [mykey-migrate Command](commands/mykey-migrate.md)
- [Arch Packaging](packaging/arch.md)

Current documentation scope is intentionally lean:

- core architecture and trust boundaries
- current release-relevant components
- operator-facing command behavior
- packaging direction

What is intentionally not broken out yet:

- GUI flows
- walkthrough-style onboarding guides
- browser-platform-authenticator research notes
- future passkey implementation details

Those can be added later once the behavior is stable enough to document once.
