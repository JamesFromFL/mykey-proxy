# MyKey Arch Packaging Transition

Last updated: 2026-04-21

## Purpose

This note splits the current `scripts/install.sh` and `scripts/uninstall.sh`
behavior into three buckets:

- package payload
- post-install or user setup
- remove from the package path entirely

The goal is to pivot MyKey away from a script-driven installer and toward an
Arch/AUR package layout that matches how system-integrated software should be
delivered.

## Packaging Rules

- Package-owned files should install into package-managed paths, not
  `/usr/local` and not user home directories.
- Package install must not depend on live desktop state, active D-Bus sessions,
  Secret Service ownership, or successful enrollment.
- Package uninstall must not destroy user secrets, local auth state, or system
  users blindly.
- User services should be shipped in `/usr/lib/systemd/user/`, not copied into
  `~/.config/systemd/user/`.
- System services should be shipped in `/usr/lib/systemd/system/`, not dropped
  into `/etc/systemd/system/`.
- Package install should leave `mykey-daemon` active so the auth setup surface
  works immediately after installation.
- For Arch, daemon finalization should happen in a post-transaction hook after
  `sysusers.d` and `tmpfiles.d` have already run.
- Package install should not auto-enable or auto-start user services.
- Runtime setup belongs in explicit commands and post-install instructions.

## Target Arch Layout

The package transition should aim for this shape:

- Binaries in `/usr/bin/`
- PAM modules in `/usr/lib/security/`
- System unit files in `/usr/lib/systemd/system/`
- User unit files in `/usr/lib/systemd/user/`
- Polkit actions in `/usr/share/polkit-1/actions/`
- Package-owned D-Bus policy in `/usr/share/dbus-1/system.d/` or
  `/usr/share/dbus-1/session.d/`
- System user creation through `/usr/lib/sysusers.d/`
- Runtime/state directory creation through `/usr/lib/tmpfiles.d/`
- User-session Secret Service state in the user's data dir, not in `/etc`
  - typically `${XDG_DATA_HOME:-$HOME/.local/share}/mykey/`

## Package Payload

These are valid package payload items and should move out of the runtime
installer into the Arch package itself:

- `mykey-daemon`
- `mykey-secrets`
- `mykey-tray`
- `mykey-migrate`
- `mykey-pin`
- `mykey-pin-auth`
- `mykey-auth`
- `mykeypin.so`
- `pam_mykey.so`
- `mykey-daemon.service`
- `mykey-secrets.service`
- `mykey-tray.service`
- `com.mykey.Daemon.conf`
- `com.mykey.authenticate.policy`
- `trusted-binaries.json` generation if runtime hash verification remains part
  of MyKey

These are also package concerns, but should be represented as package metadata
or helper files instead of being created imperatively by `install.sh`:

- the `mykey` system user
- the `/etc/mykey` state tree and ownership model

For Arch, that means:

- `mykey.sysusers` for the system user
- `mykey.tmpfiles` for state directories and permissions

## Post-Install Or User Setup

These actions still matter, but should happen after package install through
instructions or explicit commands, not during `pacman -S`, except for the
required daemon bring-up:

- `mykey-daemon` should already be active when package install returns
- on Arch, the post-transaction hook should:
  - regenerate `/etc/mykey/trusted-binaries.json` from the final installed
    `/usr/bin/mykey-daemon`
  - reload systemd state
  - enable and start `mykey-daemon` on first install
  - restart `mykey-daemon` on upgrade if the service is already enabled
- complete auth-first local setup
  - `sudo mykey-auth setup`
  - this should own:
    - PIN-first setup
    - optional security-key enrollment when PIN exists
    - optional biometric enrollment when PIN exists
    - required base PAM takeover
    - optional login/unlock takeover
- enroll into MyKey Secret Service ownership
  - `mykey-migrate --enroll`
  - this is optional and separate from auth-first setup
  - on first setup, do not enable `mykey-secrets` manually before enroll
  - enroll should own the provider handoff sequence:
    - ensure the old provider is still active and readable
    - stop the old provider only after migration data is staged and verified
    - enable and start `mykey-secrets` only after takeover is safe
- disable MyKey-managed PAM takeover before a clean local-auth teardown
  - `sudo mykey-auth disable`
  - the command should then walk `sudo mykey-auth logout` for opt-in login teardown
- optionally enable `mykey-tray`
  - `mykey-tray enable`
- verify runtime state
  - `mykey-auth status`
  - `mykey-tray status`
  - `mykey-pin status`
  - `systemctl --user status mykey-secrets`
  - `journalctl -u mykey-daemon`

If a package-level `.install` file is used, it should print these commands as
guidance, while leaving daemon finalization to the post-transaction hook rather
than the earlier scriptlet phase.

## Remove From The Package Path Entirely

These should not be part of package install or uninstall:

- cargo discovery
- building from source in `install.sh`
- distro detection and package-manager dependency installation
- sudo keepalive loops
- Secure Boot, TPM2, and EFI signature gating during package install
- live health-check gating during package install
- auto-starting user services during package install
- copying user units into `~/.config/systemd/user/`
- manual symlink fallback into `default.target.wants`
- stale `/tmp` log cleanup
- `mykey-migrate --unenroll` as an uninstall prerequisite
- `userdel mykey` on uninstall
- `rm -rf /etc/mykey` on uninstall
- removing session state and user data unconditionally on uninstall

Those checks still have value, but they belong in runtime validation or a
future `doctor`-style command, not in package transactions.

## Release-Surface Findings That Affect Packaging

These findings from the release-surface audit should shape the package pivot:

- The current sudoers rule for `pkcheck` is stale.
  - `mykey-daemon` runs `pkcheck` directly and does not use `sudo`.
  - Do not carry `/etc/sudoers.d/mykey` into the Arch package unless a real
    code path requires it again.
- The polkit defaults are broader than a local-active-session model.
  - `allow_any`, `allow_inactive`, and `allow_active` are all `auth_self`.
  - Tighten this before calling the packaging story stable.
- `mykey-daemon` still relies on `/tmp/mykey-daemon.log`.
  - Move daemon logging to journald or make it opt-in before freezing the unit
    hardening and package shape.
- The `org.freedesktop.secrets` session-bus policy file should be treated as
  provisional.
  - Keep it only if it is proven necessary for the shipped session-bus model.

## Current Packaging Blockers

These are the main issues keeping the first Arch scaffold from being a
complete, shippable package today:

- `mykey-migrate --enroll` still needs packaging-aware guardrails.
  - First-time setup should route users through `mykey-migrate --enroll`, not
    direct `systemctl --user enable --now mykey-secrets`.
  - Enroll should be safe against accidental re-entry when `mykey-secrets`
    already owns `org.freedesktop.secrets`.
  - The package/install guidance must reflect that ordering exactly.
- `mykey-daemon` still defaults to `/tmp/mykey-daemon.log`.
  - The packaged systemd unit still has to tolerate that legacy path.
  - Move the daemon to journald or opt-in logging before freezing the final
    service hardening.
- The current polkit defaults still need tightening.
  - The package should not be treated as stable while
    `allow_any` / `allow_inactive` / `allow_active` all remain `auth_self`.
- The package path still needs fresh host validation after the hook-based
  daemon finalization changes.
  - the previous host validation uncovered three concrete bugs:
    - daemon TPM access for the `mykey` service account
    - trusted-binary hash generation from the pre-package artifact instead of
      the final installed daemon binary
    - daemon startup timing that ran too early in `post_install()`
  - the current repo now addresses those through `SupplementaryGroups=tss` on
    the daemon service and a post-transaction package hook, but that path
    still needs a clean host re-test
- Uninstall and purge are not the same operation yet.
  - Package removal should preserve `/etc/mykey` state by default so secrets
    are not silently destroyed or orphaned.
  - Sensitive-state deletion should happen only through an explicit MyKey
    teardown path after successful unenroll/restore.

## Current Script Mapping

### `scripts/install.sh`

Package payload behavior that should move into packaging:

- binary installs
- PAM module installs
- D-Bus policy install
- polkit policy install
- service file install
- trusted-binaries manifest generation
- system user creation
- runtime directory creation

Post-install or user setup that should become instructions:

- auth-first setup guidance (`sudo mykey-auth setup`)
- `mykey-migrate --enroll`
- `mykey-secrets` user-service enablement
- optional tray enablement
- final validation steps shown to the user

Behavior to remove from the package path:

- cargo lookup and compilation
- distro package installation helpers
- Secure Boot and TPM gating
- live EFI signature verification
- direct writes into `~/.config/systemd/user/`
- service autostart in the installer
- stale log cleanup

### `scripts/uninstall.sh`

Keep only as a developer teardown helper during the transition.

Do not model package removal on this script. In particular, package removal
must not:

- require `mykey-migrate --unenroll`
- delete `/etc/mykey` recursively
- delete the `mykey` system user unconditionally
- remove user-level service state from the current `$HOME`

## Immediate Next Steps

1. Create `packaging/arch/PKGBUILD`.
2. Create `packaging/arch/mykey.install` for post-install guidance text.
3. Create `packaging/arch/mykey.sysusers`.
4. Create `packaging/arch/mykey.tmpfiles`.
5. Move package-owned unit and policy install targets away from `/usr/local`
   and `/etc`-only assumptions.
6. Demote `scripts/install.sh` and `scripts/uninstall.sh` to developer/setup
   tooling instead of distribution tooling.
