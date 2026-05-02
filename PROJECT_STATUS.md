# MyKey Project Status

Last updated: 2026-05-02

## Purpose
- Canonical running project status and to-do document for MyKey release hardening.
- Track work in execution order first, then by module and severity.
- Keep this file updated before and after each patch set.
- Current rule for `mykey-pin`: do not stop for a commit until it reaches a usable state.
- Keep the chronological project timeline in the `Project History` section at the bottom.

## Current Status
- `mykey-migrate`
  - gnome-keyring unenroll/restore path is working and was live-tested successfully.
  - KWallet enroll and unenroll paths are live-validated with provider-specific wallet readiness handling.
  - KeePassXC enroll and unenroll paths are live-validated with provider-specific group readiness, item unlock, and metadata-only verification fallback when KeePassXC refuses post-restore secret reads.
  - enroll path has merge-safe staging and no longer replaces existing MyKey storage with a provider read.
  - enroll now unlocks source collections before bulk secret reads, so locked source keyrings fail with a prompt instead of partial-read errors.
  - enroll staging now activates inside the writable per-user MyKey secrets store instead of requiring writes to `/etc/mykey`.
- `mykey-pin`
  - current PIN auth path is release-ready for the validated local-auth scope
  - Level 1 PIN architecture is usable and host-validated
  - MyKey PIN remains the local fallback backend behind `pam_mykey.so`
  - first-time PIN setup and reset now route through a dedicated elevated-password helper and password-only PAM service
- `mykey-auth`
  - local-auth subtree now groups:
    - `mykey-pam`
    - `mykey-pin`
    - `mykey-biometrics`
    - `mykey-security-key`
  - MyKey local auth is an orchestration layer over existing system auth stacks.
  - MyKey should integrate and validate existing backends such as `fprintd`, `Howdy`, and security-key/FIDO2 tooling instead of reimplementing them.
  - biometric management actions now use the same dedicated elevated-password path as PIN setup and reset
  - `mykey-security-key` now owns security-key enrollment, status, unenroll, and direct provider testing
  - `mykey-auth setup` now exists as the guided auth-first entrypoint over PIN, optional security key, optional biometrics, required base PAM takeover, and optional login takeover
  - `sudo mykey-auth setup` now targets the invoking Linux account correctly during PIN work instead of root
  - the guided setup, disable, and re-enable lifecycle is now live-validated on-host for the current release scope
- `pam_mykey`
  - Phase A pin-backed base is now in repo through `mykey-auth/mykey-pam` and the `mykey-auth` helper
  - Phase A live validation is complete through `pamtester`
  - initial host validation is now complete for `sudo`, `polkit-1`, and the opt-in `gdm-fingerprint` target
  - runtime auth now follows daemon local-auth policy instead of hardcoding PIN-only behavior
  - biometric-first runtime auth now exists for supported `fprintd` and `Howdy` policy backends, with capped attempts, explicit verifier timeout/cancellation control, and MyKey PIN fallback
  - security-key-first runtime auth now exists for the `pam_u2f` policy backend, with MyKey PIN fallback
  - broader login-manager and distro-surface calibration is still open beyond the validated targets above
  - security-key runtime auth still needs real hardware validation
  - local-auth policy now lives in daemon-owned state instead of being hardcoded in the helper
  - remaining work is provider polish, real security-key hardware validation, and packaging cleanup rather than missing core orchestration

---

## Ordered To-Do

1. [x] `Critical` `mykey-daemon` Tighten daemon trust boundary for PIN work.
   - exact trusted MyKey binary basename matching
   - include trusted MyKey caller binaries such as `mykey-pin`, `mykey-pin-auth`, `mykey-auth`, `mykey-secrets`, `mykey-migrate`, and `mykey-manager`
   - cross-check caller-supplied PID against D-Bus sender credentials
   - enforce sender/PID verification on `Connect`, `Register`, `Authenticate`, `SealSecret`, `UnsealSecret`, and `Disconnect`
   - verified with `mykey-daemon` release build

2. [x] `Critical` `mykey-daemon` Add daemon-owned per-user PIN storage helpers.
   - daemon-side `PinStore`
   - per-user storage under `/etc/mykey/pin/<uid>/`
   - per-user sealed PIN blob helpers
   - per-user attempts and lockout helpers
   - atomic writes for PIN and attempts state
   - verified with unit tests and `mykey-daemon` release build

3. [x] `Critical` `mykey-daemon` Add daemon D-Bus PIN API.
   - extend `DaemonState` to own `PinStore`
   - change caller authorization to return caller identity, including Unix UID
   - enforce caller-to-user binding for per-user PIN operations
   - expose `PinStatus`, `PinEnroll`, `PinVerify`, `PinChange`, and `PinReset`
   - keep verification and lockout state inside the daemon
   - verified with focused PIN caller and UID-binding tests plus `mykey-daemon` release build

4. [x] `Critical` `mykey-pin` Update the daemon client for the new PIN API.
   - add async client methods for the daemon PIN calls
   - stop using generic seal/unseal from the client for PIN logic
   - verified with `mykey-pin` release build

5. [x] `Critical` `mykey-pin` Convert the CLI to daemon-backed per-user PIN operations.
   - stop direct reads and writes to `/etc/mykey/pin`
   - resolve current user and operate on that user only
   - use daemon `PinStatus`, `PinEnroll`, `PinVerify`, `PinChange`, and `PinReset`
   - verified with `mykey-pin` release build

6. [x] `Critical` `mykey-pin` Add a trusted PAM helper binary.
   - create `mykey-pin-auth`
   - make it the trusted bridge between PAM and `mykey-daemon`
   - prepare for privileged target-user auth flows later
   - verified with `mykey-pin` release build

7. [x] `Important` `mykey-pin` Reduce the PAM module to prompt plus helper dispatch.
   - stop direct daemon verification from the PAM host process
   - stop direct file access from the PAM module
   - use the helper exit status for PAM success or failure
   - verified with `mykey-pin` release build

8. [x] `Important` `scripts/install.sh` `scripts/uninstall.sh` Update installation wiring for the new PIN architecture.
   - install and remove `mykey-pin-auth`
   - switch `/etc/mykey/pin` ownership model to daemon-owned storage
   - keep PAM module install path aligned
   - verified with `bash -n scripts/install.sh scripts/uninstall.sh`

9. [x] `Important` `mykey-migrate` Unlock source keyrings during enroll before bulk reads.
   - prepare and unlock source collections before `GetSecret`
   - avoid fail-closed enroll aborts caused only by a locked source keyring
   - verified with `mykey-migrate` release build

10. [x] `Important` `mykey-migrate` Keep enroll staging inside the writable secrets tree.
   - stage and rollback within the writable user secrets tree
   - avoid permission failures from renaming through `/etc/mykey`
   - verified with `mykey-migrate` release build

11. [x] `Important` `scripts/install.sh` Convert Secure Boot setup into prerequisite verification.
   - remove interactive Secure Boot setup and EFI signing prompts
   - require Secure Boot, TPM2, systemd-boot, and verified signed EFI files before install continues
   - fail fast with a consolidated prerequisite summary if requirements are not met
   - de-duplicate same-inode EFI paths during verification so case-variant aliases do not fail prechecks
   - verified with `bash -n scripts/install.sh`

12. [x] `Critical` `validation` Run focused end-to-end validation for usable `mykey-pin`.
   - build checks completed
   - CLI set/change/reset/status checks completed
   - PAM helper sanity checks completed
   - strong-auth polkit validation for first-time enroll and reset completed
   - PAM end-to-end local auth flow completed with `pamtester`

13. [x] `Important` `mykey-pin` Add strong-auth enrollment and reset policy.
   - daemon-side user-presence confirmation is implemented
   - `mykey-pin` first-time enroll and reset now call through the daemon for strong-auth
   - live-validated with GUI polkit prompts on both first-time enroll and reset

14. [x] `Important` `mykey-daemon` `mykey-pin` Move brute-force protection to the PIN path only.
   - keep hardening for `mykey-pin`
   - stop affecting normal password fallback flows like `sudo` password prompts
   - daemon-side polkit/password verification no longer imposes a MyKey-managed cooldown
   - current PIN lockout schedule is 2 free failed attempts, then 1m → 5m → 15m → 30m → 1h → 2h → 5h starting on the 3rd bad PIN

15. [x] `Moderate` `mykey-pin` Add explicit PIN policy.
   - first-release PIN policy is numeric-only
   - minimum length: 4 digits
   - maximum length: 12 digits
   - empty and non-numeric PINs are rejected in both the CLI and daemon API

16. [x] `Critical` `pam_mykey` Build `pam_mykey.so` into the final MyKey-managed local-auth entrypoint.
   - replace the long-term need for separate user-managed PAM ordering between biometrics, security keys, PIN, and password
   - make `pam_mykey.so` the first MyKey auth module for supported system auth flows such as `sudo`, lock screen, login-adjacent prompts, and other safe local PAM targets
   - make MyKey responsible for installing and maintaining its supported PAM integration points so auth reaches MyKey first
   - Phase A base is in place: `mykey-auth/mykey-pam` and `mykey-auth` currently route through MyKey PIN
   - `mykey-auth setup` now exists as the guided auth-first entrypoint over PIN, optional security key, optional biometrics, required base PAM takeover, and optional login takeover
   - Phase A live validation is complete with `pamtester`
   - normal local auth should be MyKey-managed and should not rely on users hand-editing PAM ordering
   - elevated actions must stay outside normal biometric-only auth and continue to require stronger verification
   - live host validation is now complete for `sudo`, `polkit-1`, and opt-in `gdm-fingerprint`, including clean disable/re-enable teardown and bring-up

17. [x] `Critical` `local auth policy` Encode the hard MyKey auth rules in daemon-owned policy.
   - MyKey must orchestrate existing system auth stacks instead of reimplementing biometrics or security-key verification itself
   - first enforcement step is in place: invalid biometric-without-PIN policy is sanitised to a safe disabled state on daemon read
   - daemon now computes an effective local-auth policy instead of trusting raw stored fields
   - biometrics require a configured MyKey PIN fallback
   - enabling biometrics without a PIN must first trigger PIN setup
   - removing or resetting PIN while biometrics are enabled must automatically disable biometrics and inform the user why
   - when PIN is configured, normal local auth should not fall through to the user password
   - when PIN is not configured, password fallback is allowed for normal local auth
   - password-based paths must use exponential rate limiting instead of hard lockout
   - elevated MyKey actions must always require password and use a separate rate-limited path from everyday local auth
   - elevated PIN setup/reset and biometric management now use a dedicated `mykey-elevated-auth` helper plus a password-only PAM service instead of the generic polkit presence path
   - normal password fallback now stays inside MyKey: `pam_mykey.so` prompts for Linux account password through `mykey-auth` and the password-only PAM service instead of falling through to downstream password modules

18. [x] `Important` `mykey-biometrics` Add a dedicated biometric setup and management helper on top of existing system stacks.
   - first scaffold now exists through `mykey-auth biometrics` with `enroll`, `unenroll`, `status`, and `exit`
   - support backend selection for `fprintd` and `Howdy`
   - detect whether the selected backend is installed and offer install guidance or install integration where appropriate
   - drive backend enrollment, backend validation, MyKey policy enablement, and final verification
   - require a PIN before enabling biometrics and explain the fallback policy clearly during setup
   - remove the need for users to hand-edit PAM configuration to get MyKey biometrics working
   - setup, runtime auth, policy re-enable, and policy teardown are now live-validated on-host for the `fprintd` path

19. [ ] `Important` `mykey-security-key` Add a dedicated security-key setup and management helper on top of existing system stacks.
   - `mykey-security-key` now exists with `enroll`, `status`, `unenroll`, and `test`
   - it uses `pamu2fcfg` and `pam_u2f` instead of reimplementing security-key verification in MyKey
   - it records TPM-sealed per-user registry metadata and syncs a MyKey-owned shared `pam_u2f` authfile
   - enroll and unenroll require both a configured MyKey PIN fallback and the dedicated elevated-password path
   - enroll now enables the security-key stage in daemon-owned local-auth policy, and removing the last enrolled key falls back to PIN-only local auth if no biometric stage remains
   - run live enrollment, status, test, and unenroll validation once a real hardware security key is available
   - keep security-key auth as a first-class local-auth backend alongside biometrics and MyKey PIN

20. [x] `Important` `local auth policy` Add backend-first local auth orchestration with MyKey-managed fallback.
   - daemon-owned local-auth policy state now exists under `/etc/mykey/auth`
   - `mykey-auth` now reads daemon policy instead of hardcoding PIN-only behavior
   - existing pin-only users are backfilled automatically into local-auth policy on first status read
   - daemon policy and `LocalAuthStatus` now use an ordered backend-set model instead of a single `primary_method`
   - `pam_mykey.so` now switches between MyKey-managed Linux password fallback, pin-only auth, and the current staged chain from daemon policy
   - daemon now exposes ordered auth-chain state, active biometric backends, password-fallback allowance, elevated-action password requirements, and biometric attempt limits as effective policy outputs
   - `pam_mykey.so` now allows up to 3 biometric attempts per auth session before falling back to MyKey PIN
   - biometric failures do not increment the MyKey PIN brute-force counter unless PIN fallback is actually attempted
   - `pam_mykey.so` now supports the staged chain `biometric group -> security key -> pin`, using `mykey-auth`, `mykey-security-key-auth`, and `pam_u2f`
   - keep MyKey PIN as the normal local fallback when biometrics or security keys are enabled
   - reserve elevated authentication for high-risk actions such as first-time PIN setup, PIN reset, biometric enrollment or disablement, security-key enrollment or disablement, recovery actions, and future TOTP enrollment
   - ordered-backend rollout status:
     1. [x] refactor daemon local-auth policy and D-Bus status from a single `primary_method` into an ordered backend-set model
     2. [x] harden the biometric verifier layer so fingerprint and face auth have explicit timeout/cancellation behavior and do not rely on ad hoc fallback semantics
     3. [x] implement the biometric group stage so multiple configured biometric providers can race and satisfy auth on first success
     4. [x] wire the final failure-closed runtime chain inside `pam_mykey.so`: biometrics group -> security key -> MyKey PIN
   - live host validation is now complete for the current PIN + biometric release scope; remaining work is wider login-manager calibration, provider polish, and real security-key hardware validation rather than missing staged-chain wiring

21. [ ] `Moderate` `packaging` Align final package behavior with GUI and CLI release model.
   - `mykey-manager` as GUI frontend
   - modules callable directly from terminal
   - installer replaces current script-only assumptions

22. [x] `Critical` `audit` Audit and retire `mykey-host` from the current architecture.
   - identify stale host-side auth, PAM, TPM, or crypto responsibilities that should already live in `mykey-daemon`
   - confirm the host only handles native messaging, daemon session transport, and request/response marshaling
   - stale host-side PAM, TPM, legacy crypto helpers, and local credential-resolution code have been removed from the compiled host path
   - the host component was then removed entirely once the extension and native-messaging path left project scope

23. [x] `Important` `audit` Audit `mykey-secrets` and `mykey-tray` against the current auth and trust model.
   - verify daemon integration assumptions
   - identify stale direct-auth assumptions
   - identify release-critical correctness or trust-boundary issues
   - `mykey-secrets` no longer serves stale in-memory collection, item, or alias state after runtime create/replace/delete operations
   - `mykey-secrets` now updates replace-in-place items on disk coherently and `GetSecret` reads the current stored item state
   - `mykey-secrets` collection, item, and alias JSON writes now use atomic replace semantics
   - `mykey-secrets` default `/tmp` logging has been removed; logging is now opt-in through `MYKEY_SECRETS_LOG`
   - `mykey-secrets` no longer logs search attribute values by default, and storage load failures are now surfaced in warnings instead of being silently skipped
   - `mykey-tray` default `/tmp` logging has been removed; logging is now opt-in through `MYKEY_TRAY_LOG`
   - `mykey-tray` now exposes `enable`, `disable`, and `status` CLI commands and shares one component-status snapshot path with the tray menu
   - `mykey-tray` is now optional in install flow and no longer forces a hardcoded `DISPLAY`, `DBUS_SESSION_BUS_ADDRESS`, or `default.target.wants` autostart path
   - `mykey-tray` now exits when `mykey-daemon` is no longer active instead of lingering as a detached status icon

24. [x] `Moderate` `control surface` Build the MyKey TUI before the GUI manager.
   - a top-level `mykey` entrypoint now exists
   - `mykey --help` is now the primary discovery surface for installed modules and workflows
   - `mykey help <topic>` now shows routed subcommands plus their core arguments and help paths
   - the terminal control surface now routes directly into `mykey-auth`, `mykey-pin`, `mykey-security-key`, `mykey-tray`, `mykey-secrets`, `mykey-migrate`, and `mykey-daemon`
   - `mykey-manager` stays deferred until the backend and TUI stack are stable
   - current `mykey-manager` is still only a placeholder shell

25. [x] `Important` `audit` Audit installer, service, D-Bus, and polkit wiring as one release surface.
   - the current script-driven install/remove path is not package-safe because it writes package payload into `/usr/local`, `~/.config/systemd/user`, and `/etc/systemd/system`
   - the current install/remove path is coupled to live runtime state through service startup and `mykey-migrate --enroll` / `--unenroll`
   - the current sudoers rule for `pkcheck` appears stale because the daemon executes `pkcheck` directly
   - the current polkit defaults are broader than a local-active-session-only trust model
   - the current `mykey-daemon` service hardening is still coupled to legacy `/tmp` logging
   - the current Secret Service session-bus policy file should be retained only if its necessity is proven
   - `scripts/install.sh`
   - `scripts/uninstall.sh`
   - systemd units
   - D-Bus policy files
   - polkit policy files

26. [x] `Important` `docs` Overhaul `docs/architecture.md` around the current MyKey platform instead of the old MyKey Proxy layout.
   - stop describing the project as only a WebAuthn proxy
   - reflect the current `mykey-auth/` subtree, daemon-owned local auth policy, and current component boundaries
   - keep it as the technical system-layout document for reviewers and advanced users

27. [x] `Important` `docs` Overhaul `docs/threat-model.md` around the current MyKey platform and enforced policy.
   - stop describing only the old proxy threat model
   - reflect daemon-owned PIN policy, `pam_mykey`, local auth orchestration, and current prerequisite enforcement
   - keep it as the trust-boundary and attacker-model document for technical reviewers

28. [ ] `Low` `docs` Document PIN setup and fallback behavior clearly.
   - explain that PIN is optional
   - explain that PIN is device-local
   - explain password fallback and recovery expectations

29. [ ] `Extra` `level-2` Plan the next TPM-auth redesign after Level 1 is usable.
   - move beyond sealed verifier model
   - aim closer to a true Windows Hello-like local auth protector

30. [ ] `Moderate` `mykey-pin` Explore TOTP-based recovery for PIN reset and lockout recovery.
   - recovery factor only, not a normal authentication method
   - should help with forgotten PIN or lockout recovery
   - keep it local and optional, with clear backup and recovery expectations

31. [x] `Important` `scope` Remove `mykey-proxy` from project scope and repo.
   - the extension-based WebAuthn proxy is no longer a product direction
   - MyKey is pivoting toward native cross-platform authenticator behavior instead of store-submitted browser interception

32. [ ] `Important` `research` Explore legitimate Linux platform-authenticator integration as research only.
   - map what a downstream Chromium `kMyKeyLinux`-style backend would require
   - keep this out of release scope while MyKey pivots to device-bound cross-platform passkeys
   - document why browser patching is research, not the shipping integration path

33. [ ] `Important` `passkeys` Define the first device-bound cross-platform passkey scope.
   - keep passkey storage local to MyKey
   - do not turn MyKey into a syncing password manager or credential migrator
   - design the authenticator boundary so browser policy stays in the browser and credential protection stays in MyKey

34. [ ] `Moderate` `mykey-tray` Finalize tray status semantics after the current optional-service pass lands.
   - keep the tray icon menu/status line minimal, with one-word status labels only
   - keep detailed component state in `mykey-tray status` instead of the tray menu
   - change `mykey-auth` tray status from binary-presence reporting to daemon-owned local-auth policy reporting
   - report `mykey-auth` as `configured` or `unconfigured` based on real local-auth policy state
   - only claim that MyKey is `managing` local auth once PAM integration can be verified reliably instead of inferred

35. [ ] `Important` `packaging` Pivot delivery from script-driven install to Arch/AUR packaging.
   - use [packaging/arch/TRANSITION.md](/home/james/Git/mykey/packaging/arch/TRANSITION.md) as the package/setup split
   - initial scaffolding is now in repo:
     - `packaging/arch/PKGBUILD`
     - `packaging/arch/mykey.install`
     - `packaging/arch/mykey.sysusers`
     - `packaging/arch/mykey.tmpfiles`
   - Arch post-install guidance now treats auth-first setup as the default rollout:
     `sudo mykey-auth setup`, then optional `mykey-migrate --enroll` for Secret Service takeover
   - package install now finalizes `mykey-daemon` through a post-transaction hook so auth setup works immediately after installation
   - the same hook now regenerates `/etc/mykey/trusted-binaries.json` from the final installed daemon binary instead of the pre-package build artifact
   - the packaged daemon service now carries TPM access through `SupplementaryGroups=tss` instead of package-time mutation of the `mykey` service account
   - move package-owned artifacts out of `/usr/local` and user-home installation logic
   - demote `scripts/install.sh` and `scripts/uninstall.sh` into developer/setup tooling instead of distribution tooling
   - keep daemon-owned machine state under `/etc/mykey`, but keep Secret Service user state under the user's MyKey data dir instead of package-owned `/etc` paths

36. [ ] `Important` `mykey-migrate` Harden enroll and teardown around the package-driven setup flow.
   - package guidance should route first-time Secret Service setup through `mykey-migrate --enroll`, not manual `mykey-secrets` enablement
   - enroll should verify that the previous provider is still enabled and readable before takeover begins
   - enroll should be safe against accidental second runs when MyKey already owns `org.freedesktop.secrets`
   - define teardown as an explicit MyKey action, not ordinary package removal
   - ordinary package uninstall should preserve `/etc/mykey` state; sensitive cleanup should require successful unenroll or an explicit purge path
   - after the first release, align the migration CLI with the rest of MyKey around `mykey-migrate enroll|unenroll` and `mykey migrate ...` instead of the current `--enroll` / `--unenroll` flags

---

## By Module

### `mykey-auth`

#### Important
- [x] Reorganize the local-auth repo layout under one parent subtree.
  - `mykey-auth/mykey-pam`
  - `mykey-auth/mykey-pin`
  - `mykey-auth/mykey-biometrics`
- [ ] Keep MyKey as the orchestration layer over existing system auth stacks.
  - integrate `fprintd`, `Howdy`, security-key/FIDO2 tooling, and MyKey PIN as backends
  - do not reimplement biometric or security-key verification stacks inside MyKey

### `mykey-migrate`

#### Important
- [x] Unlock source collections during enroll before bulk reads.
- [x] Keep enroll staging inside the writable secrets tree.

### `mykey-daemon`

#### Critical
- [x] Tighten daemon trust boundary for PIN work.
- [x] Add daemon-owned per-user PIN storage helpers.
- [x] Add daemon D-Bus PIN API.
- [x] Enforce caller-to-user binding for PIN methods.

#### Important
- [x] Move PIN verification, change, reset, and lockout updates fully behind daemon methods.
- [x] Revisit daemon-side brute-force behavior so non-PIN password flows are not over-hardened.
  - daemon-side polkit/password verification no longer carries a MyKey-managed cooldown
- [x] Keep the current PIN lockout schedule at 2 free attempts, then 1m → 5m → 15m → 30m → 1h → 2h → 5h starting on the 3rd bad PIN.

#### Moderate
- [ ] Later move from sealed verifier behavior toward a stronger TPM-backed local auth protector.

### `mykey-pin`

#### Critical
- [x] Update daemon client for daemon PIN methods.
- [x] Convert CLI to per-user daemon-backed operations.
- [x] Add trusted PAM helper binary.

#### Important
- [x] Reduce PAM module to prompt plus helper dispatch only.
- [x] Add strong-auth gate for first-time enroll and reset.
  - live-validated with GUI polkit prompts on first-time enroll and reset
- [ ] Keep MyKey PIN as the fallback backend for unified MyKey local auth.
  - `mykey-pin` remains the PIN authenticator behind future `pam_mykey.so`
  - biometric and security-key backend failures must not count toward the PIN lockout schedule
  - biometric-first runtime auth now falls back to PIN without incrementing the PIN counter until PIN fallback is actually attempted

#### Moderate
- [x] Add explicit PIN policy and user-facing validation rules.
  - numeric-only, 4 to 12 digits, enforced in both CLI and daemon
- [ ] Evaluate optional TOTP-based recovery for PIN reset and lockout recovery only.

### `pam_mykey`

#### Critical
- [x] Establish the Phase A pin-backed `pam_mykey.so` and `mykey-auth` base.
- [x] Live-validate the Phase A pin-backed `pam_mykey.so` path with `pamtester`.
- [ ] Build `pam_mykey.so` into the final unified MyKey PAM entrypoint for normal local auth.
- [ ] Make MyKey, not the user, responsible for auth ordering and fallback between biometrics, security keys, PIN, and password.
- [x] Make MyKey responsible for installing and maintaining supported first-wave PAM service integration so auth reaches MyKey first.
  - `mykey-auth enable|disable|login|logout|status` now manages MyKey-owned PAM blocks in supported targets instead of asking users to hand-edit `/etc/pam.d`
  - base managed targets are `sudo` and `polkit-1`
  - login and unlock takeover is a separate opt-in flow through `mykey-auth login` and `mykey-auth logout`
  - the managed block uses `-auth` plus PAM control rules so a removed `pam_mykey.so` falls through cleanly on uninstall

### `local auth policy`

#### Important
- [x] Move local-auth mode selection into daemon-owned per-user policy state.
- [x] Make `mykey-auth` consult daemon local-auth policy instead of hardcoding PIN-only behavior.
- [x] Backfill existing pin-only users into daemon-owned local-auth policy automatically.
- [x] Sanitize invalid biometric-without-PIN policy back to a safe disabled state on daemon read.
- [x] Clear biometric policy automatically when PIN is reset.

#### Important
- [x] Define supported first-wave PAM targets such as `sudo`, lock screen, and other safe local auth prompts.
  - base managed wave is now `sudo` and `polkit-1`
  - login and unlock targets are detected separately and only enabled through the dedicated `mykey-auth login` flow
  - `system-auth`, `system-login`, and `system-local-login` are intentionally left unmanaged because they are too broad for MyKey's takeover scope
- [x] Keep elevated MyKey management actions outside biometric-only PAM auth.
  - first-time PIN setup/reset and biometric management now require `mykey-elevated-auth`
  - the helper authenticates through a dedicated password-only `mykey-elevated-auth` PAM service instead of `system-auth`, fingerprint, `Howdy`, or `pam_mykey`
  - the daemon issues and consumes purpose-scoped short-lived elevated grants after successful password verification
- [x] Enforce hard local-auth invariants in daemon-owned policy.
  - biometrics require PIN fallback
  - removing or resetting PIN disables biometrics
  - no normal password fallback once PIN exists
  - normal password fallback now stays inside MyKey when no PIN is configured
  - daemon now computes the effective policy state and exposes password-fallback, elevated-password, and biometric-attempt outputs through `LocalAuthStatus`
- [ ] Add login-target discovery notifications to `mykey-tray`.
  - detect newly installed supported login or unlock PAM targets such as `sddm`, `lightdm`, `kde`, or `cinnamon-screensaver`
  - show a short tray notification directing the user to run `sudo mykey-auth login`
  - allow per-target dismissal so the same login manager is not prompted repeatedly
- [x] Use exponential rate limiting for password fallback and elevated password auth instead of hard lockout.
  - elevated password auth now has its own separate backoff path
  - normal password fallback now has its own separate daemon-owned backoff path
- [x] Refactor daemon local-auth policy and D-Bus status into an ordered backend-set model.
  - daemon policy now represents biometrics, security key, and PIN as one coherent staged chain instead of one active backend plus fallback
  - `LocalAuthStatus` now returns ordered auth-chain state plus active biometric backends
  - password fallback remains derived and allowed only when no PIN exists
- [x] Harden the biometric verifier layer before multi-provider orchestration.
  - biometric runtime verifiers now run under an explicit MyKey-owned timeout/cancellation layer instead of unbounded blocking child-process waits
  - `fprintd-verify` and `howdy test` are now bounded provider probes with cleanup semantics, which gives the next multi-provider stage a safe verifier foundation
  - failed or stalled biometric attempts now time out cleanly instead of being able to hang the MyKey auth chain indefinitely
- [x] Implement the biometric group stage with first-success wins semantics.
  - allow multiple configured biometric providers to run as one stage
  - accept the first successful biometric result
  - cancel the losing providers cleanly and treat partial provider unavailability as non-fatal while another provider is still active
- [x] Wire the final failure-closed runtime chain inside `pam_mykey.so`.
  - ordered chain should be: biometrics group -> security key -> MyKey PIN
  - once MyKey owns the prompt for a supported target, backend failure must stay inside MyKey and not fall through to downstream PAM auth
  - biometric and security-key failures must still leave the PIN counter untouched until PIN fallback is actually attempted

### `mykey-biometrics`

#### Important
- [x] Add the first `mykey-auth biometrics` setup/status/unenroll scaffold.
  - interactive `enroll`, `unenroll`, `status`, and `exit` flow now lives under `mykey-auth biometrics`
  - the flow keeps TPM-sealed biometric tracking metadata under `/etc/mykey/auth/<uid>/`
  - the current Linux account name is the single tracked identity in the sealed registry; no new Linux accounts are created
- [x] Support first biometric backend selection for `fprintd` and `Howdy`.
  - the current scaffold can enroll through `fprintd` and `Howdy`, detect hardware best-effort, and prompt for package install when practical
  - the daemon policy model now records the full active biometric provider set instead of one selected provider
- [x] Use the existing system biometric stacks instead of reimplementing biometric verification inside MyKey.
  - `pam_mykey` now drives `fprintd-verify` and `howdy test` as backend-owned biometric verification attempts before PIN fallback
  - those provider calls now sit behind a bounded MyKey verifier layer with explicit timeout/cancellation behavior
- [x] Validate backend enrollment before enabling MyKey biometric policy.
  - the scaffold verifies the Linux account password for management actions through the dedicated elevated-auth path
  - it requires a MyKey PIN fallback and only flips biometric policy after provider enrollment succeeds
- [x] Enable MyKey-managed biometric auth without requiring users to hand-edit PAM files.
  - `mykey-auth` now exposes daemon-driven staged local auth through `pam_mykey.so`, with the biometric stage racing all configured providers before falling through to security key and then PIN
- [ ] Track backend-native scan identifiers when the upstream stack exposes them cleanly.
  - `fprintd` CLI does not currently expose stable per-scan IDs for MyKey to track
- [ ] Support finer-grained provider deletion where the upstream biometric stack allows it.
  - current `fprintd` unenroll path is account-wide, not per recorded fingerprint slot or scan
- [x] Support more than one active biometric backend in daemon-owned local-auth policy.
  - the daemon now stores the full active biometric provider set, and `pam_mykey.so` accepts whichever configured biometric provider succeeds first

### `mykey-security-key`

#### Important
- [x] Add a first-wave `mykey-security-key` enroll, status, test, and unenroll surface.
  - uses TPM-sealed per-user registry metadata plus a MyKey-owned shared `pam_u2f` authfile
  - supports optional key nicknames and enrolled-at timestamps
- [x] Use the existing system security-key/FIDO2 stack instead of reimplementing key verification inside MyKey.
  - `pamu2fcfg` handles enrollment
  - `pam_u2f` handles test-time verification through a dedicated PAM service
- [x] Validate security-key enrollment before enabling MyKey security-key policy.
  - the first wave requires successful `pamu2fcfg` enrollment before registry/authfile state is written
  - enroll and unenroll require Linux account password verification through the dedicated elevated-auth path
  - a configured MyKey PIN fallback remains mandatory
- [x] Enable MyKey-managed security-key auth without requiring users to hand-edit PAM files.
  - `mykey-security-key enroll` now enables security-key-first daemon policy for the current Linux account
  - `pam_mykey.so` now reaches the dedicated `pam_u2f` helper path before MyKey PIN fallback
- [ ] Run live security-key validation with a real hardware key once one is available.
  - validate enroll, status, test, and unenroll against a real `pam_u2f` key
  - validate security-key-first `pam_mykey.so` auth plus PIN fallback on a real host
  - confirm the shared authfile and sealed registry stay in sync through the full lifecycle

### `mykey`

#### Moderate
- [x] Add a top-level `mykey` TUI entrypoint and help surface.
  - `mykey --help` now lists the major MyKey modules and primary workflows
  - `mykey help <topic>` exposes routed commands, core arguments, and workflow notes
  - `mykey` now routes top-level module commands and common auth aliases to the existing binaries
  - this is now the primary terminal UX before any real GUI manager work

### `passkeys`

#### Important
- [ ] Define MyKey's local passkey storage model for device-bound cross-platform credentials.
- [ ] Keep browser-facing WebAuthn policy enforcement outside MyKey.
- [x] Remove `mykey-host`; the current cross-platform direction does not need a native-messaging bridge.

### `scripts/install.sh` and `scripts/uninstall.sh`

#### Important
- [x] Install and remove `mykey-pin-auth`.
- [x] Change `/etc/mykey/pin` ownership model from real-user-owned to daemon-owned.
- [x] Keep PAM module install path aligned with the new architecture.
- [x] Convert Secure Boot handling from interactive setup/signing to strict prerequisite verification in the installer.

#### Low
- [ ] Revisit script relevance later once package-driven install flow replaces script-driven setup.

### `audit`

#### Critical
- [x] Audit and retire `mykey-host` from the current daemon-owned architecture.
  - stale host-side PAM, TPM, local crypto, and local credential helper modules were removed from the compiled host path
  - the native-messaging bridge was removed entirely after the project pivoted away from the browser extension architecture

#### Important
- [x] Audit `mykey-secrets` and `mykey-tray` against the current auth and trust model.
- [x] Audit installer, services, D-Bus policy, and polkit policy as one release surface.
  - package/setup split is now captured in [packaging/arch/TRANSITION.md](/home/james/Git/mykey/packaging/arch/TRANSITION.md)

### `mykey-manager`

#### Low
- [ ] Keep `mykey-manager` deferred until the backend and TUI stack are stable.
  - current manager code is only a placeholder shell

### `docs`

#### Important
- [x] Overhaul `docs/architecture.md` around the current MyKey platform.
- [x] Overhaul `docs/threat-model.md` around the current MyKey platform.

### `validation`

#### Critical
- [ ] Keep verifying each Level 1 step before moving to the next.
- [ ] Do not commit `mykey-pin` work until the path is usable end-to-end.

#### Important
- [ ] Add focused manual validation for CLI, helper, and PAM behavior before moving to Level 2.
  - CLI, helper, elevated-password, and PAM end-to-end validation are complete
- [ ] Run live security-key validation once hardware is available.
  - enroll, status, test, unenroll, and security-key-first `pam_mykey.so` auth still need a real-key pass on a host with `pam_u2f`
- [ ] Run a full host-installed auth calibration pass once the local-auth surface is further along.
  - live package install and host-side auth calibration are now in progress on an Arch test machine
  - the current PIN + biometric release scope is now host-validated for `sudo`, `polkit-1`, and opt-in `gdm-fingerprint`
  - dedicated elevated-password flow is now live-validated for `mykey pin reset` and `sudo mykey-auth biometrics`, both requiring the Linux account password instead of fingerprint or MyKey PIN
  - elevated-management frontends now precheck the dedicated cooldown before prompting for the Linux password, and that UX fix is now live-validated on-host
  - `pamtester polkit-1 "$USER" authenticate` is now live-validated for both successful fingerprint auth and fingerprint failure falling back to MyKey PIN
  - `sudo true` is now live-validated for successful fingerprint auth, biometric failure falling back to PIN, correct PIN lockout thresholding, and retries staying pinned inside MyKey after fallback begins
  - `sudo mykey-auth disable` is now live-validated for clean teardown of base and selected login targets, with native auth resuming afterward
  - `sudo mykey-auth setup` is now live-validated for clean re-enable of base targets, while leaving login targets unchanged when the operator declines login takeover
  - elevated-password backoff is now live-validated as separate from MyKey PIN lockout
  - validate the install/package surface on a real machine instead of only through repo-side builds
  - the last host install exposed three package-era bugs: TPM access for the `mykey` daemon user, trusted-binary hash generation from the pre-package daemon artifact, and daemon startup timing during `post_install()`
  - repo-side fixes are now staged through `SupplementaryGroups=tss` and a post-transaction package hook, but that package path still needs a fresh host re-test before it can be called stable

---

## Active Design Notes

### `mykey-pin` target model
- local, device-bound, Windows Hello-like optional PIN
- PIN is not the Unix password
- password remains fallback and recovery path
- local auth only, not a reusable remote credential
- the auth-related codebase now lives under the `mykey-auth/` subtree for clarity
- normal MyKey local auth should be managed through a unified `pam_mykey.so` layer
- `mykey-pin` should serve as the PIN fallback backend behind that unified auth layer
- biometrics should be offered first, then fall back to MyKey PIN
- elevated actions should require stronger authentication than biometrics alone

### `mykey-tray` target model
- tray stays intentionally minimal
- tray click/menu should show concise one-word status only
- verbose operational detail belongs in `mykey-tray status`
- tray auth state should come from daemon-owned local-auth policy, not just helper-binary presence
- the tray should not claim MyKey is managing auth until supported PAM paths are verifiably routed through MyKey

### Level 1 boundary
- architecture first
- no full TPM auth-value redesign yet
- no TPM dictionary-lockout redesign yet
- no broad PAM policy rollout yet

### Current known issues driving the redesign
- daemon trust model did not previously fit PAM-hosted authentication
- PIN state was global instead of per-user
- clients were reading and writing PIN state directly
- verification authority was not centralized in the daemon
- reset and lockout behavior lived in the wrong layer

---

## Follow-Up Queue

### Important
- [ ] Revisit `mykey-daemon` password-side brute-force behavior after Level 1 `mykey-pin` is usable.
- [ ] Review remaining modules one at a time before first release.
- [ ] Keep `docs/architecture.md` and `docs/threat-model.md` updated as the platform design changes instead of letting them drift behind the code again.
- [ ] Track the `tss-esapi -> picky-asn1-x509` future-incompat warning in the TPM dependency stack and update or pin that chain before a future Rust release turns it into a hard build failure.

### Low
- [ ] Keep GUI/package integration notes separate from backend correctness work until backend paths are stable.

---

## Project History

Reconstructed from commit history in chronological order.
Grouped by day, oldest first.

### 2026-04-04
- Scaffolded the repo, initial docs, assets, and the base project structure.
- Added the Chromium MV3 extension scaffold with `webAuthenticationProxy`, crypto helpers, and storage helpers.
- Added the first Rust native-messaging host with PAM auth, P-256 crypto, TPM stubs, and request handlers.
- Added the persistent daemon with D-Bus transport, session tokens, AES-GCM IPC encryption, HMAC validation, replay protection, caller ancestry checks, prerequisite enforcement, and systemd hardening.
- Bridged the native host to the daemon over D-Bus with encrypted request transport and HMAC on all messages.
- Rewrote the README with roadmap, requirements, disclaimer, and a plain-English project overview.
- Rewrote the threat model around the early proxy-era design and its planned mitigations.
- Rewrote the architecture document with the initial implementation, request flows, and trust model.
- Corrected author attribution to JamesFromFL.
- Added the first system tray indicator with KStatusNotifierItem compatibility.
- Wired daemon `Register` and `Authenticate` end to end with PAM gating, P-256 key generation, TPM sealing, authenticator data construction, and assertion signing.
- Fixed installer Cargo detection when run under `sudo`.
- Improved installer cargo discovery and tray user-service installation ownership.
- Switched the daemon path to the system D-Bus and ensured the installer builds as the real user instead of root.
- Added the D-Bus system policy file and installed it from the installer.
- Polished install and uninstall wiring around D-Bus, the system bus, and user-owned tray service setup.

### 2026-04-05
- Added the first guided installer with Secure Boot setup, TPM checks, per-file EFI signing, extension setup, and a full health check.
- Updated the README to match the installer flow, stylized logo, and then-current project status.
- Fixed the native host to use the system bus instead of the session bus.
- Removed the bootstrap key from daemon session setup and returned the session token directly over the kernel-verified system bus.
- Removed bootstrap-key decryption from the native host to match the new daemon session model.
- Removed bootstrap-key generation and related health checks from the installer.
- Updated architecture and threat-model docs to reflect bootstrap-key removal and the system-bus session model.
- Fixed extension startup to call `attach()` and corrected error handling to use the proper completion APIs.
- Fixed protocol parsing to accept numeric or string `requestId` values and corrected `clientDataJSON` field casing.
- Cleared the replay cache on new daemon sessions and passed the calling PID through auth handlers.
- Replaced broken `/dev/tty` PAM prompting in the daemon with `polkit pkcheck` so desktop auth agents can handle user presence.
- Improved extension startup/error handling again, increased timeout to 30 seconds, and returned the extra WebAuthn fields Chrome expected.
- Added polkit policy, a sudoers rule for `pkcheck`, TPM group handling, and write exceptions for credential storage in the hardened service unit.
- Fixed `rpIdHash` computation to hash the full Chrome extension origin in the proxy design.

### 2026-04-06
- Added real TPM2 key sealing with PCR 0+7 policy binding through `tss-esapi`.
- Improved installer Secure Boot guidance by adding a Microsoft keys prompt, opening `chrome://extensions`, and correcting the polkit owner annotation.
- Added daemon-side polkit retry logic with escalating cooldowns to slow password guessing.
- Updated README, architecture, and threat-model docs to reflect real TPM sealing, polkit auth, brute-force protection, and the planned manager.
- Removed the NordPass compatibility mention from the docs.
- Simplified the README roadmap and status presentation.
- Updated docs again to remove MOK scope, correct bootstrap-key references, add brute-force notes, and expand Firefox/manager planning.
- Fixed daemon `rpIdHash` handling for extension IDs versus normal web relying parties.
- Fixed the extension to extract `userId` and `userName` correctly so `userHandle` storage and return behavior were accurate.
- Hard-enforced Secure Boot in the daemon at startup instead of treating it as advisory.
- Marked hard Secure Boot enforcement as complete in the README.
- Renamed the project from WebAuthn Proxy to MyKey Proxy across binaries, D-Bus names, config paths, scripts, and docs.
- Cleaned up remaining `webauthn-proxy` references missed during the rename.
- Fixed the renamed tray service filename and removed an invalid `ProtectMemory` unit directive.
- Prevented installer runs as root, fixed tray installation for non-root users, ensured extension setup always runs, and corrected binary-signing logic.
- Removed invalid ELF binary signing and corrected tray installation to run in the real user context.

### 2026-04-07
- Added the initial GTK4 manager application scaffold.

### 2026-04-08
- Expanded the README with more project detail and testing notes.
- Revised and strengthened the threat-model document.
- Revised the architecture document again for the MyKey Proxy design.
- Added Discord release notifications.
- Added Discord dev-log notifications.

### 2026-04-09
- Renamed the project from MyKey Proxy to MyKey and broadened the project framing.
- Replaced the old assets with the new MyKey branding set.
- Added size-variant logos.
- Updated the README logo image.
- Improved README logo presentation.
- Changed the repository URL from `mykey-proxy` to `mykey`.
- Renamed `daemon/` to `mykey-daemon/` and updated D-Bus names and config paths to the final `com.mykey.*` and `/etc/mykey/` forms.
- Renamed `native-host/` to `mykey-host/` and updated its D-Bus names and references.
- Renamed the Chromium extension tree to `mykey-proxy/chromium/`, added the Firefox placeholder, regenerated icons, and renamed the native-messaging host manifest.
- Renamed `systray/` to `mykey-tray/` and updated icon generation and references.
- Renamed `manager/` to `mykey-manager/` and updated application IDs and window titles.
- Renamed scripts/config files and updated all remaining `mykey-proxy` references across the repo.
- Updated `CLAUDE.md` to reflect the expanded MyKey scope, component names, and crate layout.
- Updated the Discord workflow branding from MyKey Proxy to MyKey.
- Added `SealSecret` and `UnsealSecret` daemon methods to support the TPM-backed secrets path.
- Added the initial `mykey-secrets` crate with Secret Service skeleton APIs, session management, storage layout, and a daemon TPM client.
- Added the `mykey-secrets` user service, session-bus policy file, and installer wiring.
- Implemented `CreateItem`, `SearchItems`, and `GetSecrets` with real TPM-sealed storage in `mykey-secrets`.
- Fixed installer directory creation for `/etc/mykey/secrets/default/`.
- Fixed stale installer references to the old daemon directory.
- Corrected daemon binary install paths and hash labels in the installer.
- Added Secure Boot and TPM prerequisite enforcement to `mykey-secrets` startup.
- Fixed remaining installer path references, session D-Bus directory creation, health checks, and binary checks for `mykey-secrets`.
- Removed invalid binary-integrity prerequisites from `mykey-secrets`, fixed service startup ordering, converted it to a user service, and added session D-Bus directory creation.

### 2026-04-10
- Added the standalone `mykey-migrate` tool for Secret Service migration from GNOME Keyring, KWallet, and KeePassXC into MyKey.
- Updated the tray icon to use the new repo-root MyKey logo asset.
- Added a dedicated daemon caller-validation path for first-party MyKey tools such as `mykey-secrets`, `mykey-migrate`, and `mykey-manager`.

### 2026-04-11
- Rewrote migration provider detection around D-Bus and systemd, added KeePassXC stop guidance, wrote provider info to `/etc/mykey/provider/info.json`, and added optional keychain deletion prompts.
- Refactored `mykey-migrate` around explicit `--enroll` and `--unenroll` subcommands.
- Updated README component and roadmap sections to match the migration/secrets work.
- Fixed README markdown.
- Fixed README component-name formatting.
- Added the `--enroll` and `--unenroll` command flow, collection unlock before writes, provider info handling, and keychain deletion prompts.
- Wired `mykey-migrate` into installer build, health checks, and uninstall flow and cleaned stale `mykey-secrets` logs before startup.
- Fixed session-bus policy so the real user can own `org.freedesktop.secrets`, corrected `/etc/mykey` traversal permissions, removed the race from `--now`, and cleaned logs before service start.
- Added detection and stopping of conflicting Secret Service providers in the installer and fixed related shell and permission issues.

### 2026-04-13
- Rewrote `mykey-migrate --enroll` and `--unenroll` into fuller self-contained flows with provider selection and simpler installer handoff.
- Added envelope encryption for large secret sealing and made uninstall start with `mykey-migrate --unenroll`.
- Added a patience notice to enroll output for slow TPM sealing.
- Ensured `mykey-secrets` always starts at the end of enroll and removed an incorrect early exit from unenroll.
- Fixed the full set of identified migration audit bugs around service startup, provider masking, fatal stop failures, unenroll menus, service name handling, systemd fallback detection, unlock behavior, and invalid user-service dependencies.

### 2026-04-14
- Aligned migration enroll and unenroll flows to the intended spec, including verified start/stop behavior, fatal cleanup, provider advisories, and correct keychain deletion order.
- Carried the same migration fixes into the install/uninstall scripts and removed duplicated `mykey-secrets` operations.
- Replaced the uninstall `pkexec` block with a `sudo -v` keepalive pattern.
- Marked the migration tool complete in the README.
- Registered all collections and items on `mykey-secrets` startup, added `Unlock`, `Lock`, `Collections`, and `ReadAlias`, fixed D-Bus object paths, and pointed the default alias to the migrated collection.
- Fixed UUID handling across all remaining Secret Service paths and added collection search logging.
- Replaced the blocking daemon client in `mykey-secrets` with an async client and fixed missing awaits.
- Fixed remaining Secret Service compliance issues around duplicate alias objects, session cleanup, item deletion, collection modification timestamps, and `ItemCreated` signaling.

### 2026-04-16
- Implemented `Collection.Delete`, `CreateCollection`, change signals, alias persistence, and collection lifecycle signals in `mykey-secrets`.
- Changed enroll to uninstall the previous provider before killing it, added XDG autostart for `mykey-secrets`, and continued Secret Service feature completion.
- Fixed unenroll cleanup of `/etc/mykey/secrets`, corrected provider stop ordering, and refined autostart management.
- Added a pause-and-retry recovery pattern across migration flows with explicit support links and user guidance.
- Added the Firefox extension scaffold as a placeholder while Mozilla platform authenticator support remained unavailable.
- Revised the project roadmap with updated status.
- Revised the roadmap again for WebAuthn and Firefox planning.

### 2026-04-17
- Added the `mykey-pin` crate with a PAM module and CLI for TPM-backed PIN authentication aligned with daemon lockout behavior.
- Wired `mykey-pin` into installer build, install, health check, and uninstall cleanup and created the initial `/etc/mykey/pin/` path.
- Simplified unenroll collection handling back to a cleaner user-assisted unlock flow.

### 2026-04-18
- Rewrote the unenroll collection flow toward spec-correct Secret Service behavior.

### 2026-04-19
- Hardened Secret Service unenroll and restore behavior.
- Hardened KWallet and KeePassXC readiness handling.
- Hardened enroll transaction behavior and storage staging.

### 2026-04-20
- Redesigned PIN auth around a daemon-owned per-user PAM flow.
- Rewrote the README project overview and roadmap again.
- Removed `CLAUDE.md` from the repo.
- Reorganized the local-auth stack under `mykey-auth/`.

### 2026-04-22
- Overhauled the platform around daemon-owned local auth and de-scoped the browser-bridge architecture.
- Removed `mykey-proxy` from project scope and repo.
- Removed `mykey-host` from project scope and repo.
- Added `mykey-auth enable|disable|login|logout|status` with MyKey-managed PAM target handling.
- Added the first `mykey-auth biometrics` scaffold with `fprintd` and `Howdy` setup, status, and TPM-sealed metadata tracking.
- Fixed `mykey-secrets` runtime state handling, atomic writes, and user-path ownership model.
- Reworked `mykey-tray` into an optional daemon-coupled tray with `run|enable|disable|status`.
- Audited installer, services, D-Bus policy, and polkit policy as one release surface.
- Added the first Arch packaging scaffold and transition notes.
- Moved repo-backed documentation into `docs/` and retired the old top-level architecture and threat-model files.
- Overhauled `docs/architecture.md` around the current runtime layers, service ownership, state layout, and setup model.
- Overhauled `docs/threat-model.md` around the current daemon, PAM, secrets, migration, and packaging trust boundaries.
- Refined the architecture and threat-model docs with quick-reference tables, lifecycle summaries, trust-boundary summaries, and explicit explanations for the supported security baseline.
- Refined the README to use friendlier front-facing links for docs and project status and added a threat-model pointer under supported-system requirements.
- Extended daemon-owned local-auth policy with effective password-fallback, elevated-password, and biometric-attempt outputs and surfaced that policy through `mykey-auth status`.

### 2026-04-23
- Moved elevated MyKey management auth onto a dedicated `mykey-elevated-auth` helper and password-only PAM service.
- Added daemon-owned elevated-auth rate limiting and purpose-scoped grants for PIN setup/reset and biometric management.
- Switched `mykey-pin` first-time setup/reset and `mykey-auth biometrics` management actions off the old generic presence-check path.
- Updated installer, uninstaller, and Arch packaging to ship the new helper and dedicated PAM service.
- Wired `pam_mykey.so` and `mykey-auth` into daemon-driven biometric-first runtime auth with capped attempts and MyKey PIN fallback for `fprintd` and `Howdy`.
- Split local-auth daemon client modules by binary responsibility and removed stale generic presence wrappers to keep auth crate builds warning-clean.
- Finished MyKey-managed normal password fallback: `pam_mykey.so` now prompts for Linux account password through `mykey-auth`, with daemon-owned backoff and no downstream password fallback once a PIN exists.
- Cleaned the daemon warning set by removing stale crypto/diagnostic helpers, gating test-only policy helpers, and updating AES-GCM call sites away from deprecated APIs.
- Added the first-wave `mykey-security-key` tool with `enroll`, `status`, `unenroll`, and `test`, plus a dedicated `pam_u2f` PAM service, sealed registry metadata, and package/install wiring.
- Wired security-key-first local auth into daemon policy and `pam_mykey.so`, with `mykey-security-key` managing activation and MyKey PIN remaining the fallback path.
- Added the guided `mykey-auth setup` flow for daemon readiness checks, PIN-first bring-up, optional security key and biometrics, required base PAM takeover, and optional login takeover.
- Updated Arch packaging docs and scriptlets so package install now brings up `mykey-daemon` automatically and points operators at `sudo mykey-auth setup` as the primary next step.
- Fixed the setup path so `mykey-pin` honors `SUDO_UID` and configures the invoking Linux account instead of root when launched through `sudo`.
- Trimmed redundant biometric setup menus so pre-printed action and device lists now go straight to `Selection:` without being restated by the prompt helper.
- Fail-closed MyKey-managed PAM targets with `default=die` and taught `pam_mykey.so` to keep retries pinned to MyKey PIN fallback within the same PAM transaction after biometrics have already been exhausted.
- Cleared stale PIN failure debt after successful biometric or security-key auth so a good MyKey login resets the PIN counter instead of preserving old lockout history.
- Kept locked PIN fallback retries inside MyKey during the same PAM transaction so `sudo` no longer restarts fingerprint after PIN fallback is already locked.

### 2026-04-24
- Live-validated the elevated-password path on-host for `mykey pin reset` and `mykey-pin set`, including separate cooldown behavior from the MyKey PIN lockout path.
- Added elevated-management cooldown prechecks so `mykey pin reset`, `mykey-auth biometrics`, and `mykey-security-key` no longer prompt for the Linux password while elevated auth is already rate-limited.
- Live-validated `pamtester polkit-1 "$USER" authenticate` for both successful fingerprint auth and fingerprint failure falling back to MyKey PIN.
- Live-validated clean PAM teardown through `sudo mykey-auth disable`, with native `sudo` auth resuming after MyKey-managed blocks were removed.
- Live-validated `sudo mykey-auth setup` as a repeatable re-enable path for base PAM targets, with login takeover remaining opt-in and left untouched when declined.
- Tightened PAM-facing lockout UX so the lockout-triggering PIN failure now reports the active cooldown immediately, and locked-PIN retries inside the same PAM conversation no longer spam the same lockout message on every retry.
- Clarified `mykey-pin reset` so operators are told that biometric and security-key stages tied to the old PIN must be reconfigured after a new PIN is set.
- Hardened the Arch package path by moving daemon finalization into post-transaction hooks, regenerating `trusted-binaries.json` from the final installed daemon binary, and shifting TPM access onto the daemon service unit through `SupplementaryGroups=tss`.
- Live-validated the hardened Arch package path from a fresh install and trimmed the package post-install message down to the minimal auth-first next steps.
- Smoothed `mykey-migrate --enroll` startup by auto-waiting for `mykey-secrets` to claim `org.freedesktop.secrets` before falling back to the manual recovery prompt.
- Added guided KWallet destination-readiness retry during `mykey-migrate --unenroll` so restore can wait for an unlocked/exported wallet instead of immediately fataling on the first check.
- Split `mykey-migrate --unenroll` more explicitly by provider path, preserving the working gnome-keyring restore flow while adding KWallet-specific wallet-creation guidance and post-restore handling.

### 2026-05-01
- Started the migration transaction-safety hardening pass by adding direct MyKey storage auditing for parsed collections/items, raw storage entries, and parse/read issues.
- Changed `mykey-migrate --enroll` from replace semantics to merge semantics so provider reads are added to existing MyKey storage instead of replacing the whole store.
- Guarded enroll against suspicious MyKey storage states and stopped offering old-keychain deletion when a transaction copied no new provider secrets.
- Wired `mykey-migrate --unenroll` to audit MyKey storage before provider handoff, fail closed on suspicious storage, and reuse the audited source set for restore planning.
- Made unenroll provider verification and finalization fail before MyKey cleanup when destination listing, restore verification, or provider finalization fails.
- Added persistent `mykey-migrate` event logging under the user's MyKey state directory for source/destination providers, audit counts, merge counts, restore verification, cleanup, rollback, and fatal decisions.

### 2026-05-02
- Live-validated gnome-keyring, KWallet, and KeePassXC migration handoff paths after transaction-safety hardening.
- Added KeePassXC-specific Secret Service handling: skip destructive write probes, wait for exposed database groups, unlock individual source items before `GetSecret`, and verify restore by expected metadata when KeePassXC exposes restored items but refuses post-restore value reads.
- Added non-secret KeePassXC inventory logging for collection paths, item paths, labels, locked state, content type, exposed attribute keys, and secret-read availability to make future failures diagnosable.
