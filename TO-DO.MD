# MyKey TO-DO

Last updated: 2026-04-20

## Purpose
- Canonical running to-do list for MyKey release hardening.
- Track work in execution order first, then by module and severity.
- Keep this file updated before and after each patch set.
- Current rule for `mykey-pin`: do not stop for a commit until it reaches a usable state.

## Current Status
- `mykey-migrate`
  - gnome-keyring unenroll/restore path is working and was live-tested successfully.
  - KWallet readiness handling is improved and now stops at the correct wallet-readiness boundary.
  - KeePassXC readiness handling is improved and now stops with explicit setup guidance.
  - enroll path has already been hardened.
  - enroll now unlocks source collections before bulk secret reads, so locked source keyrings fail with a prompt instead of partial-read errors.
  - enroll staging now activates inside the writable `/etc/mykey/secrets` tree instead of requiring writes to `/etc/mykey`.
- `mykey-pin`
  - active redesign target
  - not yet release-ready
  - Level 1 PIN architecture is usable and validated
  - next auth direction is a unified `pam_mykey.so` local-auth layer that orchestrates existing backends and keeps MyKey PIN as the local fallback
- `mykey-auth`
  - local-auth subtree now groups:
    - `mykey-pam`
    - `mykey-pin`
    - `mykey-biometrics`
    - `mykey-security-key`
  - MyKey local auth is an orchestration layer over existing system auth stacks.
  - MyKey should integrate and validate existing backends such as `fprintd`, `Howdy`, and security-key/FIDO2 tooling instead of reimplementing them.
- `pam_mykey`
  - Phase A pin-backed base is now in repo through `mykey-auth/mykey-pam` and the `mykey-auth` helper
  - Phase A live validation is complete through `pamtester`
  - current behavior still routes through the existing MyKey PIN backend
  - local-auth policy now lives in daemon-owned state instead of being hardcoded in the helper
  - backend orchestration, policy enforcement, and supported PAM target integration remain open work

---

## Ordered To-Do

1. [x] `Critical` `mykey-daemon` Tighten daemon trust boundary for PIN work.
   - exact trusted MyKey binary basename matching
   - include `mykey-host`, `mykey-pin`, and `mykey-pin-auth` in trusted MyKey caller set
   - cross-check caller-supplied PID against D-Bus sender credentials
   - enforce sender/PID verification on `Connect`, `Register`, `Authenticate`, `SealSecret`, `UnsealSecret`, and `Disconnect`
   - verified with `mykey-daemon` release build and `mykey-host` release build

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
   - stage and rollback within `/etc/mykey/secrets`
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
   - current PIN lockout schedule remains 3 free failed attempts, then 1m → 5m → 15m → 30m → 1h → 2h → 5h

15. [x] `Moderate` `mykey-pin` Add explicit PIN policy.
   - first-release PIN policy is numeric-only
   - minimum length: 4 digits
   - maximum length: 12 digits
   - empty and non-numeric PINs are rejected in both the CLI and daemon API

16. [ ] `Critical` `pam_mykey` Build `pam_mykey.so` into the final MyKey-managed local-auth entrypoint.
   - replace the long-term need for separate user-managed PAM ordering between biometrics, security keys, PIN, and password
   - make `pam_mykey.so` the first MyKey auth module for supported system auth flows such as `sudo`, lock screen, login-adjacent prompts, and other safe local PAM targets
   - make MyKey responsible for installing and maintaining its supported PAM integration points so auth reaches MyKey first
   - Phase A base is in place: `mykey-auth/mykey-pam` and `mykey-auth` currently route through MyKey PIN
   - Phase A live validation is complete with `pamtester`
   - normal local auth should be MyKey-managed and should not rely on users hand-editing PAM ordering
   - elevated actions must stay outside normal biometric-only auth and continue to require stronger verification

17. [ ] `Critical` `local auth policy` Encode the hard MyKey auth rules in daemon-owned policy.
   - MyKey must orchestrate existing system auth stacks instead of reimplementing biometrics or security-key verification itself
   - first enforcement step is in place: invalid biometric-without-PIN policy is sanitised to a safe disabled state on daemon read
   - biometrics require a configured MyKey PIN fallback
   - enabling biometrics without a PIN must first trigger PIN setup
   - removing or resetting PIN while biometrics are enabled must automatically disable biometrics and inform the user why
   - when PIN is configured, normal local auth should not fall through to the user password
   - when PIN is not configured, password fallback is allowed for normal local auth
   - password-based paths must use exponential rate limiting instead of hard lockout
   - elevated MyKey actions must always require password and use a separate rate-limited path from everyday local auth

18. [ ] `Important` `mykey-biometrics` Add a dedicated biometric setup and management helper on top of existing system stacks.
   - add `mykey-biometrics` with commands such as `setup`, `status`, `test`, `reset`, and later `disable`
   - support backend selection for `fprintd` and `Howdy`
   - detect whether the selected backend is installed and offer install guidance or install integration where appropriate
   - drive backend enrollment, backend validation, MyKey policy enablement, and final verification
   - require a PIN before enabling biometrics and explain the fallback policy clearly during setup
   - remove the need for users to hand-edit PAM configuration to get MyKey biometrics working

19. [ ] `Important` `mykey-security-key` Add a dedicated security-key setup and management helper on top of existing system stacks.
   - add `mykey-security-key` with commands such as `setup`, `status`, `test`, `reset`, and later `disable`
   - integrate with the existing system security-key/FIDO2 stack instead of reimplementing key verification in MyKey
   - add security-key policy enablement and validation behind `pam_mykey.so`
   - keep security-key auth as a first-class local-auth backend alongside biometrics and MyKey PIN

20. [ ] `Important` `local auth policy` Add backend-first local auth orchestration with MyKey-managed fallback.
   - daemon-owned local-auth policy state now exists under `/etc/mykey/auth`
   - `mykey-auth` now reads daemon policy instead of hardcoding PIN-only behavior
   - existing pin-only users are backfilled automatically into local-auth policy on first status read
   - allow up to 3 biometric attempts per auth session before falling back to MyKey PIN
   - biometric failures must not increment the MyKey PIN brute-force counter
   - add the security-key path into MyKey-managed auth ordering once its helper exists
   - keep MyKey PIN as the normal local fallback when biometrics or security keys are enabled
   - reserve elevated authentication for high-risk actions such as first-time PIN setup, PIN reset, biometric enrollment or disablement, security-key enrollment or disablement, recovery actions, and future TOTP enrollment

21. [ ] `Moderate` `packaging` Align final package behavior with GUI and CLI release model.
   - `mykey-manager` as GUI frontend
   - modules callable directly from terminal
   - installer replaces current script-only assumptions

22. [ ] `Critical` `audit` Audit `mykey-host` against the current daemon-owned architecture.
   - identify stale host-side auth, PAM, TPM, or crypto responsibilities that should already live in `mykey-daemon`
   - confirm the host only handles native messaging, daemon session transport, and request/response marshaling
   - remove or plan removal of legacy modules that no longer match the current trust boundary

23. [ ] `Important` `audit` Audit `mykey-secrets` and `mykey-tray` against the current auth and trust model.
   - verify daemon integration assumptions
   - identify stale direct-auth assumptions
   - identify release-critical correctness or trust-boundary issues

24. [ ] `Low` `mykey-manager` Defer manager audit and implementation until the backend and TUI stack are stable.
   - current `mykey-manager` is only a placeholder shell
   - real manager work should happen after the functional local-auth and secrets stack is settled

25. [ ] `Important` `audit` Audit installer, service, D-Bus, and polkit wiring as one release surface.
   - `scripts/install.sh`
   - `scripts/uninstall.sh`
   - systemd units
   - D-Bus policy files
   - polkit policy files

26. [ ] `Important` `docs` Rewrite `ARCHITECTURE.md` around the current MyKey platform instead of the old MyKey Proxy layout.
   - stop describing the project as only a WebAuthn proxy
   - reflect the current `mykey-auth/` subtree, daemon-owned local auth policy, and current component boundaries
   - keep it as the technical system-layout document for reviewers and advanced users

27. [ ] `Important` `docs` Rewrite `THREAT_MODEL.md` around the current MyKey platform and enforced policy.
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
- [ ] Move PIN verification, change, reset, and lockout updates fully behind daemon methods.
- [x] Revisit daemon-side brute-force behavior so non-PIN password flows are not over-hardened.
  - daemon-side polkit/password verification no longer carries a MyKey-managed cooldown
- [x] Keep the current PIN lockout schedule at 3 free attempts, then 1m → 5m → 15m → 30m → 1h → 2h → 5h.

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
- [ ] Make MyKey responsible for installing and maintaining supported PAM service integration so auth reaches MyKey first.

### `local auth policy`

#### Important
- [x] Move local-auth mode selection into daemon-owned per-user policy state.
- [x] Make `mykey-auth` consult daemon local-auth policy instead of hardcoding PIN-only behavior.
- [x] Backfill existing pin-only users into daemon-owned local-auth policy automatically.
- [x] Sanitize invalid biometric-without-PIN policy back to a safe disabled state on daemon read.
- [x] Clear biometric policy automatically when PIN is reset.

#### Important
- [ ] Define supported first-wave PAM targets such as `sudo`, lock screen, and other safe local auth prompts.
- [ ] Keep elevated MyKey management actions outside biometric-only PAM auth.
- [ ] Enforce hard local-auth invariants in daemon-owned policy.
  - biometrics require PIN fallback
  - removing or resetting PIN disables biometrics
  - no normal password fallback once PIN exists
- [ ] Use exponential rate limiting for password fallback and elevated password auth instead of hard lockout.

### `mykey-biometrics`

#### Important
- [ ] Add `mykey-biometrics` setup, status, test, and reset flows.
- [ ] Support backend selection for `fprintd` and `Howdy`.
- [ ] Use the existing system biometric stacks instead of reimplementing biometric verification inside MyKey.
- [ ] Validate backend enrollment before enabling MyKey biometric policy.
- [ ] Enable MyKey-managed biometric auth without requiring users to hand-edit PAM files.

### `mykey-security-key`

#### Important
- [ ] Add `mykey-security-key` setup, status, test, and reset flows.
- [ ] Use the existing system security-key/FIDO2 stack instead of reimplementing key verification inside MyKey.
- [ ] Validate security-key enrollment before enabling MyKey security-key policy.
- [ ] Enable MyKey-managed security-key auth without requiring users to hand-edit PAM files.

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
- [ ] Audit `mykey-host` against the current daemon-owned architecture.
  - remove or quarantine stale host-side auth logic that no longer matches the trust boundary
  - current audit findings:
    - `mykey-host` still compiles legacy PAM, TPM, local crypto, and local credential helper modules that no longer belong in the browser-facing host
    - `mykey-host` currently logs RP IDs and usernames to `/tmp/mykey-host.log`, which should be treated as a privacy leak and cleaned up during the host refactor

#### Important
- [ ] Audit `mykey-secrets` and `mykey-tray` against the current auth and trust model.
- [ ] Audit installer, services, D-Bus policy, and polkit policy as one release surface.

### `mykey-manager`

#### Low
- [ ] Keep `mykey-manager` deferred until the backend and TUI stack are stable.
  - current manager code is only a placeholder shell

### `docs`

#### Important
- [ ] Rewrite `ARCHITECTURE.md` around the current MyKey platform.
- [ ] Rewrite `THREAT_MODEL.md` around the current MyKey platform.

### `validation`

#### Critical
- [ ] Keep verifying each Level 1 step before moving to the next.
- [ ] Do not commit `mykey-pin` work until the path is usable end-to-end.

#### Important
- [ ] Add focused manual validation for CLI, helper, and PAM behavior before moving to Level 2.
  - CLI, helper, strong-auth, and PAM end-to-end validation are complete

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
- [ ] Keep `ARCHITECTURE.md` and `THREAT_MODEL.md` updated as the platform design changes instead of letting them drift behind the code again.

### Low
- [ ] Keep GUI/package integration notes separate from backend correctness work until backend paths are stable.
