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
  - current focus is Level 1 architecture only

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

14. [ ] `Important` `mykey-daemon` `mykey-pin` Move brute-force protection to the PIN path only.
   - keep hardening for `mykey-pin`
   - stop affecting normal password fallback flows like `sudo` password prompts
   - current PIN lockout schedule is 3 free failed attempts, then 1m → 5m → 15m → 30m → 1h → 2h → 5h

15. [ ] `Moderate` `mykey-pin` Add explicit PIN policy.
   - minimum length
   - empty PIN rejection
   - final decision on numeric-only vs broader local PIN policy

16. [ ] `Moderate` `packaging` Align final package behavior with GUI and CLI release model.
   - `mykey-manager` as GUI frontend
   - modules callable directly from terminal
   - installer replaces current script-only assumptions

17. [ ] `Low` `docs` Document PIN setup and fallback behavior clearly.
   - explain that PIN is optional
   - explain that PIN is device-local
   - explain password fallback and recovery expectations

18. [ ] `Extra` `level-2` Plan the next TPM-auth redesign after Level 1 is usable.
   - move beyond sealed verifier model
   - aim closer to a true Windows Hello-like local auth protector

19. [ ] `Moderate` `mykey-pin` Explore TOTP-based recovery for PIN reset and lockout recovery.
   - recovery factor only, not a normal authentication method
   - should help with forgotten PIN or lockout recovery
   - keep it local and optional, with clear backup and recovery expectations

---

## By Module

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
- [ ] Revisit daemon-side brute-force behavior later so non-PIN password flows are not over-hardened.
- [ ] Keep the current PIN lockout schedule at 3 free attempts, then 1m → 5m → 15m → 30m → 1h → 2h → 5h unless later tuning proves necessary.

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

#### Moderate
- [ ] Add explicit PIN policy and user-facing validation rules.
- [ ] Evaluate optional TOTP-based recovery for PIN reset and lockout recovery only.

### `scripts/install.sh` and `scripts/uninstall.sh`

#### Important
- [x] Install and remove `mykey-pin-auth`.
- [x] Change `/etc/mykey/pin` ownership model from real-user-owned to daemon-owned.
- [x] Keep PAM module install path aligned with the new architecture.
- [x] Convert Secure Boot handling from interactive setup/signing to strict prerequisite verification in the installer.

#### Low
- [ ] Revisit script relevance later once package-driven install flow replaces script-driven setup.

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

### Low
- [ ] Keep GUI/package integration notes separate from backend correctness work until backend paths are stable.
