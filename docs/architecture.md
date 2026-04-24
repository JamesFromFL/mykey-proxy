# MyKey Architecture

## Purpose

This document describes the current MyKey platform as it exists in the repo
today.

Its job is to explain:

- which components are part of the active architecture
- which components are authoritative versus optional
- how auth, secrets, and migration actually flow through the system
- which parts are transitional or still incomplete

This is not a roadmap document and it does not treat removed or planned
components as if they are part of the live runtime.

## Platform Summary

MyKey is currently a Linux local-authentication and secret-storage platform
built around:

- a privileged system daemon
- explicit PAM integration managed by MyKey
- a user-session Secret Service provider
- an explicit migration tool for provider handoff
- an optional tray process for status and later notifications

The current platform is intentionally narrower than older project versions:

- no browser extension bridge
- no native-messaging host
- no extension-managed WebAuthn interception

## Core Architecture Rules

The current platform is built around a few hard rules:

1. High-trust security state belongs to `mykey-daemon`, not to user-session
   services or PAM modules.
2. MyKey should manage its own PAM placement instead of relying on users to
   hand-edit PAM files.
3. Secret Service takeover is a migration event, not a package-install side
   effect.
4. Optional session UX components such as the tray should never become the
   primary control plane for security-critical state changes.
5. Package installation should place files on disk; setup commands should own
   runtime transitions.

## Runtime Layers

### System trust layer

The system trust layer is `mykey-daemon`.

It is the privileged core of the platform and owns:

- daemon-side local-auth policy
- daemon-side PIN state and lockout behavior
- TPM-backed sealing and unsealing helpers
- privileged D-Bus methods
- caller validation for privileged operations

This is the main trust anchor in the current design.

### Local-auth integration layer

The local-auth layer lives under `mykey-auth/`.

Today it includes:

- `mykey-pam`
  - `pam_mykey.so`
  - `mykey-auth`
  - `mykey-elevated-auth`
  - PAM target inspection and managed PAM edits
- `mykey-pin`
  - PIN setup, reset, verify, and status workflows
- biometric setup scaffolding in `mykey-auth biometrics`
- `mykey-security-key`
  - security-key enrollment, status, test, and unenroll on top of `pamu2fcfg`
    and `pam_u2f`

This layer is responsible for connecting PAM-facing system behavior to the
daemon-owned auth model without putting high-trust logic directly in the PAM
module.

### Secret Service layer

The Secret Service layer is made of:

- `mykey-secrets`
- `mykey-migrate`

`mykey-secrets` is the user-session provider that claims
`org.freedesktop.secrets` when MyKey is the active provider.

`mykey-migrate` is the only supported handoff tool for:

- enrolling MyKey as the active Secret Service provider
- restoring the previous provider later

This separation is intentional: the provider should not be enabled blindly just
because the package is installed.

### Session UX layer

The session UX layer is currently small:

- `mykey`
- `mykey-tray`
- `mykey-manager` placeholder code

`mykey` is now the primary terminal control surface. It is intentionally thin
and routes into the underlying component binaries instead of replacing them.

`mykey-tray` is optional and intentionally minimal. It exists to show status
and later surface small notifications such as login-manager detection.

`mykey-manager` is not yet a real control surface and should not be treated as
architecturally important today.

## Runtime Topology

### Local auth path

```text
Local PAM consumer
    └── pam_mykey.so
         └── mykey-auth
              └── mykey-daemon (system service)
                   ├── local-auth policy
                   ├── PIN state and lockout
                   ├── TPM-backed sealing helpers
                   └── caller validation
```

Important current reality:

- `pam_mykey.so` is the intended long-term local-auth entrypoint
- runtime auth now follows daemon local-auth policy instead of hardcoding PIN-only behavior
- when no MyKey PIN is configured, `pam_mykey.so` now keeps normal Linux
  password fallback inside MyKey through `mykey-auth`, the password-only PAM
  service, and daemon-owned backoff state
- when biometric-first policy is active, `mykey-auth` now drives up to the
  daemon-configured biometric attempt limit through the selected `fprintd` or
  `Howdy` backend before falling back to MyKey PIN
- when security-key-first policy is active, `mykey-auth` now drives the
  dedicated `mykey-security-key-auth` / `pam_u2f` path before falling back to
  MyKey PIN
- the daemon now computes effective local-auth policy outputs such as password
  fallback allowance, elevated-action password requirements, and biometric
  attempt limits instead of exposing only raw stored settings
- initial host-installed calibration of biometric-first PAM behavior is now
  complete for `sudo`, `polkit-1`, and the opt-in `gdm-fingerprint` target,
  but broader login-manager and distro-surface calibration is still pending
- security-key runtime auth is now wired, but still needs real hardware
  validation on a host with `pam_u2f`

### Elevated management auth path

```text
Local MyKey frontend (`mykey-pin`, `mykey-auth biometrics`, `mykey-security-key`)
    └── mykey-elevated-auth
         └── PAM service: mykey-elevated-auth (password-only)
              └── mykey-daemon (system service)
                   ├── elevated-auth rate limit state
                   └── purpose-scoped grants for PIN enroll/reset, biometric management, and security-key management
```

Important current reality:

- this path is separate from normal `pam_mykey.so` runtime auth
- it exists so elevated MyKey actions do not inherit fingerprint, `Howdy`, or
  other broad shared PAM stacks by accident
- it currently gates first-time PIN setup, PIN reset, biometric management, and
  security-key enroll/unenroll

### Security-key management and runtime path

```text
mykey-security-key
    ├── enroll / unenroll
    │    ├── mykey-elevated-auth
    │    ├── pamu2fcfg
    │    ├── mykey-daemon SealSecret/UnsealSecret
    │    ├── mykey-daemon local-auth policy
    │    └── /etc/mykey/security-keys.pam_u2f
    └── test
         └── PAM service: mykey-security-key-auth
              └── pam_u2f.so

Local PAM consumer
    └── pam_mykey.so
         └── mykey-auth
              └── mykey-security-key-auth
                   └── PAM service: mykey-security-key-auth
                        └── pam_u2f.so
```

Important current reality:

- MyKey owns the metadata registry and the shared `pam_u2f` authfile
- the runtime verifier is still the existing system `pam_u2f` stack
- security-key-first runtime auth now exists through `pam_mykey.so`
- real hardware validation of that runtime path is still pending

### Secret Service path

```text
Desktop Secret Service clients
    └── org.freedesktop.secrets
         └── mykey-secrets (user service, only when enrolled)
              ├── collection and item metadata
              ├── provider metadata
              └── sealed secret payloads backed by MyKey storage

Provider handoff:
    mykey-migrate --enroll / --unenroll
```

Important current rule:

- users should not be told to enable `mykey-secrets` directly as the first
  setup step
- `mykey-migrate` owns provider takeover and restoration

### Tray path

```text
User session
    └── mykey-tray (optional)
         ├── status snapshot
         ├── later notifications
         └── lifecycle tied to mykey-daemon availability
```

The tray is not required for MyKey to work.

## Operational Flows

### First-time local-auth setup

The intended first-time auth path is:

```text
package install
    -> mykey-daemon already active
    -> run mykey-auth setup
    -> optionally run mykey-migrate --enroll
```

Important design rule:

- `mykey-auth setup` owns the auth-first operator flow:
  - PIN first
  - optional security key when PIN exists
  - optional biometrics when PIN exists
  - required base PAM takeover
  - optional login/unlock takeover
- `mykey-auth enable` remains the lower-level base-target command for `sudo`
  and `polkit-1`
- login takeover remains explicit and opt-in even when driven from setup

### Secret Service takeover

The intended provider handoff path is:

```text
existing provider still active
    -> mykey-migrate --enroll
    -> old provider is read while still available
    -> secrets are staged into MyKey storage
    -> mykey-secrets is enabled only when takeover is safe
    -> MyKey becomes the active Secret Service provider
```

This is why users should not be told to enable `mykey-secrets` by hand before
running `mykey-migrate --enroll`.

### Secret Service restoration and recovery

The intended restore path is:

```text
mykey-migrate --unenroll
    -> previous provider is restored
    -> MyKey leaves the provider path only after restoration is ready
```

If a user removes MyKey without unenrolling first, the recovery path is still:

```text
reinstall MyKey
    -> run mykey-migrate --unenroll
```

## Component Roles

### `mykey-daemon`

`mykey-daemon` is the privileged backend.

It should be thought of as:

- the owner of daemon-side auth state
- the owner of privileged crypto helpers
- the enforcement point for privileged MyKey D-Bus calls

Other components should stay thinner than the daemon.

### `mykey-auth`

`mykey-auth` is the local-auth command surface and orchestration layer.

Its current responsibilities are:

- managing MyKey-owned PAM takeover points
- separating base auth targets from login and unlock targets
- exposing `enable`, `disable`, `login`, `logout`, and `status`
- hosting biometric setup scaffolding

It is not a replacement login manager and it is not a standalone secrets
component.

### `mykey-pin`

`mykey-pin` is the explicit PIN-management CLI.

It does not own the canonical PIN state itself. It is a frontend over the
daemon-owned PIN APIs.

That split is important because it keeps:

- PIN verification
- lockout behavior
- daemon-owned state

out of direct CLI ownership.

### `mykey-secrets`

`mykey-secrets` is the Secret Service provider.

It runs in the user session, not as a system daemon, and it stores:

- user-owned provider and collection metadata
- sealed secret payloads

Its correctness matters, but it is not the system trust anchor.

### `mykey-migrate`

`mykey-migrate` is the provider-transition tool.

It exists specifically because Secret Service ownership changes must happen in
the right order:

- the old provider must still be reachable when secrets are copied in
- MyKey should only take the bus once takeover is safe
- restoration should happen explicitly during unenroll

### `mykey-tray`

`mykey-tray` is an optional session helper.

It should remain:

- lightweight
- non-authoritative
- a visibility surface, not a replacement for explicit CLI setup commands

### `mykey-manager`

`mykey-manager` is currently just a placeholder.

It should not be treated as a real architectural control plane yet.

## Service Ownership And Activation

| Component | Scope | Role | Typical activation |
|---|---|---|---|
| `mykey-daemon` | system service | privileged backend | `sudo systemctl enable --now mykey-daemon` |
| `mykey-secrets` | user service | Secret Service provider | `mykey-migrate --enroll` |
| `mykey-tray` | user service | optional status surface | `mykey-tray enable` |

`mykey`, `mykey-auth`, `mykey-pin`, and `mykey-migrate` are command surfaces,
not long-running services.

## Quick Reference

| Area | Primary owner | Notes |
|---|---|---|
| local-auth policy | `mykey-daemon` | per-user policy under `/etc/mykey/auth/<uid>/` |
| PIN state and lockout | `mykey-daemon` | per-user state under `/etc/mykey/pin/<uid>/` |
| PAM target management | `mykey-auth` | writes explicit MyKey-managed blocks in `/etc/pam.d` |
| top-level terminal UX | `mykey` | thin routing and help surface over the installed MyKey binaries |
| Secret Service bus ownership | `mykey-migrate` + `mykey-secrets` | migration decides when takeover happens; provider owns the bus only when enrolled |
| session status UX | `mykey-tray` | optional, non-authoritative, daemon-coupled |
| future GUI orchestration | `mykey-manager` | not a real control plane yet |

## State Layout

### Daemon-owned state

The daemon-owned side lives under `/etc/mykey`.

Important current areas include:

- `/etc/mykey/pin/<uid>/`
  - sealed PIN state
  - attempt and lockout metadata
- `/etc/mykey/auth/<uid>/`
  - local-auth policy
- other daemon-owned machine and auth state

This state is package-installed but daemon-governed.

### User-session state

The user-session side lives under:

- `MYKEY_DATA_DIR`, if set
- otherwise `XDG_DATA_HOME/mykey`
- otherwise `~/.local/share/mykey`

Important current areas include:

- `.../mykey/secrets/`
  - collections
  - items
- `.../mykey/provider/`
  - provider handoff metadata

This split exists because `mykey-secrets` and `mykey-migrate` are user-session
tools, even though they rely on daemon-backed protection for secret payloads.

### PAM state

MyKey-managed PAM edits live in `/etc/pam.d`.

Important current rule:

- MyKey should manage specific supported targets
- it should not treat shared include files such as `system-auth` as the main
  integration point

That is why base auth targets and login targets are handled separately.

## Key Paths And Interfaces

| Path / interface | Role |
|---|---|
| `/etc/mykey/` | daemon-owned machine and auth state |
| `/etc/mykey/pin/<uid>/` | per-user sealed PIN state and lockout metadata |
| `/etc/mykey/auth/<uid>/` | per-user local-auth policy |
| `/etc/pam.d/` | MyKey-managed PAM target integration |
| `MYKEY_DATA_DIR` / `XDG_DATA_HOME/mykey` | user-owned secrets and provider metadata |
| `com.mykey.Daemon` on the system bus | privileged MyKey D-Bus surface |
| `org.freedesktop.secrets` on the session bus | Secret Service provider ownership when MyKey is enrolled |

## Current Auth Model

The current local-auth model is narrower than the final intended design.

What is live today:

- `pam_mykey.so` now uses daemon policy to choose between MyKey-managed Linux
  password fallback and an ordered local-auth chain
- daemon-owned local-auth policy exists
- biometric setup and backend selection scaffolding exist
- staged local-auth policy now represents biometrics, security key, and PIN as
  one coherent chain instead of one `primary_method`
- the current runtime can drive `biometric group -> security key -> pin`, with
  the biometric stage racing all configured providers and accepting first
  success
- the biometric verifier layer now runs upstream provider checks under explicit
  timeout/cancellation control so a stalled provider cannot block the MyKey
  chain indefinitely
- MyKey-managed PAM placement exists
- elevated MyKey management actions use a dedicated password-only PAM service through `mykey-elevated-auth`
- security-key management and live runtime flows now exist through
  `mykey-security-key`, `mykey-auth`, and a dedicated `pam_u2f` PAM service

What is not complete yet:

- live hardware security-key validation
- broader host-installed validation of biometric-first behavior across
  supported PAM surfaces beyond `sudo`, `polkit-1`, and opt-in
  `gdm-fingerprint`

So the current architecture should be read as:

- daemon-owned staged local auth is real
- biometrics now participate in the live `pam_mykey.so` runtime path, including
  the multi-provider first-success stage, and the current host validation now
  covers `sudo`, `polkit-1`, and opt-in `gdm-fingerprint`, but broader
  login-manager and distro-surface calibration is still incomplete
- security keys now participate in the live `pam_mykey.so` runtime path, but
  still need hardware validation and broader host-installed calibration

## Secret Service Model

The Secret Service model is intentionally explicit:

- package install places files on disk
- `mykey-migrate --enroll` performs provider takeover
- `mykey-migrate --unenroll` restores the previous provider

That rule exists because provider ownership is stateful and safety-sensitive.

Blind package removal should preserve MyKey state so recovery remains possible
by reinstalling and unenrolling.

## Setup And Packaging Model

MyKey is mid-pivot from script-driven installation to an Arch/AUR package
model.

The package should own:

- binaries
- PAM modules
- unit files
- D-Bus policy
- polkit actions
- `sysusers.d` and `tmpfiles.d` metadata

The package should not own:

- provider migration logic
- auth enrollment decisions
- login-manager takeover decisions
- destructive removal of user state

That means the intended operator flow is increasingly:

```text
package install
    -> mykey-daemon auto-started by package install
    -> run mykey-auth setup
    -> optionally run mykey-migrate --enroll
    -> optionally enable mykey-tray
```

## Transitional And Legacy Areas

The current architecture still contains some transitional elements:

- `mykey-daemon` still retains older browser-facing request surfaces and caller
  validation logic even though the browser bridge is no longer a product path
- `mykey-daemon` still has legacy `/tmp` logging behavior that should be
  removed
- the package and uninstall behavior is still being tightened around migration
  safety and user-state preservation
- biometric runtime now exists, but broader host-installed calibration is still
  pending

These are part of the current architecture picture and should not be ignored
when evaluating the system.

## Explicitly De-scoped Paths

These older paths are no longer part of the active architecture:

- `mykey-proxy`
- `mykey-host`
- extension-managed WebAuthn interception

Cross-platform passkeys remain future research and design work, not a current
runtime path in this architecture.
