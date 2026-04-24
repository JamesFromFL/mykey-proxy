# MyKey Threat Model

## Purpose

This document defines the current security model for MyKey as it exists today.
It is meant to track the code that is actually shipped, not older proxy-era
plans or future ideas.

This threat model covers:

- `mykey-daemon` as the privileged system trust anchor
- `mykey` as the top-level terminal routing surface
- `mykey-auth` and `pam_mykey.so` as the local-auth entrypoint
- `mykey-secrets` as the user-session Secret Service provider
- `mykey-migrate` as the explicit provider handoff tool
- service, D-Bus, polkit, PAM, and packaging behavior that changes security
  posture

This threat model does not cover the removed browser extension / native host
architecture, and it does not describe unimplemented passkey support as if
those paths already exist.

## Security Objectives

MyKey is currently trying to achieve five things:

1. Keep local-auth policy, PIN state, and privileged crypto operations under
   daemon control instead of user-process control.
2. Prevent untrusted local processes from invoking privileged daemon APIs as a
   different process or user.
3. Protect secret payloads at rest by storing TPM-sealed blobs rather than
   user-readable plaintext secret files.
4. Make MyKey-managed PAM takeover explicit and recoverable instead of brittle
   or destructive.
5. Make Secret Service provider handoff an explicit migration event rather than
   a package-manager side effect.

## Supported Security Baseline

MyKey's stricter requirements are not there for branding or aesthetics. They
exist because the platform is trying to move trust away from ad hoc user-space
state and into boundaries the system can actually enforce.

### UEFI and Secure Boot

MyKey treats Secure Boot as part of its supported security baseline because it
needs a trustworthy boot chain for TPM-backed protection to mean anything.

Why this matters:

- without a verified boot chain, an attacker can boot altered userspace or an
  alternate OS and try to coerce the machine into releasing protected state
- MyKey's design is intentionally trying to protect against "same hardware,
  wrong software state" problems, not just "same Linux user, wrong process"
- requiring Secure Boot makes the platform's "device-bound" claim much more
  honest

This is not just a dependency. It is part of the argument that MyKey should be
trusted to bind secrets and auth state to a known-good machine state instead of
to whatever userspace happens to be running.

### TPM 2.0

MyKey treats TPM2 as part of its intended security model because it wants
sealed, machine-bound protection rather than plain software-only local secret
storage.

Why this matters:

- daemon-owned PIN and secret payload handling are designed around TPM-backed
  sealing and unsealing helpers
- the TPM is what lets MyKey claim that sensitive state is bound to this device
  instead of being a plain copyable file
- without a TPM-backed design, MyKey would be much closer to a normal software
  keyring with extra steps

This is also why TPM presence is worth explaining to users rather than hand
waving away as "required for TPM sealing." The TPM is what turns MyKey from a
normal local secret store into a stronger device-bound protection model.

### systemd and the D-Bus system bus

MyKey relies on a long-running privileged daemon, service ownership, and D-Bus
sender credentials to enforce its trust boundary.

Why this matters:

- `mykey-daemon` is supposed to be the single privileged backend, not one more
  helper process in a pile of scripts
- systemd gives MyKey a stable service boundary and sandboxing surface
- the system bus gives MyKey sender PID and UID information that the daemon can
  validate instead of trusting caller-supplied metadata

This is how MyKey keeps privileged auth state out of random user-session
processes.

### Top-level CLI routing

MyKey now has a thin top-level `mykey` command.

Why this matters:

- it is the primary operator-facing discovery surface for installed MyKey tools
- it routes to the real component binaries instead of implementing privileged
  behavior itself
- it does not widen the daemon trust boundary on its own; the security
  boundary remains with the routed binaries and the daemon APIs they already
  use

### PAM and polkit

MyKey depends on PAM and polkit because it is deliberately integrating with the
system's local-auth model instead of trying to replace the whole thing.

Why this matters:

- PAM lets MyKey enter supported local-auth flows while still falling through
  safely when MyKey is absent or intentionally disabled at the PAM layer
- once MyKey is active for a supported target, normal Linux password fallback
  can stay inside MyKey instead of dropping through to downstream PAM modules
- PAM also gives MyKey a narrow dedicated password-only service for elevated
  management actions such as first-time PIN setup/reset and biometric changes
- polkit still matters for supported system auth surfaces such as `polkit-1`,
  but elevated MyKey management no longer depends on the broad generic polkit
  confirmation path
- using these native OS boundaries is more defensible than inventing a second
  parallel auth stack for everything

This is part of the design: MyKey wants to own its security-sensitive layer,
not every layer.

### Trusted package or build provenance

MyKey assumes the installed first-party binaries are coming from a trusted
package or trusted build source.

Why this matters:

- the daemon trusts specific MyKey frontends by exact basename plus D-Bus
  sender credentials
- MyKey also has a binary-integrity manifest path in its current model
- if the installed first-party binaries are already malicious, the rest of the
  local trust model starts from bad assumptions

This is why MyKey's package and install story matters to the security model and
not just to convenience.

## Protected Assets

The main assets MyKey is responsible for are:

- daemon-owned state under `/etc/mykey`
  - per-user sealed PIN state
  - per-user PIN attempt / lockout state
  - per-user local-auth policy
  - other daemon-owned auth metadata
- user-session Secret Service state under `MYKEY_DATA_DIR` or
  `XDG_DATA_HOME/mykey`
  - collection metadata
  - item metadata
  - provider handoff metadata
- PAM routing decisions in `/etc/pam.d`
- the system D-Bus surface exposed by `com.mykey.Daemon`
- session-bus ownership of `org.freedesktop.secrets`

MyKey does not currently treat user-session metadata as its only protection
boundary. The real secret payloads stored by `mykey-secrets` are sealed blobs,
so metadata exposure or tampering is not equivalent to plaintext secret
disclosure.

## Assumptions

MyKey depends on the following assumptions:

- root is trusted
- the kernel is trusted
- firmware and boot state are trusted enough for TPM-backed protection to mean
  anything
- the TPM is functioning correctly
- systemd, PAM, D-Bus, and polkit are functioning correctly
- first-party MyKey binaries are installed from a trusted package or build
  source

If those assumptions fail, MyKey's guarantees degrade with them.

## Attacker Model

The current model mainly considers these attacker classes:

- an unprivileged local process trying to call privileged daemon APIs directly
- a same-user desktop/session process trying to tamper with user-owned MyKey
  state
- a local attacker trying to brute-force the MyKey PIN
- operator or packaging mistakes that leave PAM or Secret Service ownership in
  a broken state
- a confused-deputy situation where one process claims another process's PID or
  user identity

The model is weaker against:

- a fully compromised logged-in desktop session
- root or kernel compromise
- malicious firmware or broken TPM behavior
- physical attacks on the machine or TPM

## Trust Boundaries

### `mykey-daemon`

`mykey-daemon` is the main privileged boundary in the current platform.

It runs as a dedicated system user, exposes `com.mykey.Daemon` on the system
bus, owns daemon-side auth policy and PIN state, and performs TPM-facing
sealing and unsealing operations.

If the daemon is compromised, MyKey's security model is largely compromised.

### Caller validation boundary

The daemon does not blindly trust caller-supplied PIDs.

For privileged requests it currently:

- resolves the D-Bus sender identity
- fetches sender PID and Unix UID from D-Bus credentials
- rejects the call if the supplied PID does not match the real sender PID
- restricts PIN and local-auth policy methods to trusted MyKey frontend
  basenames
- restricts per-user auth calls to the calling UID unless the caller is root

This is an important mitigation against simple spoofing, but it is not full
caller attestation. The daemon trusts installed first-party frontends by exact
basename and sender credentials; it does not perform code-signing or path
attestation for those binaries.

### PAM boundary

PAM consumers do not talk to the daemon directly. The path is:

`PAM consumer -> pam_mykey.so -> mykey-auth -> mykey-daemon`

This boundary exists to keep the PAM module thin and to avoid placing daemon
logic or secret-state handling directly in the PAM host process.

The intended security property here is:

- if MyKey is configured and succeeds, it should authenticate first
- if no MyKey PIN is configured yet, normal Linux password fallback should
  still be mediated by MyKey instead of bypassing it
- if MyKey is absent or intentionally disabled, PAM should fall through to the
  next method cleanly

### User-session Secret Service boundary

`mykey-secrets` is a user-session service, not a system daemon.

That means:

- its metadata lives in a user-owned private data directory
- it owns `org.freedesktop.secrets` only when explicitly enrolled
- it is trusted to act on the user's Secret Service state
- it is not the primary privileged boundary for auth policy or machine-owned
  state

MyKey relies on file permissions and sealed secret payloads here, not on the
fiction that same-user metadata is untouchable.

### Provider handoff boundary

Only one Secret Service provider should own `org.freedesktop.secrets` at a
time.

MyKey treats provider switching as an explicit action owned by
`mykey-migrate --enroll` and `mykey-migrate --unenroll`, not something that
should happen automatically during package install or package removal.

### Package and setup boundary

Package installation should place files on disk. Runtime ownership changes
should happen through explicit commands.

That separation matters because MyKey has security-sensitive transitions:

- taking over PAM targets
- taking over Secret Service ownership
- restoring the previous Secret Service provider

Those should not be implicit package-manager side effects.

## Trust Boundary Summary

| Boundary | Primary mechanism | Why it exists |
|---|---|---|
| local process -> `mykey-daemon` | D-Bus sender PID/UID checks plus trusted-caller restrictions | keep privileged daemon APIs from being callable by arbitrary local processes |
| PAM consumer -> `pam_mykey.so` -> `mykey-auth` | thin PAM module plus helper indirection | keep high-trust logic out of the PAM host process while preserving safe fallback only when MyKey is absent or intentionally disabled |
| user session -> `mykey-secrets` | private user data dir plus sealed secret payloads | let MyKey act as a session provider without pretending the whole user session is a privileged boundary |
| provider switch -> `mykey-migrate` | explicit enroll / unenroll ownership | prevent package install or removal from silently taking over or breaking Secret Service ownership |
| package install -> runtime setup | package payload vs setup-command split, with daemon bring-up as the only intended install-time side effect | keep destructive or high-risk transitions out of package-manager side effects while still leaving the auth backend ready for immediate setup |

## Threats And Current Mitigations

### Untrusted local process calls privileged daemon APIs

Threat:

- a local process calls `com.mykey.Daemon` directly and tries to impersonate
  another caller or user

Current mitigations:

- D-Bus sender PID and UID are resolved by the daemon
- the supplied PID must match the actual sender PID
- PIN and local-auth policy APIs are restricted to trusted MyKey frontend
  basenames
- per-user calls are bound to the caller's UID unless root is involved
- many privileged paths require an existing daemon session first

Residual risk:

- the daemon still retains older browser-oriented request surfaces and browser
  caller validation logic even though the extension and native host are no
  longer in project scope

### PIN brute force

Threat:

- repeated guesses against the MyKey PIN

Current mitigations:

- PIN state is owned by the daemon instead of CLI or PAM code
- the sealed PIN verifier lives under `/etc/mykey/pin/<uid>/`
- attempt state is tracked per user
- cooldown and lockout behavior is enforced in the daemon
- writes are atomic

Residual risk:

- MyKey still depends on the daemon boundary, host integrity, and TPM trust

### Stale or broken PAM takeover

Threat:

- MyKey is added to PAM and later disappears, becomes unconfigured, or is only
  partially removed

Current mitigations:

- MyKey writes explicit managed blocks instead of asking the user to hand-edit
  PAM files
- base auth targets and login targets are handled separately
- login takeover is explicit and opt-in
- `pam_mykey.so` only uses `PAM_IGNORE` for safe absence / disabled cases; when
  normal password fallback is allowed, it stays on a MyKey-managed password
  path instead of falling through to downstream password modules
- MyKey-managed PAM entries can be written with a leading `-auth` style entry
  so a missing module file does not become a hard failure

Residual risk:

- PAM integration is safety-sensitive and still deserves careful manual review
  on every expansion of supported targets

### User-session tampering with MyKey Secret Service state

Threat:

- a same-user process edits MyKey metadata files or tries to corrupt Secret
  Service state

Current mitigations:

- user-session state lives in a private user data directory
- directories are created with private permissions
- collection, item, and alias files use atomic replace behavior
- secret payloads are stored as sealed blobs, not plaintext secrets

Residual risk:

- same-user processes can still corrupt metadata, cause denial of service, or
  interfere with provider state
- MyKey does not claim to fully defend a compromised logged-in desktop session
  from itself

### Silent provider lockout during uninstall or provider switching

Threat:

- the user removes MyKey or switches providers without restoring the previous
  Secret Service owner

Current mitigations:

- `mykey-migrate` owns enroll and unenroll
- package removal is being shaped to preserve state by default
- reinstall plus `mykey-migrate --unenroll` remains a recovery path after a
  blind uninstall
- MyKey no longer assumes package install/remove should perform live provider
  handoff implicitly

Residual risk:

- a user can still lock themselves out of secret access temporarily by removing
  MyKey without running the explicit unenroll flow first

### Invalid or unsafe local-auth policy

Threat:

- the local-auth policy is left in an impossible or unsafe state

Current mitigations:

- daemon-owned local-auth policy is normalized on read
- biometric policy without a PIN fallback is sanitized back to a safe state
- the daemon computes effective policy outputs from live state, so missing-PIN
  or contradictory policy combinations are collapsed back to safe behavior
- daemon-owned effective policy now exposes an ordered auth chain plus active
  biometric backends instead of a single `primary_method`
- effective policy now explicitly distinguishes when normal password fallback is
  allowed, when elevated MyKey actions still require password, and what the
  biometric attempt ceiling is
- biometric runtime verification now runs under explicit timeout/cancellation
  control so a stalled provider cannot hold the MyKey chain open indefinitely
- biometric setup is explicitly tied to MyKey policy management instead of
  hand-edited PAM changes
- elevated MyKey actions now go through a dedicated password-only PAM service
  instead of inheriting fingerprint or other broad shared PAM stacks

Residual risk:

- biometric runtime auth now exists, but its host-installed behavior still
  needs calibration across the supported PAM surfaces MyKey manages
- security-key runtime auth now exists, but it still needs real hardware
  validation and broad host-installed calibration

### Over-broad package or setup behavior

Threat:

- installation logic performs too many privileged runtime actions and leaves the
  system in a brittle or confusing state

Current mitigations:

- MyKey is moving toward a package-driven model instead of a giant imperative
  installer being the product boundary
- package payload, explicit setup, and runtime management are being split into
  separate concerns
- tray startup is now optional instead of forced

Residual risk:

- packaging and install/remove behavior are still in transition

## Current Security Debt

These are known current weaknesses or unfinished areas, not hypothetical future
concerns:

- `mykey-daemon` still logs to `/tmp/mykey-daemon.log`, and the service unit
  still allows `/tmp` writes for that reason
- the polkit action for `com.mykey.authenticate` is still broader than an
  active-local-session-only model because it uses `auth_self` for `allow_any`,
  `allow_inactive`, and `allow_active`
- legacy browser-facing request methods and browser caller validation still
  exist in the daemon even though the browser bridge has been removed from
  release scope
- biometric runtime auth now shells out to upstream provider verification
  commands and still needs broad host-installed calibration, especially across
  display-manager and login-adjacent PAM surfaces
- security-key runtime auth now shells out through a dedicated `pam_u2f` helper
  path and still needs real-key validation on supported hosts
- package-safe install/remove behavior and provider teardown messaging are still
  being tightened

## Out Of Scope

MyKey does not currently try to defend against:

- malicious root
- kernel compromise
- firmware compromise
- physical attacks on the TPM or motherboard
- a fully compromised logged-in desktop session acting as the legitimate user
- browser platform-authenticator integration that is no longer in release scope

## Maintenance Rule

This file is meant to be the in-repo source of truth for the current MyKey
trust model.

If the daemon boundary, PAM model, Secret Service ownership model, or package
and setup behavior change, this document should be updated in the same work,
not later.
