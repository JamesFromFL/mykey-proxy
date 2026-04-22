# MyKey

<p align="center">
  <img src="assets/mykey-logo-stylized.png" width="500" alt="MyKey logo">
</p>

<p align="center">
  <strong>Windows Hello–style authentication for Linux.</strong><br>
  Hardware-backed secrets, local authentication, and a cleaner security experience built around TPM2, Secure Boot, and native Linux tools.
</p>

---

## 👋 What Is MyKey?

MyKey is a Linux security platform that brings authentication, secret storage, and secure local workflows together into one system.

Instead of juggling separate tools for browser authentication, desktop keyrings, local unlock, and future PIN or biometric flows, MyKey is designed to make those pieces feel like one coherent experience.

At a high level, MyKey aims to give Linux users:

- 🔐 hardware-backed authentication
- 🧠 TPM-sealed secret storage
- 🗝️ a Secret Service provider
- 🔄 a migration path from existing keyrings
- 🔑 future cross-platform passkey and authenticator support
- 🔢 a Windows Hello–style local PIN path

**Simple to use. Serious about security. Built for Linux first.**

---

## ✨ Why MyKey?

Linux already has strong security building blocks. The problem is that they are often split across different tools, desktop environments, and workflows.

MyKey tries to make that experience feel more unified.

The goal is not to hide how security works. The goal is to make the important parts easier to use without turning them into mystery boxes.

If Windows Hello made local authentication feel modern and straightforward, MyKey is trying to bring that same spirit to Linux using open tools and real hardware protections.

---

## 🧩 Components

MyKey is made up of focused modules that work together.

The local-auth pieces are now grouped under the `mykey-auth/` subtree so the
repo layout stays readable as PIN, PAM, and biometric support grow.

### ⚙️ `mykey-daemon`
The security core of the project.

It handles:
- TPM interaction
- authentication decisions
- caller validation
- secure policy checks
- privileged operations used by the rest of MyKey

### 🖥️ `mykey-tray`
An optional tray app for status and quick interaction.

It is managed through:
- `mykey-tray enable`
- `mykey-tray disable`
- `mykey-tray status`

### 🗝️ `mykey-secrets`
A Secret Service provider backed by MyKey’s hardware-focused design.

This is intended to act as a secure alternative to traditional software-only keyring providers.

### 🔄 `mykey-migrate`
A migration tool that can move secrets between MyKey and existing Secret Service providers such as GNOME Keyring, KWallet, and KeePassXC.

### 🔢 `mykey-pin`
An optional local PIN-based authentication path.

The long-term goal is a Windows Hello–style local authenticator for Linux:
- device-local
- optional
- TPM-aware
- separate from the user’s Unix password

### 🧩 `mykey-auth`
The local-auth subtree that groups MyKey’s system authentication pieces.

It currently contains:
- `mykey-pam` for the PAM-facing local auth layer
- `mykey-pin` for PIN management and fallback auth
- `mykey-biometrics` as the planned home for biometric setup and policy

Current Phase A management commands:
- `mykey-pin set` to configure the MyKey PIN policy
- `sudo mykey-auth enable` to place MyKey first for supported elevation prompts and then optionally hand off to login setup
- `sudo mykey-auth biometrics` to drive biometric enrollment, provider setup, and active backend selection
- `sudo mykey-auth login` to opt into MyKey-managed login and unlock PAM targets
- `sudo mykey-auth disable` to remove the base MyKey-managed PAM entries and then walk login teardown
- `sudo mykey-auth logout` to remove MyKey-managed login and unlock PAM targets
- `mykey-auth status` to inspect local-auth policy plus base/login PAM integration state

### 🎛️ `mykey-manager`
A planned GUI frontend for managing MyKey features from one place.

---

## 🛡️ Security Model

MyKey is designed around a few clear ideas.

### Hardware should matter
Secrets and security-sensitive operations should be tied to the machine through TPM2 wherever possible.

### Local authentication should stay local
MyKey PIN is meant to be a local device authenticator, not a network password and not something that should leave the machine.

### Boot trust matters
MyKey relies on a known-good boot chain. That is why Secure Boot, TPM measurements, and predictable boot configuration are part of the design.

### Convenience and recovery are not the same thing
Convenient daily authentication and elevated security actions are different categories.

MyKey is moving toward this model:
- 👆 normal local auth: biometrics or MyKey PIN
- 🔐 elevated actions: stronger verification for setup, reset, and recovery flows

---

## 🖥️ Supported System

MyKey is intentionally opinionated.

It is currently designed for a security-focused Linux setup with:

### 🔩 Required hardware
- TPM 2.0
- UEFI firmware
- Secure Boot enabled

### ⚙️ Required system stack
- systemd
- systemd-boot
- sbctl
- UKI-based boot flow
- PAM
- D-Bus
- polkit

### ❗ Why the requirements are strict
MyKey seals data against platform state. That only works reliably when the boot chain and local trust model are predictable.

If the platform configuration drifts too far from the expected model, sealed data may fail to unlock. That is not a bug in the security model. That is part of how the protection works.

---

## 🚧 Current Project Status

MyKey is in active development and moving toward its first release.

The core platform is no longer just an idea. Several major pieces are already working together, including TPM-backed operations, Secret Service support, secret migration, and daemon-owned local authentication.

### ✅ What is working now
- TPM-backed daemon architecture
- Secret Service provider support through `mykey-secrets`
- bidirectional secret migration with `mykey-migrate`
- Secure Boot and platform prerequisite validation in the installer
- per-user MyKey PIN foundation with daemon-backed verification
- PAM-backed MyKey PIN authentication flow
- strong-auth gating for PIN setup and reset

### 🛠️ What is being finished now
These are the main items still being refined before MyKey feels ready for a first public release:

- final `mykey-pin` policy and user experience
- biometric-first local authentication with PIN fallback
- re-scoping passkey work around a native cross-platform authenticator path
- cleanup of remaining brute-force behavior so it only affects MyKey PIN flows
- packaging and release polish
- clearer documentation for setup, fallback, and supported system requirements
- continued work on `mykey-manager`

### 📌 What this means today
MyKey already has real working subsystems, but the project is still in the release-hardening phase.

It is best described as:
- functional in important areas
- still evolving in policy and UX
- not yet production-ready

---

## 🗺️ Roadmap

The roadmap is about where MyKey goes after the current release-hardening work is finished.

### 📦 Near-term
These are the first-release and shortly-after-release goals:

- complete `mykey-manager`
- finalize MyKey PIN policy and local auth behavior
- add biometric-first local auth using supported Linux biometric frontends
- improve packaging and installation experience
- define the first cross-platform authenticator and passkey storage path
- publish clearer user-facing documentation
- prepare AUR packaging

### 🔧 Mid-term
These are the next meaningful platform improvements after the first release is stable:

- expand recovery options for MyKey PIN
- explore optional TOTP-based recovery flows
- improve onboarding and management through the GUI
- refine desktop integration and service management
- research legitimate Linux platform-authenticator integration as a long-term browser patch path, not a release feature
- continue hardening and validation across supported environments

### 🚀 Long-term
These are the bigger platform goals that move MyKey closer to a full Windows Hello–style Linux experience:

- evolve MyKey PIN beyond the current sealed-verifier model toward a stronger TPM-backed local auth design
- broaden supported authentication flows while keeping them local and hardware-aware
- support device-bound cross-platform passkeys without turning MyKey into a syncing password manager
- improve distribution options beyond source install
- revisit Firefox support if browser platform support becomes practical
- continue building toward a more complete Linux authentication platform, not just a collection of tools

---

## 📥 Installation

```bash
git clone https://github.com/JamesFromFL/mykey
cd mykey
./scripts/install.sh
```

The installer currently handles:
- TPM validation
- Secure Boot validation
- signed boot file checks
- build and install steps
- MyKey secret migration
- final health checks

> ⚠️ The installer is still evolving. Expect some changes while the first release is being prepared.

---

## 🗑️ Uninstall

```bash
./scripts/uninstall.sh
```

This removes the installed MyKey components and restores your previous Secret Service setup when applicable.

---

## 🧪 Testing

Current real-world testing has focused on:

### 🗝️ Secret management
- migration to and from GNOME Keyring
- KWallet and KeePassXC readiness handling

### 🔢 Local authentication
- daemon-backed MyKey PIN flows
- helper-backed PAM authentication
- strong-auth gating for setup and reset actions

Testing coverage is improving, but this is still an active project and not a completed security product.

---

## ⚠️ Important Warning

MyKey is experimental software.

That means:

- it has not been formally audited
- it is still changing quickly
- it should not be treated as production-ready security software yet

If you use it, do so carefully and with the understanding that the project is still being hardened.

If you find a security issue, please report it responsibly.

---

## 🤖 AI Disclosure

Parts of this project were developed with the help of AI tools.

Architecture direction, review, validation, and final decisions remain human-driven.

---

## 📜 License

MIT — JamesFromFL, 2026
