# WebAuthn Proxy
![WebAuthn Proxy](assets/AuthnProxyLogoCircle.png)

Linux has no built-in way to satisfy modern browser security checks that Windows and Mac handle automatically. This project fills that gap — it lets Chrome on Linux use your system's built-in security hardware to handle authentication requests that would otherwise just fail.

## How It Works

When a website or browser extension asks for secure authentication, the proxy intercepts that request before it fails. It passes the request to a background service running on your machine. That service verifies you are physically present using your Linux login credentials, then uses your machine's security chip to cryptographically sign the response. The approval goes back to the browser — no passwords sent over the network, everything stays on your machine.

## System Requirements

- Linux (any major distribution with systemd)
- Chrome or Chromium browser
- TPM 2.0 chip — required. Most computers made after 2016 have one. Check with: `cat /sys/class/tpm/tpm0/tpm_version_major`
- Secure Boot enabled in your BIOS/UEFI settings
- Rust toolchain — install from [rustup.rs](https://rustup.rs)
- tpm2-tools — install via your package manager (`pacman -S tpm2-tools` / `apt install tpm2-tools`)
- PAM development libraries — `libpam0g-dev` (Debian/Ubuntu) or `pam` (Arch)
- D-Bus — included in all major Linux distributions by default
- systemd — required for the background service

## What's Inside

- **Browser Extension** — watches for authentication requests in Chrome and routes them into the proxy instead of letting them fail
- **Native Host** — the bridge between the browser and your system, translates browser messages into system calls
- **Daemon** — the always-running background service that handles the actual security work: verifying you, protecting your keys, and signing responses
- **Installer** — one script that builds everything, sets up the service, and walks you through the final steps

## Disclaimer

This project was built by a cybersecurity student as a learning exercise in platform security and authentication. It was born out of a personal need — Linux had no working solution for a problem I ran into daily, so I built one.

This project is in early development. The code has not been audited. There are known unfinished components — TPM2 hardware key sealing is currently stubbed with a software fallback, and MOK binary signing is not yet implemented.

Installation and daily use is not recommended at this stage. If you choose to install and use this software, you do so entirely at your own risk.

I do not guarantee the safety, security, or integrity of any platform keys, credentials, or authentication operations performed by this software. Platform key security is serious — treat it accordingly.

Parts of this project were developed with the assistance of AI tools including Claude by Anthropic. All architectural decisions, security design, and final implementation were reviewed and directed by a human. AI-assisted code should always be treated with the same scrutiny as any other untrusted code — read it, understand it, and verify it before running it on your system.

If you find a security issue please open a GitHub issue or contact me directly before disclosing publicly.

## Project Status

### Done
- Chrome MV3 extension with WebAuthn request interception
- Native messaging host — browser to system bridge
- Persistent background daemon with D-Bus communication
- End-to-end AES-256-GCM encrypted communication between all components
- HMAC request signing to prevent message tampering
- Replay attack protection with sequence numbers and timestamp windows
- Process ancestry verification — only a real Chrome process can talk to the daemon
- PAM authentication gate — your Linux credentials must pass before any key is touched
- P-256 cryptographic key generation and ECDSA signing
- Credential storage and lifecycle management
- Hardened systemd service with strict permissions and memory protections
- Install script with hardware prerequisite checks

### In Progress
- TPM2 hardware key sealing with PCR boot-state binding — software fallback is active in the meantime
- MOK binary signing so Secure Boot verifies the installed binaries
- Secure Boot hard enforcement — currently a warning, will become a hard exit

### Planned — Linux Platform
- System tray app showing proxy status and enrolled credentials
- Credential management UI
- Full TPM2 integration with PCR 0, 7, and 11 binding
- Fingerprint authentication via fprintd
- Face recognition via Howdy

### Planned — Mobile Bridge

Pair your phone with your Linux machine. When a site requests authentication your phone receives the request, you approve it using Face ID, fingerprint, or PIN, and the signed response comes back to your browser automatically. Works on iOS and Android. Uses local network when available, encrypted relay as fallback.

## Installation

1. Clone the repo: `git clone https://github.com/JamesFromFL/webauthn-proxy`
2. Run the installer: `sudo ./scripts/install.sh`
3. Load the extension in Chrome: go to `chrome://extensions` → enable Developer mode → Load unpacked → select the `extension/` folder
4. Copy your extension ID from `chrome://extensions` and run the `sed` command the installer printed
5. Start the daemon: `systemctl start webauthn-proxy-daemon`
6. Test it — try unlocking a NordPass TOTP code on Linux

## Logs and Troubleshooting

- Daemon logs: `journalctl -u webauthn-proxy-daemon`
- Native host logs: `/tmp/webauthn-proxy-host.log`
- Extension logs: open Chrome DevTools on the background service worker from `chrome://extensions`

## License

MIT — JamesFromFL, 2026
