#!/usr/bin/env bash
# install.sh — MyKey full installer
# Handles: prerequisite verification, build, install, extension setup, and health check
# Run as normal user: ./scripts/install.sh (will prompt for sudo when needed)

if [[ $EUID -eq 0 ]]; then
    echo "Do not run this script as root. Run as your normal user: ./scripts/install.sh"
    exit 1
fi

set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────
PASS="✓"; FAIL="✗"; WARN="⚠"; INFO="→"
ok()    { echo "  ${PASS} $*"; }
fail()  { echo "  ${FAIL} $*" >&2; }
warn()  { echo "  ${WARN} $*"; }
info()  { echo "  ${INFO} $*"; }
die()   { echo ""; echo "FATAL: $*" >&2; exit 1; }
confirm() {
    local prompt="$1"
    local reply
    echo ""
    read -rp "  ${prompt} [y/N] " reply
    echo ""
    [[ "${reply,,}" == "y" || "${reply,,}" == "yes" ]]
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FAILED=0
PRECHECK_ERRORS=()

requirement_fail() {
    fail "$*"
    PRECHECK_ERRORS+=("$*")
}

enforce_prechecks() {
    if [[ ${#PRECHECK_ERRORS[@]} -eq 0 ]]; then
        return
    fi

    echo ""
    echo "  MyKey cannot be installed on this system until all required security"
    echo "  prerequisites are met. This is intentional and part of MyKey's"
    echo "  security design."
    echo ""
    echo "  Failed requirement(s):"
    for err in "${PRECHECK_ERRORS[@]}"; do
        echo "    - ${err}"
    done
    echo ""
    die "Resolve the requirement(s) above and run ./scripts/install.sh again."
}

# ── Cargo discovery ───────────────────────────────────────────────────────────
find_cargo() {
    local user_home
    if [[ -n "${SUDO_USER:-}" ]]; then
        user_home=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
    else
        user_home="${HOME}"
    fi
    for candidate in \
        "${user_home}/.cargo/bin/cargo" \
        "${user_home}/.rustup/toolchains/"*/bin/cargo
    do
        [[ -x "${candidate}" ]] && echo "${candidate}" && return 0
    done
    for home in /home/*/; do
        for candidate in \
            "${home}.cargo/bin/cargo" \
            "${home}.rustup/toolchains/"*/bin/cargo
        do
            [[ -x "${candidate}" ]] && echo "${candidate}" && return 0
        done
    done
    for candidate in /usr/local/bin/cargo /usr/bin/cargo; do
        [[ -x "${candidate}" ]] && echo "${candidate}" && return 0
    done
    return 1
}

CARGO="$(find_cargo)" || die "cargo not found. Install Rust from rustup.rs"
export PATH="$(dirname "${CARGO}"):${PATH}"
info "Using cargo: ${CARGO}"

# ── Real user (for tray service and home-dir operations) ─────────────────────
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# ── Distro detection ──────────────────────────────────────────────────────────
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}
DISTRO="$(detect_distro)"
info "Detected distribution: ${DISTRO}"

# ── Package manager helper ────────────────────────────────────────────────────
install_package() {
    local pkg="$1"
    case "${DISTRO}" in
        arch|manjaro|endeavouros)
            sudo pacman -S --noconfirm "${pkg}" ;;
        ubuntu|debian|linuxmint|pop)
            sudo apt-get install -y "${pkg}" ;;
        fedora)
            sudo dnf install -y "${pkg}" ;;
        opensuse*|sles)
            sudo zypper install -y "${pkg}" ;;
        *)
            die "Unknown distro '${DISTRO}' — please install '${pkg}' manually and re-run" ;;
    esac
}

echo ""
echo "  This installer requires sudo for system-level operations."
echo "  You may be prompted for your password."
echo ""
sudo -v || die "sudo authentication failed — cannot continue"
# Keep sudo alive in the background for the duration of the script
while true; do sudo -n true; sleep 50; kill -0 "$$" || exit; done 2>/dev/null &
SUDO_KEEPALIVE_PID=$!
trap 'kill "${SUDO_KEEPALIVE_PID}" 2>/dev/null' EXIT

# ════════════════════════════════════════════════════════════════════════════
# PHASE 1 — SECURE BOOT
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 1 — Secure Boot"
echo "════════════════════════════════════════════════════════════"

detect_secure_boot_state() {
    # Primary: read raw EFI variable — most reliable across all tools
    local sb_var val
    sb_var="$(find /sys/firmware/efi/efivars -name 'SecureBoot-*' 2>/dev/null | head -1)"
    if [[ -n "${sb_var}" ]]; then
        # The EFI variable is 5 bytes: 4 attribute bytes + 1 value byte
        # Value byte: 1 = enabled, 0 = disabled
        val="$(od -An -tu1 "${sb_var}" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' | tail -1)"
        if [[ "${val}" == "1" ]]; then
            echo "enabled"
            return
        fi
    fi

    # Check Setup Mode via EFI variable
    local sm_var sm_val
    sm_var="$(find /sys/firmware/efi/efivars -name 'SetupMode-*' 2>/dev/null | head -1)"
    if [[ -n "${sm_var}" ]]; then
        sm_val="$(od -An -tu1 "${sm_var}" 2>/dev/null | tr -s ' ' '\n' | grep -v '^$' | tail -1)"
        if [[ "${sm_val}" == "1" ]]; then
            echo "setup_mode"
            return
        fi
    fi

    # Secondary: sbctl if available
    if command -v sbctl &>/dev/null; then
        local status
        status="$(sbctl status 2>/dev/null || true)"
        if echo "${status}" | grep -qiE "secure boot.*enabled|enabled.*secure boot"; then
            echo "enabled"; return
        elif echo "${status}" | grep -qiE "setup mode.*enabled|enabled.*setup mode"; then
            echo "setup_mode"; return
        elif echo "${status}" | grep -qiE "secure boot.*disabled|disabled.*secure boot"; then
            echo "disabled"; return
        fi
    fi

    # Tertiary: mokutil
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state="$(mokutil --sb-state 2>/dev/null || true)"
        echo "${sb_state}" | grep -q "SecureBoot enabled" && echo "enabled" && return
        echo "disabled"
        return
    fi

    echo "disabled"
}

SB_STATE="$(detect_secure_boot_state)"

case "${SB_STATE}" in
    enabled)
        ok "Secure Boot is enabled"
        ;;
    setup_mode)
        requirement_fail "Secure Boot is in Setup Mode. Full Secure Boot enforcement is required."
        ;;
    disabled)
        requirement_fail "Secure Boot is disabled."
        ;;
    *)
        requirement_fail "Secure Boot state could not be determined."
        ;;
esac

# ════════════════════════════════════════════════════════════════════════════
# PHASE 2 — TPM2
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 2 — TPM2"
echo "════════════════════════════════════════════════════════════"

if [[ -c /dev/tpm0 && -c /dev/tpmrm0 ]]; then
    ok "TPM2 device present"

    if ! command -v tpm2_getcap &>/dev/null; then
        warn "tpm2-tools not installed — installing..."
        install_package tpm2-tools
    fi

    if tpm2_getcap properties-fixed &>/dev/null; then
        ok "TPM2 is responsive"
    else
        requirement_fail "TPM2 device is present but not responding."
    fi
else
    requirement_fail "TPM2 device nodes /dev/tpm0 and /dev/tpmrm0 were not found."
fi

# ════════════════════════════════════════════════════════════════════════════
# PHASE 3 — DETECT BOOT ENVIRONMENT
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 3 — Boot Environment Detection"
echo "════════════════════════════════════════════════════════════"

detect_esp() {
    local esp
    esp="$(bootctl status 2>/dev/null | grep -i "ESP:" | awk '{print $2}' | head -1)"
    if [[ -n "${esp}" && -d "${esp}" ]]; then
        echo "${esp}"
        return 0
    fi
    for mp in /efi /boot/efi /boot; do
        if mountpoint -q "${mp}" 2>/dev/null; then
            if [[ -d "${mp}/EFI" ]]; then
                echo "${mp}"
                return 0
            fi
        fi
    done
    return 1
}

ESP="$(detect_esp || true)"
if [[ -n "${ESP}" ]]; then
    ok "EFI System Partition: ${ESP}"
else
    requirement_fail "EFI System Partition could not be detected."
fi

BOOTLOADER="unknown"
if [[ -n "${ESP}" && ( -f "${ESP}/EFI/systemd/systemd-bootx64.efi" || \
   -f "${ESP}/EFI/systemd/systemd-bootaa64.efi" ) ]]; then
    BOOTLOADER="systemd-boot"
    ok "Bootloader: systemd-boot"
elif [[ -n "${ESP}" && ( -f "${ESP}/EFI/grub/grubx64.efi" || \
     -f "${ESP}/EFI/grub2/grubx64.efi" ) ]] || \
     command -v grub-install &>/dev/null || \
     command -v grub2-install &>/dev/null; then
    BOOTLOADER="grub"
    requirement_fail "Bootloader is GRUB. MyKey currently requires systemd-boot."
else
    requirement_fail "Bootloader could not be detected as systemd-boot."
    BOOTLOADER="unknown"
fi

FILES_TO_SIGN=()

should_exclude() {
    local f="${1,,}"
    [[ "${f}" =~ /microsoft/ ]] && return 0
    [[ "${f}" =~ /windows/ ]] && return 0
    [[ "${f}" =~ bootmgr ]] && return 0
    [[ "${f}" =~ memtest ]] && return 0
    [[ "${f}" =~ recovery ]] && return 0
    return 1
}

detect_files_to_sign() {
    info "Scanning for required signed EFI files..."

    if [[ -z "${ESP}" || "${BOOTLOADER}" != "systemd-boot" ]]; then
        return
    fi

    for f in \
        "${ESP}/EFI/systemd/systemd-bootx64.efi" \
        "${ESP}/EFI/systemd/systemd-bootaa64.efi" \
        "${ESP}/EFI/BOOT/BOOTX64.EFI" \
        "${ESP}/EFI/BOOT/bootx64.efi"
    do
        if [[ -f "${f}" ]]; then
            if should_exclude "${f}"; then
                warn "Auto-excluded: ${f}"
            else
                FILES_TO_SIGN+=("${f}")
            fi
        fi
    done

    for f in "${ESP}/EFI/Linux/"*.efi; do
        if [[ -f "${f}" ]]; then
            if should_exclude "${f}"; then
                warn "Auto-excluded (Windows/Microsoft file): ${f}"
            else
                FILES_TO_SIGN+=("${f}")
            fi
        fi
    done

    for dir in \
        "${ESP}/EFI/arch" \
        "${ESP}/EFI/ubuntu" \
        "${ESP}/EFI/fedora" \
        "${ESP}/EFI/opensuse"
    do
        for f in "${dir}/"*.efi; do
            if [[ -f "${f}" ]]; then
                if should_exclude "${f}"; then
                    warn "Auto-excluded (Windows/Microsoft file): ${f}"
                else
                    FILES_TO_SIGN+=("${f}")
                fi
            fi
        done
    done

    # Deduplicate by backing file identity first, then by literal path.
    # Some ESPs expose the same EFI binary under multiple case variants
    # (for example BOOTX64.EFI and bootx64.efi) that resolve to the same inode.
    local -A seen
    local -A seen_inode
    local deduped=()
    local f
    for f in "${FILES_TO_SIGN[@]:-}"; do
        local inode_key=""
        if [[ -e "${f}" ]]; then
            inode_key="$(stat -Lc '%d:%i' "${f}" 2>/dev/null || true)"
        fi
        if [[ -n "${inode_key}" && -n "${seen_inode[${inode_key}]:-}" ]]; then
            continue
        fi
        if [[ -z "${seen[${f}]:-}" ]]; then
            seen["${f}"]=1
            if [[ -n "${inode_key}" ]]; then
                seen_inode["${inode_key}"]=1
            fi
            deduped+=("${f}")
        fi
    done
    FILES_TO_SIGN=()
    for f in "${deduped[@]:-}"; do
        FILES_TO_SIGN+=("${f}")
    done
}

detect_files_to_sign

if [[ ${#FILES_TO_SIGN[@]} -gt 0 ]]; then
    info "Required signed EFI files:"
    for f in "${FILES_TO_SIGN[@]}"; do
        echo "      ${f}"
    done
else
    requirement_fail "No required EFI files were found to verify."
fi

verify_required_efi_files() {
    if [[ ${#FILES_TO_SIGN[@]} -eq 0 ]]; then
        return
    fi

    if ! command -v sbctl &>/dev/null; then
        requirement_fail "sbctl is required to verify Secure Boot file signatures."
        return
    fi

    echo ""
    info "Checking required EFI files in sbctl..."
    local file_db verify_out signed_count
    file_db="$(sudo sbctl list-files 2>/dev/null || true)"
    for f in "${FILES_TO_SIGN[@]}"; do
        if printf '%s\n' "${file_db}" | grep -Fq "${f}"; then
            ok "Enrolled: ${f}"
        else
            requirement_fail "Required EFI file is not enrolled in sbctl: ${f}"
        fi
    done

    echo ""
    info "Verifying EFI signatures..."
    verify_out="$(sudo sbctl verify 2>&1 || true)"
    signed_count=$(printf '%s\n' "${verify_out}" | grep -c "✓" || true)

    if [[ "${signed_count}" -lt "${#FILES_TO_SIGN[@]}" ]]; then
        requirement_fail "sbctl verify reported ${signed_count} signed EFI file(s), fewer than the ${#FILES_TO_SIGN[@]} required file(s)."
    else
        ok "Required EFI files appear signed."
    fi
}

verify_required_efi_files
enforce_prechecks

# ════════════════════════════════════════════════════════════════════════════
# PHASE 4 — BUILD AND INSTALL
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 4 — Build and Install"
echo "════════════════════════════════════════════════════════════"

DAEMON_BINARY="mykey-daemon"
TRAY_BINARY="mykey-tray"
SECRETS_BINARY="mykey-secrets"
PIN_BINARY="mykey-pin"
PIN_HELPER_BINARY="mykey-pin-auth"
AUTH_BINARY="mykey-auth"
DAEMON_DEST="/usr/local/bin/${DAEMON_BINARY}"
TRAY_DEST="/usr/local/bin/${TRAY_BINARY}"
SECRETS_DEST="/usr/local/bin/${SECRETS_BINARY}"
PIN_DEST="/usr/local/bin/mykey-pin"
PIN_HELPER_DEST="/usr/local/bin/mykey-pin-auth"
AUTH_DEST="/usr/local/bin/${AUTH_BINARY}"
PIN_SO_DEST="/usr/lib/security/mykeypin.so"
AUTH_SO_DEST="/usr/lib/security/pam_mykey.so"
PIN_DIR="/etc/mykey/pin"
LOCAL_AUTH_DIR="/etc/mykey/auth"
SYSTEMD_UNIT_SRC="${REPO_ROOT}/scripts/mykey-daemon.service"
TRAY_SERVICE_SRC="${REPO_ROOT}/scripts/mykey-tray.service"
SECRETS_SERVICE_SRC="${REPO_ROOT}/scripts/mykey-secrets.service"
SECRETS_DBUS_CONF_SRC="${REPO_ROOT}/scripts/org.freedesktop.secrets.conf"
WEBAUTHN_DIR="/etc/mykey"
CREDENTIAL_DIR="${WEBAUTHN_DIR}/credentials"
KEY_DIR="${WEBAUTHN_DIR}/keys"
SECRETS_DIR="${WEBAUTHN_DIR}/secrets"
TRUSTED_HASHES="${WEBAUTHN_DIR}/trusted-binaries.json"
POLKIT_POLICY="/usr/share/polkit-1/actions/com.mykey.authenticate.policy"
SYSTEMD_UNIT="/etc/systemd/system/mykey-daemon.service"
DAEMON_USER="mykey"
# ── 4.1 Create dedicated system user ─────────────────────────────────────
echo ""
info "Ensuring system user '${DAEMON_USER}' exists..."
if id "${DAEMON_USER}" &>/dev/null; then
    ok "User '${DAEMON_USER}' already exists."
else
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin "${DAEMON_USER}"
    ok "Created system user '${DAEMON_USER}'."
fi
# Add to tss group so the daemon can access TPM2 device nodes
sudo usermod -aG tss "${DAEMON_USER}" 2>/dev/null || true

# Install sudoers rule so the daemon can run pkcheck as root (polkit
# cross-identity checks require uid 0)
echo "==> Installing sudoers rule for polkit check..."
sudo tee /etc/sudoers.d/mykey > /dev/null << 'EOF'
# Allow mykey daemon to run pkcheck as root for user presence verification
mykey ALL=(root) NOPASSWD: /usr/bin/pkcheck
EOF
sudo chmod 0440 /etc/sudoers.d/mykey
ok "Sudoers rule installed."

# ── 4.2 Build daemon ──────────────────────────────────────────────────────
echo ""
info "Building ${DAEMON_BINARY} (release)..."
cd "${REPO_ROOT}/mykey-daemon"
RUSTFLAGS="-A warnings" "${CARGO}" build --features tpm2 --release
ok "Build complete: ${DAEMON_BINARY}"

# ── 4.3 Install binaries ──────────────────────────────────────────────────
echo ""
info "Installing binaries..."
sudo install -m 0755 "${REPO_ROOT}/mykey-daemon/target/release/${DAEMON_BINARY}" "${DAEMON_DEST}"
ok "${DAEMON_DEST}"

# ── 4.5 Create /etc/mykey/ directory structure ───────────────────
echo ""
info "Creating ${WEBAUTHN_DIR}/ directories..."
sudo install -d -m 0700 -o "${DAEMON_USER}" "${WEBAUTHN_DIR}"
sudo install -d -m 0700 -o "${DAEMON_USER}" "${CREDENTIAL_DIR}"
sudo install -d -m 0700 -o "${DAEMON_USER}" "${KEY_DIR}"
sudo install -d -m 0700 -o "${DAEMON_USER}" "${PIN_DIR}"
sudo install -d -m 0700 -o "${DAEMON_USER}" "${LOCAL_AUTH_DIR}"
ok "Directories ready."

# ── 4.7 Write initial trusted binary hashes ───────────────────────────────
echo ""
info "Writing trusted binary hashes to ${TRUSTED_HASHES}..."
DAEMON_HASH="$(sha256sum "${DAEMON_DEST}" | awk '{print $1}')"
sudo tee "${TRUSTED_HASHES}" > /dev/null << EOF
[
  { "path": "${DAEMON_DEST}", "sha256": "${DAEMON_HASH}" }
]
EOF
sudo chmod 0644 "${TRUSTED_HASHES}"
ok "mykey-daemon: ${DAEMON_HASH}"

# ── 4.8 Install D-Bus system policy ──────────────────────────────────────
echo ""
info "Installing D-Bus system policy..."
sudo install -m 0644 "${REPO_ROOT}/scripts/com.mykey.Daemon.conf" \
    "/etc/dbus-1/system.d/com.mykey.Daemon.conf"
ok "D-Bus policy installed."

# ── 4.9 Install polkit policy ─────────────────────────────────────────────
echo ""
info "Installing polkit policy..."
sudo install -m 0644 "${REPO_ROOT}/scripts/com.mykey.authenticate.policy" \
    "${POLKIT_POLICY}"
ok "Polkit policy installed."

# ── 4.10 Install and enable systemd daemon service ────────────────────────
echo ""
info "Installing systemd service unit..."
sudo install -m 0644 "${SYSTEMD_UNIT_SRC}" "${SYSTEMD_UNIT}"
sudo systemctl daemon-reload
sudo systemctl enable mykey-daemon
ok "Daemon service enabled."

# ── 4.12 Build mykey-tray ────────────────────────────────────────────────────
echo ""
info "Building ${TRAY_BINARY} (release)..."
cd "${REPO_ROOT}/mykey-tray"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: ${TRAY_BINARY}"

# ── 4.13 Install mykey-tray binary ───────────────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-tray/target/release/${TRAY_BINARY}" "${TRAY_DEST}"
ok "${TRAY_DEST}"

# ── 4.14 Install tray user service (as the real user, not root) ───────────
echo ""
info "Installing tray user service..."

SYSTEMD_USER_DIR="${REAL_HOME}/.config/systemd/user"

mkdir -p "${SYSTEMD_USER_DIR}"

cp "${TRAY_SERVICE_SRC}" "${SYSTEMD_USER_DIR}/mykey-tray.service"
chmod 0644 "${SYSTEMD_USER_DIR}/mykey-tray.service"

systemctl --user daemon-reload
ok "Tray service installed for user '${REAL_USER}' (optional; enable with: mykey-tray enable)"

# ── 4.15 Build mykey-secrets ─────────────────────────────────────────────────
echo ""
info "Building ${SECRETS_BINARY} (release)..."
cd "${REPO_ROOT}/mykey-secrets"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: ${SECRETS_BINARY}"

# ── 4.16 Install mykey-secrets binary ────────────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-secrets/target/release/${SECRETS_BINARY}" "${SECRETS_DEST}"
ok "${SECRETS_DEST}"

# ── 4.17 Install Secret Service D-Bus session policy ─────────────────────────
echo ""
info "Installing Secret Service D-Bus policy..."
sudo mkdir -p /etc/dbus-1/session.d/
sudo install -m 0644 "${SECRETS_DBUS_CONF_SRC}" \
    /etc/dbus-1/session.d/org.freedesktop.secrets.conf
ok "/etc/dbus-1/session.d/org.freedesktop.secrets.conf"

# ── 4.18 Install and enable mykey-secrets user service ───────────────────────
echo ""
info "Installing mykey-secrets user service..."

cp "${SECRETS_SERVICE_SRC}" "${SYSTEMD_USER_DIR}/mykey-secrets.service"
chmod 0644 "${SYSTEMD_USER_DIR}/mykey-secrets.service"

systemctl --user daemon-reload
systemctl --user enable mykey-secrets

# Symlink fallback to guarantee enable persists
AUTOSTART_DIR="${SYSTEMD_USER_DIR}/default.target.wants"
mkdir -p "${AUTOSTART_DIR}"
ln -sf "${SYSTEMD_USER_DIR}/mykey-secrets.service" \
       "${AUTOSTART_DIR}/mykey-secrets.service"

ok "mykey-secrets service installed and enabled for user '${REAL_USER}'"

# ── 4.19 Build mykey-migrate ─────────────────────────────────
echo ""
info "Building mykey-migrate (release)..."
cd "${REPO_ROOT}/mykey-migrate"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: mykey-migrate"

# ── 4.20 Install mykey-migrate binary ────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-migrate/target/release/mykey-migrate" \
    "/usr/local/bin/mykey-migrate"
ok "/usr/local/bin/mykey-migrate"

# ── 4.21 Build mykey-pin ─────────────────────────────────────────────────
echo ""
info "Building mykey-pin (release)..."
cd "${REPO_ROOT}/mykey-auth/mykey-pin"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: mykey-pin"

# ── 4.22 Install mykey-pin binary ────────────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-auth/mykey-pin/target/release/mykey-pin" \
    "${PIN_DEST}"
ok "${PIN_DEST}"

# ── 4.23 Install mykey-pin-auth helper ────────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-auth/mykey-pin/target/release/${PIN_HELPER_BINARY}" \
    "${PIN_HELPER_DEST}"
ok "${PIN_HELPER_DEST}"

# ── 4.24 Install mykeypin.so PAM module ──────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-auth/mykey-pin/target/release/libmykeypin.so" \
    "${PIN_SO_DEST}"
ok "${PIN_SO_DEST}"

# ── 4.25 Build mykey-auth ────────────────────────────────────────────────
echo ""
info "Building ${AUTH_BINARY} (release)..."
cd "${REPO_ROOT}/mykey-auth/mykey-pam"
RUSTFLAGS="-A warnings" "${CARGO}" build --release
ok "Build complete: ${AUTH_BINARY}"

# ── 4.26 Install mykey-auth binary ───────────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-auth/mykey-pam/target/release/${AUTH_BINARY}" \
    "${AUTH_DEST}"
ok "${AUTH_DEST}"

# ── 4.27 Install pam_mykey.so PAM module ─────────────────────────────────
sudo install -m 0755 "${REPO_ROOT}/mykey-auth/mykey-pam/target/release/libpam_mykey.so" \
    "${AUTH_SO_DEST}"
ok "${AUTH_SO_DEST}"

# Update binary hashes after installation
echo ""
info "Updating trusted binary hashes..."
DAEMON_HASH="$(sha256sum "${DAEMON_DEST}" | awk '{print $1}')"
sudo tee "${TRUSTED_HASHES}" > /dev/null << EOF
[
  { "path": "${DAEMON_DEST}", "sha256": "${DAEMON_HASH}" }
]
EOF
ok "Binary hashes updated"

# ════════════════════════════════════════════════════════════════════════════
# PHASE 5 — START SERVICES
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 5 — Start Services"
echo "════════════════════════════════════════════════════════════"

echo ""
info "Starting mykey-daemon..."
sudo systemctl start mykey-daemon
sleep 2
if systemctl is-active --quiet mykey-daemon; then
    ok "mykey-daemon is running"
else
    die "mykey-daemon failed to start. Check: journalctl -u mykey-daemon -n 20"
fi

# Clean up stale log files that may be owned by mykey system user
sudo rm -f /tmp/mykey-secrets.log
sudo rm -f /tmp/mykey-daemon.log

# ── Secret Service enrollment ─────────────────────────────────────
echo ""
info "Running mykey-migrate --enroll..."
mykey-migrate --enroll || die "Enrollment failed. Fix the error above and run ./scripts/install.sh again."

# ════════════════════════════════════════════════════════════════════════════
# PHASE 6 — FINAL HEALTH CHECK
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Phase 6 — Final Health Check"
echo "════════════════════════════════════════════════════════════"
echo ""

# [1/8] Secure Boot
echo "[1/8] Secure Boot..."
SB_FINAL="$(detect_secure_boot_state)"
case "${SB_FINAL}" in
    enabled) ok "Secure Boot is enabled" ;;
    *)       fail "Secure Boot is not enabled"; FAILED=1 ;;
esac

# [2/8] TPM2
echo "[2/8] TPM2..."
if [[ -c /dev/tpm0 && -c /dev/tpmrm0 ]]; then
    ok "TPM2 present"
else
    fail "TPM2 not found"
    FAILED=1
fi

# [3/8] Binaries
echo "[3/8] Binaries..."
for bin in "${DAEMON_BINARY}" "${TRAY_BINARY}" "${SECRETS_BINARY}" "mykey-migrate" "${PIN_BINARY}" "${PIN_HELPER_BINARY}" "${AUTH_BINARY}"; do
    if [[ -x "/usr/local/bin/${bin}" ]]; then
        ok "/usr/local/bin/${bin}"
    else
        fail "/usr/local/bin/${bin} missing"
        FAILED=1
    fi
done

# [4/8] Configuration files
echo "[4/8] Configuration..."
for f in \
    "${TRUSTED_HASHES}" \
    "${POLKIT_POLICY}" \
    "/etc/dbus-1/system.d/com.mykey.Daemon.conf" \
    "${PIN_SO_DEST}" \
    "${AUTH_SO_DEST}"
do
    if sudo test -f "${f}"; then
        ok "${f}"
    else
        fail "${f} missing"
        FAILED=1
    fi
done

# [5/8] Binary integrity
echo "[5/8] Binary integrity..."
if command -v python3 &>/dev/null; then
    sudo python3 - << 'PYEOF'
import json, hashlib, sys
try:
    with open("/etc/mykey/trusted-binaries.json") as f:
        entries = json.load(f)
    all_ok = True
    for entry in entries:
        with open(entry["path"], "rb") as bf:
            actual = hashlib.sha256(bf.read()).hexdigest()
        if actual == entry["sha256"]:
            print(f"  \u2713 {entry['path']}")
        else:
            print(f"  \u2717 {entry['path']} \u2014 hash mismatch", file=sys.stderr)
            all_ok = False
    sys.exit(0 if all_ok else 1)
except Exception as e:
    print(f"  ! Could not verify hashes: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
    [[ $? -eq 0 ]] || FAILED=1
else
    warn "python3 not found — skipping hash verification"
fi

# [6/8] Daemon service
echo "[6/8] Daemon service..."
if systemctl is-active --quiet mykey-daemon; then
    ok "mykey-daemon is running"
else
    fail "mykey-daemon is not running"
    FAILED=1
fi

# [7/8] Tray service
echo "[7/8] Tray service..."
if systemctl --user is-active --quiet mykey-tray 2>/dev/null; then
    ok "mykey-tray is running"
elif systemctl --user is-enabled --quiet mykey-tray 2>/dev/null; then
    warn "mykey-tray is enabled but not running"
    warn "Check with: mykey-tray status"
else
    ok "mykey-tray is optional and currently off"
    echo "    Enable later with: mykey-tray enable"
fi

# [8/8] Secrets service
echo "[8/8] Secrets service..."
if systemctl --user is-active --quiet mykey-secrets 2>/dev/null; then
    ok "mykey-secrets is running"
else
    warn "mykey-secrets is not running"
    warn "Start with: systemctl --user start mykey-secrets"
fi

# ── Final summary ─────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
if [[ "${FAILED}" -eq 0 ]]; then
    echo " Installation complete — all checks passed."
    echo ""
    echo " Next validation steps:"
    echo "   1. Verify PIN status with: mykey-pin status"
    echo "   2. Verify Secret Service with: systemctl --user status mykey-secrets"
    echo "   3. Optional tray: mykey-tray enable"
    echo "   4. Verify tray status with: mykey-tray status"
    echo ""
    echo " Live logs:"
    echo "   journalctl -u mykey-daemon -f"
else
    echo " Installation completed with errors — review the output above."
    echo " Fix any failed checks and run ./scripts/install.sh again."
fi
echo "════════════════════════════════════════════════════════════"
echo ""
