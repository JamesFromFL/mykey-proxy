#!/bin/sh
set -eu

mode="${1:-}"
service_name="mykey-daemon"
daemon_path="/usr/bin/mykey-daemon"
trusted_manifest="/etc/mykey/trusted-binaries.json"

log_warning() {
  printf 'warning: %s\n' "$*" >&2
}

refresh_trusted_manifest() {
  if [ ! -x "${daemon_path}" ]; then
    log_warning "${daemon_path} is missing; skipping trusted-binaries.json refresh"
    return 0
  fi

  install -d -m 0711 /etc/mykey

  daemon_sha="$(sha256sum "${daemon_path}" | awk '{print $1}')"
  manifest_tmp="${trusted_manifest}.tmp.$$"
  printf '[\n  { "path": "%s", "sha256": "%s" }\n]\n' \
    "${daemon_path}" \
    "${daemon_sha}" > "${manifest_tmp}"
  chmod 0644 "${manifest_tmp}"
  mv "${manifest_tmp}" "${trusted_manifest}"
}

reload_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  systemctl daemon-reload >/dev/null 2>&1 || true
}

enable_and_start_daemon() {
  if ! command -v systemctl >/dev/null 2>&1; then
    log_warning "systemctl is unavailable; run 'sudo systemctl enable --now ${service_name}' manually"
    return 0
  fi

  if ! systemctl enable --now "${service_name}" >/dev/null 2>&1; then
    log_warning "could not enable and start ${service_name}; run 'sudo systemctl enable --now ${service_name}' manually"
  fi
}

restart_enabled_daemon() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  if systemctl is-enabled --quiet "${service_name}" >/dev/null 2>&1 ||
     systemctl is-active --quiet "${service_name}" >/dev/null 2>&1; then
    if ! systemctl restart "${service_name}" >/dev/null 2>&1; then
      log_warning "could not restart ${service_name}; run 'sudo systemctl restart ${service_name}' manually"
    fi
  fi
}

case "${mode}" in
  install)
    refresh_trusted_manifest
    reload_systemd
    enable_and_start_daemon
    ;;
  upgrade)
    refresh_trusted_manifest
    reload_systemd
    restart_enabled_daemon
    ;;
  *)
    printf 'Usage: %s <install|upgrade>\n' "$0" >&2
    exit 2
    ;;
esac
