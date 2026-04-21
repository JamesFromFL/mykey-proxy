// validator.rs — Caller process verification and request integrity checks.
//
// All verification failures are logged with [validator] prefix including the
// specific reason, to aid incident investigation without leaking secrets.

use std::path::Path;

use hmac::{Hmac, Mac};
use log::{debug, warn};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Caller process verification
// ---------------------------------------------------------------------------

/// Verify that `pid` is a supported browser process with a browser ancestor.
///
/// The daemon runs as a different system user than the browser, so
/// `/proc/{pid}/exe` may be unreadable (EPERM). The strategy is:
///
///   1. Try `/proc/{pid}/exe` — if readable, validate it; if EPERM, defer to
///      cmdline; any other error is a hard fail.
///   2. `/proc/{pid}/cmdline` — always readable across user boundaries on
///      Linux; must contain a recognised browser identifier.
///   3. Parent ancestry via cmdline — parent or grandparent cmdline must also
///      contain a browser identifier (exe symlinks are attempted first if
///      readable, then cmdline as fallback).
///
/// Returns false on any failure; never panics.
pub fn verify_caller_process(pid: u32) -> bool {
    // ── Check 1: binary path (EPERM is non-fatal; falls through to cmdline) ──
    let exe_ok = match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(exe) => {
            let s = exe.to_string_lossy();
            if is_valid_browser_exe(&s) {
                debug!("[validator] pid={pid} exe={s} — recognised browser");
                true
            } else {
                warn!("[validator] pid={pid} exe={s} — not a recognised browser");
                false
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Daemon runs as a different user — exe unreadable, fall through to cmdline
            debug!("[validator] pid={pid} exe unreadable (permission denied) — deferring to cmdline");
            true
        }
        Err(e) => {
            warn!("[validator] pid={pid} cannot read exe: {e}");
            false
        }
    };
    if !exe_ok {
        return false;
    }

    // ── Check 2: cmdline (readable across user boundaries) ───────────────
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(cmdline) => {
            let s = String::from_utf8_lossy(&cmdline);
            if is_valid_browser_exe(&s) {
                debug!("[validator] pid={pid} cmdline contains browser identifier");
            } else {
                warn!(
                    "[validator] pid={pid} cmdline does not contain browser identifier: {}",
                    &s[..s.len().min(200)]
                );
                return false;
            }
        }
        Err(e) => {
            warn!("[validator] pid={pid} cannot read cmdline: {e}");
            return false;
        }
    }

    // ── Check 3: parent/grandparent ancestry ─────────────────────────────
    if let Some(ppid) = read_ppid(pid) {
        // Try parent exe first; fall back to parent cmdline on EPERM
        let parent_browser = match std::fs::read_link(format!("/proc/{ppid}/exe")) {
            Ok(p) => is_valid_browser_exe(&p.to_string_lossy()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                // Fall through to cmdline check below
                false
            }
            Err(_) => false,
        };

        if parent_browser {
            debug!("[validator] pid={pid} parent ppid={ppid} exe — recognised browser");
            return true;
        }

        // Parent cmdline (always readable)
        if let Ok(cmdline) = std::fs::read(format!("/proc/{ppid}/cmdline")) {
            if is_valid_browser_exe(&String::from_utf8_lossy(&cmdline)) {
                debug!("[validator] pid={pid} parent ppid={ppid} cmdline — recognised browser");
                return true;
            }
        }

        // Grandparent check
        if let Some(gppid) = read_ppid(ppid) {
            let gp_browser = match std::fs::read_link(format!("/proc/{gppid}/exe")) {
                Ok(p) => is_valid_browser_exe(&p.to_string_lossy()),
                Err(_) => false,
            };
            if gp_browser {
                debug!("[validator] pid={pid} grandparent ppid={gppid} exe — recognised browser");
                return true;
            }
            if let Ok(cmdline) = std::fs::read(format!("/proc/{gppid}/cmdline")) {
                if is_valid_browser_exe(&String::from_utf8_lossy(&cmdline)) {
                    debug!(
                        "[validator] pid={pid} grandparent ppid={gppid} cmdline — recognised browser"
                    );
                    return true;
                }
            }
        }

        warn!("[validator] pid={pid} no recognised browser found in parent/grandparent chain");
        false
    } else {
        warn!("[validator] pid={pid} cannot determine parent pid");
        false
    }
}

/// Return true if the path/name belongs to a supported browser binary.
///
/// Accepts Chromium, Chrome, Brave, Microsoft Edge, and Vivaldi — matched
/// case-insensitively so distro-repackaged names (e.g. `chromium-browser`) are
/// also covered.
fn is_valid_browser_exe(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("chromium")
        || lower.contains("chrome")
        || lower.contains("brave")
        || lower.contains("microsoft-edge")
        || lower.contains("vivaldi")
}

/// Return true if the path/name belongs to a trusted MyKey binary.
///
/// Matching is done against the exact executable basename (argv[0] or
/// `/proc/{pid}/exe` basename), not by substring. Kept separate from
/// `is_valid_browser_exe` — these callers have different ancestry
/// characteristics (systemd or shell parents) and must not be conflated with
/// browser processes.
const TRUSTED_MYKEY_BINARIES: &[&str] = &[
    "mykey-host",
    "mykey-secrets",
    "mykey-migrate",
    "mykey-manager",
    "mykey-pin",
    "mykey-pin-auth",
    "mykey-auth",
];

fn is_valid_mykey_program(program: &str) -> bool {
    let name = Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    TRUSTED_MYKEY_BINARIES.iter().any(|trusted| *trusted == name)
}

fn canonical_mykey_program_name(program: &str) -> Option<&'static str> {
    let name = Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    TRUSTED_MYKEY_BINARIES.iter().copied().find(|trusted| *trusted == name)
}

fn cmdline_program(cmdline: &[u8]) -> Option<&str> {
    let argv0 = cmdline.split(|b| *b == 0).next()?;
    if argv0.is_empty() {
        return None;
    }
    std::str::from_utf8(argv0).ok()
}

/// Identify the trusted MyKey program for `pid`, if any.
///
/// Returns the canonical trusted basename such as `mykey-pin` or
/// `mykey-manager` if the process matches a trusted MyKey binary.
pub fn trusted_mykey_program(pid: u32) -> Option<&'static str> {
    // Check exe symlink first.
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(exe) => {
            let s = exe.to_string_lossy();
            if let Some(name) = canonical_mykey_program_name(&s) {
                debug!("[validator] pid={pid} exe={s} — recognised MyKey binary");
                return Some(name);
            }
            debug!("[validator] pid={pid} exe={s} — not a recognised MyKey binary, checking cmdline");
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            debug!("[validator] pid={pid} exe unreadable (permission denied) — checking cmdline");
        }
        Err(e) => {
            warn!("[validator] pid={pid} cannot read exe: {e}");
        }
    }

    // Fall back to cmdline.
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(cmdline) => {
            let preview = String::from_utf8_lossy(&cmdline);
            match cmdline_program(&cmdline) {
                Some(program) if is_valid_mykey_program(program) => {
                    let name = canonical_mykey_program_name(program)
                        .expect("trusted MyKey cmdline program should canonicalize");
                    debug!("[validator] pid={pid} cmdline argv0={program} — recognised MyKey binary");
                    Some(name)
                }
                _ => {
                    warn!(
                        "[validator] pid={pid} cmdline argv0 is not a recognised MyKey binary: {}",
                        &preview[..preview.len().min(200)]
                    );
                    None
                }
            }
        }
        Err(e) => {
            warn!("[validator] pid={pid} cannot read cmdline: {e}");
            None
        }
    }
}

/// Parse the PPid field from /proc/{pid}/status.
fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Binary integrity verification
// ---------------------------------------------------------------------------

/// SHA-256 hash the file at `path` and compare to `expected_hex`.
/// Returns true if they match, false otherwise.
pub fn verify_binary_integrity(path: &str, expected_hex: &str) -> bool {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            warn!("[validator] Cannot read binary at {path}: {e}");
            return false;
        }
    };
    let actual = hex::encode(Sha256::digest(&data));
    let matches = actual == expected_hex;
    if !matches {
        warn!(
            "[validator] Binary integrity MISMATCH for {path}: expected={expected_hex} actual={actual}"
        );
    } else {
        debug!("[validator] Binary integrity OK: {path}");
    }
    matches
}

// ---------------------------------------------------------------------------
// HMAC request authentication
// ---------------------------------------------------------------------------

/// Verify HMAC-SHA256(token, payload) equals `expected_hmac` in constant time.
///
/// A failed verification is logged with the pid context but never with the
/// token or payload contents.
pub fn verify_request_hmac(token: &[u8], payload: &[u8], expected_hmac: &[u8]) -> bool {
    let mut mac = match HmacSha256::new_from_slice(token) {
        Ok(m) => m,
        Err(e) => {
            warn!("[validator] HMAC init failed (bad key length?): {e}");
            return false;
        }
    };
    mac.update(payload);
    match mac.verify_slice(expected_hmac) {
        Ok(()) => {
            debug!("[validator] HMAC verification OK");
            true
        }
        Err(_) => {
            warn!("[validator] HMAC verification FAILED — payload may have been tampered with");
            false
        }
    }
}
