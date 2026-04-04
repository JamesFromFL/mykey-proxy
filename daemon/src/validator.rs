// validator.rs — Caller process verification and request integrity checks.
//
// All verification failures are logged with [validator] prefix including the
// specific reason, to aid incident investigation without leaking secrets.

use hmac::{Hmac, Mac};
use log::{debug, warn};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Caller process verification
// ---------------------------------------------------------------------------

/// Verify that `pid` is a Chrome or Chromium process whose parent is also a
/// Chrome/Chromium process.
///
/// Checks performed (in order):
///   1. /proc/{pid}/exe  resolves to a chrome/chromium binary path
///   2. /proc/{pid}/status PPid line — parent also resolves to chrome/chromium
///   3. /proc/{pid}/cmdline contains "chrome" or "chromium"
///
/// Returns false on any failure; never panics.
pub fn verify_caller_process(pid: u32) -> bool {
    // ── Check 1: binary path ────────────────────────────────────────────
    let exe_path = match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => p,
        Err(e) => {
            warn!("[validator] Cannot read /proc/{pid}/exe: {e}");
            return false;
        }
    };
    let exe_str = exe_path.to_string_lossy();
    if !is_chrome_binary(&exe_str) {
        warn!("[validator] pid={pid} exe={exe_str} is not a chrome/chromium binary");
        return false;
    }

    // ── Check 2: parent process ─────────────────────────────────────────
    let ppid = match read_ppid(pid) {
        Some(p) => p,
        None => {
            warn!("[validator] Cannot determine PPid for pid={pid}");
            return false;
        }
    };
    let parent_exe = match std::fs::read_link(format!("/proc/{ppid}/exe")) {
        Ok(p) => p,
        Err(e) => {
            warn!("[validator] Cannot read /proc/{ppid}/exe (parent of pid={pid}): {e}");
            return false;
        }
    };
    let parent_str = parent_exe.to_string_lossy();
    if !is_chrome_binary(&parent_str) {
        warn!(
            "[validator] pid={pid} parent pid={ppid} exe={parent_str} is not chrome/chromium"
        );
        return false;
    }

    // ── Check 3: cmdline sanity check ───────────────────────────────────
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(cmdline) => {
            let cmdline_str = String::from_utf8_lossy(&cmdline);
            // cmdline is null-separated; argv[0] is the binary name
            if !cmdline_str.contains("chrome") && !cmdline_str.contains("chromium") {
                warn!("[validator] pid={pid} cmdline does not contain chrome/chromium");
                return false;
            }
        }
        Err(e) => {
            warn!("[validator] Cannot read /proc/{pid}/cmdline: {e}");
            return false;
        }
    }

    debug!("[validator] pid={pid} passed all process verification checks");
    true
}

/// Return true if the given path looks like a Chrome or Chromium binary.
fn is_chrome_binary(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("google-chrome")
        || lower.contains("chromium")
        || lower.contains("chrome-sandbox")
        || lower.contains("/chrome")
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
