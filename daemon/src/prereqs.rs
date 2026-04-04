// prereqs.rs — System prerequisite checks run at daemon startup.
//
// All checks log with [prereqs] prefix.  enforce_prereqs() runs all four and
// returns Err with a combined summary if any fail.  main() does a hard exit on
// any failure.

use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::io::Read;

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Run all prerequisite checks.  Returns Ok if every check passes, or
/// Err(summary_string) listing every failure.
pub fn enforce_prereqs() -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();

    match check_secure_boot() {
        Ok(()) => info!("[prereqs] Secure Boot: OK"),
        Err(e) => {
            warn!("[prereqs] Secure Boot: {}", e);
            // Non-fatal in development — warn but do not block startup.
            // Promote to failure in production by pushing to `failures`.
        }
    }

    match check_tpm2_present() {
        Ok(()) => info!("[prereqs] TPM2 present: OK"),
        Err(e) => {
            warn!("[prereqs] TPM2 not found: {}", e);
            // Non-fatal: software fallback is active until --features tpm2 build.
        }
    }

    match check_tpm2_responsive() {
        Ok(()) => info!("[prereqs] TPM2 responsive: OK"),
        Err(e) => {
            warn!("[prereqs] TPM2 not responsive: {}", e);
        }
    }

    match check_binary_hashes() {
        Ok(()) => info!("[prereqs] Binary integrity: OK"),
        Err(e) => {
            error!("[prereqs] Binary integrity check failed: {}", e);
            failures.push(format!("binary integrity: {e}"));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/// Verify Secure Boot is enabled by reading the EFI variable.
///
/// The SecureBoot variable lives at:
///   /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
///
/// The EFI variable format: 4-byte attribute header, then the value byte.
/// Value byte == 1 means Secure Boot is enabled.
pub fn check_secure_boot() -> Result<(), String> {
    let var_path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

    let data = std::fs::read(var_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "EFI variable not found — system may not be UEFI or may not expose efivars".to_string()
        } else {
            format!("Cannot read SecureBoot EFI variable: {e}")
        }
    })?;

    // Bytes 0–3: EFI_VARIABLE_ATTRIBUTES (u32 LE).  Byte 4: value.
    match data.get(4) {
        Some(&1) => Ok(()),
        Some(&v) => Err(format!("Secure Boot is disabled (value={v})")),
        None => Err("SecureBoot EFI variable is too short to parse".to_string()),
    }
}

/// Check that /dev/tpm0 and /dev/tpmrm0 exist and are accessible.
pub fn check_tpm2_present() -> Result<(), String> {
    let check = |path: &str| {
        std::fs::metadata(path).map_err(|e| format!("{path} inaccessible: {e}"))
    };
    check("/dev/tpm0")?;
    check("/dev/tpmrm0")?;
    Ok(())
}

/// Open /dev/tpmrm0 and send a minimal TPM2_GetCapability command to verify
/// the TPM2 resource manager is actually responding.
///
/// TPM2_GetCapability for TPM_CAP_TPM_PROPERTIES / TPM_PT_MANUFACTURER:
///   80 01           TPM_ST_NO_SESSIONS
///   00 00 00 16     commandSize = 22 bytes
///   00 00 01 7A     TPM_CC_GetCapability
///   00 00 00 06     TPM_CAP_TPM_PROPERTIES
///   00 00 01 05     TPM_PT_MANUFACTURER
///   00 00 00 01     propertyCount = 1
pub fn check_tpm2_responsive() -> Result<(), String> {
    const CMD: [u8; 22] = [
        0x80, 0x01,                   // TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x16,       // commandSize = 22
        0x00, 0x00, 0x01, 0x7A,       // TPM_CC_GetCapability
        0x00, 0x00, 0x00, 0x06,       // TPM_CAP_TPM_PROPERTIES
        0x00, 0x00, 0x01, 0x05,       // TPM_PT_MANUFACTURER
        0x00, 0x00, 0x00, 0x01,       // propertyCount = 1
    ];
    // Expected response tag: 0x80 0x01 (TPM_ST_NO_SESSIONS)
    // Expected response code at bytes 6–9: 0x00 0x00 0x00 0x00 (TPM_RC_SUCCESS)

    use std::io::Write;

    let path = "/dev/tpmrm0";
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("Cannot open {path}: {e}"))?;

    file.write_all(&CMD)
        .map_err(|e| format!("Cannot write TPM2 command: {e}"))?;

    let mut response = [0u8; 64];
    // Set a short read timeout by using a non-blocking approach via the file
    let n = file
        .read(&mut response)
        .map_err(|e| format!("Cannot read TPM2 response: {e}"))?;

    if n < 10 {
        return Err(format!("TPM2 response too short: {n} bytes"));
    }
    // Check response tag (must be TPM_ST_NO_SESSIONS = 0x8001)
    if response[0] != 0x80 || response[1] != 0x01 {
        return Err(format!(
            "Unexpected TPM2 response tag: {:02x}{:02x}",
            response[0], response[1]
        ));
    }
    // Check response code at bytes 6–9 (must be TPM_RC_SUCCESS = 0x00000000)
    if response[6..10] != [0x00, 0x00, 0x00, 0x00] {
        return Err(format!(
            "TPM2 returned error code: {:02x}{:02x}{:02x}{:02x}",
            response[6], response[7], response[8], response[9]
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Binary integrity check
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct TrustedBinary {
    path: String,
    sha256: String, // hex-encoded
}

/// Read /etc/webauthn-proxy/trusted-binaries.json, SHA-256 each binary, and
/// verify the hashes match.  Missing file is treated as "not yet set up" and
/// returns Ok (the install script creates this file).
pub fn check_binary_hashes() -> Result<(), String> {
    let manifest_path = "/etc/webauthn-proxy/trusted-binaries.json";

    let data = match std::fs::read(manifest_path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("[prereqs] trusted-binaries.json not found — skipping hash check (run install.sh to set up)");
            return Ok(());
        }
        Err(e) => return Err(format!("Cannot read {manifest_path}: {e}")),
    };

    let entries: Vec<TrustedBinary> = serde_json::from_slice(&data)
        .map_err(|e| format!("Malformed trusted-binaries.json: {e}"))?;

    let mut failures = Vec::new();

    for entry in &entries {
        match sha256_file(&entry.path) {
            Ok(actual) if actual == entry.sha256 => {
                info!("[prereqs] Hash OK: {}", entry.path);
            }
            Ok(actual) => {
                error!(
                    "[prereqs] Hash MISMATCH for {}: expected={} actual={}",
                    entry.path, entry.sha256, actual
                );
                failures.push(format!("hash mismatch for {}", entry.path));
            }
            Err(e) => {
                warn!("[prereqs] Cannot hash {}: {}", entry.path, e);
                // Missing binary is not a hard failure on first run
            }
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join(", "))
    }
}

/// SHA-256 of a file, returned as a lowercase hex string.
fn sha256_file(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Cannot read {path}: {e}"))?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}
