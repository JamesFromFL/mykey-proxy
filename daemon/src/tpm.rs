// tpm.rs — TPM2 key sealing layer (daemon-side mirror of native-host/src/tpm.rs).
//
// Production intent (behind the `tpm2` feature flag):
//
//   TODO: seal_key(key_bytes) → sealed blob
//         Use TPM2_Create under the SRK with a PCR policy covering
//         PCR 0 (firmware), PCR 7 (Secure Boot), PCR 11 (boot loader).
//         Private key material never leaves the TPM boundary.
//
//   TODO: unseal_key(sealed_blob) → key_bytes
//         Load the blob with TPM2_Load, verify the PCR policy, use TPM2_Sign
//         to produce signatures inside the TPM.  PCR drift causes hard failure.
//
//   TODO: generate_in_tpm() → (public_key_bytes, key_handle)
//         Generate the P-256 key inside the TPM using TPM2_Create with
//         TPM_ALG_ECDSA + TPM_ECC_NIST_P256.  Private key never exported.
//
// Current state — SOFTWARE FALLBACK (not production safe).
// See native-host/src/tpm.rs for the full rationale.

use log::warn;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY_DIR: &str = "/etc/webauthn-proxy/keys";

// ---------------------------------------------------------------------------
// Software fallback
// ---------------------------------------------------------------------------

/// Store a private key as a hex file.
///
/// ⚠ SOFTWARE FALLBACK — plaintext key on disk.  Replace with TPM2 sealing.
pub fn seal_key(credential_id_hex: &str, key_bytes: &[u8]) -> Result<(), String> {
    warn!(
        "⚠ SOFTWARE FALLBACK (daemon): storing key for credential {} in plaintext. \
         Enable --features tpm2 for real TPM sealing.",
        credential_id_hex
    );

    std::fs::create_dir_all(KEY_DIR)
        .map_err(|e| format!("Cannot create key directory {KEY_DIR}: {e}"))?;

    let path = key_path(credential_id_hex);
    let hex_str = hex::encode(key_bytes);

    std::fs::write(&path, hex_str.as_bytes())
        .map_err(|e| format!("Cannot write key to {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Cannot chmod key file: {e}"))?;
    }

    Ok(())
}

/// Load a private key from the hex file.
///
/// ⚠ SOFTWARE FALLBACK — plaintext key on disk.
pub fn unseal_key(credential_id_hex: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    warn!(
        "⚠ SOFTWARE FALLBACK (daemon): loading plaintext key for credential {}.",
        credential_id_hex
    );

    let path = key_path(credential_id_hex);
    let hex_bytes = std::fs::read(&path)
        .map_err(|e| format!("Cannot read key from {}: {e}", path.display()))?;

    let hex_str = std::str::from_utf8(&hex_bytes)
        .map_err(|_| "Key file is not valid UTF-8".to_string())?
        .trim();

    let key = hex::decode(hex_str)
        .map_err(|e| format!("Key file contains invalid hex: {e}"))?;

    Ok(Zeroizing::new(key))
}

fn key_path(credential_id_hex: &str) -> PathBuf {
    Path::new(KEY_DIR).join(format!("{}.key", credential_id_hex))
}

// ---------------------------------------------------------------------------
// TPM2 stubs (compiled only with --features tpm2)
// ---------------------------------------------------------------------------

#[cfg(feature = "tpm2")]
pub mod tpm2 {
    // TODO: Implement using tss_esapi::Context with TCTI /dev/tpmrm0.
    // Key creation should use a PCR policy session bound to PCR 0, 7, and 11.
    // Signing should happen inside the TPM via TPM2_Sign with ECDSA P-256.

    pub fn seal_key_tpm2(_key_bytes: &[u8]) -> Result<Vec<u8>, String> {
        Err("TPM2 sealing not yet implemented".to_string())
    }

    pub fn unseal_key_tpm2(_sealed_blob: &[u8]) -> Result<Vec<u8>, String> {
        Err("TPM2 unsealing not yet implemented".to_string())
    }

    pub fn generate_in_tpm() -> Result<Vec<u8>, String> {
        Err("TPM2 in-TPM key generation not yet implemented".to_string())
    }
}
