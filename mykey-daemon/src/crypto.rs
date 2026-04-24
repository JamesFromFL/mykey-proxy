// crypto.rs — AES-256-GCM payload encryption/decryption and HMAC helpers.
//
// Used for encrypting session tokens returned to callers (keyed on bootstrap
// secret) and for encrypting/decrypting request/response payloads (keyed on
// session token).
//
// IMPORTANT: key material and plaintext are never logged.  Only sizes and
// status outcomes are logged, with [crypto] prefix.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use log::{debug, warn};
use rand::RngCore;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Encrypted payload envelope
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedPayload {
    /// Random 12-byte nonce (base64url encoded in JSON serialisation).
    pub nonce: [u8; 12],
    /// AES-256-GCM ciphertext + authentication tag.
    pub ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

/// Encrypt `plaintext` with AES-256-GCM using `key` (32 bytes).
///
/// Generates a fresh random nonce on each call.  Returns an `EncryptedPayload`
/// containing the nonce and ciphertext.
pub fn encrypt_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPayload, String> {
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "[crypto] Invalid AES-256-GCM key".to_string())?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "[crypto] AES-256-GCM encryption failed".to_string())?;

    debug!(
        "[crypto] Encrypted {} bytes → {} bytes ciphertext",
        plaintext.len(),
        ciphertext.len()
    );
    Ok(EncryptedPayload {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypt an `EncryptedPayload` with AES-256-GCM using `key` (32 bytes).
///
/// Fails if the authentication tag does not match (ciphertext was tampered
/// with or the wrong key was used).
pub fn decrypt_payload(
    key: &[u8; 32],
    payload: EncryptedPayload,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| "[crypto] Invalid AES-256-GCM key".to_string())?;
    let nonce = Nonce::from(payload.nonce);

    let plaintext = cipher
        .decrypt(&nonce, payload.ciphertext.as_ref())
        .map_err(|_| {
            warn!("[crypto] AES-256-GCM decryption failed — authentication tag mismatch");
            "[crypto] Decryption failed: authentication tag mismatch".to_string()
        })?;

    debug!(
        "[crypto] Decrypted {} bytes ciphertext → {} bytes plaintext",
        payload.ciphertext.len(),
        plaintext.len()
    );
    Ok(Zeroizing::new(plaintext))
}
