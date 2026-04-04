// crypto.js — WebAuthn binary encoding helpers used by the extension layer.
// Private keys never pass through here; this file only handles public-facing
// data structures (clientDataJSON, rpIdHash, base64url encoding).

// ---------------------------------------------------------------------------
// Base64url
// ---------------------------------------------------------------------------

/**
 * Encode an ArrayBuffer or Uint8Array to a base64url string (no padding).
 *
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function encodeBase64Url(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url string (with or without padding) to a Uint8Array.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function decodeBase64Url(str) {
  // Normalise: base64url → base64
  const base64 = str
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(str.length + ((4 - (str.length % 4)) % 4), '=');

  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// clientDataJSON
// ---------------------------------------------------------------------------

/**
 * Build a minimal clientDataJSON object conforming to the WebAuthn spec
 * (https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata).
 *
 * The result is the UTF-8 string that the native host must include verbatim
 * in its authenticator response so that relying parties can verify it.
 *
 * @param {'webauthn.create'|'webauthn.get'} type
 * @param {string} challengeBase64Url  — the raw challenge value, base64url-encoded
 * @param {string} origin              — the RP origin (e.g. "https://example.com")
 * @returns {string}  JSON string
 */
export function buildClientDataJSON(type, challengeBase64Url, origin) {
  const clientData = {
    type,
    challenge: challengeBase64Url,
    origin: origin.startsWith('http') ? origin : `https://${origin}`,
    crossOrigin: false,
  };
  return JSON.stringify(clientData);
}

// ---------------------------------------------------------------------------
// rpIdHash
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 hash of an RP ID string and return it as a Uint8Array.
 *
 * This value is included in the authenticatorData and must match what the
 * native host computes when it assembles the authenticator response.
 *
 * @param {string} rpId  — e.g. "example.com"
 * @returns {Promise<Uint8Array>}
 */
export async function computeRpIdHash(rpId) {
  const encoded = new TextEncoder().encode(rpId);
  const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(hashBuffer);
}

/**
 * Convenience wrapper: compute rpIdHash and return it as a base64url string.
 *
 * @param {string} rpId
 * @returns {Promise<string>}
 */
export async function computeRpIdHashBase64Url(rpId) {
  const hash = await computeRpIdHash(rpId);
  return encodeBase64Url(hash);
}
