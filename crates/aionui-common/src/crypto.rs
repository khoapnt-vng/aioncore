use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::path::Path;

const NONCE_SIZE: usize = 12;
const KEY_SIZE: usize = 32;

/// Crypto helper error independent of HTTP/API boundaries.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AES-256 key must be exactly {expected} bytes, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    #[error("Failed to create cipher: {0}")]
    CipherInit(String),

    #[error("RNG failure: {0}")]
    Random(String),

    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Invalid base64: {0}")]
    InvalidBase64(String),

    #[error("Ciphertext too short")]
    CiphertextTooShort,

    #[error("Decryption failed: invalid key or corrupted data")]
    DecryptionFailed,

    #[error("Invalid UTF-8 in decrypted data: {0}")]
    InvalidUtf8(String),

    #[error("Encryption key file error: {0}")]
    KeyFile(String),
}

impl CryptoError {
    /// Returns true for caller/data problems that API boundaries should map to 400.
    pub fn is_bad_request(&self) -> bool {
        matches!(
            self,
            Self::InvalidKeySize { .. } | Self::InvalidBase64(_) | Self::CiphertextTooShort | Self::DecryptionFailed
        )
    }
}

/// Encrypt a string value using AES-256-GCM.
///
/// The key must be exactly 32 bytes. Output is base64-encoded (nonce + ciphertext + tag).
pub fn encrypt_string(plaintext: &str, key: &[u8]) -> Result<String, CryptoError> {
    validate_key_size(key)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::CipherInit(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| CryptoError::Random(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::Encryption(e.to_string()))?;

    let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(combined))
}

/// Decrypt an AES-256-GCM encrypted string.
///
/// The key must be exactly 32 bytes. Input is base64-encoded (nonce + ciphertext + tag).
pub fn decrypt_string(ciphertext: &str, key: &[u8]) -> Result<String, CryptoError> {
    validate_key_size(key)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::CipherInit(e.to_string()))?;

    let combined = BASE64
        .decode(ciphertext)
        .map_err(|e| CryptoError::InvalidBase64(e.to_string()))?;

    if combined.len() < NONCE_SIZE {
        return Err(CryptoError::CiphertextTooShort);
    }

    let (nonce_bytes, encrypted) = combined.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|e| CryptoError::InvalidUtf8(e.to_string()))
}

fn validate_key_size(key: &[u8]) -> Result<(), CryptoError> {
    if key.len() != KEY_SIZE {
        return Err(CryptoError::InvalidKeySize {
            expected: KEY_SIZE,
            actual: key.len(),
        });
    }
    Ok(())
}

/// SECURITY (D-05): load the 32-byte data-encryption key from a dedicated file,
/// creating it (cryptographically random, `0600` on Unix) on first use.
///
/// The key is stored in its OWN file — deliberately NOT derived from the `jwt_secret`
/// column inside the SQLite database that holds the ciphertext. An attacker who reads
/// only the database can no longer reconstruct the encryption key.
///
/// Note: this key is independent per install; it is not portable, so a database copied
/// to another machine without this key file cannot be decrypted there.
pub fn load_or_create_encryption_key(key_path: &Path) -> Result<[u8; KEY_SIZE], CryptoError> {
    match std::fs::read(key_path) {
        Ok(bytes) if bytes.len() == KEY_SIZE => {
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&bytes);
            Ok(key)
        }
        Ok(bytes) => Err(CryptoError::KeyFile(format!(
            "key file {} has invalid length {} (expected {KEY_SIZE})",
            key_path.display(),
            bytes.len()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; KEY_SIZE];
            getrandom::getrandom(&mut key).map_err(|e| CryptoError::Random(e.to_string()))?;
            if let Some(parent) = key_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| CryptoError::KeyFile(e.to_string()))?;
            }
            write_key_file(key_path, &key)?;
            Ok(key)
        }
        Err(err) => Err(CryptoError::KeyFile(err.to_string())),
    }
}

#[cfg(unix)]
fn write_key_file(key_path: &Path, key: &[u8]) -> Result<(), CryptoError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // create with 0600 so the key is never briefly world-readable.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(key_path)
        .map_err(|e| CryptoError::KeyFile(e.to_string()))?;
    file.write_all(key).map_err(|e| CryptoError::KeyFile(e.to_string()))
}

#[cfg(not(unix))]
fn write_key_file(key_path: &Path, key: &[u8]) -> Result<(), CryptoError> {
    // Windows: rely on the per-user profile ACL of the app data directory.
    std::fs::write(key_path, key).map_err(|e| CryptoError::KeyFile(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn load_or_create_encryption_key_is_stable_and_usable() {
        let dir = std::env::temp_dir().join(format!("aionui-enc-key-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key_path = dir.join(".aionui-enc-key");

        // First call creates the key; second call must return the identical bytes.
        let k1 = load_or_create_encryption_key(&key_path).expect("create key");
        let k2 = load_or_create_encryption_key(&key_path).expect("reload key");
        assert_eq!(k1, k2, "key must be stable across reloads");
        assert_ne!(k1, [0u8; 32], "key must not be all-zero");

        // The key must round-trip through the AES layer.
        let ciphertext = encrypt_string("secret", &k1).unwrap();
        assert_eq!(decrypt_string(&ciphertext, &k2).unwrap(), "secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_roundtrip() {
        let key = test_key();
        let encrypted = encrypt_string("hello", &key).unwrap();
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "hello");
    }

    #[test]
    fn test_empty_string() {
        let key = test_key();
        let encrypted = encrypt_string("", &key).unwrap();
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_unicode() {
        let key = test_key();
        let encrypted = encrypt_string("你好世界", &key).unwrap();
        let decrypted = decrypt_string(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "你好世界");
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = test_key();
        let encrypted = encrypt_string("hello", &key).unwrap();
        let wrong_key = [0x99; 32];
        assert!(matches!(
            decrypt_string(&encrypted, &wrong_key),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn test_nonce_randomness() {
        let key = test_key();
        let enc1 = encrypt_string("hello", &key).unwrap();
        let enc2 = encrypt_string("hello", &key).unwrap();
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_invalid_key_size() {
        let short_key = [0u8; 16];
        assert!(matches!(
            encrypt_string("hello", &short_key),
            Err(CryptoError::InvalidKeySize {
                expected: KEY_SIZE,
                actual: 16
            })
        ));
        assert!(matches!(
            decrypt_string("dGVzdA==", &short_key),
            Err(CryptoError::InvalidKeySize {
                expected: KEY_SIZE,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_invalid_base64() {
        let key = test_key();
        assert!(matches!(
            decrypt_string("not-valid-base64!!!", &key),
            Err(CryptoError::InvalidBase64(_))
        ));
    }

    #[test]
    fn test_ciphertext_too_short() {
        let key = test_key();
        // Base64 of less than 12 bytes
        let short = BASE64.encode([0u8; 5]);
        assert!(matches!(
            decrypt_string(&short, &key),
            Err(CryptoError::CiphertextTooShort)
        ));
    }
}
