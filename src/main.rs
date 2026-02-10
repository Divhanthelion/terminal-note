//! A clean, fast TUI notes app for Linux inspired by Apple Notes. Supports markdown editing, optional AES‑256‑GCM encryption with Argon2 key derivation, vim‑style bindings, full‑text search, syntax highlighting for code blocks and export to plain markdown.

pub mod crypto {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::{Aead, Error as AesError};
    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, Error as ArgonError},
    };
    use rand::rngs::OsRng;
    use rand::RngCore;
    use base64;

    /// Holds the derived key and salt for a note.
    pub struct CryptoContext {
        pub salt: [u8; 16],
        pub key: [u8; 32],
    }

    /// Errors that can occur during crypto operations.
    #[derive(Debug)]
    pub enum CryptoError {
        Argon2(ArgonError),
        Aes(AesError),
    }

    /// Derives a 256‑bit key from the password and salt using Argon2.
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
        // Argon2 requires a base64 encoded salt string.
        let salt_str = SaltString::b64_encode(salt).map_err(CryptoError::Argon2)?;
        let argon2 = Argon2::default();

        // Hash the password with the given salt.
        let hash_obj = argon2
            .hash_password_simple(password, &salt_str)
            .map_err(CryptoError::Argon2)?;

        // The hash string has the form:
        // $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        // We need the base64 encoded <hash> part.
        let hash_str = hash_obj.to_string();
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 5 {
            return Err(CryptoError::Argon2(ArgonError::InvalidFormat));
        }
        let hash_b64 = parts[parts.len() - 1];
        let hash_bytes =
            base64::decode(hash_b64).map_err(|_| CryptoError::Argon2(ArgonError::InvalidFormat))?;

        if hash_bytes.len() != 32 {
            return Err(CryptoError::Argon2(ArgonError::InvalidFormat));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes);
        Ok(key)
    }

    /// Encrypts data with AES‑256‑GCM, returns (ciphertext, nonce).
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(CryptoError::Aes)?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(CryptoError::Aes)?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypts data with AES‑256‑GCM.
    pub fn decrypt(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(CryptoError::Aes)?;
        let nonce = Nonce::from_slice(nonce);
        let plaintext =
            cipher.decrypt(nonce, ciphertext).map_err(CryptoError::Aes)?;
        Ok(plaintext)
    }
}

pub mod note {
    //! Defines the core data model for a note and related errors.
    todo!()
}

pub mod storage {
    //! Handles file I/O for notes, including optional encryption.
    todo!()
}

pub mod search {
    //! Implements a simple full‑text search index over note titles and bodies.
    todo!()
}

pub mod app {
    //! Core state machine that orchestrates notes, storage and search.
    todo!()
}

pub mod ui {
    //! Renders the TUI and handles user input.
    todo!()
}

pub mod main {
    //! Application entry point that wires everything together.
    todo!()
}

fn main() {
    println!("Starting application...");
    todo!("Wire up application entry point")
}
