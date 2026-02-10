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
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use std::str::FromStr;

    /// Represents a single note with metadata.
    pub struct Note {
        pub id: String,
        pub title: String,
        pub body: String,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
        pub encrypted: bool,
    }

    /// Errors that can occur while manipulating notes.
    pub enum NoteError {
        Io(std::io::Error),
        Json(serde_json::Error),
        Validation(String),
    }

    impl Note {
        /// Creates a new note with the given title and body.
        ///
        /// The `id` is generated from the current timestamp in nanoseconds,
        /// and both `created_at` and `updated_at` are set to the current UTC time.
        /// The note is initially unencrypted (`encrypted = false`).
        pub fn new(title: &str, body: &str) -> Self {
            let now = Utc::now();
            Self {
                id: format!("{}", now.timestamp_nanos()),
                title: title.to_string(),
                body: body.to_string(),
                created_at: now,
                updated_at: now,
                encrypted: false,
            }
        }

        /// Parses a `serde_json::Value` into a `Note`.
        ///
        /// Expects the JSON object to contain the keys:
        /// `id`, `title`, `body`, `created_at`, `updated_at`, and `encrypted`.
        /// The timestamps must be RFC3339 strings.
        pub fn from_json(json: &Value) -> Result<Self, NoteError> {
            // Helper to extract a string field
            fn get_str(json: &Value, key: &str) -> Result<String, NoteError> {
                json.get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .ok_or_else(|| {
                        NoteError::Validation(format!("Missing or invalid field '{}'", key))
                    })
            }

            // Helper to extract a bool field
            fn get_bool(json: &Value, key: &str) -> Result<bool, NoteError> {
                json.get(key)
                    .and_then(|v| v.as_bool())
                    .ok_or_else(|| {
                        NoteError::Validation(format!("Missing or invalid field '{}'", key))
                    })
            }

            // Helper to extract a DateTime<Utc> from an RFC3339 string
            fn get_datetime(json: &Value, key: &str) -> Result<DateTime<Utc>, NoteError> {
                let s = get_str(json, key)?;
                DateTime::parse_from_rfc3339(&s)
                    .map(|dt| dt.with_timezone(&Utc))
                    .map_err(NoteError::Json)
            }

            let id = get_str(json, "id")?;
            let title = get_str(json, "title")?;
            let body = get_str(json, "body")?;
            let created_at = get_datetime(json, "created_at")?;
            let updated_at = get_datetime(json, "updated_at")?;
            let encrypted = get_bool(json, "encrypted")?;

            Ok(Self {
                id,
                title,
                body,
                created_at,
                updated_at,
                encrypted,
            })
        }

        /// Serializes the note into a `serde_json::Value`.
        ///
        /// The timestamps are formatted as RFC3339 strings.
        pub fn to_json(&self) -> Value {
            let mut map = serde_json::Map::new();
            map.insert("id".to_string(), Value::String(self.id.clone()));
            map.insert("title".to_string(), Value::String(self.title.clone()));
            map.insert("body".to_string(), Value::String(self.body.clone()));
            map.insert(
                "created_at".to_string(),
                Value::String(self.created_at.to_rfc3339()),
            );
            map.insert(
                "updated_at".to_string(),
                Value::String(self.updated_at.to_rfc3339()),
            );
            map.insert("encrypted".to_string(), Value::Bool(self.encrypted));
            Value::Object(map)
        }
    }
}

pub mod storage {
    //! Handles file I/O for notes, including optional encryption.
    todo!()
}

pub mod search {
    use std::collections::HashMap;
    use crate::note::Note;

    /// Inverted index mapping terms to note IDs.
    pub struct SearchEngine {
        pub index: HashMap<String, Vec<String>>,
    }

    impl SearchEngine {
        /// Builds the index from a slice of notes.
        ///
        /// The index maps each lower‑cased term (split on whitespace) to a list of
        /// note IDs that contain the term in either title or body. Duplicate IDs
        /// for a given term are removed.
        pub fn new(notes: &[Note]) -> Self {
            let mut index: HashMap<String, Vec<String>> = HashMap::new();

            for note in notes {
                let id = note.id.clone();
                // Tokenize title and body
                for term in tokenize(&note.title) {
                    let entry = index.entry(term).or_insert_with(Vec::new);
                    if !entry.contains(&id) {
                        entry.push(id.clone());
                    }
                }
                for term in tokenize(&note.body) {
                    let entry = index.entry(term).or_insert_with(Vec::new);
                    if !entry.contains(&id) {
                        entry.push(id.clone());
                    }
                }
            }

            SearchEngine { index }
        }

        /// Returns a vector of note IDs that contain the given term.
        ///
        /// The search is case‑insensitive; `term` is lower‑cased before lookup.
        /// If the term does not exist in the index, an empty vector is returned.
        pub fn query(&self, term: &str) -> Vec<String> {
            let key = term.to_lowercase();
            self.index.get(&key).cloned().unwrap_or_default()
        }
    }

    /// Simple tokenizer: splits on whitespace and lower‑cases each token.
    ///
    /// This helper is intentionally minimal; it does not strip punctuation.
    fn tokenize(text: &str) -> Vec<String> {
        text.split_whitespace()
            .map(|s| s.to_lowercase())
            .collect()
    }
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
