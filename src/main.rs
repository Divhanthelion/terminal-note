//! A clean, fast TUI notes app for Linux inspired by Apple Notes. Supports markdown editing, optional AES‑256‑GCM encryption with Argon2 key derivation, vim‑style bindings, full‑text search, syntax highlighting for code blocks and export to plain markdown.

pub mod crypto {
     use std::fmt::Display;
     use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
     use aes_gcm::aead::Aead;
     use argon2::{
        password_hash::{SaltString, Error as ArgonError},
        Argon2, PasswordHasher,
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
        Aes(String),
        Custom(String),
    }

    impl Display for CryptoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                CryptoError::Argon2(e) => write!(f, "Argon2 error: {}", e),
                CryptoError::Aes(e) => write!(f, "AES error: {}", e),
                CryptoError::Custom(e) => write!(f, "{}", e),
            }
        }
    }

    /// Derives a 256‑bit key from the password and salt using Argon2.
    pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
        // Argon2 requires a base64 encoded salt string.
        let salt_str = SaltString::b64_encode(salt).map_err(CryptoError::Argon2)?;
        let argon2 = Argon2::default();

        // Hash the password with the given salt.
        let hash_obj = argon2
            .hash_password(password.as_bytes(), &salt_str)
            .map_err(CryptoError::Argon2)?;

        // The hash string has the form:
        // $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        // We need the base64 encoded <hash> part.
        let hash_str = hash_obj.to_string();
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 5 {
            return Err(CryptoError::Custom("invalid hash format".into()));
        }
        let hash_b64 = parts[parts.len() - 1];
        let hash_bytes =
            base64::decode(hash_b64).map_err(|_| CryptoError::Custom("invalid base64".into()))?;

        if hash_bytes.len() != 32 {
            return Err(CryptoError::Custom("invalid hash length".into()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes);
        Ok(key)
    }

/// Encrypts data with AES‑256‑GCM, returns (ciphertext, nonce).
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Aes(e.to_string()))?;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::Aes(format!("{}", e)))?;

        Ok((ciphertext, nonce.to_vec()))
    }

/// Decrypts data with AES‑256‑GCM, returns plaintext.
pub fn decrypt(ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
           let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::Aes(e.to_string()))?;
           let nonce = Nonce::from_slice(nonce);
           let plaintext =
               cipher.decrypt(nonce, ciphertext).map_err(|e| CryptoError::Aes(format!("{}", e)))?;
           Ok(plaintext)
       }
}

pub mod note {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    

    /// Represents a single note with metadata.
    #[derive(Serialize, Deserialize, Clone)]
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
                     .map_err(|e| NoteError::Validation(format!("Invalid datetime: {}", e)))
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
    use std::fmt::Display;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use base64::{decode as b64_decode, encode as b64_encode};
    use rand::Rng;
    use serde::ser::Error;
    use serde_json::{json, Value};

    /// Root directory for all notes and the index file.
    pub struct Storage {
        pub base_dir: PathBuf,
    }

    /// Errors that can occur while accessing the filesystem.
    #[derive(Debug)]
    pub enum StorageError {
        Io(std::io::Error),
        Json(serde_json::Error),
        Crypto(crate::crypto::CryptoError),
    }

    impl Display for StorageError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                StorageError::Io(e) => write!(f, "IO error: {}", e),
                StorageError::Json(e) => write!(f, "JSON error: {}", e),
                StorageError::Crypto(e) => write!(f, "Crypto error: {}", e),
            }
        }
    }

    impl From<std::io::Error> for StorageError {
        fn from(e: std::io::Error) -> Self { StorageError::Io(e) }
    }
    impl From<serde_json::Error> for StorageError {
        fn from(e: serde_json::Error) -> Self { StorageError::Json(e) }
    }
    impl From<crate::crypto::CryptoError> for StorageError {
        fn from(e: crate::crypto::CryptoError) -> Self { StorageError::Crypto(e) }
    }

    /// CRUD operations for notes on disk.
    impl Storage {
        /// Create a new `Storage`. The default base directory is `./notes`.
        pub fn new() -> Result<Self, StorageError> {
            let base_dir = PathBuf::from("./notes");
            if !base_dir.exists() {
                fs::create_dir_all(&base_dir)?;
            }
            Ok(Storage { base_dir })
        }

        /// Load a note by its id.
        pub fn load_note(&self, id: &str) -> Result<crate::note::Note, StorageError> {
            let path = self.note_path(id);
            let mut file = File::open(&path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;

            // Try to parse as JSON first
            let v: Value = serde_json::from_slice(&data)?;

            // Check if the file contains an encrypted payload
            if v.get("ciphertext").is_some() {
                // Encrypted note - Return placeholder
                let created_at = if let Some(s) = v.get("created_at").and_then(|v| v.as_str()) {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now())
                } else {
                    chrono::Utc::now()
                };

                let updated_at = if let Some(s) = v.get("updated_at").and_then(|v| v.as_str()) {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now())
                } else {
                    chrono::Utc::now()
                };

                return Ok(crate::note::Note {
                    id: id.to_string(),
                    title: "🔒 Encrypted".to_string(),
                    body: "".to_string(),
                    created_at,
                    updated_at,
                    encrypted: true,
                });
            }
            let note: crate::note::Note = serde_json::from_value(v)?;
            Ok(note)
        }

        pub fn unlock_note(&self, id: &str, password: &str) -> Result<crate::note::Note, StorageError> {
            let path = self.note_path(id);
            let mut file = File::open(&path)?;
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;

            let v: Value = serde_json::from_slice(&data)?;
            
            if v.get("ciphertext").is_none() {
                // Not encrypted, just load it
                return self.load_note(id);
            }

            let salt_b64 = v.get("salt").and_then(|v| v.as_str()).ok_or_else(|| {
                StorageError::Json(serde_json::Error::custom("missing salt"))
            })?;
            let nonce_b64 = v.get("nonce").and_then(|v| v.as_str()).ok_or_else(|| {
                StorageError::Json(serde_json::Error::custom("missing nonce"))
            })?;
            let ciphertext_b64 = v.get("ciphertext").and_then(|v| v.as_str()).ok_or_else(|| {
                StorageError::Json(serde_json::Error::custom("missing ciphertext"))
            })?;

            let salt = b64_decode(salt_b64).map_err(|e| StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            let nonce = b64_decode(nonce_b64).map_err(|e| StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
            let ciphertext = b64_decode(ciphertext_b64).map_err(|e| StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

            let key = crate::crypto::derive_key(password, &salt)?;
            let plaintext = crate::crypto::decrypt(&ciphertext, &nonce, &key).map_err(StorageError::Crypto)?;

            let note: crate::note::Note = serde_json::from_slice(&plaintext)?;
            Ok(note)
        }

        /// Save a note. If `password_opt` is provided, the note will be encrypted.
        pub fn save_note(
            &self,
            note: &crate::note::Note,
            password_opt: Option<&str>,
        ) -> Result<(), StorageError> {
            let path = self.note_path(&note.id);
            if let Some(password) = password_opt {
                // Encrypt
                let mut rng = rand::thread_rng();
                let salt: [u8; 16] = rng.gen();
                let key = crate::crypto::derive_key(password, &salt)?;
                let mut note_to_encrypt = note.clone();
                note_to_encrypt.encrypted = true;
                let plaintext = serde_json::to_vec(&note_to_encrypt.to_json())?;
                let (ciphertext, nonce) = crate::crypto::encrypt(&plaintext, &key)?;
                
                let payload = json!({
                    "id": note.id,
                    "created_at": note.created_at.to_rfc3339(),
                    "updated_at": note.updated_at.to_rfc3339(),
                    "salt": b64_encode(salt),
                    "nonce": b64_encode(nonce),
                    "ciphertext": b64_encode(ciphertext)
                });
                let mut file = File::create(&path)?;
                file.write_all(&serde_json::to_vec_pretty(&payload)?)?;
            } else {
                // Plain
                let mut file = File::create(&path)?;
                file.write_all(&serde_json::to_vec_pretty(&note.to_json())?)?;
            }
            Ok(())
        }

        /// Delete a note by its id.
        pub fn delete_note(&self, id: &str) -> Result<(), StorageError> {
            let path = self.note_path(id);
            if path.exists() {
                fs::remove_file(path)?;
            }
            Ok(())
        }

        /// List all notes in the storage.
        pub fn list_notes(&self) -> Result<Vec<crate::note::Note>, StorageError> {
            let mut notes = Vec::new();
            for entry in fs::read_dir(&self.base_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                    if let Ok(note) = self.load_note(&path.file_stem().unwrap().to_string_lossy()) {
                        notes.push(note);
                    }
                }
            }
            Ok(notes)
        }

        fn note_path(&self, id: &str) -> PathBuf {
            self.base_dir.join(format!("{}.json", id))
        }
    }
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
    use std::collections::HashMap;
    use chrono::Utc;
    use crate::storage::Storage;

    /// Holds the in‑memory state of the application.
    pub struct App {
        pub notes: HashMap<String, crate::note::Note>,
        pub current_note_id: Option<String>,
        pub search_engine: crate::search::SearchEngine,
        pub storage: Storage,
        pub should_quit: bool,
        pub selected_index: usize,
        pub is_editing: bool,
        
        // Password Prompt State
        pub password_prompt_active: bool,
        pub password_buffer: String,
        pub pending_operation: Option<PendingOperation>,
        pub error_message: Option<String>,
    }

    #[derive(Clone)]
    pub enum PendingOperation {
        Unlock(String), // Note ID
        Lock(String),   // Note ID
    }

/// High‑level errors that can be surfaced to the UI.
     pub enum AppError {
         Storage(crate::storage::StorageError),
         Search,
     }

     impl std::fmt::Display for AppError {
         fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
             match self {
                 AppError::Storage(e) => write!(f, "Storage error: {}", e),
                 AppError::Search => write!(f, "Search error"),
             }
         }
     }

     impl From<crate::storage::StorageError> for AppError {
        fn from(err: crate::storage::StorageError) -> Self {
            AppError::Storage(err)
        }
    }

    impl App {
        /// Create a new `App` instance by loading all notes from the given storage.
        pub fn new(storage: Storage) -> Result<Self, AppError> {
            let notes_vec = storage.list_notes()?;
            let notes_map: HashMap<String, crate::note::Note> =
                notes_vec.iter().cloned().map(|n| (n.id.clone(), n)).collect();
            let search_engine = crate::search::SearchEngine::new(&notes_vec);
            Ok(App {
                notes: notes_map,
                current_note_id: None,
                search_engine,
                storage,
                should_quit: false,
                selected_index: 0,
                is_editing: false,
                password_prompt_active: false,
                password_buffer: String::new(),
                pending_operation: None,
                error_message: None,
            })
        }

        /// Add a new note with the given title and body.
        pub fn add_note(&mut self, title: &str, body: &str) -> Result<(), AppError> {
            let note = crate::note::Note::new(title, body);
            // Persist the new note
            self.storage_save(&note)?;
            // Insert into in‑memory map
            self.notes.insert(note.id.clone(), note);
            // Rebuild search index
            self.reindex();
            Ok(())
        }

        /// Edit an existing note identified by `id`. Only the fields provided
        /// (i.e. `Some`) are updated.
        pub fn edit_note(
            &mut self,
            id: &str,
            title: Option<&str>,
            body: Option<&str>,
        ) -> Result<(), AppError> {
            // Clone the note to avoid borrowing issues
            let mut note = self.notes.get(id).cloned().ok_or(AppError::Search)?;
            
            if let Some(t) = title {
                note.title = t.to_string();
            }
            if let Some(b) = body {
                note.body = b.to_string();
            }
            note.updated_at = Utc::now();

            // Persist changes
            self.storage_save(&note)?;
            // Rebuild search index
            self.reindex();
            
            // Update the in-memory note after reindexing
            self.notes.insert(id.to_string(), note);
            Ok(())
        }

        /// Delete the note with the given `id`.
        pub fn delete_note(&mut self, id: &str) -> Result<(), AppError> {
            // Remove from in‑memory map
            let removed = self.notes.remove(id).ok_or(AppError::Search)?;
            // Delete from storage
            self.storage_delete(&removed.id)?;
            // Rebuild search index
            self.reindex();
            Ok(())
        }

        /// Search for notes containing `term`. Returns references to matching
        /// notes.
        pub fn search(&self, term: &str) -> Vec<&crate::note::Note> {
            let ids = self.search_engine.query(term);
            ids.iter()
                .filter_map(|id| self.notes.get(id))
                .collect::<Vec<&crate::note::Note>>()
        }

        /// Reload all notes from the given storage, replacing the current state.
        pub fn load_all(&mut self) -> Result<(), AppError> {
            let notes_vec = self.storage.list_notes()?;
            self.notes.clear();
            for note in notes_vec.iter().cloned() {
                self.notes.insert(note.id.clone(), note);
            }
            self.reindex();
            Ok(())
        }

        pub fn get_sorted_note_ids(&self) -> Vec<String> {
            let mut notes: Vec<_> = self.notes.values().collect::<Vec<_>>();
            notes.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            notes.iter().map(|n| n.id.clone()).collect()
        }

        pub fn initiate_unlock(&mut self, id: &str) {
             self.pending_operation = Some(PendingOperation::Unlock(id.to_string()));
             self.password_prompt_active = true;
             self.password_buffer.clear();
             self.error_message = None;
        }

        pub fn initiate_lock(&mut self, id: &str) {
             self.pending_operation = Some(PendingOperation::Lock(id.to_string()));
             self.password_prompt_active = true;
             self.password_buffer.clear();
             self.error_message = None;
        }

        pub fn cancel_password(&mut self) {
             self.password_prompt_active = false;
             self.password_buffer.clear();
             self.pending_operation = None;
             self.error_message = None;
        }

        pub fn submit_password(&mut self) -> Result<(), AppError> {
             if let Some(op) = self.pending_operation.clone() {
                 match op {
                     PendingOperation::Unlock(id) => {
                         match self.storage.unlock_note(&id, &self.password_buffer) {
                             Ok(note) => {
                                 self.notes.insert(id, note);
                                 self.password_prompt_active = false;
                                 self.password_buffer.clear();
                                 self.pending_operation = None;
                                 self.error_message = None;
                             }
                             Err(_) => {
                                 self.error_message = Some("Incorrect password".to_string());
                                 self.password_buffer.clear();
                             }
                         }
                     }
                     PendingOperation::Lock(id) => {
                         if let Some(note) = self.notes.get(&id) {
                             // Save with password
                             if let Err(e) = self.storage.save_note(note, Some(&self.password_buffer)) {
                                 return Err(AppError::Storage(e));
                             }
                             // Reload to reflect encrypted state
                             if let Ok(note) = self.storage.load_note(&id) {
                                  self.notes.insert(id, note);
                             }
                             self.password_prompt_active = false;
                             self.password_buffer.clear();
                             self.pending_operation = None;
                             self.error_message = None;
                         }
                     }
                 }
             }
             Ok(())
        }

        // --------------------------------------------------------------------
        // Internal helpers
        // --------------------------------------------------------------------

        /// Persist a note to storage.
        fn storage_save(&self, note: &crate::note::Note) -> Result<(), AppError> {
            self.storage.save_note(note, None)?;
            Ok(())
        }

        /// Delete a note from storage.
        fn storage_delete(&self, id: &str) -> Result<(), AppError> {
            self.storage.delete_note(id)?;
            Ok(())
        }

        /// Rebuild the search index from the current notes.
        fn reindex(&mut self) {
            let notes_vec: Vec<crate::note::Note> = self.notes.values().cloned().collect();
            self.search_engine = crate::search::SearchEngine::new(&notes_vec);
        }
    }
}

pub mod ui {
    use std::io::{stdout, Stdout};

    use crossterm::{
        event::{read, Event, KeyCode, EnableBracketedPaste, DisableBracketedPaste},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Style, Modifier, Color},
        Terminal,
        widgets::{Block, Borders, List, ListItem},
    };

    /// Encapsulates the terminal backend.
    pub struct UI {
        pub terminal: Terminal<CrosstermBackend<Stdout>>,
    }

    /// Errors that can occur during rendering or input handling.
    #[derive(Debug)]
    pub enum UIError {
        Tui(String),
        Crossterm(std::io::Error),
    }

    impl std::fmt::Display for UIError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                UIError::Tui(e) => write!(f, "TUI error: {}", e),
                UIError::Crossterm(e) => write!(f, "Crossterm error: {}", e),
            }
        }
    }

    impl From<std::io::Error> for UIError {
        fn from(e: std::io::Error) -> Self {
            UIError::Crossterm(e)
        }
    }

    impl UI {
        /// Create a new `UI` instance.
        pub fn new() -> Result<Self, UIError> {
            enable_raw_mode()?;
            let mut stdout = stdout();
            execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
            let backend = CrosstermBackend::new(stdout);
            let terminal = Terminal::new(backend).map_err(|e| UIError::Tui(e.to_string()))?;
            Ok(Self { terminal })
        }

        /// Cleanup the terminal state.
        pub fn cleanup(&mut self) -> Result<(), UIError> {
            let _ = execute!(self.terminal.backend_mut(), DisableBracketedPaste);
            disable_raw_mode()?;
            execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
            self.terminal.show_cursor()?;
            Ok(())
        }

        /// Render the current state of `app` to the screen.
        pub fn render(&mut self, app: &crate::app::App) -> Result<(), UIError> {
            let mut notes = app
                .notes
                .values()
                .collect::<Vec<_>>();
            
            notes.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

            let sidebar_items = notes
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let style = if i == app.selected_index {
                        Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    let title = if n.encrypted && n.body.is_empty() {
                         format!("🔒 {}", n.id) // Or some other indicator
                    } else {
                         format!(" {}", n.title)
                    };
                    ListItem::new(title).style(style)
                })
                .collect::<Vec<_>>();

            let sidebar = List::new(sidebar_items)
                .block(Block::default().borders(Borders::ALL).title(" Notes "))
                .style(Style::default().fg(Color::White));

            let main_content = if let Some(note) = notes.get(app.selected_index) {
                let mut text = vec![
                    ratatui::text::Line::from(vec![
                        ratatui::text::Span::styled("Title: ", Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan)),
                        ratatui::text::Span::raw(&note.title),
                    ]),
                    ratatui::text::Line::from(""),
                ];

                if note.encrypted && note.body.is_empty() {
                    text.push(ratatui::text::Line::from(ratatui::text::Span::styled(
                        "This note is encrypted. Press Enter to unlock.",
                        Style::default().fg(Color::Red).add_modifier(Modifier::ITALIC),
                    )));
                } else {
                    for line in note.body.lines() {
                        text.push(ratatui::text::Line::from(line));
                    }
                }
                
                // Add a cursor-like block at the end if editing
                if app.is_editing {
                    text.push(ratatui::text::Line::from(vec![
                        ratatui::text::Span::styled("█", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK))
                    ]));
                }

                let block_title = if app.is_editing {
                    " Editing Content (Esc to save) "
                } else if note.encrypted && note.body.is_empty() {
                    " Encrypted Note "
                } else {
                    " Note Content (Enter to edit, 'l' to lock) "
                };

                let block_style = if app.is_editing {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };

                ratatui::widgets::Paragraph::new(text)
                    .block(Block::default()
                        .borders(Borders::ALL)
                        .title(block_title)
                        .border_style(block_style))
                    .wrap(ratatui::widgets::Wrap { trim: false })
            } else {
                ratatui::widgets::Paragraph::new("No note selected. Press 'n' to create one.")
                    .block(Block::default().borders(Borders::ALL).title("Note Content"))
            };

            self.terminal
                .draw(|f| {
                    let size = f.area();
                    let chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([
                            Constraint::Percentage(30),
                            Constraint::Percentage(70),
                        ].as_ref())
                        .split(size);

                    f.render_widget(sidebar, chunks[0]);
                    f.render_widget(main_content, chunks[1]);

                    if app.password_prompt_active {
                        let popup_layout = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([
                                Constraint::Percentage(40),
                                Constraint::Percentage(20),
                                Constraint::Percentage(40),
                            ].as_ref())
                            .split(size);

                        let area = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints([
                                Constraint::Percentage(30),
                                Constraint::Percentage(40),
                                Constraint::Percentage(30),
                            ].as_ref())
                            .split(popup_layout[1])[1];

                        f.render_widget(ratatui::widgets::Clear, area);
                        
                        let title = if let Some(crate::app::PendingOperation::Lock(_)) = app.pending_operation {
                            " Set Password "
                        } else {
                            " Enter Password "
                        };

                        let content = if let Some(err) = &app.error_message {
                             format!("{}\n\nPress Esc to cancel.", err)
                        } else {
                             "*".repeat(app.password_buffer.len())
                        };

                        let popup = ratatui::widgets::Paragraph::new(content)
                            .block(Block::default().borders(Borders::ALL).title(title).style(Style::default().fg(Color::Red)))
                            .wrap(ratatui::widgets::Wrap { trim: true });
                        f.render_widget(popup, area);
                    }
                })
                .map(|_| ())
                .map_err(|e| UIError::Tui(e.to_string()))
        }

        /// Handle a single user input event.
        pub fn handle_input(&mut self, app: &mut crate::app::App) -> Result<(), UIError> {
            if crossterm::event::poll(std::time::Duration::from_millis(10))? {
                let event = read().map_err(UIError::Crossterm)?;
                let sorted_ids = app.get_sorted_note_ids();

                match event {
                    Event::Key(key_event) => {
                        if app.password_prompt_active {
                             match key_event.code {
                                 KeyCode::Esc => app.cancel_password(),
                                 KeyCode::Enter => {
                                     let _ = app.submit_password();
                                 }
                                 KeyCode::Backspace => {
                                     app.password_buffer.pop();
                                 }
                                 KeyCode::Char(c) => {
                                     app.password_buffer.push(c);
                                 }
                                 _ => {}
                             }
                             return Ok(());
                        }

                        if app.is_editing {
                            if let Some(note_id) = sorted_ids.get(app.selected_index) {
                                let note_id = note_id.clone();
                                match key_event.code {
                                    KeyCode::Esc => {
                                        app.is_editing = false;
                                        // Persist when exiting edit mode
                                        if let Some(n) = app.notes.get(&note_id) {
                                            let body = n.body.clone();
                                            let _ = app.edit_note(&note_id, None, Some(&body));
                                        }
                                    }
                                    KeyCode::Char(c) => {
                                        if let Some(n) = app.notes.get_mut(&note_id) {
                                            n.body.push(c);
                                        }
                                    }
                                    KeyCode::Backspace => {
                                        if let Some(n) = app.notes.get_mut(&note_id) {
                                            n.body.pop();
                                        }
                                    }
                                    KeyCode::Enter => {
                                        if let Some(n) = app.notes.get_mut(&note_id) {
                                            n.body.push('\n');
                                        }
                                    }
                                    _ => {}
                                }
                            } else {
                                app.is_editing = false;
                            }
                        } else {
                            match key_event.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    app.should_quit = true;
                                }
                                KeyCode::Char('n') => {
                                    let _ = app.add_note("New Note", "");
                                    app.selected_index = 0;
                                }
                                KeyCode::Char('d') => {
                                    if let Some(note_id) = sorted_ids.get(app.selected_index) {
                                        let _ = app.delete_note(note_id);
                                        if app.selected_index > 0 {
                                            app.selected_index -= 1;
                                        }
                                    }
                                }
                                KeyCode::Char('l') => {
                                     if let Some(note_id) = sorted_ids.get(app.selected_index) {
                                         app.initiate_lock(note_id);
                                     }
                                }
                                KeyCode::Up => {
                                    if app.selected_index > 0 {
                                        app.selected_index -= 1;
                                    }
                                }
                                KeyCode::Down => {
                                    if app.selected_index + 1 < sorted_ids.len() {
                                        app.selected_index += 1;
                                    }
                                }
                                KeyCode::Enter => {
                                    if let Some(note_id) = sorted_ids.get(app.selected_index) {
                                        if let Some(note) = app.notes.get(note_id) {
                                            if note.encrypted && note.body.is_empty() {
                                                app.initiate_unlock(note_id);
                                            } else {
                                                app.is_editing = true;
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Event::Paste(content) => {
                        if app.is_editing {
                            if let Some(note_id) = sorted_ids.get(app.selected_index) {
                                if let Some(n) = app.notes.get_mut(note_id) {
                                    n.body.push_str(&content);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            Ok(())
        }
    }
}

pub mod main {
    use std::error::Error;
    use crate::{
        storage::Storage,
        app::App,
        ui::UI,
    };

    /// Initializes storage, app state and runs the UI loop.
    pub fn main() -> Result<(), Box<dyn Error>> {
        // Create storage backend
        let storage = Storage::new()
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

        // Load all notes into the application state
        let mut app = App::new(storage)
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

        // Create the UI
        let mut ui = UI::new()
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

        // Main event loop
        loop {
            // Render the UI; propagate any rendering errors
            ui.render(&app)
                .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

            // Handle user input; break on error (e.g., exit command)
            match ui.handle_input(&mut app) {
                Ok(_) => {}
                Err(e) => {
                    let _ = ui.cleanup();
                    return Err(Box::<dyn Error>::from(e.to_string()));
                }
            }

            if app.should_quit {
                break;
            }
        }

        ui.cleanup().map_err(|e| Box::<dyn Error>::from(e.to_string()))?;
        Ok(())
    }
}

fn main() {
    if let Err(e) = crate::main::main() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}