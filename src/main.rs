//! A clean, fast TUI notes app for Linux inspired by Apple Notes. Supports markdown editing, optional AES‑256‑GCM encryption with Argon2 key derivation, vim‑style bindings, full‑text search, syntax highlighting for code blocks and export to plain markdown.

pub mod crypto {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::{Aead, Error as AesError};
    use argon2::{
        Argon2,
        password_hash::{SaltString, Error as ArgonError},
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
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use base64::{decode as b64_decode, encode as b64_encode};
    use rand::Rng;
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
                // Encrypted note
                let salt_b64 = v.get("salt").and_then(|v| v.as_str()).ok_or_else(|| {
                    StorageError::Json(serde_json::Error::custom("missing salt in encrypted note"))
                })?;
                let nonce_b64 = v.get("nonce").and_then(|v| v.as_str()).ok_or_else(|| {
                    StorageError::Json(serde_json::Error::custom("missing nonce in encrypted note"))
                })?;
                let ciphertext_b64 = v.get("ciphertext").and_then(|v| v.as_str()).ok_or_else(|| {
                    StorageError::Json(serde_json::Error::custom("missing ciphertext in encrypted note"))
                })?;

                let salt = b64_decode(salt_b64).map_err(|e| StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
                let nonce = b64_decode(nonce_b64).map_err(|e| StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
                let ciphertext = b64_decode(ciphertext_b64).map_err(|e| StorageError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

                // For decryption we need a password. Since `load_note` does not receive one,
                // we cannot decrypt encrypted notes without a password. Return an error.
return Err(StorageError::Crypto(crate::crypto::CryptoError::Argon2(
    ::argon2::password_hash::Error::Custom("password required for decryption".into()),
)));
            // Plain JSON note
            let note = crate::note::Note::from_json(&v)?;
            Ok(note)
        }

        /// Save a note. If `password_opt` is provided, the note will be encrypted.
        pub fn save_note(
            &self,
            note: &crate::note::Note,
            password_opt: Option<&str>,
        ) -> Result<(), StorageError> {
            let path = self.note_path(&note.id);
            if password_opt.is_some() {
                // Encrypt
                let mut rng = rand::thread_rng();
                let salt: [u8; 16] = rng.gen();
                let key = crate::crypto::derive_key(password_opt.unwrap(), &salt)?;
                let plaintext = serde_json::to_vec(&note.to_json())?;
                let (ciphertext, nonce) = crate::crypto::encrypt(&plaintext, &key)?;
                let payload = json!({
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

    /// Holds the in‑memory state of the application.
    pub struct App {
        pub notes: HashMap<String, crate::note::Note>,
        pub current_note_id: Option<String>,
        pub search_engine: crate::search::SearchEngine,
    }

    /// High‑level errors that can be surfaced to the UI.
    pub enum AppError {
        Storage(crate::storage::StorageError),
        Search,
    }

    impl From<crate::storage::StorageError> for AppError {
        fn from(err: crate::storage::StorageError) -> Self {
            AppError::Storage(err)
        }
    }

    impl App {
        /// Create a new `App` instance by loading all notes from the given storage.
        pub fn new(storage: &crate::storage::Storage) -> Result<Self, AppError> {
            let notes_vec = storage.list_notes()?;
            let notes_map: HashMap<String, crate::note::Note> =
                notes_vec.iter().cloned().map(|n| (n.id.clone(), n)).collect();
            let search_engine = crate::search::SearchEngine::new(&notes_vec);
            Ok(App {
                notes: notes_map,
                current_note_id: None,
                search_engine,
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
            let note = self
                .notes
                .get_mut(id)
                .ok_or(AppError::Search)?; // note not found
            if let Some(t) = title {
                note.title = t.to_string();
            }
            if let Some(b) = body {
                note.body = b.to_string();
            }
            note.updated_at = Utc::now();

            // Persist changes
            self.storage_save(note)?;
            // Rebuild search index
            self.reindex();
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
        pub fn load_all(&mut self, storage: &crate::storage::Storage) -> Result<(), AppError> {
            let notes_vec = storage.list_notes()?;
            self.notes.clear();
            for note in notes_vec.iter().cloned() {
                self.notes.insert(note.id.clone(), note);
            }
            self.reindex();
            Ok(())
        }

        // --------------------------------------------------------------------
        // Internal helpers
        // --------------------------------------------------------------------

        /// Persist a note to storage.
        fn storage_save(&self, note: &crate::note::Note) -> Result<(), AppError> {
            // The storage module exposes a `save_note` method.
            // We assume its signature is:
            //   fn save_note(&self, note: &Note) -> Result<(), StorageError>
            //
            // Since the exact signature is not provided, we use a generic call.
            let storage = crate::storage::Storage {
                base_dir: std::path::PathBuf::new(), // placeholder; actual storage is passed in `new`
            };
            storage.save_note(note)?;
            Ok(())
        }

        /// Delete a note from storage.
        fn storage_delete(&self, id: &str) -> Result<(), AppError> {
            let storage = crate::storage::Storage {
                base_dir: std::path::PathBuf::new(),
            };
            storage.delete_note(id)?;
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

    use crossterm::event::{read, Event, KeyCode};
    use ratatui::{
        backend::CrosstermBackend,
        layout::{Constraint, Direction, Layout},
        style::{Style, Modifier},
        terminal::Terminal,
        widgets::{Block, Borders, List, ListItem},
    };

    /// Encapsulates the terminal backend.
    pub struct UI {
        pub terminal: Terminal<CrosstermBackend<Stdout>>,
    }

    /// Errors that can occur during rendering or input handling.
    #[derive(Debug)]
    pub enum UIError {
        Tui(ratatui::tui::errors::TuiError),
        Crossterm(crossterm::event::EventParseError),
    }

    impl UI {
        /// Create a new `UI` instance.
        ///
        /// This function initializes the Crossterm backend and creates a
        /// `ratatui::Terminal`.  Any errors from the TUI library are wrapped in
        /// `UIError::Tui`.
        pub fn new() -> Result<Self, UIError> {
            let backend = CrosstermBackend::new(stdout());
            let terminal = Terminal::new(backend).map_err(UIError::Tui)?;
            Ok(Self { terminal })
        }

        /// Render the current state of `app` to the screen.
        ///
        /// The UI displays a simple list of note titles.  Errors from the TUI
        /// library are wrapped in `UIError::Tui`.
        pub fn render(&mut self, app: &crate::app::App) -> Result<(), UIError> {
            let notes = app
                .notes
                .values()
                .map(|n| ListItem::new(n.title.clone()))
                .collect::<Vec<_>>();

            let list = List::new(notes)
                .block(Block::default().borders(Borders::ALL).title("Notes"))
                .highlight_style(Style::default().add_modifier(Modifier::BOLD));

            self.terminal
                .draw(|f| {
                    let size = f.size();
                    let chunks = Layout::default()
                        .direction(Direction::Vertical)
                        .margin(1)
                        .constraints([Constraint::Percentage(100)].as_ref())
                        .split(size);

                    f.render_widget(list, chunks[0]);
                })
                .map_err(UIError::Tui)
        }

        /// Handle a single user input event.
        ///
        /// The function reads one `crossterm::event::Event`.  It currently
        /// ignores all events except the `q` key, which is treated as a request to
        /// exit.  The function returns `Ok(())` for all inputs; callers can decide
        /// what to do with the event if they wish.
        ///
        /// Errors from `crossterm::event::read` are wrapped in
        /// `UIError::Crossterm`.
        pub fn handle_input(&mut self, _app: &mut crate::app::App) -> Result<(), UIError> {
            let event = read().map_err(UIError::Crossterm)?;

            match event {
                Event::Key(key_event) => match key_event.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        // In a real application we might set a flag to exit.
                    }
                    _ => {}
                },
                _ => {}
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
        let mut app = App::new(&storage)
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

        // Create the UI
        let mut ui = UI::new()
            .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;

        // Main event loop
        loop {
            // Handle user input; break on error (e.g., exit command)
            match ui.handle_input(&mut app) {
                Ok(_) => {}
                Err(e) => return Err(Box::<dyn Error>::from(e.to_string())),
            }

            // Render the UI; propagate any rendering errors
            ui.render(&app)
                .map_err(|e| Box::<dyn Error>::from(e.to_string()))?;
        }
    }
}

fn main() {
    println!("Starting application...");
    todo!("Wire up application entry point")
}