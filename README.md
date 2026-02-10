Project Overview
TerminalNote is a terminal-based notes application (TUI) written in Rust. It features a clean interface inspired by Apple Notes, supporting Markdown editing (planned), AES-256-GCM encryption with Argon2 key derivation, and full-text search.

Core Technologies
Rust: Language
Ratatui: TUI framework
Crossterm: Terminal backend and event handling
AES-GCM & Argon2: Cryptographic primitives
Serde: Serialization/Deserialization
Chrono: Time management
Architecture
The project follows a modular design within src/main.rs:

crypto: Handles encryption, decryption, and key derivation.
note: Defines the Note struct and JSON serialization logic.
storage: Manages disk I/O, saving and loading notes from ./notes/.
search: Implements a simple inverted index for full-text search.
app: Maintains the in-memory state of the application.
ui: Handles terminal rendering and user input.
Building and Running
Prerequisites
Rust (Cargo)
Key Commands
Run: cargo run
Build: cargo build --release
Test: cargo test (Note: Tests are not yet implemented in the current version)
Development Conventions
TUI Management: Always ensure enable_raw_mode and EnterAlternateScreen are called on startup, and their counterparts are called on cleanup.
Persistence: All notes are stored as individual .json files in the ./notes directory.
Error Handling: Use custom Error enums (StorageError, UIError, AppError) to wrap lower-level errors.
Search: The search engine must be re-indexed whenever notes are added, edited, or deleted.
Usage
Press n to create a new placeholder note.
Press q or Esc to exit the application.
Press Enter to edit a note.
Press l to lock (encrypt) the selected note.
Press Enter on a locked note to unlock it (requires password).
Notes are automatically persisted to the ./notes/ directory.
