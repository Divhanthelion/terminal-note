# TerminalNote

A terminal-based notes application (TUI) written in Rust with a clean interface inspired by Apple Notes.

## Features

- 📝 **Markdown editing** (planned)
- - 🔒 **AES-256-GCM encryption** with Argon2 key derivation
  - - 🔍 **Full-text search** with inverted index
    - - 💾 **Auto-save** to individual JSON files
      - - 🎨 **Clean TUI interface** built with Ratatui
       
        - ## Core Technologies
       
        - - **Rust** - Language
          - - **Ratatui** - TUI framework
            - - **Crossterm** - Terminal backend and event handling
              - - **AES-GCM & Argon2** - Cryptographic primitives
                - - **Serde** - Serialization/Deserialization
                  - - **Chrono** - Time management
                   
                    - ## Architecture
                   
                    - The project follows a modular design within `src/main.rs`:
                   
                    - - **crypto** - Handles encryption, decryption, and key derivation
                      - - **note** - Defines the Note struct and JSON serialization logic
                        - - **storage** - Manages disk I/O, saving and loading notes from `./notes/`
                          - - **search** - Implements a simple inverted index for full-text search
                            - - **app** - Maintains the in-memory state of the application
                              - - **ui** - Handles terminal rendering and user input
                               
                                - ## Building and Running
                               
                                - ### Prerequisites
                               
                                - - Rust (Cargo)
                                 
                                  - ### Key Commands
                                 
                                  - ```bash
                                    # Run the application
                                    cargo run

                                    # Build release version
                                    cargo build --release

                                    # Run tests (Note: Tests are not yet implemented)
                                    cargo test
                                    ```

                                    ## Usage

                                    | Key | Action |
                                    |-----|--------|
                                    | `n` | Create a new placeholder note |
                                    | `Enter` | Edit the selected note |
                                    | `l` | Lock (encrypt) the selected note |
                                    | `Enter` (on locked note) | Unlock note (requires password) |
                                    | `q` or `Esc` | Exit the application |

                                    Notes are automatically persisted to the `./notes/` directory.

                                    ## Development Conventions

                                    ### TUI Management
                                    Always ensure `enable_raw_mode` and `EnterAlternateScreen` are called on startup, and their counterparts are called on cleanup.

                                    ### Persistence
                                    All notes are stored as individual `.json` files in the `./notes` directory.

                                    ### Error Handling
                                    Use custom Error enums (`StorageError`, `UIError`, `AppError`) to wrap lower-level errors.

                                    ### Search
                                    The search engine must be re-indexed whenever notes are added, edited, or deleted.
