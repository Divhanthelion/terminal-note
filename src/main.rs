//! A clean, fast TUI notes app for Linux inspired by Apple Notes. Supports markdown editing, optional AES‑256‑GCM encryption with Argon2 key derivation, vim‑style bindings, full‑text search, syntax highlighting for code blocks and export to plain markdown.

pub mod crypto {
    //! Provides key derivation, encryption and decryption utilities.
    todo!()
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
