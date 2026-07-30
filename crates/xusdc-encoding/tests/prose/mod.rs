//! The prose gate's shared modules, wired into `comment_prose_quality.rs` with `#[path]`.
//!
//! `extract` reads comments out of source; `text` turns them into words and scores. The rules and
//! their tests stay in the test file itself, so the gate reads as one list of properties.

pub mod extract;
pub mod rules;
pub mod text;
