//! Program model shared by every crate in the workspace.
//!
//! This is the Rust counterpart of the subset of Ghidra's `Program` API
//! (`Memory`, `SymbolTable`, `FunctionManager`, `ReferenceManager`, `Listing`)
//! that auto-analysis needs. It is intentionally in-memory only.

pub mod hex;
pub mod memory;
pub mod report;

pub use memory::{MemoryBlock, MemoryMap, Perms};
pub use report::*;
