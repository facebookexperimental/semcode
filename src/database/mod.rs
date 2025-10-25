// SPDX-License-Identifier: MIT OR Apache-2.0
pub mod batch_processing;
pub mod calls;
mod connection;
pub mod content;
mod functions;
pub mod processed_files;
mod schema;
pub mod search;
pub mod sql_utils;
mod symbol_filename;
mod types;
mod vectors;

pub use connection::DatabaseManager;
// Re-export commonly used items if needed
