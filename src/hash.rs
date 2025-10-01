// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use std::path::Path;

/// Compute git hash of file as hex string
pub fn compute_file_hash(file_path: &Path) -> Result<Option<String>> {
    crate::git::get_git_file_hash(file_path)
}

/// Compute git hash of string content as hex string
/// For content that's not in a file, we use SHA-1 which is git's hash algorithm
pub fn compute_content_hash(content: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute blake3 hash of content for deduplication
/// Blake3 is faster than SHA-1 and provides better collision resistance for content deduplication
pub fn compute_blake3_hash(content: &str) -> String {
    hex::encode(blake3::hash(content.as_bytes()).as_bytes())
}

// Conversion functions removed - we now work directly with hex strings
