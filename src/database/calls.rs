// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Call relationships are now embedded in function/macro JSON columns.
// This file contains only legacy struct definitions still used by TreeSitter analyzer.
// The CallStore class and calls table operations have been removed.

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CallRelationship {
    pub caller: String,
    pub callee: String,
    pub caller_git_file_hash: String, // Git hash of the caller's file as hex string
    pub callee_git_file_hash: Option<String>, // Git hash of the callee's file as hex string (None if not resolved yet)
}

// CallStore class and all methods removed - call relationships are now embedded in function JSON columns
