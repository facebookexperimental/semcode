// SPDX-License-Identifier: MIT OR Apache-2.0
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String, // Git hash of the file content as hex string
    pub line_start: u32,
    pub line_end: u32,
    pub return_type: String,
    pub parameters: Vec<ParameterInfo>,
    pub body: String,
    #[serde(default)]
    pub calls: Option<Vec<String>>, // Function names called by this function
    #[serde(default)]
    pub types: Option<Vec<String>>, // Type names used by this function
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterInfo {
    pub name: String,      // Parameter name (e.g., "buffer")
    pub type_name: String, // Type name (e.g., "struct buffer_head")
    #[serde(default)]
    pub type_file_path: Option<String>, // File where type is defined
    #[serde(default)]
    pub type_git_file_hash: Option<String>, // Hash of file containing type definition
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeInfo {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String, // Git hash of the file content as hex string
    pub line_start: u32,
    pub kind: String,
    pub size: Option<u64>,
    pub members: Vec<FieldInfo>,
    pub definition: String, // Added to store raw type definition with comments
    #[serde(default)]
    pub types: Option<Vec<String>>, // Type names referenced by this type
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub type_name: String,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedefInfo {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String, // Git hash of the file content as hex string
    pub line_start: u32,
    pub underlying_type: String,
    pub definition: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroInfo {
    pub name: String,
    pub file_path: String,
    pub git_file_hash: String, // Git hash of the file content as hex string
    pub line_start: u32,
    pub is_function_like: bool,
    pub parameters: Option<Vec<String>>,
    pub definition: String,
    #[serde(default)]
    pub calls: Option<Vec<String>>, // Function names called by this macro
    #[serde(default)]
    pub types: Option<Vec<String>>, // Type names used by this macro
}

/// Git commit metadata with changed symbols
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCommitInfo {
    pub git_sha: String,                    // The commit SHA
    pub parent_sha: Vec<String>,            // Parent commit SHAs (multiple for merges)
    pub author: String,                     // Author name and email
    pub subject: String,                    // Single line commit title
    pub message: String,                    // Full commit message
    pub tags: HashMap<String, Vec<String>>, // Tags from commit message (Signed-off-by:, etc.)
    pub diff: String,                       // Full unified diff
    pub symbols: Vec<String>,               // Changed symbols (filename:symbol() format)
}

/// Global type registry for cross-file type resolution
#[derive(Debug, Clone)]
pub struct GlobalTypeRegistry {
    /// Map from type name to type information
    pub types: HashMap<String, TypeInfo>,
    /// Map from typedef name to typedef information
    pub typedefs: HashMap<String, TypedefInfo>,
}

impl Default for GlobalTypeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalTypeRegistry {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            typedefs: HashMap::new(),
        }
    }

    /// Register types from analysis results
    pub fn register_types(&mut self, types: Vec<TypeInfo>, typedefs: Vec<TypedefInfo>) {
        for type_info in types {
            self.types.insert(type_info.name.clone(), type_info);
        }
        for typedef_info in typedefs {
            self.typedefs
                .insert(typedef_info.name.clone(), typedef_info);
        }
    }

    /// Look up type information by name, checking both types and typedefs
    pub fn lookup_type(&self, type_name: &str) -> Option<(String, String)> {
        // Remove common type prefixes and suffixes for lookup
        let cleaned_name = self.clean_type_name(type_name);

        // First check direct types
        if let Some(type_info) = self.types.get(&cleaned_name) {
            return Some((type_info.file_path.clone(), type_info.git_file_hash.clone()));
        }

        // Then check typedefs
        if let Some(typedef_info) = self.typedefs.get(&cleaned_name) {
            return Some((
                typedef_info.file_path.clone(),
                typedef_info.git_file_hash.clone(),
            ));
        }

        None
    }

    /// Clean type name by removing common C/C++ type decorations
    fn clean_type_name(&self, type_name: &str) -> String {
        let cleaned = type_name
            .trim()
            .replace("const ", "")
            .replace("volatile ", "")
            .replace("static ", "")
            .replace("extern ", "")
            .replace("inline ", "")
            .replace(" *", "")
            .replace("*", "")
            .replace(" &", "")
            .replace("&", "")
            .trim()
            .to_string();

        // Handle array syntax like "char[256]" or "unsigned long [ 2 ]"
        if let Some(bracket_pos) = cleaned.find('[') {
            cleaned[..bracket_pos].trim().to_string()
        } else {
            cleaned
        }
    }
}

/// Represents a file from a git commit stored in a temporary file
#[derive(Debug, Clone)]
pub struct GitFileEntry {
    pub relative_path: std::path::PathBuf,
    pub blob_id: String,
    pub temp_file_path: std::path::PathBuf,
}

impl GitFileEntry {
    /// Manually clean up the temporary file
    pub fn cleanup(&self) -> std::io::Result<()> {
        if self.temp_file_path.exists() {
            std::fs::remove_file(&self.temp_file_path)?;
        }
        Ok(())
    }
}

impl Drop for GitFileEntry {
    fn drop(&mut self) {
        // Best effort cleanup - don't panic on errors
        if self.temp_file_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.temp_file_path) {
                tracing::warn!(
                    "Failed to cleanup temp file {}: {}",
                    self.temp_file_path.display(),
                    e
                );
            }
        }
    }
}

/// Lightweight reference to a git file for on-demand loading
#[derive(Debug, Clone)]
pub struct GitFileManifestEntry {
    pub relative_path: std::path::PathBuf,
    pub object_id: gix::ObjectId,
}
