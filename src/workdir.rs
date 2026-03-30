// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory index of uncommitted working directory changes.
//!
//! This module detects files that differ from the HEAD commit (modified, new, or deleted)
//! and analyzes them with tree-sitter to produce an in-memory overlay of functions, types,
//! and macros. The overlay can be composed with database lookups to query uncommitted state.

use anyhow::Result;
use gix::bstr::ByteSlice;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::file_extensions::is_supported_for_analysis;
use crate::hash::compute_blake3_hash;
use crate::treesitter_analyzer::TreeSitterAnalyzer;
use crate::types::{FunctionInfo, TypeInfo};

/// In-memory index of functions, types, and macros extracted from uncommitted working
/// directory changes. Built by scanning dirty files and analyzing them with tree-sitter.
pub struct WorkdirIndex {
    /// Functions from dirty files, keyed by name (lowercase for case-insensitive lookup)
    functions: HashMap<String, Vec<FunctionInfo>>,
    /// Types from dirty files, keyed by name (lowercase)
    types: HashMap<String, Vec<TypeInfo>>,
    /// Macros from dirty files, keyed by name (lowercase)
    macros: HashMap<String, Vec<FunctionInfo>>,
    /// Dirty file manifest: relative file_path -> blake3 content hash
    dirty_manifest: HashMap<String, String>,
    /// Files tracked in HEAD but deleted in the working directory
    deleted_files: HashSet<String>,
}

/// Classification of a file's working directory status
#[derive(Debug)]
enum DirtyStatus {
    /// File is modified (exists in HEAD and working directory with different content)
    Modified,
    /// File is new (exists in working directory but not in HEAD)
    New,
}

/// A file that differs from HEAD
#[derive(Debug)]
struct DirtyFile {
    /// Relative path within the repository
    relative_path: String,
    /// Full absolute path on disk
    absolute_path: std::path::PathBuf,
    /// How this file differs from HEAD
    _status: DirtyStatus,
}

impl WorkdirIndex {
    /// Build a WorkdirIndex by scanning the working directory for uncommitted changes.
    ///
    /// This detects modified, new, and deleted files by comparing the working directory
    /// against the HEAD commit tree. Files with supported extensions are analyzed with
    /// tree-sitter and their extracted symbols are stored in memory.
    pub fn build(repo_path: &Path) -> Result<Self> {
        let repo = gix::discover(repo_path)?;
        let workdir = repo
            .workdir()
            .ok_or_else(|| anyhow::anyhow!("Cannot index bare repository"))?
            .to_path_buf();

        // Build HEAD tree manifest: relative_path -> git blob OID as hex
        let mut head_files: HashMap<String, String> = HashMap::new();
        if let Ok(head_commit) = repo.head_commit() {
            if let Ok(tree) = head_commit.tree() {
                use gix::traverse::tree::Recorder;
                let mut recorder = Recorder::default();
                if tree.traverse().breadthfirst(&mut recorder).is_ok() {
                    for entry in &recorder.records {
                        if entry.mode.is_blob() {
                            let path = entry.filepath.to_str_lossy();
                            head_files.insert(path.to_string(), entry.oid.to_string());
                        }
                    }
                }
            }
        }

        // Scan working directory for supported files
        let mut workdir_files: HashMap<String, std::path::PathBuf> = HashMap::new();
        Self::walk_directory(&workdir, &workdir, &mut workdir_files)?;

        // Classify files
        let mut dirty_files: Vec<DirtyFile> = Vec::new();
        let mut deleted_files: HashSet<String> = HashSet::new();
        let mut dirty_manifest: HashMap<String, String> = HashMap::new();

        // Check for modified and new files
        for (rel_path, abs_path) in &workdir_files {
            let content = match std::fs::read_to_string(abs_path) {
                Ok(c) => c,
                Err(_) => continue, // Skip binary or unreadable files
            };
            let content_hash = compute_blake3_hash(&content);

            if let Some(head_oid) = head_files.get(rel_path) {
                // File exists in HEAD — check if content differs
                // Read blob from HEAD and compare via blake3
                let head_content_hash = Self::blob_blake3_hash(&repo, head_oid);
                if head_content_hash.as_deref() != Some(content_hash.as_str()) {
                    dirty_manifest.insert(rel_path.clone(), content_hash);
                    dirty_files.push(DirtyFile {
                        relative_path: rel_path.clone(),
                        absolute_path: abs_path.clone(),
                        _status: DirtyStatus::Modified,
                    });
                }
            } else {
                // File not in HEAD — it's new/untracked
                dirty_manifest.insert(rel_path.clone(), content_hash);
                dirty_files.push(DirtyFile {
                    relative_path: rel_path.clone(),
                    absolute_path: abs_path.clone(),
                    _status: DirtyStatus::New,
                });
            }
        }

        // Check for deleted files (in HEAD but not in working directory)
        for rel_path in head_files.keys() {
            if !workdir_files.contains_key(rel_path) && is_supported_for_analysis(rel_path) {
                deleted_files.insert(rel_path.clone());
            }
        }

        // Analyze dirty files with tree-sitter
        let mut functions: HashMap<String, Vec<FunctionInfo>> = HashMap::new();
        let mut types: HashMap<String, Vec<TypeInfo>> = HashMap::new();
        let mut macros: HashMap<String, Vec<FunctionInfo>> = HashMap::new();

        let mut analyzer = TreeSitterAnalyzer::new()?;
        let source_root = Some(workdir.as_path());

        for dirty_file in &dirty_files {
            let content = match std::fs::read_to_string(&dirty_file.absolute_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let content_hash = dirty_manifest
                .get(&dirty_file.relative_path)
                .expect("dirty file must have a manifest entry");
            let file_path = Path::new(&dirty_file.relative_path);

            match analyzer.analyze_source_with_metadata(
                &content,
                file_path,
                content_hash,
                source_root,
            ) {
                Ok((file_functions, file_types, file_macros)) => {
                    for func in file_functions {
                        functions
                            .entry(func.name.to_lowercase())
                            .or_default()
                            .push(func);
                    }
                    for ty in file_types {
                        types.entry(ty.name.to_lowercase()).or_default().push(ty);
                    }
                    for mac in file_macros {
                        macros.entry(mac.name.to_lowercase()).or_default().push(mac);
                    }
                }
                Err(e) => {
                    tracing::info!(
                        "Failed to analyze dirty file {}: {}",
                        dirty_file.relative_path,
                        e
                    );
                }
            }
        }

        Ok(Self {
            functions,
            types,
            macros,
            dirty_manifest,
            deleted_files,
        })
    }

    /// Produce a merged manifest combining a HEAD manifest with working directory overrides.
    ///
    /// - Modified/new files: use the blake3 content hash from the dirty manifest
    /// - Deleted files: removed from the result
    /// - Clean files: pass through from `head_manifest` unchanged
    pub fn merged_manifest(
        &self,
        head_manifest: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        let mut merged = head_manifest.clone();

        // Remove deleted files
        for path in &self.deleted_files {
            merged.remove(path);
        }

        // Override with dirty file hashes
        for (path, hash) in &self.dirty_manifest {
            merged.insert(path.clone(), hash.clone());
        }

        merged
    }

    /// Find a function by exact name in the working directory overlay.
    /// Returns the best match if multiple definitions exist (prefers .c over .h, longer body).
    pub fn find_function(&self, name: &str) -> Option<&FunctionInfo> {
        let key = name.to_lowercase();
        // Check functions first, then macros
        self.functions
            .get(&key)
            .and_then(|v| Self::best_function(v))
            .or_else(|| self.macros.get(&key).and_then(|v| Self::best_function(v)))
    }

    /// Find all functions matching a name (exact, case-insensitive).
    /// Includes both functions and macros.
    pub fn find_all_functions(&self, name: &str) -> Vec<&FunctionInfo> {
        let key = name.to_lowercase();
        let mut results: Vec<&FunctionInfo> = Vec::new();
        if let Some(funcs) = self.functions.get(&key) {
            results.extend(funcs.iter());
        }
        if let Some(macs) = self.macros.get(&key) {
            results.extend(macs.iter());
        }
        results
    }

    /// Find functions matching a regex pattern.
    pub fn find_functions_regex(&self, pattern: &str) -> Vec<&FunctionInfo> {
        let re = match Regex::new(&format!("(?i){}", pattern)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut results = Vec::new();
        for (name, funcs) in &self.functions {
            if re.is_match(name) {
                results.extend(funcs.iter());
            }
        }
        for (name, macs) in &self.macros {
            if re.is_match(name) {
                results.extend(macs.iter());
            }
        }
        results
    }

    /// Find a type by exact name in the working directory overlay.
    pub fn find_type(&self, name: &str) -> Option<&TypeInfo> {
        let key = name.to_lowercase();
        self.types.get(&key).and_then(|v| v.first())
    }

    /// Find all types matching a name (exact, case-insensitive).
    pub fn find_all_types(&self, name: &str) -> Vec<&TypeInfo> {
        let key = name.to_lowercase();
        self.types
            .get(&key)
            .map_or(Vec::new(), |v| v.iter().collect())
    }

    /// Find types matching a regex pattern.
    pub fn find_types_regex(&self, pattern: &str) -> Vec<&TypeInfo> {
        let re = match Regex::new(&format!("(?i){}", pattern)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let mut results = Vec::new();
        for (name, tys) in &self.types {
            if re.is_match(name) {
                results.extend(tys.iter());
            }
        }
        results
    }

    /// Grep function bodies with a regex pattern, optionally filtering by file path.
    pub fn grep_functions(&self, pattern: &str, path_pattern: Option<&str>) -> Vec<&FunctionInfo> {
        let body_re = match Regex::new(&format!("(?i){}", pattern)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        let path_re = path_pattern.and_then(|p| Regex::new(&format!("(?i){}", p)).ok());

        let mut results = Vec::new();
        let all_funcs = self.functions.values().chain(self.macros.values());
        for funcs in all_funcs {
            for func in funcs {
                if let Some(ref pre) = path_re {
                    if !pre.is_match(&func.file_path) {
                        continue;
                    }
                }
                if body_re.is_match(&func.body) {
                    results.push(func);
                }
            }
        }
        results
    }

    /// Find functions in dirty files that call the given function name.
    pub fn find_callers(&self, name: &str) -> Vec<&FunctionInfo> {
        let target = name.to_lowercase();
        let mut results = Vec::new();
        let all_funcs = self.functions.values().chain(self.macros.values());
        for funcs in all_funcs {
            for func in funcs {
                if let Some(ref calls) = func.calls {
                    if calls.iter().any(|c| c.to_lowercase() == target) {
                        results.push(func);
                    }
                }
            }
        }
        results
    }

    /// Get the callees of a function in the dirty overlay.
    pub fn find_callees(&self, name: &str) -> Option<Vec<String>> {
        self.find_function(name).and_then(|f| f.calls.clone())
    }

    /// Check if a file path has uncommitted changes.
    pub fn is_dirty(&self, file_path: &str) -> bool {
        self.dirty_manifest.contains_key(file_path)
    }

    /// Check if a file was deleted in the working directory.
    pub fn is_deleted(&self, file_path: &str) -> bool {
        self.deleted_files.contains(file_path)
    }

    /// Returns true if no dirty files were detected.
    pub fn is_empty(&self) -> bool {
        self.dirty_manifest.is_empty() && self.deleted_files.is_empty()
    }

    /// Number of dirty files indexed.
    pub fn dirty_file_count(&self) -> usize {
        self.dirty_manifest.len()
    }

    /// Number of deleted files detected.
    pub fn deleted_file_count(&self) -> usize {
        self.deleted_files.len()
    }

    /// Number of functions (including macros) in the overlay.
    pub fn function_count(&self) -> usize {
        self.functions.values().map(|v| v.len()).sum::<usize>()
            + self.macros.values().map(|v| v.len()).sum::<usize>()
    }

    /// Number of types in the overlay.
    pub fn type_count(&self) -> usize {
        self.types.values().map(|v| v.len()).sum::<usize>()
    }

    /// Get the set of file paths that are dirty (modified or new).
    pub fn dirty_file_paths(&self) -> &HashMap<String, String> {
        &self.dirty_manifest
    }

    /// Get the set of deleted file paths.
    pub fn deleted_file_paths(&self) -> &HashSet<String> {
        &self.deleted_files
    }

    /// Iterator over all functions and macros in the overlay.
    pub fn all_functions_iter(&self) -> impl Iterator<Item = &FunctionInfo> {
        self.functions
            .values()
            .flatten()
            .chain(self.macros.values().flatten())
    }

    /// Iterator over all types in the overlay.
    pub fn all_types_iter(&self) -> impl Iterator<Item = &TypeInfo> {
        self.types.values().flatten()
    }

    // --- Private helpers ---

    /// Walk a directory recursively, collecting files with supported extensions.
    fn walk_directory(
        root: &Path,
        dir: &Path,
        files: &mut HashMap<String, std::path::PathBuf>,
    ) -> Result<()> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return Ok(()), // Skip unreadable directories
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();

            // Skip hidden directories and common non-source directories
            if name_str.starts_with('.') || name_str == "target" || name_str == "node_modules" {
                continue;
            }

            if path.is_dir() {
                Self::walk_directory(root, &path, files)?;
            } else if path.is_file() {
                let rel_path = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                if is_supported_for_analysis(&rel_path) {
                    files.insert(rel_path, path);
                }
            }
        }
        Ok(())
    }

    /// Compute blake3 hash of a git blob's content by its OID.
    fn blob_blake3_hash(repo: &gix::Repository, oid_hex: &str) -> Option<String> {
        let oid = gix::ObjectId::from_hex(oid_hex.as_bytes()).ok()?;
        let object = repo.find_object(oid).ok()?;
        let content = object.data.as_bstr().to_str().ok()?;
        Some(compute_blake3_hash(content))
    }

    /// Select the best function from multiple matches (prefers .c over .h, longer body).
    fn best_function(matches: &[FunctionInfo]) -> Option<&FunctionInfo> {
        if matches.is_empty() {
            return None;
        }
        if matches.len() == 1 {
            return Some(&matches[0]);
        }
        matches.iter().max_by(|a, b| {
            let a_is_source = a.file_path.ends_with(".c");
            let b_is_source = b.file_path.ends_with(".c");
            if a_is_source != b_is_source {
                return a_is_source.cmp(&b_is_source);
            }
            a.body.len().cmp(&b.body.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Helper to create a git repo in a temp directory with an initial commit
    fn create_test_repo() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmpdir = tempfile::tempdir().unwrap();
        let repo_path = tmpdir.path().to_path_buf();

        // Initialize a git repo using gix
        let repo = gix::init(&repo_path).unwrap();

        // Create a C source file
        let src_path = repo_path.join("test.c");
        fs::write(
            &src_path,
            r#"
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

void hello(void) {
    printf("hello\n");
}
"#,
        )
        .unwrap();

        // Create a header file
        let hdr_path = repo_path.join("test.h");
        fs::write(
            &hdr_path,
            r#"
#ifndef TEST_H
#define TEST_H

int add(int a, int b);
void hello(void);

#endif
"#,
        )
        .unwrap();

        // Stage and commit using git CLI (gix commit API is complex)
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&repo_path)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(&repo_path)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@test.com")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@test.com")
            .output()
            .unwrap();

        // Drop and re-discover to pick up the commit
        drop(repo);

        (tmpdir, repo_path)
    }

    #[test]
    fn test_clean_repo_produces_empty_index() {
        let (_tmpdir, repo_path) = create_test_repo();
        let index = WorkdirIndex::build(&repo_path).unwrap();
        assert!(index.is_empty());
        assert_eq!(index.function_count(), 0);
        assert_eq!(index.type_count(), 0);
    }

    #[test]
    fn test_modified_file_detected() {
        let (_tmpdir, repo_path) = create_test_repo();

        // Modify test.c
        fs::write(
            repo_path.join("test.c"),
            r#"
#include <stdio.h>

int add(int a, int b) {
    return a + b + 1;  // modified
}

int subtract(int a, int b) {
    return a - b;
}

void hello(void) {
    printf("hello world\n");
}
"#,
        )
        .unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();
        assert!(!index.is_empty());
        assert!(index.is_dirty("test.c"));
        assert!(!index.is_dirty("test.h"));
        assert!(!index.is_deleted("test.c"));

        // Should find the new subtract function
        assert!(index.find_function("subtract").is_some());
        // Should find the modified add function
        assert!(index.find_function("add").is_some());
    }

    #[test]
    fn test_new_file_detected() {
        let (_tmpdir, repo_path) = create_test_repo();

        // Add a new file
        fs::write(
            repo_path.join("new.c"),
            r#"
int multiply(int a, int b) {
    return a * b;
}
"#,
        )
        .unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();
        assert!(!index.is_empty());
        assert!(index.is_dirty("new.c"));
        assert!(index.find_function("multiply").is_some());
    }

    #[test]
    fn test_deleted_file_detected() {
        let (_tmpdir, repo_path) = create_test_repo();

        // Delete test.c
        fs::remove_file(repo_path.join("test.c")).unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();
        assert!(!index.is_empty());
        assert!(index.is_deleted("test.c"));
        assert!(!index.is_dirty("test.c"));
    }

    #[test]
    fn test_merged_manifest() {
        let (_tmpdir, repo_path) = create_test_repo();

        // Modify test.c and add new.c
        fs::write(
            repo_path.join("test.c"),
            "int changed(void) { return 1; }\n",
        )
        .unwrap();
        fs::write(
            repo_path.join("new.c"),
            "int new_func(void) { return 2; }\n",
        )
        .unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();

        // Create a fake HEAD manifest
        let mut head_manifest = HashMap::new();
        head_manifest.insert("test.c".to_string(), "abc123".to_string());
        head_manifest.insert("test.h".to_string(), "def456".to_string());

        let merged = index.merged_manifest(&head_manifest);

        // test.c should have the dirty hash, not the HEAD hash
        assert_ne!(merged.get("test.c").unwrap(), "abc123");
        // test.h should be unchanged
        assert_eq!(merged.get("test.h").unwrap(), "def456");
        // new.c should be added
        assert!(merged.contains_key("new.c"));
    }

    #[test]
    fn test_find_callers_in_overlay() {
        let (_tmpdir, repo_path) = create_test_repo();

        fs::write(
            repo_path.join("test.c"),
            r#"
int add(int a, int b) {
    return a + b;
}

int compute(int x) {
    return add(x, 1);
}
"#,
        )
        .unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();
        let callers = index.find_callers("add");
        assert!(!callers.is_empty());
        assert!(callers.iter().any(|f| f.name == "compute"));
    }

    #[test]
    fn test_grep_functions() {
        let (_tmpdir, repo_path) = create_test_repo();

        fs::write(
            repo_path.join("test.c"),
            r#"
int special_value(void) {
    return 42;
}

int other(void) {
    return 0;
}
"#,
        )
        .unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();
        let results = index.grep_functions("42", None);
        assert!(!results.is_empty());
        assert!(results.iter().any(|f| f.name == "special_value"));
        // "other" should not match
        assert!(!results.iter().any(|f| f.name == "other"));
    }

    #[test]
    fn test_regex_search() {
        let (_tmpdir, repo_path) = create_test_repo();

        fs::write(
            repo_path.join("test.c"),
            r#"
int foo_bar(void) { return 1; }
int foo_baz(void) { return 2; }
int unrelated(void) { return 3; }
"#,
        )
        .unwrap();

        let index = WorkdirIndex::build(&repo_path).unwrap();
        let results = index.find_functions_regex("foo_.*");
        assert_eq!(results.len(), 2);
    }
}
