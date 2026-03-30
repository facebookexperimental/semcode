// SPDX-License-Identifier: MIT OR Apache-2.0
//! In-memory index of uncommitted working directory changes.
//!
//! This module detects files that differ from the HEAD commit (modified, new, or deleted)
//! and analyzes them with tree-sitter to produce an in-memory overlay of functions, types,
//! and macros. The overlay can be composed with database lookups to query uncommitted state.
//!
//! Incremental rebuilds use mtime + file size to skip re-analyzing files that haven't
//! changed since the last build, making repeated queries in interactive mode fast.

use anyhow::Result;
use gix::bstr::ByteSlice;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::SystemTime;

use crate::file_extensions::is_supported_for_analysis;
use crate::hash::compute_blake3_hash;
use crate::treesitter_analyzer::TreeSitterAnalyzer;
use crate::types::{FunctionInfo, TypeInfo};

/// Cached stat metadata + analysis results for a single dirty file.
#[derive(Clone)]
struct FileCacheEntry {
    /// File modification time (seconds since epoch)
    mtime_secs: u64,
    /// File modification time (nanoseconds component)
    mtime_nanos: u32,
    /// File size in bytes
    size: u64,
    /// Blake3 content hash (used as git_file_hash in the manifest)
    content_hash: String,
    /// Extracted functions
    functions: Vec<FunctionInfo>,
    /// Extracted types
    types: Vec<TypeInfo>,
    /// Extracted macros (stored as FunctionInfo)
    macros: Vec<FunctionInfo>,
}

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
    /// Per-file cache of stat metadata + analysis results, for incremental rebuilds
    file_cache: HashMap<String, FileCacheEntry>,
    /// HEAD commit SHA at the time of the last build (to detect when HEAD changes)
    head_sha: Option<String>,
}

impl WorkdirIndex {
    /// Build a WorkdirIndex by scanning the working directory for uncommitted changes.
    ///
    /// Equivalent to `build_incremental(repo_path, None)`.
    pub fn build(repo_path: &Path) -> Result<Self> {
        Self::build_incremental(repo_path, None)
    }

    /// Build a WorkdirIndex, reusing cached analysis results from a previous index
    /// for files whose mtime and size haven't changed.
    ///
    /// If `previous` is `None` or HEAD has changed since the previous build, all dirty
    /// files are re-analyzed from scratch.
    pub fn build_incremental(repo_path: &Path, previous: Option<&WorkdirIndex>) -> Result<Self> {
        let total_start = std::time::Instant::now();

        let t = std::time::Instant::now();
        let repo = gix::discover(repo_path)?;
        let workdir = repo
            .workdir()
            .ok_or_else(|| anyhow::anyhow!("Cannot index bare repository"))?
            .to_path_buf();
        tracing::info!("workdir: gix discover: {:?}", t.elapsed());

        // Get current HEAD SHA
        let t = std::time::Instant::now();
        let current_head_sha = repo.head_commit().ok().map(|c| c.id().to_string());
        tracing::info!("workdir: head commit: {:?}", t.elapsed());

        // Determine if the previous cache is valid (HEAD hasn't changed)
        let prev_cache: Option<&HashMap<String, FileCacheEntry>> = previous.and_then(|prev| {
            if prev.head_sha == current_head_sha {
                Some(&prev.file_cache)
            } else {
                None
            }
        });
        tracing::info!(
            "workdir: cache valid: {}, cached files: {}",
            prev_cache.is_some(),
            prev_cache.map_or(0, |c| c.len())
        );

        // Read git index for stat-based fast path (like `git status`)
        let t = std::time::Instant::now();
        let git_index = repo.open_index()?;
        let stat_options = repo.stat_options()?;

        // Build index map: path -> (stat, oid) for tracked files with supported extensions
        struct IndexEntry {
            stat: gix::index::entry::Stat,
            oid: gix::ObjectId,
        }
        let mut index_map: HashMap<String, IndexEntry> = HashMap::new();
        for entry in git_index.entries() {
            let path = entry.path_in(git_index.path_backing());
            if let Ok(path_str) = std::str::from_utf8(path) {
                if is_supported_for_analysis(path_str) {
                    index_map.insert(
                        path_str.to_string(),
                        IndexEntry {
                            stat: entry.stat,
                            oid: entry.id,
                        },
                    );
                }
            }
        }
        tracing::info!(
            "workdir: read git index ({} tracked supported files): {:?}",
            index_map.len(),
            t.elapsed()
        );

        // Build HEAD tree manifest: relative_path -> git blob OID
        // Only for supported files (used to detect staged-but-not-committed changes)
        let t = std::time::Instant::now();
        let mut head_oids: HashMap<String, gix::ObjectId> = HashMap::new();
        if let Ok(head_commit) = repo.head_commit() {
            if let Ok(tree) = head_commit.tree() {
                use gix::traverse::tree::Recorder;
                let mut recorder = Recorder::default();
                if tree.traverse().breadthfirst(&mut recorder).is_ok() {
                    for entry in &recorder.records {
                        if entry.mode.is_blob() {
                            let path = entry.filepath.to_str_lossy();
                            if is_supported_for_analysis(&path) {
                                head_oids.insert(path.to_string(), entry.oid);
                            }
                        }
                    }
                }
            }
        }
        tracing::info!(
            "workdir: HEAD tree walk ({} supported files): {:?}",
            head_oids.len(),
            t.elapsed()
        );

        // Classify tracked files using stat-based fast path.
        // Only iterate files in the index — no directory walk needed.
        let mut dirty_files_to_analyze: Vec<(String, std::path::PathBuf)> = Vec::new();
        let mut deleted_files: HashSet<String> = HashSet::new();
        let mut dirty_manifest: HashMap<String, String> = HashMap::new();
        let mut file_cache: HashMap<String, FileCacheEntry> = HashMap::new();

        // Aggregated symbol maps
        let mut functions: HashMap<String, Vec<FunctionInfo>> = HashMap::new();
        let mut types: HashMap<String, Vec<TypeInfo>> = HashMap::new();
        let mut macros: HashMap<String, Vec<FunctionInfo>> = HashMap::new();

        let t = std::time::Instant::now();
        let mut stat_clean = 0usize;
        let mut cache_hits = 0usize;
        let mut files_read = 0usize;
        let mut tracked_hash_dirty = 0usize;
        let mut tracked_hash_clean = 0usize;

        for (rel_path, idx_entry) in &index_map {
            let abs_path = workdir.join(rel_path);

            let gix_meta = match gix::index::fs::Metadata::from_path_no_follow(&abs_path) {
                Ok(m) => m,
                Err(_) => continue, // File doesn't exist on disk (deleted)
            };
            let meta = match std::fs::metadata(&abs_path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let (mtime_secs, mtime_nanos) = mtime_from_metadata(&meta);
            let size = meta.len();

            // Fast path: check git index stat to skip clean tracked files
            // If workdir stat matches index stat AND index OID matches HEAD OID → clean
            let workdir_stat = gix::index::entry::Stat::from_fs(&gix_meta)?;
            if idx_entry.stat.matches(&workdir_stat, stat_options) {
                if let Some(head_oid) = head_oids.get(rel_path) {
                    if idx_entry.oid == *head_oid {
                        stat_clean += 1;
                        continue;
                    }
                }
                // Index stat matches but OID differs from HEAD → staged change, dirty
            }

            // Check if we can reuse the previous cache entry (mtime+size unchanged)
            if let Some(cached) = prev_cache.and_then(|c| c.get(rel_path)) {
                if cached.mtime_secs == mtime_secs
                    && cached.mtime_nanos == mtime_nanos
                    && cached.size == size
                {
                    // File unchanged since last workdir build — reuse cached results
                    dirty_manifest.insert(rel_path.clone(), cached.content_hash.clone());
                    insert_symbols(
                        &cached.functions,
                        &cached.types,
                        &cached.macros,
                        &mut functions,
                        &mut types,
                        &mut macros,
                    );
                    file_cache.insert(rel_path.clone(), cached.clone());
                    cache_hits += 1;
                    continue;
                }
            }

            // Need to read and check this file
            let content = match std::fs::read_to_string(&abs_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            files_read += 1;
            let content_hash = compute_blake3_hash(&content);

            // Compare content hash against HEAD OID directly
            let is_dirty = if let Some(head_oid) = head_oids.get(rel_path) {
                match gix::objs::compute_hash(
                    repo.object_hash(),
                    gix::object::Kind::Blob,
                    content.as_bytes(),
                ) {
                    Ok(workdir_oid) => {
                        if workdir_oid != *head_oid {
                            tracked_hash_dirty += 1;
                            true
                        } else {
                            tracked_hash_clean += 1;
                            false
                        }
                    }
                    Err(_) => true,
                }
            } else {
                true // In index but not in HEAD (staged new file)
            };

            if is_dirty {
                dirty_manifest.insert(rel_path.clone(), content_hash.clone());
                dirty_files_to_analyze.push((rel_path.clone(), abs_path.clone()));
                file_cache.insert(
                    rel_path.clone(),
                    FileCacheEntry {
                        mtime_secs,
                        mtime_nanos,
                        size,
                        content_hash,
                        functions: Vec::new(),
                        types: Vec::new(),
                        macros: Vec::new(),
                    },
                );
            }
        }
        tracing::info!(
            "workdir: classify files: {:?} (stat_clean={}, cache_hits={}, files_read={}, hash_dirty={}, hash_clean={}, dirty={})",
            t.elapsed(),
            stat_clean,
            cache_hits,
            files_read,
            tracked_hash_dirty,
            tracked_hash_clean,
            dirty_files_to_analyze.len()
        );

        // Check for deleted files (in HEAD but not on disk)
        let t = std::time::Instant::now();
        for rel_path in head_oids.keys() {
            if !workdir.join(rel_path).exists() {
                deleted_files.insert(rel_path.clone());
            }
        }
        tracing::info!(
            "workdir: deleted files check ({} deleted): {:?}",
            deleted_files.len(),
            t.elapsed()
        );

        // Analyze dirty files that weren't served from cache
        let t = std::time::Instant::now();
        let mut analyzer = TreeSitterAnalyzer::new()?;
        let source_root = Some(workdir.as_path());

        for (rel_path, abs_path) in &dirty_files_to_analyze {
            let content = match std::fs::read_to_string(abs_path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let content_hash = dirty_manifest
                .get(rel_path)
                .expect("dirty file must have a manifest entry");
            let file_path = Path::new(rel_path);

            match analyzer.analyze_source_with_metadata(
                &content,
                file_path,
                content_hash,
                source_root,
            ) {
                Ok((file_functions, file_types, file_macros)) => {
                    // Update the cache entry with analysis results
                    if let Some(entry) = file_cache.get_mut(rel_path) {
                        entry.functions = file_functions.clone();
                        entry.types = file_types.clone();
                        entry.macros = file_macros.clone();
                    }
                    insert_symbols(
                        &file_functions,
                        &file_types,
                        &file_macros,
                        &mut functions,
                        &mut types,
                        &mut macros,
                    );
                }
                Err(e) => {
                    tracing::info!("Failed to analyze dirty file {}: {}", rel_path, e);
                }
            }
        }
        tracing::info!(
            "workdir: tree-sitter analysis ({} files): {:?}",
            dirty_files_to_analyze.len(),
            t.elapsed()
        );

        tracing::info!("workdir: total build time: {:?}", total_start.elapsed());

        Ok(Self {
            functions,
            types,
            macros,
            dirty_manifest,
            deleted_files,
            file_cache,
            head_sha: current_head_sha,
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

/// Extract mtime as (seconds, nanoseconds) from file metadata.
fn mtime_from_metadata(meta: &std::fs::Metadata) -> (u64, u32) {
    match meta.modified() {
        Ok(mtime) => match mtime.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => (d.as_secs(), d.subsec_nanos()),
            Err(_) => (0, 0),
        },
        Err(_) => (0, 0),
    }
}

/// Insert analysis results into the aggregated symbol maps.
fn insert_symbols(
    file_functions: &[FunctionInfo],
    file_types: &[TypeInfo],
    file_macros: &[FunctionInfo],
    functions: &mut HashMap<String, Vec<FunctionInfo>>,
    types: &mut HashMap<String, Vec<TypeInfo>>,
    macros: &mut HashMap<String, Vec<FunctionInfo>>,
) {
    for func in file_functions {
        functions
            .entry(func.name.to_lowercase())
            .or_default()
            .push(func.clone());
    }
    for ty in file_types {
        types
            .entry(ty.name.to_lowercase())
            .or_default()
            .push(ty.clone());
    }
    for mac in file_macros {
        macros
            .entry(mac.name.to_lowercase())
            .or_default()
            .push(mac.clone());
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
        let _repo = gix::init(&repo_path).unwrap();

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

        // Add a new file and stage it (git add) so it appears in the index
        fs::write(
            repo_path.join("new.c"),
            r#"
int multiply(int a, int b) {
    return a * b;
}
"#,
        )
        .unwrap();
        std::process::Command::new("git")
            .args(["add", "new.c"])
            .current_dir(&repo_path)
            .output()
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

        // Modify test.c and stage a new file
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
        std::process::Command::new("git")
            .args(["add", "new.c"])
            .current_dir(&repo_path)
            .output()
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
        // new.c should be added (it's staged)
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

    #[test]
    fn test_incremental_reuses_cache() {
        let (_tmpdir, repo_path) = create_test_repo();

        // Modify test.c
        fs::write(
            repo_path.join("test.c"),
            r#"
int modified_func(void) { return 42; }
"#,
        )
        .unwrap();

        // First build
        let index1 = WorkdirIndex::build(&repo_path).unwrap();
        assert!(index1.find_function("modified_func").is_some());
        assert_eq!(index1.dirty_file_count(), 1);

        // Second build (incremental) — file hasn't changed, should reuse cache
        let index2 = WorkdirIndex::build_incremental(&repo_path, Some(&index1)).unwrap();
        assert!(index2.find_function("modified_func").is_some());
        assert_eq!(index2.dirty_file_count(), 1);

        // Modify the file again
        fs::write(
            repo_path.join("test.c"),
            r#"
int another_func(void) { return 99; }
"#,
        )
        .unwrap();

        // Third build (incremental) — file changed, should re-analyze
        let index3 = WorkdirIndex::build_incremental(&repo_path, Some(&index2)).unwrap();
        assert!(index3.find_function("another_func").is_some());
        assert!(index3.find_function("modified_func").is_none());
    }
}
