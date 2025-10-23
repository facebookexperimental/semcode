// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use dashmap::DashMap;
use gix;
use gix::bstr::ByteSlice;

/// Helper function to resolve a revspec (SHA, tag, etc.) to a commit object
/// Ensures that tags are properly dereferenced to their target commits
pub fn resolve_to_commit<'a>(repo: &'a gix::Repository, revspec: &str) -> Result<gix::Commit<'a>> {
    // Add ^{commit} to dereference tags to commits, but insert it before ancestry operators
    // For example: v6.16~8 becomes v6.16^{commit}~8
    let commit_spec = if revspec.contains("^{") {
        // Already has explicit dereference syntax, use as-is
        revspec.to_string()
    } else {
        // Find the first ancestry operator (~ or ^)
        let ancestry_pos = revspec.find('~').into_iter().chain(revspec.find('^')).min();

        match ancestry_pos {
            Some(pos) => {
                // Insert ^{commit} before the ancestry operator
                format!("{}^{{commit}}{}", &revspec[..pos], &revspec[pos..])
            }
            None => {
                // No ancestry operators, append ^{commit} at the end
                format!("{revspec}^{{commit}}")
            }
        }
    };

    repo.rev_parse_single(commit_spec.as_str())?
        .object()?
        .try_into_commit()
        .map_err(|_| anyhow::anyhow!("'{}' does not resolve to a commit", revspec))
}
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};

// Global cache for git file hashes - lock-free concurrent access
static GIT_HASH_CACHE: Lazy<DashMap<PathBuf, Option<String>>> = Lazy::new(DashMap::new);

// Pre-computed manifest of all files in current git commit
static GIT_MANIFEST: Lazy<DashMap<PathBuf, String>> = Lazy::new(DashMap::new);

/// Clear the git hash cache (useful for testing or when repository changes)
pub fn clear_git_cache() {
    GIT_HASH_CACHE.clear();
    GIT_MANIFEST.clear();
}

/// Pre-compute all git file hashes for the current commit to avoid lock contention
pub fn build_git_manifest<P: AsRef<Path>>(repo_path: P) -> Result<()> {
    let repo_path = repo_path.as_ref();

    // Clear existing manifest
    GIT_MANIFEST.clear();

    match gix::discover(repo_path) {
        Ok(repo) => {
            let head = repo.head_commit()?;
            let tree = head.tree()?;

            let repo_workdir = repo
                .workdir()
                .ok_or_else(|| anyhow::anyhow!("Repository has no working directory"))?;

            // Walk the entire git tree and build manifest
            use gix::traverse::tree::Recorder;
            let mut recorder = Recorder::default();
            tree.traverse().breadthfirst(&mut recorder)?;

            for entry in recorder.records {
                if entry.mode.is_blob() {
                    let full_path = repo_workdir
                        .join(std::path::Path::new(entry.filepath.to_str_lossy().as_ref()));
                    let canonical_path = full_path.canonicalize().unwrap_or(full_path);

                    GIT_MANIFEST.insert(canonical_path, entry.oid.to_string());
                }
            }

            tracing::info!("Built git manifest with {} files", GIT_MANIFEST.len());
            Ok(())
        }
        Err(e) => {
            tracing::warn!("Failed to build git manifest: {} (not a git repository)", e);
            Ok(()) // Not being in a git repo is not an error
        }
    }
}

/// Get the current git SHA for a repository containing the given path
pub fn get_git_sha<P: AsRef<Path>>(path: P) -> Result<Option<String>> {
    // Try to discover the git repository starting from the given path
    match gix::discover(path) {
        Ok(repo) => {
            // Get the HEAD commit
            match repo.head_commit() {
                Ok(commit) => Ok(Some(commit.id().to_string())),
                Err(_) => {
                    // HEAD might be unborn (no commits yet) or detached
                    Ok(None)
                }
            }
        }
        Err(_) => {
            // Not a git repository or git not available
            Ok(None)
        }
    }
}

/// Get git SHA for a specific working directory
pub fn get_git_sha_for_workdir<P: AsRef<Path>>(workdir: P) -> Result<Option<String>> {
    get_git_sha(workdir)
}

/// Get git hash for a specific file in the current commit (using pre-computed manifest)
pub fn get_git_file_hash<P: AsRef<Path>>(file_path: P) -> Result<Option<String>> {
    let file_path = file_path.as_ref();
    let canonical_path = file_path
        .canonicalize()
        .unwrap_or_else(|_| file_path.to_path_buf());

    // First check if we have it in the pre-computed manifest (fast, lock-free)
    if let Some(hash) = GIT_MANIFEST.get(&canonical_path) {
        return Ok(Some(hash.clone()));
    }

    // Fall back to old caching behavior if not in manifest
    // (for files processed before manifest was built)
    if let Some(cached_result) = GIT_HASH_CACHE.get(&canonical_path) {
        return Ok(cached_result.clone());
    }

    // Last resort: compute it (should rarely happen after manifest is built)
    let result = get_git_file_hash_uncached(&canonical_path);

    // Cache the result
    GIT_HASH_CACHE.insert(
        canonical_path,
        result.as_ref().ok().and_then(|opt| opt.clone()),
    );

    result
}

/// Internal function that does the actual git hash computation (no caching)
fn get_git_file_hash_uncached<P: AsRef<Path>>(file_path: P) -> Result<Option<String>> {
    let file_path = file_path.as_ref();

    // Try to discover the git repository starting from the file's directory
    let search_path = file_path.parent().unwrap_or(Path::new("."));

    match gix::discover(search_path) {
        Ok(repo) => {
            // Get the HEAD commit
            let commit = repo.head_commit()?;
            let tree = commit.tree()?;

            // Get the relative path from the repository root to the file
            let repo_workdir = repo
                .workdir()
                .ok_or_else(|| anyhow::anyhow!("Repository has no working directory"))?;

            let relative_path = file_path.strip_prefix(repo_workdir).map_err(|_| {
                anyhow::anyhow!("File is not in repository: {}", file_path.display())
            })?;

            // Look up the file in the git tree
            match tree.lookup_entry_by_path(relative_path) {
                Ok(Some(entry)) => Ok(Some(entry.object_id().to_string())),
                Ok(None) | Err(_) => {
                    // File not found in git tree (might be untracked)
                    Ok(None)
                }
            }
        }
        Err(_) => {
            // Not a git repository
            Ok(None)
        }
    }
}

/// Get git hash for a file as hex string, with fallback for non-git files
pub fn get_git_file_hash_with_fallback<P: AsRef<Path>>(file_path: P) -> Result<String> {
    let file_path_ref = file_path.as_ref();

    match get_git_file_hash(file_path_ref)? {
        Some(hash_string) => Ok(hash_string),
        None => {
            // File not in git, fall back to computing SHA-1 of file content
            use sha1::{Digest, Sha1};
            use std::fs::File;
            use std::io::Read;

            let mut file = File::open(file_path_ref)
                .map_err(|e| anyhow::anyhow!("Failed to open file for hashing: {}", e))?;
            let mut hasher = Sha1::new();
            let mut buffer = [0; 8192];

            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }

            Ok(hex::encode(hasher.finalize()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_git_sha_current_dir() {
        // This should work if running in a git repository
        let result = get_git_sha(".");
        assert!(result.is_ok());

        // If we're in a git repo, we should get a SHA
        if let Ok(Some(sha)) = result {
            assert_eq!(sha.len(), 40); // Git SHA is 40 characters
            assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_get_git_sha_non_git_dir() {
        // This should return None for a non-git directory
        let result = get_git_sha("/tmp");
        assert!(result.is_ok());
        // May or may not be in a git repo depending on system
    }
}

/// Get git hash for a specific file at a specific commit
pub fn get_git_file_hash_at_commit<P: AsRef<Path>>(
    repo_path: P,
    commit_sha: &str,
    file_path: &str,
) -> Result<Option<String>> {
    let repo_path = repo_path.as_ref();

    match gix::discover(repo_path) {
        Ok(repo) => {
            // Parse the commit SHA using revparse (supports short SHAs, tags, etc.)
            let commit = resolve_to_commit(&repo, commit_sha)?;

            let tree = commit.tree().map_err(|e| {
                anyhow::anyhow!("Failed to get tree for commit '{}': {}", commit_sha, e)
            })?;

            // Look up the file in the git tree
            match tree.lookup_entry_by_path(Path::new(file_path)) {
                Ok(Some(entry)) => Ok(Some(entry.object_id().to_string())),
                Ok(None) | Err(_) => {
                    // File not found in git tree at this commit
                    tracing::debug!("File '{}' not found in commit '{}'", file_path, commit_sha);
                    Ok(None)
                }
            }
        }
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Information about a changed file between two commits
#[derive(Debug, Clone)]
pub struct ChangedFile {
    pub path: String,
    pub old_file_hash: Option<String>, // None if file was added
    pub new_file_hash: Option<String>, // None if file was deleted
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    Renamed,
}

/// Get list of changed files between two commits using git diff
pub fn get_changed_files<P: AsRef<Path>>(
    repo_path: P,
    commit_a: &str,
    commit_b: &str,
) -> Result<Vec<ChangedFile>> {
    let repo_path = repo_path.as_ref();

    tracing::debug!(
        "Getting changed files between commits {} and {}",
        commit_a,
        commit_b
    );

    match gix::discover(repo_path) {
        Ok(repo) => {
            // Parse commit SHAs using revparse (supports short SHAs, tags, etc.)
            let commit_a_obj = resolve_to_commit(&repo, commit_a)?;
            let commit_b_obj = resolve_to_commit(&repo, commit_b)?;

            // Get trees
            let tree_a = commit_a_obj.tree().map_err(|e| {
                anyhow::anyhow!("Failed to get tree for commit '{}': {}", commit_a, e)
            })?;
            let tree_b = commit_b_obj.tree().map_err(|e| {
                anyhow::anyhow!("Failed to get tree for commit '{}': {}", commit_b, e)
            })?;

            // Perform diff
            let changes = repo
                .diff_tree_to_tree(Some(&tree_a), Some(&tree_b), None)
                .map_err(|e| anyhow::anyhow!("Failed to create diff: {}", e))?;

            let mut changed_files = Vec::new();

            // Process diff changes
            for change in changes {
                use gix::object::tree::diff::ChangeDetached;
                match change {
                    ChangeDetached::Addition { location, id, .. } => {
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: None,
                            new_file_hash: Some(id.to_string()),
                            change_type: ChangeType::Added,
                        });
                    }
                    ChangeDetached::Deletion { location, id, .. } => {
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: Some(id.to_string()),
                            new_file_hash: None,
                            change_type: ChangeType::Deleted,
                        });
                    }
                    ChangeDetached::Modification {
                        location,
                        previous_id,
                        id,
                        ..
                    } => {
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: Some(previous_id.to_string()),
                            new_file_hash: Some(id.to_string()),
                            change_type: ChangeType::Modified,
                        });
                    }
                    ChangeDetached::Rewrite {
                        source_location: _,
                        location,
                        source_id,
                        id,
                        ..
                    } => {
                        // For rewrite (rename), use the new location as the path
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: Some(source_id.to_string()),
                            new_file_hash: Some(id.to_string()),
                            change_type: ChangeType::Renamed,
                        });
                    }
                }
            }

            tracing::debug!(
                "Found {} changed files between commits",
                changed_files.len()
            );
            Ok(changed_files)
        }
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Get list of changed files from a base commit to working directory
pub fn get_changed_files_to_workdir<P: AsRef<Path>>(
    repo_path: P,
    base_commit: &str,
) -> Result<Vec<ChangedFile>> {
    let repo_path = repo_path.as_ref();

    tracing::debug!(
        "Getting changed files from commit {} to working directory",
        base_commit
    );

    match gix::discover(repo_path) {
        Ok(repo) => {
            // Parse base commit SHA using revparse (supports short SHAs, tags, etc.)
            let base_commit_obj = resolve_to_commit(&repo, base_commit)?;
            let base_tree = base_commit_obj.tree().map_err(|e| {
                anyhow::anyhow!("Failed to get tree for commit '{}': {}", base_commit, e)
            })?;

            // Get current HEAD commit
            let head_commit = repo
                .head_commit()
                .map_err(|e| anyhow::anyhow!("Failed to get HEAD commit: {}", e))?;
            let head_tree = head_commit
                .tree()
                .map_err(|e| anyhow::anyhow!("Failed to get HEAD tree: {}", e))?;

            // Perform diff from base to HEAD
            let changes = repo
                .diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None)
                .map_err(|e| anyhow::anyhow!("Failed to create diff: {}", e))?;

            let mut changed_files = Vec::new();

            // Process diff changes
            for change in changes {
                use gix::object::tree::diff::ChangeDetached;
                match change {
                    ChangeDetached::Addition { location, id, .. } => {
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: None,
                            new_file_hash: Some(id.to_string()),
                            change_type: ChangeType::Added,
                        });
                    }
                    ChangeDetached::Deletion { location, id, .. } => {
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: Some(id.to_string()),
                            new_file_hash: None,
                            change_type: ChangeType::Deleted,
                        });
                    }
                    ChangeDetached::Modification {
                        location,
                        previous_id,
                        id,
                        ..
                    } => {
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: Some(previous_id.to_string()),
                            new_file_hash: Some(id.to_string()),
                            change_type: ChangeType::Modified,
                        });
                    }
                    ChangeDetached::Rewrite {
                        source_location: _,
                        location,
                        source_id,
                        id,
                        ..
                    } => {
                        // For rewrite (rename), use the new location as the path
                        changed_files.push(ChangedFile {
                            path: location.to_string(),
                            old_file_hash: Some(source_id.to_string()),
                            new_file_hash: Some(id.to_string()),
                            change_type: ChangeType::Renamed,
                        });
                    }
                }
            }

            tracing::debug!(
                "Found {} changed files from base commit to HEAD",
                changed_files.len()
            );
            Ok(changed_files)
        }
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Walk a git tree at a specific commit with a reused repository reference
/// This version avoids repeated repository discovery for better performance
pub fn walk_tree_at_commit_with_repo<F>(
    repo: &gix::Repository,
    commit_sha: &str,
    mut process_entry: F,
) -> Result<()>
where
    F: FnMut(&str, &gix::ObjectId) -> Result<()>,
{
    // Parse the commit SHA using revparse (supports short SHAs, tags, etc.)
    let commit = resolve_to_commit(repo, commit_sha)?;

    let tree = commit
        .tree()
        .map_err(|e| anyhow::anyhow!("Failed to get tree for commit '{}': {}", commit_sha, e))?;

    // Walk the entire git tree using breadthfirst traversal
    use gix::traverse::tree::Recorder;
    let mut recorder = Recorder::default();
    tree.traverse().breadthfirst(&mut recorder)?;

    // Process each blob entry with the provided callback
    for entry in recorder.records {
        if entry.mode.is_blob() {
            let relative_path = entry.filepath.to_str_lossy();
            process_entry(&relative_path, &entry.oid)?;
        }
    }

    Ok(())
}

/// Walk a git tree at a specific commit and process each blob entry with a callback
/// This is a generic utility function that allows callers to collect or process entries in their own way
pub fn walk_tree_at_commit<P: AsRef<Path>, F>(
    repo_path: P,
    commit_sha: &str,
    process_entry: F,
) -> Result<()>
where
    F: FnMut(&str, &gix::ObjectId) -> Result<()>,
{
    let repo_path = repo_path.as_ref();

    match gix::discover(repo_path) {
        Ok(repo) => walk_tree_at_commit_with_repo(&repo, commit_sha, process_entry),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Resolve multiple file paths to their git hashes at a specific commit
pub fn resolve_files_at_commit<P: AsRef<Path>>(
    repo_path: P,
    commit_sha: &str,
    file_paths: &[String],
) -> Result<std::collections::HashMap<String, String>> {
    let repo_path = repo_path.as_ref();
    let mut resolved_hashes = std::collections::HashMap::new();

    tracing::debug!(
        "Resolving {} file paths at commit {}",
        file_paths.len(),
        commit_sha
    );

    match gix::discover(repo_path) {
        Ok(repo) => {
            // Parse the commit SHA using revparse (supports short SHAs, tags, etc.)
            let commit = resolve_to_commit(&repo, commit_sha)?;

            let tree = commit.tree().map_err(|e| {
                anyhow::anyhow!("Failed to get tree for commit '{}': {}", commit_sha, e)
            })?;

            // Resolve each file path
            for file_path in file_paths {
                match tree.lookup_entry_by_path(Path::new(file_path)) {
                    Ok(Some(entry)) => {
                        let git_file_hash = entry.object_id().to_string();
                        tracing::debug!("Resolved '{}' -> {}", file_path, git_file_hash);
                        resolved_hashes.insert(file_path.clone(), git_file_hash);
                    }
                    Ok(None) | Err(_) => {
                        tracing::debug!(
                            "File '{}' not found in commit '{}'",
                            file_path,
                            commit_sha
                        );
                        // Don't insert anything for missing files
                    }
                }
            }

            tracing::debug!(
                "Successfully resolved {} out of {} file paths",
                resolved_hashes.len(),
                file_paths.len()
            );
            Ok(resolved_hashes)
        }
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Check if a commit is reachable from a given SHA
/// Returns true if target_sha is an ancestor of from_sha (i.e., can be reached by walking backwards from from_sha)
/// Uses git merge-base for efficient ancestry checking
pub fn is_commit_reachable<P: AsRef<Path>>(
    repo_path: P,
    from_sha: &str,
    target_sha: &str,
) -> Result<bool> {
    let repo_path = repo_path.as_ref();

    match gix::discover(repo_path) {
        Ok(repo) => {
            // Parse both commit SHAs using revparse
            let from_commit = resolve_to_commit(&repo, from_sha)?;
            let target_commit = resolve_to_commit(&repo, target_sha)?;

            let from_id = from_commit.id().detach();
            let target_id = target_commit.id().detach();

            // Quick check: if they're the same commit, it's reachable
            if from_id == target_id {
                return Ok(true);
            }

            // Use merge-base to efficiently check ancestry
            // If target_sha is an ancestor of from_sha, then the merge-base will be target_sha itself
            match repo.merge_bases_many(from_id, &[target_id]) {
                Ok(merge_bases) => {
                    // Check if target_id is one of the merge bases
                    // If it is, then target_sha is an ancestor of from_sha (reachable)
                    Ok(merge_bases.iter().any(|base| base.detach() == target_id))
                }
                Err(e) => Err(anyhow::anyhow!("Failed to compute merge base: {}", e)),
            }
        }
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Basic commit information extracted from git
#[derive(Debug, Clone)]
pub struct BasicCommitInfo {
    pub git_sha: String,
    pub parent_sha: Vec<String>,
    pub author: String,
    pub subject: String,
    pub message: String,
    pub diff: String,
    pub symbols: Vec<String>,
    pub files: Vec<String>,
}

/// Extract basic commit metadata directly from git (without indexing)
/// This is used as a fallback when commit is not indexed in the database
pub fn get_commit_info_from_git<P: AsRef<Path>>(
    repo_path: P,
    commit_ref: &str,
) -> Result<BasicCommitInfo> {
    let repo_path = repo_path.as_ref();

    match gix::discover(repo_path) {
        Ok(repo) => {
            // Resolve commit
            let commit = resolve_to_commit(&repo, commit_ref)?;

            // Get commit metadata
            let git_sha = commit.id().to_string();

            // Get parent commits
            let parent_sha: Vec<String> = commit.parent_ids().map(|id| id.to_string()).collect();

            // Get author
            let author_sig = commit.author()?;
            let author = format!("{} <{}>", author_sig.name, author_sig.email);

            // Get commit message
            let message_bytes = commit.message_raw()?;
            let message = String::from_utf8_lossy(&message_bytes).to_string();

            // Extract subject (first line of message)
            let subject = message.lines().next().unwrap_or("").to_string();

            // Generate proper unified diff for commits with exactly one parent
            let (diff, symbols, files) = if parent_sha.len() == 1 {
                match generate_commit_diff_with_symbols(&repo, &parent_sha[0], &git_sha) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::warn!("Failed to generate diff for commit {}: {}", git_sha, e);
                        (
                            String::from("(diff generation failed)"),
                            Vec::new(),
                            Vec::new(),
                        )
                    }
                }
            } else {
                // Skip diff for merge commits (multiple parents) or root commits (no parents)
                if parent_sha.is_empty() {
                    (
                        String::from("(root commit - no diff)"),
                        Vec::new(),
                        Vec::new(),
                    )
                } else {
                    (
                        String::from("(merge commit - diff not shown)"),
                        Vec::new(),
                        Vec::new(),
                    )
                }
            };

            Ok(BasicCommitInfo {
                git_sha,
                parent_sha,
                author,
                subject,
                message,
                diff,
                symbols,
                files,
            })
        }
        Err(e) => Err(anyhow::anyhow!(
            "Failed to discover git repository from '{}': {}",
            repo_path.display(),
            e
        )),
    }
}

/// Generate a unified diff between two commits with proper hunk headers and symbol extraction
/// Uses the same algorithm as during indexing for consistency
fn generate_commit_diff_with_symbols(
    repo: &gix::Repository,
    from_sha: &str,
    to_sha: &str,
) -> Result<(String, Vec<String>, Vec<String>)> {
    use std::fmt::Write as _;

    let from_commit = resolve_to_commit(repo, from_sha)?;
    let to_commit = resolve_to_commit(repo, to_sha)?;

    let from_tree = from_commit.tree()?;
    let to_tree = to_commit.tree()?;

    let mut diff_output = String::new();
    let mut all_symbols = Vec::new();
    let mut changed_files = Vec::new();

    // Use gitoxide's diff functionality
    from_tree
        .changes()?
        .for_each_to_obtain_tree(&to_tree, |change| {
            use gix::object::tree::diff::Action;

            match change {
                gix::object::tree::diff::Change::Modification {
                    previous_entry_mode,
                    previous_id,
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    // Skip non-blob modifications
                    if !previous_entry_mode.is_blob() || !entry_mode.is_blob() {
                        return Ok::<_, anyhow::Error>(Action::Continue);
                    }

                    let path = location.to_string();
                    changed_files.push(path.clone());

                    // Write diff header
                    let _ = writeln!(diff_output, "diff --git a/{} b/{}", path, path);
                    let _ = writeln!(diff_output, "--- a/{}", path);
                    let _ = writeln!(diff_output, "+++ b/{}", path);

                    // Get file contents
                    if let (Ok(old_obj), Ok(new_obj)) =
                        (repo.find_object(previous_id), repo.find_object(id))
                    {
                        if let (Ok(old_blob), Ok(new_blob)) =
                            (old_obj.try_into_blob(), new_obj.try_into_blob())
                        {
                            let old_content = String::from_utf8_lossy(old_blob.data.as_slice());
                            let new_content = String::from_utf8_lossy(new_blob.data.as_slice());

                            // Generate diff and extract symbols using the same algorithm as indexing
                            let (write_result, file_symbols) = write_diff_and_extract_symbols(
                                &mut diff_output,
                                &old_content,
                                &new_content,
                                &path,
                            );
                            let _ = write_result;
                            all_symbols.extend(file_symbols);
                        }
                    }

                    Ok(Action::Continue)
                }
                gix::object::tree::diff::Change::Addition {
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    if !entry_mode.is_blob() {
                        return Ok(Action::Continue);
                    }

                    let path = location.to_string();
                    changed_files.push(path.clone());
                    let _ = writeln!(diff_output, "diff --git a/{} b/{}", path, path);
                    let _ = writeln!(diff_output, "--- /dev/null");
                    let _ = writeln!(diff_output, "+++ b/{}", path);

                    if let Ok(obj) = repo.find_object(id) {
                        if let Ok(blob) = obj.try_into_blob() {
                            let content = String::from_utf8_lossy(blob.data.as_slice());
                            let _ =
                                writeln!(diff_output, "@@ -0,0 +1,{} @@", content.lines().count());
                            for line in content.lines() {
                                let _ = writeln!(diff_output, "+{}", line);
                            }
                        }
                    }

                    Ok(Action::Continue)
                }
                gix::object::tree::diff::Change::Deletion {
                    entry_mode,
                    id,
                    location,
                    ..
                } => {
                    if !entry_mode.is_blob() {
                        return Ok(Action::Continue);
                    }

                    let path = location.to_string();
                    changed_files.push(path.clone());
                    let _ = writeln!(diff_output, "diff --git a/{} b/{}", path, path);
                    let _ = writeln!(diff_output, "--- a/{}", path);
                    let _ = writeln!(diff_output, "+++ /dev/null");

                    if let Ok(obj) = repo.find_object(id) {
                        if let Ok(blob) = obj.try_into_blob() {
                            let content = String::from_utf8_lossy(blob.data.as_slice());
                            let _ =
                                writeln!(diff_output, "@@ -1,{} +0,0 @@", content.lines().count());
                            for line in content.lines() {
                                let _ = writeln!(diff_output, "-{}", line);
                            }
                        }
                    }

                    Ok(Action::Continue)
                }
                gix::object::tree::diff::Change::Rewrite { .. } => {
                    // Rewrite represents a complete file replacement - rare in practice
                    // Skip for now as it's complex to handle properly
                    Ok::<_, anyhow::Error>(Action::Continue)
                }
            }
        })?;

    Ok((diff_output, all_symbols, changed_files))
}

/// Write a unified diff and extract symbols from changed lines
/// This is the same logic used during indexing
pub fn write_diff_and_extract_symbols(
    output: &mut String,
    old: &str,
    new: &str,
    file_path: &str,
) -> (std::fmt::Result, Vec<String>) {
    use similar::{ChangeTag, TextDiff};
    use std::collections::HashSet;
    use std::fmt::Write;

    // Generate a proper diff using the Myers algorithm
    let diff = TextDiff::from_lines(old, new);

    let mut write_result = Ok(());

    // Parse file into lines for symbol lookup
    let new_lines: Vec<&str> = new.lines().collect();

    // Generate unified diff format with 3 lines of context (like git default)
    for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
        // Get the first line number from the hunk to find symbol context
        let start_line = hunk
            .iter_changes()
            .find_map(|c| c.new_index())
            .unwrap_or(1)
            .saturating_sub(1); // Convert to 0-indexed

        // Find the symbol at the start of this hunk using walk-back
        let symbol_context = if file_path.ends_with(".c")
            || file_path.ends_with(".h")
            || file_path.ends_with(".cpp")
            || file_path.ends_with(".cc")
            || file_path.ends_with(".cxx")
        {
            crate::symbol_walkback::find_symbol_for_line(&new_lines, start_line).or_else(|| {
                // If walk-back fails, try to find the first non-empty line in the hunk
                hunk.iter_changes()
                    .find(|c| !c.value().trim().is_empty())
                    .and_then(|c| c.new_index())
                    .and_then(|idx| {
                        if idx > 0 {
                            crate::symbol_walkback::find_symbol_for_line(&new_lines, idx - 1)
                        } else {
                            None
                        }
                    })
            })
        } else {
            None
        };

        // Write hunk header with symbol context (like git does)
        if write_result.is_ok() {
            if let Some(ref symbol) = symbol_context {
                // Format: @@ -old_start,old_count +new_start,new_count @@ symbol
                // Convert header to string and append symbol
                let header_str = format!("{}", hunk.header());
                write_result = writeln!(output, "{} {}", header_str.trim_end(), symbol);
            } else {
                write_result = writeln!(output, "{}", hunk.header());
            }
        }

        // Write the actual changes
        for change in hunk.iter_changes() {
            let sign = match change.tag() {
                ChangeTag::Delete => "-",
                ChangeTag::Insert => "+",
                ChangeTag::Equal => " ",
            };
            if write_result.is_ok() {
                write_result = write!(output, "{}{}", sign, change.value());
            }
        }
    }

    // Extract symbols for C/C++ files only using walk-back algorithm
    let symbols = if file_path.ends_with(".c")
        || file_path.ends_with(".h")
        || file_path.ends_with(".cpp")
        || file_path.ends_with(".cc")
        || file_path.ends_with(".cxx")
    {
        // Collect modified line numbers from both old and new files
        let mut new_modified_lines = HashSet::new();
        let mut old_modified_lines = HashSet::new();

        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            for change in hunk.iter_changes() {
                use similar::ChangeTag;
                match change.tag() {
                    ChangeTag::Insert => {
                        // Added lines - check in new file
                        if let Some(line_num) = change.new_index() {
                            if line_num > 0 {
                                new_modified_lines.insert(line_num - 1);
                            }
                        }
                    }
                    ChangeTag::Delete => {
                        // Deleted lines - check in old file
                        if let Some(line_num) = change.old_index() {
                            if line_num > 0 {
                                old_modified_lines.insert(line_num - 1);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Extract symbols from both old (deletions) and new (additions/modifications)
        let mut all_symbols = HashSet::new();
        all_symbols.extend(crate::symbol_walkback::extract_symbols_by_walkback(
            new,
            &new_modified_lines,
        ));
        all_symbols.extend(crate::symbol_walkback::extract_symbols_by_walkback(
            old,
            &old_modified_lines,
        ));

        all_symbols.into_iter().collect()
    } else {
        Vec::new()
    };

    (write_result, symbols)
}
