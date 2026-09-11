// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::CallRelationship;
use anyhow::Result;
use arrow::array::{Array, StringArray};
use arrow::record_batch::RecordBatch;
use colored::*;
use futures::TryStreamExt;
use lancedb::connection::Connection;
use lancedb::connection::LanceFileVersion;
use lancedb::database::listing::ListingDatabaseOptions;
use lancedb::index::scalar::FullTextSearchQuery;
use lancedb::query::ExecutableQuery;
use lancedb::query::QueryBase;

use crate::database::branches::IndexedBranchStore;
use crate::database::functions::FunctionStore;
use crate::database::schema::SchemaManager;
use crate::database::search::{SearchManager, VectorSearchManager};
use crate::database::symbol_filename::SymbolFilenameStore;
use crate::database::types::{TypeStore, TypedefStore};
// CallStore removed - call relationships are now embedded in function JSON columns
use crate::database::content::{ContentInfo, ContentStore};
use crate::database::processed_files::{ProcessedFileRecord, ProcessedFileStore};
use crate::database::vectors::VectorStore;
use crate::treesitter_analyzer::TreeSitterAnalyzer;
use crate::types::{ChosenDefinition, FunctionInfo, TypeInfo, TypedefInfo};
use crate::vectorizer::CodeVectorizer;
use crate::workdir::WorkdirIndex;
use crate::worktree::{WorkingCopy, WorkingCopyHashes};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

// Optimal batch size for LanceDB operations
pub const OPTIMAL_BATCH_SIZE: usize = 65536;

/// A revision's file manifest: path to blob id, shared because building one
/// walks the whole tree.
type GitManifest = std::sync::Arc<crate::database::resolution::RevisionPaths>;

/// Why a revision cannot account for a symbol. The answer is the same in all
/// three cases; the reason is what tells an index that does not have the tree
/// apart from a symbol that is not in it.
#[derive(Copy, Clone)]
enum Absent {
    /// The revision itself did not resolve, so no path could be looked up in
    /// it. Either the repository does not have that commit or git failed.
    RevisionUnknown,
    /// The files the symbol lives in are not in that tree.
    PathsNotInTree,
    /// The files are in the tree, holding content no indexed row has.
    ContentNotIndexed,
}

impl Absent {
    fn reason(self) -> &'static str {
        match self {
            Absent::RevisionUnknown => "the revision did not resolve",
            Absent::PathsNotInTree => "its files are not in that tree",
            Absent::ContentNotIndexed => "no indexed row holds the content that tree has",
        }
    }
}

/// What a candidate file holds against the blob hash a query is checking it
/// against — the row's, or the tree's at the revision asked about. Answering
/// `Indexed` costs a stat; the other two cost a stat and a hash, of one file,
/// never a walk of files the query did not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateFile {
    /// The disk holds exactly the expected hash: the indexed row is current.
    Indexed,
    /// The disk holds something else: an uncommitted edit on top of it.
    Edited,
    /// There is no file here any more.
    Deleted,
}

/// Where a name's rows do live, for the line that reports it absent.
///
/// A revision with no branch is normal: the index records commits it read,
/// and only some of them were branch tips.
fn describe_revisions(
    revisions: &[String],
    branches: &[crate::database::branches::IndexedBranchInfo],
) -> String {
    let revs: Vec<&str> = revisions
        .iter()
        .map(|r| &r[..r.len().min(12)])
        .take(4)
        .collect();
    let more = revisions.len().saturating_sub(revs.len());
    let at = if more > 0 {
        format!("{} and {} more", revs.join(", "), more)
    } else {
        revs.join(", ")
    };
    if branches.is_empty() {
        return format!("its rows are at {at}, on no indexed branch");
    }
    let names: Vec<&str> = branches.iter().map(|b| b.branch_name.as_str()).collect();
    format!("its rows are at {at}, on {}", names.join(", "))
}

/// The same, for an index that cannot name a revision: the files the rows
/// came from and the content they carry. `processed_files` holds a revision
/// only when the indexer was given one, so this is what most indexes can
/// say, and it is enough to tell a caller which tree to look in.
fn describe_files(places: &[(String, String)]) -> String {
    let mut seen = HashSet::new();
    let mut described = Vec::new();
    for (path, hash) in places {
        if !seen.insert(path) {
            continue;
        }
        if described.len() < 3 {
            described.push(format!("{path} (blob {})", &hash[..hash.len().min(12)]));
        }
    }
    if described.is_empty() {
        return "the index has no row for it".to_string();
    }
    let more = seen.len().saturating_sub(described.len());
    if more > 0 {
        format!("its rows are in {}, and {more} more", described.join(", "))
    } else {
        format!("its rows are in {}", described.join(", "))
    }
}

/// One line per absence, because an answer that is missing says nothing. An
/// unresolvable revision is the operator's problem and warns; a symbol that
/// is simply not in the tree is an answer and informs.
fn log_absence(kind: &str, name: &str, git_sha: &str, why: Absent, elsewhere: &str) {
    let reason = why.reason();
    match why {
        Absent::RevisionUnknown => {
            tracing::warn!("{kind} '{name}' is not answered for {git_sha}: {reason}; {elsewhere}")
        }
        _ => tracing::info!("{kind} '{name}' is not at {git_sha}: {reason}; {elsewhere}"),
    }
}

pub struct DatabaseManager {
    connection: Connection,
    git_repo_path: String,
    function_store: FunctionStore,
    type_store: TypeStore,
    typedef_store: TypedefStore,
    search_manager: SearchManager,
    vector_search_manager: VectorSearchManager,
    schema_manager: SchemaManager,
    processed_file_store: ProcessedFileStore,
    content_store: ContentStore,
    dispatch_site_store: crate::database::dispatch_sites::DispatchSiteStore,
    registration_store: crate::database::registrations::RegistrationStore,
    argument_function_store: crate::database::argument_functions::ArgumentFunctionStore,
    unresolved_edge_store: crate::database::unresolved_edges::UnresolvedEdgeStore,
    global_store: crate::database::globals::GlobalStore,
    object_macro_store: crate::database::object_macros::ObjectMacroStore,
    symbol_filename_store: SymbolFilenameStore,
    branch_store: IndexedBranchStore,
    workdir_index: std::sync::RwLock<Option<WorkdirIndex>>,
    /// The last manifest generated, kept because a single query asks for the
    /// same revision several times. Building one walks the whole tree.
    manifest_cache: std::sync::RwLock<Option<(String, GitManifest)>>,
    /// Identifiers that are compiler attributes, read once per process.
    attribute_names: std::sync::OnceLock<Arc<HashSet<String>>>,
    /// Hashes of working-copy files a query has already looked at, memoised
    /// on (size, mtime) so a name asked about twice reads its file once.
    /// This is what a query stats instead of the working tree.
    working_copy: WorkingCopyHashes,
    /// Set when the caller has said it will not be editing: skip the
    /// per-candidate stat entirely and trust every row, the way `--git-only`
    /// always has.
    git_only: AtomicBool,
    /// Bumped by a long-lived caller (the REPL) once per top-level command,
    /// so `ensure_workdir_index_built` can tell "asked again within the
    /// command that just built this" (several `_git_aware` calls in one
    /// `func` — cheap, must stay a no-op) from "asked again in a later
    /// command" (a REPL user had a chance to edit a file in between — must
    /// refresh). A caller that never calls `note_repl_command` (MCP, LSP,
    /// `-q`) leaves this at 0 forever, which builds the overlay once and
    /// reuses it — right for a caller with no prompt to edit a file at.
    workdir_command_generation: AtomicU64,
    /// The command generation the current `workdir_index` was last built or
    /// refreshed for. `u64::MAX` means "never built", so the first build on
    /// generation 0 is not mistaken for already-current.
    workdir_index_generation: AtomicU64,
}

impl DatabaseManager {
    pub async fn new(db_path: &str, git_repo_path: String) -> Result<Self> {
        let database_options = ListingDatabaseOptions::builder()
            .data_storage_version(LanceFileVersion::V2_2)
            .build();
        let connection = lancedb::connect(db_path)
            .database_options(&database_options)
            .execute()
            .await?;

        Ok(Self {
            connection: connection.clone(),
            git_repo_path: git_repo_path.clone(),
            function_store: FunctionStore::new(connection.clone()),
            type_store: TypeStore::new(connection.clone()),
            typedef_store: TypedefStore::new(connection.clone()),
            search_manager: SearchManager::new(connection.clone(), git_repo_path),
            vector_search_manager: VectorSearchManager::new(connection.clone()),
            schema_manager: SchemaManager::new(connection.clone()),
            processed_file_store: ProcessedFileStore::new(connection.clone()),
            content_store: ContentStore::new(connection.clone()),
            dispatch_site_store: crate::database::dispatch_sites::DispatchSiteStore::new(
                connection.clone(),
            ),
            registration_store: crate::database::registrations::RegistrationStore::new(
                connection.clone(),
            ),
            argument_function_store:
                crate::database::argument_functions::ArgumentFunctionStore::new(connection.clone()),
            unresolved_edge_store: crate::database::unresolved_edges::UnresolvedEdgeStore::new(
                connection.clone(),
            ),
            global_store: crate::database::globals::GlobalStore::new(connection.clone()),
            symbol_filename_store: SymbolFilenameStore::new(connection.clone()),
            object_macro_store: crate::database::object_macros::ObjectMacroStore::new(
                connection.clone(),
            ),
            branch_store: IndexedBranchStore::new(connection.clone()),
            workdir_index: std::sync::RwLock::new(None),
            manifest_cache: std::sync::RwLock::new(None),
            attribute_names: std::sync::OnceLock::new(),
            working_copy: WorkingCopyHashes::new(),
            git_only: AtomicBool::new(false),
            workdir_command_generation: AtomicU64::new(0),
            workdir_index_generation: AtomicU64::new(u64::MAX),
        })
    }

    /// Mark the start of a new top-level command, so the next lookup that
    /// needs the working-copy overlay treats it as due for a freshness
    /// check instead of reusing whatever the previous command already built
    /// or refreshed — an edit made between two REPL commands becomes visible
    /// to the first overlay-consuming call in the next one. Call once per
    /// command read from the prompt, before dispatching it; calling it more
    /// than once for the same command only costs one extra refresh, calling
    /// it not at all builds the overlay once and reuses it (see
    /// `workdir_command_generation`'s doc comment).
    pub fn note_repl_command(&self) {
        self.workdir_command_generation
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Say the caller will not be editing: candidate files are trusted
    /// without a stat, and the working-tree overlay is never built, on-miss
    /// or otherwise. Matches the REPL's `--git-only`.
    pub fn set_git_only(&self, git_only: bool) {
        self.git_only.store(git_only, Ordering::Relaxed);
    }

    fn is_git_only(&self) -> bool {
        self.git_only.load(Ordering::Relaxed)
    }

    /// Whether `git_sha` is the commit currently checked out — the only
    /// relationship in which the working copy can answer for it. A query
    /// naming an explicit SHA or branch other than what is checked out has
    /// no such relationship: the file on disk is some other, unrelated
    /// version, and comparing it against a blob from that revision would
    /// manufacture an edit out of an unrelated diff — the wrong-branch
    /// answer this code exists to prevent, reappearing through the
    /// working-copy overlay instead of the index. A ref read, not a walk of
    /// anything, and cheap enough to ask every time rather than trust a
    /// caller to remember to say so.
    fn is_checked_out(&self, git_sha: &str) -> bool {
        if git_sha.is_empty() {
            return false;
        }
        match gix::discover(&self.git_repo_path) {
            Ok(repo) => repo
                .head_commit()
                .map(|c| c.id().to_string() == git_sha)
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// Whether the working-copy overlay may be consulted for a query naming
    /// `git_sha`: the caller has not opted out (`git_only`), and the working
    /// copy actually represents that revision.
    fn workdir_overlay_usable(&self, git_sha: &str) -> bool {
        !self.is_git_only() && self.is_checked_out(git_sha)
    }

    pub async fn list_tables(&self) -> Result<Vec<String>> {
        Ok(self.connection.table_names().execute().await?)
    }

    /// The schema version the index was written by. `None` means it predates
    /// versioning, which for these purposes is older than anything.
    pub async fn stored_schema_version(&self) -> Result<Option<u32>> {
        self.schema_manager.stored_schema_version().await
    }

    /// Content hashes this build's extractor has read, which is the set a
    /// later run may skip. A file read by an older extractor is missing from
    /// it even though the file itself has not changed.
    pub async fn processed_by_this_extractor(&self) -> Result<std::collections::HashSet<String>> {
        Ok(self
            .get_all_processed_files()
            .await?
            .into_iter()
            .filter(|record| record.extractor_version == Some(crate::SCHEMA_VERSION))
            .map(|record| record.git_file_sha)
            .collect())
    }

    /// True when any file in the index was read by an older extractor, so
    /// what is stored for it is not what a fresh index would hold.
    ///
    /// Asked of the files rather than of a mark on the database as a whole: a
    /// run over a commit range reads the files that commit touched and no
    /// others, and a database-wide mark would call the whole index current on
    /// the strength of those few.
    pub async fn index_predates_reader(&self) -> Result<bool> {
        let files = self.get_all_processed_files().await?;
        if !files.is_empty() {
            return Ok(files
                .iter()
                .any(|record| record.extractor_version != Some(crate::SCHEMA_VERSION)));
        }

        // No files to ask, so fall back to the mark on the database: an index
        // holding rows from before that mark existed still predates this
        // build, and a fresh one does not.
        Ok(self.stored_schema_version().await?.unwrap_or(0) < crate::SCHEMA_VERSION)
    }

    /// Mark the index as holding what this build writes, with the options it
    /// was built with.
    /// Forget files an older extractor read, after this one has read the tree.
    pub async fn forget_older_processed_files(&self) -> Result<usize> {
        self.forget_processed_before(crate::SCHEMA_VERSION).await
    }

    /// The same, against a stated version, so a test can name one.
    pub async fn forget_processed_before(&self, version: u32) -> Result<usize> {
        self.processed_file_store.forget_older_than(version).await
    }

    pub async fn record_index_build(&self, extensions: &[String], no_macros: bool) -> Result<()> {
        self.schema_manager
            .set_index_build(extensions, no_macros)
            .await
    }

    pub async fn record_tree_sha(&self, sha: &str) -> Result<()> {
        self.schema_manager.set_tree_sha(sha).await
    }

    pub async fn recorded_tree_sha(&self) -> Result<Option<String>> {
        self.schema_manager.meta_value("index:tree_sha").await
    }

    /// How the index was built: the extensions indexed, and whether macros
    /// were skipped. `None` when the index does not say, which is every index
    /// written before this was recorded.
    pub async fn recorded_index_options(&self) -> Result<Option<(Vec<String>, bool)>> {
        let Some(extensions) = self.schema_manager.meta_value("index:extensions").await? else {
            return Ok(None);
        };
        if extensions.is_empty() {
            return Ok(None);
        }

        let no_macros = self
            .schema_manager
            .meta_value("index:macros")
            .await?
            .map(|value| value == "skipped")
            .unwrap_or(false);

        Ok(Some((
            extensions.split(',').map(|e| e.to_string()).collect(),
            no_macros,
        )))
    }

    pub async fn create_tables(&self) -> Result<()> {
        self.schema_manager.create_all_tables().await?;
        self.schema_manager.create_scalar_indices().await?;
        Ok(())
    }

    /// Set the working directory index for overlaying uncommitted changes on queries.
    /// When set, all `_git_aware` methods will automatically merge results from the
    /// working directory overlay with database results.
    pub fn set_workdir_index(&self, workdir: WorkdirIndex) {
        *self.workdir_index.write().unwrap() = Some(workdir);
    }

    /// Check if a workdir index is set.
    pub fn has_workdir_index(&self) -> bool {
        self.workdir_index.read().unwrap().is_some()
    }

    /// Clear the working directory index.
    pub fn clear_workdir_index(&self) {
        *self.workdir_index.write().unwrap() = None;
    }

    /// Take the working directory index out, leaving None in its place.
    /// Used to extract the previous index for incremental rebuilds.
    pub fn take_workdir_index(&self) -> Option<WorkdirIndex> {
        self.workdir_index.write().unwrap().take()
    }

    pub async fn clear_all_data(&self) -> Result<()> {
        // Delete all data from each main table
        for table_name in &[
            "functions",
            "types",
            "vectors",
            "commit_vectors",
            "lore_vectors",
            "processed_files",
            "symbol_filename",
            "git_commits",
            "lore",
            "lore_indexed_commits",
            "indexed_branches",
        ] {
            if let Ok(table) = self.connection.open_table(*table_name).execute().await {
                table.delete("1=1").await?;
            }
        }

        // Delete all data from content shard tables (content_0 through content_15)
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if let Ok(table) = self.connection.open_table(&table_name).execute().await {
                table.delete("1=1").await?;
            }
        }

        Ok(())
    }

    /// Scan all tables for 100% duplicate entries and report statistics
    pub async fn scan_for_duplicates(&self) -> Result<()> {
        println!("{}", "=== Database Duplicate Scan ===".bold().green());
        println!("Scanning for entries where ALL columns are identical...\n");

        let tables_to_scan = [
            "functions",
            "types",
            "processed_files",
            "symbol_filename",
            "git_commits",
            "vectors", // Function vectors table
            "commit_vectors",
            "lore",
            "lore_vectors",
        ];

        // Scan main tables
        for table_name in &tables_to_scan {
            if let Ok(table) = self.connection.open_table(*table_name).execute().await {
                match self.scan_table_for_duplicates(table_name, &table).await {
                    Ok((total_rows, duplicate_groups, duplicate_count, examples)) => {
                        println!("{}", format!("=== {table_name} ===").bold().cyan());
                        println!("Total rows: {}", total_rows.to_string().yellow());

                        if duplicate_groups > 0 {
                            println!("Duplicate groups: {}", duplicate_groups.to_string().red());
                            println!(
                                "Total duplicate rows: {}",
                                duplicate_count.to_string().red()
                            );

                            // Debug the calculation
                            let percentage = duplicate_count as f64 / total_rows as f64 * 100.0;
                            println!("Duplicate percentage: {percentage:.2}%");

                            if !examples.is_empty() {
                                println!("\nExample duplicates (showing up to 5 groups):");
                                for (i, example) in examples.iter().enumerate().take(5) {
                                    println!(
                                        "  Group {}: {} identical rows",
                                        i + 1,
                                        example.len().to_string().yellow()
                                    );
                                    if let Some(first_row) = example.first() {
                                        println!("    Sample: {}", first_row.cyan());
                                    }
                                }
                            }
                        } else {
                            println!("{}", "No duplicates found ✓".green());
                        }
                        println!();
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to scan table {}: {}",
                            "Error:".red(),
                            table_name,
                            e
                        );
                    }
                }
            } else {
                println!("{} Table {} not found", "Warning:".yellow(), table_name);
            }
        }

        // Scan content shard tables (content_0 through content_15)
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if let Ok(table) = self.connection.open_table(&table_name).execute().await {
                match self.scan_table_for_duplicates(&table_name, &table).await {
                    Ok((total_rows, duplicate_groups, duplicate_count, examples)) => {
                        println!("{}", format!("=== {table_name} ===").bold().cyan());
                        println!("Total rows: {}", total_rows.to_string().yellow());

                        if duplicate_groups > 0 {
                            println!("Duplicate groups: {}", duplicate_groups.to_string().red());
                            println!(
                                "Total duplicate rows: {}",
                                duplicate_count.to_string().red()
                            );

                            let percentage = duplicate_count as f64 / total_rows as f64 * 100.0;
                            println!("Duplicate percentage: {percentage:.2}%");

                            if !examples.is_empty() {
                                println!("\nExample duplicates (showing up to 5 groups):");
                                for (i, example) in examples.iter().enumerate().take(5) {
                                    println!(
                                        "  Group {}: {} identical rows",
                                        i + 1,
                                        example.len().to_string().yellow()
                                    );
                                    if let Some(first_row) = example.first() {
                                        println!("    Sample: {}", first_row.cyan());
                                    }
                                }
                            }
                        } else {
                            println!("{}", "No duplicates found ✓".green());
                        }
                        println!();
                    }
                    Err(e) => {
                        println!(
                            "{} Failed to scan table {}: {}",
                            "Error:".red(),
                            table_name,
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Scan a specific table for duplicates
    async fn scan_table_for_duplicates(
        &self,
        table_name: &str,
        table: &lancedb::Table,
    ) -> Result<(usize, usize, usize, Vec<Vec<String>>)> {
        use futures::TryStreamExt;
        use std::collections::HashMap;

        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let mut row_counts: HashMap<String, usize> = HashMap::new();
        let mut row_examples: HashMap<String, String> = HashMap::new();
        let mut total_rows = 0;

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            for row_idx in 0..batch.num_rows() {
                total_rows += 1;

                // Create a string representation of all columns for this row
                let row_signature = self.create_row_signature(&batch, row_idx, table_name)?;

                // Count occurrences and store example
                *row_counts.entry(row_signature.clone()).or_insert(0) += 1;
                row_examples
                    .entry(row_signature.clone())
                    .or_insert_with(|| {
                        self.create_readable_row_summary(&batch, row_idx, table_name)
                            .unwrap_or_default()
                    });
            }
        }

        // Find duplicates (count > 1)
        let mut duplicate_groups = 0;
        let mut total_duplicate_rows = 0;
        let mut examples = Vec::new();

        for (signature, count) in &row_counts {
            if *count > 1 {
                duplicate_groups += 1;
                total_duplicate_rows += count;

                // Create example entries for this duplicate group
                if examples.len() < 5 {
                    let example_description = row_examples.get(signature).unwrap_or(signature);
                    examples.push(vec![example_description.clone(); *count]);
                }
            }
        }

        Ok((total_rows, duplicate_groups, total_duplicate_rows, examples))
    }

    /// Create a unique signature for a row by concatenating all column values
    fn create_row_signature(
        &self,
        batch: &arrow::record_batch::RecordBatch,
        row_idx: usize,
        _table_name: &str,
    ) -> Result<String> {
        use arrow::array::Array;

        let mut signature_parts = Vec::new();

        for col_idx in 0..batch.num_columns() {
            let column = batch.column(col_idx);
            let value_str = match column.data_type() {
                arrow::datatypes::DataType::Utf8 => {
                    let string_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::StringArray>()
                        .unwrap();
                    if string_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        string_array.value(row_idx).to_string()
                    }
                }
                // FixedSizeBinary(32) case removed - all hashes now stored as Utf8 hex strings
                arrow::datatypes::DataType::UInt32 => {
                    let uint32_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::UInt32Array>()
                        .unwrap();
                    if uint32_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        uint32_array.value(row_idx).to_string()
                    }
                }
                arrow::datatypes::DataType::UInt64 => {
                    let uint64_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::UInt64Array>()
                        .unwrap();
                    if uint64_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        uint64_array.value(row_idx).to_string()
                    }
                }
                arrow::datatypes::DataType::Boolean => {
                    let bool_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::BooleanArray>()
                        .unwrap();
                    if bool_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        bool_array.value(row_idx).to_string()
                    }
                }
                arrow::datatypes::DataType::Float32 => {
                    let float32_array = column
                        .as_any()
                        .downcast_ref::<arrow::array::Float32Array>()
                        .unwrap();
                    if float32_array.is_null(row_idx) {
                        "NULL".to_string()
                    } else {
                        float32_array.value(row_idx).to_string()
                    }
                }
                _ => format!("UNSUPPORTED_TYPE_{}", column.data_type()),
            };
            signature_parts.push(value_str);
        }

        Ok(signature_parts.join("||"))
    }

    /// Create a human-readable summary of a row for examples
    fn create_readable_row_summary(
        &self,
        batch: &arrow::record_batch::RecordBatch,
        row_idx: usize,
        table_name: &str,
    ) -> Result<String> {
        use arrow::array::Array;

        match table_name {
            "functions" => {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                let name = if name_array.is_null(row_idx) {
                    "NULL"
                } else {
                    name_array.value(row_idx)
                };
                let file_path = if file_path_array.is_null(row_idx) {
                    "NULL"
                } else {
                    file_path_array.value(row_idx)
                };
                let git_hash = if git_hash_array.is_null(row_idx) {
                    "NULL".to_string()
                } else {
                    let hash_str = git_hash_array.value(row_idx);
                    if hash_str.len() >= 8 {
                        hash_str[..8].to_string()
                    } else {
                        hash_str.to_string()
                    }
                };

                Ok(format!("{name}() in {file_path} ({git_hash}...)"))
            }
            "types" => {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let kind_array = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                let name = if name_array.is_null(row_idx) {
                    "NULL"
                } else {
                    name_array.value(row_idx)
                };
                let file_path = if file_path_array.is_null(row_idx) {
                    "NULL"
                } else {
                    file_path_array.value(row_idx)
                };
                let kind = if kind_array.is_null(row_idx) {
                    "NULL"
                } else {
                    kind_array.value(row_idx)
                };

                Ok(format!("{kind} {name} in {file_path}"))
            }
            _ => {
                // Generic format for other tables
                let first_col = batch.column(0);
                let first_value = match first_col.data_type() {
                    arrow::datatypes::DataType::Utf8 => {
                        let string_array = first_col
                            .as_any()
                            .downcast_ref::<arrow::array::StringArray>()
                            .unwrap();
                        if string_array.is_null(row_idx) {
                            "NULL".to_string()
                        } else {
                            string_array.value(row_idx).to_string()
                        }
                    }
                    _ => "...".to_string(),
                };
                Ok(format!("{table_name} row: {first_value}"))
            }
        }
    }

    pub async fn optimize_tables(&self) -> Result<()> {
        self.schema_manager.optimize_tables().await
    }

    pub async fn compact_and_cleanup(&self) -> Result<()> {
        self.schema_manager.compact_and_cleanup().await
    }

    pub async fn compact_lore_tables(&self) -> Result<()> {
        self.schema_manager.compact_lore_tables().await
    }

    /// Drop and recreate all tables for maximum space savings
    pub async fn drop_and_recreate_tables(&self) -> Result<()> {
        self.schema_manager.drop_and_recreate_tables().await
    }

    /// Drop and rebuild all FTS indices for the lore table from scratch.
    pub async fn create_lore_fts_indices(&self) -> Result<()> {
        self.schema_manager.create_lore_fts_indices().await
    }

    /// Create FTS indices only if they do not already exist.
    pub async fn ensure_lore_fts_indices(&self) -> Result<()> {
        self.schema_manager.ensure_lore_fts_indices().await
    }

    /// Merge newly-inserted rows into existing lore FTS indices.
    pub async fn optimize_lore_fts_indices(&self) -> Result<()> {
        self.schema_manager.optimize_lore_fts_indices().await
    }

    /// Get lore table information including row count and indices
    pub async fn get_lore_table_info(&self) -> Result<String> {
        use std::fmt::Write;
        let mut output = String::new();

        let table = self.connection.open_table("lore").execute().await?;

        // Get row count
        let count = table.count_rows(None).await?;
        writeln!(&mut output, "Lore Table Information:")?;
        writeln!(&mut output, "  Total emails: {}", count)?;

        // List indices
        let indices = table.list_indices().await?;
        writeln!(&mut output, "\nIndices ({} total):", indices.len())?;

        for idx in &indices {
            writeln!(
                &mut output,
                "  - {} on {:?} (type: {:?})",
                idx.name, idx.columns, idx.index_type
            )?;
        }

        Ok(output)
    }

    /// Drop and recreate a specific table
    pub async fn drop_and_recreate_table(&self, table_name: &str) -> Result<()> {
        self.schema_manager
            .drop_and_recreate_table(table_name)
            .await
    }

    pub async fn rebuild_indices(&self) -> Result<()> {
        self.schema_manager.rebuild_indices().await
    }

    pub async fn create_vector_index(&self) -> Result<()> {
        self.vector_search_manager.create_vector_index().await
    }

    // Combined batch operations for optimal performance
    pub async fn insert_batch_combined(
        &self,
        mut functions: Vec<FunctionInfo>,
        types: Vec<TypeInfo>,
        macros: Vec<FunctionInfo>,
    ) -> Result<()> {
        // Macros are now stored as functions - combine them
        functions.extend(macros);
        // Step 1: Extract all content and combine into a single batch
        let mut all_content_items = Vec::new();

        // Extract function bodies
        for func in &functions {
            if !func.body.is_empty() {
                all_content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&func.body),
                    content: func.body.clone(),
                });
            }
        }

        // Extract type definitions
        for type_info in &types {
            if !type_info.definition.is_empty() {
                all_content_items.push(crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&type_info.definition),
                    content: type_info.definition.clone(),
                });
            }
        }

        // Note: Macros are now stored as functions, so no separate loop needed

        // Step 2: Extract symbol_filename pairs for all entities
        let mut symbol_filename_pairs = Vec::new();

        // Extract from functions
        for func in &functions {
            symbol_filename_pairs.push((func.name.clone(), func.file_path.clone()));
        }

        // Extract from types
        for type_info in &types {
            symbol_filename_pairs.push((type_info.name.clone(), type_info.file_path.clone()));
        }

        // An object-like macro is stored twice on purpose: as a function,
        // which is where a caller looks it up by name, and here with its
        // expansion beside it, which is what reading a declaration needs.
        let object_macros = Self::object_macros_among(&functions);

        // Step 3: Insert content and metadata in parallel
        let (content_result, func_result, type_result, symbol_filename_result) = tokio::join!(
            async {
                if !all_content_items.is_empty() {
                    self.content_store.insert_batch(all_content_items).await
                } else {
                    Ok(())
                }
            },
            async {
                if !functions.is_empty() {
                    self.insert_functions_metadata_only(functions).await
                } else {
                    Ok(())
                }
            },
            async {
                if !types.is_empty() {
                    self.insert_types_metadata_only(types).await
                } else {
                    Ok(())
                }
            },
            async {
                if !symbol_filename_pairs.is_empty() {
                    self.symbol_filename_store
                        .insert_batch(symbol_filename_pairs)
                        .await
                } else {
                    Ok(())
                }
            }
        );

        content_result?;
        func_result?;
        type_result?;
        symbol_filename_result?;
        self.object_macro_store.insert_batch(object_macros).await?;

        Ok(())
    }

    // Function operations
    /// Record dispatch sites: calls that go through a value rather than
    /// naming a function.
    pub async fn insert_dispatch_sites(
        &self,
        sites: Vec<crate::types::DispatchSite>,
    ) -> Result<()> {
        self.dispatch_site_store.insert_batch(sites).await
    }

    /// Record functions installed in struct members.
    pub async fn insert_registrations(
        &self,
        registrations: Vec<crate::types::Registration>,
    ) -> Result<()> {
        self.registration_store.insert_batch(registrations).await
    }

    /// Record file-scope variables of aggregate type.
    pub async fn insert_globals(&self, globals: Vec<crate::types::GlobalVariable>) -> Result<()> {
        self.global_store.insert_batch(globals).await
    }

    /// Record functions named as call arguments.
    pub async fn insert_argument_functions(
        &self,
        arguments: Vec<crate::types::ArgumentFunction>,
    ) -> Result<()> {
        self.argument_function_store.insert_batch(arguments).await
    }

    pub async fn insert_unresolved_edges(
        &self,
        edges: Vec<crate::types::UnresolvedEdge>,
    ) -> Result<()> {
        self.unresolved_edge_store.insert_batch(edges).await
    }

    /// What the index cannot say about this name, and where to look instead.
    pub async fn find_unresolved_edges_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Vec<crate::types::UnresolvedEdge>> {
        let edges = self.unresolved_edge_store.find_by_name(name).await?;
        let manifest = self.git_manifest_cached(git_sha).await?;
        if manifest.is_empty() {
            return Ok(edges);
        }
        Ok(edges
            .into_iter()
            .filter(|edge| {
                manifest
                    .hash_of(&edge.file_path)
                    .is_some_and(|hash| hash == edge.git_file_hash)
            })
            .collect())
    }

    /// Every call handed this name.
    pub async fn find_argument_functions_of(
        &self,
        target: &str,
    ) -> Result<Vec<crate::types::ArgumentFunction>> {
        self.argument_function_store.find_by_target(target).await
    }

    /// Everything installed in one member of one type, at a revision.
    /// What each dispatch inside these functions can reach.
    ///
    /// A call chain that stops at `file->f_op->read()` stops one lookup short
    /// of the answer: the site is recorded, the registrations are recorded,
    /// and joining them is what the chain needs to keep going.
    pub async fn resolve_dispatches_in(
        &self,
        callers: &[String],
        git_sha: &str,
    ) -> Result<std::collections::HashMap<String, Vec<crate::types::ResolvedDispatch>>> {
        use crate::database::resolution::at_revision;

        let manifest = self.git_manifest_cached(git_sha).await?;
        let mut resolved = std::collections::HashMap::new();
        // A slot is asked about once per function that dispatches through it,
        // and ops tables are shared: cache what each one holds.
        let mut slots: std::collections::HashMap<(String, String), Vec<String>> =
            std::collections::HashMap::new();

        for caller in callers {
            let mut sites = at_revision(
                self.dispatch_site_store.find_by_caller(caller).await?,
                &manifest,
                |s| (s.file_path.as_str(), s.git_file_hash.as_str()),
            );
            if sites.is_empty() {
                continue;
            }
            self.type_chained_receivers(&mut sites, &manifest).await?;
            self.type_global_receivers(&mut sites, &manifest).await?;

            let mut dispatches = Vec::new();
            for site in sites {
                // A site whose receiver type is unknown reaches every member
                // of that name in the tree, which is not an answer a chain
                // can follow. `callers` reports those as a count.
                let Some(container_type) = site.receiver_type.clone() else {
                    continue;
                };

                let key = (container_type.clone(), site.member.clone());
                let targets = match slots.get(&key) {
                    Some(known) => known.clone(),
                    None => {
                        let mut targets: Vec<String> = at_revision(
                            self.registration_store
                                .find_by_slot(&container_type, &site.member)
                                .await?,
                            &manifest,
                            |r| (r.file_path.as_str(), r.git_file_hash.as_str()),
                        )
                        .into_iter()
                        .map(|registration| registration.target)
                        .collect();
                        targets.sort();
                        targets.dedup();
                        slots.insert(key, targets.clone());
                        targets
                    }
                };

                if targets.is_empty() {
                    continue;
                }

                dispatches.push(crate::types::ResolvedDispatch {
                    receiver_expr: site.receiver_expr.clone().unwrap_or_default(),
                    container_type,
                    member: site.member.clone(),
                    file_path: site.file_path.clone(),
                    line: site.line,
                    targets,
                });
            }

            if !dispatches.is_empty() {
                dispatches.sort_by(|a, b| {
                    (&a.file_path, a.line, &a.member).cmp(&(&b.file_path, b.line, &b.member))
                });
                resolved.insert(caller.clone(), dispatches);
            }
        }

        Ok(resolved)
    }

    /// Give a registration recorded through a field the container type it
    /// was installed into.
    ///
    /// `s->s_shrink->scan_objects = f` knows `s` is a `struct super_block`
    /// and that the receiver reads `s_shrink`; what that field is declared as
    /// lives with struct super_block, so it is looked up here, where the
    /// whole tree's types are available. A row whose path cannot be resolved
    /// keeps an empty container and joins nothing, which is what it did
    /// before it was recorded at all.
    /// Drop table rows whose claim the typedef does not support.
    ///
    /// `static bfa_isr_func_t bfa_isrs[N] = { ... }` is a table only because
    /// `bfa_isr_func_t` is a typedef for a function pointer, and the file that
    /// declares the table does not say so. The extractor records the claim and
    /// the name; this is where it is checked, against the typedef the index
    /// holds. An array of enum constants declared the same way keeps no rows.
    async fn keep_verified_tables(
        &self,
        registrations: &mut Vec<crate::types::Registration>,
        git_sha: &str,
    ) -> Result<()> {
        let claimed: HashSet<String> = registrations
            .iter()
            .filter(|r| r.member == crate::types::ARRAY_ELEMENT_MEMBER)
            .filter_map(|r| r.container_base_type.clone())
            .collect();
        if claimed.is_empty() {
            return Ok(());
        }

        let mut points_at_a_function = HashMap::new();
        for name in claimed {
            // A typedef the index does not hold cannot support the claim.
            // Saying so costs a table; keeping it would invent one.
            let verdict = self.type_is_function_pointer(&name, git_sha).await?;
            points_at_a_function.insert(name, verdict);
        }

        registrations.retain(|r| {
            let Some(claim) = r.container_base_type.as_deref() else {
                return true;
            };
            if r.member != crate::types::ARRAY_ELEMENT_MEMBER {
                return true;
            }
            points_at_a_function.get(claim).copied().unwrap_or(false)
        });

        Ok(())
    }

    async fn resolve_chained_registrations(
        &self,
        registrations: &mut [crate::types::Registration],
        manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<()> {
        let mut resolved: std::collections::HashMap<(String, String), Option<String>> =
            std::collections::HashMap::new();

        for registration in registrations.iter_mut() {
            if !registration.container_type.is_empty() {
                continue;
            }
            let (Some(base), Some(field)) = (
                registration.container_base_type.as_deref(),
                registration.container_field.as_deref(),
            ) else {
                continue;
            };

            let key = (base.to_string(), field.to_string());
            let container = match resolved.get(&key) {
                Some(known) => known.clone(),
                None => {
                    let mut current = Some(base.to_string());
                    for step in field.split('.') {
                        let Some(container_name) = current.take() else {
                            break;
                        };
                        current = self
                            .field_aggregate(&container_name, step, manifest)
                            .await?;
                    }
                    resolved.insert(key, current.clone());
                    current
                }
            };

            if let Some(container) = container {
                registration.container_type = container;
            }
        }

        Ok(())
    }

    /// What a field of a type is declared as, when every definition of that
    /// type at this revision agrees.
    ///
    /// A tree holds more than one `struct file`, and the types table holds
    /// each of them at every indexed commit. Disagreement means not enough is
    /// known, so the answer is nothing rather than one of the candidates.
    async fn field_aggregate(
        &self,
        container_name: &str,
        field: &str,
        manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Option<String>> {
        use crate::database::resolution::{aggregate_of, at_revision};

        let definitions = at_revision(
            self.type_store.find_all_by_name(container_name).await?,
            manifest,
            |t| (t.file_path.as_str(), t.git_file_hash.as_str()),
        );

        let mut agreed: Option<String> = None;
        for container in definitions {
            let Some(field_type) = container
                .members
                .iter()
                .find(|member| member.name == field)
                .and_then(|member| aggregate_of(&member.type_name))
            else {
                continue;
            };

            match &agreed {
                Some(known) if *known != field_type => return Ok(None),
                _ => agreed = Some(field_type),
            }
        }

        Ok(agreed)
    }

    pub async fn find_registrations_for_slot_git_aware(
        &self,
        container_type: &str,
        member: &str,
        git_sha: &str,
    ) -> Result<Vec<crate::types::Registration>> {
        let manifest = self.git_manifest_cached(git_sha).await?;

        // Asking the store for the slot would miss every registration made
        // through a field, because those rows do not know their container
        // until it is resolved. Ask for this container's rows and the ones
        // that have yet to name theirs, resolve, then filter.
        let mut registrations = crate::database::resolution::at_revision(
            self.registration_store
                .find_by_member_for_container(container_type, member)
                .await?,
            &manifest,
            |r| (r.file_path.as_str(), r.git_file_hash.as_str()),
        );
        self.resolve_chained_registrations(&mut registrations, &manifest)
            .await?;
        self.keep_verified_tables(&mut registrations, git_sha)
            .await?;
        registrations.retain(|r| r.container_type == container_type);

        Ok(registrations)
    }

    pub async fn find_registrations_of_git_aware(
        &self,
        target: &str,
        git_sha: &str,
    ) -> Result<Vec<crate::types::Registration>> {
        let manifest = self.git_manifest_cached(git_sha).await?;

        let mut registrations = crate::database::resolution::at_revision(
            self.registration_store.find_by_target(target).await?,
            &manifest,
            |r| (r.file_path.as_str(), r.git_file_hash.as_str()),
        );
        self.resolve_chained_registrations(&mut registrations, &manifest)
            .await?;
        self.keep_verified_tables(&mut registrations, git_sha)
            .await?;

        Ok(registrations)
    }

    /// Every call handed this name, at a revision.
    ///
    /// A row records only that an argument named an identifier; the name
    /// belongs to a function if the functions table says so, which is what
    /// separates `request_irq(irq, nic_intr, ...)` from an enum constant that
    /// happens to sit in the same position.
    pub async fn find_argument_functions_of_git_aware(
        &self,
        target: &str,
        git_sha: &str,
    ) -> Result<Vec<crate::types::ArgumentFunction>> {
        if self
            .find_function_git_aware(target, git_sha)
            .await?
            .is_none()
        {
            return Ok(Vec::new());
        }

        let manifest = self.git_manifest_cached(git_sha).await?;
        Ok(crate::database::resolution::at_revision(
            self.argument_function_store.find_by_target(target).await?,
            &manifest,
            |a| (a.file_path.as_str(), a.git_file_hash.as_str()),
        ))
    }

    /// Every recorded argument, for measurement.
    pub async fn all_argument_functions(&self) -> Result<Vec<crate::types::ArgumentFunction>> {
        self.argument_function_store.all().await
    }

    /// Whether a written type denotes a function pointer, following one
    /// typedef. `irq_handler_t` does; `unsigned int` does not.
    pub async fn type_is_function_pointer(&self, type_name: &str, git_sha: &str) -> Result<bool> {
        if type_name.contains("(*") {
            return Ok(true);
        }
        let bare = type_name
            .replace("const", " ")
            .replace('*', " ")
            .trim()
            .to_string();
        let Some(name) = bare.split_whitespace().next_back() else {
            return Ok(false);
        };
        // A typedef the index does not hold cannot support the claim.
        Ok(match self.find_typedef_git_aware(name, git_sha).await? {
            Some(typedef) => typedef.underlying_type.contains("(*"),
            None => false,
        })
    }

    /// The aggregate a member of a type is declared as, at a revision.
    ///
    /// `inode::i_rcu` is an `rcu_head`, which is what says the head a
    /// callback was queued on belongs to that inode.
    pub async fn member_aggregate_git_aware(
        &self,
        container_type: &str,
        member: &str,
        git_sha: &str,
    ) -> Result<Option<String>> {
        let manifest = self.git_manifest_cached(git_sha).await?;
        self.field_aggregate(container_type, member, &manifest)
            .await
    }

    /// Where a call puts the function it is handed.
    ///
    /// `request_irq(irq, nic_intr, ...)` installs nothing by itself: the
    /// wrapper hands its parameter to `request_threaded_irq`, which stores it
    /// in `irqaction::handler`. Follow that until a body stores the parameter
    /// in a member, and report the path taken, because a two-hop claim that
    /// reads like a one-hop fact is worse than no answer.
    ///
    /// Bounded: a wrapper chain that has not reached a member within a few
    /// hops is not one, and a cycle must not spin.
    pub async fn follow_handed_parameter(
        &self,
        callee: &str,
        argument_index: u32,
        git_sha: &str,
    ) -> Result<Option<crate::types::Handover>> {
        const MAX_HOPS: usize = 4;
        const MAX_BRANCHES: usize = 32;

        let mut seen = std::collections::HashSet::new();
        // Breadth first: a body often hands the same parameter to more than
        // one call, an error path among them, and the first is not the one
        // that registers.
        let mut queue = std::collections::VecDeque::new();
        queue.push_back((callee.to_string(), argument_index, Vec::<String>::new()));
        let mut visited = 0usize;

        while let Some((current, index, path)) = queue.pop_front() {
            if path.len() >= MAX_HOPS || visited >= MAX_BRANCHES {
                continue;
            }
            visited += 1;
            if !seen.insert((current.clone(), index)) {
                continue;
            }
            let Some(function) = self.find_function_git_aware(&current, git_sha).await? else {
                continue;
            };
            let Some(parameter) = function.parameters.get(index as usize) else {
                continue;
            };
            if parameter.name.is_empty() {
                continue;
            }
            // An integer handed into an integer member is not a function
            // being installed, and following it reports `nla_put_u32`
            // installing something in `nlattr::nla_type`.
            if path.is_empty()
                && !self
                    .type_is_function_pointer(&parameter.type_name, git_sha)
                    .await?
            {
                return Ok(None);
            }

            let mut path = path.clone();
            path.push(format!("{current}({})", parameter.name));

            let fates = crate::TreeSitterAnalyzer::parameter_fate(&function.body, &parameter.name);
            for fate in &fates {
                match fate {
                    crate::ParameterFate::StoredIn {
                        container_type,
                        member,
                    } if !container_type.is_empty() => {
                        return Ok(Some(crate::types::Handover::StoredIn {
                            path,
                            container_type: container_type.clone(),
                            member: member.clone(),
                        }));
                    }
                    crate::ParameterFate::Invoked => {
                        return Ok(Some(crate::types::Handover::Invoked { path }));
                    }
                    _ => {}
                }
            }
            for fate in &fates {
                if let crate::ParameterFate::HandedOn {
                    callee,
                    argument_index,
                } = fate
                {
                    queue.push_back((callee.clone(), *argument_index, path.clone()));
                }
            }
        }

        Ok(None)
    }

    /// Everything installed in one member of one type.
    pub async fn find_registrations_for_slot(
        &self,
        container_type: &str,
        member: &str,
    ) -> Result<Vec<crate::types::Registration>> {
        self.registration_store
            .find_by_slot(container_type, member)
            .await
    }

    /// Every place a function is installed.
    pub async fn find_registrations_of(
        &self,
        target: &str,
    ) -> Result<Vec<crate::types::Registration>> {
        self.registration_store.find_by_target(target).await
    }

    /// Everything installed in a member of this name, whatever the type.
    pub async fn find_registrations_by_member(
        &self,
        member: &str,
    ) -> Result<Vec<crate::types::Registration>> {
        self.registration_store.find_by_member(member).await
    }

    /// Call sites that can reach this function without naming it: a member
    /// call where the function is installed in that member, or a site that
    /// names it outright.
    ///
    /// Rows are filtered to the revision being queried, the same way function
    /// lookups are, so a registration removed in a later commit stops
    /// answering.
    pub async fn find_indirect_callers(
        &self,
        target: &str,
        git_sha: &str,
    ) -> Result<Vec<crate::database::resolution::IndirectCaller>> {
        use crate::database::resolution::{at_revision, group_by_member, indirect_callers};

        let manifest = self.git_manifest_cached(git_sha).await?;

        let mut registrations = at_revision(
            self.registration_store.find_by_target(target).await?,
            &manifest,
            |r| (r.file_path.as_str(), r.git_file_hash.as_str()),
        );
        self.resolve_chained_registrations(&mut registrations, &manifest)
            .await?;
        self.keep_verified_tables(&mut registrations, git_sha)
            .await?;
        let stated = at_revision(
            self.dispatch_site_store.find_by_target(target).await?,
            &manifest,
            |s| (s.file_path.as_str(), s.git_file_hash.as_str()),
        );

        // Only the members the function is actually installed in matter.
        let mut sites = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for registration in &registrations {
            if !seen.insert(registration.member.clone()) {
                continue;
            }
            sites.extend(at_revision(
                self.dispatch_site_store
                    .find_by_member(&registration.member)
                    .await?,
                &manifest,
                |s| (s.file_path.as_str(), s.git_file_hash.as_str()),
            ));
        }

        self.type_chained_receivers(&mut sites, &manifest).await?;
        self.type_global_receivers(&mut sites, &manifest).await?;

        Ok(indirect_callers(
            &registrations,
            &group_by_member(sites),
            &stated,
        ))
    }

    /// Finish typing the receivers the analyzer could only half-type.
    ///
    /// A site written `file->f_op->read()` stored the type of `file` and the
    /// field `f_op`. What `f_op` is declared as lives with struct file, in a
    /// header the analyzer was not looking at, so the last hop happens here,
    /// where the whole tree's types are available.
    /// Type a receiver that names a file-scope variable declared elsewhere.
    ///
    /// `ppc_md.memory_block_size()` is written in a file that includes
    /// machdep.h rather than containing it, so the analyzer sees a plain name
    /// it cannot type. The declaration is in the index; the join happens here.
    ///
    /// A name declared with two different aggregates at one revision is left
    /// alone: filing a site under the wrong type joins it with the wrong
    /// registrations, which is worse than admitting the type is unknown.
    async fn type_global_receivers(
        &self,
        sites: &mut [crate::types::DispatchSite],
        manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<()> {
        let mut resolved: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();

        for site in sites.iter_mut() {
            if site.receiver_type.is_some() || site.receiver_base_type.is_some() {
                continue;
            }
            let Some(receiver) = site.receiver_expr.as_deref() else {
                continue;
            };
            let receiver = receiver.trim();
            if receiver.is_empty()
                || !receiver.chars().all(|c| c.is_alphanumeric() || c == '_')
                || receiver.chars().next().is_some_and(|c| c.is_numeric())
            {
                continue;
            }

            let type_name = match resolved.get(receiver) {
                Some(known) => known.clone(),
                None => {
                    let declarations = crate::database::resolution::at_revision(
                        self.global_store.find_by_name(receiver).await?,
                        manifest,
                        |global| (global.file_path.as_str(), global.git_file_hash.as_str()),
                    );
                    let mut types: Vec<String> = declarations
                        .into_iter()
                        .map(|global| global.type_name)
                        .collect();
                    types.sort();
                    types.dedup();
                    let answer = match types.len() {
                        1 => types.pop(),
                        _ => None,
                    };
                    resolved.insert(receiver.to_string(), answer.clone());
                    answer
                }
            };

            site.receiver_type = type_name;
        }

        Ok(())
    }

    async fn type_chained_receivers(
        &self,
        sites: &mut [crate::types::DispatchSite],
        manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<()> {
        let mut resolved: std::collections::HashMap<(String, String), Option<String>> =
            std::collections::HashMap::new();

        for site in sites.iter_mut() {
            if site.receiver_type.is_some() {
                continue;
            }
            let (Some(base), Some(field)) = (
                site.receiver_base_type.as_deref(),
                site.receiver_field.as_deref(),
            ) else {
                continue;
            };

            let key = (base.to_string(), field.to_string());
            let field_type = match resolved.get(&key) {
                Some(known) => known.clone(),
                None => {
                    // Walk the path one field at a time: `display->parent->dsb`
                    // needs the type of `parent` before the type of `dsb`.
                    let mut current = Some(base.to_string());
                    for step in field.split('.') {
                        let Some(container_name) = current.take() else {
                            break;
                        };
                        current = self
                            .field_aggregate(&container_name, step, manifest)
                            .await?;
                    }

                    resolved.insert(key, current.clone());
                    current
                }
            };

            site.receiver_type = field_type;
        }

        Ok(())
    }

    /// Dispatch sites that go through the named member.
    pub async fn find_dispatch_sites_by_member(
        &self,
        member: &str,
    ) -> Result<Vec<crate::types::DispatchSite>> {
        self.dispatch_site_store.find_by_member(member).await
    }

    /// Dispatch sites inside the named function.
    pub async fn find_dispatch_sites_by_caller(
        &self,
        caller_name: &str,
    ) -> Result<Vec<crate::types::DispatchSite>> {
        self.dispatch_site_store.find_by_caller(caller_name).await
    }

    /// The object-like macros in a batch of extracted functions.
    ///
    /// A macro reaches the database as a function with no return type; an
    /// object-like one also has no parameters, and its body is the whole
    /// `#define`. The expansion is what follows the name — the alias or the
    /// attribute — and is the only part a declaration needs.
    fn object_macros_among(
        functions: &[FunctionInfo],
    ) -> Vec<crate::database::object_macros::ObjectMacro> {
        functions
            .iter()
            .filter(|f| f.return_type.is_empty() && f.parameters.is_empty())
            .filter_map(|f| {
                let directive = f.body.trim_start().strip_prefix('#')?.trim_start();
                if !directive.starts_with("define") {
                    return None;
                }
                let expansion = f.body.split_once(&f.name).map(|(_, rest)| rest.trim())?;
                Some(crate::database::object_macros::ObjectMacro {
                    name: f.name.clone(),
                    expansion: expansion.to_string(),
                    file_path: f.file_path.clone(),
                    git_file_hash: f.git_file_hash.clone(),
                })
            })
            .collect()
    }

    pub async fn insert_functions(&self, functions: Vec<FunctionInfo>) -> Result<()> {
        // Extract (symbol_name, filename) pairs for symbol_filename table
        let symbol_filename_pairs: Vec<(String, String)> = functions
            .iter()
            .map(|f| (f.name.clone(), f.file_path.clone()))
            .collect();
        let object_macros = Self::object_macros_among(&functions);

        // Insert functions
        self.function_store.insert_batch(functions).await?;
        self.object_macro_store.insert_batch(object_macros).await?;

        // Insert into symbol_filename table
        self.symbol_filename_store
            .insert_batch(symbol_filename_pairs)
            .await?;

        Ok(())
    }

    // --- Workdir overlay helpers ---
    //
    // Two mechanisms, not one. `candidate_state` answers for a single named
    // file with a stat and, on a mismatch, a hash, which is what a
    // name-keyed answer runs on. The `workdir_*` helpers below it still consult a full
    // `WorkdirIndex`, built by walking every tracked file, for the queries a
    // name cannot bound in advance (regex, grep, callers) and for the
    // on-miss fallback (a symbol with no row at all). `ensure_workdir_index_built`
    // is what makes that walk lazy: the first of these helpers actually
    // consulted in a process builds it, once, instead of every command
    // building it whether asked for or not — and keeps it current across
    // the top-level commands of one REPL session rather than
    // freezing it at whatever the working tree held on that first build.

    /// Build the working-copy overlay for `git_sha` if nothing has this
    /// process yet, unless it is unusable for it (see
    /// `workdir_overlay_usable`); refresh it, at most once per top-level
    /// command (see `workdir_command_generation`'s doc comment), if it
    /// already exists.
    ///
    /// A naive "refresh whenever asked" is wrong here: a single `func`
    /// command calls both `get_function_callees_git_aware` and
    /// `get_function_callers_git_aware`, each of which reaches this through
    /// its own `workdir_find_*` helper, so an unconditional refresh would
    /// walk the tracked-file set twice for one command instead of once —
    /// measured while building this patch: 266,533 statx for `help; func
    /// alloc_super; help` against ~131,489 for a single build, because the
    /// second call inside the same `func` command refreshed instead of
    /// reusing. Gating on the command generation fixes that: every call
    /// within one command sees the same generation and reuses; the first
    /// call in the *next* command sees a new one and refreshes through
    /// `build_incremental`'s own cache (HEAD SHA plus per-file mtime/size,
    /// the mechanism `test_incremental_reuses_cache` in workdir.rs covers
    /// directly) — a stat of each tracked file, not a re-read or a re-parse
    /// of the ones that have not changed. A command that never touches this
    /// path (`help` on its own) still never pays either cost.
    fn ensure_workdir_index_built(&self, git_sha: &str) {
        if !self.workdir_overlay_usable(git_sha) {
            return;
        }
        let current_generation = self.workdir_command_generation.load(Ordering::Relaxed);
        let built_for_generation = self
            .workdir_index_generation
            .swap(current_generation, Ordering::Relaxed);
        if built_for_generation == current_generation && self.has_workdir_index() {
            return;
        }
        let repo_path = Path::new(&self.git_repo_path);
        let (built, refreshing) = {
            let guard = self.workdir_index.read().unwrap();
            let refreshing = guard.is_some();
            (
                WorkdirIndex::build_incremental(repo_path, guard.as_ref()),
                refreshing,
            )
        };
        match built {
            Ok(workdir) => {
                tracing::info!(
                    "workdir: {} overlay: {} dirty, {} deleted, {} functions, {} types",
                    if refreshing {
                        "refreshed"
                    } else {
                        "built on demand"
                    },
                    workdir.dirty_file_count(),
                    workdir.deleted_file_count(),
                    workdir.function_count(),
                    workdir.type_count(),
                );
                self.set_workdir_index(workdir);
            }
            Err(e) => tracing::info!(
                "workdir: could not {} overlay: {e}",
                if refreshing {
                    "refresh"
                } else {
                    "build on demand"
                }
            ),
        }
    }

    /// Look up a function in the workdir overlay (if set).
    fn workdir_find_function(&self, name: &str, git_sha: &str) -> Option<FunctionInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard.as_ref().and_then(|w| w.find_function(name).cloned())
    }

    /// Look up all functions matching a name in the workdir overlay.
    fn workdir_find_all_functions(&self, name: &str, git_sha: &str) -> Vec<FunctionInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|w| w.find_all_functions(name).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Look up all types matching a name in the workdir overlay.
    fn workdir_find_all_types(&self, name: &str, git_sha: &str) -> Vec<TypeInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|w| w.find_all_types(name).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Find callers in the workdir overlay.
    fn workdir_find_callers(&self, name: &str, git_sha: &str) -> Vec<FunctionInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|w| w.find_callers(name).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Find callees in the workdir overlay.
    fn workdir_find_callees(&self, name: &str, git_sha: &str) -> Option<Vec<String>> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard.as_ref().and_then(|w| w.find_callees(name))
    }

    /// Grep function bodies in the workdir overlay.
    fn workdir_grep_functions(
        &self,
        pattern: &str,
        path_pattern: Option<&str>,
        git_sha: &str,
    ) -> Vec<FunctionInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|w| {
                w.grep_functions(pattern, path_pattern)
                    .into_iter()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Regex search for functions in the workdir overlay.
    fn workdir_find_functions_regex(&self, pattern: &str, git_sha: &str) -> Vec<FunctionInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|w| {
                w.find_functions_regex(pattern)
                    .into_iter()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Regex search for types in the workdir overlay.
    fn workdir_find_types_regex(&self, pattern: &str, git_sha: &str) -> Vec<TypeInfo> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|w| w.find_types_regex(pattern).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Check if a file is deleted in the workdir overlay.
    fn workdir_is_deleted(&self, file_path: &str, git_sha: &str) -> bool {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard.as_ref().is_some_and(|w| w.is_deleted(file_path))
    }

    fn workdir_is_dirty(&self, file_path: &str, git_sha: &str) -> bool {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard.as_ref().is_some_and(|w| w.is_dirty(file_path))
    }

    fn workdir_dirty_count(&self, git_sha: &str) -> usize {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard.as_ref().map_or(0, |w| w.dirty_file_count())
    }

    /// What one candidate file — a path a query already named, with the blob
    /// hash its row (or the tree) says belongs there — currently holds. The
    /// primitive a common query runs on: a stat, and only on a
    /// mismatch a hash, of the handful of files a name-keyed lookup touches,
    /// never a walk of the tree the query did not ask about. `git_sha` gates
    /// it on `is_checked_out`: comparing the working copy against a blob
    /// from a revision it does not represent would answer for the wrong one.
    fn candidate_state(
        &self,
        file_path: &str,
        expected_hash: &str,
        git_sha: &str,
    ) -> CandidateFile {
        if !self.workdir_overlay_usable(git_sha) {
            return CandidateFile::Indexed;
        }
        let abs_path = Path::new(&self.git_repo_path).join(file_path);
        match self.working_copy.compare(&abs_path, expected_hash) {
            Ok(WorkingCopy::Same) => CandidateFile::Indexed,
            Ok(WorkingCopy::Different) => CandidateFile::Edited,
            Ok(WorkingCopy::Absent) => CandidateFile::Deleted,
            Err(e) => {
                // A stat that fails for a reason other than "not found" (a
                // permission error, say) is not evidence the file changed;
                // trust the row rather than manufacture an edit or a
                // deletion from an I/O error.
                tracing::debug!("workdir: could not stat {file_path}: {e}");
                CandidateFile::Indexed
            }
        }
    }

    /// Read and parse one file from the working copy, hashed the same way a
    /// row's `git_file_hash` is — a git blob id, not the workdir index's
    /// internal blake3 — so the result is indistinguishable from a row to
    /// whatever compares it against one.
    fn reparse_file(&self, file_path: &str) -> Option<crate::treesitter_analyzer::FileAnalysis> {
        let abs_path = Path::new(&self.git_repo_path).join(file_path);
        let content = std::fs::read_to_string(&abs_path).ok()?;
        let hash = self.working_copy.blob_id_of(&abs_path).ok().flatten()?;
        let mut analyzer = TreeSitterAnalyzer::new().ok()?;
        let source_root = Some(Path::new(&self.git_repo_path));
        match analyzer.analyze_source_with_metadata(
            &content,
            Path::new(file_path),
            &hash,
            source_root,
        ) {
            Ok(analysis) => Some(analysis),
            Err(e) => {
                tracing::info!("workdir: failed to re-parse {file_path}: {e}");
                None
            }
        }
    }

    /// The functions and macros named `name` in one edited candidate file —
    /// the answer for `CandidateFile::Edited`, without building an index over
    /// anything the query did not name.
    fn reparse_functions(&self, file_path: &str, name: &str) -> Vec<FunctionInfo> {
        let Some(analysis) = self.reparse_file(file_path) else {
            return Vec::new();
        };
        analysis
            .functions
            .into_iter()
            .chain(analysis.macros)
            .filter(|f| f.name.eq_ignore_ascii_case(name))
            .collect()
    }

    /// The same, for a type or typedef name (typedefs are extracted into
    /// `types` with `kind = "typedef"`, the way the indexer stores them).
    fn reparse_types(&self, file_path: &str, name: &str) -> Vec<TypeInfo> {
        let Some(analysis) = self.reparse_file(file_path) else {
            return Vec::new();
        };
        analysis
            .types
            .into_iter()
            .filter(|t| t.name.eq_ignore_ascii_case(name))
            .collect()
    }

    /// Merge a HEAD manifest with workdir dirty/deleted state.
    #[allow(dead_code)]
    fn workdir_merged_manifest(
        &self,
        head_manifest: std::collections::HashMap<String, String>,
    ) -> std::collections::HashMap<String, String> {
        let guard = self.workdir_index.read().unwrap();
        match guard.as_ref() {
            Some(w) => w.merged_manifest(&head_manifest),
            None => head_manifest,
        }
    }

    /// The answer when the requested revision cannot be mapped onto the files
    /// a symbol lives in: the paths do not exist at that revision, the
    /// revision itself does not resolve, or no row carries the content the
    /// revision holds.
    ///
    /// All three say the same thing — the index cannot show the symbol is in
    /// the tree that was named — so all three answer that it is not there.
    /// Where its rows do live is logged, from the revisions the index recorded
    /// for their content.
    async fn function_not_at_revision(
        &self,
        name: &str,
        git_sha: &str,
        why: Absent,
    ) -> Result<Option<FunctionInfo>> {
        // On-miss scan: a symbol that exists only in an edited file has no
        // row in the index and no candidate path from symbol_filename. The
        // eager overlay already answers this before the manifest is built, but
        // an absence after the manifest has to answer it too, or an edit
        // would be invisible once the overlay is no longer built eagerly. Scan the overlay here — 197,179 stat calls become a
        // lookup in a HashMap that is already in memory, ~0.01ms for the four
        // files a typical query touches against 1.10s for the scan it replaces.
        if let Some(func) = self.workdir_find_function(name, git_sha) {
            let dirty = self.workdir_dirty_count(git_sha);
            tracing::info!(
                "function '{name}' is not in the index at {git_sha}: {}; but {dirty} dirty file(s) have it — answering from the working tree",
                why.reason()
            );
            return Ok(Some(func));
        }
        self.log_absent_function(name, git_sha, why).await;
        Ok(None)
    }

    /// The same, for a lookup that returns every match rather than one.
    async fn functions_not_at_revision(
        &self,
        name: &str,
        git_sha: &str,
        why: Absent,
    ) -> Result<Vec<FunctionInfo>> {
        let workdir_matches = self.workdir_find_all_functions(name, git_sha);
        if !workdir_matches.is_empty() {
            let dirty = self.workdir_dirty_count(git_sha);
            tracing::info!(
                "function '{name}' is not in the index at {git_sha}: {}; but {dirty} dirty file(s) have {} match(es) — answering from the working tree",
                why.reason(),
                workdir_matches.len()
            );
            return Ok(self.filter_implementations_only(workdir_matches));
        }
        self.log_absent_function(name, git_sha, why).await;
        Ok(Vec::new())
    }

    /// The same, for types. A dirty file is part of the revision the caller
    /// asked about — the tree plus what is on disk — so a match from one is an
    /// answer for that revision, not a borrowed answer from another.
    ///
    /// The candidate-level check in `find_types_git_aware` already answers a
    /// dirty *known* candidate; this is reached only when no candidate
    /// existed at all, or none of them held the content indexed — so a match
    /// here can only come from the on-miss scan, built lazily, once.
    async fn types_not_at_revision(
        &self,
        name: &str,
        git_sha: &str,
        why: Absent,
    ) -> Result<Vec<TypeInfo>> {
        let on_miss = self.workdir_find_all_types(name, git_sha);
        if !on_miss.is_empty() {
            let dirty = self.workdir_dirty_count(git_sha);
            tracing::info!(
                "type '{name}' is not in the index at {git_sha}: {}; but {dirty} dirty file(s) have {} match(es) — answering from the working tree (on-miss)",
                why.reason(),
                on_miss.len()
            );
            return Ok(on_miss);
        }
        let place = self
            .find_type(name)
            .await?
            .map(|ty| (ty.file_path, ty.git_file_hash));
        self.log_absent_symbol("type", name, git_sha, why, place)
            .await;
        Ok(Vec::new())
    }

    /// The same, for typedefs.
    async fn typedef_not_at_revision(
        &self,
        name: &str,
        git_sha: &str,
        why: Absent,
    ) -> Result<Option<TypedefInfo>> {
        // On-miss scan: typedefs are stored as types in the workdir overlay.
        // If a dirty file defines a type of the same name, surface that it
        // exists in the working tree rather than silently returning absence.
        let on_miss = self.workdir_find_all_types(name, git_sha);
        if !on_miss.is_empty() {
            let dirty = self.workdir_dirty_count(git_sha);
            tracing::info!(
                "typedef '{name}' is not in the index at {git_sha}: {}; but {dirty} dirty file(s) have a type of the same name — answering from the working tree (on-miss)",
                why.reason()
            );
        }
        let place = self
            .find_typedef(name)
            .await?
            .map(|td| (td.file_path, td.git_file_hash));
        self.log_absent_symbol("typedef", name, git_sha, why, place)
            .await;
        Ok(None)
    }

    /// Report a function absent at a revision, naming the revisions its rows
    /// were indexed at, or the files they came from when the index recorded no
    /// revision for their content.
    async fn log_absent_function(&self, name: &str, git_sha: &str, why: Absent) {
        let elsewhere = match self.symbol_revisions(name).await {
            Ok((revisions, branches)) if !revisions.is_empty() => {
                describe_revisions(&revisions, &branches)
            }
            Ok(_) => match self.function_store.find_all_by_name_unfiltered(name).await {
                Ok(rows) => describe_files(
                    &rows
                        .into_iter()
                        .map(|r| (r.file_path, r.git_file_hash))
                        .collect::<Vec<_>>(),
                ),
                Err(e) => format!("the index could not say where it is: {e}"),
            },
            Err(e) => format!("the index could not say where it is: {e}"),
        };
        log_absence("function", name, git_sha, why, &elsewhere);
    }

    /// The same for a symbol whose rows are not in the functions table. The
    /// row is read to describe where its content lives, never to answer with.
    async fn log_absent_symbol(
        &self,
        kind: &str,
        name: &str,
        git_sha: &str,
        why: Absent,
        place: Option<(String, String)>,
    ) {
        let Some((path, hash)) = place else {
            log_absence(kind, name, git_sha, why, "the index has no row for it");
            return;
        };
        let elsewhere = match self.where_hash_lives(&hash).await {
            Ok((revisions, branches)) if !revisions.is_empty() => {
                describe_revisions(&revisions, &branches)
            }
            Ok(_) => describe_files(&[(path, hash)]),
            Err(e) => format!("the index could not say where it is: {e}"),
        };
        log_absence(kind, name, git_sha, why, &elsewhere);
    }

    /// Whether the repository can resolve a revision at all.
    fn revision_resolves(&self, git_sha: &str) -> bool {
        match gix::discover(&self.git_repo_path) {
            Ok(repo) => crate::git::resolve_to_commit(&repo, git_sha).is_ok(),
            Err(_) => false,
        }
    }

    /// Which absence it is when no path resolved. `resolve_git_file_hashes`
    /// answers with an empty map both for a path that is not in the tree and
    /// for a git failure, so ask the repository which one happened. Only
    /// reached on the absence path, so the extra `gix::discover` is not on any
    /// answer's way.
    fn why_nothing_resolved(&self, git_sha: &str) -> Absent {
        if self.revision_resolves(git_sha) {
            Absent::PathsNotInTree
        } else {
            Absent::RevisionUnknown
        }
    }

    /// The revisions and branches that hold one file blob.
    async fn where_hash_lives(
        &self,
        hash: &str,
    ) -> Result<(
        Vec<String>,
        Vec<crate::database::branches::IndexedBranchInfo>,
    )> {
        let revisions = self.revisions_for_file_hash(hash).await?;
        let branches = self.branches_for_file_hash(hash).await?;
        Ok((revisions, branches))
    }

    /// Find a function by name without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `find_function_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns the "best match" from all indexed versions without considering git history.
    /// Prefers .c over .h files, implementations over declarations, but may not match
    /// the version currently in your working directory.
    pub async fn find_function(&self, name: &str) -> Result<Option<FunctionInfo>> {
        // Get all functions with this name and select the best one (prefers .c over .h, implementations over declarations)
        let all_matches = self
            .function_store
            .find_all_by_name_unfiltered(name)
            .await?;
        if all_matches.is_empty() {
            return Ok(None);
        }

        // Use the same smart selection logic as git-aware lookups
        let best_match = self.select_best_function_match(all_matches);
        Ok(Some(best_match))
    }

    pub async fn find_function_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Option<FunctionInfo>> {
        let git_manifest = self.git_manifest_cached(git_sha).await?;
        if git_manifest.is_empty() {
            let why = self.why_nothing_resolved(git_sha);
            return self.function_not_at_revision(name, git_sha, why).await;
        }
        self.find_function_with_manifest(name, &git_manifest).await
    }

    /// Find a function by name, and say which other definitions were set aside.
    ///
    /// For a command that must answer about one definition. `callers` and
    /// `callchain` start from a single function and cannot report every
    /// definition the way a callee query does, so they report the choice.
    pub async fn find_function_git_aware_reporting(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Option<ChosenDefinition>> {
        let git_manifest = self.git_manifest_cached(git_sha).await?;
        if git_manifest.is_empty() {
            let why = self.why_nothing_resolved(git_sha);
            return Ok(self
                .function_not_at_revision(name, git_sha, why)
                .await?
                .map(|function| ChosenDefinition {
                    function,
                    others: Vec::new(),
                }));
        }
        self.find_function_with_manifest_reporting(name, &git_manifest)
            .await
    }

    /// Find a function by name using a pre-generated git manifest (fast - no manifest regeneration)
    pub async fn find_function_with_manifest(
        &self,
        name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Option<FunctionInfo>> {
        Ok(self
            .find_function_with_manifest_reporting(name, git_manifest)
            .await?
            .map(|chosen| chosen.function))
    }

    /// The body of `find_function_with_manifest`, keeping the alternatives.
    pub async fn find_function_with_manifest_reporting(
        &self,
        name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Option<ChosenDefinition>> {
        let revision = match git_manifest.revision() {
            "" => "the revision asked about",
            sha => sha,
        };

        // Step 1: Get candidate file paths from symbol_filename table
        let unique_file_paths = self
            .symbol_filename_store
            .get_filenames_for_symbol(name)
            .await?;
        if unique_file_paths.is_empty() {
            // No row has ever named this function: the on-miss path is the
            // only one that can still find it, in an edit the index has
            // never seen.
            return Ok(self
                .function_not_at_revision(name, revision, Absent::PathsNotInTree)
                .await?
                .map(ChosenDefinition::only));
        }

        // Step 2: Use manifest to get hashes for candidate files (fast HashMap lookups)
        let mut resolved_hashes = Vec::new();
        for file_path in &unique_file_paths {
            if let Some(hash) = git_manifest.hash_of(file_path) {
                resolved_hashes.push((file_path.clone(), hash));
            }
        }

        if resolved_hashes.is_empty() {
            return Ok(self
                .function_not_at_revision(name, revision, Absent::PathsNotInTree)
                .await?
                .map(ChosenDefinition::only));
        }

        // Step 3: stat (and, on a mismatch, hash) each candidate against the
        // blob it has at this revision. A match answers the indexed row with
        // no further git call; a difference is an edit, answered by parsing
        // that one file; a deletion answers nothing for that candidate.
        let mut matches = Vec::new();
        for (file_path, git_hash) in &resolved_hashes {
            match self.candidate_state(file_path, git_hash, revision) {
                CandidateFile::Indexed => {
                    if let Some(func) = self
                        .function_store
                        .find_by_name_file_and_hash(name, file_path, git_hash)
                        .await?
                    {
                        matches.push(func);
                    }
                }
                CandidateFile::Edited => matches.extend(self.reparse_functions(file_path, name)),
                CandidateFile::Deleted => {}
            }
        }

        // Step 4: Pick the best result (prefer implementation over declaration)
        if matches.is_empty() {
            return Ok(self
                .function_not_at_revision(name, revision, Absent::ContentNotIndexed)
                .await?
                .map(ChosenDefinition::only));
        }

        Ok(Some(self.choose_definition(matches)))
    }

    /// Get just the types field for a function using pre-generated manifest (very fast - no body fetching)
    pub async fn get_function_types_with_manifest(
        &self,
        name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Vec<String>> {
        // Query functions table directly - only read the columns we need
        let escaped_name = name.replace("'", "''");
        let table = self.connection.open_table("functions").execute().await?;

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Find best matching function and extract types
        let mut matches = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let line_start_array = batch
                    .column(3)
                    .as_any()
                    .downcast_ref::<arrow::array::Int64Array>()
                    .unwrap();
                let line_end_array = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<arrow::array::Int64Array>()
                    .unwrap();

                // Find the types column
                let types_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "types")
                    .ok_or_else(|| anyhow::anyhow!("types column not found in functions table"))?;
                let types_array = batch
                    .column(types_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let file_path = file_path_array.value(i);
                    let git_file_hash = git_file_hash_array.value(i);

                    // Check if this function exists at the target git SHA
                    if let Some(expected_hash) = git_manifest.hash_of(file_path) {
                        if git_file_hash == expected_hash {
                            // Parse the types JSON
                            let types = if types_array.is_null(i) {
                                None
                            } else {
                                serde_json::from_str::<Vec<String>>(types_array.value(i)).ok()
                            };

                            matches.push((
                                file_path.to_string(),
                                line_start_array.value(i) as u32,
                                line_end_array.value(i) as u32,
                                types,
                            ));
                        }
                    }
                }
            }
        }

        if matches.is_empty() {
            return Ok(Vec::new());
        }

        // Select best match (prefer implementation over declaration)
        let best_match = matches
            .into_iter()
            .max_by_key(|(file_path, line_start, line_end, _)| {
                let line_count = line_end.saturating_sub(*line_start);
                let is_header = file_path.ends_with(".h");
                (if is_header { 0 } else { 1 }, line_count)
            });

        match best_match {
            Some((_, _, _, Some(types))) => Ok(types),
            _ => Ok(Vec::new()),
        }
    }

    /// Find ALL functions by name at a specific git commit, excluding declarations
    pub async fn find_all_functions_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        // Step 1: Get candidate file paths from symbol_filename table (optimized - no need to load full function records)
        let unique_file_paths = self
            .symbol_filename_store
            .get_filenames_for_symbol(name)
            .await?;
        if unique_file_paths.is_empty() {
            // No row has ever named this function: only the on-miss path can
            // still find it, in an edit the index has never seen.
            return self
                .functions_not_at_revision(name, git_sha, Absent::PathsNotInTree)
                .await;
        }

        tracing::debug!(
            "find_all_functions_git_aware: Found {} unique files for function '{}'",
            unique_file_paths.len(),
            name
        );

        // Step 2: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            return self
                .functions_not_at_revision(name, git_sha, self.why_nothing_resolved(git_sha))
                .await;
        }

        // Step 3: stat (and, on a mismatch, hash) each candidate against the
        // blob it has at this revision — a handful of files, not the working
        // tree. A match answers the indexed row with no further git call; a
        // difference is an edit, answered by parsing that one file; a
        // deletion answers nothing for that candidate.
        let mut matches = Vec::new();
        for (file_path, git_hash) in &resolved_hashes {
            match self.candidate_state(file_path, git_hash, git_sha) {
                CandidateFile::Indexed => {
                    if let Some(func) = self
                        .function_store
                        .find_by_name_file_and_hash(name, file_path, git_hash)
                        .await?
                    {
                        matches.push(func);
                    }
                }
                CandidateFile::Edited => matches.extend(self.reparse_functions(file_path, name)),
                CandidateFile::Deleted => {}
            }
        }

        // Step 4: Filter out declarations but keep all implementations
        if matches.is_empty() {
            // Not a resolution failure: the revision is known and no row holds
            // the content it has. Either way the symbol is not in that tree.
            return self
                .functions_not_at_revision(name, git_sha, Absent::ContentNotIndexed)
                .await;
        }

        let mut implementations = self.filter_implementations_only(matches);
        // A stable order, so two runs and two readers see the same list. The
        // candidate files are resolved through a hash map, so without this the
        // nine definitions of `pr_warn` came back in a different order each
        // run, which reads as the tree having changed.
        implementations.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then(a.line_start.cmp(&b.line_start))
        });
        tracing::info!(
            "Git-aware lookup succeeded: found {} implementations of '{}' at commit '{}'",
            implementations.len(),
            name,
            git_sha
        );
        Ok(implementations)
    }

    /// Filter out declarations, keeping only function implementations
    ///
    /// The row's own text decides, the same test a callee query uses. A body
    /// length threshold decided it before -- "more than 50 bytes" -- and
    /// dropped short definitions that are not declarations at all: of six
    /// definitions of `kfree` in Linux, a callee query reported six and this
    /// listed five. Two commands in one answer then disagreed about how many
    /// definitions a name has, which is the thing the reader was being asked
    /// to go and check.
    fn filter_implementations_only(&self, functions: Vec<FunctionInfo>) -> Vec<FunctionInfo> {
        functions
            .into_iter()
            .filter(|func| {
                // Macros (empty return_type) are always implementations
                if func.return_type.is_empty() {
                    return true;
                }
                !func.body.is_empty() && !crate::types::text_is_prototype(&func.body)
            })
            .collect()
    }

    /// Select the best function match, prioritizing definitions over declarations
    fn select_best_function_match(&self, matches: Vec<FunctionInfo>) -> FunctionInfo {
        self.choose_definition(matches).function
    }

    /// The definition to answer about, and every other definition of the name.
    ///
    /// The choice is a heuristic and stays one -- which definition a call site
    /// reaches depends on the file it is written in and on the configuration
    /// the tree is built with, and the index knows neither. What changes is
    /// that the alternatives come back with it, so a caller can say a choice
    /// was made instead of presenting it as the answer.
    ///
    /// A prototype is not an alternative: nearly every exported function has
    /// one, and counting it would call almost every name ambiguous. The row's
    /// own text decides, the same test a callee query uses.
    fn choose_definition(&self, mut matches: Vec<FunctionInfo>) -> ChosenDefinition {
        if matches.len() == 1 {
            return ChosenDefinition::only(matches.into_iter().next().unwrap());
        }

        // The language most definitions of this name are written in. Two
        // languages that give one name to two things are not one ambiguous
        // name, and `Device::pr_warn` in rust/kernel/device.rs is stored under
        // the bare name, so it competes with the C macro that 4,065 functions
        // call. Ranking the minority language last answers the question the
        // tree is mostly written in; where a name is defined in one language
        // this decides nothing.
        let mut by_language: HashMap<&str, usize> = HashMap::new();
        for candidate in &matches {
            *by_language
                .entry(crate::types::path_language(&candidate.file_path))
                .or_default() += 1;
        }
        // A strict majority or nothing: more than half the definitions, not
        // merely more than any other language. Two definitions in two
        // languages have no majority, and picking the alphabetically later one
        // would decide a C tree's answer by the spelling of an extension. The
        // rung is a stand-in for an extraction defect -- a Rust method stored
        // under its bare name -- so it fires where the tree is nearly
        // unanimous and stays out of the way otherwise.
        let highest = by_language.values().copied().max().unwrap_or_default();
        let unique_top = by_language
            .values()
            .filter(|count| **count == highest)
            .count()
            == 1;
        let majority_language = match unique_top && highest * 2 > matches.len() {
            true => by_language
                .iter()
                .find(|(_, count)| **count == highest)
                .map(|(language, _)| language.to_string())
                .unwrap_or_default(),
            false => String::new(),
        };

        // Prioritize by multiple criteria
        matches.sort_by(|a, b| {
            // 1. Prefer a row that defines the name. Some rows are neither a
            //    definition nor a declaration: arch/x86/xen/suspend_hvm.c:22
            //    is `BUG_ON(xen_set_upcall_vector(cpu));`, a call site stored
            //    under the name it calls. It is a .c file in the tree being
            //    audited, so every rung below this one ranked it first, and a
            //    question about BUG_ON was answered from a use of it.
            let a_defines = !crate::types::text_is_prototype(&a.body);
            let b_defines = !crate::types::text_is_prototype(&b.body);
            if a_defines != b_defines {
                return b_defines.cmp(&a_defines);
            }

            // 2. Prefer the program being audited over another program that
            //    shares the tree. Without this, `pr_warn` answers from
            //    arch/x86/tools/insn_decoder_test.c -- a .c file, so rung 2
            //    ranks it above include/linux/printk.h, and a kernel question
            //    gets a host tool's answer.
            let a_other = crate::types::path_is_other_program(&a.file_path);
            let b_other = crate::types::path_is_other_program(&b.file_path);
            if a_other != b_other {
                return a_other.cmp(&b_other);
            }

            // 3. Prefer the language most definitions of the name are in.
            let a_majority = crate::types::path_language(&a.file_path) == majority_language;
            let b_majority = crate::types::path_language(&b.file_path) == majority_language;
            if a_majority != b_majority {
                return b_majority.cmp(&a_majority);
            }

            // 4. Prefer .c files over .h files
            let a_is_source = a.file_path.ends_with(".c");
            let b_is_source = b.file_path.ends_with(".c");
            if a_is_source != b_is_source {
                return b_is_source.cmp(&a_is_source);
            }

            // 5. Prefer functions with bodies (implementations)
            let a_span = a.line_end.saturating_sub(a.line_start);
            let b_span = b.line_end.saturating_sub(b.line_start);
            let a_has_body = a_span > 0 && a.body.len() > 50;
            let b_has_body = b_span > 0 && b.body.len() > 50;
            if a_has_body != b_has_body {
                return b_has_body.cmp(&a_has_body);
            }

            // 6. Prefer functions with parameters
            let a_has_params = !a.parameters.is_empty();
            let b_has_params = !b.parameters.is_empty();
            if a_has_params != b_has_params {
                return b_has_params.cmp(&a_has_params);
            }

            // 7. Prefer longer bodies (more implementation detail)
            let by_body = b.body.len().cmp(&a.body.len());
            if by_body != std::cmp::Ordering::Equal {
                return by_body;
            }

            // 8. A tie decided by nothing is still decided the same way twice:
            //    the file order a lookup returns is not stable, and two runs
            //    answering differently reads as the tree having changed.
            a.file_path
                .cmp(&b.file_path)
                .then(a.line_start.cmp(&b.line_start))
        });

        tracing::debug!(
            "Selected best match from {} candidates: {} in {}",
            matches.len(),
            matches[0].name,
            matches[0].file_path
        );

        let mut matches = matches.into_iter();
        let function = matches.next().unwrap();
        let others = matches
            .filter(|candidate| !crate::types::text_is_prototype(&candidate.body))
            .map(|candidate| crate::types::DefinitionSite {
                file_path: candidate.file_path,
                line_start: candidate.line_start,
            })
            .collect();
        ChosenDefinition { function, others }
    }

    /// Find all functions by name without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return multiple outdated versions.
    /// For normal operations, use `find_all_functions_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns ALL indexed versions of functions with the given name across all commits,
    /// which may include outdated versions that don't match your working directory.
    pub async fn find_all_functions(&self, name: &str) -> Result<Vec<FunctionInfo>> {
        self.function_store.find_all_by_name(name).await
    }

    /// Get access to the vector store for dimension verification
    pub async fn get_vector_store(&self) -> Result<VectorStore> {
        Ok(VectorStore::new(self.connection.clone()))
    }

    pub async fn get_all_functions(&self) -> Result<Vec<FunctionInfo>> {
        self.function_store.get_all().await
    }

    pub async fn get_all_functions_metadata_only(&self) -> Result<Vec<FunctionInfo>> {
        self.function_store.get_all_metadata_only().await
    }

    /// Search for functions using fuzzy matching without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `search_functions_fuzzy_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns fuzzy matches across all indexed commits without filtering by git history.
    /// Results may include functions that have been deleted, renamed, or modified.
    pub async fn search_functions_fuzzy(&self, pattern: &str) -> Result<Vec<FunctionInfo>> {
        self.search_manager.search_functions_fuzzy(pattern).await
    }

    pub async fn search_functions_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        self.search_manager
            .search_functions_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    pub async fn update_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        self.vector_search_manager.update_vectors(vectorizer).await
    }

    pub async fn update_commit_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        self.vector_search_manager
            .update_commit_vectors(vectorizer)
            .await
    }

    pub async fn update_lore_vectors(&self, vectorizer: &CodeVectorizer) -> Result<()> {
        self.vector_search_manager
            .update_lore_vectors(vectorizer)
            .await
    }

    pub async fn search_similar_commits(
        &self,
        query_vector: &[f32],
        limit: usize,
    ) -> Result<Vec<(crate::types::GitCommitInfo, f32)>> {
        self.vector_search_manager
            .search_similar_commits(query_vector, limit)
            .await
    }

    pub async fn search_similar_lore_emails(
        &self,
        query_vector: &[f32],
        limit: usize,
        filters: &crate::database::search::LoreEmailFilters<'_>,
    ) -> Result<Vec<(crate::types::LoreEmailInfo, f32)>> {
        self.vector_search_manager
            .search_similar_lore_emails(query_vector, limit, filters)
            .await
    }

    pub async fn search_similar_functions_with_scores(
        &self,
        query_vector: &[f32],
        limit: usize,
        filter: Option<String>,
    ) -> Result<Vec<crate::database::search::FunctionMatch>> {
        self.vector_search_manager
            .search_similar_functions_with_scores(query_vector, limit, filter)
            .await
    }

    pub async fn search_similar_functions(
        &self,
        query_vector: &[f32],
        limit: usize,
        filter: Option<String>,
    ) -> Result<Vec<FunctionInfo>> {
        self.vector_search_manager
            .search_similar_functions(query_vector, limit, filter)
            .await
    }

    pub async fn search_similar_by_name(
        &self,
        vectorizer: &CodeVectorizer,
        name: &str,
        limit: usize,
    ) -> Result<Vec<FunctionInfo>> {
        self.vector_search_manager
            .search_similar_by_name(vectorizer, name, limit)
            .await
    }

    // Type operations
    pub async fn insert_types(&self, types: Vec<TypeInfo>) -> Result<()> {
        // Extract unique type definitions and store them in content table for deduplication
        let mut unique_definitions = std::collections::HashSet::new();
        for type_info in &types {
            if !type_info.definition.is_empty() {
                unique_definitions.insert(type_info.definition.clone());
            }
        }

        // Store unique type definitions in content table
        if !unique_definitions.is_empty() {
            let unique_count = unique_definitions.len();
            let content_items: Vec<crate::database::content::ContentInfo> = unique_definitions
                .into_iter()
                .map(|definition| crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&definition),
                    content: definition,
                })
                .collect();

            // Insert content items with batch existence checking
            if let Err(e) = self.content_store.insert_batch(content_items).await {
                tracing::warn!("Failed to populate content table during insertion: {}", e);
                // Continue with insertion even if content storage fails
            } else {
                tracing::debug!(
                    "Successfully populated content table with {} unique type definitions",
                    unique_count
                );
            }
        }

        // Extract (type_name, filename) pairs for symbol_filename table
        let type_filename_pairs: Vec<(String, String)> = types
            .iter()
            .map(|t| (t.name.clone(), t.file_path.clone()))
            .collect();

        // Insert types as usual (keeping existing definition column for now)
        self.type_store.insert_batch(types).await?;

        // Insert into symbol_filename table
        self.symbol_filename_store
            .insert_batch(type_filename_pairs)
            .await?;

        Ok(())
    }

    /// Find a type by name without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return an outdated version.
    /// For normal operations, use `find_type_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns the first matching type found without considering git history.
    /// The returned type may not match the version in your working directory.
    /// Names that are compiler attributes rather than members.
    ///
    /// `struct { ... } __packed;` and `struct { ... } lru_gen;` parse the
    /// same, so the extractor records both as named members. The first names
    /// nothing: C flattens an anonymous member into the type that holds it,
    /// and `mm->mm_mt` is the field, not `mm->__randomize_layout.mm_mt`.
    ///
    /// Deciding needs what the identifier expands to, which is written in
    /// another file, so it is asked here where the whole index is readable.
    /// An alias is followed: `____cacheline_aligned_in_smp` expands to
    /// `____cacheline_aligned`, which expands to an attribute.
    async fn attribute_names(&self) -> Result<Arc<HashSet<String>>> {
        if let Some(known) = self.attribute_names.get() {
            return Ok(known.clone());
        }

        let macros = self.object_macro_store.all().await?;
        let bodies: HashMap<&str, &str> = macros
            .iter()
            .map(|(name, expansion)| (name.as_str(), expansion.as_str()))
            .collect();

        let mut attributes = HashSet::new();
        for (name, body) in &bodies {
            let mut current = *body;
            // Alias chains are short; the bound stops a cycle.
            for _ in 0..8 {
                if current.contains("__attribute__") {
                    attributes.insert((*name).to_string());
                    break;
                }
                match bodies.get(current.trim()) {
                    Some(next) => current = next,
                    None => break,
                }
            }
        }

        let attributes = Arc::new(attributes);
        let _ = self.attribute_names.set(attributes.clone());
        Ok(attributes)
    }

    /// Drop from a field path what is an attribute rather than a member.
    fn flatten_anonymous_members(types: &mut Vec<TypeInfo>, attributes: &HashSet<String>) {
        for ty in types {
            ty.members.retain_mut(|field| {
                let kept: Vec<&str> = field
                    .name
                    .split('.')
                    .filter(|part| !attributes.contains(*part))
                    .collect();

                // Nothing left means the member was the anonymous aggregate
                // itself, which C gives no name and nothing can refer to.
                if kept.is_empty() {
                    return false;
                }
                field.name = kept.join(".");
                true
            });
        }
    }

    pub async fn find_type(&self, name: &str) -> Result<Option<TypeInfo>> {
        self.type_store.find_by_name(name).await
    }

    pub async fn find_type_git_aware(&self, name: &str, git_sha: &str) -> Result<Option<TypeInfo>> {
        Ok(self
            .find_types_git_aware(name, git_sha)
            .await?
            .into_iter()
            .next())
    }

    /// Find all type definitions with an exact name at a specific git commit.
    pub async fn find_types_git_aware(&self, name: &str, git_sha: &str) -> Result<Vec<TypeInfo>> {
        // Step 1: Get candidate file paths from symbol_filename table (optimized - no need to load full type records)
        let unique_file_paths = self
            .symbol_filename_store
            .get_filenames_for_symbol(name)
            .await?;
        if unique_file_paths.is_empty() {
            // No row has ever named this type: only the on-miss path can
            // still find it, in an edit the index has never seen.
            return self
                .types_not_at_revision(name, git_sha, Absent::PathsNotInTree)
                .await;
        }

        // Step 2: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            let why = self.why_nothing_resolved(git_sha);
            return self.types_not_at_revision(name, git_sha, why).await;
        }

        // Step 3: stat (and, on a mismatch, hash) each candidate against the
        // blob it has at this revision. A match keeps its hash for one batched
        // DB query — the common case pays for a stat and nothing else; a
        // difference is an edit, answered by parsing that one file; a
        // deletion answers nothing for that candidate.
        let mut trusted_hashes: Vec<String> = Vec::new();
        let mut matches: Vec<TypeInfo> = Vec::new();
        for (file_path, git_hash) in &resolved_hashes {
            match self.candidate_state(file_path, git_hash, git_sha) {
                CandidateFile::Indexed => trusted_hashes.push(git_hash.clone()),
                CandidateFile::Edited => matches.extend(self.reparse_types(file_path, name)),
                CandidateFile::Deleted => {}
            }
        }
        if !trusted_hashes.is_empty() {
            matches.extend(
                self.type_store
                    .find_by_git_hashes(&trusted_hashes, Some(name), None)
                    .await?,
            );
        }

        if matches.is_empty() {
            return self
                .types_not_at_revision(name, git_sha, Absent::ContentNotIndexed)
                .await;
        }

        matches.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then(a.line_start.cmp(&b.line_start))
        });
        let attributes = self.attribute_names().await?;
        Self::flatten_anonymous_members(&mut matches, &attributes);
        Ok(matches)
    }

    pub async fn get_all_types(&self) -> Result<Vec<TypeInfo>> {
        self.type_store.get_all().await
    }

    /// Get all types without resolving content hashes - much faster for dumps
    pub async fn get_all_types_metadata_only(&self) -> Result<Vec<TypeInfo>> {
        self.type_store.get_all_metadata_only().await
    }

    /// Count all types without resolving content - much faster for counts
    pub async fn count_types(&self) -> Result<usize> {
        self.type_store.count_all().await
    }

    /// Count all functions without resolving content - much faster for counts
    pub async fn count_functions(&self) -> Result<usize> {
        self.function_store.count_all().await
    }

    /// Count all typedefs without resolving content - much faster for counts
    pub async fn count_typedefs(&self) -> Result<usize> {
        self.typedef_store.count_all().await
    }

    /// Search for types using fuzzy matching without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `search_types_fuzzy_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns fuzzy matches across all indexed commits without filtering by git history.
    /// Results may include types that have been deleted, renamed, or modified.
    pub async fn search_types_fuzzy(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        self.search_manager.search_types_fuzzy(pattern).await
    }

    pub async fn search_types_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypeInfo>> {
        self.search_manager
            .search_types_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    pub async fn search_types_by_kind(&self, kind: &str) -> Result<Vec<TypeInfo>> {
        self.search_manager.search_types_by_kind(kind).await
    }

    pub async fn type_exists(&self, name: &str, kind: &str, file_path: &str) -> Result<bool> {
        self.type_store.exists(name, kind, file_path).await
    }

    // Typedef operations
    pub async fn insert_typedefs(&self, typedefs: Vec<TypedefInfo>) -> Result<()> {
        // Extract unique typedef definitions and store them in content table for deduplication
        let mut unique_definitions = std::collections::HashSet::new();
        for typedef_info in &typedefs {
            if !typedef_info.definition.is_empty() {
                unique_definitions.insert(typedef_info.definition.clone());
            }
        }

        // Store unique typedef definitions in content table
        if !unique_definitions.is_empty() {
            let unique_count = unique_definitions.len();
            let content_items: Vec<crate::database::content::ContentInfo> = unique_definitions
                .into_iter()
                .map(|definition| crate::database::content::ContentInfo {
                    blake3_hash: crate::hash::compute_blake3_hash(&definition),
                    content: definition,
                })
                .collect();

            // Insert content items with batch existence checking
            if let Err(e) = self.content_store.insert_batch(content_items).await {
                tracing::warn!("Failed to populate content table during insertion: {}", e);
                // Continue with insertion even if content storage fails
            } else {
                tracing::debug!(
                    "Successfully populated content table with {} unique typedef definitions",
                    unique_count
                );
            }
        }

        // Extract (typedef_name, filename) pairs for symbol_filename table
        let typedef_filename_pairs: Vec<(String, String)> = typedefs
            .iter()
            .map(|td| (td.name.clone(), td.file_path.clone()))
            .collect();

        // Insert typedefs as usual (keeping existing definition column for now)
        self.typedef_store.insert_batch(typedefs).await?;

        // Insert into symbol_filename table
        self.symbol_filename_store
            .insert_batch(typedef_filename_pairs)
            .await?;

        Ok(())
    }

    /// Find a typedef by name without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return an outdated version.
    /// For normal operations, use `find_typedef_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns the first matching typedef found without considering git history.
    /// The returned typedef may not match the version in your working directory.
    pub async fn find_typedef(&self, name: &str) -> Result<Option<TypedefInfo>> {
        self.typedef_store.find_by_name(name).await
    }

    pub async fn find_typedef_git_aware(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Result<Option<TypedefInfo>> {
        // Step 1: Get candidate file paths from symbol_filename table (optimized - no need to load full typedef records)
        let unique_file_paths = self
            .symbol_filename_store
            .get_filenames_for_symbol(name)
            .await?;
        if unique_file_paths.is_empty() {
            return Ok(None);
        }

        // Step 2: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            let why = self.why_nothing_resolved(git_sha);
            return self.typedef_not_at_revision(name, git_sha, why).await;
        }

        // Step 3: Direct targeted search using git hashes
        let hash_values: Vec<String> = resolved_hashes.values().cloned().collect();
        let typedefs = self
            .typedef_store
            .find_by_git_hashes(&hash_values, Some(name))
            .await?;

        if typedefs.is_empty() {
            return self
                .typedef_not_at_revision(name, git_sha, Absent::ContentNotIndexed)
                .await;
        }

        // Return the first match
        Ok(typedefs.into_iter().next())
    }

    pub async fn get_all_typedefs(&self) -> Result<Vec<TypedefInfo>> {
        self.typedef_store.get_all().await
    }

    /// Search for typedefs using fuzzy matching without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `search_typedefs_fuzzy_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns fuzzy matches across all indexed commits without filtering by git history.
    /// Results may include typedefs that have been deleted, renamed, or modified.
    pub async fn search_typedefs_fuzzy(&self, pattern: &str) -> Result<Vec<TypedefInfo>> {
        self.search_manager.search_typedefs_fuzzy(pattern).await
    }

    pub async fn search_typedefs_fuzzy_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypedefInfo>> {
        self.search_manager
            .search_typedefs_fuzzy_git_aware(pattern, git_sha)
            .await
    }

    pub async fn typedef_exists(&self, name: &str, file_path: &str) -> Result<bool> {
        self.typedef_store.exists(name, file_path).await
    }

    /// Search types using regex patterns on the name column without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `search_types_regex_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns regex matches across all indexed commits without filtering by git history.
    /// Results may include types that have been deleted, renamed, or modified.
    pub async fn search_types_regex(&self, pattern: &str) -> Result<Vec<TypeInfo>> {
        self.search_manager.search_types_regex(pattern).await
    }

    /// Search types using regex patterns on the name column (git-aware)
    pub async fn search_types_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypeInfo>> {
        let workdir_matches = self.workdir_find_types_regex(pattern, git_sha);
        let workdir_files: HashSet<String> = workdir_matches
            .iter()
            .map(|t| t.file_path.clone())
            .collect();

        let mut db_results = self
            .search_manager
            .search_types_regex_git_aware(pattern, git_sha)
            .await?;

        // Filter out DB results from dirty/deleted files, then prepend workdir matches
        db_results.retain(|t| {
            !workdir_files.contains(&t.file_path) && !self.workdir_is_deleted(&t.file_path, git_sha)
        });

        let mut merged = workdir_matches;
        merged.extend(db_results);
        Ok(merged)
    }

    /// Search typedefs using regex patterns on the name column without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `search_typedefs_regex_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns regex matches across all indexed commits without filtering by git history.
    /// Results may include typedefs that have been deleted, renamed, or modified.
    pub async fn search_typedefs_regex(&self, pattern: &str) -> Result<Vec<TypedefInfo>> {
        self.search_manager.search_typedefs_regex(pattern).await
    }

    /// Search typedefs using regex patterns on the name column (git-aware)
    pub async fn search_typedefs_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<TypedefInfo>> {
        self.search_manager
            .search_typedefs_regex_git_aware(pattern, git_sha)
            .await
    }

    // Metadata-only insertion methods (skip content storage for performance)
    async fn insert_functions_metadata_only(&self, functions: Vec<FunctionInfo>) -> Result<()> {
        // Insert functions metadata
        self.function_store.insert_metadata_only(functions).await?;
        Ok(())
    }

    async fn insert_types_metadata_only(&self, types: Vec<TypeInfo>) -> Result<()> {
        self.type_store.insert_metadata_only(types).await
    }

    /// Search functions using regex patterns on the name column without git awareness (non-git-aware)
    ///
    /// **WARNING**: This method does NOT filter by git commit and may return outdated versions.
    /// For normal operations, use `search_functions_regex_git_aware()` instead.
    ///
    /// # When to Use This Method
    /// - Fallback when git SHA cannot be determined (not in a git repository)
    /// - Administrative/debugging operations that need to see all versions
    /// - Operations that explicitly require seeing historical data across commits
    ///
    /// # Behavior
    /// Returns regex matches across all indexed commits without filtering by git history.
    /// Results may include functions that have been deleted, renamed, or modified.
    pub async fn search_functions_regex(&self, pattern: &str) -> Result<Vec<FunctionInfo>> {
        self.search_manager.search_functions_regex(pattern).await
    }

    /// Search functions using regex patterns on the name column (git-aware)
    pub async fn search_functions_regex_git_aware(
        &self,
        pattern: &str,
        git_sha: &str,
    ) -> Result<Vec<FunctionInfo>> {
        let workdir_matches = self.workdir_find_functions_regex(pattern, git_sha);
        let workdir_files: HashSet<String> = workdir_matches
            .iter()
            .map(|f| f.file_path.clone())
            .collect();

        let mut db_results = self
            .search_manager
            .search_functions_regex_git_aware(pattern, git_sha)
            .await?;

        db_results.retain(|f| {
            !workdir_files.contains(&f.file_path) && !self.workdir_is_deleted(&f.file_path, git_sha)
        });

        let mut merged = workdir_matches;
        merged.extend(db_results);
        Ok(merged)
    }

    // Call relationship operations
    // Call relationship insertion/resolution methods removed - call relationships are now embedded in function JSON columns

    /// Count distinct current-commit entities that call functions or reference types.
    /// Embedded relationship arrays are deduplicated during indexing, so these are
    /// referrer counts rather than raw source occurrence counts.
    pub async fn get_distinct_reference_counts_git_aware(
        &self,
        function_names: &[String],
        type_names: &[String],
        git_sha: &str,
    ) -> Result<(
        std::collections::HashMap<String, usize>,
        std::collections::HashMap<String, usize>,
    )> {
        use std::collections::{HashMap, HashSet};

        let function_targets: HashSet<String> = function_names.iter().cloned().collect();
        let type_targets: HashSet<String> = type_names.iter().cloned().collect();
        let mut function_referrers: HashMap<String, HashSet<String>> = HashMap::new();
        let mut type_referrers: HashMap<String, HashSet<String>> = HashMap::new();
        let git_manifest = self.generate_git_manifest(git_sha).await?;

        if !git_manifest.is_empty() && (!function_targets.is_empty() || !type_targets.is_empty()) {
            let functions_table = self.connection.open_table("functions").execute().await?;
            let relationship_filter = match (function_targets.is_empty(), type_targets.is_empty()) {
                (false, false) => "calls IS NOT NULL OR types IS NOT NULL",
                (false, true) => "calls IS NOT NULL",
                (true, false) => "types IS NOT NULL",
                (true, true) => unreachable!(),
            };
            let batches = functions_table
                .query()
                .only_if(relationship_filter)
                .select(lancedb::query::Select::Columns(vec![
                    "name".to_string(),
                    "file_path".to_string(),
                    "git_file_hash".to_string(),
                    "line_start".to_string(),
                    "calls".to_string(),
                    "types".to_string(),
                ]))
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in batches {
                let names: &StringArray = super::get_column(&batch, "name")?;
                let paths: &StringArray = super::get_column(&batch, "file_path")?;
                let hashes: &StringArray = super::get_column(&batch, "git_file_hash")?;
                let lines: &arrow::array::Int64Array = super::get_column(&batch, "line_start")?;
                let calls: &StringArray = super::get_column(&batch, "calls")?;
                let types: &StringArray = super::get_column(&batch, "types")?;

                for row in 0..batch.num_rows() {
                    let path = paths.value(row);
                    if self.workdir_is_dirty(path, git_sha)
                        || self.workdir_is_deleted(path, git_sha)
                    {
                        continue;
                    }
                    if git_manifest.hash_of(path).as_deref() != Some(hashes.value(row)) {
                        continue;
                    }
                    let identity = format!(
                        "function:{}:{}:{}",
                        path,
                        lines.value(row),
                        names.value(row)
                    );
                    if !calls.is_null(row) {
                        let values = crate::database::parse_call_list(calls.value(row))?;
                        for target in values {
                            if function_targets.contains(&target) {
                                function_referrers
                                    .entry(target)
                                    .or_default()
                                    .insert(identity.clone());
                            }
                        }
                    }
                    if !types.is_null(row) {
                        if let Ok(values) = serde_json::from_str::<Vec<String>>(types.value(row)) {
                            for target in values {
                                if type_targets.contains(&target) {
                                    type_referrers
                                        .entry(target)
                                        .or_default()
                                        .insert(identity.clone());
                                }
                            }
                        }
                    }
                }
            }

            if !type_targets.is_empty() {
                let types_table = self.connection.open_table("types").execute().await?;
                let batches = types_table
                    .query()
                    .only_if("types IS NOT NULL")
                    .select(lancedb::query::Select::Columns(vec![
                        "name".to_string(),
                        "file_path".to_string(),
                        "git_file_hash".to_string(),
                        "line".to_string(),
                        "types".to_string(),
                    ]))
                    .execute()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?;

                for batch in batches {
                    let names: &StringArray = super::get_column(&batch, "name")?;
                    let paths: &StringArray = super::get_column(&batch, "file_path")?;
                    let hashes: &StringArray = super::get_column(&batch, "git_file_hash")?;
                    let lines: &arrow::array::Int64Array = super::get_column(&batch, "line")?;
                    let types: &StringArray = super::get_column(&batch, "types")?;

                    for row in 0..batch.num_rows() {
                        let path = paths.value(row);
                        if self.workdir_is_dirty(path, git_sha)
                            || self.workdir_is_deleted(path, git_sha)
                        {
                            continue;
                        }
                        if git_manifest.hash_of(path).as_deref() != Some(hashes.value(row)) {
                            continue;
                        }
                        if types.is_null(row) {
                            continue;
                        }
                        let identity =
                            format!("type:{}:{}:{}", path, lines.value(row), names.value(row));
                        if let Ok(values) = serde_json::from_str::<Vec<String>>(types.value(row)) {
                            for target in values {
                                if type_targets.contains(&target) {
                                    type_referrers
                                        .entry(target)
                                        .or_default()
                                        .insert(identity.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        let (workdir_function_counts, workdir_type_counts) = {
            let guard = self.workdir_index.read().unwrap();
            guard
                .as_ref()
                .map(|index| index.distinct_reference_counts(&function_targets, &type_targets))
                .unwrap_or_default()
        };
        let function_counts = function_targets
            .into_iter()
            .map(|name| {
                let count = function_referrers.get(&name).map_or(0, HashSet::len)
                    + workdir_function_counts
                        .get(&name)
                        .copied()
                        .unwrap_or_default();
                (name, count)
            })
            .collect();
        let type_counts = type_targets
            .into_iter()
            .map(|name| {
                let count = type_referrers.get(&name).map_or(0, HashSet::len)
                    + workdir_type_counts.get(&name).copied().unwrap_or_default();
                (name, count)
            })
            .collect();
        Ok((function_counts, type_counts))
    }

    pub async fn get_function_callers(&self, function_name: &str) -> Result<Vec<String>> {
        let total_start = std::time::Instant::now();

        // Use efficient filtering: find functions whose calls JSON contains the target function name
        let escaped_name = function_name.replace("'", "''"); // SQL escape

        let open_table_start = std::time::Instant::now();
        let table = self.connection.open_table("functions").execute().await?;
        tracing::info!(
            "get_function_callers: open_table took {:?}",
            open_table_start.elapsed()
        );

        // Filter for functions whose calls column contains the exact function name
        // Match as complete JSON array element: "name", or "name"]
        // This avoids false positives like "name_suffix" or "prefix_name"
        let filter = format!(
            "calls IS NOT NULL AND (calls LIKE '%\"{escaped_name}\",%' OR calls LIKE '%\"{escaped_name}\"]%')"
        );

        let query_start = std::time::Instant::now();
        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        tracing::info!(
            "get_function_callers: query and collect took {:?}",
            query_start.elapsed()
        );

        let process_start = std::time::Instant::now();
        let mut callers = std::collections::HashSet::new();
        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column (should be at index based on schema)
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    if !calls_array.is_null(i) {
                        let caller_name = name_array.value(i).to_string();
                        let calls_json = calls_array.value(i);

                        // Parse JSON and verify it actually contains function_name
                        // (the LIKE filter might have false positives)
                        let calls_list = crate::database::parse_call_list(calls_json)?;
                        if calls_list.contains(&function_name.to_string()) {
                            callers.insert(caller_name);
                        }
                    }
                }
            }
        }
        tracing::info!(
            "get_function_callers: batch processing took {:?}",
            process_start.elapsed()
        );

        let result: Vec<String> = callers.into_iter().collect();
        tracing::info!(
            "get_function_callers: TOTAL time {:?}, found {} callers",
            total_start.elapsed(),
            result.len()
        );
        Ok(result)
    }

    pub async fn get_function_callers_git_aware(
        &self,
        function_name: &str,
        git_sha: &str,
    ) -> Result<Vec<String>> {
        // Collect callers from workdir overlay
        let workdir_callers = self.workdir_find_callers(function_name, git_sha);
        let mut caller_names: Vec<String> =
            workdir_callers.iter().map(|f| f.name.clone()).collect();

        let git_manifest = self.git_manifest_cached(git_sha).await?;
        if !git_manifest.is_empty() {
            let db_callers = self
                .get_function_callers_with_manifest(function_name, &git_manifest)
                .await?;
            for name in db_callers {
                if !caller_names.contains(&name) {
                    caller_names.push(name);
                }
            }
        }
        Ok(caller_names)
    }

    // Optimized methods for call chain analysis

    /// Get functions that have no callers (entry points)
    pub async fn get_entry_point_functions(&self) -> Result<Vec<String>> {
        // New schema: find functions that make calls but are never called by others
        let table = self.connection.open_table("functions").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut functions_with_calls = std::collections::HashSet::new();
        let mut functions_that_are_called = std::collections::HashSet::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let function_name = name_array.value(i).to_string();

                    // Check if this function makes calls
                    if !calls_array.is_null(i) {
                        let calls_json = calls_array.value(i);
                        let calls_list = crate::database::parse_call_list(calls_json)?;
                        if !calls_list.is_empty() {
                            functions_with_calls.insert(function_name.clone());
                            // Add all called functions to the set
                            for called_func in calls_list {
                                functions_that_are_called.insert(called_func);
                            }
                        }
                    }
                }
            }
        }

        // Entry points are functions that make calls but are never called
        let entry_points: Vec<String> = functions_with_calls
            .difference(&functions_that_are_called)
            .cloned()
            .collect();

        Ok(entry_points)
    }

    /// Get functions by a list of names (batch lookup)
    pub async fn get_functions_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, Vec<FunctionInfo>>> {
        self.function_store.get_by_names(names).await
    }

    /// Get types by a list of names (batch lookup)
    pub async fn get_types_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, TypeInfo>> {
        self.type_store.get_by_names(names).await
    }

    /// Get typedefs by a list of names (batch lookup)
    pub async fn get_typedefs_by_names(
        &self,
        names: &[String],
    ) -> Result<std::collections::HashMap<String, TypedefInfo>> {
        self.typedef_store.get_by_names(names).await
    }

    /// Efficiently collect functions in a call chain from a starting function
    /// Uses different strategies based on database size
    pub async fn collect_callchain_functions(
        &self,
        start_function: &str,
        max_depth: usize,
        include_forward: bool,
        include_reverse: bool,
        git_sha: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        // For small databases (< 1000 functions), use the old full-scan approach
        // For large databases, use targeted queries
        let function_count = self.get_function_count().await?;

        if function_count < 1000 {
            // Small database: use in-memory approach (faster for small datasets)
            self.collect_callchain_functions_in_memory(
                start_function,
                max_depth,
                include_forward,
                include_reverse,
                git_sha,
            )
            .await
        } else {
            // Large database: use targeted queries
            self.collect_callchain_functions_targeted(
                start_function,
                max_depth,
                include_forward,
                include_reverse,
                git_sha,
            )
            .await
        }
    }

    /// Get total function count (cached/efficient)
    async fn get_function_count(&self) -> Result<usize> {
        let table = self.connection.open_table("functions").execute().await?;
        Ok(table.count_rows(None).await?)
    }

    /// Use full in-memory approach (good for small databases)
    async fn collect_callchain_functions_in_memory(
        &self,
        start_function: &str,
        max_depth: usize,
        include_forward: bool,
        include_reverse: bool,
        git_sha: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        // For small databases, we'll still use the targeted approach with call store
        // since the embedded call fields have been removed
        self.collect_callchain_functions_targeted(
            start_function,
            max_depth,
            include_forward,
            include_reverse,
            git_sha,
        )
        .await
    }

    /// Use targeted queries (good for large databases) - optimized with git manifest for 10-100x speedup
    async fn collect_callchain_functions_targeted(
        &self,
        start_function: &str,
        max_depth: usize,
        include_forward: bool,
        include_reverse: bool,
        git_sha: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        // Optimize git-aware operations by generating manifest once
        let git_manifest = if let Some(sha) = git_sha {
            tracing::info!(
                "Generating git manifest for callchain optimization at commit: {}",
                sha
            );
            Some(self.generate_git_manifest(sha).await?)
        } else {
            None
        };

        let mut result = std::collections::HashSet::new();
        let mut to_visit = std::collections::VecDeque::new();
        let mut visited = std::collections::HashSet::new();

        to_visit.push_back((start_function.to_string(), 0));
        result.insert(start_function.to_string());

        while let Some((func_name, depth)) = to_visit.pop_front() {
            if depth >= max_depth || visited.contains(&func_name) {
                continue;
            }

            visited.insert(func_name.clone());

            // Get function details to find call relationships
            let function_exists = if let Some(manifest) = &git_manifest {
                self.function_exists_in_manifest(&func_name, manifest)
                    .await?
            } else {
                self.find_function(&func_name).await?.is_some()
            };

            if function_exists {
                if include_forward {
                    let callees = if let Some(manifest) = &git_manifest {
                        self.get_function_callees_with_manifest(&func_name, manifest)
                            .await?
                    } else {
                        self.get_function_callees(&func_name).await?
                    };
                    for callee in callees {
                        if !result.contains(&callee) {
                            result.insert(callee.clone());
                            to_visit.push_back((callee, depth + 1));
                        }
                    }
                }

                if include_reverse {
                    let callers = if let Some(manifest) = &git_manifest {
                        self.get_function_callers_with_manifest(&func_name, manifest)
                            .await?
                    } else {
                        self.get_function_callers(&func_name).await?
                    };
                    for caller in callers {
                        if !result.contains(&caller) {
                            result.insert(caller.clone());
                            to_visit.push_back((caller, depth + 1));
                        }
                    }
                }
            }
            // Note: Macros are now stored as functions, so no separate macro check needed
        }

        Ok(result)
    }

    pub async fn get_function_callees(&self, function_name: &str) -> Result<Vec<String>> {
        // Get all functions with this name and select the best one (prefers definitions over declarations)
        let all_matches = self
            .function_store
            .find_all_by_name_unfiltered(function_name)
            .await?;
        if all_matches.is_empty() {
            return Ok(Vec::new());
        }

        // Use the same smart selection logic to prefer implementations over declarations
        let best_match = self.select_best_function_match(all_matches);

        // Get the calls from the best match (already deserialized as Vec<String>)
        if let Some(ref calls_list) = best_match.calls {
            return Ok(calls_list.clone());
        }

        Ok(Vec::new())
    }

    pub async fn get_function_callees_git_aware(
        &self,
        function_name: &str,
        git_sha: &str,
    ) -> Result<Vec<String>> {
        // Check workdir overlay first — if the function is in a dirty file, use its callees
        if let Some(callees) = self.workdir_find_callees(function_name, git_sha) {
            return Ok(callees);
        }
        let git_manifest = self.git_manifest_cached(git_sha).await?;
        if git_manifest.is_empty() {
            return Ok(Vec::new());
        }
        self.get_function_callees_with_manifest(function_name, &git_manifest)
            .await
    }

    /// Every definition of the name at this commit, with what each calls.
    pub async fn get_function_callees_by_definition_git_aware(
        &self,
        function_name: &str,
        git_sha: &str,
    ) -> Result<Vec<crate::types::CalleeDefinition>> {
        let git_manifest = self.git_manifest_cached(git_sha).await?;
        let mut definitions = if git_manifest.is_empty() {
            Vec::new()
        } else {
            self.get_function_callees_by_definition(function_name, &git_manifest)
                .await?
        };

        // What the working directory says overrides what the commit said about
        // the same file, and a definition that exists only in an edited file
        // exists. Reporting the committed rows here would answer about a file
        // the reader has already changed.
        let dirty = self.workdir_callee_definitions(function_name, git_sha);
        if !dirty.is_empty() {
            definitions.retain(|definition| {
                !dirty
                    .iter()
                    .any(|edited| edited.file_path == definition.file_path)
            });
            definitions.extend(dirty);
            definitions.sort_by(|a, b| {
                a.file_path
                    .cmp(&b.file_path)
                    .then(a.line_start.cmp(&b.line_start))
            });
        }
        Ok(definitions)
    }

    /// The definitions of a name in files the working directory has edited.
    fn workdir_callee_definitions(
        &self,
        name: &str,
        git_sha: &str,
    ) -> Vec<crate::types::CalleeDefinition> {
        self.ensure_workdir_index_built(git_sha);
        let guard = self.workdir_index.read().unwrap();
        guard
            .as_ref()
            .map(|workdir| {
                workdir
                    .find_all_functions(name)
                    .into_iter()
                    .map(|function| crate::types::CalleeDefinition {
                        file_path: function.file_path.clone(),
                        line_start: function.line_start,
                        line_end: function.line_end,
                        callees: function.calls.clone().unwrap_or_default(),
                        is_definition: !crate::types::text_is_prototype(&function.body),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub async fn get_all_call_relationships(&self) -> Result<Vec<CallRelationship>> {
        // New schema: reconstruct call relationships from embedded JSON in functions table
        let table = self.connection.open_table("functions").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut all_relationships = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let caller_name = name_array.value(i).to_string();
                    let caller_git_file_hash = git_file_hash_array.value(i).to_string();

                    if !calls_array.is_null(i) {
                        let calls_json = calls_array.value(i);
                        let calls_list = crate::database::parse_call_list(calls_json)?;
                        for callee_name in calls_list {
                            // Getting the callee's git hash would need a lookup per callee.
                            all_relationships.push(CallRelationship {
                                caller: caller_name.clone(),
                                callee: callee_name,
                                caller_git_file_hash: caller_git_file_hash.clone(),
                                callee_git_file_hash: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(all_relationships)
    }

    /// Run database optimization and rebuild indices
    pub async fn optimize_database(&self) -> Result<()> {
        use colored::Colorize;

        tracing::info!(
            "\n{}",
            "═══ DATABASE OPTIMIZATION STARTED ═══".yellow().bold()
        );
        let start_time = std::time::Instant::now();
        tracing::info!("Running database optimization...");

        // Rebuild all scalar indices to ensure they're optimal
        tracing::info!("{}", "  → Rebuilding scalar indices...".cyan());
        self.rebuild_indices().await?;
        tracing::info!("{}", "  ✓ Scalar indices rebuilt".green());

        // Run table optimization
        tracing::info!("{}", "  → Optimizing tables...".cyan());
        self.optimize_tables().await?;
        tracing::info!("{}", "  ✓ Tables optimized".green());

        // Compact and cleanup (triggers compression)
        tracing::info!("{}", "  → Compacting and pruning old versions...".cyan());
        self.compact_and_cleanup().await?;
        tracing::info!("{}", "  ✓ Compaction complete".green());

        let elapsed = start_time.elapsed();
        tracing::info!(
            "{}",
            format!(
                "═══ DATABASE OPTIMIZATION COMPLETE ({:.1}s) ═══\n",
                elapsed.as_secs_f64()
            )
            .yellow()
            .bold()
        );
        tracing::info!(
            "Database optimization complete in {:.1}s",
            elapsed.as_secs_f64()
        );
        Ok(())
    }

    /// Check if database needs optimization based on fragment statistics
    /// Returns (needs_optimization, diagnostic_message)
    pub async fn check_optimization_health(&self) -> Result<(bool, String)> {
        use colored::Colorize;

        let table_names = self.connection.table_names().execute().await?;
        let mut needs_optimization = false;
        let mut messages = Vec::new();

        // Tables to check (prioritize the largest ones)
        let critical_tables = [
            "functions",
            "types",
            "vectors",
            "commit_vectors",
            "lore_vectors",
            "processed_files",
            "git_commits",
            "lore",
            "symbol_filename",
        ];

        let mut total_fragments = 0;
        let mut total_small_fragments = 0;

        for table_name in &critical_tables {
            if !table_names.iter().any(|n| n == table_name) {
                continue;
            }

            let table = self.connection.open_table(*table_name).execute().await?;

            // Get table statistics
            match table.stats().await {
                Ok(stats) => {
                    let frag_stats = &stats.fragment_stats;
                    total_fragments += frag_stats.num_fragments;
                    total_small_fragments += frag_stats.num_small_fragments;

                    // Heuristics for when optimization is needed:
                    // 1. More than 600 fragments triggers auto-optimization
                    //    (LanceDB recommends <100 for optimal performance, but we use 600
                    //     to avoid over-optimizing during incremental updates)
                    if frag_stats.num_fragments > 600 {
                        needs_optimization = true;
                        messages.push(format!(
                            "{}: {} fragments (auto-optimize threshold: 600)",
                            table_name.yellow(),
                            frag_stats.num_fragments.to_string().red()
                        ));
                    }

                    // 2. More than 50% small fragments (< 100K rows each)
                    if frag_stats.num_fragments > 0 {
                        let small_fragment_pct = (frag_stats.num_small_fragments as f64
                            / frag_stats.num_fragments as f64)
                            * 100.0;
                        if small_fragment_pct > 50.0 && frag_stats.num_small_fragments > 10 {
                            needs_optimization = true;
                            messages.push(format!(
                                "{}: {:.1}% small fragments ({}/{})",
                                table_name.yellow(),
                                small_fragment_pct,
                                frag_stats.num_small_fragments.to_string().red(),
                                frag_stats.num_fragments
                            ));
                        }
                    }

                    // 3. Very small mean fragment size suggests many small inserts
                    if frag_stats.lengths.mean < 1000 && stats.num_rows > 10000 {
                        needs_optimization = true;
                        messages.push(format!(
                            "{}: small mean fragment size ({} rows/fragment)",
                            table_name.yellow(),
                            frag_stats.lengths.mean.to_string().red()
                        ));
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get stats for table {}: {}", table_name, e);
                }
            }
        }

        // Also check content shards (aggregate stats)
        let mut content_fragments = 0;
        let mut content_small_fragments = 0;
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            if !table_names.iter().any(|n| n == &table_name) {
                continue;
            }

            let table = self.connection.open_table(&table_name).execute().await?;
            if let Ok(stats) = table.stats().await {
                content_fragments += stats.fragment_stats.num_fragments;
                content_small_fragments += stats.fragment_stats.num_small_fragments;
            }
        }

        if content_fragments > 0 {
            total_fragments += content_fragments;
            total_small_fragments += content_small_fragments;

            // Content shards are expected to have more fragments due to sharding
            // But still check if they're excessive (16 shards × 600 = 9600, use 3000 as threshold)
            if content_fragments > 3000 {
                needs_optimization = true;
                messages.push(format!(
                    "{}: {} fragments across 16 shards (threshold: 3000)",
                    "content shards".yellow(),
                    content_fragments.to_string().red()
                ));
            }
        }

        // Build summary message
        let summary = if needs_optimization {
            let mut msg = format!("{}\n", "Optimizing database...".yellow());
            for message in &messages {
                msg.push_str(&format!("  • {}\n", message));
            }
            msg.push_str(&format!(
                "\nTotal: {} fragments ({} small)\n",
                total_fragments.to_string().yellow(),
                total_small_fragments.to_string().yellow()
            ));
            msg
        } else {
            format!(
                "{} Database is healthy ({} fragments, {} small)\n",
                "✓".green().bold(),
                total_fragments.to_string().green(),
                total_small_fragments.to_string().green()
            )
        };

        Ok((needs_optimization, summary))
    }

    /// Get database storage statistics and compression info
    pub async fn get_storage_stats(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;
        let mut total_rows = 0;

        println!("{}", "=== Database Storage Statistics ===".bold().green());

        // Process main tables
        for table_name in &[
            "functions",
            "types",
            "vectors",
            "commit_vectors",
            "lore_vectors",
            "processed_files",
            "git_commits",
            "lore",
            "symbol_filename",
        ] {
            if table_names.iter().any(|n| n == table_name) {
                let table = self.connection.open_table(*table_name).execute().await?;
                match table.count_rows(None).await {
                    Ok(count) => {
                        println!("{}: {} rows", table_name.cyan(), count.to_string().yellow());
                        total_rows += count;

                        // Estimate storage for functions table (largest consumer)
                        if *table_name == "functions" {
                            // Get vector statistics from the separate vectors table
                            use crate::database::vectors::VectorStore;
                            let vector_store = VectorStore::new(self.connection.clone());
                            let total_vectors = vector_store.get_stats().await.unwrap_or(0);
                            // Since we now store vectors by content hash, we can't directly
                            // correlate with function count, so we'll estimate
                            let functions_with_vectors = total_vectors; // Approximate
                            let functions_without_vectors = count - functions_with_vectors;
                            let actual_vector_storage = functions_with_vectors * 256 * 4; // bytes for actual vectors (model2vec)
                            let est_text_storage = count * 2048; // rough estimate for bodies

                            println!(
                                "  Functions with vectors: {}",
                                functions_with_vectors.to_string().green()
                            );
                            println!(
                                "  Functions without vectors: {}",
                                functions_without_vectors.to_string().cyan()
                            );
                            println!(
                                "  Vector storage: {} MB",
                                (actual_vector_storage / 1024 / 1024).to_string().yellow()
                            );
                            println!(
                                "  Estimated text storage: {} MB",
                                (est_text_storage / 1024 / 1024).to_string().yellow()
                            );

                            if functions_with_vectors > 0 {
                                let vector_efficiency =
                                    (functions_with_vectors as f64 / count as f64) * 100.0;
                                println!(
                                    "  Vector coverage: {:.1}%",
                                    vector_efficiency.to_string().bold().green()
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("{}: Error getting count - {}", table_name.red(), e);
                    }
                }
            }
        }

        // Process content shard tables (content_0 through content_15) and aggregate stats
        let mut total_content_rows = 0;
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            let table = self.connection.open_table(&table_name).execute().await?;
            match table.count_rows(None).await {
                Ok(count) => {
                    total_content_rows += count;
                }
                Err(e) => {
                    println!("{}: Error getting count - {}", table_name.red(), e);
                }
            }
        }

        if total_content_rows > 0 {
            println!(
                "{}: {} rows (across 16 shards)",
                "content".cyan(),
                total_content_rows.to_string().yellow()
            );
            total_rows += total_content_rows;
        }

        println!(
            "{}: {} rows",
            "Total".bold(),
            total_rows.to_string().yellow()
        );
        println!(
            "\n{}",
            "Note: LanceDB uses columnar compression (LZ4/ZSTD) automatically".bright_black()
        );
        println!(
            "{}",
            "Vectors are stored in a separate table for deduplication and efficiency"
                .bright_black()
        );

        Ok(())
    }

    /// Optimize database files and consolidate data fragments
    pub async fn compact_database(&self) -> Result<()> {
        tracing::info!("Running database optimization to reduce file size...");

        // Step 1: Run optimization and cleanup sequence
        self.compact_and_cleanup().await?;

        // Step 2: CRITICAL - Drop old table references and recreate to release handles
        tracing::info!("Releasing old table handles and checking out latest versions...");

        // Force recreation of table connections to release old version handles
        // This is crucial for LanceDB garbage collection to work properly
        let table_names = self.connection.table_names().execute().await?;

        for table_name in &[
            "functions",
            "types",
            "vectors",
            "commit_vectors",
            "lore_vectors",
            "processed_files",
            "git_commits",
            "lore",
            "symbol_filename",
        ] {
            if table_names.iter().any(|n| n == table_name) {
                // Open table with fresh handle and checkout latest
                match self.connection.open_table(*table_name).execute().await {
                    Ok(table) => {
                        // Checkout latest version to ensure we're not holding old handles
                        if let Err(e) = table.checkout_latest().await {
                            tracing::warn!("Could not checkout latest for {}: {}", table_name, e);
                        }
                        // Table handle will be dropped automatically when it goes out of scope
                    }
                    Err(e) => {
                        tracing::warn!("Could not reopen table {}: {}", table_name, e);
                    }
                }
            }
        }

        tracing::info!("Database optimization and handle cleanup complete");
        Ok(())
    }

    /// Get compaction statistics
    pub async fn get_compaction_stats(&self) -> Result<()> {
        let table_names = self.connection.table_names().execute().await?;

        println!(
            "{}",
            "=== Database Compaction Statistics ===".bold().green()
        );

        // Process main tables
        for table_name in &[
            "functions",
            "types",
            "vectors",
            "commit_vectors",
            "lore_vectors",
            "processed_files",
            "git_commits",
            "lore",
            "symbol_filename",
        ] {
            if table_names.iter().any(|n| n == table_name) {
                let table = self.connection.open_table(*table_name).execute().await?;

                match table.count_rows(None).await {
                    Ok(count) => {
                        println!("{}: {} rows", table_name.cyan(), count.to_string().yellow());

                        // Try to get more detailed stats if available
                        // Note: Specific LanceDB version info may not be accessible in all versions
                    }
                    Err(e) => {
                        println!("{}: Error - {}", table_name.red(), e);
                    }
                }
            }
        }

        // Process content shard tables (content_0 through content_15)
        let mut total_content_rows = 0;
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            let table = self.connection.open_table(&table_name).execute().await?;
            match table.count_rows(None).await {
                Ok(count) => {
                    total_content_rows += count;
                }
                Err(e) => {
                    println!("{}: Error - {}", table_name.red(), e);
                }
            }
        }

        if total_content_rows > 0 {
            println!(
                "{}: {} rows (across 16 shards)",
                "content".cyan(),
                total_content_rows.to_string().yellow()
            );
        }

        println!("\n{}", "Tips for compaction and cleanup:".bold().cyan());
        println!("• Run 'compact_db' periodically after large data imports");
        println!(
            "• Current implementation uses optimize() + checkout_latest() + handle management"
        );
        println!("• If database keeps growing, the LanceDB version may not expose cleanup_old_versions()");
        println!("• Manual cleanup may require external tools or newer LanceDB versions");
        println!("• Check LanceDB logs for actual cleanup statistics");

        Ok(())
    }

    // clear_call_relationships removed - calls table no longer exists

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Centralized git file hash resolution for all stores
    /// Resolves file paths to git blob hashes at a specific commit using gitoxide
    pub async fn resolve_git_file_hashes(
        &self,
        file_paths: &[String],
        git_sha: &str,
    ) -> Result<std::collections::HashMap<String, String>> {
        match crate::git::resolve_files_at_commit(&self.git_repo_path, git_sha, file_paths) {
            Ok(resolved_hashes) => {
                // If no files were resolved, log this as a warning
                if resolved_hashes.is_empty() {
                    tracing::warn!(
                        "No files were resolved at commit {} in repository {}",
                        git_sha,
                        self.git_repo_path
                    );
                }

                Ok(resolved_hashes)
            }
            Err(e) => {
                tracing::error!("DatabaseManager::resolve_git_file_hashes: Failed to resolve git files at commit {}: {}", git_sha, e);
                tracing::error!("Repository path: {}", self.git_repo_path);
                tracing::error!("Requested file paths: {:?}", file_paths);
                Ok(std::collections::HashMap::new()) // Return empty map instead of failing, let caller handle
            }
        }
    }

    // Processed files operations

    /// Record that a file has been processed with the given git SHA and file content hash
    pub async fn mark_file_processed(
        &self,
        file: String,
        git_sha: Option<String>,
        git_file_sha: String,
    ) -> Result<()> {
        let record = ProcessedFileRecord {
            file,
            git_sha,
            git_file_sha,
            extractor_version: Some(crate::SCHEMA_VERSION),
        };
        self.processed_file_store.insert(record).await
    }

    /// Record multiple processed files
    pub async fn mark_files_processed(&self, records: Vec<ProcessedFileRecord>) -> Result<()> {
        self.processed_file_store.insert_batch(records).await
    }

    /// Check if a file has been processed with the given git SHA and file content hash
    pub async fn is_file_processed(&self, git_file_sha: &str) -> Result<bool> {
        self.processed_file_store.is_processed(git_file_sha).await
    }

    /// Get all processed files for a specific git SHA
    pub async fn get_processed_files_for_git_sha(
        &self,
        git_sha: Option<&str>,
    ) -> Result<Vec<ProcessedFileRecord>> {
        self.processed_file_store
            .get_processed_files_for_git_sha(git_sha)
            .await
    }

    /// Remove processed file records for a specific git SHA (useful when git head changes)
    pub async fn clear_processed_files_for_git_sha(&self, git_sha: Option<&str>) -> Result<()> {
        self.processed_file_store.remove_for_git_sha(git_sha).await
    }

    /// Remove a specific processed file record
    pub async fn unmark_file_processed(
        &self,
        file: &str,
        git_sha: Option<&str>,
        git_file_sha: &str,
    ) -> Result<()> {
        self.processed_file_store
            .remove_file(file, git_sha, git_file_sha)
            .await
    }

    /// Get total count of processed files
    pub async fn get_processed_files_count(&self) -> Result<usize> {
        self.processed_file_store.count().await
    }

    /// Get all processed file records
    pub async fn get_all_processed_files(&self) -> Result<Vec<ProcessedFileRecord>> {
        self.processed_file_store.get_all().await
    }

    /// Get all symbol-filename pairs
    pub async fn get_all_symbol_filename_pairs(&self) -> Result<Vec<(String, String)>> {
        self.symbol_filename_store.get_all().await
    }

    /// Get all existing git file SHAs from processed files for deduplication (optimized streaming version)
    pub async fn get_existing_git_file_shas(&self) -> Result<std::collections::HashSet<String>> {
        // Use the optimized method that only loads git_file_sha column
        self.processed_file_store.get_all_git_file_shas().await
    }

    /// Get file/git_file_sha pairs for pipeline deduplication (optimized for large datasets)
    pub async fn get_processed_file_pairs(
        &self,
    ) -> Result<std::collections::HashSet<(String, String)>> {
        // Use the optimized method that only loads the two needed columns
        self.processed_file_store.get_all_file_git_sha_pairs().await
    }

    // ==================== Branch Management ====================

    /// Record that a branch has been indexed at a specific commit
    pub async fn record_branch_indexed(
        &self,
        branch_name: &str,
        tip_commit: &str,
        remote: Option<&str>,
    ) -> Result<()> {
        use crate::database::branches::IndexedBranchInfo;
        let info = IndexedBranchInfo {
            branch_name: branch_name.to_string(),
            tip_commit: tip_commit.to_string(),
            indexed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            remote: remote.map(|s| s.to_string()),
        };
        self.branch_store.record_branch_indexed(&info).await
    }

    /// Get the tip commit for a specific branch
    pub async fn get_branch_tip(&self, branch_name: &str) -> Result<Option<String>> {
        self.branch_store.get_branch_tip(branch_name).await
    }

    /// Get full information about a specific indexed branch
    pub async fn get_indexed_branch_info(
        &self,
        branch_name: &str,
    ) -> Result<Option<crate::database::branches::IndexedBranchInfo>> {
        self.branch_store.get_branch_info(branch_name).await
    }

    /// List all indexed branches
    pub async fn list_indexed_branches(
        &self,
    ) -> Result<Vec<crate::database::branches::IndexedBranchInfo>> {
        self.branch_store.list_indexed_branches().await
    }

    /// Check if a branch is indexed at the current tip commit
    pub async fn is_branch_current(&self, branch_name: &str, current_tip: &str) -> Result<bool> {
        self.branch_store
            .is_branch_current(branch_name, current_tip)
            .await
    }

    /// Remove a branch record (used when branch is deleted)
    pub async fn remove_indexed_branch(&self, branch_name: &str) -> Result<()> {
        self.branch_store.remove_branch(branch_name).await
    }

    /// Remove all branches for a specific remote
    pub async fn remove_branches_by_remote(&self, remote: &str) -> Result<usize> {
        self.branch_store.remove_branches_by_remote(remote).await
    }

    /// Get all branches that point to a specific commit
    pub async fn get_branches_at_commit(
        &self,
        commit_sha: &str,
    ) -> Result<Vec<crate::database::branches::IndexedBranchInfo>> {
        self.branch_store.get_branches_at_commit(commit_sha).await
    }

    /// Get count of indexed branches
    pub async fn get_indexed_branch_count(&self) -> Result<usize> {
        self.branch_store.count().await
    }

    // ==================== End Branch Management ====================

    // ---- Revision reporting -----------------------------------------------

    /// Revisions that contain a file blob, via `processed_files`.
    ///
    /// `git_file_hash` is the blob id stored on each row. Reading
    /// `processed_files` costs ~0.08s for the whole table versus 0.36s for
    /// `git ls-tree`; this helper reads only the rows for one hash.
    pub async fn revisions_for_file_hash(&self, git_file_hash: &str) -> Result<Vec<String>> {
        self.processed_file_store
            .get_revisions_for_file_hash(git_file_hash)
            .await
    }

    /// Branches that contain a file blob, via `revisions_for_file_hash`
    /// plus the indexed branch tips. Sorted by branch name for stable output.
    pub async fn branches_for_file_hash(
        &self,
        git_file_hash: &str,
    ) -> Result<Vec<crate::database::branches::IndexedBranchInfo>> {
        let revisions = self.revisions_for_file_hash(git_file_hash).await?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for rev in revisions {
            for branch in self.branch_store.get_branches_at_commit(&rev).await? {
                if seen.insert(branch.branch_name.clone()) {
                    out.push(branch);
                }
            }
        }
        out.sort_by(|a, b| a.branch_name.cmp(&b.branch_name));
        Ok(out)
    }

    /// Where a symbol of a given name was found: distinct revisions and
    /// branches that hold at least one row for it. Reads `functions` for the
    /// name, then `processed_files` for each distinct hash. No caller uses
    /// this yet; it is the read side of "not at this revision, present on
    /// ...".
    pub async fn symbol_revisions(
        &self,
        name: &str,
    ) -> Result<(
        Vec<String>,
        Vec<crate::database::branches::IndexedBranchInfo>,
    )> {
        let rows = self
            .function_store
            .find_all_by_name_unfiltered(name)
            .await?;
        let mut hashes: std::collections::HashSet<String> = std::collections::HashSet::new();
        for row in &rows {
            hashes.insert(row.git_file_hash.clone());
        }
        let mut rev_set = std::collections::HashSet::new();
        for hash in hashes {
            for rev in self.revisions_for_file_hash(&hash).await? {
                rev_set.insert(rev);
            }
        }
        let mut revisions: Vec<String> = rev_set.into_iter().collect();
        revisions.sort();
        let mut branches = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for rev in &revisions {
            for b in self.branch_store.get_branches_at_commit(rev).await? {
                if seen.insert(b.branch_name.clone()) {
                    branches.push(b);
                }
            }
        }
        branches.sort_by(|a, b| a.branch_name.cmp(&b.branch_name));
        Ok((revisions, branches))
    }

    pub async fn get_existing_function_names(&self) -> Result<std::collections::HashSet<String>> {
        use futures::TryStreamExt;

        let table = self.connection.open_table("functions").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut function_names = std::collections::HashSet::new();

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            let name_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow::array::StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let function_name = name_array.value(i);
                function_names.insert(function_name.to_string());
            }
        }

        tracing::debug!(
            "Loaded {} existing function names for call relationship filtering",
            function_names.len()
        );
        Ok(function_names)
    }

    // Incremental scan support methods

    /// Determine which files need to be rescanned for incremental updates
    /// Given commitA and commitB, finds all files that should be processed
    pub async fn get_files_for_incremental_scan(
        &self,
        commit_a: &str,
        commit_b: &str,
    ) -> Result<std::collections::HashSet<String>> {
        use crate::git::{get_changed_files, ChangeType};

        tracing::info!(
            "Calculating files for incremental scan from {} to {}",
            commit_a,
            commit_b
        );

        // Step 1: Get directly changed files between commits
        let changed_files = get_changed_files(&self.git_repo_path, commit_a, commit_b)?;
        let mut files_to_scan = std::collections::HashSet::new();

        // Add all directly changed files (except deleted ones)
        for changed_file in &changed_files {
            if changed_file.change_type != ChangeType::Deleted {
                files_to_scan.insert(changed_file.path.clone());
            }
        }

        tracing::info!("Found {} directly changed files", files_to_scan.len());

        // Step 2: Find files connected via relationship tables
        let connected_files = self.find_files_connected_to_changes(&changed_files).await?;
        files_to_scan.extend(connected_files);

        tracing::info!("Total files for incremental scan: {}", files_to_scan.len());

        Ok(files_to_scan)
    }

    /// Find files that are connected to changed files via call graphs and type relationships
    async fn find_files_connected_to_changes(
        &self,
        changed_files: &[crate::git::ChangedFile],
    ) -> Result<std::collections::HashSet<String>> {
        let mut connected_files = std::collections::HashSet::new();

        // Collect all file paths that changed
        let changed_file_paths: std::collections::HashSet<String> =
            changed_files.iter().map(|cf| cf.path.clone()).collect();

        tracing::debug!(
            "Finding files connected to {} changed files",
            changed_file_paths.len()
        );
        for (i, file) in changed_file_paths.iter().enumerate() {
            tracing::debug!("  Changed file {}: {}", i + 1, file);
        }

        // Step 1: Find files connected via call relationships
        let call_connected = self.find_files_connected_via_calls(changed_files).await?;
        connected_files.extend(call_connected.iter().cloned());
        tracing::debug!("Found {} files connected via calls", call_connected.len());

        // Step 2 & 3: Function-type and type-type relationship tracking disabled
        // (will be reimplemented using embedded calls/types columns)

        // Remove files that are already in the changed files list
        connected_files.retain(|f| !changed_file_paths.contains(f));

        tracing::info!(
            "Found {} additional files connected to changes",
            connected_files.len()
        );
        if !connected_files.is_empty() {
            tracing::info!("Connected files:");
            for (i, file) in connected_files.iter().enumerate() {
                tracing::info!("  Connected file {}: {}", i + 1, file);
            }
        }

        Ok(connected_files)
    }

    /// Find files connected via call relationships (optimized with pre-loaded mappings)
    /// If fileA changes, find all files that:
    /// 1. Call functions in fileA (callers of changed functions)
    /// 2. Contain functions called by fileA (callees of changed functions)
    async fn find_files_connected_via_calls(
        &self,
        changed_files: &[crate::git::ChangedFile],
    ) -> Result<std::collections::HashSet<String>> {
        // TODO: Reimplement this method using embedded JSON calls columns instead of the old calls table
        // The calls table no longer exists - call relationships are now embedded in function JSON columns
        // This method should:
        // 1. Read the calls JSON column from functions table
        // 2. Parse the JSON arrays to find call relationships
        // 3. Find files connected to changed files via these relationships

        let _changed_file_paths: std::collections::HashSet<String> =
            changed_files.iter().map(|cf| cf.path.clone()).collect();

        tracing::debug!("Call connection analysis disabled - calls table removed, embedded JSON approach not yet implemented");
        tracing::debug!(
            "Returning empty set for {} changed files",
            changed_files.len()
        );

        // Return empty set until reimplemented
        Ok(std::collections::HashSet::new())
    }

    /// Search function bodies using regex patterns via LanceDB - searches sharded content tables
    pub async fn grep_function_bodies(
        &self,
        pattern: &str,
        path_pattern: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<FunctionInfo>, bool)> {
        use futures::TryStreamExt;

        // Step 1: Search all content shard tables for matching content
        // Only escape single quotes for SQL string literal - preserve backslashes for regex
        let escaped_pattern = pattern.replace("'", "''");

        let where_clause = format!("regexp_like(content, '{escaped_pattern}')");

        // Collect matching blake3 hashes from all content shards (content_0 through content_15)
        let mut matching_hashes: Vec<String> = Vec::new();

        // Query all 16 content shard tables
        for shard in 0..16u8 {
            let table_name = format!("content_{shard}");
            let content_table = self.connection.open_table(&table_name).execute().await?;
            let content_results = content_table
                .query()
                .only_if(&where_clause)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            // Collect matching hashes from this shard
            for batch in &content_results {
                let blake3_hash_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    matching_hashes.push(blake3_hash_array.value(i).to_string());
                }
            }
        }

        if matching_hashes.is_empty() {
            return Ok((Vec::new(), false));
        }

        // Step 2: Find functions that have these body hashes
        let functions_table = self.connection.open_table("functions").execute().await?;
        let mut matching_functions = Vec::new();
        let mut limit_hit = false;

        // Optimize batch processing based on hash count
        let hash_count = matching_hashes.len();
        let function_lookup_start = std::time::Instant::now();

        // Determine processing strategy based on hash count and available parallelism
        let available_cores = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        let parallel_threshold = if available_cores >= 8 { 1000 } else { 2000 };

        if hash_count <= parallel_threshold {
            // For smaller result sets, use a single query for optimal performance
            tracing::debug!(
                "Using optimized single query for {} hashes (threshold: {})",
                hash_count,
                parallel_threshold
            );

            let hash_list: Vec<String> = matching_hashes
                .iter()
                .map(|hash| format!("'{hash}'"))
                .collect();

            let in_clause = hash_list.join(", ");
            let filter = format!("body_hash IN ({in_clause})");

            let function_results = functions_table
                .query()
                .only_if(filter)
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            let functions = self
                .function_store
                .extract_functions_from_batches(&function_results)
                .await?;
            for func in functions {
                if path_pattern.is_none() && limit > 0 && matching_functions.len() >= limit {
                    limit_hit = true;
                    break;
                }
                matching_functions.push(func);
            }
        } else {
            // For larger result sets, use batched queries optimized for parallel processing
            let chunk_size = 500; // Balanced size for parallel processing with 16 CPUs

            // Process chunks concurrently for better performance
            use futures::stream::{self, StreamExt};

            let chunks: Vec<_> = matching_hashes.chunks(chunk_size).collect();
            // Use up to 16 CPUs, but adapt based on available cores and chunk count
            let max_concurrency = std::cmp::min(
                16,
                std::thread::available_parallelism()
                    .map(|p| p.get())
                    .unwrap_or(4),
            );
            let concurrent_limit = std::cmp::min(max_concurrency, chunks.len());

            tracing::debug!("Using parallel batched queries: {} chunks of {} hashes each, {} concurrent workers ({} CPU cores available)",
                chunks.len(), chunk_size, concurrent_limit,
                std::thread::available_parallelism().map(|p| p.get()).unwrap_or(1));

            // Collect all function batches from every chunk, then do a single bulk
            // content fetch across all chunks to avoid repeated table opens.
            let mut all_function_batches: Vec<RecordBatch> = Vec::new();

            let mut chunk_stream = stream::iter(chunks)
                .map(|chunk| {
                    let functions_table = &functions_table;
                    async move {
                        let hash_list: Vec<String> =
                            chunk.iter().map(|hash| format!("'{hash}'")).collect();

                        let in_clause = hash_list.join(", ");
                        let filter = format!("body_hash IN ({in_clause})");

                        let function_results = functions_table
                            .query()
                            .only_if(filter)
                            .execute()
                            .await?
                            .try_collect::<Vec<_>>()
                            .await?;

                        Ok::<Vec<RecordBatch>, anyhow::Error>(function_results)
                    }
                })
                .buffer_unordered(concurrent_limit);

            while let Some(chunk_result) = chunk_stream.next().await {
                all_function_batches.extend(chunk_result?);
            }

            let functions = self
                .function_store
                .extract_functions_from_batches(&all_function_batches)
                .await?;

            // Collect results, applying the limit
            for func in functions {
                if path_pattern.is_none() && limit > 0 && matching_functions.len() >= limit {
                    limit_hit = true;
                    break;
                }
                matching_functions.push(func);
            }
        }

        let function_lookup_duration = function_lookup_start.elapsed();
        tracing::debug!(
            "Function body grep: pattern '{}' matched {} content entries, {} functions in {:?}{}",
            pattern,
            matching_hashes.len(),
            matching_functions.len(),
            function_lookup_duration,
            if path_pattern.is_some() {
                " (no limit applied yet - will limit after path filtering)"
            } else {
                ""
            }
        );

        // Filter by path pattern if provided
        let (final_functions, final_limit_hit) = if let Some(path_regex) = path_pattern {
            match regex::RegexBuilder::new(path_regex)
                .case_insensitive(true)
                .build()
            {
                Ok(path_re) => {
                    let original_count = matching_functions.len();
                    let mut filtered = Vec::new();
                    let mut path_limit_hit = false;

                    // Apply path filter while respecting limit (0 = unlimited)
                    for func in matching_functions {
                        if path_re.is_match(&func.file_path) {
                            if limit > 0 && filtered.len() >= limit {
                                path_limit_hit = true;
                                break;
                            }
                            filtered.push(func);
                        }
                    }

                    tracing::debug!(
                        "Path filter '{}' reduced results from {} to {} functions",
                        path_regex,
                        original_count,
                        filtered.len()
                    );

                    // When path filtering is used, limit applies to filtered results only
                    (filtered, path_limit_hit)
                }
                Err(e) => {
                    tracing::error!("Invalid path regex '{}': {}", path_regex, e);
                    return Err(anyhow::anyhow!(
                        "Invalid path regex '{}': {}",
                        path_regex,
                        e
                    ));
                }
            }
        } else {
            (matching_functions, limit_hit)
        };

        Ok((final_functions, final_limit_hit))
    }

    /// Git-aware search function bodies using regex patterns via LanceDB - searches sharded content tables
    /// Filters results to only include functions that exist at the specified git commit
    pub async fn grep_function_bodies_git_aware(
        &self,
        pattern: &str,
        path_pattern: Option<&str>,
        limit: usize,
        git_sha: &str,
    ) -> Result<(Vec<FunctionInfo>, bool)> {
        // Get workdir overlay matches first
        let workdir_matches = self.workdir_grep_functions(pattern, path_pattern, git_sha);
        let workdir_files: HashSet<String> = workdir_matches
            .iter()
            .map(|f| f.file_path.clone())
            .collect();

        // Step 1: Get all matching functions using the existing non-git-aware method
        let (all_matching_functions, limit_hit_pre_filter) =
            self.grep_function_bodies(pattern, path_pattern, 0).await?; // Use 0 for unlimited to get all matches first

        if all_matching_functions.is_empty() && workdir_matches.is_empty() {
            return Ok((Vec::new(), false));
        }

        // Step 2: Extract unique file paths from matching functions
        let unique_file_paths: Vec<String> = all_matching_functions
            .iter()
            .map(|f| f.file_path.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        tracing::debug!(
            "grep_function_bodies_git_aware: Found {} matching functions in {} unique files, filtering by git SHA {}",
            all_matching_functions.len(),
            unique_file_paths.len(),
            git_sha
        );

        // Step 3: Resolve file paths to git hashes at target commit
        let resolved_hashes = self
            .resolve_git_file_hashes(&unique_file_paths, git_sha)
            .await?;
        if resolved_hashes.is_empty() {
            tracing::warn!(
                "No files resolved for grep pattern '{}' at commit '{}'",
                pattern,
                git_sha
            );
            return Ok((Vec::new(), false));
        }

        // Step 4: Filter functions to only those that exist in the git manifest
        let mut git_filtered_functions = Vec::new();
        let mut limit_hit = false;
        let total_matching_functions = all_matching_functions.len();

        for func in &all_matching_functions {
            // Check if this function's file SHA matches the git manifest
            if let Some(expected_hash) = resolved_hashes.get(&func.file_path) {
                if func.git_file_hash == *expected_hash {
                    if limit > 0 && git_filtered_functions.len() >= limit {
                        limit_hit = true;
                        break;
                    }
                    tracing::debug!(
                        "Including function: {} in {} (hash: {})",
                        func.name,
                        func.file_path,
                        func.git_file_hash
                    );
                    git_filtered_functions.push(func.clone());
                } else {
                    tracing::debug!(
                        "Filtered out function: {} in {} (hash mismatch: {} vs {})",
                        func.name,
                        func.file_path,
                        func.git_file_hash,
                        expected_hash
                    );
                }
            } else {
                tracing::debug!(
                    "Filtered out function: {} in {} (file not found in git manifest)",
                    func.name,
                    func.file_path
                );
            }
        }

        // Merge workdir results with DB results, excluding dirty/deleted files from DB
        let mut merged = workdir_matches;
        for func in git_filtered_functions {
            if !workdir_files.contains(&func.file_path)
                && !self.workdir_is_deleted(&func.file_path, git_sha)
            {
                merged.push(func);
            }
        }

        let mut final_limit_hit = limit_hit || limit_hit_pre_filter;
        if limit > 0 && merged.len() > limit {
            merged.truncate(limit);
            final_limit_hit = true;
        }

        tracing::info!(
            "Git-aware grep: pattern '{}' matched {} DB functions + {} workdir, filtered to {} at git commit {}",
            pattern,
            total_matching_functions,
            workdir_files.len(),
            merged.len(),
            git_sha
        );

        Ok((merged, final_limit_hit))
    }

    /// Efficient callers function implementation following the 4-step algorithm:
    /// 1. Identify git commit SHA (passed as argument or default to current commit)
    /// 2. Generate manifest of all file SHAs in that git commit
    /// 3. Find functions that call the target function using efficient LanceDB query
    /// 4. Report the results
    pub async fn find_callers_efficient(
        &self,
        target_function: &str,
        git_sha: Option<&str>,
    ) -> Result<Vec<FunctionInfo>> {
        let total_start = std::time::Instant::now();
        tracing::info!(
            "Starting efficient callers search for function: {}",
            target_function
        );

        // Step 1: Identify git commit SHA
        let step1_start = std::time::Instant::now();
        let effective_git_sha = match git_sha {
            Some(sha) => {
                tracing::info!("Using provided git commit SHA: {}", sha);
                sha.to_string()
            }
            None => {
                // Default to current commit
                match crate::git::get_git_sha(&self.git_repo_path) {
                    Ok(Some(current_sha)) => {
                        tracing::info!("Using current git commit SHA: {}", current_sha);
                        current_sha
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "Not in a git repository, falling back to non-git-aware search"
                        );
                        return self.find_callers_non_git_aware(target_function).await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to get current git SHA: {}, falling back to non-git-aware search", e);
                        return self.find_callers_non_git_aware(target_function).await;
                    }
                }
            }
        };
        tracing::info!(
            "find_callers_efficient: Step 1 (identify git SHA) took {:?}",
            step1_start.elapsed()
        );

        // Step 2: Generate manifest of all file SHAs in that git commit
        let step2_start = std::time::Instant::now();
        tracing::info!(
            "Generating complete git file manifest for commit: {}",
            effective_git_sha
        );
        let git_manifest = self.git_manifest_cached(&effective_git_sha).await?;
        tracing::info!(
            "Generated manifest with {} files at commit {}",
            git_manifest.len(),
            effective_git_sha
        );
        tracing::info!(
            "find_callers_efficient: Step 2 (generate git manifest) took {:?}",
            step2_start.elapsed()
        );

        if git_manifest.is_empty() {
            tracing::warn!("No files found in git commit {}", effective_git_sha);
            return Ok(Vec::new());
        }

        // Step 3: Find functions that call the target function using efficient LanceDB query
        let step3_start = std::time::Instant::now();
        tracing::info!("Searching for functions that call: {}", target_function);

        // Use the new embedded JSON schema to find all potential callers
        let all_callers = self.get_function_callers(target_function).await?;
        if all_callers.is_empty() {
            tracing::info!("No functions call '{}' in database", target_function);
            return Ok(Vec::new());
        }

        tracing::info!(
            "Found {} potential callers, filtering against {} files in git manifest",
            all_callers.len(),
            git_manifest.len()
        );

        // Get function details for all callers
        let caller_functions = self.function_store.get_by_names(&all_callers).await?;
        if caller_functions.is_empty() {
            tracing::warn!("No caller function details found");
            return Ok(Vec::new());
        }
        tracing::info!("find_callers_efficient: Step 3 (find potential callers) took {:?}, found {} potential callers",
            step3_start.elapsed(), all_callers.len());

        // Step 4: Filter callers to only those that exist in the git manifest and report results
        let step4_start = std::time::Instant::now();
        let mut valid_callers = Vec::new();

        for caller_name in &all_callers {
            if let Some(func) = caller_functions.get(caller_name).and_then(|f| f.first()) {
                // Check if this function's file SHA matches the git manifest
                if let Some(expected_hash) = git_manifest.hash_of(&func.file_path) {
                    if func.git_file_hash == expected_hash {
                        valid_callers.push(func.clone());
                        tracing::debug!(
                            "Valid caller: {} in {} (hash: {})",
                            func.name,
                            func.file_path,
                            func.git_file_hash
                        );
                    } else {
                        tracing::debug!(
                            "Filtered out caller: {} in {} (hash mismatch: {} vs {})",
                            func.name,
                            func.file_path,
                            func.git_file_hash,
                            expected_hash
                        );
                    }
                } else {
                    tracing::debug!(
                        "Filtered out caller: {} in {} (file not found in git manifest)",
                        func.name,
                        func.file_path
                    );
                }
            }
        }
        tracing::info!(
            "find_callers_efficient: Step 4 (filter callers against manifest) took {:?}",
            step4_start.elapsed()
        );

        tracing::info!(
            "Found {} valid callers for '{}' at git commit {}",
            valid_callers.len(),
            target_function,
            effective_git_sha
        );

        tracing::info!(
            "find_callers_efficient: TOTAL time {:?}, found {} valid callers",
            total_start.elapsed(),
            valid_callers.len()
        );
        Ok(valid_callers)
    }

    /// Get callers using pre-loaded git manifest for filtering
    /// Generate a complete manifest of all file paths and their SHAs at a specific git commit
    /// Uses the shared git tree traversal utility for consistency
    /// The manifest for a revision, walking the tree only when it is not the
    /// one already in hand.
    ///
    /// `callers` asks twice — once for direct callers, once for indirect —
    /// and each walk reads about 90,000 entries on a Linux tree. The cache
    /// holds one revision: a query asks about one, and the second ask is
    /// where the saving is.
    pub async fn git_manifest_cached(&self, git_sha: &str) -> Result<GitManifest> {
        if let Ok(cache) = self.manifest_cache.read() {
            if let Some((sha, manifest)) = cache.as_ref() {
                if sha == git_sha {
                    return Ok(manifest.clone());
                }
            }
        }

        let manifest = std::sync::Arc::new(self.generate_git_manifest(git_sha).await?);
        if let Ok(mut cache) = self.manifest_cache.write() {
            *cache = Some((git_sha.to_string(), manifest.clone()));
        }

        Ok(manifest)
    }

    pub async fn generate_git_manifest(
        &self,
        git_sha: &str,
    ) -> Result<crate::database::resolution::RevisionPaths> {
        let (dirty, deleted) = {
            let guard = self.workdir_index.read().unwrap();
            match guard.as_ref() {
                Some(w) => (w.dirty_file_paths().clone(), w.deleted_file_paths().clone()),
                None => (
                    std::collections::HashMap::new(),
                    std::collections::HashSet::new(),
                ),
            }
        };
        let valid = self.revision_resolves(git_sha);
        Ok(crate::database::resolution::RevisionPaths::new_lazy(
            std::path::PathBuf::from(&self.git_repo_path),
            git_sha.to_string(),
            dirty,
            deleted,
            valid,
        ))
    }

    /// Fallback callers search when not in git repository
    async fn find_callers_non_git_aware(&self, target_function: &str) -> Result<Vec<FunctionInfo>> {
        tracing::info!(
            "Performing non-git-aware callers search for: {}",
            target_function
        );

        let all_callers = self.get_function_callers(target_function).await?;
        if all_callers.is_empty() {
            return Ok(Vec::new());
        }

        let caller_functions = self.function_store.get_by_names(&all_callers).await?;
        let callers_vec: Vec<FunctionInfo> = caller_functions
            .into_values()
            .filter_map(|mut candidates| {
                if candidates.is_empty() {
                    None
                } else {
                    Some(candidates.swap_remove(0))
                }
            })
            .collect();

        tracing::info!(
            "Found {} callers for '{}' (non-git-aware)",
            callers_vec.len(),
            target_function
        );
        Ok(callers_vec)
    }

    // Content operations for deduplication

    /// Store content and return the blake3 hash
    pub async fn store_content(&self, content: &str) -> Result<String> {
        self.content_store.store_content(content).await
    }

    /// Store content and return hex hash
    pub async fn store_content_with_hex_hash(&self, content: &str) -> Result<String> {
        self.content_store
            .store_content_with_hex_hash(content)
            .await
    }

    /// Get content by blake3 hash
    pub async fn get_content(&self, blake3_hash: &str) -> Result<Option<String>> {
        self.content_store.get_content(blake3_hash).await
    }

    /// Get content by blake3 hash hex string
    pub async fn get_content_by_hex(&self, blake3_hash_hex: &str) -> Result<Option<String>> {
        self.content_store.get_content_by_hex(blake3_hash_hex).await
    }

    /// Bulk fetch content for multiple hashes - optimized for dump operations
    pub async fn get_content_bulk(
        &self,
        hashes: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        self.content_store.get_content_bulk(hashes).await
    }

    /// Check if content exists by hash
    pub async fn content_exists(&self, blake3_hash: &str) -> Result<bool> {
        self.content_store.content_exists(blake3_hash).await
    }

    /// Insert a batch of content items
    pub async fn insert_content_batch(&self, content_items: Vec<ContentInfo>) -> Result<()> {
        self.content_store.insert_batch(content_items).await
    }

    /// Get all content (for debugging/analysis)
    pub async fn get_all_content(&self) -> Result<Vec<ContentInfo>> {
        self.content_store.get_all().await
    }

    /// Get statistics about content storage
    pub async fn get_content_stats(&self) -> Result<crate::database::content::ContentStats> {
        self.content_store.get_stats().await
    }

    // ============================================================================
    // Git Manifest-based optimization methods for bulk operations
    // ============================================================================

    /// Check if a function exists at git commit using pre-generated manifest (fast)
    async fn function_exists_in_manifest(
        &self,
        function_name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<bool> {
        // Get all functions with this name (non-git-aware, fast database query)
        let all_functions = self
            .function_store
            .find_all_by_name_unfiltered(function_name)
            .await?;

        // Check if any function exists in the git manifest (fast HashMap lookup)
        for func in &all_functions {
            if let Some(expected_hash) = git_manifest.hash_of(&func.file_path) {
                if func.git_file_hash == expected_hash {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Get function callees using pre-generated manifest (fast)
    /// Every definition of the name that this revision holds, with what each
    /// one calls.
    ///
    /// Collapsing these to one answer is how `calls pr_warn` came to report
    /// `fprintf` and `va_end`: nine definitions exist, and the one picked was a
    /// userspace copy no kernel caller can reach. A reader given the file each
    /// set came from can tell which applies; a reader given one set cannot tell
    /// there was a choice.
    pub async fn get_function_callees_by_definition(
        &self,
        function_name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Vec<crate::types::CalleeDefinition>> {
        // Query functions table directly - efficient, doesn't fetch bodies
        let escaped_name = function_name.replace("'", "''");
        let table = self.connection.open_table("functions").execute().await?;

        let results = table
            .query()
            .only_if(format!("name = '{escaped_name}'"))
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        // Filter by git hash and collect matching functions
        let mut matches = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let line_start_array = batch
                    .column(3)
                    .as_any()
                    .downcast_ref::<arrow::array::Int64Array>()
                    .unwrap();
                let line_end_array = batch
                    .column(4)
                    .as_any()
                    .downcast_ref::<arrow::array::Int64Array>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let body_hash_array = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "body_hash")
                    .and_then(|index| {
                        batch
                            .column(index)
                            .as_any()
                            .downcast_ref::<arrow::array::StringArray>()
                    });

                for i in 0..batch.num_rows() {
                    let file_path = file_path_array.value(i);
                    let git_file_hash = git_file_hash_array.value(i);
                    let body_hash = body_hash_array.and_then(|array| {
                        array
                            .is_valid(i)
                            .then(|| array.value(i).to_string())
                            .filter(|hash| !hash.is_empty())
                    });

                    // Fast manifest lookup
                    if let Some(expected_hash) = git_manifest.hash_of(file_path) {
                        if git_file_hash == expected_hash {
                            // Parse the calls JSON
                            let calls = if calls_array.is_null(i) {
                                None
                            } else {
                                Some(crate::database::parse_call_list(calls_array.value(i))?)
                            };

                            // Collect lightweight info for selection
                            matches.push((
                                file_path.to_string(),
                                line_start_array.value(i) as u32,
                                line_end_array.value(i) as u32,
                                calls,
                                body_hash,
                            ));
                        }
                    }
                }
            }
        }

        // Whether each row defines the name or only declares it. The row's own
        // text decides, so it is read here -- for the handful of rows that
        // share one name, not for the table.
        let mut definitions: Vec<crate::types::CalleeDefinition> = Vec::new();
        for (file_path, line_start, line_end, calls, body_hash) in matches {
            let text = match &body_hash {
                Some(hash) => self.get_content(hash).await?.unwrap_or_default(),
                None => String::new(),
            };
            definitions.push(crate::types::CalleeDefinition {
                file_path,
                line_start,
                line_end,
                callees: calls.unwrap_or_default(),
                is_definition: !text.is_empty() && !crate::types::text_is_prototype(&text),
            });
        }
        // A stable order, so two runs and two readers see the same list.
        definitions.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then(a.line_start.cmp(&b.line_start))
        });
        Ok(definitions)
    }

    /// The callees of the definition this revision most likely means.
    ///
    /// A single answer is what a call chain needs -- walking every definition of
    /// every name multiplies a chain by the ambiguity at each step. Where the
    /// choice is shown to a reader rather than walked,
    /// `get_function_callees_by_definition` reports all of them instead.
    ///
    /// Which definition that is comes from `choose_definition`, the same place
    /// the header line above a chain comes from, and the row is then looked up
    /// by where it was read. Ranking here as well is what made a chain
    /// contradict itself: this function preferred a long `.c` body and the
    /// header preferred the program being audited, so `callchain pr_warn` named
    /// include/linux/printk.h:563 and then listed the callees of
    /// arch/x86/tools/insn_decoder_test.c:48.
    pub async fn get_function_callees_with_manifest(
        &self,
        function_name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Vec<String>> {
        let definitions = self
            .get_function_callees_by_definition(function_name, git_manifest)
            .await?;
        let chosen = self
            .find_function_with_manifest_reporting(function_name, git_manifest)
            .await?;
        let Some(chosen) = chosen else {
            return Ok(Vec::new());
        };
        Ok(definitions
            .into_iter()
            .find(|definition| {
                definition.file_path == chosen.function.file_path
                    && definition.line_start == chosen.function.line_start
            })
            .map(|definition| definition.callees)
            .unwrap_or_default())
    }

    /// Build a complete caller index from the database in ONE scan.
    /// Returns HashMap<callee_name, Vec<caller_name>> filtered by git manifest.
    /// This is much faster than doing N separate LIKE queries for N functions.
    pub async fn build_caller_index_with_manifest(
        &self,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<std::collections::HashMap<String, Vec<String>>> {
        let start = std::time::Instant::now();
        let table = self.connection.open_table("functions").execute().await?;

        // Query all functions that have calls (one scan)
        let results = table
            .query()
            .only_if("calls IS NOT NULL")
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut caller_index: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let file_path = file_path_array.value(i);
                    let git_file_hash = git_file_hash_array.value(i);

                    // Only include functions that exist at the current git commit
                    if let Some(expected_hash) = git_manifest.hash_of(file_path) {
                        if git_file_hash == expected_hash {
                            let caller_name = name_array.value(i);
                            if !calls_array.is_null(i) {
                                let calls_list =
                                    crate::database::parse_call_list(calls_array.value(i))?;
                                for callee in calls_list {
                                    caller_index
                                        .entry(callee)
                                        .or_default()
                                        .push(caller_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        tracing::info!(
            "build_caller_index_with_manifest: built index with {} callees in {:?}",
            caller_index.len(),
            start.elapsed()
        );
        Ok(caller_index)
    }

    /// Get function callers using pre-generated manifest (fast)
    pub async fn get_function_callers_with_manifest(
        &self,
        function_name: &str,
        git_manifest: &crate::database::resolution::RevisionPaths,
    ) -> Result<Vec<String>> {
        // Use efficient filtering: find functions whose calls JSON contains the target function name
        let escaped_name = function_name.replace("'", "''"); // SQL escape
        let table = self.connection.open_table("functions").execute().await?;

        // Filter for functions whose calls column contains the target function name
        let filter = format!("calls IS NOT NULL AND calls LIKE '%\\\"{escaped_name}\\\"%%'");
        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut callers = Vec::new();

        for batch in results {
            if batch.num_rows() > 0 {
                let name_array = batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let file_path_array = batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();
                let git_file_hash_array = batch
                    .column(2)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                // Find the calls column
                let calls_column_idx = batch
                    .schema()
                    .fields()
                    .iter()
                    .position(|f| f.name() == "calls")
                    .ok_or_else(|| anyhow::anyhow!("calls column not found in functions table"))?;
                let calls_array = batch
                    .column(calls_column_idx)
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .unwrap();

                for i in 0..batch.num_rows() {
                    let caller_name = name_array.value(i);
                    let file_path = file_path_array.value(i);
                    let git_file_hash = git_file_hash_array.value(i).to_string();

                    // Fast manifest lookup instead of expensive git resolution
                    if let Some(expected_hash) = git_manifest.hash_of(file_path) {
                        if git_file_hash == expected_hash {
                            // This function exists at the git SHA, verify it actually calls our target
                            if !calls_array.is_null(i) {
                                let calls_json = calls_array.value(i);
                                let calls_list = crate::database::parse_call_list(calls_json)?;
                                if calls_list.contains(&function_name.to_string()) {
                                    callers.push(caller_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(callers)
    }

    // Git commits operations

    /// Insert git commit metadata
    pub async fn insert_git_commits(
        &self,
        commits: Vec<crate::types::GitCommitInfo>,
    ) -> Result<()> {
        use arrow::array::{ArrayRef, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use arrow::record_batch::RecordBatch;
        use std::sync::Arc;

        if commits.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "insert_git_commits: Starting batch insertion of {} commits into git_commits table",
            commits.len()
        );

        let schema = Arc::new(Schema::new(vec![
            Field::new("git_sha", DataType::Utf8, false),
            Field::new("parent_sha", DataType::Utf8, false),
            Field::new("author", DataType::Utf8, false),
            Field::new("subject", DataType::Utf8, false),
            Field::new("message", DataType::Utf8, false),
            Field::new("tags", DataType::Utf8, false),
            Field::new("diff", DataType::Utf8, false),
            Field::new("symbols", DataType::Utf8, false),
            Field::new("files", DataType::Utf8, false),
        ]));

        tracing::info!(
            "insert_git_commits: Converting {} commits to Arrow arrays (serializing JSON for tags/symbols)...",
            commits.len()
        );
        let array_conversion_start = std::time::Instant::now();

        let mut git_shas = Vec::new();
        let mut parent_shas = Vec::new();
        let mut authors = Vec::new();
        let mut subjects = Vec::new();
        let mut messages = Vec::new();
        let mut tags = Vec::new();
        let mut diffs = Vec::new();
        let mut symbols = Vec::new();
        let mut files = Vec::new();

        for commit in commits {
            git_shas.push(commit.git_sha);
            parent_shas.push(serde_json::to_string(&commit.parent_sha)?);
            authors.push(commit.author);
            subjects.push(commit.subject);
            messages.push(commit.message);
            tags.push(serde_json::to_string(&commit.tags)?);
            diffs.push(commit.diff);
            symbols.push(serde_json::to_string(&commit.symbols)?);
            files.push(serde_json::to_string(&commit.files)?);
        }

        tracing::info!(
            "insert_git_commits: Array conversion completed in {:.2}s",
            array_conversion_start.elapsed().as_secs_f64()
        );

        tracing::info!(
            "insert_git_commits: Creating Arrow RecordBatch with {} rows...",
            git_shas.len()
        );
        let batch_creation_start = std::time::Instant::now();

        let columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from(git_shas)),
            Arc::new(StringArray::from(parent_shas)),
            Arc::new(StringArray::from(authors)),
            Arc::new(StringArray::from(subjects)),
            Arc::new(StringArray::from(messages)),
            Arc::new(StringArray::from(tags)),
            Arc::new(StringArray::from(diffs)),
            Arc::new(StringArray::from(symbols)),
            Arc::new(StringArray::from(files)),
        ];

        let batch = RecordBatch::try_new(schema.clone(), columns)?;
        let batches = vec![Ok(batch)];
        let batch_iterator =
            arrow::record_batch::RecordBatchIterator::new(batches.into_iter(), schema);

        tracing::info!(
            "insert_git_commits: RecordBatch creation completed in {:.2}s",
            batch_creation_start.elapsed().as_secs_f64()
        );

        tracing::info!("insert_git_commits: Opening git_commits table...");
        let table_open_start = std::time::Instant::now();
        let table = self.connection.open_table("git_commits").execute().await?;
        tracing::info!(
            "insert_git_commits: Table opened in {:.2}s",
            table_open_start.elapsed().as_secs_f64()
        );

        // Use merge_insert for upsert functionality (update if exists, insert if not)
        tracing::info!(
            "insert_git_commits: Executing merge_insert upsert operation (this may take several seconds)..."
        );
        let merge_insert_start = std::time::Instant::now();
        let mut merge_insert = table.merge_insert(&["git_sha"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        merge_insert.execute(Box::new(batch_iterator)).await?;
        tracing::info!(
            "insert_git_commits: Merge_insert completed in {:.2}s",
            merge_insert_start.elapsed().as_secs_f64()
        );

        tracing::info!("insert_git_commits: Batch insertion complete");

        Ok(())
    }

    /// Insert lore emails into the database, returning the indices of
    /// any emails that could not be stored.  Callers must not record
    /// commit SHAs for failed indices in the lore_indexed_commits
    /// table, otherwise those emails are permanently lost.
    pub async fn insert_lore_emails(
        &self,
        emails: &[crate::types::LoreEmailInfo],
    ) -> Result<Vec<usize>> {
        use arrow::datatypes::{DataType, Field, Schema};
        use std::sync::Arc;

        if emails.is_empty() {
            return Ok(Vec::new());
        }

        tracing::info!(
            "insert_lore_emails: Starting batch insertion of {} emails into lore table",
            emails.len()
        );

        let schema = Arc::new(Schema::new(vec![
            Field::new("git_commit_sha", DataType::Utf8, false),
            Field::new("from", DataType::Utf8, false),
            Field::new("date", DataType::Utf8, false),
            Field::new("date_timestamp", DataType::Int64, false),
            Field::new("message_id", DataType::Utf8, false),
            Field::new("in_reply_to", DataType::Utf8, true),
            Field::new("subject", DataType::Utf8, false),
            Field::new("references", DataType::Utf8, true),
            Field::new("recipients", DataType::Utf8, false),
            Field::new("body", DataType::Utf8, false),
            Field::new("symbols", DataType::Utf8, false),
        ]));

        // Deduplicate by message_id within the batch.  A lore
        // archive can contain the same email in multiple git commits;
        // appending duplicates would create redundant rows.  Keep the
        // last occurrence.
        let mut seen = std::collections::HashMap::with_capacity(emails.len());
        for (i, email) in emails.iter().enumerate() {
            seen.insert(&email.message_id, i);
        }
        let mut dedup_indices: Vec<usize> = seen.into_values().collect();
        dedup_indices.sort_unstable();

        let dedup_count = emails.len() - dedup_indices.len();
        if dedup_count > 0 {
            tracing::info!(
                "insert_lore_emails: Removed {} duplicate message_ids from batch of {}",
                dedup_count,
                emails.len()
            );
        }

        let table = self.connection.open_table("lore").execute().await?;

        let mut failed_indices: Vec<usize> = Vec::new();

        // Filter out emails whose message_id already exists in the
        // table.  Normally every email here is new because
        // index_lore_archive skips already-indexed commits, but a
        // partial failure on a previous run can leave rows in the
        // table whose commit SHA was never recorded in
        // lore_indexed_commits.  Filtering avoids duplicates without
        // relying on merge_insert, which hits a spurious null-column
        // error in lance-file 3.0.1.
        let new_indices = Self::filter_existing_lore_ids(&table, emails, &dedup_indices).await?;

        if new_indices.len() < dedup_indices.len() {
            tracing::info!(
                "insert_lore_emails: {} of {} already in table, inserting {}",
                dedup_indices.len() - new_indices.len(),
                dedup_indices.len(),
                new_indices.len(),
            );
        }

        if new_indices.is_empty() {
            tracing::info!("insert_lore_emails: no new emails to insert");
            return Ok(failed_indices);
        }

        // Use table.add() instead of merge_insert.  merge_insert in
        // lance-file 3.0.1 introduces spurious nulls during its
        // internal join/write phase, causing every insert to fail
        // with "subject contained null values".  Plain append avoids
        // the merge codepath entirely.  Duplicates are prevented by
        // the filter_existing_lore_ids check above.
        if let Err(e) = Self::add_lore_chunk(&table, emails, &new_indices, &schema).await {
            tracing::warn!(
                "insert_lore_emails: full batch of {} failed ({}), \
                 falling back to chunked insertion",
                new_indices.len(),
                e
            );

            const MAX_CHUNK: usize = 128;

            for chunk in new_indices.chunks(MAX_CHUNK) {
                if let Err(e) = Self::add_lore_chunk(&table, emails, chunk, &schema).await {
                    tracing::warn!(
                        "insert_lore_emails: chunk of {} failed ({}), \
                         retrying individually",
                        chunk.len(),
                        e
                    );
                    for &idx in chunk {
                        if let Err(e2) = Self::add_lore_chunk(&table, emails, &[idx], &schema).await
                        {
                            tracing::warn!(
                                "insert_lore_emails: skipping \
                                 message_id={}: {}",
                                emails[idx].message_id,
                                e2
                            );
                            failed_indices.push(idx);
                        }
                    }
                }
            }
        }

        if !failed_indices.is_empty() {
            tracing::warn!(
                "insert_lore_emails: {} of {} emails failed to insert",
                failed_indices.len(),
                new_indices.len()
            );
        }

        tracing::info!("insert_lore_emails: Batch insertion complete");

        Ok(failed_indices)
    }

    /// Return the subset of `indices` whose message_id does not
    /// already exist in the lore table.
    async fn filter_existing_lore_ids(
        table: &lancedb::Table,
        emails: &[crate::types::LoreEmailInfo],
        indices: &[usize],
    ) -> Result<Vec<usize>> {
        use futures::TryStreamExt as _;

        // Build an IN-list predicate.  message_ids are already
        // validated to be non-empty, but escape single quotes for
        // the SQL literal.
        let id_list: Vec<String> = indices
            .iter()
            .map(|&i| format!("'{}'", emails[i].message_id.replace('\'', "''")))
            .collect();

        let predicate = format!("message_id IN ({})", id_list.join(", "));

        let stream = table
            .query()
            .select(lancedb::query::Select::Columns(vec![
                "message_id".to_string()
            ]))
            .only_if(&predicate)
            .execute()
            .await?;
        let batches: Vec<_> = stream.try_collect().await?;

        let mut existing = std::collections::HashSet::new();
        for batch in &batches {
            if let Some(col) = batch.column_by_name("message_id") {
                let arr = col
                    .as_any()
                    .downcast_ref::<arrow::array::StringArray>()
                    .expect("message_id column must be StringArray");
                for i in 0..arr.len() {
                    if !arr.is_null(i) {
                        existing.insert(arr.value(i).to_string());
                    }
                }
            }
        }

        Ok(indices
            .iter()
            .copied()
            .filter(|&i| !existing.contains(&emails[i].message_id))
            .collect())
    }

    /// Build a [`RecordBatch`] from the given email indices and
    /// append it to the lore table.
    async fn add_lore_chunk(
        table: &lancedb::Table,
        emails: &[crate::types::LoreEmailInfo],
        indices: &[usize],
        schema: &std::sync::Arc<arrow::datatypes::Schema>,
    ) -> Result<()> {
        use arrow::array::{ArrayRef, Int64Array, StringArray};
        use arrow::record_batch::RecordBatch;
        use std::sync::Arc;

        debug_assert!(indices.iter().all(|&i| i < emails.len()));

        let mut git_commit_shas = Vec::with_capacity(indices.len());
        let mut from_addrs = Vec::with_capacity(indices.len());
        let mut dates = Vec::with_capacity(indices.len());
        let mut date_timestamps = Vec::with_capacity(indices.len());
        let mut message_ids = Vec::with_capacity(indices.len());
        let mut in_reply_tos = Vec::with_capacity(indices.len());
        let mut subjects = Vec::with_capacity(indices.len());
        let mut references_list = Vec::with_capacity(indices.len());
        let mut recipients_list = Vec::with_capacity(indices.len());
        let mut bodies = Vec::with_capacity(indices.len());
        let mut symbols_list = Vec::with_capacity(indices.len());

        for &idx in indices {
            let email = &emails[idx];
            git_commit_shas.push(email.git_commit_sha.clone());
            from_addrs.push(email.from.clone());
            dates.push(email.date.clone());
            date_timestamps.push(email.date_timestamp);
            message_ids.push(email.message_id.clone());
            in_reply_tos.push(email.in_reply_to.clone());
            subjects.push(email.subject.clone());
            references_list.push(email.references.clone());
            recipients_list.push(email.recipients.clone());
            bodies.push(email.body.clone());
            symbols_list.push(serde_json::to_string(&email.symbols)?);
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from(git_commit_shas)),
            Arc::new(StringArray::from(from_addrs)),
            Arc::new(StringArray::from(dates)),
            Arc::new(Int64Array::from(date_timestamps)),
            Arc::new(StringArray::from(message_ids)),
            Arc::new(StringArray::from(in_reply_tos)),
            Arc::new(StringArray::from(subjects)),
            Arc::new(StringArray::from(references_list)),
            Arc::new(StringArray::from(recipients_list)),
            Arc::new(StringArray::from(bodies)),
            Arc::new(StringArray::from(symbols_list)),
        ];

        let batch = RecordBatch::try_new(schema.clone(), columns)?;
        table.add(vec![batch]).execute().await?;
        Ok(())
    }

    /// Parse an RFC 2822 date string into a Unix timestamp.
    /// Returns 0 if parsing fails.
    fn parse_date_to_timestamp(date_str: &str) -> i64 {
        chrono::DateTime::parse_from_rfc2822(date_str)
            .map(|dt| dt.timestamp())
            .unwrap_or(0)
    }

    /// Extract date_timestamp from a batch row, falling back to parsing the
    /// date string for databases that predate the date_timestamp column.
    fn get_date_timestamp(
        date_timestamps: Option<&arrow::array::Int64Array>,
        dates: &arrow::array::GenericStringArray<i32>,
        row: usize,
    ) -> i64 {
        if let Some(ts) = date_timestamps {
            ts.value(row)
        } else {
            Self::parse_date_to_timestamp(dates.value(row))
        }
    }

    /// Get all lore emails from the database
    pub async fn get_all_lore_emails(&self) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;

        let table = self.connection.open_table("lore").execute().await?;
        let stream = table.query().execute().await?;
        let batches: Vec<_> = stream.try_collect().await?;

        let mut emails = Vec::new();

        for batch in batches {
            let num_rows = batch.num_rows();

            // Extract columns
            let git_commit_shas = batch
                .column_by_name("git_commit_sha")
                .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                .as_string::<i32>();
            let from_addrs = batch
                .column_by_name("from")
                .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                .as_string::<i32>();
            let dates = batch
                .column_by_name("date")
                .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                .as_string::<i32>();
            let date_timestamps = batch
                .column_by_name("date_timestamp")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
            let message_ids = batch
                .column_by_name("message_id")
                .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                .as_string::<i32>();
            let in_reply_tos = batch
                .column_by_name("in_reply_to")
                .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                .as_string::<i32>();
            let subjects = batch
                .column_by_name("subject")
                .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                .as_string::<i32>();
            let references_list = batch
                .column_by_name("references")
                .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                .as_string::<i32>();
            let recipients_list = batch
                .column_by_name("recipients")
                .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                .as_string::<i32>();
            let bodies = batch
                .column_by_name("body")
                .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                .as_string::<i32>();
            let symbols_list = batch
                .column_by_name("symbols")
                .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                .as_string::<i32>();

            for i in 0..num_rows {
                // Parse JSON symbols array
                let symbols_json = symbols_list.value(i);
                let symbols: Vec<String> = serde_json::from_str(symbols_json).unwrap_or_default();

                let email = crate::types::LoreEmailInfo {
                    git_commit_sha: git_commit_shas.value(i).to_string(),
                    from: from_addrs.value(i).to_string(),
                    date: dates.value(i).to_string(),
                    date_timestamp: Self::get_date_timestamp(date_timestamps, dates, i),
                    message_id: message_ids.value(i).to_string(),
                    in_reply_to: if in_reply_tos.is_null(i) {
                        None
                    } else {
                        Some(in_reply_tos.value(i).to_string())
                    },
                    subject: subjects.value(i).to_string(),
                    references: if references_list.is_null(i) {
                        None
                    } else {
                        Some(references_list.value(i).to_string())
                    },
                    recipients: recipients_list.value(i).to_string(),
                    body: bodies.value(i).to_string(),
                    symbols,
                };
                emails.push(email);
            }
        }

        Ok(emails)
    }

    /// Search lore emails using Full Text Search with regex post-filtering
    pub async fn search_lore_emails(
        &self,
        field: &str,
        pattern: &str,
        limit: usize,
        since_date: Option<&str>,
        until_date: Option<&str>,
    ) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;

        // Parse filter dates to Unix timestamps for database-level filtering
        let since_timestamp = since_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.timestamp());
        let until_timestamp = until_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.timestamp());

        tracing::info!(
            "lore search: field='{}' pattern='{}' since_timestamp={:?} until_timestamp={:?}",
            field,
            pattern,
            since_timestamp,
            until_timestamp
        );

        let table = self.connection.open_table("lore").execute().await?;

        // Only use date_timestamp filter if the column exists in the table
        let has_date_timestamp = table
            .schema()
            .await
            .map(|s| s.field_with_name("date_timestamp").is_ok())
            .unwrap_or(false);
        let date_filter = if has_date_timestamp {
            match (since_timestamp, until_timestamp) {
                (Some(since), Some(until)) => Some(format!(
                    "date_timestamp >= {} AND date_timestamp <= {}",
                    since, until
                )),
                (Some(since), None) => Some(format!("date_timestamp >= {}", since)),
                (None, Some(until)) => Some(format!("date_timestamp <= {}", until)),
                (None, None) => None,
            }
        } else {
            None
        };

        // FTS uses simple tokenizer - normalize pattern by stripping special chars
        let fts_pattern = pattern
            .split(|c: char| !c.is_alphanumeric() && c != ' ')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");

        let regex = regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()?;
        let mut emails = Vec::new();
        let target_limit = if limit > 0 { limit } else { 10000 };

        // Incremental search: start with reasonable limit, expand until matches stop increasing
        let mut fts_limit = if limit > 0 { limit * 10 } else { 10000 };
        let mut previous_count = 0;
        let mut first_iteration = true;

        loop {
            // When the FTS pattern is empty (e.g. regex ".*" has no
            // alphanumeric tokens), skip FTS and use a plain table
            // scan so the regex post-filter still runs.
            let batches: Vec<_> = if fts_pattern.is_empty() {
                tracing::info!(
                    "FTS pattern empty for field '{}', falling back to table scan",
                    field
                );
                let mut query_builder = table.query();
                if let Some(ref filter) = date_filter {
                    query_builder = query_builder.only_if(filter);
                }
                query_builder
                    .limit(fts_limit)
                    .execute()
                    .await?
                    .try_collect()
                    .await?
            } else {
                let fts_query =
                    FullTextSearchQuery::new(fts_pattern.clone()).with_column(field.to_owned())?;

                let mut query_builder = table.query().full_text_search(fts_query);

                // Apply date filter at database level so limit applies to date-filtered results
                if let Some(ref filter) = date_filter {
                    query_builder = query_builder.only_if(filter);
                }

                query_builder
                    .limit(fts_limit)
                    .execute()
                    .await?
                    .try_collect()
                    .await?
            };

            let fts_count: usize = batches.iter().map(|b| b.num_rows()).sum();
            tracing::info!(
                "FTS returned {} candidates with limit {} for field '{}'",
                fts_count,
                fts_limit,
                field
            );

            // Step 2: Post-filter with regex and build email objects
            emails.clear(); // Reset for this iteration

            for batch in batches {
                let num_rows = batch.num_rows();

                // Extract columns
                let git_commit_shas = batch
                    .column_by_name("git_commit_sha")
                    .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                    .as_string::<i32>();
                let from_addrs = batch
                    .column_by_name("from")
                    .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                    .as_string::<i32>();
                let dates = batch
                    .column_by_name("date")
                    .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                    .as_string::<i32>();
                let date_timestamps = batch
                    .column_by_name("date_timestamp")
                    .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
                let message_ids = batch
                    .column_by_name("message_id")
                    .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                    .as_string::<i32>();
                let in_reply_tos = batch
                    .column_by_name("in_reply_to")
                    .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                    .as_string::<i32>();
                let subjects = batch
                    .column_by_name("subject")
                    .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                    .as_string::<i32>();
                let references_list = batch
                    .column_by_name("references")
                    .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                    .as_string::<i32>();
                let recipients_list = batch
                    .column_by_name("recipients")
                    .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                    .as_string::<i32>();
                let bodies = batch
                    .column_by_name("body")
                    .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                    .as_string::<i32>();
                let symbols_list = batch
                    .column_by_name("symbols")
                    .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                    .as_string::<i32>();

                for i in 0..num_rows {
                    // Get the field value for regex matching
                    let field_value = match field {
                        "from" => from_addrs.value(i),
                        "subject" => subjects.value(i),
                        "body" => bodies.value(i),
                        "recipients" => recipients_list.value(i),
                        "symbols" => symbols_list.value(i),
                        _ => continue, // Skip if unknown field
                    };

                    // Apply regex filter (case-insensitive for better matching)
                    if !regex.is_match(field_value) {
                        continue;
                    }

                    // Check limit
                    if limit > 0 && emails.len() >= limit {
                        break;
                    }

                    // Parse JSON symbols array
                    let symbols_json = symbols_list.value(i);
                    let symbols: Vec<String> =
                        serde_json::from_str(symbols_json).unwrap_or_default();

                    let email = crate::types::LoreEmailInfo {
                        git_commit_sha: git_commit_shas.value(i).to_string(),
                        from: from_addrs.value(i).to_string(),
                        date: dates.value(i).to_string(),
                        date_timestamp: Self::get_date_timestamp(date_timestamps, dates, i),
                        message_id: message_ids.value(i).to_string(),
                        in_reply_to: if in_reply_tos.is_null(i) {
                            None
                        } else {
                            Some(in_reply_tos.value(i).to_string())
                        },
                        subject: subjects.value(i).to_string(),
                        references: if references_list.is_null(i) {
                            None
                        } else {
                            Some(references_list.value(i).to_string())
                        },
                        recipients: recipients_list.value(i).to_string(),
                        body: bodies.value(i).to_string(),
                        symbols,
                    };
                    emails.push(email);
                }

                if limit > 0 && emails.len() >= limit {
                    break;
                }
            }

            // Check stopping conditions
            if emails.len() >= target_limit {
                tracing::info!(
                    "Found {} results (target: {}), stopping",
                    emails.len(),
                    target_limit
                );
                break;
            }

            // Stop if count didn't increase (no more matches available)
            // Skip this check on the first iteration to allow at least one expansion
            if !first_iteration && emails.len() == previous_count {
                tracing::info!(
                    "Found {} results, count stopped increasing at FTS limit {}",
                    emails.len(),
                    fts_limit
                );
                break;
            }

            first_iteration = false;

            // Stop if we've searched a very large set
            if fts_limit >= 1000000 {
                tracing::info!(
                    "Found {} results, reached max FTS limit of {}",
                    emails.len(),
                    fts_limit
                );
                break;
            }

            tracing::info!(
                "Found {} results with FTS limit {}, trying larger limit",
                emails.len(),
                fts_limit
            );

            previous_count = emails.len();
            fts_limit *= 5; // Exponential expansion
        }

        Ok(emails)
    }

    /// Helper function to query lore emails by multiple fields and return intersection
    /// Uses regex alternation for OR within fields, intersection for AND across fields
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn query_lore_by_fields_intersection(
        &self,
        from_patterns: Option<&[String]>,
        subject_patterns: Option<&[String]>,
        body_patterns: Option<&[String]>,
        recipients_patterns: Option<&[String]>,
        search_limit: usize,
        since_date: Option<&str>,
        until_date: Option<&str>,
    ) -> Result<std::collections::HashSet<String>> {
        use std::collections::HashSet;

        let lore_table = self.connection.open_table("lore").execute().await?;
        let mut field_result_sets: Vec<HashSet<String>> = Vec::new();

        // Parse date filters into DateTime for temporal comparison
        // in query_field_impl (RFC 2822 string comparison is not
        // meaningful for date ordering).
        let since_dt = since_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));
        let until_dt = until_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc));

        // Helper function to query a field using FTS with regex and
        // date post-filtering.  Selects the "date" column alongside
        // the searched field so temporal filtering happens on the
        // already-fetched FTS candidates without extra lookups.
        async fn query_field_impl(
            lore_table: &lancedb::Table,
            field_name: String,
            pattern: String,
            search_limit: usize,
            since: Option<chrono::DateTime<chrono::Utc>>,
            until: Option<chrono::DateTime<chrono::Utc>>,
        ) -> Result<HashSet<String>> {
            // FTS uses simple tokenizer - normalize pattern by stripping special chars
            let fts_pattern = pattern
                .split(|c: char| !c.is_alphanumeric() && c != ' ')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");

            tracing::info!(
                "FTS query on field '{}': original='{}' normalized='{}'",
                field_name,
                pattern,
                fts_pattern
            );

            let effective_limit = if search_limit > 0 {
                search_limit
            } else {
                100000
            };

            // When the FTS pattern is empty (e.g. regex ".*" has no
            // alphanumeric tokens), skip FTS and fall back to a plain
            // table scan so the regex post-filter still runs.
            let results = if fts_pattern.is_empty() {
                tracing::info!(
                    "FTS pattern empty for field '{}', falling back to table scan",
                    field_name
                );
                lore_table
                    .query()
                    .select(lancedb::query::Select::Columns(vec![
                        "message_id".to_string(),
                        field_name.clone(),
                        "date".to_string(),
                    ]))
                    .limit(effective_limit)
                    .execute()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?
            } else {
                let fts_query =
                    FullTextSearchQuery::new(fts_pattern).with_column(field_name.clone())?;
                lore_table
                    .query()
                    .full_text_search(fts_query)
                    .select(lancedb::query::Select::Columns(vec![
                        "message_id".to_string(),
                        "_score".to_string(),
                        field_name.clone(),
                        "date".to_string(),
                    ]))
                    .limit(effective_limit)
                    .execute()
                    .await?
                    .try_collect::<Vec<_>>()
                    .await?
            };

            // Post-filter with regex and date range in memory
            let fts_result_count: usize = results.iter().map(|b| b.num_rows()).sum();
            tracing::info!(
                "FTS returned {} candidates for field '{}'",
                fts_result_count,
                field_name
            );

            let regex = regex::RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .build()?;
            let has_date_filter = since.is_some() || until.is_some();
            let mut message_ids = HashSet::new();
            let mut bad_dates: usize = 0;

            for batch in &results {
                let msg_array: &arrow::array::StringArray = super::get_column(batch, "message_id")?;
                let field_array: &arrow::array::StringArray =
                    super::get_column(batch, &field_name)?;
                let date_array: &arrow::array::StringArray = super::get_column(batch, "date")?;

                for i in 0..batch.num_rows() {
                    if !regex.is_match(field_array.value(i)) {
                        continue;
                    }
                    if has_date_filter {
                        if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(date_array.value(i)) {
                            let dt_utc = dt.with_timezone(&chrono::Utc);
                            if since.is_some_and(|s| dt_utc < s) {
                                continue;
                            }
                            if until.is_some_and(|u| dt_utc > u) {
                                continue;
                            }
                        } else {
                            bad_dates += 1;
                            continue;
                        }
                    }
                    message_ids.insert(msg_array.value(i).to_string());
                }
            }

            if bad_dates > 0 {
                tracing::warn!(
                    "Skipped {} candidates with unparseable dates for field '{}'",
                    bad_dates,
                    field_name
                );
            }

            tracing::info!(
                "Regex filter kept {} of {} FTS candidates",
                message_ids.len(),
                fts_result_count
            );

            Ok(message_ids)
        }

        // Query from field (OR across patterns, then push single set)
        if let Some(patterns) = from_patterns {
            if !patterns.is_empty() {
                let mut field_union = HashSet::new();
                for pattern in patterns {
                    let results = query_field_impl(
                        &lore_table,
                        "from".to_string(),
                        pattern.clone(),
                        search_limit,
                        since_dt,
                        until_dt,
                    )
                    .await?;
                    field_union.extend(results);
                }
                tracing::info!("lore from field returned {} results", field_union.len());
                field_result_sets.push(field_union);
            }
        }

        // Query subject field (OR across patterns)
        if let Some(patterns) = subject_patterns {
            if !patterns.is_empty() {
                let mut field_union = HashSet::new();
                for pattern in patterns {
                    let results = query_field_impl(
                        &lore_table,
                        "subject".to_string(),
                        pattern.clone(),
                        search_limit,
                        since_dt,
                        until_dt,
                    )
                    .await?;
                    field_union.extend(results);
                }
                tracing::info!("lore subject field returned {} results", field_union.len());
                field_result_sets.push(field_union);
            }
        }

        // Query body field (OR across patterns)
        if let Some(patterns) = body_patterns {
            if !patterns.is_empty() {
                let mut field_union = HashSet::new();
                for pattern in patterns {
                    let results = query_field_impl(
                        &lore_table,
                        "body".to_string(),
                        pattern.clone(),
                        search_limit,
                        since_dt,
                        until_dt,
                    )
                    .await?;
                    field_union.extend(results);
                }
                tracing::info!("lore body field returned {} results", field_union.len());
                field_result_sets.push(field_union);
            }
        }

        // Query recipients field (OR across patterns)
        if let Some(patterns) = recipients_patterns {
            if !patterns.is_empty() {
                let mut field_union = HashSet::new();
                for pattern in patterns {
                    let results = query_field_impl(
                        &lore_table,
                        "recipients".to_string(),
                        pattern.clone(),
                        search_limit,
                        since_dt,
                        until_dt,
                    )
                    .await?;
                    field_union.extend(results);
                }
                tracing::info!(
                    "lore recipients field returned {} results",
                    field_union.len()
                );
                field_result_sets.push(field_union);
            }
        }

        // Compute intersection efficiently
        if field_result_sets.is_empty() {
            return Ok(HashSet::new());
        }

        tracing::info!(
            "lore intersection: {} field result sets with sizes: {:?}",
            field_result_sets.len(),
            field_result_sets
                .iter()
                .map(|s| s.len())
                .collect::<Vec<_>>()
        );

        // Start with the smallest set for faster intersection
        field_result_sets.sort_by_key(|s| s.len());

        let mut intersection = field_result_sets[0].clone();
        for set in field_result_sets.iter().skip(1) {
            // Use retain for in-place intersection (faster than creating new set)
            intersection.retain(|id| set.contains(id));

            // Early exit if intersection becomes empty
            if intersection.is_empty() {
                break;
            }
        }

        Ok(intersection)
    }

    /// Search lore emails with multiple field-pattern conditions
    /// field_patterns: Vec of (field_name, pattern) tuples
    /// Patterns for the same field are combined with OR, different fields are combined with AND
    pub async fn search_lore_emails_multi_field(
        &self,
        field_patterns: Vec<(&str, &str)>,
        limit: usize,
        since_date: Option<&str>,
        until_date: Option<&str>,
    ) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use std::collections::HashMap;

        if field_patterns.is_empty() {
            return Ok(Vec::new());
        }

        // Group patterns by field
        let mut field_map: HashMap<&str, Vec<String>> = HashMap::new();
        for (field, pattern) in field_patterns {
            field_map
                .entry(field)
                .or_default()
                .push(pattern.to_string());
        }

        // Extract patterns for each field
        let from_patterns = field_map.get("from").map(|v| v.as_slice());
        let subject_patterns = field_map.get("subject").map(|v| v.as_slice());
        let body_patterns = field_map.get("body").map(|v| v.as_slice());
        let recipients_patterns = field_map.get("recipients").map(|v| v.as_slice());

        // Use helper to get intersection of message_ids.
        // Date range is pushed into FTS queries so the candidate set
        // is already bounded before intersection and fetching.
        let intersection = self
            .query_lore_by_fields_intersection(
                from_patterns,
                subject_patterns,
                body_patterns,
                recipients_patterns,
                0, // No limit for individual queries
                since_date,
                until_date,
            )
            .await?;

        tracing::info!("Final intersection has {} message_ids", intersection.len());

        if intersection.is_empty() {
            return Ok(Vec::new());
        }

        // Fetch full email records for the intersection.
        // Date filtering was already pushed into the per-field FTS
        // queries, so the intersection is already date-bounded.
        let count_limit = if limit > 0 { limit } else { intersection.len() };
        let ids: Vec<&String> = intersection.iter().take(count_limit).collect();
        let final_emails = self.fetch_lore_emails_by_message_ids(&ids).await?;

        tracing::info!(
            "Fetched {} email records from {} message_ids",
            final_emails.len(),
            intersection.len()
        );

        Ok(final_emails)
    }

    /// Fetch lore emails by message IDs in batches.
    ///
    /// Builds `message_id IN (...)` predicates in chunks to avoid
    /// per-ID round-trips while keeping predicate size bounded.
    async fn fetch_lore_emails_by_message_ids(
        &self,
        message_ids: &[&String],
    ) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;

        if message_ids.is_empty() {
            return Ok(Vec::new());
        }

        let table = self.connection.open_table("lore").execute().await?;
        let mut emails = Vec::with_capacity(message_ids.len());

        for chunk in message_ids.chunks(500) {
            let placeholders: Vec<String> = chunk
                .iter()
                .map(|id| {
                    let escaped = id.replace('\'', "''");
                    format!("'{}'", escaped)
                })
                .collect();
            let predicate = format!("message_id IN ({})", placeholders.join(", "));

            let results = table
                .query()
                .only_if(&predicate)
                .limit(chunk.len())
                .execute()
                .await?
                .try_collect::<Vec<_>>()
                .await?;

            for batch in &results {
                let git_commit_shas = batch
                    .column_by_name("git_commit_sha")
                    .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                    .as_string::<i32>();
                let from_addrs = batch
                    .column_by_name("from")
                    .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                    .as_string::<i32>();
                let dates = batch
                    .column_by_name("date")
                    .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                    .as_string::<i32>();
                let date_timestamps = batch
                    .column_by_name("date_timestamp")
                    .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
                let msg_ids = batch
                    .column_by_name("message_id")
                    .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                    .as_string::<i32>();
                let in_reply_tos = batch
                    .column_by_name("in_reply_to")
                    .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                    .as_string::<i32>();
                let subjects = batch
                    .column_by_name("subject")
                    .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                    .as_string::<i32>();
                let references_list = batch
                    .column_by_name("references")
                    .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                    .as_string::<i32>();
                let recipients_list = batch
                    .column_by_name("recipients")
                    .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                    .as_string::<i32>();
                let bodies = batch
                    .column_by_name("body")
                    .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                    .as_string::<i32>();
                let symbols_list = batch
                    .column_by_name("symbols")
                    .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                    .as_string::<i32>();

                for i in 0..batch.num_rows() {
                    let symbols_json = symbols_list.value(i);
                    let symbols: Vec<String> =
                        serde_json::from_str(symbols_json).unwrap_or_default();

                    emails.push(crate::types::LoreEmailInfo {
                        git_commit_sha: git_commit_shas.value(i).to_string(),
                        from: from_addrs.value(i).to_string(),
                        date: dates.value(i).to_string(),
                        date_timestamp: Self::get_date_timestamp(date_timestamps, dates, i),
                        message_id: msg_ids.value(i).to_string(),
                        in_reply_to: if in_reply_tos.is_null(i) {
                            None
                        } else {
                            Some(in_reply_tos.value(i).to_string())
                        },
                        subject: subjects.value(i).to_string(),
                        references: if references_list.is_null(i) {
                            None
                        } else {
                            Some(references_list.value(i).to_string())
                        },
                        recipients: recipients_list.value(i).to_string(),
                        body: bodies.value(i).to_string(),
                        symbols,
                    });
                }
            }
        }

        Ok(emails)
    }

    /// Get a lore email by exact message_id match
    pub async fn get_lore_email_by_message_id(
        &self,
        message_id: &str,
    ) -> Result<Option<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;

        // Add < > around message_id if not already present
        let normalized_message_id = if message_id.starts_with('<') && message_id.ends_with('>') {
            message_id.to_string()
        } else {
            format!("<{}>", message_id)
        };

        // Escape SQL string literal
        let escaped_message_id = normalized_message_id.replace("'", "''");
        let filter = format!("message_id = '{}'", escaped_message_id);

        let table = self.connection.open_table("lore").execute().await?;
        let stream = table.query().only_if(&filter).limit(1).execute().await?;
        let batches: Vec<_> = stream.try_collect().await?;

        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }

            // Extract columns
            let git_commit_shas = batch
                .column_by_name("git_commit_sha")
                .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                .as_string::<i32>();
            let from_addrs = batch
                .column_by_name("from")
                .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                .as_string::<i32>();
            let dates = batch
                .column_by_name("date")
                .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                .as_string::<i32>();
            let date_timestamps = batch
                .column_by_name("date_timestamp")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
            let message_ids = batch
                .column_by_name("message_id")
                .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                .as_string::<i32>();
            let in_reply_tos = batch
                .column_by_name("in_reply_to")
                .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                .as_string::<i32>();
            let subjects = batch
                .column_by_name("subject")
                .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                .as_string::<i32>();
            let references_list = batch
                .column_by_name("references")
                .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                .as_string::<i32>();
            let recipients_list = batch
                .column_by_name("recipients")
                .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                .as_string::<i32>();
            let bodies = batch
                .column_by_name("body")
                .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                .as_string::<i32>();
            let symbols_list = batch
                .column_by_name("symbols")
                .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                .as_string::<i32>();

            // Parse JSON symbols array
            let symbols_json = symbols_list.value(0);
            let symbols: Vec<String> = serde_json::from_str(symbols_json).unwrap_or_default();

            // Return the first (and only) result
            let email = crate::types::LoreEmailInfo {
                git_commit_sha: git_commit_shas.value(0).to_string(),
                from: from_addrs.value(0).to_string(),
                date: dates.value(0).to_string(),
                date_timestamp: Self::get_date_timestamp(date_timestamps, dates, 0),
                message_id: message_ids.value(0).to_string(),
                in_reply_to: if in_reply_tos.is_null(0) {
                    None
                } else {
                    Some(in_reply_tos.value(0).to_string())
                },
                subject: subjects.value(0).to_string(),
                references: if references_list.is_null(0) {
                    None
                } else {
                    Some(references_list.value(0).to_string())
                },
                recipients: recipients_list.value(0).to_string(),
                body: bodies.value(0).to_string(),
                symbols,
            };

            return Ok(Some(email));
        }

        Ok(None)
    }

    /// Get all emails that reference a message-id (in in_reply_to or references fields)
    pub async fn get_lore_emails_referencing(
        &self,
        message_id: &str,
    ) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;
        use std::collections::HashSet;

        // Escape SQL string literal for pattern matching
        let escaped_message_id = message_id.replace("\\", "\\\\").replace("'", "''");

        let table = self.connection.open_table("lore").execute().await?;

        // Query 1: Find emails where in_reply_to matches
        let filter1 = format!("in_reply_to = '{}'", escaped_message_id);
        let stream1 = table.query().only_if(&filter1).execute().await?;
        let batches1: Vec<_> = stream1.try_collect().await?;

        // Query 2: Find emails where references contains the message-id
        let filter2 = format!("regexp_like(`references`, '{}')", escaped_message_id);
        let stream2 = table.query().only_if(&filter2).execute().await?;
        let batches2: Vec<_> = stream2.try_collect().await?;

        // Combine batches from both queries
        let mut batches = batches1;
        batches.extend(batches2);

        let mut emails = Vec::new();
        let mut seen_message_ids = HashSet::new();

        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }

            // Extract columns
            let git_commit_shas = batch
                .column_by_name("git_commit_sha")
                .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                .as_string::<i32>();
            let from_addrs = batch
                .column_by_name("from")
                .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                .as_string::<i32>();
            let dates = batch
                .column_by_name("date")
                .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                .as_string::<i32>();
            let date_timestamps = batch
                .column_by_name("date_timestamp")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
            let message_ids = batch
                .column_by_name("message_id")
                .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                .as_string::<i32>();
            let in_reply_tos = batch
                .column_by_name("in_reply_to")
                .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                .as_string::<i32>();
            let subjects = batch
                .column_by_name("subject")
                .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                .as_string::<i32>();
            let references_list = batch
                .column_by_name("references")
                .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                .as_string::<i32>();
            let recipients_list = batch
                .column_by_name("recipients")
                .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                .as_string::<i32>();
            let bodies = batch
                .column_by_name("body")
                .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                .as_string::<i32>();
            let symbols_list = batch
                .column_by_name("symbols")
                .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                .as_string::<i32>();

            for i in 0..batch.num_rows() {
                let message_id = message_ids.value(i).to_string();

                // Skip if we've already seen this message_id (deduplication)
                if !seen_message_ids.insert(message_id.clone()) {
                    continue;
                }

                // Parse JSON symbols array
                let symbols_json = symbols_list.value(i);
                let symbols: Vec<String> = serde_json::from_str(symbols_json).unwrap_or_default();

                let email = crate::types::LoreEmailInfo {
                    git_commit_sha: git_commit_shas.value(i).to_string(),
                    from: from_addrs.value(i).to_string(),
                    date: dates.value(i).to_string(),
                    date_timestamp: Self::get_date_timestamp(date_timestamps, dates, i),
                    message_id,
                    in_reply_to: if in_reply_tos.is_null(i) {
                        None
                    } else {
                        Some(in_reply_tos.value(i).to_string())
                    },
                    subject: subjects.value(i).to_string(),
                    references: if references_list.is_null(i) {
                        None
                    } else {
                        Some(references_list.value(i).to_string())
                    },
                    recipients: recipients_list.value(i).to_string(),
                    body: bodies.value(i).to_string(),
                    symbols,
                };
                emails.push(email);
            }
        }

        Ok(emails)
    }

    /// Search lore emails by exact subject match (case-sensitive substring match)
    pub async fn search_lore_emails_by_subject(
        &self,
        subject: &str,
        limit: usize,
        since_date: Option<&str>,
        until_date: Option<&str>,
    ) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;

        // Parse filter dates to Unix timestamps for database-level filtering
        let since_timestamp = since_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.timestamp());
        let until_timestamp = until_date
            .and_then(|d| chrono::DateTime::parse_from_rfc2822(d).ok())
            .map(|dt| dt.timestamp());

        // Escape SQL string literal
        let escaped_subject = subject.replace("'", "''");

        let table = self.connection.open_table("lore").execute().await?;
        let has_date_timestamp = table
            .schema()
            .await
            .map(|s| s.field_with_name("date_timestamp").is_ok())
            .unwrap_or(false);

        // Build WHERE clause with subject filter and optional date filters
        let mut where_parts = vec![format!("subject LIKE '%{}%'", escaped_subject)];

        if has_date_timestamp {
            if let Some(since) = since_timestamp {
                where_parts.push(format!("date_timestamp >= {}", since));
            }
            if let Some(until) = until_timestamp {
                where_parts.push(format!("date_timestamp <= {}", until));
            }
        }

        let where_clause = where_parts.join(" AND ");
        let mut query = table.query().only_if(&where_clause);

        if limit > 0 {
            query = query.limit(limit);
        }

        let stream = query.execute().await?;
        let batches: Vec<_> = stream.try_collect().await?;

        let mut emails = Vec::new();

        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }

            // Extract columns
            let git_commit_shas = batch
                .column_by_name("git_commit_sha")
                .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                .as_string::<i32>();
            let from_addrs = batch
                .column_by_name("from")
                .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                .as_string::<i32>();
            let dates = batch
                .column_by_name("date")
                .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                .as_string::<i32>();
            let date_timestamps = batch
                .column_by_name("date_timestamp")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
            let message_ids = batch
                .column_by_name("message_id")
                .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                .as_string::<i32>();
            let in_reply_tos = batch
                .column_by_name("in_reply_to")
                .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                .as_string::<i32>();
            let subjects = batch
                .column_by_name("subject")
                .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                .as_string::<i32>();
            let references_list = batch
                .column_by_name("references")
                .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                .as_string::<i32>();
            let recipients_list = batch
                .column_by_name("recipients")
                .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                .as_string::<i32>();
            let bodies = batch
                .column_by_name("body")
                .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                .as_string::<i32>();
            let symbols_list = batch
                .column_by_name("symbols")
                .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                .as_string::<i32>();

            for i in 0..batch.num_rows() {
                // Parse JSON symbols array
                let symbols_json = symbols_list.value(i);
                let symbols: Vec<String> = serde_json::from_str(symbols_json).unwrap_or_default();

                let email = crate::types::LoreEmailInfo {
                    git_commit_sha: git_commit_shas.value(i).to_string(),
                    from: from_addrs.value(i).to_string(),
                    date: dates.value(i).to_string(),
                    date_timestamp: Self::get_date_timestamp(date_timestamps, dates, i),
                    message_id: message_ids.value(i).to_string(),
                    in_reply_to: if in_reply_tos.is_null(i) {
                        None
                    } else {
                        Some(in_reply_tos.value(i).to_string())
                    },
                    subject: subjects.value(i).to_string(),
                    references: if references_list.is_null(i) {
                        None
                    } else {
                        Some(references_list.value(i).to_string())
                    },
                    recipients: recipients_list.value(i).to_string(),
                    body: bodies.value(i).to_string(),
                    symbols,
                };

                emails.push(email);
            }
        }

        Ok(emails)
    }

    /// Get all lore emails for a specific git commit SHA
    pub async fn get_lore_emails_by_commit(
        &self,
        git_sha: &str,
    ) -> Result<Vec<crate::types::LoreEmailInfo>> {
        use arrow::array::AsArray;
        use futures::TryStreamExt;

        // Escape SQL string literal
        let escaped_sha = git_sha.replace("'", "''");
        let filter = format!("git_commit_sha = '{}'", escaped_sha);

        let table = self.connection.open_table("lore").execute().await?;
        let stream = table.query().only_if(&filter).execute().await?;
        let batches: Vec<_> = stream.try_collect().await?;

        let mut emails = Vec::new();

        for batch in batches {
            if batch.num_rows() == 0 {
                continue;
            }

            // Extract columns
            let git_commit_shas = batch
                .column_by_name("git_commit_sha")
                .ok_or_else(|| anyhow::anyhow!("Missing git_commit_sha column"))?
                .as_string::<i32>();
            let from_addrs = batch
                .column_by_name("from")
                .ok_or_else(|| anyhow::anyhow!("Missing from column"))?
                .as_string::<i32>();
            let dates = batch
                .column_by_name("date")
                .ok_or_else(|| anyhow::anyhow!("Missing date column"))?
                .as_string::<i32>();
            let date_timestamps = batch
                .column_by_name("date_timestamp")
                .and_then(|c| c.as_any().downcast_ref::<arrow::array::Int64Array>());
            let message_ids = batch
                .column_by_name("message_id")
                .ok_or_else(|| anyhow::anyhow!("Missing message_id column"))?
                .as_string::<i32>();
            let in_reply_tos = batch
                .column_by_name("in_reply_to")
                .ok_or_else(|| anyhow::anyhow!("Missing in_reply_to column"))?
                .as_string::<i32>();
            let subjects = batch
                .column_by_name("subject")
                .ok_or_else(|| anyhow::anyhow!("Missing subject column"))?
                .as_string::<i32>();
            let references_list = batch
                .column_by_name("references")
                .ok_or_else(|| anyhow::anyhow!("Missing references column"))?
                .as_string::<i32>();
            let recipients_list = batch
                .column_by_name("recipients")
                .ok_or_else(|| anyhow::anyhow!("Missing recipients column"))?
                .as_string::<i32>();
            let bodies = batch
                .column_by_name("body")
                .ok_or_else(|| anyhow::anyhow!("Missing body column"))?
                .as_string::<i32>();
            let symbols_list = batch
                .column_by_name("symbols")
                .ok_or_else(|| anyhow::anyhow!("Missing symbols column"))?
                .as_string::<i32>();

            for i in 0..batch.num_rows() {
                // Parse JSON symbols array
                let symbols_json = symbols_list.value(i);
                let symbols: Vec<String> = serde_json::from_str(symbols_json).unwrap_or_default();

                let email = crate::types::LoreEmailInfo {
                    git_commit_sha: git_commit_shas.value(i).to_string(),
                    from: from_addrs.value(i).to_string(),
                    date: dates.value(i).to_string(),
                    date_timestamp: Self::get_date_timestamp(date_timestamps, dates, i),
                    message_id: message_ids.value(i).to_string(),
                    in_reply_to: if in_reply_tos.is_null(i) {
                        None
                    } else {
                        Some(in_reply_tos.value(i).to_string())
                    },
                    subject: subjects.value(i).to_string(),
                    references: if references_list.is_null(i) {
                        None
                    } else {
                        Some(references_list.value(i).to_string())
                    },
                    recipients: recipients_list.value(i).to_string(),
                    body: bodies.value(i).to_string(),
                    symbols,
                };
                emails.push(email);
            }
        }

        Ok(emails)
    }

    /// Get a single git commit by SHA
    pub async fn get_git_commit_by_sha(
        &self,
        git_sha: &str,
    ) -> Result<Option<crate::types::GitCommitInfo>> {
        use futures::TryStreamExt;

        let table = self.connection.open_table("git_commits").execute().await?;

        // Escape SQL string literal
        let escaped_sha = git_sha.replace("'", "''");
        let filter = format!("git_sha = '{}'", escaped_sha);

        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            let git_sha_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let parent_sha_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let author_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let subject_array = batch
                .column(3)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let message_array = batch
                .column(4)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let tags_array = batch
                .column(5)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let diff_array = batch
                .column(6)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let symbols_array = batch
                .column(7)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let files_array = batch
                .column(8)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();

            if batch.num_rows() > 0 {
                let git_sha = git_sha_array.value(0).to_string();
                let parent_sha: Vec<String> = serde_json::from_str(parent_sha_array.value(0))?;
                let author = author_array.value(0).to_string();
                let subject = subject_array.value(0).to_string();
                let message = message_array.value(0).to_string();
                let tags = serde_json::from_str(tags_array.value(0))?;
                let diff = diff_array.value(0).to_string();
                let symbols: Vec<String> = serde_json::from_str(symbols_array.value(0))?;
                let files: Vec<String> = serde_json::from_str(files_array.value(0))?;

                return Ok(Some(crate::types::GitCommitInfo {
                    git_sha,
                    parent_sha,
                    author,
                    subject,
                    message,
                    tags,
                    diff,
                    symbols,
                    files,
                }));
            }
        }

        Ok(None)
    }

    /// Get all git commits from the database
    pub async fn get_all_git_commits(&self) -> Result<Vec<crate::types::GitCommitInfo>> {
        use futures::TryStreamExt;

        let table = self.connection.open_table("git_commits").execute().await?;
        let results = table
            .query()
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut commits = Vec::new();

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            let git_sha_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let parent_sha_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let author_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let subject_array = batch
                .column(3)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let message_array = batch
                .column(4)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let tags_array = batch
                .column(5)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let diff_array = batch
                .column(6)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let symbols_array = batch
                .column(7)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let files_array = batch
                .column(8)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let git_sha = git_sha_array.value(i).to_string();
                let parent_sha: Vec<String> = serde_json::from_str(parent_sha_array.value(i))?;
                let author = author_array.value(i).to_string();
                let subject = subject_array.value(i).to_string();
                let message = message_array.value(i).to_string();
                let tags = serde_json::from_str(tags_array.value(i))?;
                let diff = diff_array.value(i).to_string();
                let symbols: Vec<String> = serde_json::from_str(symbols_array.value(i))?;
                let files: Vec<String> = serde_json::from_str(files_array.value(i))?;

                commits.push(crate::types::GitCommitInfo {
                    git_sha,
                    parent_sha,
                    author,
                    subject,
                    message,
                    tags,
                    diff,
                    symbols,
                    files,
                });
            }
        }

        Ok(commits)
    }

    /// Query commits by a chunk of SHAs with post-processing filters
    /// Regex and symbol filtering are done in Rust code after fetching SHA-filtered results
    /// This avoids complex SQL operations while still reducing the dataset via SHA filtering
    pub async fn query_commits_chunk_filtered(
        &self,
        sha_chunk: &[String],
        regex_patterns: &[String],
        symbol_patterns: &[String],
    ) -> Result<Vec<crate::types::GitCommitInfo>> {
        use futures::TryStreamExt;

        if sha_chunk.is_empty() {
            return Ok(Vec::new());
        }

        let table = self.connection.open_table("git_commits").execute().await?;

        // Build SQL WHERE clause with only SHA IN clause
        // Regex and symbol filtering will be done in Rust post-processing
        let escaped_shas: Vec<String> = sha_chunk
            .iter()
            .map(|sha| format!("'{}'", sha.replace("'", "''")))
            .collect();
        let filter = format!("git_sha IN ({})", escaped_shas.join(", "));

        let results = table
            .query()
            .only_if(filter)
            .execute()
            .await?
            .try_collect::<Vec<_>>()
            .await?;

        let mut commits = Vec::new();

        for batch in results {
            if batch.num_rows() == 0 {
                continue;
            }

            let git_sha_array = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let parent_sha_array = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let author_array = batch
                .column(2)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let subject_array = batch
                .column(3)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let message_array = batch
                .column(4)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let tags_array = batch
                .column(5)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let diff_array = batch
                .column(6)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let symbols_array = batch
                .column(7)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let files_array = batch
                .column(8)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();

            for i in 0..batch.num_rows() {
                let git_sha = git_sha_array.value(i).to_string();
                let parent_sha: Vec<String> = serde_json::from_str(parent_sha_array.value(i))?;
                let author = author_array.value(i).to_string();
                let subject = subject_array.value(i).to_string();
                let message = message_array.value(i).to_string();
                let tags = serde_json::from_str(tags_array.value(i))?;
                let diff = diff_array.value(i).to_string();
                let symbols: Vec<String> = serde_json::from_str(symbols_array.value(i))?;
                let files: Vec<String> = serde_json::from_str(files_array.value(i))?;

                commits.push(crate::types::GitCommitInfo {
                    git_sha,
                    parent_sha,
                    author,
                    subject,
                    message,
                    tags,
                    diff,
                    symbols,
                    files,
                });
            }
        }

        // Apply regex filtering in Rust code (post-processing)
        if !regex_patterns.is_empty() {
            // Compile regex patterns
            let mut regexes = Vec::new();
            for pattern in regex_patterns {
                match regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                {
                    Ok(re) => regexes.push(re),
                    Err(e) => {
                        tracing::warn!("Invalid regex pattern '{}': {}", pattern, e);
                        continue;
                    }
                }
            }

            // Filter commits: ALL regex patterns must match (in message OR diff)
            commits.retain(|commit| {
                regexes
                    .iter()
                    .all(|re| re.is_match(&commit.message) || re.is_match(&commit.diff))
            });
        }

        // Apply symbol filtering in Rust code (post-processing)
        if !symbol_patterns.is_empty() {
            // Compile symbol regex patterns
            let mut symbol_regexes = Vec::new();
            for pattern in symbol_patterns {
                match regex::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                {
                    Ok(re) => symbol_regexes.push(re),
                    Err(e) => {
                        tracing::warn!("Invalid symbol regex pattern '{}': {}", pattern, e);
                        continue;
                    }
                }
            }

            // Filter commits: ALL symbol patterns must match
            commits.retain(|commit| {
                symbol_regexes
                    .iter()
                    .all(|re| commit.symbols.iter().any(|symbol| re.is_match(symbol)))
            });
        }

        Ok(commits)
    }

    /// Return the set of commit SHAs already recorded in the
    /// lore_indexed_commits table. The table contains only short
    /// SHA strings, so reading it entirely into memory is cheap.
    pub async fn get_indexed_lore_commits(&self) -> Result<HashSet<String>> {
        let table = match self
            .connection
            .open_table("lore_indexed_commits")
            .execute()
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Failed to open lore_indexed_commits table: {}", e);
                return Ok(HashSet::new());
            }
        };

        let stream = table
            .query()
            .select(lancedb::query::Select::Columns(vec![
                "git_commit_sha".to_string()
            ]))
            .execute()
            .await?;

        let batches: Vec<_> = stream.try_collect().await?;
        let mut existing = HashSet::new();
        for batch in batches {
            if let Some(column) = batch.column_by_name("git_commit_sha") {
                if let Some(string_array) = column.as_any().downcast_ref::<StringArray>() {
                    existing.reserve(string_array.len());
                    for i in 0..string_array.len() {
                        existing.insert(string_array.value(i).to_string());
                    }
                }
            }
        }

        Ok(existing)
    }

    /// Record git commit SHAs that have been processed for lore indexing.
    pub async fn insert_lore_indexed_commits(&self, commit_shas: &[String]) -> Result<()> {
        use arrow::array::{ArrayRef, StringArray};
        use arrow::datatypes::{DataType, Field, Schema};
        use arrow::record_batch::RecordBatch;
        use std::sync::Arc;

        if commit_shas.is_empty() {
            return Ok(());
        }

        let schema = Arc::new(Schema::new(vec![Field::new(
            "git_commit_sha",
            DataType::Utf8,
            false,
        )]));

        let columns: Vec<ArrayRef> = vec![Arc::new(StringArray::from(commit_shas.to_vec()))];

        let batch = RecordBatch::try_new(schema.clone(), columns)?;
        let batches = vec![Ok(batch)];
        let batch_iterator =
            arrow::record_batch::RecordBatchIterator::new(batches.into_iter(), schema);

        let table = self
            .connection
            .open_table("lore_indexed_commits")
            .execute()
            .await?;
        let mut merge_insert = table.merge_insert(&["git_commit_sha"]);
        merge_insert
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        merge_insert.execute(Box::new(batch_iterator)).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{ArrayRef, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use std::sync::Arc;

    fn git(repo: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .env("GIT_AUTHOR_NAME", "Semcode Test")
            .env("GIT_AUTHOR_EMAIL", "semcode@example.com")
            .env("GIT_COMMITTER_NAME", "Semcode Test")
            .env("GIT_COMMITTER_EMAIL", "semcode@example.com")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[tokio::test]
    async fn new_tables_use_lance_format_2_2() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();

        let schema = Arc::new(Schema::new(vec![Field::new(
            "value",
            DataType::Utf8,
            false,
        )]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(StringArray::from(vec!["test"])) as ArrayRef],
        )
        .unwrap();
        let table = db
            .connection
            .create_table("storage_version_test", vec![batch])
            .execute()
            .await
            .unwrap();
        let dataset = table.dataset().unwrap().get().await.unwrap();

        assert_eq!(dataset.manifest().data_storage_format.version, "2.2");
    }

    fn test_function(name: &str, file_path: &str, git_file_hash: &str) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            file_path: file_path.to_string(),
            git_file_hash: git_file_hash.to_string(),
            line_start: 1,
            line_end: 3,
            return_type: "int".to_string(),
            parameters: Vec::new(),
            body: format!("int {name}(void) {{ return 0; }}"),
            calls: Some(vec!["target".to_string()]),
            types: None,
        }
    }

    #[tokio::test]
    async fn indirect_callers_come_from_the_revision_being_queried() {
        use crate::types::{DispatchKind, DispatchSite, Registration, RegistrationKind};

        let repo_dir = tempfile::tempdir().unwrap();
        let repo_path = repo_dir.path();
        git(repo_path, &["init", "-q"]);
        std::fs::write(repo_path.join("driver.c"), "/* ops table */\n").unwrap();
        std::fs::write(repo_path.join("vfs.c"), "/* caller */\n").unwrap();
        git(repo_path, &["add", "driver.c", "vfs.c"]);
        git(repo_path, &["commit", "-q", "-m", "initial"]);

        let git_sha = crate::git::get_git_sha(repo_path).unwrap().unwrap();
        let driver_hash = crate::git::get_git_file_hash_at_commit(repo_path, &git_sha, "driver.c")
            .unwrap()
            .unwrap();
        let vfs_hash = crate::git::get_git_file_hash_at_commit(repo_path, &git_sha, "vfs.c")
            .unwrap()
            .unwrap();

        let db_path = repo_path.join(".semcode.db");
        let db = DatabaseManager::new(
            db_path.to_str().unwrap(),
            repo_path.to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();

        db.insert_functions(vec![test_function("my_read", "driver.c", &driver_hash)])
            .await
            .unwrap();

        db.insert_registrations(vec![Registration {
            container_type: "file_operations".to_string(),
            member: "read".to_string(),
            target: "my_read".to_string(),
            file_path: "driver.c".to_string(),
            git_file_hash: driver_hash.clone(),
            byte_start: 0,
            line: 1,
            enclosing_function: String::new(),
            kind: RegistrationKind::DesignatedInit,
            container_base_type: None,
            container_field: None,
        }])
        .await
        .unwrap();

        let site = |file: &str, hash: &str, receiver_type: Option<&str>| DispatchSite {
            caller_name: "vfs_read".to_string(),
            file_path: file.to_string(),
            git_file_hash: hash.to_string(),
            byte_start: 0,
            line: 1,
            member: "read".to_string(),
            receiver_expr: Some("f->f_op".to_string()),
            receiver_type: receiver_type.map(|t| t.to_string()),
            receiver_base_type: None,
            receiver_field: None,
            kind: DispatchKind::MemberArrow,
            target: None,
        };

        db.insert_dispatch_sites(vec![
            site("vfs.c", &vfs_hash, Some("file_operations")),
            // Same site recorded when vfs.c had different content: it is not
            // part of this revision and must not answer.
            site("vfs.c", "stale-hash", Some("file_operations")),
        ])
        .await
        .unwrap();

        let found = db.find_indirect_callers("my_read", &git_sha).await.unwrap();

        assert_eq!(found.len(), 1, "stale rows answered too: {found:?}");
        assert_eq!(found[0].caller_name, "vfs_read");
        assert!(
            found[0].evidence.is_type_matched(),
            "receiver type matched the registration but was not reported as such: {:?}",
            found[0].evidence
        );
    }

    #[tokio::test]
    async fn registrations_are_looked_up_by_slot_and_by_target() {
        use crate::types::{Registration, RegistrationKind};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();

        let registration = |member: &str, target: &str, byte_start: u64| Registration {
            container_type: "file_operations".to_string(),
            member: member.to_string(),
            target: target.to_string(),
            file_path: "a.c".to_string(),
            git_file_hash: "hash-a".to_string(),
            byte_start,
            line: 10,
            enclosing_function: String::new(),
            kind: RegistrationKind::DesignatedInit,
            container_base_type: None,
            container_field: None,
        };

        let rows = vec![
            registration("read", "my_read", 100),
            registration("write", "my_write", 140),
        ];
        db.insert_registrations(rows.clone()).await.unwrap();
        // Reindexing the same file must not duplicate them.
        db.insert_registrations(rows).await.unwrap();

        let slot = db
            .find_registrations_for_slot("file_operations", "read")
            .await
            .unwrap();
        assert_eq!(
            slot.len(),
            1,
            "duplicate rows for one initializer: {slot:?}"
        );
        assert_eq!(slot[0].target, "my_read");

        let by_target = db.find_registrations_of("my_write").await.unwrap();
        assert_eq!(by_target.len(), 1);
        assert_eq!(by_target[0].member, "write");

        // A member of a different type must not answer for this one.
        let other = db
            .find_registrations_for_slot("other_ops", "read")
            .await
            .unwrap();
        assert!(other.is_empty(), "slot lookup ignored the type: {other:?}");
    }

    #[tokio::test]
    async fn reindexing_unchanged_content_keeps_one_row_per_dispatch_site() {
        use crate::types::{DispatchKind, DispatchSite};

        let temp_dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();

        let site = DispatchSite {
            caller_name: "go".to_string(),
            file_path: "a.c".to_string(),
            git_file_hash: "hash-a".to_string(),
            byte_start: 120,
            line: 7,
            member: "read".to_string(),
            receiver_expr: Some("ops".to_string()),
            receiver_type: None,
            receiver_base_type: None,
            receiver_field: None,
            kind: DispatchKind::MemberArrow,
            target: None,
        };

        db.insert_dispatch_sites(vec![site.clone()]).await.unwrap();
        db.insert_dispatch_sites(vec![site.clone()]).await.unwrap();

        let stored = db.find_dispatch_sites_by_member("read").await.unwrap();
        assert_eq!(
            stored,
            vec![site],
            "re-inserting the same site duplicated it"
        );
    }

    #[tokio::test]
    async fn bulk_lookup_returns_every_definition_of_a_name() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db = DatabaseManager::new(
            temp_dir.path().to_str().unwrap(),
            temp_dir.path().to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();

        // Two static functions of the same name in different files, as the
        // kernel has by the thousand.
        db.insert_functions(vec![
            test_function("dup_caller", "a.c", "hash-a"),
            test_function("dup_caller", "b.c", "hash-b"),
        ])
        .await
        .unwrap();

        let map = db
            .get_functions_by_names(&["dup_caller".to_string()])
            .await
            .unwrap();

        let candidates = map
            .get("dup_caller")
            .expect("name missing from bulk lookup");
        let mut files: Vec<&str> = candidates.iter().map(|f| f.file_path.as_str()).collect();
        files.sort_unstable();

        assert_eq!(files, vec!["a.c", "b.c"]);
    }

    #[tokio::test]
    async fn git_aware_type_lookup_returns_all_definitions() {
        let repo_dir = tempfile::tempdir().unwrap();
        let repo_path = repo_dir.path();
        git(repo_path, &["init", "-q"]);
        std::fs::write(repo_path.join("a.h"), "struct duplicate { int a; };\n").unwrap();
        std::fs::write(repo_path.join("b.h"), "struct duplicate { long b; };\n").unwrap();
        git(repo_path, &["add", "a.h", "b.h"]);
        git(repo_path, &["commit", "-q", "-m", "initial"]);

        let git_sha = crate::git::get_git_sha(repo_path).unwrap().unwrap();
        let a_hash = crate::git::get_git_file_hash_at_commit(repo_path, &git_sha, "a.h")
            .unwrap()
            .unwrap();
        let b_hash = crate::git::get_git_file_hash_at_commit(repo_path, &git_sha, "b.h")
            .unwrap()
            .unwrap();
        let db_path = repo_path.join(".semcode.db");
        let db = DatabaseManager::new(
            db_path.to_str().unwrap(),
            repo_path.to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();
        db.insert_types(vec![
            TypeInfo {
                name: "duplicate".to_string(),
                file_path: "a.h".to_string(),
                git_file_hash: a_hash.clone(),
                line_start: 1,
                kind: "struct".to_string(),
                size: None,
                members: Vec::new(),
                definition: "struct duplicate { int a; };".to_string(),
                types: None,
            },
            TypeInfo {
                name: "duplicate".to_string(),
                file_path: "b.h".to_string(),
                git_file_hash: b_hash.clone(),
                line_start: 1,
                kind: "struct".to_string(),
                size: None,
                members: Vec::new(),
                definition: "struct duplicate { long b; };".to_string(),
                types: None,
            },
            TypeInfo {
                name: "container".to_string(),
                file_path: "b.h".to_string(),
                git_file_hash: b_hash.clone(),
                line_start: 2,
                kind: "struct".to_string(),
                size: None,
                members: Vec::new(),
                definition: "struct container { struct duplicate *value; };".to_string(),
                types: Some(vec!["duplicate".to_string()]),
            },
        ])
        .await
        .unwrap();
        db.insert_functions(vec![
            FunctionInfo {
                name: "caller_one".to_string(),
                file_path: "a.h".to_string(),
                git_file_hash: a_hash,
                line_start: 2,
                line_end: 2,
                return_type: "void".to_string(),
                parameters: Vec::new(),
                body: "void caller_one(void) { target(); }".to_string(),
                calls: Some(vec!["target".to_string()]),
                types: Some(vec!["duplicate".to_string()]),
            },
            FunctionInfo {
                name: "caller_two".to_string(),
                file_path: "b.h".to_string(),
                git_file_hash: b_hash,
                line_start: 3,
                line_end: 3,
                return_type: "void".to_string(),
                parameters: Vec::new(),
                body: "void caller_two(void) { target(); }".to_string(),
                calls: Some(vec!["target".to_string()]),
                types: Some(vec!["duplicate".to_string()]),
            },
        ])
        .await
        .unwrap();

        let definitions = db
            .find_types_git_aware("duplicate", &git_sha)
            .await
            .unwrap();
        let paths: Vec<&str> = definitions.iter().map(|ty| ty.file_path.as_str()).collect();
        assert_eq!(paths, vec!["a.h", "b.h"]);

        let (function_counts, type_counts) = db
            .get_distinct_reference_counts_git_aware(
                &["target".to_string()],
                &["duplicate".to_string()],
                &git_sha,
            )
            .await
            .unwrap();
        assert_eq!(function_counts["target"], 2);
        assert_eq!(type_counts["duplicate"], 3);
    }

    #[tokio::test]
    async fn a_later_repl_command_sees_an_edit_the_current_one_did_not() {
        // The on-miss overlay is built once, lazily, and reused within one
        // call, so `func alloc_super; help` walks the tree once rather than
        // twice. What that alone does not do is notice a file
        // changed *after* that first build: `ensure_workdir_index_built`
        // used to return immediately whenever an overlay already existed,
        // for the rest of the process. This test pins both halves of a
        // trade-off that pulls in opposite directions: refreshing on every
        // call re-walks the tree
        // twice for one `func` command (it calls both
        // `get_function_callees_git_aware` and
        // `get_function_callers_git_aware`); never refreshing leaves an
        // edit invisible for the rest of the session. `note_repl_command`
        // is the line between the two: calls before it share one overlay,
        // calls after it get a freshness check.
        //
        // (workdir.rs's own `test_incremental_reuses_cache` already covers
        // `build_incremental`'s cache primitive directly; this test is
        // about `ensure_workdir_index_built` deciding *when* to call it.)
        let repo_dir = tempfile::tempdir().unwrap();
        let repo_path = repo_dir.path();
        git(repo_path, &["init", "-q"]);
        std::fs::write(repo_path.join("a.c"), "/* placeholder */\n").unwrap();
        git(repo_path, &["add", "a.c"]);
        git(repo_path, &["commit", "-q", "-m", "initial"]);

        let git_sha = crate::git::get_git_sha(repo_path).unwrap().unwrap();

        let db_path = repo_path.join(".semcode.db");
        let db = DatabaseManager::new(
            db_path.to_str().unwrap(),
            repo_path.to_string_lossy().into_owned(),
        )
        .await
        .unwrap();
        db.create_tables().await.unwrap();

        // No row anywhere names this function — symbol_filename is empty —
        // so only the on-miss path (the workdir overlay) can ever answer
        // it. The first call builds the overlay from a clean tree and finds
        // nothing.
        let before = db
            .find_all_functions_git_aware("brand_new_func", &git_sha)
            .await
            .unwrap();
        assert!(before.is_empty(), "found before it was written: {before:?}");
        assert!(db.has_workdir_index(), "overlay was not built on first use");

        // Edit the file after the overlay already exists in this process —
        // what happens between two commands in one REPL session.
        // (Body has to clear `filter_implementations_only`'s 50-byte
        // "substantial body" floor, or a real function reads as a bare
        // declaration and this test would fail for a reason that has
        // nothing to do with the overlay.)
        std::fs::write(
            repo_path.join("a.c"),
            "int brand_new_func(void)\n{\n    int result = 42;\n    return result;\n}\n",
        )
        .unwrap();

        // Still the same command as the first call (nothing told the
        // database a new one started): the edit must not appear yet, or a
        // `func` command that checks callees and then callers would walk
        // the tracked-file set twice instead of once.
        let still_this_command = db
            .find_all_functions_git_aware("brand_new_func", &git_sha)
            .await
            .unwrap();
        assert!(
            still_this_command.is_empty(),
            "a second lookup in the same command re-walked the tree instead of reusing: {still_this_command:?}"
        );

        // A new command starts — the REPL calls this once per line read from
        // the prompt, before dispatching it.
        db.note_repl_command();

        let next_command = db
            .find_all_functions_git_aware("brand_new_func", &git_sha)
            .await
            .unwrap();
        assert_eq!(
            next_command.len(),
            1,
            "edit made before the next command is still invisible: {next_command:?}"
        );
    }
}

#[cfg(test)]
mod anonymous_members {
    use super::DatabaseManager;
    use crate::types::{FieldInfo, TypeInfo};
    use std::collections::HashSet;

    fn field(name: &str) -> FieldInfo {
        FieldInfo {
            name: name.to_string(),
            type_name: "int".to_string(),
            offset: None,
        }
    }

    fn ty(members: Vec<FieldInfo>) -> TypeInfo {
        TypeInfo {
            name: "mm_struct".to_string(),
            file_path: "include/linux/mm_types.h".to_string(),
            git_file_hash: "hash".to_string(),
            line_start: 1,
            kind: "struct".to_string(),
            size: None,
            members,
            definition: String::new(),
            types: None,
        }
    }

    #[test]
    fn an_attribute_leaves_the_path_of_a_flattened_member() {
        // mm->mm_mt is the field. __randomize_layout is what the struct is
        // marked with, and names nothing.
        let attributes: HashSet<String> = ["__randomize_layout", "____cacheline_aligned_in_smp"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut types = vec![ty(vec![
            field("__randomize_layout"),
            field("__randomize_layout.mm_mt"),
            field("__randomize_layout.____cacheline_aligned_in_smp.mm_count"),
            field("__randomize_layout.lru_gen"),
            field("cpu_bitmap"),
        ])];

        DatabaseManager::flatten_anonymous_members(&mut types, &attributes);

        let names: Vec<&str> = types[0].members.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["mm_mt", "mm_count", "lru_gen", "cpu_bitmap"]);
    }

    #[test]
    fn a_named_member_keeps_its_path() {
        // `union { ... } u;` is a member, and u.flags says where flags lives.
        let attributes: HashSet<String> = HashSet::new();
        let mut types = vec![ty(vec![field("u"), field("u.flags")])];

        DatabaseManager::flatten_anonymous_members(&mut types, &attributes);

        let names: Vec<&str> = types[0].members.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["u", "u.flags"]);
    }
}
