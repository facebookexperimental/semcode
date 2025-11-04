// SPDX-License-Identifier: MIT OR Apache-2.0
// Module declarations
mod database;
pub mod database_utils;
pub mod git;
pub mod git_range;
pub mod hash;
pub mod indexer;
pub mod perf_monitor;
pub mod symbol_walkback;
pub mod text_utils;
mod treesitter_analyzer;
mod types;
mod vectorizer;

// Query functionality modules
pub mod callchain;
pub mod diffdump;
pub mod display;
pub mod lore_writers;
pub mod pages;
pub mod search;

// Re-export the main types and structs
pub use database::processed_files::ProcessedFileRecord;
pub use database::DatabaseManager;
pub use database_utils::process_database_path;
pub use git::{get_git_sha, get_git_sha_for_workdir};
pub use hash::{compute_content_hash, compute_file_hash};
pub use text_utils::preprocess_code;
pub use treesitter_analyzer::TreeSitterAnalyzer;
pub use types::{
    FieldInfo, FunctionInfo, GitCommitInfo, GitFileEntry, GitFileManifestEntry, GlobalTypeRegistry,
    LoreEmailInfo, ParameterInfo, TypeInfo, TypedefInfo,
};
pub use vectorizer::CodeVectorizer;

// Re-export database types
pub use database::calls::CallRelationship;
pub use database::search::FunctionMatch;

// Logging utilities
pub mod logging {
    use tracing_subscriber::EnvFilter;

    /// Initialize tracing with SEMCODE_DEBUG environment variable support
    /// This provides consistent logging configuration across all semcode binaries
    pub fn init_tracing() {
        let log_level = std::env::var("SEMCODE_DEBUG").unwrap_or_else(|_| "error".to_string());

        // Map common values to appropriate filter strings
        let filter_str = match log_level.as_str() {
            "0" | "off" | "none" => "error",
            "1" | "warn" => "warn",
            "2" | "info" => "info",
            "3" | "debug" => "debug",
            "4" | "trace" => "trace",
            // Allow custom filter strings like "semcode=debug,lancedb=warn"
            custom => custom,
        };

        // Check if SEMCODE_DEBUG contains specific module overrides
        let has_custom_modules = log_level.contains("ort=")
            || log_level.contains("lancedb=")
            || log_level.contains("lance=")
            || log_level.contains("lance_index=");

        let mut env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter_str));

        // Only add default noise-reduction directives if user hasn't specified custom ones
        if !has_custom_modules {
            env_filter = env_filter
                .add_directive("ort=error".parse().unwrap())
                .add_directive("lancedb=warn".parse().unwrap())
                .add_directive("lance=warn".parse().unwrap())
                .add_directive("lance_index=warn".parse().unwrap())
                .add_directive("DatasetRecordBatchStream=error".parse().unwrap());
        }

        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}
