# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Semcode is a semantic code search tool written in Rust that indexes C/C++ codebases using machine learning embeddings. It consists of several binaries:
- `semcode-index`: Analyzes and indexes codebases using the CodeBERT model
- `semcode`: Interactive query tool for searching the indexed code
- `semcode-mcp`: Model Context Protocol server for Claude Desktop integration
- `semcode-lsp`: Language Server Protocol server for editor integration (see [docs/lsp-server.md](docs/lsp-server.md))

## Build and Development Commands

### Prerequisites
Install required system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install libclang-dev protobuf-compiler libprotobuf-dev

# Fedora
sudo dnf install clang-devel protobuf-compiler protobuf-devel
```

### Build Commands
```bash
# Build release binaries (recommended)
cargo build --release

# Use build script (creates symlinks in ./bin/)
./build.sh

# Build with test code samples
./build.sh --with-test
```

- Always use cargo fmt after making changes to properly format the files

### Database Location

Semcode uses the following search order to locate the `.semcode.db` database directory:

**For semcode-index:**
1. **-d flag**: If provided, use the specified path (direct database path or parent directory containing `.semcode.db`)
2. **Source directory**: Look for `.semcode.db` in the source directory specified by `-s`
3. **Current directory**: Fall back to `./.semcode.db` in the current working directory

**For semcode (query tool), semcode-mcp, and semcode-lsp:**
1. **-d flag / configuration**: If provided, use the specified path (direct database path or parent directory containing `.semcode.db`)
2. **Workspace/Current directory**: Use `./.semcode.db` in the workspace or current working directory

The `-d` flag can specify either:
- A direct path to the database directory (e.g., `./my-custom.db`)
- A parent directory containing `.semcode.db` (e.g., `-d /path/to/project` will use `/path/to/project/.semcode.db`)

### Running the Tools

**Typical workflow:**
```bash
# Index a codebase - creates /path/to/code/.semcode.db
./bin/semcode-index --source /path/to/code

# Query from within the indexed directory
cd /path/to/code
semcode  # Automatically finds ./.semcode.db

# Or query from elsewhere
semcode --database /path/to/code  # Uses /path/to/code/.semcode.db
```

**Other indexing options:**
```bash
# Basic analysis only (no vectors)
./bin/semcode-index --source /path/to/code

# Index files modified in git commit range
./bin/semcode-index --source /path/to/code --git HEAD~10..HEAD

# Custom database location (overrides search order)
./bin/semcode-index --source /path/to/code --database ./custom.db
```

## Architecture

### Git-Aware Operations (IMPORTANT)

**All features that query the database MUST use git-aware lookup functions.**

Semcode indexes codebases at specific git commits and stores multiple versions of functions, types, and macros as the codebase evolves. When implementing any feature that looks up code entities, always use git-aware functions to ensure you're finding the correct version that matches the user's current working directory.

#### Required Approach

1. **Obtain the current git SHA:**
   ```rust
   use semcode::git::get_git_sha;

   let git_sha = get_git_sha(&repo_path)?
       .ok_or_else(|| anyhow::anyhow!("Not a git repository"))?;
   ```

2. **Use git-aware lookup functions:**
   ```rust
   // ✅ CORRECT: Git-aware function lookup
   let function = db.find_function_git_aware(name, &git_sha).await?;

   // ❌ WRONG: Non-git-aware lookup (may return wrong version)
   let function = db.find_function(name).await?;
   ```

3. **Pass git_repo_path to DatabaseManager:**
   ```rust
   // DatabaseManager needs git_repo_path for git-aware resolution
   let db = DatabaseManager::new(&db_path, git_repo_path).await?;
   ```

#### Available Git-Aware Functions

In `DatabaseManager` (src/database/connection.rs):
- `find_function_git_aware(name: &str, git_sha: &str)` - Find function at specific commit
- `find_macro_git_aware(name: &str, git_sha: &str)` - Find macro at specific commit
- `get_function_callees_git_aware(name: &str, git_sha: &str)` - Get callees at specific commit
- `build_callchain_with_manifest()` - Call chain analysis with git manifest

#### When to Use Non-Git-Aware Functions

Non-git-aware functions like `find_function()` should **only** be used:
- As a fallback when git SHA cannot be determined (not in a git repo)
- For administrative/debugging operations that need to see all versions
- When the operation explicitly requires seeing historical data across commits

#### Example: Implementing a New Feature

```rust
// ✅ CORRECT IMPLEMENTATION
async fn my_new_feature(db: &DatabaseManager, repo_path: &str) -> Result<()> {
    // 1. Get current git SHA
    let git_sha = semcode::git::get_git_sha(repo_path)?
        .ok_or_else(|| anyhow::anyhow!("Not a git repository"))?;

    // 2. Use git-aware lookup
    if let Some(func) = db.find_function_git_aware("my_func", &git_sha).await? {
        println!("Found function at current commit: {}", func.name);
    }

    Ok(())
}

// ❌ WRONG IMPLEMENTATION (may return wrong version)
async fn my_bad_feature(db: &DatabaseManager) -> Result<()> {
    if let Some(func) = db.find_function("my_func").await? {
        println!("Found function (but which version?): {}", func.name);
    }
    Ok(())
}
```

#### Why This Matters

Without git-aware lookups:
- Users may jump to outdated function definitions
- Call chains may include deleted or renamed functions
- Type information may not match current code structure
- Results are confusing and incorrect for active development

**Remember: When in doubt, use git-aware functions!**

### Scalability
- The database is very large.  No operation should be implemented via full table
scans unless that operation is a effectively a full table scan.
- If you're tempted to do full table scans, remember that LanceDB has an
  .only_if() parameter to queries allowing you to search without doing full table
  scans.  Example: .only_if(format!("name = '{}'", escaped_name)).

Example only_if() usage for regex searches in grep_function_bodies():
```rust
// Escape special characters in the pattern for SQL string literal
let escaped_pattern = pattern
    .replace("\\", "\\\\") // Escape backslashes first
    .replace("'", "''"); // Escape single quotes for SQL

let where_clause = format!("regexp_match(content, '{}')", escaped_pattern);
let content_results = content_table
    .query()
    .only_if(&where_clause)
    .execute()
    .await?
```

Example bulk insertion with duplicate removal:
```
let tmpdir = tempfile::tempdir().unwrap();
let db = lancedb::connect(tmpdir.path().to_str().unwrap())
    .execute()
    .await
    .unwrap();
let new_data = RecordBatchIterator::new(
    vec![RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(Int32Array::from_iter_values(0..10)),
            Arc::new(
                FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
                    (0..10).map(|_| Some(vec![Some(1.0); 128])),
                    128,
                ),
            ),
        ],
    )
    .unwrap()]
    .into_iter()
    .map(Ok),
    schema.clone(),
);
// Perform an upsert operation
let mut merge_insert = tbl.merge_insert(&["id"]);
merge_insert
    .when_matched_update_all(None)
    .when_not_matched_insert_all();
merge_insert.execute(Box::new(new_data)).await.unwrap();
```


### Core Components
- **treesitter_analyzer.rs**: C/C++ code analysis using Tree-sitter, extracts functions, types, macros
- **vectorizer.rs**: CodeBERT-based semantic embedding generation using ONNX Runtime
- **database/**: LanceDB vector database operations and schema management
- **types.rs**: Core data structures (FunctionInfo, TypeInfo, MacroInfo, etc.)
- **pipeline.rs**: Multi-stage pipeline processing for optimal CPU utilization

### Binary Structure
- **src/bin/index.rs**: Indexing tool with parallel processing and batch operations
- **src/bin/query.rs**: Interactive query interface with semantic and exact search
- **src/pipeline.rs**: Pipeline processing implementation for continuous CPU utilization

### Key Features
- **Pipeline processing**: Continuous processing with optimal CPU utilization (always enabled)
- **Parallel processing**: Configurable via `-j threads[:sessions[:batch]]` format
- **Selective macro indexing**: Only indexes function-like macros (reduces noise by 95%+)
- **GPU acceleration**: Automatic CUDA detection when `--gpu` flag is used
- **Quantized models**: INT8 quantization for 2-4x faster CPU inference
- **Embedded relationships**: Call and type relationships stored as JSON arrays for ~10-15x performance

### Performance Tuning

#### Pipeline Processing (Always Enabled)
All indexing uses pipeline processing for optimal performance:
```bash
# Standard indexing with pipeline processing (creates /path/to/code/.semcode.db)
semcode-index --source /path/to/code
```

Pipeline processing provides:
- Continuous processing without gaps between batches
- Optimal CPU utilization (no idle periods)
- Parallel file parsing, deduplication, and database insertion
- Adaptive batch sizing based on processing speed
- Progress monitoring and performance statistics

#### Parallelism Configuration
Use the `-j` option to control parallelism:
```bash
# 16 analysis threads, 4 ORT sessions, batch size 32
semcode-index --vectors -j 16:4:32 --source /path/to/code
```

### Analysis Method
Semcode uses **Tree-sitter** for C/C++ code analysis:

- Uses Tree-sitter's fast incremental parser for AST analysis
- Fast processing suitable for large codebases
- Does not require compilation flags or headers to be present
- Extracts functions, types, macros, and call relationships
- Embedded JSON approach stores relationships directly in records

## Development Notes

### Grepping
- exclude .git and target directories from your source code grep commands

### Code Conventions
- Uses standard Rust formatting and conventions
- Extensive use of async/await for database operations
- Error handling via `anyhow::Result`
- Parallel processing with `rayon` crate
- Progress reporting with `indicatif`
- Use gitoxide (gix) for all git access, never command line git

### Color Output System
Semcode uses **anstream** + **owo-colors** for automatic color handling:

- **Automatic TTY detection**: `anstream::stdout()` automatically strips ANSI codes when output isn't a terminal
- **Consistent coloring**: `owo-colors` provides a clean API for colorized text
- **No manual conditionals**: Code always outputs colored text; anstream handles compatibility

**Example colorized output:**
```rust
use anstream::stdout;
use owo_colors::OwoColorize as _;
use std::io::Write;

fn display_function_info(name: &str, file: &str, line: u32, writer: &mut dyn Write) -> Result<()> {
    writeln!(writer, "Function: {}", name.yellow())?;
    writeln!(writer, "File: {} ({}:{})",
        file.cyan(),
        "line".bright_black(),
        line.to_string().bright_white()
    )?;
    Ok(())
}

// Usage: always outputs colors, anstream handles TTY detection
display_function_info("main", "src/main.rs", 42, &mut stdout())?;
```

### Dependencies
- **Tree-sitter**: Fast incremental parsing for C/C++ code analysis
- **LanceDB**: Vector database for embeddings storage
- **ONNX Runtime**: CodeBERT model inference
- **Tokenizers**: Text preprocessing for the ML model
- **Rayon**: Parallel processing framework

### Testing
```bash
# Create test code samples
./build.sh --with-test

# Test indexing on sample code (creates ./test_code/.semcode.db)
./bin/semcode-index --source ./test_code --vectors

# Test querying (from test_code directory)
cd test_code && ../bin/semcode

# Or query from current directory
./bin/semcode --database ./test_code
```

## Model and Data Storage

### Model Location
- Linux/macOS: `~/.cache/semcode/models/`

### Database Format

Uses LanceDB with an embedded JSON relationship approach. For complete schema details, see [docs/schema.md](docs/schema.md).

**Summary of key tables:**

- See docs/schema.md
- Note that function and macro tables have different schemas.  Many of the
queries are expected to search both, and need to verify they are using the correct
schema for the correct table.

#### Key Design Features

1. **Embedded JSON Relationships**: Call and type relationships are stored as JSON arrays within each entity's record rather than separate mapping tables
2. **Git SHA-based Deduplication**: Each record includes a git file hash for content-based uniqueness and incremental processing
3. **Complete Source Storage**: Full function bodies, type definitions, and macro expansions are stored for context
4. **Optimized Indexing**: BTree indices on names, file paths, and git hashes for fast queries
5. **Vector Integration**: Separate vectors table allows optional semantic search capabilities
6. **GIT Integration**: Expected to run in a git repository, and store information on a per-commit basis

### Proxy Support
Honors standard proxy environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) for model downloads.

### Key Features

- **Regex Pattern Support**: Full regex syntax supported via LanceDB's `regexp_match()` function
- **Path Filtering**: Optional secondary regex filter on file paths
- **Performance Optimized**: Uses content deduplication and efficient batching for large codebases
- **Limit Control**: Configurable result limits with limit-hit detection
- **Parallel Processing**: Automatically uses parallel queries for large result sets

### Implementation Details

The search leverages Semcode's content deduplication system:
- Function bodies are stored in a separate `content` table with Blake3 hashes
- Regex search first finds matching content entries
- Content hashes are then used to locate corresponding functions
- Path filtering is applied as a post-processing step for refined results

This approach provides excellent performance even on large codebases by avoiding full table scans and utilizing LanceDB's efficient filtering capabilities.

### Misc
- Don't use tracing::debug!() for debugging logging, there's too much other verbosity.  Use tracing::info!()
