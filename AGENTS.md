# AGENTS.md

Guidance for coding agents working in this repository.

## Project overview

Semcode is a code search and analysis tool written in Rust. It parses
codebases with Tree-sitter, stores functions, types, macros, call edges and
git history in a LanceDB database, and optionally adds embeddings for
semantic search. It indexes C, C++, Rust, Python and Zig (default extensions:
`c,h,rs,zig`; see `src/file_extensions.rs`). It can also index
lore.kernel.org mailing-list archives (see `docs/lore.md`).

Binaries (`Cargo.toml`):

| Binary          | Source                    | Purpose                                    |
|-----------------|---------------------------|--------------------------------------------|
| `semcode-index` | `src/bin/index.rs`        | Index a source tree, git ranges, branches, lore |
| `semcode`       | `src/bin/query.rs` (+ `src/bin/query_impl/`) | Interactive query tool  |
| `semcode-mcp`   | `src/bin/semcode-mcp.rs`  | MCP server (see `docs/semcode-mcp.md`)     |
| `semcode-lsp`   | `src/bin/semcode-lsp.rs`  | LSP server (see `docs/lsp-server.md`)      |

## Build

System dependencies:

```bash
# Ubuntu/Debian
sudo apt-get install build-essential libclang-dev protobuf-compiler libprotobuf-dev
# Fedora
sudo dnf install gcc-c++ clang-devel protobuf-compiler protobuf-devel
```

`protoc` is required by LanceDB; a C++ compiler is required by some
dependencies.

```bash
cargo build --release      # release binaries in target/release/
./build.sh                 # same, plus symlinks in ./bin/
./build.sh --with-test     # also writes a small C sample into ./test_code/
```

## Required checks

Run before every commit; all must pass:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

Fix clippy warnings rather than silencing them with `#[allow]`, unless there
is a specific, documented reason.

Shared git hooks in `hooks/` enforce this. Enable them with
`./setup-hooks.sh` (or `git config core.hooksPath hooks`):

- `pre-commit`: `cargo fmt --check`, `cargo check --all-targets`, `cargo test`
- `pre-push`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`

CI (`.github/workflows/ci.yml`) runs fmt, clippy and tests.

Integration tests live in `tests/`. Tests that create their own git
repositories must not depend on the caller's `GIT_*` environment variables
(the pre-commit hook unsets them for this reason).

## Repository layout

- `src/treesitter_analyzer.rs`: Tree-sitter extraction of functions, types,
  macros, globals, calls and comments for all supported languages
- `src/indexer.rs`: indexing pipeline (parallel parse, dedup, insert)
- `src/vectorizer.rs`: embedding generation with `model2vec-rs`
- `src/database/`: LanceDB access; `connection.rs` holds `DatabaseManager`,
  `schema.rs` the table schemas, other files one table or feature each
- `src/database_utils.rs`: database path resolution
- `src/git.rs`, `src/git_range.rs`, `src/worktree.rs`, `src/workdir.rs`:
  git access and working-copy overlay
- `src/callchain.rs`, `src/search.rs`, `src/file_survey.rs`,
  `src/diffdump.rs`: query features shared by the binaries
- `src/lore_*.rs`: lore archive handling
- `src/types.rs`: core data structures (`FunctionInfo`, `TypeInfo`, ...)
- `docs/`: user and design documentation; `docs/schema.md` describes the tables
- `scripts/`: Python helpers (model conversion, LSP testing)
- `plugin/`: Claude Code plugin

## Embeddings

Vectors come from a **model2vec static embedding model** loaded through
`model2vec-rs`; there is no ONNX Runtime and no transformer inference at run
time. Encoding is tokenization plus a lookup and mean of per-token vectors,
so it runs on the CPU and `--gpu` is accepted but ignored. Vectors are
256-dimensional `f32`; `vectorizer.rs` rejects any other size.

The model is loaded from `--model-path`, or from
`~/.cache/semcode/models/model2vec`. Semcode does not download it; see
"Model Setup" in `README.md` and `scripts/nomic2vec.py`. Vector generation is
optional and runs as a separate pass: `semcode-index -s . --vectors`.

## Database location

`src/database_utils.rs` resolves the `.semcode.db` directory.

`semcode-index`:
1. `-d/--database`
2. `SEMCODE_DB`
3. `.semcode.db` in the `-s/--source` directory
4. `./.semcode.db`

`semcode`, `semcode-mcp`, `semcode-lsp`:
1. `-d/--database` (or LSP configuration)
2. `SEMCODE_DB`
3. `./.semcode.db` in the workspace or current directory

A `-d` value is the database itself if it ends in `.db` or is an existing
database directory; otherwise it is a parent directory and `.semcode.db` is
appended, whether or not the directory exists yet. Keep it this way: the same
argument must name the same database whichever command runs first. Deciding
on whether a directory happens to exist would let the indexer write to one
path and later queries read from another.

## Rules for database code

### Use git-aware lookups

The database holds many versions of each function, type and macro, one per
indexed commit. Any feature that looks up code entities must resolve them at
the commit the user is working on:

```rust
let git_sha = semcode::git::get_git_sha(&repo_path)?
    .ok_or_else(|| anyhow::anyhow!("Not a git repository"))?;

// Correct
let func = db.find_function_git_aware(name, &git_sha).await?;
// Wrong: returns an arbitrary version
let func = db.find_function(name).await?;
```

`DatabaseManager::new(db_path, git_repo_path)` needs the repository path for
git-aware resolution. Examples of git-aware APIs in
`src/database/connection.rs`: `find_function_git_aware`,
`get_function_callees_git_aware`; `callchain::show_callchain` takes a
`git_sha`. Look for a `_git_aware` variant or a `git_sha` parameter before
adding a lookup.

Use non-git-aware lookups only as a fallback outside a git repository, for
admin/debug operations that need every version, or when the feature is
explicitly about history across commits.

### Avoid full table scans

The database is very large. Filter in LanceDB with `.only_if()` instead of
reading a table and filtering in Rust, unless the operation is inherently a
full scan. Escape values placed in filter strings:

```rust
let escaped = pattern.replace('\\', "\\\\").replace('\'', "''");
let rows = table
    .query()
    .only_if(format!("regexp_match(content, '{}')", escaped))
    .execute()
    .await?;
```

For bulk inserts that must not create duplicates, use
`table.merge_insert(&[key columns])` with `when_matched_update_all(None)` and
`when_not_matched_insert_all()`.

### Know the schema

Read `docs/schema.md` and `src/database/schema.rs` before touching tables.
Points that are easy to get wrong:

- Function-like macros are stored in the `functions` table with an empty
  `return_type`; object-like macros are in `object_macros`. Queries spanning
  several tables must use each table's own columns.
- Bodies and definitions are deduplicated into sharded `content_0` ..
  `content_15` tables keyed by Blake3 hex hash; entity rows reference them.
- Call relationships live in `call_edges`; indirect calls in
  `dispatch_sites` and `registrations`.
- `schema_meta` records what wrote the index; schema changes need a version
  bump (see `tests/schema_version.rs`).

## Code conventions

- Standard Rust style; `anyhow::Result` for errors; async/await for database
  work; `rayon` for CPU parallelism; `indicatif` for progress.
- Use gitoxide (`gix`) for git access from Rust. Never shell out to `git`
  from semcode code. (Using the `git` CLI yourself to work on this repository
  is fine.)
- Colored output: write colored text with `owo-colors` to an `anstream`
  writer (`anstream::stdout()`), which strips ANSI codes when the output is
  not a terminal. Don't add manual TTY checks.
- Logging: use `tracing::info!` for diagnostic messages you add while
  debugging; `tracing::debug!` output is drowned out by other crates.
- New source files start with `// SPDX-License-Identifier: MIT OR Apache-2.0`.
- When grepping the tree, exclude `target/` and `.git/`.

## Build configuration

`.cargo/config.toml` sets `-C force-frame-pointers=yes` under
`[build] rustflags`. No `target-cpu` is set, so builds target the baseline
x86-64 (SSE2). Cargo uses `target.<triple>.rustflags` instead of
`build.rustflags` when both are set, so a user-level target setting
(for example a mold linker flag) silently drops the project flags.

## Running locally

```bash
./bin/semcode-index -s /path/to/code              # creates /path/to/code/.semcode.db
./bin/semcode-index -s /path/to/code --vectors    # add embeddings (needs model)
./bin/semcode-index -s /path/to/code --git A..B   # index files changed in a range
cd /path/to/code && semcode                       # query
semcode -d /path/to/code                          # query from elsewhere
```

Useful indexer options: `-j THREADS[:BATCH]`, `--branch`/`--branches`/
`--all-branches`, `--commits A..B`, `--lore LIST`, `--clear`, `--perf`.
Run `semcode-index --help` for the full list.

Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) are honored for
network access.
