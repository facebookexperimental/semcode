# Semcode Database Schema

This document describes the LanceDB database schema used by semcode for storing and querying C/C++ code analysis results.

## Overview

Semcode uses LanceDB (Apache Arrow-based columnar database) with several key architectural features:

- **Content Deduplication**: Large content (function bodies, type definitions, macro definitions) is stored once in sharded content tables, referenced by Blake3 hex hashes
- **Content Sharding**: Content is distributed across 16 shard tables (content_0 through content_15) for optimal performance
- **Embedded Relationships**: Call relationships and type dependencies are stored as JSON arrays within each entity's record
- **Git Integration**: Git SHA-based tracking for incremental processing and multi-version support
- **Symbol Lookup Cache**: Fast symbol→filename mapping table optimizes git-aware queries
- **Hex String Storage**: All hashes are stored as hex strings for better compatibility and debuggability

## Database Technology

- **Database Engine**: LanceDB (Apache Arrow-based columnar database)
- **Vector Embeddings**: 256-dimensional float32 vectors for semantic search
- **Hash Algorithms**:
  - SHA-1 for git file content tracking (stored as hex strings)
  - Blake3 for content deduplication (faster, better collision resistance, stored as hex strings)
- **Schema Format**: Apache Arrow schemas with strongly-typed columns
- **Content Sharding**: 16-way sharding based on Blake3 hash prefix

## Database Tables

The database consists of the following tables:

1. **functions** - Function definitions, declarations, and function-like macros with embedded call and type relationships
2. **types** - Struct, union, and enum definitions with embedded type dependencies
3. **vectors** - CodeBERT embeddings for semantic search of functions and types
4. **commit_vectors** - Embeddings for git commit messages and diffs
5. **processed_files** - Tracks processed files for incremental indexing
6. **symbol_filename** - Fast lookup cache mapping symbols to file paths
7. **git_commits** - Git commit metadata with unified diffs and changed symbols
8. **lore** - Lore.kernel.org email archive with FTS indices for fast searching
9. **lore_vectors** - Vector embeddings for semantic search of lore emails
10. **indexed_branches** - Tracks which git branches have been indexed with their tip commits
11. **content_0 through content_15** - Deduplicated content storage (16 shards)

## Table Schemas

### 1. functions

Stores analyzed C/C++ function definitions, declarations, and function-like macros with content deduplication.

**Note:** Function-like macros are stored in this table with empty `return_type` and untyped parameters (empty `type_name` in ParameterInfo).

**Schema:**
```
name                (Utf8, NOT NULL)     - Function name
file_path           (Utf8, NOT NULL)     - Source file path
git_file_hash       (Utf8, NOT NULL)     - SHA-1 hash of file content as hex string
line_start          (Int64, NOT NULL)    - Starting line number
line_end            (Int64, NOT NULL)    - Ending line number
return_type         (Utf8, NOT NULL)     - Function return type
parameters          (Utf8, NOT NULL)     - JSON-encoded parameter list
body_hash           (Utf8, nullable)     - Blake3 hash referencing content table as hex string (nullable for empty bodies)
calls               (Utf8, nullable)     - JSON array of function names called by this function
types               (Utf8, nullable)     - JSON array of type names used by this function
```

**Content Storage:**
- Function bodies are stored in sharded content tables (content_0 through content_15), referenced by `body_hash`
- Empty function bodies (declarations) have null `body_hash`
- Content deduplication: identical function bodies share the same Blake3 hash
- Shard selection based on first hex character of Blake3 hash

**Rust Struct:** `FunctionInfo`
- Parameters are stored as JSON-encoded `Vec<ParameterInfo>`
- Each parameter includes: name, type_name, optional type_file_path, optional type_git_file_hash
- The `body` field in the struct is resolved from the appropriate content shard during queries

**Indices:**
- BTree on `name` (exact lookups)
- BTree on `git_file_hash` (content-based lookups)
- BTree on `file_path` (file-based queries)
- BTree on `body_hash` (content reference lookups)
- BTree on `calls` (function call relationship queries)
- BTree on `types` (type relationship queries)
- BTree on `line_start` (line-based queries and sorting)
- BTree on `line_end` (range-based queries)
- Composite on `(name, git_file_hash)` (duplicate checking)

### 2. types

Stores struct, union, enum, and typedef definitions with content deduplication and embedded type dependency data.

**Schema:**
```
name                (Utf8, NOT NULL)     - Type name
file_path           (Utf8, NOT NULL)     - Source file path
git_file_hash       (Utf8, NOT NULL)     - SHA-1 hash of file content as hex string
line                (Int64, NOT NULL)    - Line number where type is defined
kind                (Utf8, NOT NULL)     - Type kind: "struct", "union", "enum", "typedef"
size                (Int64, nullable)    - Size in bytes (if available)
fields              (Utf8, NOT NULL)     - JSON string of field/member information
definition_hash     (Utf8, nullable)     - Blake3 hash referencing content table as hex string (nullable for empty definitions)
types               (Utf8, nullable)     - JSON array of type names referenced by this type
```

**Content Storage:**
- Type definitions are stored in sharded content tables, referenced by `definition_hash`
- Empty definitions have null `definition_hash`
- Content deduplication: identical type definitions share the same Blake3 hash
- Shard selection based on first hex character of Blake3 hash

**Example JSON columns:**
```json
// fields column (for struct/union)
[
  {"name": "id", "type_name": "int", "offset": null},
  {"name": "name", "type_name": "char *", "offset": null},
  {"name": "next", "type_name": "struct node *", "offset": null}
]

// types column
["struct node", "size_t"]
```

**Indices:**
- BTree on `name` (fast type name lookups)
- BTree on `git_file_hash` (content-based lookups)
- BTree on `kind` (query by type kind)
- BTree on `file_path` (file-based queries)
- BTree on `definition_hash` (content reference lookups)
- Composite on `(name, kind, git_file_hash)` (duplicate checking)

### 3. vectors

Stores CodeBERT embeddings for semantic search functionality.

**Schema:**
```
content_hash        (Utf8, NOT NULL)                         - Blake3 hash of content as hex string
vector              (FixedSizeList[Float32, 256], NOT NULL)  - CodeBERT embedding vector
```

**Notes:**
- Vectors are linked to content via `content_hash` (Blake3 hash of the content)
- Enables semantic search across functions and types
- Vector generation is optional and controlled by the `--vectors` flag
- Vector dimension is configurable (currently 256)

**Indices:**
- BTree on `content_hash` (content hash lookups)
- IVF-PQ vector index on `vector` column (for fast approximate nearest neighbor search)
  - Uses cosine distance for similarity matching
  - Dynamically configured partitions based on dataset size
  - Optimized for semantic code search with 8 sub-vectors and 8-bit quantization

### 4. processed_files

Tracks which files have been processed for incremental indexing.

**Schema:**
```
file                (Utf8, NOT NULL)     - File path
git_sha             (Utf8, nullable)     - Git commit SHA as hex string (for incremental processing)
git_file_sha        (Utf8, NOT NULL)     - SHA-1 hash of specific file content as hex string
```

**Notes:**
- Enables incremental processing by tracking which files have been analyzed
- `git_sha` tracks the commit context for git-range based indexing
- `git_file_sha` provides content-based deduplication

**Indices:**
- BTree on `file` (fast file lookups)
- BTree on `git_sha` (commit-based queries)
- BTree on `git_file_sha` (content-based deduplication)
- Composite on `(file, git_sha)` (efficient file + git_sha lookups)

### 5. symbol_filename

Fast lookup cache mapping symbol names to file paths. Optimizes git-aware queries by avoiding full table scans.

**Schema:**
```
symbol              (Utf8, NOT NULL)     - Symbol name (function, type, or typedef)
filename            (Utf8, NOT NULL)     - File path where symbol is defined
```

**Purpose:**
- Acts as an index cache for the question "which files contain symbol X?"
- Dramatically speeds up git-aware lookups by providing candidate file paths without scanning entity tables
- Populated automatically during indexing for all functions, types, and typedefs
- Duplicate symbol-filename pairs are automatically deduplicated using composite key

**Performance Benefits:**
- Converts O(n) full table scans into O(log n) indexed lookups
- Essential for large codebases with millions of functions
- Enables efficient 3-step git-aware lookup pattern:
  1. Query symbol_filename cache → Get candidate file paths
  2. Resolve git hashes → Convert file paths to blob hashes at target commit
  3. Targeted entity lookup → Query only specific file/hash combinations

**Indices:**
- BTree on `symbol` (fast symbol name lookups)
- BTree on `filename` (file-based lookups)
- Composite on `(symbol, filename)` (fast deduplication)

### 6. commit_vectors

Stores embeddings for git commit messages and diffs, enabling semantic search across commits.

**Schema:**
```
git_commit_sha      (Utf8, NOT NULL)                         - Git commit SHA
vector              (FixedSizeList[Float32, 256], NOT NULL)  - Embedding vector for commit
```

**Notes:**
- Vectors generated from commit subject, message, and diff content
- Enables semantic search to find commits related to a concept or change pattern
- Vector dimension: 256 (matching function vectors for consistency)
- Generation is optional and controlled by indexing flags

**Indices:**
- BTree on `git_commit_sha` (fast commit lookups)
- IVF-PQ vector index on `vector` column (for approximate nearest neighbor search)

### 7. git_commits

Stores git commit metadata including unified diffs and symbols changed in each commit. Enables commit-level analysis and tracking code evolution across git history.

**Schema:**
```
git_sha             (Utf8, NOT NULL)     - Git commit SHA
parent_sha          (Utf8, NOT NULL)     - Parent commit SHAs (JSON array)
author              (Utf8, NOT NULL)     - Author name and email
subject             (Utf8, NOT NULL)     - Single line commit title
message             (Utf8, NOT NULL)     - Full commit message
tags                (Utf8, NOT NULL)     - JSON object of tags (Signed-off-by, Reviewed-by, etc.)
diff                (Utf8, NOT NULL)     - Full unified diff with enhanced hunk headers
symbols             (Utf8, NOT NULL)     - JSON array of changed symbols (functions, types, macros)
files               (Utf8, NOT NULL)     - JSON array of changed file paths
```

**Symbol Extraction:**
- Walk-back algorithm identifies changed functions, types, and macros from diff hunks
- Analyzes both additions (+) and deletions (-) for comprehensive symbol coverage
- Fast O(modified_lines × 50) performance using Tree-sitter parser
- Enhanced git-style hunk headers include symbol context: `@@ ... @@ symbol_name`

**Tag Parsing:**
Structured metadata extracted from commit messages including:
- Signed-off-by
- Reviewed-by
- Tested-by
- Acked-by
- Reported-by
- Fixes
- Cc
- And other common git trailer tags

**Example JSON columns:**
```json
// parent_sha column (single parent)
["abc123def456..."]

// parent_sha column (merge commit with multiple parents)
["abc123def456...", "789012fed321..."]

// symbols column
["mm_fault_error()", "struct vm_area_struct", "handle_mm_fault()"]

// files column
["mm/memory.c", "include/linux/mm.h"]

// tags column
{
  "Signed-off-by": ["John Doe <john@example.com>"],
  "Reviewed-by": ["Jane Smith <jane@example.com>"],
  "Fixes": ["a1b2c3d4 (\"Fix memory leak in handler\")"]
}
```

**Indices:**
- BTree on `git_sha` (fast commit lookups)
- BTree on `parent_sha` (parent commit lookups and history traversal)
- BTree on `author` (author-based queries)
- BTree on `subject` (subject searches)

**Use Cases:**
- Commit history analysis and evolution tracking
- Find commits that modified specific functions or types
- Analyze code review patterns via tags
- Track file change history
- Git history search with semantic or regex filters
- Review assistance and code archaeology

---

### 8. lore

Stores lore.kernel.org email archives for searching kernel development discussions, patches, and reviews.

**Schema:**
```
git_commit_sha      (Utf8, NOT NULL)     - Git commit SHA from lore repository
from                (Utf8, NOT NULL)     - Sender email address
date                (Utf8, NOT NULL)     - ISO 8601 timestamp
message_id          (Utf8, NOT NULL)     - Unique Message-ID (primary key)
in_reply_to         (Utf8, nullable)     - Message-ID of parent email
subject             (Utf8, NOT NULL)     - Email subject line
references          (Utf8, nullable)     - Space-separated Message-IDs of thread ancestors
recipients          (Utf8, NOT NULL)     - Comma-separated To/Cc recipients
headers             (Utf8, NOT NULL)     - Full email headers
body                (Utf8, NOT NULL)     - Email body content
symbols             (Utf8, NOT NULL)     - JSON array of symbols found in patches/diffs
```

**Indices:**
- BTree on `message_id` (unique lookups, primary key)
- BTree on `from` (exact sender lookups)
- BTree on `subject` (exact subject lookups)
- BTree on `date` (chronological queries)
- BTree on `in_reply_to` (threading queries)
- BTree on `references` (threading queries)
- BTree on `headers` (header searches)
- **FTS (Full Text Search) on `from`** - Fast keyword search on sender
- **FTS on `subject`** - Fast keyword search on subject lines
- **FTS on `body`** - Fast keyword search on email bodies
- **FTS on `recipients`** - Fast keyword search on recipients
- **FTS on `symbols`** - Fast keyword search on symbols mentioned in patches

**Search Performance:**
All lore searches use a two-phase **FTS + regex post-filtering** approach:
1. FTS phase: Fast keyword extraction and inverted index lookup returns superset
2. Regex phase: Precise pattern matching on small FTS result set in memory

This provides both speed (FTS indices) and precision (full regex support).

**Threading Support:**
Emails are linked via `in_reply_to` and `references` fields for thread reconstruction.

---

### 9. lore_vectors

Stores 256-dimensional vector embeddings for semantic search of lore emails.

**Schema:**
```
message_id          (Utf8, NOT NULL)     - Email Message-ID (links to lore table)
vector              (FixedSizeList[Float32, 256], NOT NULL) - Semantic embedding
```

**Vector Generation:**
Embeddings combine from, subject, recipients, and body into a single representation for similarity search.

**Index:**
- IVF-PQ vector index for fast approximate nearest neighbor search


### 10. indexed_branches

Tracks which git branches have been indexed, enabling multi-branch support and efficient incremental indexing across branches.

**Schema:**
```
branch_name         (Utf8, NOT NULL)     - Branch name (e.g., "main", "origin/develop")
tip_commit          (Utf8, NOT NULL)     - Commit SHA at the tip when indexed (40-char hex)
indexed_at          (Int64, NOT NULL)    - Unix timestamp of when branch was last indexed
remote              (Utf8, nullable)     - Remote name if tracking branch (e.g., "origin")
```

**Purpose:**
- Tracks which branches have been indexed and at which commit
- Enables efficient multi-branch indexing by skipping already-current branches
- Supports both local branches (e.g., "main") and remote-tracking branches (e.g., "origin/develop")
- Stores indexing timestamp for freshness tracking

**Use Cases:**
- Multi-branch indexing: `semcode-index --branches main,develop,feature-x`
- Branch update detection: Skip branches already indexed at current tip
- Query scoping: Limit queries to specific branch context
- Branch cleanup: Remove data for deleted branches

**Indices:**
- BTree on `branch_name` (primary lookup by branch name)
- BTree on `tip_commit` (find branches at specific commits)
- BTree on `remote` (filter by remote)

---

### 11. content_0 through content_15 (Content Shards)

Stores deduplicated content referenced by other tables, distributed across 16 shard tables for optimal performance.

**Schema (each shard):**
```
blake3_hash         (Utf8, NOT NULL)     - Blake3 hash of content as hex string (primary key)
content             (Utf8, NOT NULL)     - The actual content (function bodies, definitions, expansions)
```

**Content Sharding:**
- Content is distributed across 16 shard tables based on the first hex character of Blake3 hash
- Shard selection: `shard_number = first_hex_char % 16`
- Each shard operates independently for maximum parallelism
- Blake3 hashing provides fast, collision-resistant content deduplication
- Other tables reference content via `blake3_hash` foreign keys
- Significantly reduces storage size for codebases with repeated patterns

**Shard Distribution:**
- **content_0**: Blake3 hashes starting with 0
- **content_1**: Blake3 hashes starting with 1
- **...**: (continuing pattern)
- **content_15**: Blake3 hashes starting with f (and wrapping from higher hex digits)

**Indices (per shard):**
- BTree on `blake3_hash` (primary key for deduplication and fast lookups)
- BTree on `content` (text searches and pattern matching)

## Key Features

### Content Deduplication Architecture

**Blake3-based Content Storage:**
- All large content (function bodies, type definitions, macro definitions) stored once across sharded content tables
- Blake3 hashing provides fast, collision-resistant deduplication
- Other tables reference content via `blake3_hash` foreign keys as hex strings
- Dramatic storage reduction for codebases with repeated patterns

**Content Resolution:**
```rust
// Function body content is resolved via appropriate content shard lookup
let shard_table = format!("content_{}", get_shard_number(&function.body_hash));
let body_content = content_store.get_content(&function.body_hash).await?;
```

### Content Sharding System

**16-Way Sharding:**
- Content distributed across content_0 through content_15 based on Blake3 hash prefix
- Prevents single-table performance bottlenecks on large codebases
- Enables parallel operations across shards
- Automatic shard selection based on hash: `shard = first_hex_char % 16`

**Sharding Benefits:**
- **Parallel Processing**: Multiple shards can be queried/updated simultaneously
- **Reduced Lock Contention**: Operations on different shards don't interfere
- **Scalability**: Each shard maintains optimal size for performance
- **Load Distribution**: Content evenly distributed across all shards

### Embedded JSON Relationships

**Function calls example (optimized with BTree index on calls):**
```sql
-- Find all functions that call 'malloc'
SELECT name, file_path FROM functions
WHERE calls IS NOT NULL AND calls LIKE '%"malloc"%'
```

**Type dependencies example (optimized with BTree index on types):**
```sql
-- Find all functions that use 'struct node'
SELECT name, file_path FROM functions
WHERE types IS NOT NULL AND types LIKE '%"struct node"%'

-- Find all types that reference 'struct node'
SELECT name, kind FROM types
WHERE types IS NOT NULL AND types LIKE '%"struct node"%'
```

**Performance benefits:**
- **Indexed JSON searches**: BTree indices on `calls` and `types` columns enable O(log n) relationship queries
- **Pattern matching optimization**: LIKE queries on JSON arrays benefit from index pre-filtering
- **Dependency analysis**: Fast discovery of function call chains and type usage patterns

### Git SHA-based Content Tracking

Every record includes a `git_file_hash` field containing the SHA-1 hash of the file content as a hex string, enabling:
- **Content-based deduplication**: Same file content = same hash = skip reprocessing
- **Incremental indexing**: Only process files with changed content
- **Git-aware queries**: Find entities from specific git commits
- **Cross-commit consistency**: Same git hash ensures identical content across commits

### Symbol Lookup Cache (symbol_filename)

The symbol_filename table acts as a fast index cache that dramatically improves git-aware query performance:

**Problem Solved:**
- Without the cache, finding "which files contain function X?" requires scanning the entire functions table
- For large codebases with millions of functions, this is prohibitively expensive
- The same problem applies to types, typedefs, and macros

**Solution:**
- Maintain a simple (symbol, filename) mapping table with BTree indices
- Automatically populated during indexing for all entities
- Composite key (symbol, filename) prevents duplicates

**Performance Impact:**
- Converts O(n) full table scans into O(log n) indexed lookups
- Essential for the efficient 3-step git-aware lookup pattern used throughout the codebase:
  1. **Query cache**: `symbol_filename.get_filenames_for_symbol("malloc")` → `["mm/slab.c", "include/linux/slab.h"]`
  2. **Resolve git hashes**: Convert file paths to blob SHAs at target commit
  3. **Targeted lookup**: Query only the specific (name, file, hash) combinations

**Usage:**
- Used by all `*_git_aware()` lookup functions
- Critical for operations like "find function at commit", "find callers at commit", etc.
- Enables efficient call chain analysis and type relationship queries

### Commit Metadata with Symbol Extraction

The git_commits table stores git commit history with enhanced metadata:
- **Unified Diffs**: Full git-style diffs with symbol context in hunk headers
- **Walk-back Symbol Extraction**: Fast O(modified_lines × 50) algorithm identifies changed functions, types, and macros
- **Dual-file Analysis**: Extracts symbols from both additions and deletions
- **Enhanced Hunk Headers**: Git-style `@@ ... @@ symbol` format for better context
- **Commit Traversal**: Parent relationships enable git history analysis
- **Tag Parsing**: Extracts structured metadata from commit messages (Signed-off-by, Reviewed-by, etc.)
- **Use Cases**: Commit analysis, code evolution tracking, review assistance, git history search

## Query Patterns

### Basic Lookups
```sql
-- Find function by name
SELECT name, file_path, body_hash FROM functions WHERE name = 'main'

-- Find types by kind
SELECT name, definition_hash FROM types WHERE kind = 'struct'

-- Get content from appropriate shard
SELECT content FROM content_5 WHERE blake3_hash = 'abc123...'
```

### Content Resolution Queries
```sql
-- Function with body content (join with appropriate content shard)
-- Note: Shard selection done programmatically based on hash
SELECT f.name, f.file_path, c.content as body
FROM functions f
LEFT JOIN content_5 c ON f.body_hash = c.blake3_hash
WHERE f.name = 'main' AND f.body_hash LIKE '5%'

-- Type with definition content
SELECT t.name, t.kind, c.content as definition
FROM types t
LEFT JOIN content_3 c ON t.definition_hash = c.blake3_hash
WHERE t.name = 'user_data' AND t.definition_hash LIKE '3%'
```

### Relationship Queries
```sql
-- Find callers of a function (uses BTree index on calls)
SELECT name, file_path FROM functions
WHERE calls IS NOT NULL AND calls LIKE '%"target_function"%'

-- Find functions using a specific type (uses BTree index on types)
SELECT name, file_path FROM functions
WHERE types IS NOT NULL AND types LIKE '%"struct user_data"%'

-- Find all functions that use pointer types
SELECT name, file_path FROM functions
WHERE types IS NOT NULL AND types LIKE '%"*"%'
```

### Line-based and Location Queries
```sql
-- Find functions starting after line 100 (uses BTree index on line_start)
SELECT name, file_path, line_start, line_end FROM functions
WHERE line_start > 100 ORDER BY line_start

-- Find functions ending before line 500 (uses BTree index on line_end)
SELECT name, file_path, line_start, line_end FROM functions
WHERE line_end < 500

-- Find large functions (more than 50 lines, uses both line indices)
SELECT name, file_path, (line_end - line_start) as size FROM functions
WHERE (line_end - line_start) > 50 ORDER BY size DESC

-- Find functions in a specific line range
SELECT name, file_path FROM functions
WHERE line_start >= 100 AND line_end <= 200

-- Get functions sorted by location in file (uses BTree index on line_start)
SELECT name, file_path, line_start FROM functions
WHERE file_path = 'src/main.c' ORDER BY line_start
```

### Git-aware Queries
```sql
-- Find function at specific git SHA
SELECT * FROM functions
WHERE name = 'parse_config' AND git_file_hash = 'abc123...'

-- Content deduplication analysis across all shards
SELECT blake3_hash, COUNT(*) as usage_count
FROM (
  SELECT body_hash as blake3_hash FROM functions WHERE body_hash IS NOT NULL
  UNION ALL
  SELECT definition_hash FROM types WHERE definition_hash IS NOT NULL
  UNION ALL
  SELECT definition_hash FROM macros WHERE definition_hash IS NOT NULL
) GROUP BY blake3_hash HAVING usage_count > 1
```

### Commit Metadata Queries
```sql
-- Find commits by author
SELECT git_sha, subject, author FROM git_commits
WHERE author LIKE '%john@example.com%'

-- Find commits that modified a specific function
SELECT git_sha, subject, author FROM git_commits
WHERE symbols LIKE '%"malloc_wrapper()"%'

-- Find commits that modified any struct definitions
SELECT git_sha, subject, author FROM git_commits
WHERE symbols LIKE '%"struct %'

-- Find commits that modified a specific file
SELECT git_sha, subject, author FROM git_commits
WHERE files LIKE '%"mm/kmemleak.c"%'

-- Find commits that modified files in a directory
SELECT git_sha, subject, author FROM git_commits
WHERE files LIKE '%"mm/%'

-- Get full commit details including diff
SELECT git_sha, subject, message, diff, symbols FROM git_commits
WHERE git_sha = 'abc123...'

-- Find commits with multiple parents (merge commits)
SELECT git_sha, subject, author FROM git_commits
WHERE parent_sha LIKE '%,%'

-- Find commits with specific tags (e.g., reviewed commits)
SELECT git_sha, subject, author FROM git_commits
WHERE tags LIKE '%"Reviewed-by"%'

-- Traverse commit history by following parent relationships
SELECT c1.git_sha, c1.subject, c2.git_sha as parent_sha, c2.subject as parent_subject
FROM git_commits c1, git_commits c2
WHERE c1.parent_sha LIKE '%"' || c2.git_sha || '"%'
```

### Cross-shard Content Analysis
```sql
-- Find content usage patterns across shards
-- (This would be done programmatically across all content_N tables)
WITH all_content AS (
  SELECT blake3_hash FROM content_0
  UNION ALL
  SELECT blake3_hash FROM content_1
  -- ... through content_15
)
SELECT COUNT(*) as total_unique_content FROM all_content
```

## Performance Characteristics

- **Single-pass extraction**: All relationships captured during initial Tree-sitter analysis
- **O(log n) lookups**: BTree indices on all key fields including content hashes, line positions, and relationships
- **Content deduplication**: Blake3-based deduplication eliminates redundant storage
- **Efficient filtering**: JSON LIKE queries with proper indexing for relationships
- **Optimized relationship queries**: Dedicated indices on `calls` and `types` columns enable fast dependency analysis
- **Spatial query performance**: Line-based indices (`line_start`, `line_end`) provide efficient location-based searches and sorting
- **Atomic consistency**: Entity metadata stored together, content resolved on-demand
- **Minimal relationship I/O**: No cross-table joins required for call/type relationships
- **Fast content resolution**: Indexed Blake3 hash lookups for content retrieval
- **Parallel shard operations**: Multiple content shards enable concurrent operations
- **Scalable architecture**: Sharding prevents single-table bottlenecks

## Storage Efficiency

- **Multi-level deduplication**:
  - Git SHA-based file content uniqueness prevents duplicate file processing
  - Blake3-based content deduplication eliminates redundant function bodies, type definitions, and macro content
- **Columnar compression**: LanceDB's columnar format with built-in compression
- **Content normalization**: Identical source code patterns stored once regardless of location
- **Selective indexing**: Only function-like macros stored (95%+ noise reduction)
- **Hash-based storage**: Hex string hashes more storage-efficient than repeated text content
- **Automatic compaction**: Data file consolidation and optimization
- **Sharded storage**: Even distribution prevents any single table from becoming oversized

## Architecture Benefits

### Content Deduplication Impact

- **Storage reduction**: 50-80% storage savings for typical C/C++ codebases with repeated patterns
- **Cache efficiency**: Frequently accessed content patterns cached once per shard
- **Write performance**: Content stored once during batch operations across appropriate shards
- **Consistency**: Identical content guaranteed to have identical hash, ensuring data integrity

### Content Sharding Benefits

- **Horizontal Scalability**: Load distributed across 16 independent tables
- **Parallel Processing**: Multiple shards can be queried/updated simultaneously
- **Reduced Contention**: Operations on different shards don't block each other
- **Optimal Table Sizes**: Each shard maintains manageable size for peak performance
- **Fault Isolation**: Issues with one shard don't affect others

### Git Integration Benefits

- **Incremental processing**: Only analyze files that have changed since last indexing
- **Cross-commit analysis**: Track code evolution across git history
- **Content-based identity**: Same content produces same hash regardless of file location
- **Distributed analysis**: Multiple developers can build compatible databases from same git state

### Hex String Storage Benefits

- **Debugging Friendly**: Hex strings are human-readable and easy to debug
- **Cross-platform Compatibility**: Avoids binary data encoding issues
- **Query Simplicity**: Standard string operations and comparisons work directly
- **JSON Serialization**: Hex strings serialize cleanly to JSON without special encoding
