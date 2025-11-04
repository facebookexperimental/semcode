# Lore Email Archive Search Guide

This guide explains how to use semcode's lore.kernel.org email archive search features in both the query tool and the MCP server.

## Overview

Semcode can index and search lore.kernel.org email archives, providing Full Text Search (FTS) with regex post-filtering and semantic search capabilities across mailing list archives. This is particularly useful for finding discussions about specific commits, patches, or topics in kernel development.

## How It Works: FTS + Regex Hybrid Approach

All lore searches use a two-phase approach for fast, precise results:

1. **Phase 1: FTS (Full Text Search)** - Fast keyword-based search using inverted indices
   - Patterns are normalized by extracting keywords (special chars stripped)
   - Example: `"[PATCH v2]"` → `"PATCH v2"` for FTS
   - Returns a superset of candidates very quickly

2. **Phase 2: Regex Post-Filter** - Precise filtering in memory
   - Original regex pattern applied to FTS results
   - Ensures exact matching (e.g., `"clm@meta.com"` matches exactly)
   - Fast because operating on small FTS result set

## Setup: Indexing a Lore Archive

Before searching, you need to clone and index a lore archive:

```bash
# Index a lore archive (e.g., linux kernel mailing list)
semcode-index --lore https://lore.kernel.org/lkml/0

# The archive will be cloned to <db_dir>/lore/<repo_name>
# In this example: .semcode.db/lore/linux-kernel
```

### Optional: Generate Vector Embeddings for Semantic Search

To enable semantic search with the `vlore` command:

```bash
# Generate vector embeddings for indexed emails
semcode-index --lore https://lore.kernel.org/linux-kernel --vectors
```

Note: Vector generation is optional but required for the `vlore` command.

## Query Tool Commands

### 1. `lore` - Search Emails by Field

Search lore emails using regex patterns on different fields (from, subject, body, recipients, symbols).

**Syntax:**
```
lore [-v] [-m <message_id>] [-f <regex>] [-s <regex>] [-b <regex>] [-t <regex>] [-g <regex>] [--limit <N>] [--thread] [-o <output_file>]
```

**Options:**
- `-v` - Verbose mode: show full message bodies
- `-m <message_id>` - Look up a specific email by Message-ID
- `-f <regex>` - Filter by From address (can be specified multiple times)
- `-s <regex>` - Filter by Subject line (can be specified multiple times)
- `-b <regex>` - Filter by message Body (can be specified multiple times)
- `-t <regex>` - Filter by recipients (To/Cc) (can be specified multiple times)
- `-g <regex>` - Filter by symbols mentioned in any patches (can be specified multiple times)
- `--limit <N>` - Maximum number of results (default: 100)
- `--thread` - Show full email threads for each match
- `-o <output_file>` - Write output to file instead of stdout

**Filter Logic:**
- Multiple filters for the **same field** are combined with **OR** logic
  - Example: `-f torvalds -f gregkh` matches emails from torvalds OR gregkh
- Filters for **different fields** are combined with **AND** logic
  - Example: `-f torvalds -b btrfs` matches emails from torvalds AND body contains btrfs

**Regex Tips:**
- For multiline matching (e.g., matching start of line within email body), use the `(?m)` flag
  - Example: `-b '(?m)^Signed-off-by'` matches "Signed-off-by" at the start of any line
  - Without `(?m)`, `^` and `$` only match the start/end of the entire field
- Use `(?i)` for case-insensitive matching: `-s '(?i)patch'` matches "patch", "PATCH", "Patch"

**Examples:**

```bash
# Search by subject
lore -s "memory leak"

# Search with verbose output and limit
lore -v -s "performance" --limit 50

# Search by sender
lore -f "torvalds@linux-foundation.org"

# Search by recipient
lore -t "netdev@vger.kernel.org"

# Search message body
lore -b "Signed-off-by.*Linus"

# Search by symbols mentioned in patches
lore -g "malloc"
lore -g "struct.*page"

# Look up specific email by Message-ID
lore -m "<20241201120000.12345@kernel.org>"

# Show threads
lore -v -f "torvalds" --thread
lore -v -s "memory leak" --thread --limit 5

# Combine filters (AND across fields)
lore -b btrfs -f clm@meta.com              # Body contains btrfs AND from clm@meta.com
lore -f torvalds -f gregkh -b "memory leak" # From torvalds OR gregkh AND body contains memory leak
lore -g "schedule.*" -f "torvalds"         # Symbols match schedule.* AND from torvalds

# Write output to file
lore -v -s "memory leak" -o results.txt    # Save verbose results to file
lore -f torvalds --thread -o threads.txt   # Save thread view to file
```

**Output Format:**
- Summary view (default): Date, subject, from, Message-ID, and threading info
- Verbose view (`-v`): Includes full message body
- Thread view (`--thread`): Shows complete email threads in chronological order

---

### 2. `dig` - Find Emails Related to a Git Commit

Search for lore emails related to a specific git commit by matching the commit's subject line. Results are ordered by date (newest first).

**Syntax:**
```
dig [-v] [-a] [--thread] <commit>
```

**Options:**
- `-v` - Verbose mode: show full message bodies
- `-a` - Show all matching emails (default: only most recent)
- `--thread` - Show full email threads for each match
- `<commit>` - Any git reference (SHA, short SHA, branch name, HEAD, etc.)

**Examples:**

```bash
# Show most recent match thread for HEAD commit
dig HEAD

# Show most recent match with message body
dig -v abc123

# Show all matches (summary)
dig -a v6.5

# Show all matches with full threads
dig -a --thread HEAD

# Show all matches with threads and bodies
dig -v -a --thread abc123
```

**How It Works:**
1. Resolves the git reference to a commit SHA
2. Extracts the commit's subject line
3. Searches lore emails for exact subject matches
4. Shows results ordered by date (newest first)
5. By default shows only the most recent match; use `-a` to see all

**Use Cases:**
- Find mailing list discussion about a specific patch
- See review feedback for a commit
- Track the history of how a patch evolved from email to merge

---

### 3. `vlore` - Semantic Vector Search

Search for lore emails similar to the provided text using semantic vector embeddings. This allows you to find conceptually related discussions even when exact keywords don't match.

**Syntax:**
```
vlore [-f <from_regex>] [-s <subject_regex>] [-b <body_regex>] [-g <symbols_regex>] [-t <recipients_regex>] [--limit <N>] <query_text>
```

**Options:**
- `-f <from_regex>` - Filter results by From address (can be specified multiple times)
- `-s <subject_regex>` - Filter results by Subject (can be specified multiple times)
- `-b <body_regex>` - Filter results by message Body (can be specified multiple times)
- `-g <symbols_regex>` - Filter results by symbols mentioned in patches (can be specified multiple times)
- `-t <recipients_regex>` - Filter results by Recipients/To/Cc (can be specified multiple times)
- `--limit <N>` - Maximum number of results (default: 20, max: 100)
- `<query_text>` - Search query (required)

**Prerequisites:**
Vector embeddings must be generated first:
```bash
semcode-index --lore <url> --vectors
```

**Examples:**

```bash
# Basic semantic search
vlore "memory leak fix"

# With custom limit
vlore --limit 10 "performance optimization"

# Filter by sender
vlore -f "torvalds" "merge pull request"

# Multiple subject filters (OR logic)
vlore -s "RFC" -s "PATCH" "new feature"

# Body filter
vlore -b "Signed-off-by.*Linus" "kernel patch"

# Symbol filter
vlore -g "malloc" "memory management"

# Recipients filter
vlore -t "netdev@vger.kernel.org" "network patch"
```

**When to Use Semantic vs Regex Search:**
- Use `vlore` for: Finding conceptually similar discussions, broad topic searches, when you're not sure of exact keywords
- Use `lore` for: Exact pattern matching, specific authors or subjects, precise filtering

---

### 4. `dump-lore` (alias: `dlore`) - Export All Emails

Export all indexed lore emails to a JSON file for external processing.

**Syntax:**
```
dump-lore <output_file>
```

**Example:**
```bash
dump-lore emails.json
```

**Output Format:**
JSON array of email objects with fields: message_id, subject, from, date, body, recipients, in_reply_to, references.

---

## MCP Server Tools

The semcode MCP server exposes the same lore search functionality for use with Claude Desktop and other MCP clients.

### MCP Tool: `lore_search`

Search lore emails with regex filters. Same functionality as the query tool's `lore` command.

**Parameters:**
- `message_id` (string, optional) - Specific Message-ID to look up
- `from_patterns` (array of strings, optional) - From address regex patterns (OR logic)
- `subject_patterns` (array of strings, optional) - Subject regex patterns (OR logic)
- `body_patterns` (array of strings, optional) - Body regex patterns (OR logic)
- `recipient_patterns` (array of strings, optional) - Recipient regex patterns (OR logic)
- `symbols_patterns` (array of strings, optional) - Symbols regex patterns (OR logic)
- `limit` (number, optional) - Maximum results (default: 100)
- `verbose` (boolean, optional) - Show full message bodies (default: false)
- `show_thread` (boolean, optional) - Show full threads (default: false)

**Example Usage in Claude Desktop:**

When you ask Claude to search lore archives, it will automatically use this tool:

```
"Search lore for emails from Linus Torvalds about btrfs"
"Find emails with subject containing 'memory leak' and show threads"
"Look up email with message_id <20241201120000.12345@kernel.org>"
```

---

### MCP Tool: `dig`

Search for lore emails related to a git commit. Same functionality as the query tool's `dig` command.

**Parameters:**
- `commit` (string, required) - Git reference (SHA, short SHA, branch, HEAD, etc.)
- `verbose` (boolean, optional) - Show full message bodies (default: false)
- `show_all` (boolean, optional) - Show all matches vs most recent (default: false)
- `show_thread` (boolean, optional) - Show full threads (default: false)

**Example Usage in Claude Desktop:**

```
"Find lore emails related to commit abc123"
"Show all lore discussions about HEAD commit with threads"
```

---

### MCP Tool: `vlore_similar_emails`

Semantic vector search for similar lore emails. Same functionality as the query tool's `vlore` command.

**Parameters:**
- `query_text` (string, required) - Search query
- `from_patterns` (array of strings, optional) - From address filters
- `subject_patterns` (array of strings, optional) - Subject filters
- `body_patterns` (array of strings, optional) - Body filters
- `symbols_patterns` (array of strings, optional) - Symbols filters
- `recipients_patterns` (array of strings, optional) - Recipients/To/Cc filters
- `limit` (number, optional) - Maximum results (default: 20, max: 100)
- `verbose` (boolean, optional) - Show full message bodies (default: false)

**Prerequisites:**
Vector embeddings must be generated with `semcode-index --lore <url> --vectors`.

**Example Usage in Claude Desktop:**

```
"Find lore emails similar to 'memory leak fix'"
"Search for emails like 'performance optimization' from Linus"
```

---

## Database Schema

Lore emails are stored in the `lore` table with the following structure:

| Field | Type | Description |
|-------|------|-------------|
| message_id | string | Unique Message-ID (primary key) |
| subject | string | Email subject line |
| from | string | Sender email address |
| date | string | ISO 8601 timestamp |
| body | string | Full message body (headers stripped) |
| recipients | string | Comma-separated To/Cc recipients |
| symbols | JSON array | List of symbols (functions, types, macros) extracted from patches |
| in_reply_to | string | Message-ID of parent email (if reply) |
| references | string | Space-separated Message-IDs of thread ancestors |
| git_commit_subject | string | Extracted commit subject (for patches) |
| commit_sha | string | Git SHA (for patches) |

Vector embeddings (if generated) are stored in the `lore_vectors` table.

---

## Common Use Cases

### Finding Patch Discussion
```bash
# Find discussion about a specific commit
dig abc123

# See all versions and reviews
dig -a --thread abc123
```

### Tracking Maintainer Communication
```bash
# All emails from a specific maintainer about a topic
lore -f "torvalds@" -b "btrfs"

# Show full threads
lore -f "torvalds@" -b "btrfs" --thread
```

### Research Topic History
```bash
# Semantic search for broad topic
vlore "memory management improvements"

# Exact pattern search
lore -s "mm:" -b "page.*allocation"
```

### Analyzing Patch Series
```bash
# Find all patches in a series
lore -s "\[PATCH.*\]" -f "developer@example.com" --limit 50

# Show as threads to see review flow
lore -s "\[PATCH v2" --thread
```

### Finding Patches by Symbol
```bash
# Find patches that modify a specific function
lore -g "malloc"

# Find patches touching memory management structures
lore -g "struct.*page"

# Combine symbol search with other filters
lore -g "schedule.*" -f "torvalds"
lore -g "mutex_lock" -s "\[PATCH" --limit 20

# Find patches modifying multiple related symbols (OR logic)
lore -g "kmalloc" -g "kfree" -g "vmalloc"
```

---

## Tips and Best Practices

1. **Start broad, then narrow**: Use semantic search (`vlore`) to find topics, then use regex search (`lore`) for precision

2. **Use threading wisely**: The `--thread` flag is powerful but verbose. Use it when you need full context, not for initial exploration

3. **Leverage git integration**: The `dig` command is the easiest way to find discussion about commits you're already looking at in git

4. **Combine filters effectively**: Remember that same-field filters use OR logic, while different-field filters use AND logic

5. **Watch your limits**: Large result sets can be overwhelming. Use `--limit` to control output size

6. **Message-ID lookups**: If you see an interesting Message-ID in results, use `lore -m <message_id>` to view the full email

7. **Export for analysis**: Use `dump-lore` when you need to process emails with external tools or scripts

---

## Troubleshooting

### "No lore table found"
You need to index a lore archive first:
```bash
semcode-index --lore https://lore.kernel.org/linux-kernel
```

### "No similar emails found" with vlore
Vector embeddings need to be generated:
```bash
semcode-index --lore <url> --vectors
```

### "No matching emails found"
- Check your regex patterns - they may be too restrictive
- Try broadening your search or removing some filters
- Use semantic search (`vlore`) if regex isn't finding what you need

### "Column has no inverted index" error
FTS indices need to be created after indexing:
```bash
# FTS indices are automatically created during --lore indexing
# If you see this error, re-run the indexing
rm -rf .semcode.db
semcode-index --lore <url>
```

### Message-ID lookup tips
You can omit the `< >` brackets when using `-m`:
```bash
lore -m message.id@domain.com       # Works
lore -m <message.id@domain.com>     # Also works
```

---

## See Also

- [MCP Server Documentation](semcode-mcp.md) - Full MCP server setup and usage
- [Schema Documentation](schema.md) - Complete database schema details
- [Query Tool Guide](../CLAUDE.md) - General query tool usage
