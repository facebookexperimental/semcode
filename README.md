# Semcode - Semantic Code Search

Semcode is a semantic code search tool for C/C++ codebases that indexes your
codebase and allows you to search for functions, types, and code patterns using
both exact matches and semantic similarity.

## News

Rust indexing is now supported.  This just uses treesitter, but all the
semcode features are there.

Now with lore indexing!  semcode-index --lore lkml (or any list name) will
pull down the latest git archive from that list.  See [the lore documentation](docs/lore.md)
for more details.  This is a database schema change, so you'll need to reindex.

Recent commits introduced indexes for git commit history, as well as
performance improvements.  Unfortunately, these are a schema change and
you'll need to reindex your database.

## Features

- **Fast indexing** of C/C++ codebases using Tree-sitter
- **Interactive query interface** with comprehensive command set
- **Call graph analysis** with forward/reverse traversal
- **Type and macro discovery** with detailed structural information
- **Diff analysis** for understanding code changes and their impact
- **Pattern matching**
- **MCP server** for integration with AI code tools
- **GIT integration** for incremental scans of new commits

While semcode provides both a query tool and an MCP server, the primary use
case is via the MCP server.  It gives AI code tools the ability to quickly
find context about the kernel, and generally makes them more effective.

The MCP server can also be used by
[Kernel AI Review Prompts](https://github.com/masoncl/review-prompts)

## Future features

- **lore.kernel.org index** via git for searching mailing list archives

## Quick Start

### Dependencies

```
Install protobuf-devel from your distro

**Rust:**
Install from [rustup.rs](https://rustup.rs/)

### Build

```bash
# Clone and build
git clone <repository-url>
cd semcode
cargo build --release
```

Binaries end up in target/release

### Basic Usage

```bash
# Index a codebase

cd linux
semcode-index -s .

This assumes you have a linux git repo, and it puts the semcode database
into linux/.semcode.db (in the source directory)

# Start interactive query tool
semcode
```

You can index git ranges as well:
```bash
semcode-index -s . --git v6.14..v6.15
```

Once a git range is indexed, you can either use the --git arguments with
individual commands in the query tools, or git checkout some_sha and run
the query tool.  It'll grab the current HEAD and return results against it.

Type `help` in the interactive shell for complete command documentation. Here
are the most common commands:

**Function and Macro Search:**

func truncates the list of calls/callers by default, -v gives you everything

```
semcode> func printk                      # Find function by name
semcode> f EXPORT_SYMBOL                  # Find macro (short form)
semcode> function mutex_lock              # Find function (long form)
semcode> function btrfs_search.*          # Find function regex
```

**Type and Typedef Search:**
```
semcode> type struct task_struct          # Find struct by name
semcode> ty size_t                        # Find typedef (short form)
semcode> type pthread_mutex_t             # Find type by name
```

**Call Graph Analysis:**

These functions all have -v to show you paths and git file shas

```
semcode> callers mutex_lock               # Show what calls mutex_lock
semcode> calls schedule                 # Show what schedule calls
semcode> callchain kmalloc                # Show complete call graph
```

**Commit searching**:

You can search through all the commits, or through commit ranges.  There
are options for path regex (-p), symbol regex (-s) and verbose dumping of
the commit diff (-v).

**Note**: All regex patterns in semcode are **case-insensitive by default**, including commit message searches, symbol patterns, and path patterns.

```
semcode> commit HEAD                      # show the HEAD commit
semcode> commit --git v6.16..v6.17 -s kmalloc # search for kmalloc in range
semcode> commit -p fs.btrfs -r filemap        # search fs/btrfs for commits mentioning filemap
```

**Semantic Commit searching (requires vectors)**:
All the same options as commit searching, but uses the embedded vectors.  You
can optionally add regex on top to filter the results.

Semantic searches are better for topics that aren't well suited to regex, such
as find all the interface changes, or all the performance fixes.

```
semcode> vcommit -p fs.btrfs "all the interface changes"
```

**Semantic Search (requires vectors):**
```
semcode> vgrep btrfs search slot
```

**Data Export:**
```
semcode> dump-functions functions.json    # Export all functions
semcode> df funcs.json                    # Export functions (short form)
semcode> dump-types types.json            # Export all types
semcode> dt types.json                    # Export types (short form)
semcode> dump-typedefs typedefs.json      # Export all typedefs
semcode> dump-macros macros.json          # Export all macros
semcode> tables                           # Show available data tables
```

**General Commands:**
```
semcode> help                             # Show complete help with examples
semcode> h                                # Show help (short form)
semcode> quit                             # Exit the program
semcode> q                                # Exit (short form)
```

## More Usage guides

Setting up semcode with claude: [docs/claude-semcode-setup.md](docs/claude-semcode-setup.md)

Doing patch review in the kernel: [docs/claude-patch-review.md](docs/claude-patch-review.md)

## Data Storage

Semcode uses [LanceDB](https://lancedb.com/) to store:
- **Functions** with signatures, bodies, call relationships, and optional embeddings
- **Types** (structs, unions, enums) with field information
- **Typedefs** with underlying type mappings
- **Macros** (function-like only, for better signal-to-noise ratio)

## Configuration

## Performance Tuning

Use the `-j` flag to control parallelism:

The default is to try and saturate your cpus.

### Proxy Support

The model setup script honors standard proxy environment variables:

```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
python scripts/direct_download.py
```

## MCP (Model Context Protocol) Server

Semcode includes an MCP server that exposes its query functionality to AI agents like Claude:

The MCP server provides these tools:

**Basic Search:**
- `find_function` - Find functions and macros by exact name
- `find_type` - Find types, structs, and typedefs by exact name

**Call Graph Analysis:**
- `find_callers` - Find all functions that call a specific function
- `find_callees` - Find all functions called by a specific function  
- `find_callchain` - Show complete call chain for a function
- `diff_functions` - Extract and list functions from a unified diff
- `grep_functions` - regex searches through function bodies
- `vgrep_functions` - vector searches through function bodies

### MCP Configuration

Check your claude documentation on this one, but it is setup for one
semcode-mcp server per claude instance.

cd linux
semcode-index -s .
claude --mcp-config mcp-config.json
> func btrfs_search_slot

mcp-config.json:

{"mcpServers":{"semcode":{"command":"/some_path/semcode-mcp"}}}

See examples/mcp-config.json for an example file

#### Verify MCP Tools Are Available

Ask Claude to list available tools:
```
User: "What semcode tools do you have access to?"
User: "What semcode-myproject tools are available?" # For specific server
```
#### Configuration Options

**Required:**
- `command`: Absolute path to `semcode-mcp` binary
**Optional:**
- `args`: `--database` with path to your indexed database or `--git` for the repo

#### Manual Testing

You can test the MCP server outside of Claude:

```bash
# Start the MCP server manually
./bin/semcode-mcp --database /path/to/your.db

# It will wait for JSON-RPC input on stdin
# Press Ctrl+C to exit
```

**Security Notes:**
- The MCP server operates in read-only mode
- It only accesses the pre-indexed database files
- All queries are logged to stderr for debugging

### Model Setup (for vector search)

Note: this is mostly untested, and not required for general usage.  I've been
trying nomic v2 and running it through model2vec to make things faster without
a GPU.  There are scripts:

pip3 install -r scripts/requirements.txt
scripts/direct_download.py
scripts/nomic2vec.py

Take the resulting model directory and move it to ~/.cache/semcode/models/model2vec.

Then do a index run:
semcode-index -s .

Then do a vector run:
semcode-index -s . --vectors

Then you can do vector searches with the vgrep command either in the
query tool or MCP.

### Model Storage

This is only relevant for vector searching

Models are stored in:
`~/.cache/semcode/models/`

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

