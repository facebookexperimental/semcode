# Semcode MCP Plugin for Claude

A Claude plugin that provides semantic code search capabilities for C/C++ codebases through the Model Context Protocol (MCP).

## Quick Start

### 1. Build and Setup Semcode

```bash
# Build semcode
cd /path/to/semcode
cargo build --release

# Add to your PATH (choose one method)
export PATH="/path/to/semcode/target/release:$PATH"
# OR create symlinks
sudo ln -s /path/to/semcode/target/release/semcode-mcp /usr/local/bin/
sudo ln -s /path/to/semcode/target/release/semcode-index /usr/local/bin/
sudo ln -s /path/to/semcode/target/release/semcode /usr/local/bin/
```

### 2. Index Your Codebase

```bash
cd /path/to/your/code
semcode-index --source .
```

This creates a `.semcode.db` directory in your codebase.

### 3. Install the Plugin

```bash
# Add the marketplace
cd /path/to/semcode
claude plugin marketplace add $(pwd)/plugin/marketplace.json

# Install the plugin
claude plugin install semcode@semcode-local
```

**Important**: Use an absolute path or `$(pwd)` for the marketplace. Relative paths will be interpreted as GitHub URLs.

### 4. Verify Installation

Restart Claude and verify the plugin is working:
```
What semcode tools do you have access to?
```

## Database Location

By default, `semcode-mcp` looks for `.semcode.db` in your current directory. This lets you work with multiple projects:

```bash
cd /path/to/linux
claude    # Uses /path/to/linux/.semcode.db

cd /path/to/another-project
claude    # Uses /path/to/another-project/.semcode.db
```

### Optional: Fixed Database Path

To always use the same database, edit `plugin/semcode/mcp/semcode.json`:

```json
{
  "mcpServers": {
    "semcode": {
      "type": "stdio",
      "command": "semcode-mcp",
      "args": ["--database", "/absolute/path/to/your/codebase"],
      "env": {}
    }
  }
}
```

## Available Tools

The plugin provides these MCP tools for Claude:

- **find_function** - Find functions/macros by name (regex supported)
- **find_type** - Find types, structs, unions, enums, typedefs
- **find_callers** - Find functions that call a specific function
- **find_callees** - Find functions called by a specific function
- **find_callchain** - Build complete call chains (forward and reverse)
- **grep_functions** - Regex search through function bodies
- **vgrep_functions** - Vector embedding search (requires `--vectors` indexing)
- **diff_functions** - Extract functions/types from unified diffs
- **find_commit** - Search commit history by message, symbols, or paths
- **vcommit_similar_commits** - Semantic commit search
- **lore_search** - Search lore.kernel.org email archives
- **dig** - Find lore emails related to a git commit
- **vlore_similar_emails** - Semantic search of lore emails

All operations are git-aware and search at your current HEAD commit by default.

## Documentation

For detailed usage information, see:
- **[docs/semcode-mcp.md](../../docs/semcode-mcp.md)** - Complete tool reference and usage examples
- **[docs/claude-semcode-setup.md](../../docs/claude-semcode-setup.md)** - Advanced Claude configuration
- **[docs/lore.md](../../docs/lore.md)** - Linux kernel email archive integration
- **[docs/schema.md](../../docs/schema.md)** - Database schema details
- **[Main README](../../README.md)** - Project overview and build instructions

## Troubleshooting

### "command not found: semcode-mcp"

Ensure semcode binaries are in your PATH:
```bash
which semcode-mcp
export PATH="/path/to/semcode/target/release:$PATH"
```

For permanent access, add to `~/.bashrc` or `~/.zshrc`.

### "Database not found"

Index your codebase first:
```bash
cd /path/to/your/code
semcode-index --source .
```

### Performance Issues

- Use path patterns to narrow search scope
- Use the `limit` parameter to control result size
- Consider incremental indexing: `semcode-index --source . --git HEAD~10..HEAD`

## Tool Approval

To pre-approve all semcode tools for a directory, use the provided script:

```bash
./plugin/semcode/approve-tools.sh /path/to/your/project
```

See [TOOL_APPROVAL.md](TOOL_APPROVAL.md) for details.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
