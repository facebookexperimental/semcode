# Semcode MCP Configuration

This MCP server provides semantic code search capabilities for C/C++ codebases.

## Default Configuration

The default configuration uses `semcode-mcp` from your PATH with no database argument.
This means it will automatically look for `.semcode.db` in whatever directory Claude is running from.

**How it works:**
- You run Claude from `/path/to/linux`
- Semcode-mcp looks for `/path/to/linux/.semcode.db`
- This allows you to work with different projects without reconfiguring

## Custom Database Path (Advanced)

If you want to use a specific database regardless of where Claude runs from, modify `semcode.json`:

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

## Using Absolute Path to Binary

If `semcode-mcp` is not in your PATH, specify the full path:

```json
{
  "mcpServers": {
    "semcode": {
      "type": "stdio",
      "command": "/home/user/semcode/target/release/semcode-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

## Relative Path (Current Directory)

To explicitly specify current directory:

```json
{
  "mcpServers": {
    "semcode": {
      "type": "stdio",
      "command": "semcode-mcp",
      "args": ["--database", "."],
      "env": {}
    }
  }
}
```

This is equivalent to omitting `--database` entirely.

## Verification

After installation, verify by asking Claude:
```
What semcode tools do you have access to?
```

You should see tools like:
- find_function
- find_type
- find_callers
- find_callees
- find_callchain
- grep_functions
- vgrep_functions
- diff_functions
- find_commit
- vcommit_similar_commits
