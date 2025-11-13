# Tool Approval Guide

## Why Tool Approval is Needed

Claude Code requires explicit approval before MCP tools can be used. This is a security feature to prevent unauthorized code execution.

## Methods to Approve Tools

### Method 1: Interactive Approval (During Use)

When Claude tries to use a semcode tool for the first time, you'll see:

```
Do you want to proceed?
❯ 1. Yes
  2. Yes, and don't ask again for plugin:semcode:semcode - find_function commands in /home/clm/local/linux
  3. No, and tell Claude what to do differently (esc)
```

**Choose option 2** to approve that tool permanently for that directory.

You'll need to do this once per tool (13 times total) unless you pre-approve.

### Method 2: Pre-approve During Installation

When running the install script, you'll be prompted:

```bash
./plugin/semcode/install.sh

# When prompted:
Would you like to pre-approve semcode tools for a specific directory?
Enter directory path: /home/clm/local/linux
```

This will automatically approve all 13 tools for that directory.

### Method 3: Pre-approve After Installation

Use the standalone approval script:

```bash
cd /home/clm/local/src/semcode
./plugin/semcode/approve-tools.sh /home/clm/local/linux
```

This approves all 13 semcode tools for the specified directory.

### Method 4: Manual Approval (Advanced)

Edit `~/.claude.json` directly:

```bash
# Backup first
cp ~/.claude.json ~/.claude.json.backup

# Edit the file
vim ~/.claude.json
```

Find the project section and add tools to `allowedTools`:

```json
{
  "projects": {
    "/home/clm/local/linux": {
      "allowedTools": [
        "mcp__semcode__find_function",
        "mcp__semcode__find_type",
        "mcp__semcode__find_callers",
        "mcp__semcode__find_calls",
        "mcp__semcode__find_callchain",
        "mcp__semcode__diff_functions",
        "mcp__semcode__grep_functions",
        "mcp__semcode__vgrep_functions",
        "mcp__semcode__find_commit",
        "mcp__semcode__vcommit_similar_commits",
        "mcp__semcode__lore_search",
        "mcp__semcode__dig",
        "mcp__semcode__vlore_similar_emails"
      ],
      ...
    }
  }
}
```

## Complete Tool List

These are all 13 semcode tools that need approval:

1. `mcp__semcode__find_function` - Find functions/macros
2. `mcp__semcode__find_type` - Find types/structs
3. `mcp__semcode__find_callers` - Find callers
4. `mcp__semcode__find_calls` - Find callees
5. `mcp__semcode__find_callchain` - Build call chains
6. `mcp__semcode__diff_functions` - Extract from diffs
7. `mcp__semcode__grep_functions` - Regex search
8. `mcp__semcode__vgrep_functions` - Semantic search
9. `mcp__semcode__find_commit` - Find commits
10. `mcp__semcode__vcommit_similar_commits` - Semantic commit search
11. `mcp__semcode__lore_search` - Search email archives
12. `mcp__semcode__dig` - Find emails for commit
13. `mcp__semcode__vlore_similar_emails` - Semantic email search

## Per-Directory Approval

Tool approvals are **per-directory**. If you approve tools for `/home/clm/local/linux`, you'll need to approve them again for `/home/clm/local/another-project`.

To approve for multiple directories:

```bash
./plugin/semcode/approve-tools.sh /home/clm/local/linux
./plugin/semcode/approve-tools.sh /home/clm/local/btrfs
./plugin/semcode/approve-tools.sh /home/clm/projects/myproject
```

## Verifying Approval

Check your current approvals:

```bash
cat ~/.claude.json | jq '.projects["/home/clm/local/linux"].allowedTools'
```

Should show all 13 tools.

## Troubleshooting

**Issue**: Tools still asking for approval after pre-approval

**Solution**: Restart Claude Code. Changes to `~/.claude.json` only take effect after restart.

**Issue**: `jq: command not found`

**Solution**: Install jq:
```bash
sudo apt-get install jq
```

**Issue**: Accidentally broke ~/.claude.json

**Solution**: Restore from backup:
```bash
cp ~/.claude.json.backup ~/.claude.json
```

## Security Implications

Approving tools allows Claude to:
- Read your codebase database
- Execute semcode-mcp binary
- Search code, commits, and emails

This is **read-only access** to your indexed data. Semcode cannot:
- Modify your source code
- Execute arbitrary commands
- Access files outside the database

Pre-approving is safe for directories you trust and have already indexed.
