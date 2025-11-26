# Using Claude with semcode

## Patch review prompts

This example will assume you've cloned review-prompts:

https://github.com/masoncl/review-prompts/

There's nothing special about these prompts, but they already have lines using
the semcode MCP server.

## Indexing your kernel repository

semcode indexes individual git shas, and you'll want to index every sha that
you plan on reviewing or debugging.  The most basic way to do this:

```
cd linux
git checkout <sha you want to review>
semcode-index -s .
```

This just indexes the current HEAD, and if that already existed in the database,
it's a no-op.

You can also index a range:
```
cd linux
semcode-index -s . --git v6.16..v6.17
```

Bigger ranges take longer, so it's better to just index what you need.

## Configuring MCP for Claude

claude plugins are the preferred way to configure things, but you can also
setup a json file with details about the MCP server.  The documentation below
describes both.

### Configuring Claude Plugins

For instructions on installing and configuring the semcode Claude plugin, see [../plugin/README.md](../plugin/README.md).

The plugin provides a streamlined way to use semcode with Claude Code.

### Pre-approving Semcode Tools

Claude Code requires explicit approval before MCP tools can be used. To avoid being prompted once per tool, you can pre-approve all semcode tools for a specific directory:

```bash
cd /path/to/semcode
./plugin/semcode/approve-tools.sh /path/to/your/kernel
```

Example:
```bash
./plugin/semcode/approve-tools.sh /src/linux
```

This creates or updates `.claude/settings.local.json` in the specified directory with all semcode tool approvals. Restart Claude if it's currently running for changes to take effect.

**Note**: Tool approvals are per-directory. If you work with multiple codebases, run the script for each one.

For detailed information about tool approval methods and troubleshooting, see [../plugin/semcode/TOOL_APPROVAL.md](../plugin/semcode/TOOL_APPROVAL.md).

### Configuring Claude via the --mcp-config command line option

If claude plugins aren't right for your configuration, passing the mcp config
on the command line is also possible.

```
cat > mcp-config.json << EOF
{"mcpServers":{"semcode":{"command":"/full/path/to/semcode-mcp"}}}
EOF
claude --mcp-config mcp-config.json
```

## Trying it out

Now you can make sure Claude is able to use semcode:

```
claude> func btrfs_submit_bio

● I'll help you find the btrfs_submit_bio function. Let me search for it using the semantic code search tool.

● semcode - find_function (MCP)(name: "btrfs_submit_bio")
  ⎿  Function: btrfs_submit_bio (git SHA: 1367da7eb875d01102d2ed18654b24d261ff5393)
     File: fs/btrfs/bio.c:479-507
     Return Type: void
     … +34 lines (ctrl+o to expand)

● I found the btrfs_submit_bio function! Here's what it does:

  Function Overview

  - Location: fs/btrfs/bio.c, lines 479-507
  - Return Type: void (static function)
  - Parameters:
    - bio: struct bio pointer - the bio to submit
    - bioc: struct btrfs_io_context pointer - btrfs I/O context
    - smap: struct btrfs_io_stripe pointer - stripe mapping info
    - mirror_num: int - mirror number for the operation
```

## A few hints

The review prompts have three main entry points:

### General patch review:

review-core.md: "Using /full/path/to/review-core.md, review the top commit"

### Debug an OOPs, WARN, syzbot report etc:

debugging.md: "Using /full/path/to/debugging.md, analyze the bug in some_file"

### Make Claude check its work:

In an interactive debugging session, Claude's accuracy tends to decline
pretty quickly.  You can fix this by asking really careful questions, or
by constantly ask Claude to verify details, all of which is pretty similar
to the false positive checks done during patch review.

false-positive-guide.md: "Run your current analysis through /full/path/to/false-positive-guide.md"

You can also ask it to always use the false positive guide, but that can
be slow, so you can ask it to use the guide without following the instructions
for checklists or fully systematic checks.  If you put these instructions
into CLAUDE.md, Claude will consistently use them.
