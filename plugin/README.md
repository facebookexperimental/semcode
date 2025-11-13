# Semcode Claude Plugin

This directory contains the Claude plugin for semcode MCP server.

## Installation

See **[semcode/README.md](semcode/README.md)** for complete installation and usage instructions.

## Quick Start

```bash
# 1. Build semcode
cd /path/to/semcode
cargo build --release

# 2. Add to PATH
export PATH="/path/to/semcode/target/release:$PATH"

# 3. Index your codebase
cd /path/to/your/code
semcode-index --source .

# 4. Install plugin
cd /path/to/semcode
claude plugin marketplace add $(pwd)/plugin/marketplace.json
claude plugin install semcode@semcode-local

# 5. Restart Claude and verify
# Ask: "What semcode tools do you have access to?"
```

## Directory Structure

```
plugin/
├── README.md           # This file
├── marketplace.json    # Plugin marketplace manifest
└── semcode/           # Plugin implementation
    ├── README.md      # Full installation and usage guide
    ├── TOOL_APPROVAL.md
    ├── approve-tools.sh
    ├── install.sh
    └── mcp/          # MCP server configuration
```

## Documentation

- **[semcode/README.md](semcode/README.md)** - Complete plugin documentation
- **[../../docs/semcode-mcp.md](../docs/semcode-mcp.md)** - Tool reference and examples
- **[../../README.md](../README.md)** - Main project documentation
