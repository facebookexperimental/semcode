#!/bin/bash
# Installation script for semcode Claude plugin

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PLUGIN_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"
PLUGIN_NAME="semcode"
MARKETPLACE_NAME="semcode-local"

echo "=== Semcode Claude Plugin Installation ==="
echo

# Check if claude command exists
if ! command -v claude &> /dev/null; then
    echo "✗ Error: 'claude' command not found"
    echo "  Please ensure Claude Code is installed and in your PATH"
    exit 1
fi

echo "✓ Found claude command"
echo

# Check if semcode-mcp binary exists in PATH
if command -v semcode-mcp &> /dev/null; then
    MCP_BINARY="semcode-mcp"
    MCP_PATH=$(command -v semcode-mcp)
    echo "✓ Found semcode-mcp in PATH at: $MCP_PATH"
elif [ -f "$SCRIPT_DIR/../../target/release/semcode-mcp" ]; then
    echo "✗ Error: semcode-mcp found in target/release but not in PATH"
    echo "  Please add semcode binaries to your PATH:"
    echo "    export PATH=\"$SCRIPT_DIR/../../target/release:\$PATH\""
    echo "  Or add to your ~/.bashrc or ~/.zshrc for permanent access"
    exit 1
else
    echo "✗ Error: semcode-mcp binary not found"
    echo "  Please build semcode first:"
    echo "    cd $SCRIPT_DIR/../.. && cargo build --release"
    echo "  Then add it to your PATH:"
    echo "    export PATH=\"$SCRIPT_DIR/../../target/release:\$PATH\""
    exit 1
fi

echo

# Step 1: Add marketplace
echo "Step 1: Adding marketplace to Claude..."
if claude plugin marketplace add "$PLUGIN_DIR/marketplace.json"; then
    echo "✓ Marketplace added successfully"
else
    echo "⚠ Warning: Marketplace may already be added (this is OK)"
fi

echo

# Step 2: Install plugin
echo "Step 2: Installing plugin..."
if claude plugin install "$PLUGIN_NAME@$MARKETPLACE_NAME"; then
    echo "✓ Plugin installed successfully"
else
    echo "⚠ Warning: Plugin may already be installed (this is OK)"
fi

echo

# Step 3: Configure database
echo "Step 3: Configure database location"
echo
echo "How do you want to configure the database location?"
echo
echo "Options:"
echo "  1. Auto-detect from current directory (RECOMMENDED)"
echo "     Uses ./.semcode.db from wherever you run Claude"
echo "     Allows working with multiple projects"
echo
echo "  2. Specify a fixed absolute path"
echo "     Always uses the same database regardless of where Claude runs"
echo
read -p "Enter choice [1-2]: " choice

case $choice in
    1)
        DB_PATH=""
        echo "✓ Will use ./.semcode.db from Claude's working directory"
        ;;
    2)
        read -p "Enter full path to database or directory: " DB_PATH
        # Expand tilde if present
        DB_PATH="${DB_PATH/#\~/$HOME}"
        if [ ! -d "$DB_PATH" ] && [ ! -d "$DB_PATH/.semcode.db" ]; then
            echo "⚠ Warning: Path not found, but will proceed with configuration"
        fi
        ;;
    *)
        echo "Invalid choice, using auto-detect (option 1)"
        DB_PATH=""
        ;;
esac

# Update MCP configuration if database path is provided
if [ -n "$DB_PATH" ]; then
    MCP_CONFIG="$SCRIPT_DIR/mcp/semcode.json"
    echo
    echo "Updating MCP configuration at: $MCP_CONFIG"

    # Create new config with database path
    cat > "$MCP_CONFIG" << EOF
{
  "mcpServers": {
    "semcode": {
      "type": "stdio",
      "command": "$MCP_BINARY",
      "args": ["--database", "$DB_PATH"],
      "env": {}
    }
  }
}
EOF
    echo "✓ Configuration updated"
else
    # No database path specified, create config without --database arg
    MCP_CONFIG="$SCRIPT_DIR/mcp/semcode.json"
    echo
    echo "Creating MCP configuration without database path: $MCP_CONFIG"

    cat > "$MCP_CONFIG" << EOF
{
  "mcpServers": {
    "semcode": {
      "type": "stdio",
      "command": "$MCP_BINARY",
      "args": [],
      "env": {}
    }
  }
}
EOF
    echo "✓ Configuration created (will use working directory)"
fi

echo
echo "=== Tool Approval (Optional) ==="
echo
echo "Would you like to pre-approve semcode tools for a specific directory?"
echo "This will skip permission prompts when using semcode in that directory."
echo
read -p "Enter directory path (or press Enter to skip): " APPROVE_DIR

if [ -n "$APPROVE_DIR" ]; then
    # Expand tilde if present
    APPROVE_DIR="${APPROVE_DIR/#\~/$HOME}"

    # Normalize path
    APPROVE_DIR=$(realpath "$APPROVE_DIR" 2>/dev/null || echo "$APPROVE_DIR")

    echo
    echo "Pre-approving semcode tools for: $APPROVE_DIR"

    # List of all semcode tools
    TOOLS=(
        "mcp__semcode__find_function"
        "mcp__semcode__find_type"
        "mcp__semcode__find_callers"
        "mcp__semcode__find_calls"
        "mcp__semcode__find_callchain"
        "mcp__semcode__diff_functions"
        "mcp__semcode__grep_functions"
        "mcp__semcode__vgrep_functions"
        "mcp__semcode__find_commit"
        "mcp__semcode__vcommit_similar_commits"
        "mcp__semcode__lore_search"
        "mcp__semcode__dig"
        "mcp__semcode__vlore_similar_emails"
    )

    # Use jq to update the allowedTools array for the project
    if command -v jq &> /dev/null; then
        # Backup first
        cp ~/.claude.json ~/.claude.json.backup

        # Create a temporary file
        TEMP_FILE=$(mktemp)

        # Build the jq command to add tools
        jq --arg dir "$APPROVE_DIR" \
           --argjson tools "$(printf '%s\n' "${TOOLS[@]}" | jq -R . | jq -s .)" \
           '.projects[$dir].allowedTools = ($tools + (.projects[$dir].allowedTools // []) | unique)' \
           ~/.claude.json > "$TEMP_FILE"

        # Replace the original file
        mv "$TEMP_FILE" ~/.claude.json

        echo "✓ Pre-approved all semcode tools for $APPROVE_DIR"
        echo "✓ Backup saved to ~/.claude.json.backup"
    else
        echo "⚠ Warning: jq not found, skipping tool pre-approval"
        echo "  Install jq with: sudo apt-get install jq"
        echo "  Or use: ./approve-tools.sh $APPROVE_DIR"
    fi
else
    echo "Skipped tool pre-approval"
    echo "You can approve tools later with:"
    echo "  $SCRIPT_DIR/approve-tools.sh /path/to/your/project"
fi

echo
echo "=== Installation Complete! ==="
echo
echo "Next steps:"
echo "1. Restart Claude Code if it's currently running"
echo "2. Verify installation by asking Claude:"
echo "   'What semcode tools do you have access to?'"
echo
echo "You should see tools like:"
echo "  - find_function"
echo "  - find_type"
echo "  - find_callers"
echo "  - find_callees"
echo "  - grep_functions"
echo "  - find_commit"
echo
echo "For usage examples and tool reference, see:"
echo "  $SCRIPT_DIR/../../docs/semcode-mcp.md"
echo
echo "To reconfigure the database path, edit:"
echo "  $SCRIPT_DIR/mcp/semcode.json"
echo
echo "To pre-approve tools for additional directories:"
echo "  $SCRIPT_DIR/approve-tools.sh /path/to/directory"
echo

echo
echo "Installation complete!"
