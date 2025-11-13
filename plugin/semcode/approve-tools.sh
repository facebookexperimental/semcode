#!/bin/bash
# Approve semcode tools for a specific directory

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <directory>"
    echo "Example: $0 /home/clm/local/linux"
    exit 1
fi

APPROVE_DIR="$1"

# Expand tilde if present
APPROVE_DIR="${APPROVE_DIR/#\~/$HOME}"

# Normalize path
APPROVE_DIR=$(realpath "$APPROVE_DIR" 2>/dev/null || echo "$APPROVE_DIR")

echo "Pre-approving semcode tools for: $APPROVE_DIR"

# List of all semcode tools
TOOLS=(
    "mcp__plugin_semcode_semcode__find_function"
    "mcp__plugin_semcode_semcode__find_type"
    "mcp__plugin_semcode_semcode__find_callers"
    "mcp__plugin_semcode_semcode__find_calls"
    "mcp__plugin_semcode_semcode__find_callchain"
    "mcp__plugin_semcode_semcode__diff_functions"
    "mcp__plugin_semcode_semcode__grep_functions"
    "mcp__plugin_semcode_semcode__vgrep_functions"
    "mcp__plugin_semcode_semcode__find_commit"
    "mcp__plugin_semcode_semcode__vcommit_similar_commits"
    "mcp__plugin_semcode_semcode__lore_search"
    "mcp__plugin_semcode_semcode__dig"
    "mcp__plugin_semcode_semcode__vlore_similar_emails"
)

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    echo "Install with: sudo apt-get install jq"
    exit 1
fi

# Create .claude directory if it doesn't exist
CLAUDE_DIR="$APPROVE_DIR/.claude"
if [ ! -d "$CLAUDE_DIR" ]; then
    mkdir -p "$CLAUDE_DIR"
    echo "Created directory: $CLAUDE_DIR"
fi

# Path to settings file
SETTINGS_FILE="$CLAUDE_DIR/settings.local.json"

# Backup existing file if it exists
if [ -f "$SETTINGS_FILE" ]; then
    cp "$SETTINGS_FILE" "$SETTINGS_FILE.backup"
    echo "✓ Backup saved to $SETTINGS_FILE.backup"
fi

# Create a temporary file
TEMP_FILE=$(mktemp)

# Build the new settings structure
if [ -f "$SETTINGS_FILE" ]; then
    # Merge with existing file
    jq --argjson tools "$(printf '%s\n' "${TOOLS[@]}" | jq -R . | jq -s .)" \
       '.permissions.allow = ($tools + (.permissions.allow // []) | unique)' \
       "$SETTINGS_FILE" > "$TEMP_FILE"
else
    # Create new file
    jq -n --argjson tools "$(printf '%s\n' "${TOOLS[@]}" | jq -R . | jq -s .)" \
       '{permissions: {allow: $tools, deny: [], ask: []}}' > "$TEMP_FILE"
fi

# Replace the file
mv "$TEMP_FILE" "$SETTINGS_FILE"

echo "✓ Pre-approved all semcode tools for $APPROVE_DIR"
echo "✓ Settings saved to $SETTINGS_FILE"
echo
echo "All 13 semcode tools are now pre-approved for $APPROVE_DIR"
echo "Restart Claude if it's currently running for changes to take effect"
