#!/bin/bash
# LSP debugging wrapper - logs all communication to /tmp/semcode-lsp.log

LOG_FILE="/tmp/semcode-lsp-debug.log"
LSP_BINARY="$(dirname "$0")/../target/release/semcode-lsp"

echo "=== LSP Session Started: $(date) ===" >> "$LOG_FILE"
echo "Arguments: $@" >> "$LOG_FILE"
echo "Working Directory: $(pwd)" >> "$LOG_FILE"
echo "Environment:" >> "$LOG_FILE"
env >> "$LOG_FILE"
echo "===================================" >> "$LOG_FILE"

# Use tee to capture stdin/stdout while passing through
# This logs the JSON-RPC communication
exec 3>&1 4>&2
{
    # Run the LSP server
    SEMCODE_DEBUG=info "$LSP_BINARY" "$@" 2>&1 | tee -a "$LOG_FILE" >&3
} 2>&1 | tee -a "$LOG_FILE" >&4
