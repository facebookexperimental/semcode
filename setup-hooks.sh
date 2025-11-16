#!/bin/bash
# Setup script to enable git hooks for semcode project

echo "Setting up git hooks for semcode..."

# Configure git to use the hooks directory
git config core.hooksPath hooks

if [ $? -eq 0 ]; then
    echo "✓ Git hooks enabled successfully!"
    echo ""
    echo "Active hooks:"
    echo "  • pre-commit: Checks code formatting (cargo fmt)"
    echo "  • pre-push: Runs clippy and tests"
    echo ""
    echo "To disable hooks, run: git config --unset core.hooksPath"
else
    echo "✗ Failed to enable git hooks"
    exit 1
fi
