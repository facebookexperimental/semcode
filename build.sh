#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0

# Build script for semcode project

set -e

echo "=== Building Semcode ==="

# Check for required dependencies
echo "Checking dependencies..."

if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo not found. Please install Rust."
    exit 1
fi

if ! pkg-config --exists clang; then
    echo "Warning: libclang not found via pkg-config"
    echo "Make sure you have installed clang development libraries:"
    echo "  Ubuntu/Debian: sudo apt-get install libclang-dev"
    echo "  Fedora: sudo dnf install clang-devel"
    echo "  macOS: brew install llvm"
fi

if ! command -v protoc &> /dev/null; then
    echo "Error: protoc (Protocol Buffers compiler) not found."
    echo "This is required by LanceDB. Please install it:"
    echo "  Ubuntu/Debian: sudo apt-get install protobuf-compiler libprotobuf-dev"
    echo "  Fedora: sudo dnf install protobuf-compiler protobuf-devel"
    echo "  macOS: brew install protobuf"
    echo "  Or download from: https://github.com/protocolbuffers/protobuf/releases"
    exit 1
else
    # Check if protobuf includes are available
    if ! protoc --version > /dev/null 2>&1; then
        echo "Error: protoc is installed but not working properly."
        echo "You may need to install the protobuf development package:"
        echo "  Ubuntu/Debian: sudo apt-get install libprotobuf-dev"
        echo "  Fedora: sudo dnf install protobuf-devel"
        exit 1
    fi
fi

# Build the project
echo "Building release binaries..."
cargo build --release

# Create symlinks for easier access
echo "Creating symlinks..."
mkdir -p bin
ln -sf ../target/release/semcode-index bin/semcode-index
ln -sf ../target/release/semcode bin/semcode
ln -sf ../target/release/semcode-mcp bin/semcode-mcp
ln -sf ../target/release/semcode-lsp bin/semcode-lsp

echo ""
echo "=== Build Complete ==="
echo ""
echo "Binaries are available in ./bin/"
echo ""
echo "To index a codebase:"
echo "  ./bin/semcode-index --source /path/to/code --database ./code.db"
echo ""
echo "To query the database:"
echo "  ./bin/semcode --database ./code.db"
echo ""
echo "To run MCP server:"
echo "  ./bin/semcode-mcp --database ./code.db"
echo ""
echo "To run LSP server (for editor integration):"
echo "  ./bin/semcode-lsp"
echo "  See docs/lsp-server.md for Neovim/editor setup"
echo ""

# Optional: Create a small test directory with sample C files
if [ "$1" == "--with-test" ]; then
    echo "Creating test directory with sample C files..."
    mkdir -p test_code
    
    cat > test_code/main.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

struct config {
    int debug_level;
    char name[256];
    void (*handler)(int);
};

void signal_handler(int sig) {
    printf("Received signal: %d\n", sig);
}

int main(int argc, char *argv[]) {
    struct config cfg = {
        .debug_level = 1,
        .name = "test",
        .handler = signal_handler
    };
    
    printf("Starting program: %s\n", cfg.name);
    
    int *data = allocate_buffer(1024);
    if (data) {
        process_data(data, 1024);
        free(data);
    }
    
    return 0;
}
EOF

    cat > test_code/utils.h << 'EOF'
#ifndef UTILS_H
#define UTILS_H

int* allocate_buffer(size_t size);
void process_data(int* data, size_t size);
void debug_print(const char* msg);

typedef struct {
    int id;
    char* name;
    float value;
} data_item_t;

enum status_code {
    STATUS_OK = 0,
    STATUS_ERROR = -1,
    STATUS_TIMEOUT = -2
};

#endif /* UTILS_H */
EOF

    cat > test_code/utils.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

int* allocate_buffer(size_t size) {
    int* buffer = malloc(size * sizeof(int));
    if (buffer) {
        debug_print("Buffer allocated");
    }
    return buffer;
}

void process_data(int* data, size_t size) {
    debug_print("Processing data");
    for (size_t i = 0; i < size; i++) {
        data[i] = i * 2;
    }
}

void debug_print(const char* msg) {
    printf("[DEBUG] %s\n", msg);
}
EOF

    echo ""
    echo "Test code created in ./test_code/"
    echo "You can test the indexer with:"
    echo "  ./bin/semcode-index --source ./test_code --database ./test.db"
    echo "Then query with:"
    echo "  ./bin/semcode --database ./test.db"
fi
