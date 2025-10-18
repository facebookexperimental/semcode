# Clangd Integration Tests

Tests for semcode's clangd integration, which adds compiler-grade semantic enrichment (USRs, canonical types, signatures) on top of Tree-sitter-based parsing.

## Running Tests

```bash
# From project root
cargo test --test clangd_integration

# With verbose output
cargo test --test clangd_integration -- --nocapture
```

Tests run in parallel with isolated temporary databases.

## Prerequisites

For clangd tests to run (not be skipped):
```bash
# Ubuntu/Debian
sudo apt-get install libclang-dev

# Fedora
sudo dnf install clang-devel
```

## Test Fixtures

- `test_sample.c` - C code exercising functions, types, macros
- `compile_commands*.json` - Various compilation database formats for testing

## Additional Documentation

- **COMPILE_FLAGS_TEST.md** - Compile flag parsing details
- **GCC_FLAGS.md** - GCC flag filtering
- **CLANGD_CONFIG.md** - .clangd configuration support status
