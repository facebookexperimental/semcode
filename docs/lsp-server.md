# Semcode LSP Server

A Language Server Protocol (LSP) server that provides navigation features for C/C++ codebases indexed by semcode.

## Features

- **Go to Definition**: Jump to definitions of functions, macros, types, and typedefs using semcode's semantic database
- **Find References**: Show all places where a symbol is referenced (callers)
- **Git-Aware Lookups**: Automatically finds the correct version at your current commit
- **Configuration Support**: Configurable database path through LSP client settings

## Building

```bash
cargo build --release --bin semcode-lsp
```

## Usage

The LSP server communicates over stdin/stdout using the JSON-RPC 2.0 protocol as specified by the Language Server Protocol.

### Prerequisites

1. A semcode-indexed codebase:
   ```bash
   semcode-index --source /path/to/your/code
   ```

2. The resulting `.semcode.db` database in your workspace directory

## Neovim Configuration

### Using nvim-lspconfig

Add this to your Neovim configuration (`~/.config/nvim/init.lua` or similar):

```lua
-- Ensure you have nvim-lspconfig installed
-- Using lazy.nvim:
-- { 'neovim/nvim-lspconfig' }

-- Configure semcode LSP
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Define semcode-lsp if it's not already defined
if not configs.semcode_lsp then
  configs.semcode_lsp = {
    default_config = {
      cmd = { '/path/to/semcode/target/release/semcode-lsp' },
      filetypes = { 'c', 'cpp', 'cc', 'h', 'hpp' },
      root_dir = function(fname)
        -- Look for .semcode.db or use git root
        return lspconfig.util.find_git_ancestor(fname) or
               lspconfig.util.root_pattern('.semcode.db')(fname) or
               vim.fn.getcwd()
      end,
      settings = {
        semcode = {
          database_path = nil  -- Uses workspace/.semcode.db by default
        }
      }
    }
  }
end

-- Setup the LSP
lspconfig.semcode_lsp.setup({
  -- Optional: custom database path
  settings = {
    semcode = {
      database_path = "/custom/path/to/.semcode.db"  -- Optional
    }
  }
})

-- Optional: Set up keybindings
vim.api.nvim_create_autocmd('LspAttach', {
  group = vim.api.nvim_create_augroup('UserLspConfig', {}),
  callback = function(ev)
    -- Enable completion triggered by <c-x><c-o>
    vim.bo[ev.buf].omnifunc = 'v:lua.vim.lsp.omnifunc'

    local opts = { buffer = ev.buf }
    vim.keymap.set('n', 'gd', vim.lsp.buf.definition, opts)        -- Go to definition
    vim.keymap.set('n', 'gr', vim.lsp.buf.references, opts)        -- Find references (callers)
    vim.keymap.set('n', 'K', vim.lsp.buf.hover, opts)
    vim.keymap.set('n', 'gi', vim.lsp.buf.implementation, opts)
    vim.keymap.set('n', '<C-k>', vim.lsp.buf.signature_help, opts)
    vim.keymap.set('n', '<space>rn', vim.lsp.buf.rename, opts)
    vim.keymap.set('n', '<space>ca', vim.lsp.buf.code_action, opts)
  end,
})
```

### Manual Configuration

If you prefer manual configuration without nvim-lspconfig:

```lua
vim.lsp.start({
  name = 'semcode-lsp',
  cmd = { '/path/to/semcode/target/release/semcode-lsp' },
  root_dir = vim.fs.dirname(vim.fs.find({'.semcode.db', '.git'}, { upward = true })[1]),
  settings = {
    semcode = {
      database_path = nil  -- Optional custom path
    }
  }
})
```

## Configuration Options

The LSP server accepts the following configuration through the `semcode` section:

- `database_path` (string, optional): Custom path to the semcode database. If not specified, the server will:
  1. Look for `.semcode.db` in the workspace directory
  2. Fall back to `./.semcode.db` in the current directory

## Testing

To test the LSP server manually, you can run it and send JSON-RPC messages:

```bash
# Build the server
cargo build --release --bin semcode-lsp

# Run the server (it will read from stdin and write to stdout)
./target/release/semcode-lsp
```

Example initialization message:
```json
Content-Length: 246

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"processId":null,"rootUri":"file:///path/to/your/workspace","capabilities":{},"initializationOptions":{},"workspaceFolders":null}}
```

## How It Works

1. **Database Connection**: The server connects to the semcode database (`.semcode.db`) in your workspace
2. **Git Awareness**: The server detects your current git commit (HEAD) to ensure it finds the correct version of all symbols
3. **Go to Definition**: When you request "go to definition" (`gd`) on an identifier, the server:
   - Extracts the identifier name at the cursor position
   - Uses git-aware lookup to query the database at your current commit
   - Checks in priority order: function > macro > type > typedef
   - Returns the file path and line number where it is defined
   - Your editor jumps to the definition location
4. **Find References**: When you request "find references" (`gr`) on an identifier, the server:
   - Extracts the identifier name at the cursor position
   - Queries the database for all symbols that reference this identifier (callers)
   - Uses git-aware lookup to find references that exist at your current commit
   - Returns a list of all locations where it is referenced
   - Your editor displays the list of references

### Git-Aware Lookups

The LSP server uses **git-aware lookups** to ensure you always jump to the correct version of a symbol:

- On initialization, it determines your current git commit (`HEAD`)
- When looking up symbols, it finds the version that exists at your current commit
- If you have indexed multiple versions of your codebase, it intelligently selects the right one
- Falls back to non-git-aware lookup if not in a git repository

## Supported Languages

- C (`.c`, `.h`)
- C++ (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hxx`)

## Troubleshooting

### Database Not Found
If you see "Semcode database not found" messages:
1. Ensure you've run `semcode-index` on your codebase
2. Check that `.semcode.db` exists in your workspace
3. Verify the database path configuration

### Symbol Not Found
If "go to definition" doesn't work for a symbol:
1. Ensure the symbol (function, macro, type, or typedef) was indexed by semcode
2. Try using the `semcode` CLI tool to verify the symbol exists in the database
3. Check that you're using the correct identifier name (no typos)
4. **Git-related issues:**
   - Make sure your working directory is at a git commit that has been indexed
   - If you've checked out a different commit, restart the LSP server to refresh the git SHA
   - Try running `semcode-index` on your current commit if it hasn't been indexed yet

## Limitations

- Supports functions, macros, types, and typedefs (other symbols may be added in the future)
- Requires a pre-indexed semcode database
- Does not support real-time indexing of file changes
- References show symbol-level locations, not exact usage sites within function bodies
