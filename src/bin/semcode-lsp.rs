// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_lsp::jsonrpc::Result as LspResult;
use tower_lsp::lsp_types::*;
use tower_lsp::{Client, LanguageServer, LspService, Server};
use url::Url;

use semcode::{database_utils, DatabaseManager};

#[derive(Debug, Deserialize, Serialize)]
struct SemcodeLspConfig {
    database_path: Option<String>,
}

impl Default for SemcodeLspConfig {
    fn default() -> Self {
        Self {
            database_path: None,
        }
    }
}

pub struct SemcodeLspBackend {
    database: Arc<Mutex<Option<DatabaseManager>>>,
    config: Arc<Mutex<SemcodeLspConfig>>,
    git_sha: Arc<Mutex<Option<String>>>, // Cache the current git commit SHA
    git_repo_path: Arc<Mutex<Option<String>>>, // Cache the git repo path for resolving relative paths
}

impl SemcodeLspBackend {
    pub fn new(_client: Client) -> Self {
        Self {
            database: Arc::new(Mutex::new(None)),
            config: Arc::new(Mutex::new(SemcodeLspConfig::default())),
            git_sha: Arc::new(Mutex::new(None)),
            git_repo_path: Arc::new(Mutex::new(None)),
        }
    }

    async fn ensure_database_connection(&self, workspace_uri: Option<&Url>) -> Result<()> {
        let mut db = self.database.lock().await;
        if db.is_some() {
            return Ok(());
        }

        // Try to determine database path and git repo path from config or workspace
        let config = self.config.lock().await;
        let (db_path, git_repo_path) = if let Some(path) = &config.database_path {
            // Custom database path provided
            let git_repo = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| ".".to_string());
            (path.clone(), git_repo)
        } else if let Some(uri) = workspace_uri {
            // Use workspace directory (process_database_path will add .semcode.db)
            let workspace_path = uri
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("Failed to convert workspace URI to file path"))?;
            let workspace_str = workspace_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("Invalid workspace path"))?
                .to_string();
            // Pass workspace directory directly, let process_database_path add .semcode.db
            (workspace_str.clone(), workspace_str)
        } else {
            // Default to current directory (process_database_path will add .semcode.db)
            let current_dir = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| ".".to_string());
            // Pass current directory, let process_database_path add .semcode.db
            (current_dir.clone(), current_dir)
        };

        // Process the database path using semcode's utility function
        let processed_path = database_utils::process_database_path(Some(&db_path), None);

        if !Path::new(&processed_path).exists() {
            return Err(anyhow::anyhow!("Database not found"));
        }

        match DatabaseManager::new(&processed_path, git_repo_path.clone()).await {
            Ok(database_manager) => {
                *db = Some(database_manager);

                // Get the current git SHA for git-aware lookups
                let git_sha = semcode::git::get_git_sha(&git_repo_path).ok().flatten();

                *self.git_sha.lock().await = git_sha;
                *self.git_repo_path.lock().await = Some(git_repo_path);

                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn find_function_definition(&self, identifier_name: &str) -> Option<Location> {
        let db_guard = self.database.lock().await;
        let db = db_guard.as_ref()?;

        // Try git-aware lookup first if we have a git SHA
        let git_sha_guard = self.git_sha.lock().await;
        let (func_result, macro_result, type_result, typedef_result) =
            if let Some(git_sha) = git_sha_guard.as_ref() {
                // Use git-aware lookup to find function, macro, type, and typedef at current commit
                let func = db.find_function_git_aware(identifier_name, git_sha).await;
                let mac = db.find_function_git_aware(identifier_name, git_sha).await;
                let typ = db.find_type_git_aware(identifier_name, git_sha).await;
                let typedef = db.find_typedef_git_aware(identifier_name, git_sha).await;
                (func, mac, typ, typedef)
            } else {
                // Fall back to non-git-aware lookup
                let func = db.find_function(identifier_name).await;
                let mac = db.find_function(identifier_name).await;
                let typ = db.find_type(identifier_name).await;
                let typedef = db.find_typedef(identifier_name).await;
                (func, mac, typ, typedef)
            };
        drop(git_sha_guard);

        // Prioritize: function > macro > type > typedef
        let (file_path, line_start) = match (func_result, macro_result, type_result, typedef_result)
        {
            (Ok(Some(func)), _, _, _) => (func.file_path, func.line_start),
            (_, Ok(Some(mac)), _, _) => (mac.file_path, mac.line_start),
            (_, _, Ok(Some(typ)), _) => (typ.file_path, typ.line_start),
            (_, _, _, Ok(Some(typedef))) => (typedef.file_path, typedef.line_start),
            _ => return None,
        };

        // Convert relative file path to absolute path using git repo path
        let repo_path_guard = self.git_repo_path.lock().await;
        let absolute_path = if let Some(repo_path) = repo_path_guard.as_ref() {
            // Join repo path with relative file path from database
            std::path::Path::new(repo_path).join(&file_path)
        } else {
            // Fallback to relative path (shouldn't happen if database connected)
            std::path::PathBuf::from(&file_path)
        };
        drop(repo_path_guard);

        // Convert absolute file path to URI
        let file_uri = Url::from_file_path(&absolute_path).ok()?;

        // Create position (LSP uses 0-based line numbers)
        let position = Position {
            line: line_start.saturating_sub(1),
            character: 0,
        };

        Some(Location {
            uri: file_uri,
            range: Range {
                start: position,
                end: position,
            },
        })
    }

    async fn find_function_references(&self, function_name: &str) -> Vec<Location> {
        let db_guard = self.database.lock().await;
        let db = match db_guard.as_ref() {
            Some(db) => db,
            None => return Vec::new(),
        };

        // Try git-aware lookup first if we have a git SHA
        let git_sha_guard = self.git_sha.lock().await;
        let result = if let Some(git_sha) = git_sha_guard.as_ref() {
            // Use git-aware lookup to find callers at current commit
            db.get_function_callers_git_aware(function_name, git_sha)
                .await
        } else {
            // Fall back to non-git-aware lookup
            db.get_function_callers(function_name).await
        };
        drop(git_sha_guard);

        let caller_names = match result {
            Ok(callers) => callers,
            Err(_) => return Vec::new(),
        };

        // Get detailed information for each caller
        let mut locations = Vec::new();
        for caller_name in caller_names {
            // Use git-aware lookup to get the caller's location
            // Try function first, then macro, then type, then typedef
            let git_sha_guard = self.git_sha.lock().await;
            let (file_path, line_start) = if let Some(git_sha) = git_sha_guard.as_ref() {
                // Try in priority order
                if let Ok(Some(func)) = db.find_function_git_aware(&caller_name, git_sha).await {
                    (func.file_path, func.line_start)
                } else if let Ok(Some(mac)) =
                    db.find_function_git_aware(&caller_name, git_sha).await
                {
                    (mac.file_path, mac.line_start)
                } else if let Ok(Some(typ)) = db.find_type_git_aware(&caller_name, git_sha).await {
                    (typ.file_path, typ.line_start)
                } else if let Ok(Some(typedef)) =
                    db.find_typedef_git_aware(&caller_name, git_sha).await
                {
                    (typedef.file_path, typedef.line_start)
                } else {
                    drop(git_sha_guard);
                    continue;
                }
            } else {
                // Try in priority order
                if let Ok(Some(func)) = db.find_function(&caller_name).await {
                    (func.file_path, func.line_start)
                } else if let Ok(Some(mac)) = db.find_function(&caller_name).await {
                    (mac.file_path, mac.line_start)
                } else if let Ok(Some(typ)) = db.find_type(&caller_name).await {
                    (typ.file_path, typ.line_start)
                } else if let Ok(Some(typedef)) = db.find_typedef(&caller_name).await {
                    (typedef.file_path, typedef.line_start)
                } else {
                    drop(git_sha_guard);
                    continue;
                }
            };
            drop(git_sha_guard);

            // Convert relative file path to absolute path
            let repo_path_guard = self.git_repo_path.lock().await;
            let absolute_path = if let Some(repo_path) = repo_path_guard.as_ref() {
                std::path::Path::new(repo_path).join(&file_path)
            } else {
                std::path::PathBuf::from(&file_path)
            };
            drop(repo_path_guard);

            // Convert to URI
            if let Ok(file_uri) = Url::from_file_path(&absolute_path) {
                let position = Position {
                    line: line_start.saturating_sub(1),
                    character: 0,
                };

                locations.push(Location {
                    uri: file_uri,
                    range: Range {
                        start: position,
                        end: position,
                    },
                });
            }
        }

        locations
    }

    // Extract function name from the current position in the document
    fn extract_function_name_at_position(text: &str, position: &Position) -> Option<String> {
        let lines: Vec<&str> = text.lines().collect();
        if position.line as usize >= lines.len() {
            return None;
        }

        let line = lines[position.line as usize];
        let character = position.character as usize;

        if character > line.len() {
            return None;
        }

        // Find word boundaries around the cursor position
        let chars: Vec<char> = line.chars().collect();
        if character > chars.len() {
            return None;
        }

        // Find start of identifier
        let mut start = character;
        while start > 0 && (chars[start - 1].is_alphanumeric() || chars[start - 1] == '_') {
            start -= 1;
        }

        // Find end of identifier
        let mut end = character;
        while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
            end += 1;
        }

        if start < end {
            let identifier: String = chars[start..end].iter().collect();
            if !identifier.is_empty()
                && (identifier.chars().next().unwrap().is_alphabetic()
                    || identifier.starts_with('_'))
            {
                return Some(identifier);
            }
        }

        None
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for SemcodeLspBackend {
    async fn initialize(&self, params: InitializeParams) -> LspResult<InitializeResult> {
        // Try to establish database connection
        let _ = self
            .ensure_database_connection(params.root_uri.as_ref())
            .await;

        Ok(InitializeResult {
            server_info: Some(ServerInfo {
                name: "semcode-lsp".to_string(),
                version: Some("0.1.0".to_string()),
            }),
            capabilities: ServerCapabilities {
                definition_provider: Some(OneOf::Left(true)),
                references_provider: Some(OneOf::Left(true)),
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::NONE,
                )),
                ..Default::default()
            },
        })
    }

    async fn initialized(&self, _: InitializedParams) {}

    async fn shutdown(&self) -> LspResult<()> {
        Ok(())
    }

    async fn goto_definition(
        &self,
        params: GotoDefinitionParams,
    ) -> LspResult<Option<GotoDefinitionResponse>> {
        let uri = &params.text_document_position_params.text_document.uri;
        let position = &params.text_document_position_params.position;

        // Get the document text to extract the function name
        let document_text = match std::fs::read_to_string(uri.path()) {
            Ok(text) => text,
            Err(_) => return Ok(None),
        };

        // Extract function name at the cursor position
        let function_name = match Self::extract_function_name_at_position(&document_text, position)
        {
            Some(name) => name,
            None => return Ok(None),
        };

        // Find the function definition in the database
        if let Some(location) = self.find_function_definition(&function_name).await {
            Ok(Some(GotoDefinitionResponse::Scalar(location)))
        } else {
            Ok(None)
        }
    }

    async fn references(&self, params: ReferenceParams) -> LspResult<Option<Vec<Location>>> {
        let uri = &params.text_document_position.text_document.uri;
        let position = &params.text_document_position.position;

        // Get the document text to extract the function name
        let document_text = match std::fs::read_to_string(uri.path()) {
            Ok(text) => text,
            Err(_) => return Ok(None),
        };

        // Extract function name at the cursor position
        let function_name = match Self::extract_function_name_at_position(&document_text, position)
        {
            Some(name) => name,
            None => return Ok(None),
        };

        // Find all references (callers) of this function
        let locations = self.find_function_references(&function_name).await;

        if locations.is_empty() {
            Ok(None)
        } else {
            Ok(Some(locations))
        }
    }

    async fn did_change_configuration(&self, params: DidChangeConfigurationParams) {
        // Try to extract semcode-lsp specific config
        if let Some(config_obj) = params.settings.get("semcode") {
            if let Ok(config) = serde_json::from_value::<SemcodeLspConfig>(config_obj.clone()) {
                let mut current_config = self.config.lock().await;
                *current_config = config;

                // Reconnect database if path changed
                let mut db = self.database.lock().await;
                *db = None;
                drop(db);

                // Clear git SHA and repo path caches
                let mut git_sha = self.git_sha.lock().await;
                *git_sha = None;
                drop(git_sha);

                let mut repo_path = self.git_repo_path.lock().await;
                *repo_path = None;
                drop(repo_path);

                let _ = self.ensure_database_connection(None).await;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| SemcodeLspBackend::new(client));

    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
