// SPDX-License-Identifier: MIT OR Apache-2.0
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

/// Maximum time to wait for a single rust-analyzer JSON-RPC response before
/// giving up. Prevents a dead or wedged server from hanging callers forever.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: usize,
    method: String,
    params: Value,
}

#[derive(Serialize)]
struct JsonRpcNotification {
    jsonrpc: String,
    method: String,
    params: Value,
}

type ResponseSender = oneshot::Sender<Value>;

/// Frame a JSON-RPC payload with the LSP `Content-Length` header.
fn frame_message(payload: &str) -> String {
    format!("Content-Length: {}\r\n\r\n{}", payload.len(), payload)
}

/// Client to manage a background rust-analyzer process via JSON-RPC.
pub struct RustAnalyzer {
    request_tx: mpsc::Sender<(JsonRpcRequest, ResponseSender)>,
    notification_tx: mpsc::Sender<JsonRpcNotification>,
    next_id: Arc<AtomicUsize>,
    /// Owned handle to the rust-analyzer process. Spawned with `kill_on_drop`,
    /// so the process is terminated when this client is dropped rather than
    /// leaking an orphaned rust-analyzer for the lifetime of the machine.
    _child: Mutex<Child>,
}

impl RustAnalyzer {
    /// Start a new rust-analyzer process in the background and initialize it.
    pub async fn start(workspace_root: &Path) -> Result<Self> {
        info!(
            "Starting rust-analyzer for workspace: {}",
            workspace_root.display()
        );

        let mut child = Command::new("rust-analyzer")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()) // ignore stderr logs for now to avoid polluting stdout
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn rust-analyzer: {}", e))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("Failed to open stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("Failed to open stdout"))?;

        let (req_tx, mut req_rx) = mpsc::channel::<(JsonRpcRequest, ResponseSender)>(100);
        let (notif_tx, mut notif_rx) = mpsc::channel::<JsonRpcNotification>(100);
        let next_id = Arc::new(AtomicUsize::new(1));

        let pending_requests: Arc<DashMap<usize, ResponseSender>> = Arc::new(DashMap::new());
        let pending_requests_clone = pending_requests.clone();

        // Sender task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some((req, resp_tx)) = req_rx.recv() => {
                        let id = req.id;
                        pending_requests_clone.insert(id, resp_tx);
                        let payload = match serde_json::to_string(&req) {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Failed to serialize request: {}", e);
                                pending_requests_clone.remove(&id);
                                continue;
                            }
                        };
                        let msg = frame_message(&payload);
                        if let Err(e) = stdin.write_all(msg.as_bytes()).await {
                            error!("Failed to write request to stdin: {}", e);
                            pending_requests_clone.remove(&id);
                            break;
                        }
                        if let Err(e) = stdin.flush().await {
                            error!("Failed to flush stdin: {}", e);
                            pending_requests_clone.remove(&id);
                            break;
                        }
                    }
                    Some(notif) = notif_rx.recv() => {
                        let payload = match serde_json::to_string(&notif) {
                            Ok(p) => p,
                            Err(e) => {
                                error!("Failed to serialize notification: {}", e);
                                continue;
                            }
                        };
                        let msg = frame_message(&payload);
                        if let Err(e) = stdin.write_all(msg.as_bytes()).await {
                            error!("Failed to write notification to stdin: {}", e);
                            break;
                        }
                        if let Err(e) = stdin.flush().await {
                            error!("Failed to flush stdin: {}", e);
                            break;
                        }
                    }
                    else => break, // Both channels closed
                }
            }
            debug!("rust-analyzer sender task exited");
        });

        // Reader task
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut content_length = 0;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line).await {
                        Ok(0) => return, // EOF
                        Ok(_) => {
                            if line == "\r\n" || line == "\n" {
                                break;
                            }
                            if line.starts_with("Content-Length: ") {
                                if let Ok(len) = line
                                    .trim_start_matches("Content-Length: ")
                                    .trim()
                                    .parse::<usize>()
                                {
                                    content_length = len;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Error reading from stdout: {}", e);
                            return;
                        }
                    }
                }

                if content_length > 0 {
                    let mut buf = vec![0; content_length];
                    if let Err(e) = reader.read_exact(&mut buf).await {
                        error!("Error reading exact from stdout: {}", e);
                        return;
                    }
                    if let Ok(payload) = String::from_utf8(buf) {
                        if let Ok(msg) = serde_json::from_str::<Value>(&payload) {
                            // If it's a response with an ID, route it
                            if let Some(id_val) = msg.get("id") {
                                if let Some(id) = id_val.as_u64().map(|i| i as usize) {
                                    if let Some((_, sender)) = pending_requests.remove(&id) {
                                        let _ = sender.send(msg);
                                    }
                                }
                            } else {
                                // Notification from server, could be workDoneProgress, diagnostics, etc.
                                // ignoring for now
                            }
                        }
                    }
                }
            }
        });

        let client = Self {
            request_tx: req_tx,
            notification_tx: notif_tx,
            next_id,
            _child: Mutex::new(child),
        };

        // Initialize
        let workspace_uri = format!("file://{}", workspace_root.display());
        client
            .send_request(
                "initialize",
                json!({
                    "processId": std::process::id(),
                    "rootUri": workspace_uri,
                    "capabilities": {
                        "workspace": {
                            "workspaceFolders": true,
                            "symbol": {
                                "dynamicRegistration": true
                            }
                        },
                        "textDocument": {
                            "documentSymbol": {
                                "hierarchicalDocumentSymbolSupport": true
                            }
                        }
                    }
                }),
            )
            .await?;

        client.send_notification("initialized", json!({})).await?;

        info!("rust-analyzer initialized successfully");
        Ok(client)
    }

    /// Send a notification to the server.
    pub async fn send_notification(&self, method: &str, params: Value) -> Result<()> {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        };
        self.notification_tx
            .send(notif)
            .await
            .map_err(|_| anyhow!("rust-analyzer sender task dead"))?;
        Ok(())
    }

    /// Send a request to the server and wait for the response.
    ///
    /// Returns the JSON-RPC `result` payload (not the full envelope). Fails if
    /// the server reports an error, dies, or does not respond within
    /// [`REQUEST_TIMEOUT`].
    pub async fn send_request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.to_string(),
            params,
        };

        let (resp_tx, resp_rx) = oneshot::channel();
        self.request_tx
            .send((req, resp_tx))
            .await
            .map_err(|_| anyhow!("rust-analyzer sender task dead"))?;

        let response = tokio::time::timeout(REQUEST_TIMEOUT, resp_rx)
            .await
            .map_err(|_| {
                anyhow!(
                    "rust-analyzer request '{}' timed out after {}s",
                    method,
                    REQUEST_TIMEOUT.as_secs()
                )
            })?
            .map_err(|_| anyhow!("Failed to receive response from rust-analyzer"))?;
        if let Some(err) = response.get("error") {
            return Err(anyhow!("rust-analyzer error: {}", err));
        }

        // Unwrap the JSON-RPC envelope; callers only care about `result`.
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Query workspace symbols
    pub async fn workspace_symbol(&self, query: &str) -> Result<Value> {
        self.send_request(
            "workspace/symbol",
            json!({
                "query": query
            }),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_message_has_content_length_and_separator() {
        let payload = r#"{"jsonrpc":"2.0"}"#;
        let framed = frame_message(payload);
        assert_eq!(
            framed,
            format!("Content-Length: {}\r\n\r\n{}", payload.len(), payload)
        );
        // Header and body are separated by a blank line.
        let (header, body) = framed.split_once("\r\n\r\n").expect("missing separator");
        assert_eq!(header, format!("Content-Length: {}", payload.len()));
        assert_eq!(body, payload);
    }

    #[test]
    fn test_request_serializes_with_id_and_jsonrpc() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 7,
            method: "workspace/symbol".to_string(),
            params: json!({ "query": "foo" }),
        };
        let v: Value = serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["method"], "workspace/symbol");
        assert_eq!(v["params"]["query"], "foo");
    }

    #[test]
    fn test_notification_serializes_without_id() {
        let notif = JsonRpcNotification {
            jsonrpc: "2.0".to_string(),
            method: "initialized".to_string(),
            params: json!({}),
        };
        let v: Value = serde_json::from_str(&serde_json::to_string(&notif).unwrap()).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "initialized");
        assert!(v.get("id").is_none(), "notifications must not carry an id");
    }
}
