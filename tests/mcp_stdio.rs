// SPDX-License-Identifier: MIT OR Apache-2.0

use serde_json::{json, Value};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

#[tokio::test]
async fn server_exits_on_broken_stdout_with_stdin_still_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_semcode-mcp"))
        .arg("--database")
        .arg(dir.path())
        .arg("--git-repo")
        .arg(dir.path())
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();

    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    stdin
        .write_all(format!("{ping}\n").as_bytes())
        .await
        .unwrap();
    let reply = timeout(Duration::from_secs(10), stdout.next_line())
        .await
        .expect("server did not respond to ping")
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&reply).unwrap()["id"], 1);

    drop(stdout);
    let tool = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "indexing_status"}
    });
    stdin
        .write_all(format!("{tool}\n").as_bytes())
        .await
        .unwrap();
    timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("server hung after a tool response hit a broken pipe")
        .unwrap();
    drop(stdin);
}
