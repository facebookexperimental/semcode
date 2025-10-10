#!/usr/bin/env python3
"""
Simple test script for the semcode LSP server.
This script sends basic LSP messages to test the server functionality.
"""

import json
import subprocess
import sys
import os

def send_message(proc, method, params, msg_id=1):
    """Send a JSON-RPC message to the LSP server."""
    message = {
        "jsonrpc": "2.0",
        "id": msg_id,
        "method": method,
        "params": params
    }

    content = json.dumps(message)
    headers = f"Content-Length: {len(content)}\r\n\r\n"
    full_message = headers + content

    print(f"Sending: {method}")
    print(f"Content: {content}")

    proc.stdin.write(full_message.encode())
    proc.stdin.flush()

def read_response(proc):
    """Read a response from the LSP server."""
    # Read the Content-Length header
    line = proc.stdout.readline().decode().strip()
    if not line.startswith("Content-Length:"):
        return None

    length = int(line.split(":")[1].strip())

    # Read the empty line
    proc.stdout.readline()

    # Read the JSON content
    content = proc.stdout.read(length).decode()

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        print(f"Failed to parse JSON: {content}")
        return None

def test_lsp_server():
    """Test the semcode LSP server."""
    # Check if the server binary exists
    # Determine the path based on where the script is run from
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    server_path = os.path.join(project_root, "target", "release", "semcode-lsp")

    if not os.path.exists(server_path):
        print(f"LSP server not found at {server_path}")
        print("Please run 'cargo build --release --bin semcode-lsp' first")
        return False

    print("Starting semcode LSP server...")

    # Start the LSP server
    proc = subprocess.Popen(
        [server_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        # Send initialize request
        workspace_uri = f"file://{os.getcwd()}"

        send_message(proc, "initialize", {
            "processId": None,
            "rootUri": workspace_uri,
            "capabilities": {
                "textDocument": {
                    "definition": {
                        "dynamicRegistration": True,
                        "linkSupport": True
                    }
                }
            }
        })

        # Read initialize response
        response = read_response(proc)
        if response:
            print(f"Initialize response: {json.dumps(response, indent=2)}")

            if response.get("result", {}).get("capabilities", {}).get("definitionProvider"):
                print("✓ Server supports go-to-definition")
            else:
                print("✗ Server does not support go-to-definition")

        # Send initialized notification
        send_message(proc, "initialized", {})

        # Test go to definition (if you have a test file)
        test_file = "test.c"
        if os.path.exists(test_file):
            file_uri = f"file://{os.path.abspath(test_file)}"
            send_message(proc, "textDocument/definition", {
                "textDocument": {"uri": file_uri},
                "position": {"line": 0, "character": 5}
            })

            definition_response = read_response(proc)
            if definition_response:
                print(f"Definition response: {json.dumps(definition_response, indent=2)}")

        # Shutdown
        send_message(proc, "shutdown", {})
        shutdown_response = read_response(proc)
        if shutdown_response:
            print(f"Shutdown response: {json.dumps(shutdown_response, indent=2)}")

        print("Test completed successfully!")
        return True

    except Exception as e:
        print(f"Error during testing: {e}")
        return False
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    success = test_lsp_server()
    sys.exit(0 if success else 1)