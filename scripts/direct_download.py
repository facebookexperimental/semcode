#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "huggingface_hub",
# ]
# ///
from huggingface_hub import snapshot_download
path = snapshot_download("nomic-ai/nomic-embed-text-v2-moe", revision="main")
path = snapshot_download("nomic-ai/nomic-bert-2048", revision="main")
