#!/usr/bin/env python3
from huggingface_hub import snapshot_download
path = snapshot_download("nomic-ai/nomic-embed-text-v2-moe", revision="main")
path = snapshot_download("nomic-ai/nomic-bert-2048", revision="main")
