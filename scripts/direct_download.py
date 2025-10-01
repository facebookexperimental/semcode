#!/usr/bin/env python3
"""
Offline download of Nomic Embed v2 and implementation repo artifacts
Populates: ~/.cache/huggingface/hub/models--nomic-ai--nomic-embed-text-v2-moe/snapshots/latest
          ~/.cache/huggingface/hub/models--nomic-ai--nomic-bert-2048/snapshots/latest

Usage:
  # Install dependencies first:
  pip install -r requirements.txt

  # Download both models (default):
  python direct_download.py

  # Download only main embedding model:
  python direct_download.py --main-only

  # Download only implementation model:
  python direct_download.py --impl-only

  # Verify existing downloads:
  python direct_download.py --verify-only

After successful download, run nomic2vec.py to create the Model2Vec static model.
"""
import os
import sys
import argparse
import requests
from pathlib import Path
from tqdm import tqdm

MAIN_MODEL_ID = "nomic-ai/nomic-embed-text-v2-moe"
IMPL_MODEL_ID = "nomic-ai/nomic-bert-2048"

def download_file(url, dest_path, proxies=None, chunk_size=8192):
    if proxies is None:
        for var in ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY']:
            if var in os.environ:
                proxies = {'http': os.environ[var], 'https': os.environ[var]}
                print(f"Using proxy: {os.environ[var]}")
                break
        else:
            proxies = {}
    os.environ['HF_HUB_DISABLE_XET'] = '1'
    os.environ['HF_HUB_ENABLE_HF_TRANSFER'] = '0'
    resp = requests.get(url, proxies=proxies, stream=True)
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    total_size = int(resp.headers.get('content-length', 0))
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, 'wb') as f, tqdm(total=total_size, unit='B', unit_scale=True, leave=False) as pbar:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(chunk)
                pbar.update(len(chunk))
    return True

def target_cache_dir(model_id):
    safe_id = model_id.replace("/", "--")
    base = Path.home() / ".cache" / "huggingface" / "hub" / f"models--{safe_id}" / "snapshots"
    return base / "latest"

def file_map_for_model(model_id):
    base_hf = f"https://huggingface.co/{model_id}/resolve/main"

    # Common files for most transformer models
    common_files = [
        "config.json", "tokenizer_config.json", "tokenizer.json", "special_tokens_map.json",
        "model.safetensors", "pytorch_model.bin", "vocab.json", "merges.txt", "added_tokens.json",
        "chat_template.jinja", "sentencepiece.bpe.model"
    ]

    # Implementation-specific files (mainly for nomic-bert-2048)
    impl_files = [
        "configuration_bert.py", "modeling_bert.py", "tokenization_bert.py",
        "tokenization_sentencepiece.py", "__init__.py",
        "configuration_hf_nomic_bert.py", "modeling_hf_nomic_bert.py",
        "tokenization_hf_nomic_bert.py"
    ]

    # Additional files that might be needed
    additional_files = [
        "README.md", "model_config.json", "preprocessor_config.json",
        "generation_config.json", "trainer_state.json", "training_args.bin"
    ]

    # For nomic-bert-2048, include implementation files
    if "nomic-bert-2048" in model_id:
        files = common_files + impl_files + additional_files
    else:
        files = common_files + additional_files

    return {x: f"{base_hf}/{x}" for x in files}

def verify_essential_files(cache_dir, model_name):
    """Verify that essential files needed for transformers are present."""
    essential_files = ["config.json", "tokenizer.json"]
    missing_files = []

    for filename in essential_files:
        file_path = cache_dir / filename
        if not file_path.exists() or file_path.stat().st_size == 0:
            missing_files.append(filename)

    if missing_files:
        print(f"⚠ Warning: {model_name} missing essential files: {', '.join(missing_files)}")
        print(f"  The nomic2vec.py script may fail without these files.")
    else:
        print(f"✓ {model_name} essential files verified")

def create_hf_cache_structure(model_id, cache_dir):
    """Create the expected HuggingFace cache structure with refs and metadata."""
    # Create the refs directory structure
    model_base = cache_dir.parent.parent  # Go up from snapshots/latest to model root
    refs_dir = model_base / "refs"
    refs_dir.mkdir(exist_ok=True)

    # Create refs/main pointing to our snapshot
    refs_main = refs_dir / "main"
    refs_main.write_text("latest")

    # Create .no_exist directory (transformers checks this)
    no_exist_dir = model_base / ".no_exist"
    no_exist_dir.mkdir(exist_ok=True)

    print(f"✓ Created HuggingFace cache structure for {model_id}")

def fetch_files(model_id, cache_dir):
    mapping = file_map_for_model(model_id)
    (cache_dir / "additional_chat_templates").mkdir(exist_ok=True)

    for fname, url in mapping.items():
        dest_path = cache_dir / fname
        if dest_path.exists() and dest_path.stat().st_size > 0:
            print(f"✓ {fname} already exists")
            continue
        print(f"Downloading {fname} ...")
        try:
            ok = download_file(url, dest_path)
            if ok:
                print(f"✓ Downloaded {fname}")
            else:
                print(f"• {fname} not present (skipped)")
        except Exception as e:
            print(f"✗ Failed to download {fname}: {e}")

    # Create the proper HuggingFace cache structure
    create_hf_cache_structure(model_id, cache_dir)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Download Nomic AI model files for offline usage"
    )
    parser.add_argument(
        "--main-only", action="store_true",
        help="Only download the main embedding model (nomic-embed-text-v2-moe)"
    )
    parser.add_argument(
        "--impl-only", action="store_true",
        help="Only download the implementation model (nomic-bert-2048)"
    )
    parser.add_argument(
        "--verify-only", action="store_true",
        help="Only verify existing downloads without downloading new files"
    )
    return parser.parse_args()

def main():
    args = parse_args()

    if args.main_only and args.impl_only:
        print("Error: Cannot specify both --main-only and --impl-only")
        sys.exit(1)

    models_to_download = []
    if args.verify_only:
        print("Verifying existing downloads...")
    elif args.main_only:
        models_to_download = [(MAIN_MODEL_ID, "main model")]
    elif args.impl_only:
        models_to_download = [(IMPL_MODEL_ID, "implementation model")]
    else:
        models_to_download = [
            (MAIN_MODEL_ID, "main model"),
            (IMPL_MODEL_ID, "implementation model")
        ]

    # Download requested models
    cache_dirs = []
    for model_id, model_name in models_to_download:
        cache_dir = target_cache_dir(model_id)
        cache_dir.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {model_name} to: {cache_dir}")
        fetch_files(model_id, cache_dir)
        (cache_dir / ".downloaded").touch()
        cache_dirs.append((cache_dir, model_name))

    # Always verify models (even if not downloaded this time)
    all_models = [
        (target_cache_dir(MAIN_MODEL_ID), "Main model"),
        (target_cache_dir(IMPL_MODEL_ID), "Implementation model")
    ]

    print("\n" + "="*50)
    print("VERIFICATION RESULTS:")
    print("="*50)

    for cache_dir, model_name in all_models:
        if cache_dir.exists():
            verify_essential_files(cache_dir, model_name)
        else:
            print(f"✗ {model_name} not found at: {cache_dir}")

    print("\nReady for offline distillation if all files are present.")

if __name__ == "__main__":
    main()
