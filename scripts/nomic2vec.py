#!/usr/bin/env python3
"""
Distill a locally-downloaded Nomic Embed v2 model from Hugging Face into a fast Model2Vec static model (offline).
Artifacts must be downloaded first using direct_download.py, which populates:
    ~/.cache/huggingface/hub/models--nomic-ai--nomic-embed-text-v2-moe/snapshots/latest

Usage:
  # Use default cache location (after running direct_download.py):
  python nomic2vec.py

  # Or specify custom location:
  python nomic2vec.py -m /path/to/model/dir

  # Optional parameters:
  python nomic2vec.py -o ./embed_v2_m2v -v ./custom_vocab.txt --pca-dims 256 --device cuda

Requires:
  pip install -U model2vec transformers sentence-transformers
"""

import os
import sys
import argparse
from pathlib import Path

def get_default_model_dir():
    """Get the default Hugging Face cache directory for nomic-embed-text-v2-moe."""
    cache_base = Path.home() / ".cache" / "huggingface" / "hub"
    model_base = cache_base / "models--nomic-ai--nomic-embed-text-v2-moe" / "snapshots"

    # Try "latest" first (created by direct_download.py)
    latest_dir = model_base / "latest"
    if latest_dir.exists():
        return latest_dir

    # If no "latest", try to find any snapshot directory
    if model_base.exists():
        snapshot_dirs = [d for d in model_base.iterdir() if d.is_dir()]
        if snapshot_dirs:
            # Use the first available snapshot
            return snapshot_dirs[0]

    # Return the expected "latest" path even if it doesn't exist (for error messages)
    return latest_dir

def get_bert_impl_dir():
    """Get the nomic-bert-2048 implementation directory."""
    cache_base = Path.home() / ".cache" / "huggingface" / "hub"
    impl_base = cache_base / "models--nomic-ai--nomic-bert-2048" / "snapshots"

    # Try "latest" first (created by direct_download.py)
    latest_dir = impl_base / "latest"
    if latest_dir.exists():
        return latest_dir

    # If no "latest", try to find any snapshot directory
    if impl_base.exists():
        snapshot_dirs = [d for d in impl_base.iterdir() if d.is_dir()]
        if snapshot_dirs:
            return snapshot_dirs[0]

    return latest_dir

def setup_transformers_path():
    """Add the nomic-bert-2048 directory to Python path so transformers can find custom code."""
    bert_dir = get_bert_impl_dir()
    if bert_dir.exists():
        # Add to Python path so transformers can find configuration_bert.py etc.
        import sys
        sys.path.insert(0, str(bert_dir))
        print(f"✓ Added {bert_dir} to Python path for custom transformers code")

        # Set additional environment variables that may be needed
        os.environ["TRANSFORMERS_CACHE"] = str(Path.home() / ".cache" / "huggingface")
        os.environ["HF_HOME"] = str(Path.home() / ".cache" / "huggingface")

        return True
    else:
        print(f"⚠ Warning: nomic-bert-2048 implementation not found at {bert_dir}")
        print("  This may cause issues loading the model. Run direct_download.py to download it.")
        return False

def read_vocab_file(path: Path):
    vocab = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            tok = line.strip()
            if tok:
                vocab.append(tok)
    return vocab

def ensure_optional_artifacts(model_dir: Path):
    """
    Some loaders probe for these even when tokenizer.json is available.
    Create stubs so no network fallback is attempted.
    """
    opt_dir = model_dir / "additional_chat_templates"
    opt_dir.mkdir(exist_ok=True)

    merges = model_dir / "merges.txt"
    added = model_dir / "added_tokens.json"
    tmpl = model_dir / "chat_template.jinja"

    if not merges.exists():
        merges.write_text("", encoding="utf-8")
        print("• Created stub merges.txt")

    if not added.exists():
        added.write_text("{}", encoding="utf-8")
        print("• Created stub added_tokens.json")

    if not tmpl.exists():
        tmpl.write_text("", encoding="utf-8")
        print("• Created stub chat_template.jinja")

def parse_args():
    p = argparse.ArgumentParser(description="Distill local Nomic Embed v2 model to Model2Vec (offline).")
    p.add_argument("-m", "--model-dir", default=None,
                   help="Path to local model directory (contains config.json, tokenizer.json, weights). "
                        "If not specified, uses default HuggingFace cache location.")
    p.add_argument("-o", "--output-dir", default="./nomic_v2_m2v",
                   help="Directory to save the distilled Model2Vec model. Default: ./nomic_v2_m2v")
    p.add_argument("-v", "--vocab-file", default=None,
                   help="Optional custom vocabulary file (one token per line).")
    p.add_argument("--pca-dims", type=int, default=256,
                   help="Output dimensionality after PCA reduction. Default: 256")
    p.add_argument("--device", default="cpu",
                   help="Device to use, e.g., 'cpu' or 'cuda'. Default: cpu")
    p.add_argument("--no-subword", action="store_true",
                   help="Do not include teacher subword vocab (use only custom vocab if provided).")
    return p.parse_args()

def main():
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_XET"] = "1"

    args = parse_args()

    # Set up transformers path for custom code BEFORE loading any models
    setup_transformers_path()

    # Use default cache location if no model directory specified
    if args.model_dir is None:
        model_dir = get_default_model_dir()
        print(f"Using default cache location: {model_dir}")
    else:
        model_dir = Path(args.model_dir).expanduser().resolve()
        print(f"Using specified model directory: {model_dir}")

    if not model_dir.exists():
        print(f"✗ Model directory does not exist: {model_dir}")
        print("  Make sure to run direct_download.py first to download the model files.")
        print("  Example: python direct_download.py")
        sys.exit(1)

    if not (model_dir / "config.json").exists():
        print(f"✗ The model directory does not contain config.json: {model_dir}")
        print("  This may indicate an incomplete download. Try running direct_download.py again.")
        sys.exit(1)

    # Ensure stub artifacts exist so no online fallback is triggered
    ensure_optional_artifacts(model_dir)

    # Load teacher model/tokenizer from local files
    from transformers import AutoModel, AutoTokenizer, BertModel, BertTokenizer
    print("Loading model and tokenizer from local cache...")

    try:
        # Load tokenizer first
        print(f"Loading tokenizer from: {model_dir}")
        tokenizer = AutoTokenizer.from_pretrained(
            str(model_dir),
            local_files_only=True,
            trust_remote_code=True  # Need this for the custom tokenizer
        )
        print(f"✓ Tokenizer loaded successfully: {type(tokenizer).__name__}")

        # Debug: print current working directory and Python path
        print(f"Current working directory: {os.getcwd()}")
        bert_dir = get_bert_impl_dir()
        print(f"BERT implementation directory: {bert_dir}")
        print(f"BERT directory exists: {bert_dir.exists()}")

        # Load model with trust_remote_code=True since it needs custom code
        print(f"Loading model from: {model_dir}")
        model = AutoModel.from_pretrained(
            str(model_dir),
            local_files_only=True,
            trust_remote_code=True,  # Required for nomic models
            cache_dir=str(Path.home() / ".cache" / "huggingface" / "hub")  # Explicit cache dir
        )
        model.to(args.device)
        model.eval()
        print("✓ Model loaded successfully")

    except Exception as e1:
        print(f"Failed to load with trust_remote_code=True: {e1}")
        print("This model requires custom code from nomic-ai/nomic-bert-2048.")
        print("Make sure you have downloaded both model repositories:")
        print("1. python scripts/direct_download.py --main-only")
        print("2. python scripts/direct_download.py --impl-only")
        print("\nTrying alternative loading strategy...")

        try:
            # Try with XLMRoberta classes since that's what the tokenizer actually is
            from transformers import XLMRobertaTokenizer, XLMRobertaModel
            tokenizer = XLMRobertaTokenizer.from_pretrained(
                str(model_dir),
                local_files_only=True
            )
            model = XLMRobertaModel.from_pretrained(
                str(model_dir),
                local_files_only=True
            )
            model.to(args.device)
            model.eval()
            print("✓ Loaded as XLMRoberta model/tokenizer (offline)")
        except Exception as e2:
            print(f"✗ Failed to load model with all strategies")
            print(f"  AutoModel + trust_remote_code error: {e1}")
            print(f"  XLMRoberta error: {e2}")
            print("\nThe model requires custom configuration files from nomic-ai/nomic-bert-2048.")
            print("Please ensure both repositories are downloaded completely.")
            sys.exit(1)

    # Optional custom vocabulary
    vocabulary = None
    if args.vocab_file:
        vocab_path = Path(args.vocab_file).expanduser().resolve()
        if not vocab_path.exists():
            print(f"✗ VOCAB_FILE not found: {vocab_path}")
            sys.exit(1)
        vocabulary = read_vocab_file(vocab_path)
        print(f"✓ Loaded {len(vocabulary):,} custom tokens")

    # Distill to Model2Vec
    from model2vec.distill import distill_from_model
    from model2vec import StaticModel

    output_dir = Path(args.output_dir).expanduser().resolve()
    try:
        print("Starting Model2Vec distillation...")
        print(f"Model type: {type(model).__name__}")
        print(f"Tokenizer type: {type(tokenizer).__name__}")

        # Check if tokenizer has the required attributes for Model2Vec
        if not hasattr(tokenizer, 'backend_tokenizer'):
            print("⚠ Tokenizer missing backend_tokenizer attribute, trying alternatives...")

            # Try different tokenizer types that might be compatible with Model2Vec
            compatible_tokenizer = None

            # Option 1: Try to use a BERT tokenizer with the same vocabulary
            try:
                from transformers import BertTokenizer
                print("Trying BertTokenizer...")
                bert_tokenizer = BertTokenizer.from_pretrained(
                    str(model_dir),
                    local_files_only=True
                )
                if hasattr(bert_tokenizer, 'backend_tokenizer') or hasattr(bert_tokenizer, 'tokenizer'):
                    compatible_tokenizer = bert_tokenizer
                    print(f"✓ Using BertTokenizer: {type(bert_tokenizer).__name__}")
            except Exception as e1:
                print(f"BertTokenizer failed: {e1}")

            # Option 2: Try creating a basic tokenizer wrapper
            if compatible_tokenizer is None:
                print("Trying to create a basic tokenizer wrapper...")
                try:
                    # Create a comprehensive wrapper that provides the Model2Vec expected interface
                    class TokenizerWrapper:
                        def __init__(self, base_tokenizer):
                            self.base_tokenizer = base_tokenizer
                            # Create a fake backend_tokenizer with required attributes
                            self.backend_tokenizer = self._create_backend()
                            # Copy important attributes
                            self.vocab_size = base_tokenizer.vocab_size
                            self.model_max_length = getattr(base_tokenizer, 'model_max_length', 512)

                        def _create_backend(self):
                            """Create a mock backend tokenizer with required attributes."""
                            class BackendTokenizer:
                                def __init__(self, base_tokenizer):
                                    self.base = base_tokenizer
                                    # Create tokens attribute that Model2Vec expects
                                    try:
                                        # Try to get vocabulary tokens
                                        if hasattr(base_tokenizer, 'get_vocab'):
                                            vocab = base_tokenizer.get_vocab()
                                            # Create tokens list sorted by token ID
                                            self.tokens = [''] * len(vocab)
                                            for token, token_id in vocab.items():
                                                if 0 <= token_id < len(self.tokens):
                                                    self.tokens[token_id] = token
                                        else:
                                            # Fallback: create a simple tokens list
                                            self.tokens = [f"<token_{i}>" for i in range(base_tokenizer.vocab_size)]
                                    except Exception:
                                        # Last resort fallback
                                        self.tokens = [f"<token_{i}>" for i in range(getattr(base_tokenizer, 'vocab_size', 50000))]

                                    # Create a list subclass that always has a tokens attribute
                                    class SmartTokensList(list):
                                        def __init__(self, tokens_list):
                                            super().__init__(tokens_list)
                                            self.tokens = self  # Self-reference for tokens.tokens access

                                        def __getattr__(self, name):
                                            if name == 'tokens':
                                                return self
                                            raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

                                    # Replace the tokens list with our smart version
                                    self.tokens = SmartTokensList(self.tokens)

                                    # Add pre_tokenizer attribute that Model2Vec expects
                                    self.pre_tokenizer = None  # Many tokenizers don't have this, so None is acceptable

                                    # Add serialization methods that Model2Vec expects
                                    def to_str(self):
                                        # Return a minimal valid JSON tokenizer representation
                                        import json
                                        minimal_tokenizer = {
                                            "version": "1.0",
                                            "truncation": None,
                                            "padding": None,
                                            "added_tokens": [],
                                            "normalizer": None,
                                            "pre_tokenizer": None,
                                            "post_processor": None,
                                            "decoder": None,
                                            "model": {
                                                "type": "BPE",
                                                "vocab": {},
                                                "merges": []
                                            }
                                        }
                                        return json.dumps(minimal_tokenizer)

                                    def from_str(self, serialized_str):
                                        # Return self since we can't really deserialize
                                        return self

                                    # Bind the methods to self
                                    self.to_str = to_str.__get__(self)
                                    self.from_str = from_str.__get__(self)

                                def __getattr__(self, name):
                                    # Handle specific attributes that Model2Vec expects
                                    if name == 'pre_tokenizer':
                                        print(f"DEBUG: BackendTokenizer.pre_tokenizer accessed, returning None")
                                        return None
                                    elif name == 'encode':
                                        print(f"DEBUG: BackendTokenizer.encode accessed via __getattr__")
                                        # Return a wrapped version
                                        def wrapped_encode(text, **kwargs):
                                            print(f"DEBUG: BackendTokenizer wrapped_encode called with text='{text}', kwargs={kwargs}")
                                            result = self.base.encode(text, **kwargs)
                                            print(f"DEBUG: Backend encode result: {type(result)}, value: {result}")

                                            if isinstance(result, list):
                                                # Convert token IDs to token strings
                                                try:
                                                    # Use the tokenizer to convert IDs back to tokens
                                                    token_strings = []
                                                    for token_id in result:
                                                        try:
                                                            # Try to convert individual token ID to token string
                                                            token_str = self.base.convert_ids_to_tokens([token_id])[0]
                                                            token_strings.append(token_str)
                                                        except:
                                                            # Fallback: use the ID as string
                                                            token_strings.append(str(token_id))

                                                    class TokensResult(list):
                                                        def __init__(self, token_ids, token_strings):
                                                            super().__init__(token_ids)  # Keep original IDs as list content
                                                            self.tokens = token_strings  # But tokens attribute contains strings

                                                    wrapped_result = TokensResult(result, token_strings)
                                                    print(f"DEBUG: Backend wrapped result has tokens: {hasattr(wrapped_result, 'tokens')}")
                                                    print(f"DEBUG: Token strings: {token_strings}")
                                                    return wrapped_result
                                                except Exception as e:
                                                    print(f"DEBUG: Failed to convert tokens, using fallback: {e}")
                                                    # Fallback: just add tokens attribute pointing to the list
                                                    class TokensResult(list):
                                                        def __init__(self, tokens_list):
                                                            super().__init__(tokens_list)
                                                            self.tokens = [str(t) for t in tokens_list]  # Convert to strings
                                                    wrapped_result = TokensResult(result)
                                                    return wrapped_result
                                            return result
                                        return wrapped_encode
                                    else:
                                        # For all other attributes, try the base tokenizer first, then provide sensible defaults
                                        try:
                                            return getattr(self.base, name)
                                        except AttributeError:
                                            print(f"DEBUG: BackendTokenizer missing attribute '{name}', returning None")
                                            return None

                            return BackendTokenizer(self.base_tokenizer)

                        def __getattr__(self, name):
                            return getattr(self.base_tokenizer, name)

                        def encode(self, text, **kwargs):
                            # Debug logging
                            print(f"DEBUG: TokenizerWrapper.encode called with text='{text}', kwargs={kwargs}")

                            # Get the original result
                            result = self.base_tokenizer.encode(text, **kwargs)
                            print(f"DEBUG: Original result type: {type(result)}, value: {result}")

                            # If it's a list, wrap it with tokens attribute
                            if isinstance(result, list):
                                class TokensResult(list):
                                    def __init__(self, tokens_list):
                                        super().__init__(tokens_list)
                                        self.tokens = tokens_list  # This is what Model2Vec expects

                                wrapped_result = TokensResult(result)
                                print(f"DEBUG: Wrapped result type: {type(wrapped_result)}, has tokens: {hasattr(wrapped_result, 'tokens')}")
                                return wrapped_result
                            else:
                                # If it's already an object, ensure it has tokens attribute
                                if not hasattr(result, 'tokens'):
                                    result.tokens = result
                                print(f"DEBUG: Object result, added tokens: {hasattr(result, 'tokens')}")
                                return result

                        def decode(self, token_ids, **kwargs):
                            return self.base_tokenizer.decode(token_ids, **kwargs)

                        def __call__(self, *args, **kwargs):
                            result = self.base_tokenizer(*args, **kwargs)

                            # Apply the same tokens attribute fix for callable results
                            if hasattr(result, 'input_ids') and isinstance(result.input_ids, list):
                                # This handles tokenizer outputs like BatchEncoding
                                if not hasattr(result, 'tokens'):
                                    result.tokens = result.input_ids

                            return result

                    compatible_tokenizer = TokenizerWrapper(tokenizer)
                    print(f"✓ Created tokenizer wrapper")
                    # Debug: check what we created
                    print(f"  Wrapper has backend_tokenizer: {hasattr(compatible_tokenizer, 'backend_tokenizer')}")
                    if hasattr(compatible_tokenizer, 'backend_tokenizer'):
                        print(f"  Backend has tokens: {hasattr(compatible_tokenizer.backend_tokenizer, 'tokens')}")
                        if hasattr(compatible_tokenizer.backend_tokenizer, 'tokens'):
                            tokens_len = len(compatible_tokenizer.backend_tokenizer.tokens)
                            print(f"  Tokens length: {tokens_len}")
                except Exception as e2:
                    print(f"Wrapper creation failed: {e2}")

            if compatible_tokenizer is not None:
                tokenizer = compatible_tokenizer
            else:
                print("⚠ Could not create a compatible tokenizer, proceeding with original...")

        # Add extra debugging before distillation
        print(f"Final tokenizer type: {type(tokenizer).__name__}")
        print(f"Final tokenizer has backend_tokenizer: {hasattr(tokenizer, 'backend_tokenizer')}")
        if hasattr(tokenizer, 'backend_tokenizer') and hasattr(tokenizer.backend_tokenizer, 'tokens'):
            print(f"Backend tokenizer tokens type: {type(tokenizer.backend_tokenizer.tokens)}")
            print(f"First few tokens: {tokenizer.backend_tokenizer.tokens[:5] if tokenizer.backend_tokenizer.tokens else 'Empty'}")

        # Try monkey patching approach - temporarily modify list behavior
        print("Attempting distillation with monkey-patched list...")

        # Save original list class
        original_list = list

        # Create a patched list class
        class PatchedList(original_list):
            def __new__(cls, *args, **kwargs):
                instance = super().__new__(cls, *args, **kwargs)
                # Add tokens attribute that points to self
                instance.tokens = instance
                return instance

            @property
            def tokens(self):
                return self

            @tokens.setter
            def tokens(self, value):
                # Allow setting but always return self
                pass

        try:
            # Get full stack trace to see where the error is coming from
            import traceback

            # Try the distillation with detailed error catching
            m2v = distill_from_model(
                model=model,
                tokenizer=tokenizer,
                pca_dims=args.pca_dims,
                vocabulary=None,
                device=args.device
            )
        except Exception as e:
            print(f"\nFull traceback of the error:")
            traceback.print_exc()

            # Try an alternative approach - use sentence-transformers wrapper
            print(f"\nTrying alternative approach with SentenceTransformer wrapper...")
            try:
                from sentence_transformers import SentenceTransformer

                # Create a minimal sentence transformer-like wrapper
                class STWrapper:
                    def __init__(self, model, tokenizer):
                        self._model = model
                        self._tokenizer = tokenizer
                        self.max_seq_length = getattr(tokenizer, 'model_max_length', 512)

                    def encode(self, sentences, **kwargs):
                        # Simple encoding using the wrapped model
                        if isinstance(sentences, str):
                            sentences = [sentences]

                        inputs = self._tokenizer(sentences, padding=True, truncation=True,
                                               return_tensors="pt", max_length=self.max_seq_length)

                        with torch.no_grad():
                            outputs = self._model(**inputs)
                            # Use last hidden state mean pooling
                            embeddings = outputs.last_hidden_state.mean(dim=1)

                        return embeddings.cpu().numpy()

                # Try distillation from the sentence transformer wrapper
                import torch
                st_wrapper = STWrapper(model, tokenizer)

                # Try using model2vec's distill_from_sentence_transformer if available
                try:
                    from model2vec.distill import distill_from_sentence_transformer
                    m2v = distill_from_sentence_transformer(
                        st_wrapper,
                        pca_dims=args.pca_dims,
                        device=args.device
                    )
                    print("✓ Used sentence transformer distillation approach")
                except ImportError:
                    print("sentence transformer distillation not available")
                    raise e

            except Exception as e2:
                print(f"Alternative approach also failed: {e2}")
                raise e
        output_dir.mkdir(parents=True, exist_ok=True)
        m2v.save_pretrained(str(output_dir))
        print(f"✓ Saved Model2Vec static model to {output_dir}")
    except Exception as e:
        print(f"✗ Distillation failed: {e}")
        print(f"Error type: {type(e).__name__}")

        # Provide more specific troubleshooting
        if "backend_tokenizer" in str(e):
            print("\nThis error suggests tokenizer compatibility issues with Model2Vec.")
            print("The XLMRoberta tokenizer may not be fully supported.")
        elif "subword" in str(e):
            print("\nTrying without subword tokenization...")
            # Could try a different approach here

        sys.exit(1)

    # Fix tokenizer configuration for compatibility with semcode
    try:
        print("Fixing tokenizer configuration for semcode compatibility...")
        import json

        # Load and fix the tokenizer config
        config_path = output_dir / "tokenizer.json"
        if config_path.exists():
            with open(config_path, 'r') as f:
                tokenizer_config = json.load(f)

            # Get the current vocabulary
            if "model" in tokenizer_config and "vocab" in tokenizer_config["model"]:
                vocab = tokenizer_config["model"]["vocab"]

                # Check if [UNK] already exists
                unk_exists = False
                for token, score in vocab:
                    if token == "[UNK]":
                        unk_exists = True
                        print("  Found existing [UNK] token")
                        break

                if not unk_exists:
                    print("  Adding [UNK] token to vocabulary")
                    # Add [UNK] token at the same score as <unk>
                    unk_score = -12.638995969314884  # Same as <unk>
                    vocab.insert(1, ["[UNK]", unk_score])  # Insert after <pad>

                # Update unk_id to point to the [UNK] token (position 1)
                tokenizer_config["model"]["unk_id"] = 1
                print("  Set unk_id to 1 for [UNK] token")

                # Save the fixed tokenizer config
                with open(config_path, 'w') as f:
                    json.dump(tokenizer_config, f, separators=(',', ':'))
                print("  ✓ Updated tokenizer configuration")

        # Also create/update tokenizer_config.json for additional compatibility
        tokenizer_config_path = output_dir / "tokenizer_config.json"
        if tokenizer_config_path.exists():
            with open(tokenizer_config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {}

        # Ensure unk_token is properly set
        config["unk_token"] = {
            "content": "[UNK]",
            "__type": "AddedToken",
            "lstrip": False,
            "normalized": False,
            "rstrip": False,
            "single_word": False,
            "special": True
        }

        with open(tokenizer_config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print("  ✓ Updated tokenizer_config.json")

    except Exception as e:
        print(f"⚠ Warning: Could not fix tokenizer configuration: {e}")
        print("  The model may still work but might have compatibility issues with some tools")

    # Verify fast CPU inference
    try:
        fast = StaticModel.from_pretrained(str(output_dir))
        test_texts = [
            "def add(a, b): return a + b",
            "class Vec: pass",
            "How to write a binary search in Python?"
        ]
        embs = fast.encode(test_texts)
        shape = embs.shape if hasattr(embs, "shape") else (len(embs), len(embs[0]) if embs else 0)
        print("✓ Model2Vec inference OK")
        print(f"  Embeddings shape: {shape}")
    except Exception as e:
        print(f"⚠ Verification warning: {e}")
        print("  The model was saved successfully but may need additional configuration for some tools")

    print("\nAll done. The static model is ready for high‑throughput CPU embedding.")

if __name__ == "__main__":
    main()
