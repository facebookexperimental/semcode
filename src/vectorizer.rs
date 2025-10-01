// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::text_utils::preprocess_code;
use anyhow::Result;
use model2vec_rs::model::StaticModel;
use rayon::prelude::*;
use std::sync::Arc;

// Get batch size from environment or use default based on CPU count
fn get_batch_size() -> usize {
    std::env::var("SEMCODE_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            // Use CPU count * multiplier for optimal batch size
            num_cpus::get() * 64
        })
}

#[derive(Clone)]
pub struct CodeVectorizer {
    model: Arc<StaticModel>,
}

impl CodeVectorizer {
    pub async fn new() -> Result<Self> {
        Self::new_with_config(false, None).await
    }

    pub async fn new_with_config(_use_gpu: bool, model_path: Option<String>) -> Result<Self> {
        // model2vec-rs doesn't use GPU acceleration, so we ignore the gpu flag

        // Download and setup model
        let model = Self::load_model(model_path).await?;

        tracing::info!("Initialized CodeVectorizer using model2vec-rs");

        Ok(Self {
            model: Arc::new(model),
        })
    }

    async fn load_model(model_path: Option<String>) -> Result<StaticModel> {
        // If a specific model path is provided, use it directly
        if let Some(path) = model_path {
            tracing::info!("Loading model2vec from specified path: {}", path);
            return StaticModel::from_pretrained(&path, None, Some(true), None)
                .map_err(|e| anyhow::anyhow!("Failed to load model from '{}': {}", path, e));
        }

        let model_dir = dirs::cache_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("semcode")
            .join("models");

        std::fs::create_dir_all(&model_dir)?;

        // Try to load from local cache
        let local_model_path = model_dir.join("model2vec");

        if local_model_path.exists() {
            tracing::info!("Loading model2vec from local cache: {:?}", local_model_path);
            return StaticModel::from_pretrained(&local_model_path, None, Some(true), None)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to load cached model from '{:?}': {}",
                        local_model_path,
                        e
                    )
                });
        }

        // No model found
        Err(anyhow::anyhow!(
            "No model2vec model found. Please specify a model path using --model-path or place a model in {:?}",
            local_model_path
        ))
    }

    pub fn vectorize_code(&self, code: &str) -> Result<Vec<f32>> {
        let processed_code = preprocess_code(code);
        let vector = self.model.encode_single(&processed_code);

        // Verify vector dimension
        if vector.len() != 256 {
            return Err(anyhow::anyhow!(
                "Model returned vector with dimension {}, expected 256. This indicates a model configuration mismatch.",
                vector.len()
            ));
        }

        Ok(vector)
    }

    pub fn vectorize_batch(&self, code_snippets: &[&str]) -> Result<Vec<Vec<f32>>> {
        // For very large batches, process in chunks to manage memory
        let max_chunk_size = 10000;

        if code_snippets.len() > max_chunk_size {
            let mut all_vectors = Vec::new();
            for chunk in code_snippets.chunks(max_chunk_size) {
                let chunk_vectors = self.vectorize_batch_internal(chunk)?;
                all_vectors.extend(chunk_vectors);
            }
            return Ok(all_vectors);
        }

        self.vectorize_batch_internal(code_snippets)
    }

    fn vectorize_batch_internal(&self, code_snippets: &[&str]) -> Result<Vec<Vec<f32>>> {
        // Preprocess all code snippets
        let processed_snippets: Vec<String> = code_snippets
            .par_iter()
            .map(|&code| preprocess_code(code))
            .collect();

        // Use model2vec-rs batch processing with custom batch size and max_length
        let batch_size = get_batch_size();
        let vectors = self
            .model
            .encode_with_args(&processed_snippets, None, batch_size);

        // Verify all vectors have the expected dimension
        for (i, vector) in vectors.iter().enumerate() {
            if vector.len() != 256 {
                return Err(anyhow::anyhow!(
                    "Model returned vector {} with dimension {}, expected 256. This indicates a model configuration mismatch.",
                    i, vector.len()
                ));
            }
        }

        Ok(vectors)
    }

    pub fn warmup(&self) -> Result<()> {
        // Warmup the model with a dummy input to initialize caches
        tracing::info!("Warming up the model...");
        let dummy_code = "void dummy_function() { return; }";
        let _ = self.vectorize_code(dummy_code)?;
        tracing::info!("Model warmup complete");
        Ok(())
    }

    /// Get the actual dimension of vectors produced by the model
    pub fn get_model_dimension(&self) -> Result<usize> {
        let test_code = "int main() { return 0; }";
        let processed_code = preprocess_code(test_code);
        let vector = self.model.encode_single(&processed_code);
        Ok(vector.len())
    }

    /// Verify model produces expected dimension and log details
    pub fn verify_model_dimension(&self) -> Result<()> {
        let actual_dim = self.get_model_dimension()?;
        tracing::info!("Model produces {}-dimensional vectors", actual_dim);

        if actual_dim == 256 {
            tracing::info!("✓ Model dimension matches expected 256 dimensions");
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "✗ Model dimension mismatch: expected 256, got {}. Please check your model configuration.",
                actual_dim
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::text_utils::preprocess_code;

    #[test]
    fn test_preprocess_code() {
        let input = r#"
        __attribute__((packed)) struct foo {
            int x;
        };

        // This is a comment
        EXPORT_SYMBOL(foo);

        /* Multi-line
           comment */
        void bar() {
            asm volatile("nop");
        }
        "#;

        let processed = preprocess_code(input);
        assert!(!processed.contains("__attribute__"));
        assert!(!processed.contains("EXPORT_SYMBOL"));
        assert!(!processed.contains("//"));
        assert!(!processed.contains("/*"));
        assert!(!processed.contains("asm volatile"));
    }

    #[test]
    fn test_preprocess_code_preserves_line_structure() {
        let input = r#"if (condition) {
    do_something();
    do_another_thing();
}"#;

        let processed = preprocess_code(input);

        // Should preserve newlines but normalize spaces/tabs
        assert!(processed.contains('\n'), "Should preserve newlines");

        // Should not be collapsed to single line
        assert!(!processed.eq("if (condition) { do_something(); do_another_thing(); }"));

        // Should have basic structure
        assert!(processed.contains("if (condition) {\n"));
        assert!(processed.contains("do_something();\n"));

        println!("Processed: {processed:?}");
    }
}
