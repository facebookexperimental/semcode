// SPDX-License-Identifier: MIT OR Apache-2.0
//! Test utility to verify model vector dimensions

use anyhow::Result;
use clap::Parser;
use semcode::{CodeVectorizer, DatabaseManager};

#[derive(Parser, Debug)]
#[command(name = "test-vectors")]
#[command(about = "Test and verify vector dimensions from the model")]
struct Args {
    /// Database path
    #[arg(short, long)]
    database: Option<String>,

    /// Model path (optional, for testing specific model)
    #[arg(short, long)]
    model_path: Option<String>,

    /// Use GPU acceleration (if available)
    #[arg(long)]
    gpu: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    semcode::logging::init_tracing();

    let args = Args::parse();

    println!("🧪 Vector Dimension Test");
    println!("========================\n");

    // Test 1: Model dimension verification
    println!("1. Testing model vector dimension...");
    match CodeVectorizer::new_with_config(args.gpu, args.model_path).await {
        Ok(vectorizer) => {
            match vectorizer.get_model_dimension() {
                Ok(dimension) => {
                    println!("   ✓ Model produces {dimension}-dimensional vectors");

                    if dimension == 256 {
                        println!("   ✓ Dimension matches expected 256");
                    } else {
                        println!("   ⚠️  Expected 256 dimensions, got {dimension}");
                    }

                    // Test with actual code
                    println!("\n2. Testing with sample code...");
                    let test_codes = [
                        "int main() { return 0; }",
                        "void hello_world() { printf(\"Hello, World!\\n\"); }",
                        "struct Point { int x, y; };",
                    ];

                    for (i, code) in test_codes.iter().enumerate() {
                        match vectorizer.vectorize_code(code) {
                            Ok(vector) => {
                                println!("   ✓ Sample {} → {} dimensions", i + 1, vector.len());
                            }
                            Err(e) => {
                                println!("   ✗ Sample {} failed: {}", i + 1, e);
                                return Err(e);
                            }
                        }
                    }

                    // Test batch processing
                    println!("\n3. Testing batch processing...");
                    match vectorizer.vectorize_batch(&test_codes) {
                        Ok(vectors) => {
                            println!("   ✓ Batch processed {} vectors", vectors.len());
                            for (i, vector) in vectors.iter().enumerate() {
                                println!("     - Vector {}: {} dimensions", i + 1, vector.len());
                            }
                        }
                        Err(e) => {
                            println!("   ✗ Batch processing failed: {e}");
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    println!("   ✗ Failed to get model dimension: {e}");
                    return Err(e);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Failed to initialize vectorizer: {e}");
            return Err(e);
        }
    }

    // Test 2: Database dimension verification (if database provided)
    if let Some(db_path) = args.database {
        println!("\n4. Testing database vector configuration...");

        // Use current directory as git repo for database connection
        match DatabaseManager::new(&db_path, ".".to_string()).await {
            Ok(db_manager) => {
                if let Ok(vector_store) = db_manager.get_vector_store().await {
                    match vector_store.verify_vector_dimension().await {
                        Ok(db_dimension) => {
                            println!(
                                "   ✓ Database configured for {db_dimension}-dimensional vectors"
                            );

                            if db_dimension == 256 {
                                println!("   ✓ Database dimension matches expected 256");
                            } else {
                                println!(
                                    "   ⚠️  Database expects {db_dimension} dimensions, but model produces 256"
                                );
                                println!("   💡 Consider recreating the vectors table to match the model");
                            }
                        }
                        Err(e) => {
                            println!("   ⚠️  Could not verify database dimension: {e}");
                        }
                    }
                } else {
                    println!("   ⚠️  Could not access vector store (table may not exist yet)");
                }
            }
            Err(e) => {
                println!("   ⚠️  Could not connect to database: {e}");
            }
        }
    } else {
        println!("\n4. Skipping database test (no database path provided)");
        println!("   💡 Use --database <path> to test database compatibility");
    }

    println!("\n🎉 Vector dimension test complete!");
    Ok(())
}
