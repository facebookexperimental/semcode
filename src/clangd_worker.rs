// SPDX-License-Identifier: MIT OR Apache-2.0
//! Clangd worker process - performs actual enrichment in isolated process
//!
//! This module contains the worker-side code that runs in child processes.
//! Each worker:
//! - Creates its own ClangdAnalyzer instance (no shared state)
//! - Receives work requests via IPC
//! - Performs libclang enrichment
//! - Sends results back via IPC
//!
//! This design sidesteps libclang's internal global locks by running
//! multiple isolated processes, similar to how Python's multiprocessing
//! sidesteps the GIL.

use anyhow::{Context, Result};
use ipc_channel::ipc::{IpcReceiver, IpcSender};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::clangd_analyzer::ClangdAnalyzer;
use crate::{FunctionInfo, MacroInfo, TypeInfo};

/// Work request sent from parent to worker
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkRequest {
    /// File to enrich
    pub file_path: PathBuf,
    /// Functions to enrich (original symbols - will be enriched and returned)
    pub functions: Vec<FunctionInfo>,
    /// Types to enrich (original symbols - will be enriched and returned)
    pub types: Vec<TypeInfo>,
    /// Macros to enrich (original symbols - will be enriched and returned)
    pub macros: Vec<MacroInfo>,
    /// Git file SHA (passed through)
    pub git_file_sha: String,
}

/// Work response sent from worker to parent
#[derive(Debug, Serialize, Deserialize)]
pub struct WorkResponse {
    /// File that was enriched
    pub file_path: PathBuf,
    /// Enriched functions (with USR, signature, etc. applied)
    pub functions: Vec<FunctionInfo>,
    /// Enriched types (with USR, canonical type, etc. applied)
    pub types: Vec<TypeInfo>,
    /// Enriched macros (filtered and with USR applied)
    pub macros: Vec<MacroInfo>,
    /// Git file SHA (passed through)
    pub git_file_sha: String,
    /// Whether file had compile commands
    pub had_compile_commands: bool,
}

/// Worker process entry point
///
/// This is called when the binary is started with --clangd-worker flag.
/// The worker:
/// 1. Connects to parent via IPC
/// 2. Creates ClangdAnalyzer
/// 3. Processes work requests in a loop
/// 4. Exits when channel closes
pub async fn run_worker(
    worker_id: usize,
    work_rx: IpcReceiver<WorkRequest>,
    response_tx: IpcSender<WorkResponse>,
    compile_commands_path: PathBuf,
    source_root: PathBuf,
) -> Result<()> {
    tracing::debug!(
        "Worker {} starting (PID: {})",
        worker_id,
        std::process::id()
    );

    // Create ClangdAnalyzer (isolated per worker, no shared state with other workers)
    let analyzer = ClangdAnalyzer::new(&compile_commands_path, &source_root)
        .context("Failed to create ClangdAnalyzer")?;

    analyzer
        .initialize()
        .await
        .context("Failed to initialize ClangdAnalyzer")?;

    tracing::info!("Worker {} initialized and ready for work, waiting for requests...", worker_id);

    let mut files_processed = 0;

    // Process work requests until channel closes
    while let Ok(request) = work_rx.recv() {
        files_processed += 1;

        if files_processed <= 3 || files_processed % 100 == 0 {
            tracing::info!(
                "Worker {} processing file {}: {:?}",
                worker_id,
                files_processed,
                request.file_path
            );
        }

        // Check if file has compile commands
        let had_compile_commands = analyzer.can_enrich_file(&request.file_path).await;

        if !had_compile_commands {
            // No compile commands - return original symbols with no enrichment
            // But filter macros to function-like only
            let filtered_macros: Vec<MacroInfo> = request.macros.into_iter()
                .filter(|m| m.is_function_like)
                .collect();

            let response = WorkResponse {
                file_path: request.file_path,
                functions: request.functions,
                types: request.types,
                macros: filtered_macros,
                git_file_sha: request.git_file_sha,
                had_compile_commands: false,
            };

            if let Err(e) = response_tx.send(response) {
                tracing::error!("Worker {} failed to send response: {}", worker_id, e);
                break;
            }
            if files_processed <= 3 || files_processed % 100 == 0 {
                tracing::info!("Worker {} sent response {}", worker_id, files_processed);
            }
            continue;
        }

        // Extract (name, line) pairs for enrichment
        let function_keys: Vec<_> = request.functions.iter()
            .map(|f| (f.name.clone(), f.line_start))
            .collect();
        let type_keys: Vec<_> = request.types.iter()
            .map(|t| (t.name.clone(), t.line_start))
            .collect();
        let macro_keys: Vec<_> = request.macros.iter()
            .map(|m| (m.name.clone(), m.line_start))
            .collect();

        // Perform batch enrichment (single libclang parse)
        let result = analyzer
            .enrich_file_batch(
                &request.file_path,
                &function_keys,
                &type_keys,
                &macro_keys,
            )
            .await;

        match result {
            Ok((function_enrichments, type_enrichments, macro_enrichments)) => {
                // Apply enrichments to original symbols
                let mut enriched_functions = request.functions;
                let mut enriched_types = request.types;
                let mut enriched_macros = Vec::new();

                // Apply function enrichments
                for func in enriched_functions.iter_mut() {
                    if let Some(enrichment) = function_enrichments.get(&(func.name.clone(), func.line_start)) {
                        if let Some(ref usr) = enrichment.usr {
                            func.usr = Some(usr.clone());
                        }
                        if let Some(ref sig) = enrichment.signature {
                            func.signature = Some(sig.clone());
                        }
                        if let Some(ref canonical) = enrichment.canonical_type {
                            func.canonical_return_type = Some(canonical.clone());
                        }
                    }
                }

                // Apply type enrichments
                for typ in enriched_types.iter_mut() {
                    if let Some(enrichment) = type_enrichments.get(&(typ.name.clone(), typ.line_start)) {
                        if let Some(ref usr) = enrichment.usr {
                            typ.usr = Some(usr.clone());
                        }
                        if let Some(ref canonical) = enrichment.canonical_type {
                            typ.canonical_name = Some(canonical.clone());
                        }
                    }
                }

                // Apply macro enrichments and filtering
                for mac in request.macros {
                    // Always keep function-like macros
                    if mac.is_function_like {
                        let mut enriched_mac = mac;
                        if let Some(enrichment) = macro_enrichments.get(&(enriched_mac.name.clone(), enriched_mac.line_start)) {
                            if let Some(ref usr) = enrichment.usr {
                                enriched_mac.usr = Some(usr.clone());
                            }
                        }
                        enriched_macros.push(enriched_mac);
                    } else {
                        // For non-function-like macros, only keep if we got USR from clangd
                        if let Some(enrichment) = macro_enrichments.get(&(mac.name.clone(), mac.line_start)) {
                            if let Some(ref usr) = enrichment.usr {
                                let mut enriched_mac = mac;
                                enriched_mac.usr = Some(usr.clone());
                                enriched_macros.push(enriched_mac);
                            }
                        }
                    }
                }

                let response = WorkResponse {
                    file_path: request.file_path,
                    functions: enriched_functions,
                    types: enriched_types,
                    macros: enriched_macros,
                    git_file_sha: request.git_file_sha,
                    had_compile_commands: true,
                };

                if let Err(e) = response_tx.send(response) {
                    tracing::error!("Worker {} failed to send response: {}", worker_id, e);
                    break;
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Worker {} enrichment error for {:?}: {}",
                    worker_id,
                    request.file_path,
                    e
                );

                // Send original symbols without enrichment on error
                let filtered_macros: Vec<MacroInfo> = request.macros.into_iter()
                    .filter(|m| m.is_function_like)
                    .collect();

                let response = WorkResponse {
                    file_path: request.file_path,
                    functions: request.functions,
                    types: request.types,
                    macros: filtered_macros,
                    git_file_sha: request.git_file_sha,
                    had_compile_commands: true,
                };

                if let Err(e) = response_tx.send(response) {
                    tracing::error!("Worker {} failed to send error response: {}", worker_id, e);
                    break;
                }
            }
        }
    }

    tracing::info!(
        "Worker {} exiting: processed {} files, work channel closed",
        worker_id,
        files_processed
    );

    Ok(())
}
