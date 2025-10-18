// SPDX-License-Identifier: MIT OR Apache-2.0
//! Clangd processor - manages worker pool and distributes enrichment work
//!
//! This module contains the controller that runs in the main process.
//! It:
//! - Spawns multiple worker processes (self-spawning same binary)
//! - Distributes work requests to workers via IPC
//! - Collects enrichment results
//! - Handles worker failures and cleanup
//!
//! This design achieves parallelism by running multiple isolated processes,
//! each with its own libclang instance, avoiding internal libclang locks.

use anyhow::{Context, Result};
use crossbeam_channel::{bounded, Receiver, Sender};
use ipc_channel::ipc::{IpcOneShotServer, IpcReceiver, IpcSender};
use std::env;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use crate::clangd_worker::{WorkRequest, WorkResponse};
use crate::{FunctionInfo, MacroInfo, TypeInfo};

/// Parsed file ready for enrichment
#[derive(Debug)]
pub struct EnrichmentRequest {
    pub path: PathBuf,
    pub functions: Vec<FunctionInfo>,
    pub types: Vec<TypeInfo>,
    pub macros: Vec<MacroInfo>,
    pub git_file_sha: String,
    /// Worker assignment for round-robin distribution
    pub worker_id: usize,
}

/// Enriched file ready for database insertion
#[derive(Debug)]
pub struct EnrichmentResponse {
    pub path: PathBuf,
    pub functions: Vec<FunctionInfo>,
    pub types: Vec<TypeInfo>,
    pub macros: Vec<MacroInfo>,
    pub git_file_sha: String,
}

/// Worker pool that manages multiple clangd worker processes
pub struct ClangdProcessor {
    workers: Arc<std::sync::Mutex<Vec<WorkerHandle>>>,
    worker_channels: Arc<std::sync::Mutex<Vec<IpcSender<WorkRequest>>>>,
    work_tx: Option<Sender<EnrichmentRequest>>,
    result_rx: Receiver<EnrichmentResponse>,
    result_tx: Sender<EnrichmentResponse>,  // Keep for spawning collectors
    coordinator_thread: Option<thread::JoinHandle<()>>,  // Need to join on drop

    // Configuration for worker processes
    compile_commands_path: PathBuf,
    source_root: PathBuf,
    max_workers: usize,
    worker_binary_path: PathBuf,  // Path to binary to spawn for workers

    // Statistics
    pub files_with_compile_commands: Arc<AtomicUsize>,
    pub enriched_functions: Arc<AtomicUsize>,
    pub enriched_types: Arc<AtomicUsize>,
    pub enriched_macros: Arc<AtomicUsize>,
    pub macros_kept_by_clangd: Arc<AtomicUsize>,
}

struct WorkerHandle {
    id: usize,
    process: Child,
}

impl ClangdProcessor {
    /// Create a new processor with default worker count (num_cpus - 2)
    ///
    /// # Arguments
    /// * `compile_commands_path` - Path to compile_commands.json
    /// * `source_root` - Root directory of source code
    pub fn new_with_defaults(
        compile_commands_path: PathBuf,
        source_root: PathBuf,
    ) -> Result<Self> {
        let num_workers = Self::default_worker_count();
        let worker_binary = env::current_exe().context("Failed to get current executable path")?;
        Self::new_with_binary(num_workers, compile_commands_path, source_root, worker_binary)
    }

    /// Calculate default worker count: num_cpus - 2, with minimum of 1
    pub fn default_worker_count() -> usize {
        let num_cpus = num_cpus::get();
        if num_cpus <= 2 {
            1
        } else {
            num_cpus - 2
        }
    }

    /// Create a new processor with worker pool
    ///
    /// # Arguments
    /// * `max_workers` - Maximum number of worker processes
    /// * `compile_commands_path` - Path to compile_commands.json
    /// * `source_root` - Root directory of source code
    pub fn new(
        max_workers: usize,
        compile_commands_path: PathBuf,
        source_root: PathBuf,
    ) -> Result<Self> {
        let worker_binary = env::current_exe().context("Failed to get current executable path")?;
        Self::new_with_binary(max_workers, compile_commands_path, source_root, worker_binary)
    }

    /// Create a new processor with custom worker binary path (for testing)
    ///
    /// # Arguments
    /// * `max_workers` - Maximum number of worker processes
    /// * `compile_commands_path` - Path to compile_commands.json
    /// * `source_root` - Root directory of source code
    /// * `worker_binary_path` - Path to binary to use for worker processes
    pub fn new_with_binary(
        max_workers: usize,
        compile_commands_path: PathBuf,
        source_root: PathBuf,
        worker_binary_path: PathBuf,
    ) -> Result<Self> {
        tracing::info!(
            "Creating ClangdProcessor with capacity for {} workers",
            max_workers
        );

        // Channels for work distribution (large buffer to avoid backpressure)
        let (work_tx, work_rx) = bounded::<EnrichmentRequest>(100_000);
        let (result_tx, result_rx) = bounded::<EnrichmentResponse>(100_000);

        // Statistics
        let files_with_compile_commands = Arc::new(AtomicUsize::new(0));
        let enriched_functions = Arc::new(AtomicUsize::new(0));
        let enriched_types = Arc::new(AtomicUsize::new(0));
        let enriched_macros = Arc::new(AtomicUsize::new(0));
        let macros_kept_by_clangd = Arc::new(AtomicUsize::new(0));

        // Workers will be spawned by the pipeline when enrichment begins
        // Set up shared worker channels for coordinator
        let worker_channels = Arc::new(std::sync::Mutex::new(Vec::<IpcSender<WorkRequest>>::new()));
        let workers = Arc::new(std::sync::Mutex::new(Vec::<WorkerHandle>::new()));

        tracing::info!("Processor ready (max {} workers)", max_workers);

        // Spawn coordinator thread to distribute work
        let coordinator_work_rx = work_rx.clone();
        let coordinator_worker_channels = worker_channels.clone();

        let coordinator_thread = thread::Builder::new()
            .name("enrichment-coordinator".to_string())
            .spawn(move || {
                Self::coordinate_work(coordinator_work_rx, coordinator_worker_channels)
            })
            .context("Failed to spawn coordinator thread")?;

        Ok(Self {
            workers,
            worker_channels,
            work_tx: Some(work_tx),
            result_rx,
            result_tx,
            coordinator_thread: Some(coordinator_thread),
            compile_commands_path,
            source_root,
            max_workers,
            worker_binary_path,
            files_with_compile_commands,
            enriched_functions,
            enriched_types,
            enriched_macros,
            macros_kept_by_clangd,
        })
    }

    /// Spawn a new worker process
    pub fn spawn_worker(&self) -> Result<()> {
        // Get current worker count to determine worker ID
        let current_worker_id = self.workers.lock().unwrap().len();

        // Check if we've reached max workers
        if current_worker_id >= self.max_workers {
            anyhow::bail!("Maximum number of workers ({}) already spawned", self.max_workers);
        }

        tracing::debug!("Spawning worker {}", current_worker_id);

        // Create IPC channels for this worker
        let (work_server, work_server_name) = IpcOneShotServer::new()
            .context("Failed to create IPC server for work channel")?;
        let (response_server, response_server_name) = IpcOneShotServer::new()
            .context("Failed to create IPC server for response channel")?;

        // Spawn worker process using configured binary path
        let child = Command::new(&self.worker_binary_path)
            .arg("--clangd-worker")
            .arg("--worker-id")
            .arg(current_worker_id.to_string())
            .arg("--ipc-work-server")
            .arg(&work_server_name)
            .arg("--ipc-response-server")
            .arg(&response_server_name)
            .arg("--compile-commands")
            .arg(&self.compile_commands_path)
            .arg("--source")
            .arg(&self.source_root)
            .spawn()
            .with_context(|| format!("Failed to spawn worker {}", current_worker_id))?;

        let pid = child.id();
        tracing::info!("Worker {} spawned with PID {}", current_worker_id, pid);

        // Accept connections from worker
        let (_, work_tx): (_, IpcSender<WorkRequest>) = work_server
            .accept()
            .with_context(|| format!("Failed to accept work channel from worker {}", current_worker_id))?;

        let (_, response_rx): (_, IpcReceiver<WorkResponse>) = response_server
            .accept()
            .with_context(|| format!("Failed to accept response channel from worker {}", current_worker_id))?;

        // Add worker to list
        self.workers.lock().unwrap().push(WorkerHandle {
            id: current_worker_id,
            process: child,
        });

        // Add worker channel to coordinator's list
        self.worker_channels.lock().unwrap().push(work_tx);

        // Spawn thread to collect results from this worker
        let result_tx_clone = self.result_tx.clone();
        let stats_files = self.files_with_compile_commands.clone();
        let stats_funcs = self.enriched_functions.clone();
        let stats_types = self.enriched_types.clone();
        let stats_macros = self.enriched_macros.clone();
        let stats_kept = self.macros_kept_by_clangd.clone();

        thread::Builder::new()
            .name(format!("worker-{}-collector", current_worker_id))
            .spawn(move || {
                Self::collect_worker_responses(
                    current_worker_id,
                    response_rx,
                    result_tx_clone,
                    stats_files,
                    stats_funcs,
                    stats_types,
                    stats_macros,
                    stats_kept,
                );
                tracing::debug!("Worker {} collector thread exiting", current_worker_id);
            })
            .with_context(|| format!("Failed to spawn collector thread for worker {}", current_worker_id))?;

        tracing::info!("Worker {} fully initialized and ready", current_worker_id);
        Ok(())
    }

    /// Submit work for enrichment
    pub fn submit_work(&self, request: EnrichmentRequest) -> Result<()> {
        self.work_tx
            .as_ref()
            .context("Work channel closed - call finish_submitting() only after all work is submitted")?
            .send(request)
            .context("Failed to send work request")?;
        Ok(())
    }

    /// Signal that all work has been submitted
    /// This closes the work channel and allows workers to exit when done
    pub fn finish_submitting(&mut self) {
        tracing::info!("Closing work channel - all files submitted");
        self.work_tx = None;
    }

    /// Receive enriched result (blocking)
    pub fn recv_result(&self) -> Result<EnrichmentResponse> {
        self.result_rx
            .recv()
            .context("Failed to receive enrichment result")
    }

    /// Try to receive enriched result (non-blocking)
    pub fn try_recv_result(&self) -> Option<EnrichmentResponse> {
        self.result_rx.try_recv().ok()
    }

    /// Coordinator thread: distributes work to workers using round-robin assignment
    fn coordinate_work(
        work_rx: Receiver<EnrichmentRequest>,
        worker_channels: Arc<std::sync::Mutex<Vec<IpcSender<WorkRequest>>>>,
    ) {
        tracing::info!("Coordinator thread started, waiting for work...");

        let mut work_distributed = 0;
        let mut work_received = 0;

        while let Ok(request) = work_rx.recv() {
            work_received += 1;
            if work_received <= 5 || work_received % 100 == 0 {
                tracing::info!("Coordinator received work item {} for {:?}", work_received, request.path);
            }
            // Send full symbols to worker for enrichment
            let work_request = WorkRequest {
                file_path: request.path.clone(),
                functions: request.functions,
                types: request.types,
                macros: request.macros,
                git_file_sha: request.git_file_sha,
            };

            // Get current worker channels
            let channels = worker_channels.lock().unwrap();
            let num_workers = channels.len();

            if work_distributed == 0 {
                tracing::info!("Coordinator received first work item, {} workers available", num_workers);
            }

            if num_workers == 0 {
                tracing::warn!("No workers available - dropping request for {:?}", request.path);
                continue;
            }

            // Round-robin assignment - remap to actually-spawned workers (may be fewer than max_workers)
            let worker_id = request.worker_id % num_workers;

            if work_distributed < 5 {
                tracing::info!("Coordinator sending work item {} to worker {}", work_distributed, worker_id);
            }

            if let Err(e) = channels[worker_id].send(work_request) {
                tracing::error!("Failed to send work to worker {}: {}", worker_id, e);
            } else {
                work_distributed += 1;
                if work_distributed < 5 {
                    tracing::info!("Coordinator successfully sent work item {} to worker {}", work_distributed, worker_id);
                }
                if work_distributed % 1000 == 0 {
                    tracing::info!("Coordinator distributed {} work items to {} workers",
                        work_distributed, num_workers);
                }
            }
            drop(channels); // Release lock before next iteration
        }

        tracing::info!("Coordinator received {} work items, distributed {} to workers", work_received, work_distributed);

        // Close all worker channels to signal them to exit
        tracing::info!("Closing all worker channels to signal workers to exit");
        let mut channels = worker_channels.lock().unwrap();
        channels.clear(); // Drop all IPC senders - this closes the channels
        drop(channels);
    }

    /// Collector thread: receives results from a worker
    fn collect_worker_responses(
        worker_id: usize,
        response_rx: IpcReceiver<WorkResponse>,
        result_tx: Sender<EnrichmentResponse>,
        files_with_compile_commands: Arc<AtomicUsize>,
        enriched_functions: Arc<AtomicUsize>,
        enriched_types: Arc<AtomicUsize>,
        enriched_macros: Arc<AtomicUsize>,
        macros_kept_by_clangd: Arc<AtomicUsize>,
    ) {
        tracing::info!("Collector thread started for worker {}, waiting for results...", worker_id);

        let mut responses_collected = 0;

        while let Ok(worker_response) = response_rx.recv() {
            responses_collected += 1;

            if responses_collected == 1 || responses_collected % 100 == 0 {
                tracing::info!("Worker {} collector received {} responses", worker_id, responses_collected);
            }

            // Track statistics
            if worker_response.had_compile_commands {
                files_with_compile_commands.fetch_add(1, Ordering::Relaxed);
            }

            // Count enriched symbols (those with USR set)
            let func_count = worker_response.functions.iter()
                .filter(|f| f.usr.is_some())
                .count();
            let type_count = worker_response.types.iter()
                .filter(|t| t.usr.is_some())
                .count();
            let macro_count = worker_response.macros.iter()
                .filter(|m| m.usr.is_some())
                .count();

            // Count non-function-like macros that were kept due to USR
            let kept_count = worker_response.macros.iter()
                .filter(|m| !m.is_function_like && m.usr.is_some())
                .count();

            enriched_functions.fetch_add(func_count, Ordering::Relaxed);
            enriched_types.fetch_add(type_count, Ordering::Relaxed);
            enriched_macros.fetch_add(macro_count, Ordering::Relaxed);
            macros_kept_by_clangd.fetch_add(kept_count, Ordering::Relaxed);

            tracing::debug!(
                "Worker {} returned {} function, {} type, {} macro enrichments",
                worker_id,
                func_count,
                type_count,
                macro_count
            );

            // Forward enriched symbols to result channel
            let enrichment_response = EnrichmentResponse {
                path: worker_response.file_path,
                functions: worker_response.functions,
                types: worker_response.types,
                macros: worker_response.macros,
                git_file_sha: worker_response.git_file_sha,
            };

            if let Err(e) = result_tx.send(enrichment_response) {
                tracing::error!("Worker {} collector failed to send result: {}", worker_id, e);
                break;
            }
        }

        tracing::info!(
            "Worker {} collector finished after processing {} responses",
            worker_id,
            responses_collected
        );
    }
}

impl Drop for ClangdProcessor {
    fn drop(&mut self) {
        let num_workers = self.workers.lock().unwrap().len();
        tracing::info!("Shutting down ClangdProcessor and {} workers", num_workers);

        // Close work channel to signal coordinator thread to exit
        self.work_tx = None;

        // Wait for coordinator thread to exit
        if let Some(coordinator) = self.coordinator_thread.take() {
            tracing::debug!("Waiting for coordinator thread to exit");
            if let Err(e) = coordinator.join() {
                tracing::error!("Coordinator thread panicked: {:?}", e);
            } else {
                tracing::info!("Coordinator thread exited");
            }
        }

        // Close all worker channels (coordinator already did this, but just in case)
        {
            let mut channels = self.worker_channels.lock().unwrap();
            channels.clear(); // Drop all IPC senders
        }

        // Wait for all workers to exit
        let mut workers = self.workers.lock().unwrap();
        for worker in workers.iter_mut() {
            tracing::debug!("Waiting for worker {} to exit", worker.id);
            match worker.process.wait() {
                Ok(status) => {
                    tracing::info!("Worker {} exited with status: {}", worker.id, status);
                }
                Err(e) => {
                    tracing::error!("Failed to wait for worker {}: {}", worker.id, e);
                }
            }
        }

        tracing::info!("All workers shut down");
    }
}
