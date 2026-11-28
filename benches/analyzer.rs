// SPDX-License-Identifier: MIT OR Apache-2.0
//! Microbenchmarks for the Tree-sitter analyzer on real kernel sources.
//!
//! - `parse_only/*`: Tree-sitter parsing alone, the floor under analysis.
//!   A regression in `analyze_file` that `parse_only` does not share is in
//!   semcode's extraction, not in the grammar.
//! - `analyze_file/*`: full analysis of large, call-heavy files.
//! - `corpus`: full analysis of a fixed sample spread over the whole tree,
//!   so typical files, and per-file overhead, are represented too: the
//!   named files are 10x the average kernel file.
//!
//! The sources come from the pinned kernel tree `bench/bench.py setup`
//! fetches, not from this repository: the kernel is GPL-2.0, this
//! repository MIT/Apache-2.0.
//!
//! Run:      cargo bench --bench analyzer
//! Compare:  cargo bench --bench analyzer -- --save-baseline main
//!           (switch branch)
//!           cargo bench --bench analyzer -- --baseline main

use criterion::{criterion_group, BenchmarkId, Criterion, SamplingMode, Throughput};
use gix::bstr::ByteSlice;
use semcode::{Language, TreeSitterAnalyzer};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Large, call-heavy files across subsystems, plus a big header and a
/// large Rust driver file (the larger Rust files are vendored crates), so
/// a regression in either language path or in header handling shows.  Paths are relative to the kernel root, as
/// the indexer sees them.
const FILES: &[&str] = &[
    "kernel/sched/core.c",
    "mm/page_alloc.c",
    "fs/namei.c",
    "net/core/dev.c",
    "drivers/net/ethernet/intel/e1000e/netdev.c",
    "include/linux/fs.h",
    "drivers/android/binder/process.rs",
];

/// About this many files in the corpus sample.
const CORPUS_SIZE: usize = 200;
/// The extensions the corpus samples: pinned, not the indexer's defaults,
/// which would change the sample under the same benchmark ID.
const CORPUS_EXTENSIONS: &[&str] = &["c", "h", "rs", "zig"];

const NO_HASH: &str = "0000000000000000000000000000000000000000";

struct Source {
    rel: String,
    text: String,
}

/// The kernel sources at HEAD, path -> blob, read from git rather than the
/// working tree: an edited, untracked or generated file in the checkout
/// cannot change what is measured.  [`kernel_tree`] has already
/// checked that HEAD is the pinned tag.
struct Tree {
    repo: gix::Repository,
    blobs: BTreeMap<String, gix::ObjectId>,
}

impl Tree {
    fn open(root: &Path) -> Tree {
        let repo = gix::open(root).unwrap_or_else(|e| panic!("{}: {e}", root.display()));
        let blobs = {
            let tree = repo.head_commit().unwrap().tree().unwrap();
            let mut recorder = gix::traverse::tree::Recorder::default();
            tree.traverse().breadthfirst(&mut recorder).unwrap();
            recorder
                .records
                .into_iter()
                .filter(|e| e.mode.is_blob())
                .map(|e| (e.filepath.to_str_lossy().into_owned(), e.oid))
                .collect()
        };
        Tree { repo, blobs }
    }

    fn read(&self, rel: &str) -> Source {
        let id = self
            .blobs
            .get(rel)
            .unwrap_or_else(|| panic!("{rel}: not in the tree at HEAD"));
        let blob = self
            .repo
            .find_object(*id)
            .unwrap_or_else(|e| panic!("{rel}: {e}"));
        Source {
            rel: rel.to_string(),
            text: String::from_utf8_lossy(&blob.data).into_owned(),
        }
    }
}

/// About `CORPUS_SIZE` indexable files, evenly strided through the tree
/// in path order: the same files on every run of the same tree, from
/// every subsystem.
fn corpus(tree: &Tree) -> Vec<Source> {
    // BTreeMap keys: already in path order.
    let paths: Vec<&String> = tree
        .blobs
        .keys()
        .filter(|p| {
            Path::new(p.as_str())
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| CORPUS_EXTENSIONS.contains(&x))
        })
        .collect();
    let stride = (paths.len() / CORPUS_SIZE).max(1);
    paths.iter().step_by(stride).map(|p| tree.read(p)).collect()
}

// The kernel tree bench/bench.py fetches, and refusing to measure anything
// but the pinned tag.

/// The kernel tag the benchmarks are measured on, as TAG in bench/bench.py.
pub const TAG: &str = "v7.3.6";

/// `$SEMCODE_BENCH_ROOT`, default `~/.cache/semcode-bench`, as in bench.py.
pub fn bench_root() -> PathBuf {
    match std::env::var_os("SEMCODE_BENCH_ROOT").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".cache/semcode-bench")
        }
    }
}

/// The kernel tree, at [`TAG`] with no local changes.
///
/// `None` when there is no tree, so `cargo bench` without one skips rather
/// than fails.  Any other tree is fatal: its numbers would not be
/// comparable, and git-aware lookups read local edits through the
/// working-copy overlay.
pub fn kernel_tree() -> Option<PathBuf> {
    let root = bench_root().join("linux");
    if !root.join(".git").exists() {
        eprintln!(
            "No kernel tree at {}; run `bench/bench.py setup`. Skipping.",
            root.display()
        );
        return None;
    }
    if let Err(e) = check(&root) {
        eprintln!("error: {}: {e}", root.display());
        std::process::exit(1);
    }
    Some(root)
}

fn check(root: &Path) -> Result<(), String> {
    let repo = gix::open(root).map_err(|e| e.to_string())?;
    let head = repo.head_id().map_err(|e| e.to_string())?.detach();
    let want = repo
        .rev_parse_single(format!("{TAG}^{{commit}}").as_str())
        .map_err(|e| format!("no tag {TAG}: {e}"))?
        .detach();
    if head != want {
        return Err(format!("at {head}, not {TAG}"));
    }
    if repo.is_dirty().map_err(|e| e.to_string())? {
        return Err("has local changes".to_string());
    }
    Ok(())
}

fn grammar(rel: &str) -> tree_sitter::Language {
    match Language::from_path(Path::new(rel)).expect("unsupported file") {
        Language::C => tree_sitter_c::LANGUAGE.into(),
        Language::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Zig => tree_sitter_zig::LANGUAGE.into(),
    }
}

/// What analysis found in a file: functions + types + macros.  Checked
/// before timing, so a change that makes the analyzer find nothing fails
/// here instead of showing as a speedup.
fn entities(analyzer: &mut TreeSitterAnalyzer, root: &Path, src: &Source) -> usize {
    let a = analyzer
        .analyze_source_with_metadata(&src.text, Path::new(&src.rel), NO_HASH, Some(root))
        .unwrap_or_else(|e| panic!("{}: {e}", src.rel));
    a.functions.len() + a.types.len() + a.macros.len()
}

fn bench_parse_only(c: &mut Criterion, files: &[Source]) {
    let mut group = c.benchmark_group("parse_only");
    let mut parser = tree_sitter::Parser::new();
    for src in files {
        parser.set_language(&grammar(&src.rel)).unwrap();
        group.throughput(Throughput::Bytes(src.text.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(&src.rel),
            &src.text,
            |b, text| b.iter(|| black_box(parser.parse(black_box(text), None).unwrap())),
        );
    }
    group.finish();
}

fn bench_analyze_file(c: &mut Criterion, root: &Path, files: &[Source]) {
    let mut analyzer = TreeSitterAnalyzer::new().unwrap();
    for src in files {
        let found = entities(&mut analyzer, root, src);
        assert!(found > 0, "{}: analyzer found nothing", src.rel);
        eprintln!("{}: {found} entities", src.rel);
    }

    let mut group = c.benchmark_group("analyze_file");
    for src in files {
        let path = Path::new(&src.rel);
        group.throughput(Throughput::Bytes(src.text.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(&src.rel),
            &src.text,
            |b, text| {
                b.iter(|| {
                    black_box(
                        analyzer
                            .analyze_source_with_metadata(
                                black_box(text),
                                path,
                                NO_HASH,
                                Some(root),
                            )
                            .unwrap(),
                    )
                })
            },
        );
    }
    group.finish();
}

fn bench_corpus(c: &mut Criterion, root: &Path, files: &[Source]) {
    let mut analyzer = TreeSitterAnalyzer::new().unwrap();
    let found: usize = files.iter().map(|s| entities(&mut analyzer, root, s)).sum();
    let bytes: usize = files.iter().map(|s| s.text.len()).sum();
    assert!(found > 0, "corpus: analyzer found nothing");
    eprintln!(
        "corpus: {} files, {:.1} MiB, {found} entities",
        files.len(),
        bytes as f64 / (1 << 20) as f64
    );

    let mut group = c.benchmark_group("corpus");
    // One iteration analyzes every file, about a second.  Flat sampling
    // runs the same iteration count per sample instead of a growing one,
    // so 10 samples take ~15 s, not ~55 s.
    group
        .sample_size(10)
        .sampling_mode(SamplingMode::Flat)
        .measurement_time(Duration::from_secs(15));
    group.throughput(Throughput::Bytes(bytes as u64));
    group.bench_function("analyze", |b| {
        b.iter(|| {
            for src in files {
                black_box(
                    analyzer
                        .analyze_source_with_metadata(
                            &src.text,
                            Path::new(&src.rel),
                            NO_HASH,
                            Some(root),
                        )
                        .unwrap(),
                );
            }
        })
    });
    group.finish();
}

fn benches(c: &mut Criterion) {
    let Some(root) = kernel_tree() else {
        return;
    };
    let tree = Tree::open(&root);
    let files: Vec<Source> = FILES.iter().map(|rel| tree.read(rel)).collect();
    bench_parse_only(c, &files);
    bench_analyze_file(c, &root, &files);
    bench_corpus(c, &root, &corpus(&tree));
}

criterion_group! {
    name = analyzer;
    // Whole-file analysis takes tens of milliseconds; fewer, longer samples
    // keep a run to a few minutes without losing much precision.
    config = Criterion::default().sample_size(30);
    targets = benches
}
criterion::criterion_main!(analyzer);
