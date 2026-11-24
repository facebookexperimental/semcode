// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Generate bench/workload.jsonl: the tool calls the MCP read benchmarks in
// bench/bench.py replay.
//
//   cargo run --release --features bench --example bench_workload -- <index> <output>
//
// <index> is a full index of the pinned kernel tree.  The workload is
// committed, like the tag: the same calls on every run, and only rerun
// this when the tag moves.
//
// Real queries go to the kernel's core API far more often than to its
// leaf functions, and those are the expensive ones, so names are sampled
// in proportion to how heavily they are used, not uniformly: functions by
// fan-in or fan-out, types by how many functions use them.  A small light
// share stays in to keep per-call overhead visible.  Sampling is weighted reservoir sampling keyed on a
// hash of the name, so the same index gives the same workload.

use anyhow::{Context, Result};
use arrow_array::{Array, Int64Array, RecordBatch, StringArray};
use futures::TryStreamExt;
use lancedb::query::{ExecutableQuery, QueryBase, Select};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

const SEED: &str = "semcode-bench-workload-v1";

/// Paths that are not the kernel proper: their definitions still count
/// towards ambiguity, but a name defined only here is not sampled.
fn outside_kernel(path: &str) -> bool {
    ["tools/", "samples/", "scripts/", "Documentation/"]
        .iter()
        .any(|p| path.starts_with(p))
}

fn unit_hash(key: &str) -> f64 {
    let h = blake3::hash(format!("{SEED}:{key}").as_bytes());
    let v = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap());
    (v as f64 + 1.0) / (u64::MAX as f64 + 2.0)
}

/// `k` names drawn without replacement with probability proportional to
/// weight (Efraimidis-Spirakis).  The hash is salted with the stratum: an
/// unsalted name with a high hash would win every draw it is eligible for.
fn weighted<'a>(
    stratum: &str,
    items: impl IntoIterator<Item = (&'a str, f64)>,
    k: usize,
) -> Vec<String> {
    let mut keyed: Vec<(f64, &str)> = items
        .into_iter()
        .filter(|(_, w)| *w > 0.0)
        .map(|(name, w)| (unit_hash(&format!("{stratum}:{name}")).ln() / w, name))
        .collect();
    keyed.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(b.1)));
    keyed
        .into_iter()
        .take(k)
        .map(|(_, n)| n.to_string())
        .collect()
}

fn uniform<'a>(stratum: &str, items: impl IntoIterator<Item = &'a str>, k: usize) -> Vec<String> {
    weighted(stratum, items.into_iter().map(|n| (n, 1.0)), k)
}

fn heaviest<'a>(items: impl IntoIterator<Item = (&'a str, f64)>, k: usize) -> Vec<String> {
    let mut v: Vec<(f64, &str)> = items.into_iter().map(|(n, w)| (w, n)).collect();
    v.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(b.1)));
    v.into_iter().take(k).map(|(_, n)| n.to_string()).collect()
}

fn col<'a>(batch: &'a RecordBatch, name: &str) -> &'a StringArray {
    batch
        .column_by_name(name)
        .and_then(|c| c.as_any().downcast_ref::<StringArray>())
        .unwrap_or_else(|| panic!("column {name} missing or not Utf8"))
}

/// Callee spellings in a `calls` JSON array: plain strings, or objects
/// carrying the spelling in `call`.
fn callees(calls: &str) -> Vec<String> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(calls) else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|v| match v {
            Value::String(s) => Some(s),
            Value::Object(o) => o.get("call").and_then(|c| c.as_str()).map(str::to_string),
            _ => None,
        })
        .collect()
}

fn string_list(json_text: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json_text).unwrap_or_default()
}

#[derive(Default)]
struct Function {
    def_paths: BTreeSet<String>,
    kernel_def: bool,
    lines: i64,
    callers: BTreeSet<String>,
    callees: BTreeSet<String>,
    caller_paths: BTreeSet<String>,
}

#[derive(Default)]
struct Index {
    functions: HashMap<String, Function>,
    /// type name -> (definition paths, functions using it)
    types: HashMap<String, (BTreeSet<String>, usize)>,
}

async fn scan(
    db: &lancedb::Connection,
    table: &str,
    columns: &[&str],
    mut each: impl FnMut(&RecordBatch),
) -> Result<()> {
    let table = db.open_table(table).execute().await?;
    let mut stream = table
        .query()
        .select(Select::columns(columns))
        .execute()
        .await?;
    while let Some(batch) = stream.try_next().await? {
        each(&batch);
    }
    Ok(())
}

async fn load(path: &str) -> Result<Index> {
    let db = lancedb::connect(path).execute().await?;
    // The scans below read every row, whatever commit it came from: the
    // statistics are only right for an index of one tree.  An index built
    // at one commit records exactly that commit.
    let commits = db.open_table("git_commits").execute().await?;
    let commits = commits.count_rows(None).await?;
    if commits != 1 {
        anyhow::bail!(
            "{path} holds {commits} commits; build the workload from an index of one tree, \
             such as bench.py's full.db"
        );
    }
    let mut ix = Index::default();
    let mut type_uses: HashMap<String, usize> = HashMap::new();

    scan(
        &db,
        "functions",
        &[
            "name",
            "file_path",
            "line_start",
            "line_end",
            "body_hash",
            "calls",
            "types",
        ],
        |b| {
            let (name, path) = (col(b, "name"), col(b, "file_path"));
            let (hash, calls, types) = (col(b, "body_hash"), col(b, "calls"), col(b, "types"));
            let start = b.column_by_name("line_start").unwrap();
            let start = start.as_any().downcast_ref::<Int64Array>().unwrap();
            let end = b.column_by_name("line_end").unwrap();
            let end = end.as_any().downcast_ref::<Int64Array>().unwrap();
            for i in 0..b.num_rows() {
                if hash.is_null(i) {
                    continue; // a declaration, not a definition
                }
                let (n, p) = (name.value(i), path.value(i));
                let f = ix.functions.entry(n.to_string()).or_default();
                f.def_paths.insert(p.to_string());
                if !outside_kernel(p) {
                    f.kernel_def = true;
                    f.lines = f.lines.max(end.value(i) - start.value(i) + 1);
                }
                if !calls.is_null(i) {
                    for callee in callees(calls.value(i)) {
                        f.callees.insert(callee);
                    }
                }
                if !types.is_null(i) {
                    for t in BTreeSet::from_iter(string_list(types.value(i))) {
                        *type_uses.entry(t).or_default() += 1;
                    }
                }
            }
        },
    )
    .await?;

    // Invert callees into callers once every caller is known.  A name defined
    // in several files has its callees merged, and each caller is credited
    // with its first kernel definition, not the one that made the call; the
    // grep:path majority vote over caller paths tolerates that.
    let edges: Vec<(String, String)> = ix
        .functions
        .iter()
        .filter(|(_, f)| f.kernel_def)
        .flat_map(|(caller, f)| f.callees.iter().map(move |c| (c.clone(), caller.clone())))
        .collect();
    for (callee, caller) in edges {
        let caller_path = ix.functions[&caller]
            .def_paths
            .iter()
            .find(|p| !outside_kernel(p))
            .cloned();
        if let Some(f) = ix.functions.get_mut(&callee) {
            f.callers.insert(caller);
            if let Some(p) = caller_path {
                f.caller_paths.insert(p);
            }
        }
    }

    scan(&db, "types", &["name", "file_path"], |b| {
        let (name, path) = (col(b, "name"), col(b, "file_path"));
        for i in 0..b.num_rows() {
            let entry = ix.types.entry(name.value(i).to_string()).or_default();
            entry.0.insert(path.value(i).to_string());
        }
    })
    .await?;
    for (t, uses) in type_uses {
        if let Some(entry) = ix.types.get_mut(&t) {
            entry.1 = uses;
        }
    }

    Ok(ix)
}

struct Call {
    tool: &'static str,
    kind: &'static str,
    args: Value,
    /// What the answer must contain: see found() in bench/bench.py.
    expect: Vec<Value>,
}

/// The definition the tools list first-hand: in the kernel proper, and not
/// in a tree semcode treats as another program (arch/um's userspace side).
/// A `.c` file where there is one: a header may hold a variant.
fn kernel_path(paths: &BTreeSet<String>) -> String {
    let listed = |p: &&String| !outside_kernel(p) && !semcode::path_is_other_program(p);
    paths
        .iter()
        .filter(listed)
        .find(|p| p.ends_with(".c"))
        .or_else(|| paths.iter().find(listed))
        .or_else(|| paths.iter().next())
        .cloned()
        .unwrap_or_default()
}

/// What a find_function answer must contain.  One definition: its file.
/// Several rows: semcode decides from their bodies and guards which define
/// the function, and may settle on one, so accept either form of answer.
fn function_expect(name: &str, f: &Function) -> Value {
    if f.def_paths.len() == 1 {
        json!(kernel_path(&f.def_paths))
    } else {
        json!([
            format!("definitions with name '{name}'"),
            format!("Function: {name} (")
        ])
    }
}

/// Fan-in tiers: "heavy" made explicit.  Most kernel functions have a
/// handful of callers; queries go to the few with thousands.
const TIERS: &[(&str, usize, usize)] = &[
    ("top", 1000, usize::MAX),
    ("high", 100, 999),
    ("mid", 20, 99),
    ("light", 1, 5),
];

fn build(ix: &Index) -> Vec<Call> {
    let mut calls = Vec::new();
    let kernel: Vec<(&str, &Function)> = ix
        .functions
        .iter()
        .filter(|(_, f)| f.kernel_def)
        .map(|(n, f)| (n.as_str(), f))
        .collect();
    let in_tier = |tier: &str, f: &Function| {
        let &(_, lo, hi) = TIERS.iter().find(|t| t.0 == tier).unwrap();
        (lo..=hi).contains(&f.callers.len())
    };
    // Within a tier, still favour the more heavily used.
    let tier = |stratum: &str, tier: &str, k: usize| -> Vec<String> {
        let pool = kernel
            .iter()
            .filter(|(_, f)| in_tier(tier, f))
            .map(|(n, f)| (*n, f.callers.len() as f64));
        weighted(&format!("{stratum}:{tier}"), pool, k)
    };
    // A name drawn by two strata (a top-tier function that also has many
    // definitions, say) is called once, not weighted twice.
    let mut seen: BTreeSet<(&'static str, String)> = BTreeSet::new();
    let mut push = |tool: &'static str, kind: &'static str, args: Value, expect: Value| {
        if !seen.insert((tool, args.to_string())) {
            return;
        }
        calls.push(Call {
            tool,
            kind,
            args,
            expect: vec![expect],
        })
    };

    // find_function (30): by fan-in tier; names with many definitions;
    // the longest bodies.
    for (t, k, kind) in [
        ("top", 6, "fanin_top"),
        ("high", 8, "fanin_high"),
        ("mid", 6, "fanin_mid"),
    ] {
        for name in tier("find_function", t, k) {
            let expect = function_expect(&name, &ix.functions[&name]);
            push(
                "find_function",
                kind,
                json!({ "name": name }),
                json!(expect),
            );
        }
    }
    let many = kernel
        .iter()
        .filter(|(_, f)| f.def_paths.len() >= 5 && f.callers.len() >= 20)
        .map(|(n, f)| (*n, f.callers.len() as f64));
    for name in weighted("find_function:many", many, 5) {
        let expect = function_expect(&name, &ix.functions[&name]);
        push(
            "find_function",
            "many_definitions",
            json!({ "name": name }),
            json!(expect),
        );
    }
    for name in heaviest(kernel.iter().map(|(n, f)| (*n, f.lines as f64)), 5) {
        let expect = function_expect(&name, &ix.functions[&name]);
        push(
            "find_function",
            "long_body",
            json!({ "name": name }),
            json!(expect),
        );
    }

    // find_callers (24): by fan-in tier, plus a light share so per-call
    // overhead stays visible.
    for (t, k, kind) in [
        ("top", 6, "fanin_top"),
        ("high", 8, "fanin_high"),
        ("mid", 6, "fanin_mid"),
        ("light", 4, "fanin_light"),
    ] {
        for name in tier("find_callers", t, k) {
            let f = &ix.functions[&name];
            // A short caller list is printed in full: expect a caller.  A
            // long one is summarized by count, and the answer that found
            // nothing names the function too, so expect a count instead:
            // a quarter of the fan-in leaves room for semcode answering
            // about one of several definitions.
            let expect = if f.callers.len() <= 20 {
                json!(f.callers.iter().next().cloned().unwrap())
            } else {
                json!({
                    "count": r"(\d+) functions (?:directly )?call",
                    "min": (f.callers.len() / 4).max(1),
                })
            };
            push("find_callers", kind, json!({ "name": name }), expect);
        }
    }

    // find_calls (18): by fan-out tier.
    for (kind, lo, hi, k) in [
        ("fanout_top", 100, usize::MAX, 6),
        ("fanout_high", 40, 99, 6),
        ("fanout_mid", 15, 39, 6),
    ] {
        let pool = kernel
            .iter()
            .filter(|(_, f)| f.def_paths.len() == 1 && (lo..=hi).contains(&f.callees.len()))
            .map(|(n, f)| (*n, f.callees.len() as f64));
        for name in weighted(&format!("find_calls:{kind}"), pool, k) {
            let first = ix.functions[&name].callees.iter().next().cloned().unwrap();
            push("find_calls", kind, json!({ "name": name }), json!(first));
        }
    }

    // find_type (12): the most used types, then by use.
    let types: Vec<(&str, f64)> = ix
        .types
        .iter()
        .filter(|(_, (paths, uses))| *uses >= 100 && paths.iter().any(|p| !outside_kernel(p)))
        .map(|(n, (_, uses))| (n.as_str(), *uses as f64))
        .collect();
    let mut names = heaviest(types.iter().copied(), 3);
    names.extend(weighted("find_type", types.iter().copied(), 20));
    for name in dedup(names).into_iter().take(12) {
        let path = kernel_path(&ix.types[&name].0);
        push("find_type", "by_use", json!({ "name": name }), json!(path));
    }

    // grep_functions (12): a heavily used name with the default early
    // exit; a rare one scanning everything; a heavy one under a path.
    for name in tier("grep:common", "top", 4) {
        let args = json!({ "pattern": name, "limit": 50 });
        push(
            "grep_functions",
            "common_limited",
            args,
            json!("limit hit".to_string()),
        );
    }
    let rare = kernel
        .iter()
        .filter(|(n, f)| n.len() >= 12 && (2..=8).contains(&f.caller_paths.len()))
        .map(|(n, _)| *n);
    for name in uniform("grep:rare", rare, 4) {
        // The definition always matches its own name; a caller may reach
        // the function only through a macro, and not spell it out.
        let path = kernel_path(&ix.functions[&name].def_paths);
        let args = json!({ "pattern": name, "limit": 0 });
        push("grep_functions", "rare_full_scan", args, json!(path));
    }
    for name in tier("grep:path", "high", 4) {
        // The subsystem holding the most callers.
        let mut dirs: BTreeMap<&str, usize> = BTreeMap::new();
        for p in &ix.functions[&name].caller_paths {
            *dirs.entry(p.split('/').next().unwrap()).or_default() += 1;
        }
        let dir = dirs.iter().max_by_key(|(_, n)| **n).unwrap().0;
        let args = json!({ "pattern": name, "path_pattern": format!("^{dir}/"), "limit": 0 });
        push(
            "grep_functions",
            "path_filtered",
            args,
            // A result row starts with its path; the header that echoes the
            // filter, and is all a search that found nothing prints, does not.
            json!(format!("\n{dir}/")),
        );
    }

    calls
}

fn dedup(names: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    names
        .into_iter()
        .filter(|n| seen.insert(n.clone()))
        .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(db), Some(out)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: bench_workload <index> <output>");
    };
    // The same path semantics as `-d`.
    let db = semcode::process_database_path(Some(&db), None);
    let ix = load(&db).await.with_context(|| format!("reading {db}"))?;
    let mut calls = build(&ix);
    // A session's calls arrive mixed, not grouped by tool.
    calls.sort_by(|a, b| {
        let key = |c: &Call| unit_hash(&format!("{}:{}", c.tool, c.args));
        key(a).total_cmp(&key(b))
    });

    let mut file = std::fs::File::create(&out)?;
    writeln!(
        file,
        "{}",
        json!({ "meta": {
            "generator": "cargo run --release --features bench --example bench_workload",
            "seed": SEED,
            "calls": calls.len(),
        }})
    )?;
    for (i, c) in calls.iter().enumerate() {
        writeln!(
            file,
            "{}",
            json!({ "id": i + 1, "tool": c.tool, "kind": c.kind, "args": c.args, "expect": c.expect })
        )?;
    }
    eprintln!("{} calls written to {out}", calls.len());
    Ok(())
}
