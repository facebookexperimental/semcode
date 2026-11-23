# Benchmarks

Benchmarks of semcode on a pinned Linux kernel tree (`v7.3.6` from
linux-stable), so a change in the numbers is a change in semcode, not in
the input.

- `bench/bench.py`: semcode run the way users run it, timed end to end.
- `benches/analyzer.rs` (Criterion): the analyzer on real kernel files.

## Setup

```bash
cargo install hyperfine --locked   # hyperfine >= 2.0
bench/bench.py setup               # ~350 MB clone into ~/.cache/semcode-bench/linux
```

`bench/bench.py` is a [uv](https://docs.astral.sh/uv/) script with no
dependencies. Everything it writes goes under `~/.cache/semcode-bench`;
set `SEMCODE_BENCH_ROOT` to move it. Builds honour `CARGO_BUILD_JOBS`.

## `bench/bench.py run`

```bash
bench/bench.py run                 # read scenarios
bench/bench.py run -s index        # index scenarios
bench/bench.py run -s mcp -r 1     # one scenario, one session
```

It builds the checkout it's in and benchmarks it. To compare two
versions, run it in each and compare the two `summary.md` files; each
records the commit it measured. Run both on the same machine, close
together and with the machine otherwise idle: differences of a few
percent between runs can be noise.

An index is built once and read many times, so the default is the read
scenarios:

| Scenario | What it measures |
|:--|:--|
| `mcp` | `bench/workload.jsonl` replayed through `semcode-mcp`: time to ready, a first and a warm pass, and a pass with 4 requests in flight |
| `mcp-dirty` | the same on a working copy with 20 edited files (the working-copy overlay) |
| `mcp-behind` | the server started on a `v7.3.5` index with the tree at `v7.3.6`, catching up before it answers |
| `mcp-aged` | the same workload on an index holding every commit of `v7.3.5..v7.3.6`: reads on an index with accumulated history |
| `cli` | each line of `bench/queries.txt` as a one-shot `semcode -q` |

`-s index` runs the index scenarios:

| Scenario | What it measures |
|:--|:--|
| `subset` | indexing `fs/` from empty |
| `full` | indexing the whole tree from empty |
| `update` | plain `semcode-index` on a `v7.3.5` index with the tree at `v7.3.6` |

Every answer is checked, because a lookup that finds nothing answers
fast and would otherwise look like a speedup. Each workload call and CLI
query names something only a real result prints. Each index scenario
starts with an untimed run that warms the page cache, records the
per-phase breakdown (`--perf-json`), and fails if the index has no
functions. Row counts cover functions and types only.

Results go to `~/.cache/semcode-bench/results/<timestamp>/`:
`summary.md` and `summary.json` (every call's latency included), plus
logs.

## The workload

`bench/workload.jsonl` holds 94 calls to `find_function`, `find_callers`,
`find_calls`, `find_type` and `grep_functions`, weighted towards the
kernel's most used names (`kfree`, `mutex_lock`, `dev_err`, `sk_buff`)
since those are what queries go to and what costs the most.
`bench/workload.rs` generates it from a full index; it's committed, and
regenerated when the tag moves:

```bash
cargo run --release --example bench_workload -- ~/.cache/semcode-bench/db/full.db bench/workload.jsonl
```

## Criterion

```bash
cargo bench --bench analyzer   # parse_only, analyze_file, corpus
```

It reads the kernel tree, and refuses one that isn't at the tag or has
local changes.

## Moving to a new kernel

Change `TAG`, `BASE` and `FLOOR` in `bench/bench.py` and `TAG` in
`benches/analyzer.rs`, then regenerate the workload.
