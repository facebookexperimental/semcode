#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Benchmarks: semcode on a pinned kernel tree.

  bench/bench.py setup
  bench/bench.py run [-s SCENARIOS] [-r RUNS]

`run` builds the semcode checkout it is in and benchmarks it.  To compare
two versions, run it in each and compare the results; each records the
commit it measured.

SCENARIOS is a comma-separated list of scenarios or groups:

read (default):
  mcp         replay bench/workload.jsonl through semcode-mcp on an index at
              TAG: time to ready, a first and a warm pass, and a pass with
              several requests in flight
  mcp-dirty   the same on a working copy with edited files
  mcp-behind  the server started on a BASE index with the tree at TAG: it
              catches up before answering
  mcp-aged    the same workload on an index holding every commit of BASE..TAG
  cli         one-shot `semcode -q` queries from bench/queries.txt
index:
  subset      index one subtree (SUBSET) from empty
  full        index the whole tree at TAG from empty
  update      bring a BASE index to TAG: plain `semcode-index` after a pull
all:          both groups

See bench/README.md.  Run with uv; standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
REPO = BENCH_DIR.parent

# The pinned input.  TAG is indexed; BASE..TAG is the update range; FLOOR
# bounds how much history is fetched.  TAG must match benches/analyzer.rs.
TAG = "v7.3.6"
BASE = "v7.3.5"
FLOOR = "v7.3"
KERNEL_URL = "https://kernel.googlesource.com/pub/scm/linux/kernel/git/stable/linux"
SUBSET = "fs"

# Absolute: these are handed to subprocesses that run in other directories.
ROOT = Path(os.path.abspath(os.environ.get("SEMCODE_BENCH_ROOT")
                            or Path.home() / ".cache" / "semcode-bench"))
LINUX = ROOT / "linux"
DIRTY_TREE = ROOT / "linux-dirty"
DB_ROOT = ROOT / "db"

READ = ["mcp", "mcp-dirty", "mcp-behind", "mcp-aged", "cli"]
INDEX = ["subset", "full", "update"]
GROUPS = {"read": READ, "index": INDEX, "all": READ + INDEX}
# Timed runs for index and cli scenarios; server sessions for mcp ones.
DEFAULT_RUNS = {"mcp": 2, "mcp-dirty": 1, "mcp-behind": 1, "mcp-aged": 1, "cli": 10,
                "subset": 5, "full": 3, "update": 5}
# Requests in flight in the mcp scenario's parallel pass, as an agent sends them.
MCP_PARALLEL = 4
# Files the mcp-dirty scenario edits in its working copy.
DIRTY_FILES = 20
# Seconds to wait for an MCP response, or for the server to be ready.
MCP_TIMEOUT = 1800
METRICS = ["time_wall_clock", "time_user", "time_system", "memory_peak_resident"]


def step(msg: str) -> None:
    print(f"\n\033[1m==> {msg}\033[0m", flush=True)


def die(msg: str) -> None:
    sys.exit(f"error: {msg}")


def git(*args: str, cwd: Path = REPO, check: bool = True) -> str:
    out = subprocess.run(["git", *args], cwd=cwd, check=check, capture_output=True, text=True)
    return out.stdout.strip()


def sh(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=True)


def q(path: Path) -> str:
    return shlex.quote(str(path))


def db(name: str) -> Path:
    return DB_ROOT / name


def read_file(path: Path | str) -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return "unknown"


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


# ---------------------------------------------------------------- setup ----


def cmd_setup(_args: argparse.Namespace) -> None:
    """Fetch the kernel tree: TAG checked out, history since FLOOR."""
    if (LINUX / ".git").is_dir():
        have = git("rev-parse", "--verify", "--quiet", "HEAD", cwd=LINUX, check=False)
        if not have:
            die(f"{LINUX} has no checkout (an interrupted setup?); remove it and run setup again")
        if have != git("rev-parse", f"{TAG}^{{commit}}", cwd=LINUX, check=False):
            die(f"{LINUX} exists but is not at {TAG}; remove it and run setup again")
        print(f"Kernel tree already at {TAG}: {LINUX}")
        return

    step(f"Cloning {TAG} (history since {FLOOR}) from {KERNEL_URL}")
    LINUX.mkdir(parents=True)

    def run(*a: str) -> None:
        subprocess.run(["git", *a], cwd=LINUX, check=True)

    run("init", "--quiet")
    run("remote", "add", "origin", KERNEL_URL)
    run("fetch", "--no-tags", f"--shallow-exclude={FLOOR}", "origin",
        f"refs/tags/{TAG}:refs/tags/{TAG}", f"refs/tags/{BASE}:refs/tags/{BASE}")
    run("-c", "advice.detachedHead=false", "checkout", "--quiet", f"refs/tags/{TAG}")
    # The update, mcp-behind and mcp-aged scenarios need BASE..TAG complete.
    run("merge-base", "--is-ancestor", BASE, TAG)
    print(f"Ready: {LINUX}")


# ------------------------------------------------------------------ run ----


@dataclass
class Run:
    bin_dir: Path  # where cargo built the checkout's binaries
    out: Path  # this run's results
    runs: int | None  # -r, overriding DEFAULT_RUNS

    def bin(self, name: str) -> str:
        return str(self.bin_dir / name)

    def runs_for(self, scenario: str) -> int:
        return self.runs or DEFAULT_RUNS[scenario]


def build() -> Path:
    """Build the checkout this script is in; returns where its binaries are."""
    step("Building semcode")
    names = ("semcode-index", "semcode", "semcode-mcp")
    subprocess.run(["cargo", "build", "--release", "--quiet",
                    *[a for n in names for a in ("--bin", n)]], cwd=REPO, check=True)
    meta = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                          cwd=REPO, capture_output=True, text=True, check=True).stdout
    return Path(json.loads(meta)["target_directory"]) / "release"


def hyperfine(name: str, argv: list[str], runs: int, prepare: str | None = None,
              warmup: int = 0) -> list[dict]:
    """Time a command; returns one {metric: value} per run."""
    with tempfile.NamedTemporaryFile(suffix=".json") as export:
        cmd = ["hyperfine", "--style", "none", "--metrics", ",".join(METRICS),
               "--runs", str(runs), "--warmup", str(warmup), "--export-json", export.name]
        if prepare:
            cmd += ["--prepare", prepare]
        # No shell: hyperfine splits the string itself, with shell quoting.
        subprocess.run(cmd + ["-n", name, shlex.join(argv)], check=True)
        result = json.loads(Path(export.name).read_text())["results"][0]
    runs_ = [{k: v["value"] for k, v in m.items() if isinstance(v, dict)}
             for m in result["measurements"]]
    print(f"  {name}: " + ", ".join(f"{m['time_wall_clock']:.2f}s" for m in runs_), flush=True)
    return runs_


def index(run: Run, path: Path, *args: str, log: Path) -> None:
    with open(log, "w") as f:
        subprocess.run([run.bin("semcode-index"), *args, "-d", str(path)],
                       stdout=f, stderr=subprocess.STDOUT, check=True)


def copy(src: str, dst: str) -> str:
    return f"rm -rf {q(db(dst))} && cp -a {q(db(src))} {q(db(dst))}"


def ensure(run: Run, name: str, built: set[str]) -> None:
    """Build an index the scenarios share, once per run, untimed."""
    if name in built:
        return
    print(f"Building {name} (untimed)", flush=True)
    path = db(name)
    shutil.rmtree(path, ignore_errors=True)
    log = run.out / f"build-{name}.log"
    if name == "full.db":
        index(run, path, "--source", str(LINUX), log=log)
    elif name == "base.db":
        index(run, path, "--source", str(LINUX), "--git", f"{BASE}^..{BASE}", log=log)
    elif name == "aged.db":
        ensure(run, "base.db", built)
        sh(copy("base.db", "aged.db"))
        index(run, path, "--source", str(LINUX), "--git", f"{BASE}..{TAG}", log=log)
    built.add(name)


# -------------------------------------------------------- index scenarios ----


def table_counts(run: Run, path: Path) -> dict[str, int]:
    """Row counts as `semcode -q tables` reports them."""
    out = subprocess.run([run.bin("semcode"), "--database", str(path), "--git-repo", str(LINUX),
                          "-q", "tables"], capture_output=True, text=True, check=True).stdout
    return {m[1]: int(m[2]) for m in re.finditer(r"^(\w+): (\d+)$", strip_ansi(out), re.M)}


def du(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


# scenario -> (index written, arguments, command run before each run, index it starts from)
INDEX_SCENARIOS = {
    "subset": ("subset.db", ["--source", str(LINUX / SUBSET)],
               f"rm -rf {q(db('subset.db'))}", None),
    "full": ("full.db", ["--source", str(LINUX)], f"rm -rf {q(db('full.db'))}", None),
    "update": ("update.db", ["--source", str(LINUX)], copy("base.db", "update.db"), "base.db"),
}


def index_scenario(run: Run, scenario: str, built: set[str]) -> dict:
    """An untimed warm-up run, then the timed runs.  The warm-up brings the
    kernel's git objects into the page cache, records the phase breakdown
    (--perf-json, so the timed runs are not instrumented), and checks the
    index it wrote: one with no functions fails the run."""
    name, args, prepare, start = INDEX_SCENARIOS[scenario]
    if start:
        ensure(run, start, built)
    path = db(name)
    perf = run.out / f"{scenario}-perf.json"
    log = run.out / f"{scenario}.log"
    sh(prepare)
    index(run, path, *args, "--perf-json", str(perf), log=log)
    counts = table_counts(run, path)
    if not counts.get("Functions"):
        die(f"{scenario}: wrote an index with no functions; see {log}")
    argv = [run.bin("semcode-index"), *args, "-d", str(path)]
    runs = hyperfine(scenario, argv, run.runs_for(scenario), prepare)
    if scenario == "full":
        built.add("full.db")  # the last run's index serves the read scenarios
    return {"runs": runs, "counts": counts, "db_bytes": du(path),
            "phases": json.loads(perf.read_text())}


# ------------------------------------------------------------------- cli ----


def read_queries() -> list[tuple[str, str, str]]:
    """bench/queries.txt: name, expected output, query."""
    queries = []
    for line in (BENCH_DIR / "queries.txt").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            parts = line.split("\t")
            if len(parts) != 3:
                die(f"queries.txt: expected name<TAB>expected<TAB>query, got: {line!r}")
            queries.append(tuple(parts))
    return queries


def cli_scenario(run: Run, built: set[str]) -> dict:
    """One-shot queries: each is a process, so its time includes opening
    the database.  Each must print its expected string before it is timed:
    a query that finds nothing returns quickly."""
    ensure(run, "full.db", built)
    results = {}
    for name, expected, query in read_queries():
        argv = [run.bin("semcode"), "--database", str(db("full.db")),
                "--git-repo", str(LINUX), "-q", query]
        out = subprocess.run(argv, capture_output=True, text=True)
        if out.returncode != 0 or expected not in strip_ansi(out.stdout):
            die(f"cli {name}: exit {out.returncode}, {expected!r} not in output:\n"
                f"{strip_ansi(out.stdout)[-2000:]}{out.stderr[-2000:]}")
        results[name] = {"query": query,
                         "runs": hyperfine(f"cli-{name}", argv, run.runs_for("cli"), warmup=1)}
    return results


# ------------------------------------------------------------------- mcp ----


@dataclass
class Call:
    id: int
    tool: str
    args: dict
    expect: list  # what the answer must contain: see found()


def read_workload() -> list[Call]:
    """bench/workload.jsonl, written by bench/workload.rs."""
    calls = []
    for line in (BENCH_DIR / "workload.jsonl").read_text().splitlines():
        r = json.loads(line)
        if "meta" not in r:
            calls.append(Call(r["id"], r["tool"], r["args"], r["expect"]))
    return calls


class McpSession:
    """One semcode-mcp process spoken to over stdio, as an MCP client does.
    A reader thread timestamps each response as its line arrives, before it
    is parsed, so parsing a large response is not charged to the server."""

    def __init__(self, argv: list[str], log: Path):
        self.started = time.perf_counter()
        self.log = log
        with open(log, "w") as err:
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=err)
        self.responses: dict[int, tuple[float, dict]] = {}
        self.cond = threading.Condition()
        self.eof = False
        self.next_id = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            now = time.perf_counter()
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in msg:  # notifications carry none
                with self.cond:
                    self.responses[msg["id"]] = (now, msg)
                    self.cond.notify_all()
        with self.cond:
            self.eof = True
            self.cond.notify_all()

    def _write(self, msg: dict) -> float:
        sent = time.perf_counter()  # before writing: a reply cannot precede it
        try:
            self.proc.stdin.write(json.dumps(msg).encode() + b"\n")
            self.proc.stdin.flush()
        except BrokenPipeError:
            die(f"semcode-mcp exited; see {self.log}")
        return sent

    def send(self, method: str, params: dict) -> tuple[int, float]:
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        return self.next_id, self._write(msg)

    def wait_any(self, ids) -> tuple[int, float, dict]:
        deadline = time.monotonic() + MCP_TIMEOUT
        with self.cond:
            while True:
                for rid in ids:
                    if rid in self.responses:
                        return rid, *self.responses.pop(rid)
                if self.eof:
                    die(f"semcode-mcp exited; see {self.log}")
                if time.monotonic() > deadline:
                    self.proc.kill()
                    die(f"semcode-mcp gave no response in {MCP_TIMEOUT}s; see {self.log}")
                self.cond.wait(timeout=1)

    def tool(self, name: str, args: dict) -> tuple[str, bool]:
        rid, _ = self.send("tools/call", {"name": name, "arguments": args})
        return response_text(self.wait_any([rid])[2])

    def start(self) -> float:
        """Initialize, then wait out the indexing a server does at startup,
        when it refuses tool calls.  Returns seconds from spawn to ready."""
        rid, _ = self.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                          "clientInfo": {"name": "semcode-bench", "version": "1"}})
        self.wait_any([rid])
        self._write({"jsonrpc": "2.0", "method": "notifications/initialized"})
        deadline = time.monotonic() + MCP_TIMEOUT
        while time.monotonic() < deadline:
            text, _ = self.tool("indexing_status", {})
            if "Status: Completed" in text:
                return time.perf_counter() - self.started
            if "Status: Failed" in text:
                die(f"semcode-mcp indexing failed:\n{text}")
            time.sleep(0.02)
        self.proc.kill()
        die(f"semcode-mcp not ready after {MCP_TIMEOUT}s; see {self.log}")

    def peak_rss(self) -> int:
        for line in read_file(f"/proc/{self.proc.pid}/status").splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
        return 0

    def close(self) -> None:
        self.proc.stdin.close()
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def response_text(msg: dict) -> tuple[str, bool]:
    if "error" in msg:
        return json.dumps(msg["error"]), True
    result = msg.get("result", {})
    text = "".join(c.get("text", "") for c in result.get("content", []))
    return text, bool(result.get("isError"))


def replay(session: McpSession, calls: list[Call], parallel: int) -> dict[int, tuple[float, str]]:
    """Every call, `parallel` in flight at a time; returns latency and text
    by call id.  Latency runs from send to response, so with several in
    flight it includes time spent queued."""
    results, pending, todo = {}, {}, iter(calls)

    def send_next() -> None:
        call = next(todo, None)
        if call:
            rid, sent = session.send("tools/call", {"name": call.tool, "arguments": call.args})
            pending[rid] = (call, sent)

    for _ in range(parallel):
        send_next()
    while pending:
        rid, received, msg = session.wait_any(list(pending))
        call, sent = pending.pop(rid)
        text, is_error = response_text(msg)
        results[call.id] = (received - sent, "error: " + text if is_error else text)
        send_next()
    return results


# What a lookup that found nothing says.  It answers fast, so a build that
# broke a lookup would otherwise look like a faster one.
NOT_FOUND = ("error: ", "not found at git SHA", "not found in database", "Failed to survey")


def found(expected, text: str) -> bool:
    """A string must appear; any one of a list must hold; {"count": regex,
    "min": n} needs the regex's first group, a number, to reach n."""
    if isinstance(expected, list):
        return any(found(e, text) for e in expected)
    if isinstance(expected, dict):
        return any(int(c) >= expected["min"] for c in re.findall(expected["count"], text))
    return expected in text


def failures(calls: list[Call], results: dict[int, tuple[float, str]]) -> list[str]:
    bad = []
    for call in calls:
        text = results[call.id][1]
        if any(n in text for n in NOT_FOUND) or not all(found(e, text) for e in call.expect):
            bad.append(f"#{call.id} {call.tool} {json.dumps(call.args)}: {text[:300]!r}")
    return bad


def mcp_scenario(run: Run, scenario: str, index_name: str, tree: Path,
                 passes: list[tuple[str, int]], checks: list[Call] = ()) -> dict:
    """Server sessions.  Each starts on a fresh copy of the index (the
    server may index into it), waits until ready, then replays the workload
    once per pass, with that many requests in flight.  Every answer is
    checked."""
    calls = read_workload()
    sessions = []
    for s in range(run.runs_for(scenario)):
        sh(copy(index_name, f"{scenario}.db"))
        session = McpSession([run.bin("semcode-mcp"), "-d", str(db(f"{scenario}.db")),
                              "--git-repo", str(tree)], run.out / f"{scenario}-{s + 1}.log")
        result = {"ready": session.start(), "passes": {}}
        line = f"  {scenario} session {s + 1}: ready {result['ready']:.1f}s"
        for name, parallel in passes:
            start = time.perf_counter()
            answers = replay(session, calls, parallel)
            bad = failures(calls, answers)
            if bad:
                die(f"{scenario}, {name} pass: {len(bad)} of {len(calls)} calls failed "
                    "their checks:\n  " + "\n  ".join(bad[:10]))
            result["passes"][name] = {"total": time.perf_counter() - start,
                                      "calls": {i: lat for i, (lat, _) in answers.items()}}
            line += f", {name} {result['passes'][name]['total']:.1f}s"
        # After the passes, so the first pass pays for building the overlay
        # these look into, as a user's first lookup does.
        for call in checks:
            text, is_error = session.tool(call.tool, call.args)
            if is_error or not all(found(e, text) for e in call.expect):
                die(f"{scenario}: check {call.tool} {call.args} failed: {text[:500]!r}")
        result["rss"] = session.peak_rss()
        session.close()
        sessions.append(result)
        print(line, flush=True)
    return {"sessions": sessions}


def dirty_tree(calls: list[Call]) -> tuple[Path, list[Call]]:
    """A git worktree of the kernel at TAG, made afresh every run, with
    DIRTY_FILES files the workload looks into edited; and checks that the
    server sees the edits."""
    shutil.rmtree(DIRTY_TREE, ignore_errors=True)
    subprocess.run(["git", "-C", str(LINUX), "worktree", "prune"], check=True)
    subprocess.run(["git", "-C", str(LINUX), "worktree", "add", "--quiet", "--detach",
                    str(DIRTY_TREE), TAG], check=True)
    paths = []
    for call in calls:
        for p in [e for e in call.expect if isinstance(e, str)] + [call.args.get("path", "")]:
            if p.endswith((".c", ".h")) and p not in paths and (DIRTY_TREE / p).is_file():
                paths.append(p)
    paths = paths[:DIRTY_FILES]
    if not paths:
        die("mcp-dirty: no .c or .h file in the workload exists in the tree to edit")
    for i, p in enumerate(paths):
        with open(DIRTY_TREE / p, "a") as f:
            f.write(f"\n/* semcode-bench: an uncommitted edit */\n"
                    f"int semcode_bench_dirty_{i}(void)\n{{\n\treturn 0;\n}}\n")
    checks = [Call(0, "find_function", {"name": f"semcode_bench_dirty_{i}"}, [paths[i]])
              for i in (0, len(paths) - 1)]
    return DIRTY_TREE, checks


def read_scenario(run: Run, scenario: str, built: set[str]) -> dict:
    both = [("first", 1), ("warm", 1)]
    if scenario == "mcp":
        ensure(run, "full.db", built)
        return mcp_scenario(run, scenario, "full.db", LINUX, both + [("parallel", MCP_PARALLEL)])
    if scenario == "mcp-dirty":
        ensure(run, "full.db", built)
        tree, checks = dirty_tree(read_workload())
        return mcp_scenario(run, scenario, "full.db", tree, both, checks)
    if scenario == "mcp-behind":
        ensure(run, "base.db", built)
        # Once caught up the server is warm: a second pass would repeat the first.
        return mcp_scenario(run, scenario, "base.db", LINUX, [("first", 1)])
    if scenario == "mcp-aged":
        ensure(run, "aged.db", built)
        return mcp_scenario(run, scenario, "aged.db", LINUX, both)
    return cli_scenario(run, built)


# ---------------------------------------------------------------- report ----


def mean_sd(values: list[float], scale: float = 1, digits: int = 1) -> str:
    v = [x * scale for x in values]
    sd = f" ± {statistics.stdev(v):.{digits}f}" if len(v) > 1 else ""
    return f"{statistics.fmean(v):.{digits}f}{sd}"


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct / 100 * len(ordered)) - 1)]


def report_index(scenario: str, r: dict) -> list[str]:
    def col(metric: str) -> list[float]:
        return [x[metric] for x in r["runs"]]

    lines = [f"## {scenario}", "",
             "| Wall [s] | User [s] | System [s] | Peak RSS [MiB] | Functions | Types | DB [MiB] |",
             "|--:|--:|--:|--:|--:|--:|--:|",
             f"| {mean_sd(col('time_wall_clock'), digits=2)} | {mean_sd(col('time_user'))} "
             f"| {mean_sd(col('time_system'))} "
             f"| {statistics.fmean(col('memory_peak_resident')) / 2**20:.0f} "
             f"| {r['counts'].get('Functions')} | {r['counts'].get('Types')} "
             f"| {r['db_bytes'] / 2**20:.0f} |",
             "", "<details><summary>Phases (warm-up run; per-file phases are CPU time "
             "summed across threads)</summary>", "", "| Phase | [s] |", "|:--|--:|"]
    lines += [f"| {k} | {v['total_ms'] / 1000:.1f} |" for k, v in sorted(r["phases"].items())]
    return lines + ["", "</details>"]


def report_cli(r: dict) -> list[str]:
    lines = ["## cli", "", "| Query | Wall [ms] |", "|:--|--:|"]
    for name, x in r.items():
        walls = [m["time_wall_clock"] for m in x["runs"]]
        lines.append(f"| {name}: `{x['query']}` | {mean_sd(walls, 1000)} |")
    return lines


def report_mcp(scenario: str, r: dict) -> list[str]:
    sessions = r["sessions"]
    passes = list(sessions[0]["passes"])
    calls = read_workload()
    lines = [f"## {scenario}", "",
             "| Ready [s] |" + "".join(f" {p.capitalize()} pass [s] |" for p in passes)
             + " Peak RSS [MiB] |",
             "|--:" * (len(passes) + 2) + "|",
             f"| {mean_sd([s['ready'] for s in sessions])} |"
             + "".join(f" {mean_sd([s['passes'][p]['total'] for s in sessions])} |" for p in passes)
             + f" {statistics.fmean(s['rss'] for s in sessions) / 2**20:.0f} |"]

    # Per tool: each call's median over sessions, then p50/p95/max over calls.
    shown = [p for p in ("warm", "parallel") if p in passes] or ["first"]

    def latency(p: str, call_id: int) -> float:
        return statistics.median(s["passes"][p]["calls"][call_id] for s in sessions) * 1000

    lines += ["", "| Tool | Calls |" + "".join(f" {p} p50 / p95 / max [ms] |" for p in shown),
              "|:--|--:|" + "--:|" * len(shown)]
    for tool in sorted({c.tool for c in calls}) + ["all"]:
        ids = [c.id for c in calls if tool in ("all", c.tool)]
        row = f"| {'**all**' if tool == 'all' else tool} | {len(ids)} |"
        for p in shown:
            v = [latency(p, i) for i in ids]
            row += f" {percentile(v, 50):.0f} / {percentile(v, 95):.0f} / {max(v):.0f} |"
        lines.append(row)

    slowest = sorted(calls, key=lambda c: latency(shown[0], c.id), reverse=True)[:10]
    lines += ["", f"<details><summary>Slowest calls ({shown[0]} pass)</summary>", "",
              "| Call | [ms] |", "|:--|--:|"]
    lines += [f"| {c.tool}({', '.join(f'{a}={v}' for a, v in c.args.items())}) "
              f"| {latency(shown[0], c.id):.0f} |" for c in slowest]
    return lines + ["", "</details>"]


# ------------------------------------------------------------------ main ----


def cmd_run(args: argparse.Namespace) -> None:
    scenarios = []
    for s in args.scenarios.split(","):
        if s not in GROUPS and s not in GROUPS["all"]:
            die(f"unknown scenario: {s} (choose from {', '.join([*GROUPS, *GROUPS['all']])})")
        scenarios += [x for x in GROUPS.get(s, [s]) if x not in scenarios]
    if not shutil.which("hyperfine"):
        die("hyperfine not found (cargo install hyperfine --locked)")
    version = subprocess.run(["hyperfine", "--version"], capture_output=True, text=True).stdout
    if int(version.split()[1].split(".")[0]) < 2:
        die("hyperfine >= 2.0 required (for --metrics)")
    head = git("rev-parse", "HEAD", cwd=LINUX, check=False) if LINUX.is_dir() else ""
    if not head or head != git("rev-parse", f"{TAG}^{{commit}}", cwd=LINUX, check=False):
        die(f"no kernel tree at {TAG} in {LINUX}; run bench/bench.py setup")
    if git("status", "--porcelain", "--untracked-files=no", cwd=LINUX):
        die(f"{LINUX} has local changes")

    commit = git("rev-parse", "--short=12", "HEAD")
    if git("status", "--porcelain", "--untracked-files=no"):
        commit += " with uncommitted changes"
    out = ROOT / "results" / datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True)
    run = Run(build(), out, args.runs)
    # Indexes are built by this run's binaries, so none outlive it.
    shutil.rmtree(DB_ROOT, ignore_errors=True)
    DB_ROOT.mkdir(parents=True)

    meta = {
        "commit": commit,
        "date": datetime.datetime.now().isoformat(timespec="seconds"),
        "host": platform.node(),
        "cpu": next((line.split(":", 1)[1].strip()
                     for line in read_file("/proc/cpuinfo").splitlines()
                     if line.startswith("model name")), "unknown"),
        "governor": read_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "input": f"{TAG}, base {BASE}",
    }
    built: set[str] = set()
    results = {}
    for s in scenarios:
        step(s)
        results[s] = (index_scenario(run, s, built) if s in INDEX_SCENARIOS
                      else read_scenario(run, s, built))

    lines = ["# semcode benchmark", "", "```", *(f"{k}: {v}" for k, v in meta.items()), "```"]
    for s, r in results.items():
        lines.append("")
        lines += (report_index(s, r) if s in INDEX_SCENARIOS
                  else report_cli(r) if s == "cli" else report_mcp(s, r))
    lines += ["", "Mean ± standard deviation over runs or sessions."]
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    (out / "summary.json").write_text(json.dumps({"meta": meta, "results": results}, indent=1))
    step(f"Done: {out}/summary.md")
    print("\n".join(lines))


def positive_int(text: str) -> int:
    if int(text) < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {text}")
    return int(text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("setup", help="fetch the pinned kernel tree").set_defaults(func=cmd_setup)
    run = sub.add_parser("run", help="build this checkout and run scenarios")
    run.add_argument("-s", "--scenarios", default="read",
                     help="comma-separated scenarios or groups: read (default), index, all")
    run.add_argument("-r", "--runs", type=positive_int,
                     help="timed runs, or server sessions, per scenario (default: per scenario)")
    run.set_defaults(func=cmd_run)
    args = parser.parse_args()
    try:
        args.func(args)
    except subprocess.CalledProcessError as e:
        cmd = e.cmd if isinstance(e.cmd, str) else shlex.join(map(str, e.cmd))
        die(f"command failed ({e.returncode}): {cmd}")


if __name__ == "__main__":
    main()
