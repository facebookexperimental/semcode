# Semcode Multi-Branch Querying Example

This document demonstrates semcode's ability to query code across different
indexed branches, which is essential for tracking how code evolves across
kernel versions.

## Why Multi-Branch Support?

The Linux kernel maintains multiple stable branches simultaneously (5.10.y,
6.1.y, 6.6.y, 6.12.y, etc.), each receiving ongoing security fixes and
backports. When analyzing CVEs, backports, or API evolution, you often need
to query the same function across different kernel versions.

**Primary use case: Backport decisions with autosel**

When a fix lands in mainline, the stable team needs to determine:
- Which LTS branches are affected by this bug?
- Does the vulnerable code even exist in older branches?
- Will the fix apply cleanly, or has the code changed too much?

Multi-branch queries answer these questions instantly, without manually
checking out each branch or running git-blame archaeology.

Semcode's branch tracking helps you:
1. **Index once, query many** - Index multiple stable branches and switch
   between them instantly without re-indexing
2. **Track branch freshness** - Know when a branch needs re-indexing because
   new commits were pushed (e.g., a new 6.12.87 release)
3. **Compare versions** - Understand how code evolved between kernel versions
4. **Automate backport scope** - Programmatically determine which branches
   need a fix by checking if the affected code exists

## Listing Available Branches

Use `list_branches` to see all indexed branches and their status:

```
=== Indexed Branches ===

  origin/master (c9b47175) [origin]
    Status: outdated

  stable/linux-5.10.y (f964b940) [stable]
    Status: up-to-date

  stable/linux-6.1.y (50cbba13) [stable]
    Status: up-to-date

  stable/linux-6.12.y (dcbeffaf) [stable]
    Status: up-to-date

  stable/linux-6.17.y (5439375c) [stable]
    Status: up-to-date

  stable/linux-6.18.y (7d0a66e4) [stable]
    Status: up-to-date

Total: 8 branch(es) indexed
```

### Understanding Branch Status

Each branch shows a **status** field:

- **up-to-date**: The indexed commit matches the current branch tip. Queries
  reflect the latest code.
- **outdated**: The branch has received new commits since indexing. The
  indexed SHA (shown in parentheses) is behind the current branch tip.

When a branch is outdated, you can still query it - you'll just be querying
against the older indexed version. To update, re-run the indexer:

```bash
# Re-index specific branches that are outdated
semcode-index -s . --branches stable/linux-6.12.y,stable/linux-6.17.y

# Or re-index all configured branches
semcode-index -s . --branches stable/linux-5.10.y,stable/linux-6.1.y,stable/linux-6.12.y,stable/linux-6.17.y,stable/linux-6.18.y
```

### Typical Workflow: Keeping Stable Branches Current

For kernel CVE analysis, you might set up a cron job or periodic task:

```bash
# 1. Fetch latest stable branches
git fetch --all

# 2. Check which branches need updating
semcode list_branches  # Look for "outdated" status

# 3. Re-index outdated branches
semcode-index -s . --branches stable/linux-6.12.y,stable/linux-6.18.y
```

## Comparing Branches

Use `compare_branches` to understand the relationship between two branches:

```
=== Branch Comparison: stable/linux-6.1.y vs stable/linux-6.18.y ===

Branch Tips:
  stable/linux-6.1.y: 50cbba13faa2
  stable/linux-6.18.y: 7d0a66e4bb90

Merge Base: 830b3c68c1fb

Branches have diverged from merge base

Indexing Status:
  stable/linux-6.1.y: up-to-date (indexed at 50cbba13)
  stable/linux-6.18.y: up-to-date (indexed at 7d0a66e4)
```

## Querying Functions Across Branches

### Example: Tracking io_uring_setup Evolution

The `branch` parameter works with most semcode tools. Here's how
`io_uring_setup` changed between kernel 5.10 and 6.18:

**Linux 5.10 (stable/linux-5.10.y):**

```c
// File: io_uring/io_uring.c:10311-10330
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
    struct io_uring_params p;
    int i;

    if (copy_from_user(&p, params, sizeof(p)))
        return -EFAULT;
    for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
        if (p.resv[i])
            return -EINVAL;
    }

    // Flags checked individually - only 7 flags supported
    if (p.flags & ~(IORING_SETUP_IOPOLL | IORING_SETUP_SQPOLL |
            IORING_SETUP_SQ_AFF | IORING_SETUP_CQSIZE |
            IORING_SETUP_CLAMP | IORING_SETUP_ATTACH_WQ |
            IORING_SETUP_R_DISABLED))
        return -EINVAL;

    return  io_uring_create(entries, &p, params);
}
```

**Linux 6.18 (stable/linux-6.18.y):**

```c
// File: io_uring/io_uring.c:3924-3939
static long io_uring_setup(u32 entries, struct io_uring_params __user *params)
{
    struct io_uring_params p;
    int i;

    if (copy_from_user(&p, params, sizeof(p)))
        return -EFAULT;
    for (i = 0; i < ARRAY_SIZE(p.resv); i++) {
        if (p.resv[i])
            return -EINVAL;
    }

    // Consolidated into IORING_SETUP_FLAGS macro
    if (p.flags & ~IORING_SETUP_FLAGS)
        return -EINVAL;
    return io_uring_create(entries, &p, params);
}
```

**Key differences observed:**
1. File location moved from line 10311 to line 3924 (major refactoring)
2. Individual flag checks consolidated into `IORING_SETUP_FLAGS` macro
3. Code is cleaner and more maintainable in 6.18

### Example: Code Organization Changes

Using `grep_functions` with branch parameter shows how io_uring was
reorganized:

**Linux 5.10:** All io_uring code in `io_uring/io_uring.c`
```
io_uring/io_uring.c:io_poll_add_prep:5970
io_uring/io_uring.c:io_sfr_prep:4683
io_uring/io_uring.c:io_sq_thread:7562
```

**Linux 6.18:** Code split across multiple files
```
io_uring/register.c:io_register_restrictions:162
io_uring/msg_ring.c:io_msg_send_fd:247
io_uring/sqpoll.c:io_sq_offload_create:451
io_uring/io_uring.h:io_lockdep_assert_cq_locked:186
```

## Integration with Autosel Backport Workflow

When autosel (or a human maintainer) evaluates whether to backport a commit to
stable branches, multi-branch queries answer critical questions:

### Question 1: "How far back should we backport?"

A fix in mainline might only apply to recent kernels if the vulnerable code
was introduced after older LTS branches diverged.

```bash
# Does the vulnerable function exist in each stable branch?
find_function(name="vulnerable_func", branch="stable/linux-5.10.y")  # Not found = no backport needed
find_function(name="vulnerable_func", branch="stable/linux-6.1.y")   # Found = needs backport
find_function(name="vulnerable_func", branch="stable/linux-6.6.y")   # Found = needs backport
```

**Real example**: The folio APIs don't exist in 5.10.y, so any fix involving
`folio_test_slab` or similar functions only needs backporting to 5.15+.

### Question 2: "Is the fix applicable as-is, or does it need modification?"

Code often changes between versions. A fix that cleanly applies to 6.18 might
need adaptation for 5.10.

```bash
# Compare function signatures across versions
find_function(name="kfree", branch="stable/linux-5.10.y")  # In mm/slab.c, SLAB allocator
find_function(name="kfree", branch="stable/linux-6.18.y")  # In mm/slub.c, SLUB allocator

# Check if the fix's context matches
grep_functions(pattern="specific_code_pattern", branch="stable/linux-5.10.y")
grep_functions(pattern="specific_code_pattern", branch="stable/linux-6.1.y")
```

If the pattern doesn't exist in 5.10.y, the fix either doesn't apply or needs
a different approach.

### Question 3: "Is this a real issue in this LTS branch?"

Sometimes a bug exists in mainline but was never present in older branches
(e.g., introduced by a feature that wasn't backported).

```bash
# Check if the problematic code path exists
find_callers(name="problematic_func", branch="stable/linux-5.10.y")  # 0 callers = not reachable
find_callers(name="problematic_func", branch="stable/linux-6.12.y")  # 50 callers = affected

# Verify the vulnerable pattern is present
grep_functions(pattern="if.*NULL.*&&.*ptr->field", branch="stable/linux-5.10.y")
```

### Question 4: "What's the blast radius of this change?"

Understanding how many callers/callees are affected helps assess risk.

```bash
# Compare caller counts - more callers = higher risk backport
find_callers(name="affected_func", branch="stable/linux-5.10.y")   # 50 callers
find_callers(name="affected_func", branch="stable/linux-6.18.y")   # 150 callers

# The function grew significantly - the 6.18 fix might touch code paths
# that don't exist in 5.10.y
```

### Typical Autosel Workflow with Semcode

```
1. Commit appears in mainline: "Fix NULL deref in foo_handler()"

2. Autosel asks: "Should this go to stable?"
   → LLM says yes, it's a bug fix

3. Autosel asks: "Which stable branches need this?"
   → Query each branch:
     - 5.10.y: foo_handler doesn't exist (introduced in 5.15) → SKIP
     - 5.15.y: foo_handler exists, vulnerable pattern present → BACKPORT
     - 6.1.y:  foo_handler exists, vulnerable pattern present → BACKPORT
     - 6.6.y:  foo_handler exists, vulnerable pattern present → BACKPORT
     - 6.12.y: foo_handler exists, vulnerable pattern present → BACKPORT

4. Autosel asks: "Will the patch apply cleanly?"
   → Compare function bodies between mainline and each target branch
   → Flag branches where context differs significantly
```

## Use Cases

### 1. CVE Analysis Across Stable Branches

When analyzing a security fix, check which stable branches have the fix:

```
# Check if a function exists in different branches
find_function(name="vulnerable_func", branch="stable/linux-5.10.y")
find_function(name="vulnerable_func", branch="stable/linux-6.1.y")
```

### 2. Backport Verification

Verify a backport was applied correctly:

```
# Compare function implementation across branches
find_function(name="fixed_function", branch="origin/master")
find_function(name="fixed_function", branch="stable/linux-6.1.y")
```

### 3. API Evolution Tracking

Track how APIs change over kernel versions:

```
# Find callers to understand usage patterns
find_callers(name="old_api_function", branch="stable/linux-5.10.y")
find_callers(name="new_api_function", branch="stable/linux-6.18.y")
```

### 4. Regression Investigation

When a regression appears in a stable branch, compare with mainline:

```
compare_branches(branch1="stable/linux-6.12.y", branch2="origin/master")
grep_functions(pattern="suspicious_pattern", branch="stable/linux-6.12.y")
grep_functions(pattern="suspicious_pattern", branch="origin/master")
```

## Indexing Multiple Branches

To index multiple branches for querying:

```bash
# Index specific branches
semcode-index -s . --branches main,stable/linux-6.1.y,stable/linux-6.12.y

# Query tool with default branch
semcode --branch stable/linux-6.12.y
```

## MCP Tool Parameters

All these MCP tools support the `branch` parameter:

| Tool | Branch Support |
|------|----------------|
| `find_function` | Yes |
| `find_type` | Yes |
| `find_callers` | Yes |
| `find_calls` | Yes |
| `find_callchain` | Yes |
| `grep_functions` | Yes |
| `vgrep_functions` | Yes |
| `list_branches` | N/A (lists all) |
| `compare_branches` | Takes two branches |

The `branch` parameter takes precedence over `git_sha` if both are provided.

## Real-World Examples from Testing

### API Evolution: Memory Allocator Changes

The `kfree` function moved between allocators across kernel versions:

| Version | File | Allocator |
|---------|------|-----------|
| 5.10.y | `mm/slab.c:3738` | SLAB |
| 6.18.y | `mm/slub.c:6829` | SLUB |

```bash
# Query shows different implementations
find_function(name="kfree", branch="stable/linux-5.10.y")  # SLAB version
find_function(name="kfree", branch="stable/linux-6.18.y")  # SLUB version
```

### API Renaming: Profiling Annotations

Some functions were renamed with `_noprof` suffixes for memory profiling:

| 5.10.y | 6.18.y |
|--------|--------|
| `__kmalloc` | `__kmalloc_noprof` |

This is why searching for `__kmalloc` in 6.18.y returns a bootloader stub
instead of the main allocator - the real function was renamed.

### Codebase Growth

Caller counts show kernel growth over time:

| Function | 5.10.y Callers | 6.18.y Callers | Growth |
|----------|----------------|----------------|--------|
| `kvfree` | 797 | 1,476 | +85% |
| `kfree` | 24,731 | 28,294 | +14% |

### New APIs

Some APIs only exist in newer kernels:

```bash
# folio_test_slab doesn't exist in 5.10
grep_functions(pattern="folio_test_slab", branch="stable/linux-5.10.y")  # 0 results
grep_functions(pattern="folio_test_slab", branch="stable/linux-6.18.y")  # 5+ results
```

The `folio` abstraction was introduced after 5.10, so related APIs are
missing from older branches.
