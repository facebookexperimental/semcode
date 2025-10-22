# semcode usage guide

All semcode functions are git aware and default to lookups on the current
commit.  You can also pass a specific commit you're interested in.

**find_function**: search for functions and macros
  - git_sha: indicates which commit to search (default: current)
  - name: function/macro name, or a regex
  - also displays details on callers and callees
**find_type**: search for types and typedefs
  - git_sha: indicates which commit to search (default: current)
  - name: type/typdef name or regex
**find_callers**: find all functions that call a function or macro
  - git_sha: indicates which commit to search (default: current)
  - name: function to search
**find_calls**: find all functions called by a function or macro
  - git_sha: indicates which commit to search (default: current)
  - name: function to search
**find_callchain**: search complete function/macro call chain (forward and reverse)
  - git_sha: indicates which commit to search (default: current)
  - name: function or macro to search
  - up_levels: number of caller levels to show (default: 2, 0 = unlimited)
  - down_levels: number of callee levels to show (default: 3, 0 = unlimited)
  - calls_limit: max calls to show per level (default: 15, 0 = unlimited)
**diff_functions**: extract and functions and types from a unified diff
  - diff_content: the string to analyze
  - Use this to determine which symbols are involved in a given diff
**grep_functions**: search function/macro bodies for a regex
  - git_sha: indicates which commit to search (default: current)
  - pattern: the regex to search for
  - verbose: boolean, if true show full function bodies (default: false)
  - path_pattern: optional regex to filter results by path
  - limit: max number of result to return (default: 100, 0 = unlimited)
  - this only searches inside functions or macros, there's no need to escape
    your pattern to limit the search.
**vgrep_functions**: vector embedding search on functions/macros/types
  - git_sha: indicates which commit to search (default: current)
  - query_text: the regex to search for
  - verbose: boolean, if true show full function bodies (default: false)
  - path_pattern: optional regex to filter results by path
  - limit: max number of result to return (default: 100, 0 = unlimited)
  - Embedding searches are only useful when you want to search for broad
    concepts that a regex won't find well.  
  - The database might not have embeddings indexed
**find_commit**: search for changes, potentially in a range of commits
  - This can return a large body of results.  Use pagination to manage context
  - git_ref: single commit ref to lookup (sha, short sha, branch, HEAD etc)
  - git_range: optional git range to search multiple commits: HEAD~10..HEAD etc
    cannot be combined with git_ref
  - regex_patterns: optional array of regex patterns to filter commits.
    - All patterns are AND'd together
    - Applied against the combination of commit message and unified diff
  - symbol_patterns: optional array of regex of symbols to search for
    - Use this to quickly find commits changing a function or type (w/regex)
  - path_patterns: optional regex to filter commits based on which files they
    change.  Multiple regex can be passed and will be OR'd together
  - page: optional page number for pagination (1-based).  Each page contains
    50 lines, results indicate current page and total pages.  Default: full results
  - reachable_sha: optional git sha, filter results to only those reachable from the
    sha provided.  Mutually exclusive with git_range
  - verbose: show full diff in addition to metadata (default: fase)
**vcommit_similar_commits**: search commits based on vector embeddings
  - git_range: optional git range to search multiple commits: HEAD~10..HEAD etc
  - query_text: search text
  - regex_patterns: array of regex AND'd together to limit search results
  - symbol_patterns: array of regex AND'd together to limit search results based
    on symbols changed in the commit
  - path_patterns: optional regex to filter commits based on which files they
    change.  Multiple regex can be passed and will be OR'd together
  - limit: max results to return (default 10, max 50)
  - reachable_sha: optional git sha, filter results to only those reachable from the
    sha provided.  Mutually exclusive with git_range
  - page: optional page number for pagination (1-based).  Each page contains
    50 lines, results indicate current page and total pages.  Default: full results

## Recipes

### Searching for commits reachable from HEAD (or any other git sha)

If a repository heavily cherry-picks patches, it might have a backported commit
under a different git sha.  This means the most effective way to find the
backported commit is searching by commit subject:

```
semcode> commit -r "bnxt_en: Fix memory corruption when FW resources change during ifdown"
semcode> commit -r "bnxt_en: Fix memory corruption when FW resources change during ifdown" --reachable HEAD
```

❌ WRONG: reachable_sha=HEAD + git_range=HEAD~5000..HEAD
❌ WRONG: git_range=HEAD~5000..HEAD
✅ CORRECT: reachable_sha=HEAD only (no git_range)

