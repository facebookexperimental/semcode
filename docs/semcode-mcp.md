# semcode usage guide

All semcode functions are git aware and default to lookups on the current
commit.  You can also pass a specific commit you're interested in, or a branch name.

**Regex**: all patterns are case-insensitive; no `(?i)` needed.  Applies to
function names, commit messages, symbols, and lore email searches.

## Common parameters

- **git_sha**: commit to search (default: current)
- **branch**: branch name, resolved to its tip (e.g., "main"); takes
  precedence over git_sha if both are given
- **scope**: which of several same-named definitions to answer about
  (`find_callers`, `find_calls`, `find_callchain` only).  An object with one
  key per axis; the only axis today is `arch`, so `{"arch": "x86"}`.  The
  axis a language other than C needs -- the class, module or namespace that
  owns a method -- is a different question and will get its own key rather
  than being spelled `arch`.

  Without a scope, a name defined once per architecture is answered from
  whichever definition the resolver chooses.  An axis this index cannot
  honour, or an architecture no indexed file belongs to, is refused rather
  than ignored, and the refusal says what the index does have: on a tree
  with no `arch` directories there is nothing to pin, and a pin accepted
  there would be a filter that silently does nothing.  Where the name has no
  definition the scope can reach, the answer says where it is defined
  instead of "not found".
- **page**: pagination (1-based); pages are 50 lines of the tool's
  rendered text output, not 50 result records.  Omit for full results.
- **since_date / until_date**: e.g., "yesterday", "2 weeks ago",
  "2024-01-15"
- **\*_patterns**: arrays of regex.  `author_patterns`, `subject_patterns`,
  `from_patterns`, `body_patterns`, `recipients_patterns`,
  `symbols_patterns`, `path_patterns` are OR'd within an array.
  `regex_patterns` and `symbol_patterns` are AND'd within an array.

**Conventions**: boolean parameters default to `false`; `limit: 0`
means unlimited, except where the tool declares an explicit max --
in that case the max wins and `limit: 0` is rejected.

## Code lookup

In the call-graph tools below (`find_callers`, `find_calls`,
`find_callchain`), both sides of a call edge include functions and
function-like macros.

**find_function**: search for functions and macros
  - name: function/macro name, or a regex
  - also displays details on callers and callees
**find_type**: search for types and typedefs
  - name: type/typedef name or regex
**find_callers**: find callers (functions or macros) of the named entity
  - name: function or macro to search
  - scope: answer about that scope's definition, e.g. `{"arch": "x86"}`
  - also reports callers that reach it through a function pointer, with the
    evidence for each: a site that names it outright, or a member it is
    installed in whose receiver has the matching type. Sites that match on
    member name alone are reported as a count, not as answers
**find_implementors**: functions installed in a struct member
  - container_type: struct or typedef name, e.g. `file_operations`
  - member: member name, e.g. `read`
  - answers "what can be called here?" for a dispatch through that member
**find_registrations**: where a function is installed as a callback
  - name: function to search
  - answers "who can reach this?", the reverse of find_implementors
**find_calls**: find callees (functions or macros) of the named entity
  - name: function or macro to search
  - scope: answer about that scope's definition, e.g. `{"arch": "x86"}`
**find_callchain**: complete call chain (forward and reverse)
  - name: function or macro to search
  - scope: start the chain at that scope's definition; every hop is then
    answered within that build
  - up_levels: number of caller levels to show (default: 2, 0 = unlimited)
  - down_levels: number of callee levels to show (default: 3, 0 = unlimited)
  - calls_limit: max calls to show per level (default: 15, 0 = unlimited)
**diff_functions**: extract functions and types from a unified diff
  - diff_content: unified diff text (e.g., output of `git diff`)
  - use this to determine which symbols are involved in a given diff

## Code search

**file_survey**: return compact Tree-sitter syntax facts for one workspace file
  - path: source path relative to the workspace
  - reports function/type definitions, calls, type mentions, and parse errors
  - omits basic scalar types such as `int`, `char`, `u8`, and `u64` from type
    mentions
  - definition tuples are `[name, count]`, where count is distinct git-aware
    callers or referrers across the indexed workspace
  - returns compact JSON without line numbers or pretty-printing
  - does not perform symbol resolution
**grep_functions**: search function/macro bodies for a regex
  - pattern: the regex to search for
  - verbose: if true, show full function bodies
  - path_pattern: optional regex to filter results by path
  - limit: max number of results (default: 100)
  - the search is already scoped to function and macro bodies; no
    need to anchor the pattern to constrain the search (regex
    metacharacters are NOT auto-escaped)
**vgrep_functions**: vector embedding search on functions/macros/types
  - query_text: text describing the kind of functions to find
  - path_pattern: optional regex to filter results by path
  - limit: max number of results (default: 10, max: 100)
  - only useful for broad concepts that a regex won't find well
  - the database might not have embeddings indexed

## Commit search

Note: commit tools use **`git_ref`** (not `git_sha` from the common
parameters) and **`symbol_patterns`** (singular; AND'd -- distinct
from lore's plural `symbols_patterns`, which is OR'd).  They do not
accept `since_date`/`until_date`; those date filters are lore-only.

Commit selection in `find_commit`: `git_ref` and `git_range` are
mutually exclusive.  `reachable_sha` is a filter that may accompany
either, or stand alone (with no `git_ref` or `git_range`) to mean
"all indexed commits reachable from this sha".

**find_commit**: search for changes, potentially in a range of commits
  - can return a large body of results; use pagination to manage context
  - git_ref: single commit ref (sha, short sha, branch, HEAD, etc.)
  - git_range: optional range for multiple commits, e.g., HEAD~10..HEAD
  - reachable_sha: optional git sha; filter to results reachable from it
  - regex_patterns (AND'd): applied against commit message + unified diff
  - symbol_patterns (AND'd): find commits changing a function or type
  - author_patterns, subject_patterns, path_patterns (each OR'd)
  - verbose: show full diff in addition to metadata
**vcommit_similar_commits**: search commits based on vector embeddings
  - query_text: search text
  - git_range: optional range, e.g., HEAD~10..HEAD
  - reachable_sha: optional git sha, reachable-from filter (combinable
    with git_range)
  - regex_patterns (AND'd), symbol_patterns (AND'd)
  - author_patterns, subject_patterns, path_patterns (each OR'd)
  - limit: max results (default 10, max 50)

## Lore (kernel mailing list archive)

Lore tools use **`symbols_patterns`** (plural; OR'd within the array --
distinct from commit tools' singular `symbol_patterns`, which is AND'd).
All `*_patterns` arrays below are OR'd within the array.

**lore_search**: search lore.kernel.org email archives
  - message_id: optional exact message ID for direct lookup
  - verbose: show full message body
  - show_thread: show full email thread for each match
  - show_replies: show replies/subthreads under each match
    (mutually exclusive with show_thread)
  - mbox: output in MBOX format with full headers and body
  - limit: max number of results (default: 100)
  - accepts: from_patterns, subject_patterns, body_patterns,
    symbols_patterns, recipients_patterns
**dig**: find lore.kernel.org emails related to a git commit
  - commit (required): git commit reference (SHA, short SHA, HEAD,
    branch name, etc.)
  - verbose: show full message body
  - show_all: show all duplicate results, not just most recent
  - show_thread: show full thread for each result (use with show_all)
  - show_replies: show replies/subthreads (use with show_all, mutually
    exclusive with show_thread)
**vlore_similar_emails**: semantic vector search over lore.kernel.org emails
  - query_text: text describing the kind of emails to find
  - limit: max number of results (default: 20, max: 100)
  - accepts: from_patterns, subject_patterns, body_patterns,
    symbols_patterns, recipients_patterns
  - the database might not have lore embeddings indexed

## Branch / status

**list_branches**: list indexed branches with indexed SHA and
  freshness (up-to-date vs. outdated against current tip).  No
  parameters.
**compare_branches**: compare two branches; shows merge base,
  ahead/behind status, and indexing status for both
  - branch1, branch2: branch names
**indexing_status**: show background indexing progress, errors,
  and timing.  No parameters.

## Lazy Loading

Start the server with `--lazy` to cut initial context ~96%.  The
server then exposes only three meta-tools (`list_categories`,
`get_tools`, `call_tool`); call them in that order to discover
and invoke full tools on demand.

## Recipes

### Locating a backported commit reachable from HEAD (or any other sha)

Repositories that heavily cherry-pick patches store the backport
under a different git sha than the upstream commit.  Search by
commit subject to find it, then narrow to commits reachable from
the branch tip with `reachable_sha`:

```
find_commit(regex_patterns=["bnxt_en: Fix memory corruption when FW resources change during ifdown"])
find_commit(regex_patterns=["bnxt_en: Fix memory corruption when FW resources change during ifdown"],
            reachable_sha="HEAD")
```
