# Index result reports

`semcode-index --result-json PATH` writes a JSON report of what a branch
indexing run did, for scripts that keep an index current and need to know
which branches to retry.

```bash
semcode-index -s . --branches main,dev --update-branches --result-json /tmp/result.json
```

The flag works with `--branch`, `--branches` and `--all-branches`, and with
the options that modify them (`--update-branches`, `--remote-branches`,
`--clear`, `--extensions`, `--include`, `--no-macros`, `-j`,
`--db-threads`). It is rejected without a branch flag and together with
`--lore`, `--git`, `--commits` or `--vectors`.

## Format (version 1)

```json
{
  "version": 1,
  "branches": [
    { "name": "main", "outcome": "indexed", "commit": "89abcdef…" },
    { "name": "dev",  "outcome": "current", "commit": "fedc3210…" },
    { "name": "wip",  "outcome": "failed",  "commit": "00112233…", "error": "…" },
    { "name": "nope", "outcome": "failed",  "commit": null, "error": "Branch 'nope' does not exist: …" }
  ]
}
```

- `version`: always `1` for this format.
- `branches`: one entry per distinct requested name, in request order.
  With `--all-branches`, branches not named explicitly follow in the order
  git lists them. An empty inventory gives `[]`.
- `name`: the branch name as requested or as listed.
- `outcome`:
  - `indexed`: the branch was indexed and the database now records the
    commit its ref resolved to when the run started.
  - `current`: `--update-branches` skipped the branch because the database
    already records that commit. An index written by an older semcode is
    read again in full, so it never reports `current`.
  - `failed`: anything else.
- `commit`: the full commit ID the database records for this branch after
  the run, which is what queries see. For a failed update it is the tip
  from the last successful run. `null` if the database has no tip for the
  name or it could not be read.
- `error`: a human-readable message, present only when `outcome` is
  `failed`. Its wording is not part of the format.

## Exit status and the report file

- The exit status is 0 only if every branch is `indexed` or `current` and
  the report was written.
- A failed branch does not stop the others. A failing run may have
  committed some work; running the same command again is safe and skips
  what is already current.
- Some problems refuse the whole run before any branch is indexed:
  `--clear` together with a branch name that does not resolve, and
  `--extensions` or `--no-macros` naming options the recorded build does
  not hold while a requested branch is already indexed.
- Any existing file at `PATH` is removed when the run starts, and the run
  fails at once if `PATH` cannot become a file (a missing directory, a
  directory at `PATH`, a trailing `/`). A symlink at `PATH` is replaced,
  not followed.
- The new report is written once, after the last branch, to a temporary
  file in the same directory that is then renamed into place. It gets
  ordinary file permissions under the umask.
- No file at `PATH` after the run means the run did not finish: it was
  refused or failed before producing outcomes (an unusable path, a
  rejected flag combination, a database that would not open), or it was
  killed or crashed partway, possibly after indexing some branches. The
  reason is on stderr.
- A relative `PATH` is relative to the working directory.

## Compatibility

Within version 1, new optional fields may be added; readers should ignore
fields they do not know. Removing or renaming a field, changing what one
means, or adding an `outcome` value requires a new version. Other indexing
modes may later report their own top-level lists next to `branches`.
