# Index result reports

`semcode-index --result-json PATH` writes a JSON report of what a branch
or lore indexing run did, for scripts that keep an index current and need
to know which branches or archives to retry.

```bash
semcode-index -s . --branches main,dev --update-branches --result-json /tmp/result.json
```

The flag works with `--branch`, `--branches` and `--all-branches`, and with
the options that modify them (`--update-branches`, `--remote-branches`,
`--clear`, `--extensions`, `--include`, `--no-macros`, `-j`,
`--db-threads`), and with `--lore` (see [Lore archives](#lore-archives)).
It is rejected without a branch flag or `--lore`, together with `--git`,
`--commits` or `--vectors`, and when `--lore` and branch flags are mixed.

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

## Lore archives

```bash
semcode-index --lore bpf,netdev --result-json /tmp/result.json   # clone or update these
semcode-index --lore --result-json /tmp/result.json              # refresh every archive
```

```json
{
  "version": 1,
  "archives": [
    { "name": "bpf",    "outcome": "indexed" },
    { "name": "netdev", "outcome": "failed", "error": "…" }
  ]
}
```

- `archives`: one entry per archive the run handled, in place of
  `branches`. With a list, one entry per distinct entry, in request
  order. Without one (refresh), in no particular order. A refresh with
  no archives gives `[]`.
- `name`: with a list, the entry as given (a list name or a URL).
  On refresh, the archive's path under `<db>/lore/`, such as `bpf/0`.
  Credentials in a URL are removed here and in `error`:
  `https://user:token@host/x` is reported as `https://host/x`.
- `outcome`:
  - `indexed`: the archive had commits not yet indexed, and all of them
    are now indexed.
  - `current`: every commit of the archive was already indexed.
  - `failed`: anything else, such as a failed clone, fetch, or a
    partly indexed archive. Indexing again retries what is missing.
- `error`: as for branches.

The exit status is 0 only if every archive is `indexed` or `current` and
the report was written. The rules for the report file above apply
unchanged.

## Compatibility

Within version 1, new optional fields may be added; readers should ignore
fields they do not know. Removing or renaming a field, changing what one
means, or adding an `outcome` value requires a new version. Other indexing
modes may later report their own top-level lists next to `branches`.
