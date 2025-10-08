# Reviewing kernel code with Claude and semcode

One of the primary use cases for semcode is giving Claude more information
about the codebase. With the MCP server, Semcode allows agents to quickly find
context about functions, call graphs, and types, which speeds up the review and
reduces the tokens spent on grepping through kernel sources.

## Claude and semcode initial setup

Follow the instructions in claude-semcode-setup.md before trying the rest
of this guide.

## Patch review prompts

This example will assume you've cloned review-prompts:

https://github.com/masoncl/review-prompts/

There's nothing special about these prompts, but they already have lines using
the semcode MCP server.


## Indexing your kernel repository

semcode indexes individual git shas, and you'll want to index every sha that
you plan on reviewing.  The most basic way to do this:

```
cd linux
git checkout <sha you want to review>
semcode-index -s .
```

If you're reviewing a series of patches:

```
cd linux
git checkout v6.16

# do the initial index
semcode-index -s .

<apply the patches>

# do the incremental index
semcode-index -s . --git v6.16..HEAD
```

If the semcode index already existed, it'll just process the git shas that
are missing from the database.

## Reviewing code

Let's assume you have the review-prompts git repo in /src/review-prompts.
Claude expects full path names for things and is most reliable when you give
it fully resolved paths.

```
cd linux
claude --mcp-config mcp-config.json
claude> Using prompt /src/review-prompts/review-core.md, review the top commit
```

You can also:

```
claude --mcp-config mcp-config.json -p "Using prompt /src/review-prompts/review-core.md, review the top commit" 
```

But you'll need to make sure you have permissions configured so that Claude
doesn't need to ask you for access to the semcode tools.

When using -p, Claude's output is much less verbose, which can make it hard
to debug the prompts, but you can fix that by using stream-json output:

```
claude --verbose --verbose --output-format=stream-json
```

scripts/claude-json.py can be used to convert this into markdown

With the AI patch review prompts, when Claude finds a regression, it puts
it into ./review-inline.txt

## Reviewing the review

Once Claude has found regressions, it's a good idea to ask it questions
about the review and make sure everything is correct. It's usually obvious
when it's making assumptions, and you can dive into them individually to make
sure they are correct.

