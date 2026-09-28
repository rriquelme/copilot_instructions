---
name: slim-instructions
description: Reduce per-turn token cost of a repository's Copilot instruction files by splitting them into a small always-on core plus lazily loaded skills and path-scoped instructions. Use when asked to slim, split, tier, or reduce the context cost of copilot-instructions.md, AGENTS.md, CLAUDE.md, or .github/instructions in the current repo. Repo-only; never edits files under the home directory.
---

# slim-instructions

Goal: the current repo's instruction files cost as few tokens per turn as
possible, with no rule lost and no behavior changed. Only the loading tier
of each rule changes.

## Loading tiers (why this works)

| Tier | Location | In context |
|---|---|---|
| Core | `.github/copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md` | Every turn, full text |
| Skill | `.github/skills/<name>/SKILL.md` | Name + description every turn; body only when invoked |
| Path-scoped | `.github/instructions/<name>.instructions.md` with `applyTo` | Only when a matching file is in play |

Moving a rule from Core to Skill saves its full token cost on every turn
where it is not needed. The risk is a rule that never gets loaded when it
should. The core keeps one pointer line per skill to close that gap.

## Hard boundaries

- Read and write only inside the repo root of the current working directory.
  If no repo root is found (no `.git`, no `.github`, no `AGENTS.md`), stop
  and say so.
- Never write, move, or delete anything under `$HOME`. `~/.copilot`,
  `~/.agents`, `~/.claude` are read-only inputs at most.
- Never delete an original. Originals move to
  `.github/instructions-archive/<YYYY-MM-DD>/` with their relative path.
- Never write before the plan is approved. Steps 1 to 3 produce a plan and
  stop. Step 4 runs only after an explicit "approved", "go", or "apply".
- Do not touch source code, README files, or anything outside the
  instruction files listed in step 1.

## Step 1. Inventory

Run `scripts/inventory.sh` from the repo root. It lists every instruction
file with line, word, and estimated token counts, and whether it is core,
skill, or path-scoped today.

Files it looks for:

- `.github/copilot-instructions.md`
- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` at the root
- `.github/instructions/**/*.instructions.md`
- `.github/skills/*/SKILL.md`, `.claude/skills/*/SKILL.md`, `.agents/skills/*/SKILL.md`

Also read, without ever writing: `~/.copilot/copilot-instructions.md` and
`~/.copilot/skills/*/SKILL.md` if they exist. Any rule in the repo that
duplicates one of those is classified `dup-global` and dropped from the
repo, because the global copy is already in every turn.

## Step 2. Classify every rule

Read each core file top to bottom. Split it into rules: a heading with its
body, or a bullet, or a worked example. Classify each one:

**core** — must be in context before the first tool call of any task,
because it changes what the agent does on turn one. Examples: how to
classify a message, what never to do without asking, git bans, reply
ending rules. A core rule that is currently long gets compressed to its
operative sentences; its explanation and examples move to a skill.

**skill:<name>** — only matters for one task shape and can be loaded when
that task starts. Examples: how to format an explanation of a repo, flow
notation, how to lay out a failure report, documentation policy details,
review style. Group by task shape, not by original section. Name the skill
by the task: `explain-code`, `report-failure`, `docs-policy`, `review-style`.

**path:<glob>** — applies only to certain file types or directories.
Examples: language conventions, test layout, framework rules.

**dup-global** — same rule already in `~/.copilot/copilot-instructions.md`
or a personal skill. Drop from repo.

**drop** — exact duplicate of another rule in the same repo, or a rule with
no operative content (headings with nothing under them, transitions).

Worked examples follow the rule they illustrate. An example for a core rule
stays in core only if it is under six lines and the rule has been observed
to fail without it; otherwise it goes to the skill that owns that topic.

## Step 3. Plan and stop

Print:

1. A table: rule (first line, truncated), current file, proposed tier,
   reason (one clause).
2. The proposed core file in full, so it can be judged as a whole.
3. For each proposed skill: its `description` line (this is the only part
   that costs tokens every turn, so it must be short and specific about
   when to load) and a one-line list of what moves into it.
4. Token estimate before and after for the always-on tier.
5. The exact pointer lines the core will carry, one per skill, in the form
   "When <task shape>, load the <name> skill."

Then stop. Do not write anything.

## Step 4. Apply (only after approval)

1. Create `.github/instructions-archive/<date>/` and move each original
   there, preserving relative paths.
2. Write the new core file.
3. Write each `.github/skills/<name>/SKILL.md` with frontmatter `name` and
   `description` exactly as approved, body from the classified rules,
   unchanged wording where possible.
4. Write each `.github/instructions/<name>.instructions.md` with
   `applyTo` frontmatter.
5. Re-run `scripts/inventory.sh` and print before/after.

## Step 5. Verification list

Print three to five test prompts, one per skill or moved rule, each with
the expected pass behavior in one line. Suggest running `/context` in a
fresh session before and after to see the system-tokens difference.

## Compression rules for the core

- One rule per bullet, operative verb first. No rationale in core; rationale
  lives in the skill.
- No worked examples over six lines.
- No calibration samples.
- Keep exact phrasings that were observed to matter (banned phrases, fixed
  headings like "Noticed, not changed"). Those are cheap and load-bearing.
- Target: under 100 lines, under 1,500 estimated tokens.
