# Skill Registry

**Delegator use only.** Any agent that launches sub-agents reads this registry to resolve compact rules, then injects them directly into sub-agent prompts. Sub-agents do NOT read this registry or individual SKILL.md files.

See `_shared/skill-resolver.md` for the full resolution protocol.

## User Skills

| Trigger | Skill | Path |
|---------|-------|------|
| Creating a pull request, opening a PR, or preparing changes for review | branch-pr | ~/.claude/skills/branch-pr/SKILL.md |
| Writing Go tests, using teatest, or adding test coverage | go-testing | ~/.claude/skills/go-testing/SKILL.md |
| Creating a GitHub issue, reporting a bug, or requesting a feature | issue-creation | ~/.claude/skills/issue-creation/SKILL.md |
| User says "judgment day", "judgment-day", "review adversarial", "dual review", "doble review", "juzgar", "que lo juzguen" | judgment-day | ~/.claude/skills/judgment-day/SKILL.md |
| Creating a new skill, adding agent instructions, or documenting patterns for AI | skill-creator | ~/.claude/skills/skill-creator/SKILL.md |

## Compact Rules

Pre-digested rules per skill. Delegators copy matching blocks into sub-agent prompts as `## Project Standards (auto-resolved)`.

### branch-pr
- Every PR MUST link an approved issue — `Closes #N`, `Fixes #N`, or `Resolves #N` in the body; blank PRs are blocked by CI
- Linked issue MUST have `status:approved` label before opening any PR
- Every PR MUST have exactly one `type:*` label — pick from: `type:feature`, `type:bug`, `type:docs`, `type:refactor`, `type:chore`, `type:breaking-change`
- Branch naming: `type/description` — lowercase, only `a-z0-9._-` in description part
- Valid branch types: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `revert`
- Commits MUST follow conventional format: `type(scope): description` — no `Co-Authored-By` trailers
- Run `shellcheck scripts/*.sh` on any modified shell scripts before opening PR
- PR body MUST include: linked issue, type checkbox, 1-3 bullet summary, changes table, test plan, contributor checklist
- All automated checks (issue reference, approved label, type label, shellcheck) must pass before merge

### go-testing
- Only applies to `.go` files — skip entirely for Python/Django projects
- Table-driven tests are the standard pattern: define `[]struct{ name, input, expected, wantErr }`, iterate with `t.Run`
- Use `teatest.NewTestModel` for full Bubbletea TUI flow testing; test `Model.Update()` directly for state transitions
- Golden file tests: store expected output in `testdata/*.golden`; use `-update` flag to regenerate
- Mock `os/exec` via interface + mock; use `t.TempDir()` for file operations in tests
- Skip long integration tests with `testing.Short()` checks
- Test both success and error paths for every function that returns an error

### issue-creation
- Blank issues are disabled — MUST use the bug report or feature request template
- Every new issue automatically gets `status:needs-review`; maintainer must add `status:approved` before any PR can reference it
- Search for duplicate issues before creating a new one
- Questions and help requests go to Discussions, NOT issues
- Fill ALL required template fields; check ALL pre-flight checkboxes
- Bug reports require: description, reproduction steps, expected vs actual behavior, OS, agent/client, shell

### judgment-day
- Launch exactly TWO judge sub-agents in parallel (async) — never sequential, never just one
- Neither judge knows the other exists — send identical target scope, zero cross-contamination
- Orchestrator synthesizes verdicts: CRITICAL blocks merge, WARNING should be fixed, SUGGESTION is optional
- Fix agent applies CRITICAL + WARNING only; surface SUGGESTION items to the user
- Re-judge after fixes; escalate to user if not resolved after 2 iterations
- Inject `## Project Standards (auto-resolved)` with matching compact rules into BOTH judge prompts AND the fix agent prompt
- If no skill registry exists, warn user before starting: "Judges will review without project-specific standards"

### skill-creator
- Frontmatter is mandatory: `name`, `description` (must include `Trigger:` keyword), `license: Apache-2.0`, `metadata.author`, `metadata.version`
- Skill directory: `~/.claude/skills/{skill-name}/SKILL.md` (user-level) or `.claude/skills/{skill-name}/SKILL.md` (project-level)
- Project-level skills override user-level skills with the same name
- `description` field MUST include `Trigger:` text — this is how the registry auto-detects when to apply the skill
- Use `assets/` for templates, schemas, example configs; use `references/` for local doc paths only (no web URLs)
- Compact Rules section is REQUIRED — 5-15 lines, actionable only, no motivation or full examples
- After creating, run `skill-registry` to update `.atl/skill-registry.md`
- Add skill entry to `AGENTS.md` if the project uses one

## Project Conventions

| File | Path | Notes |
|------|------|-------|
| Global CLAUDE.md | ~/.claude/CLAUDE.md | User-level conventions: language (Rioplatense voseo), tone, commit style (no Co-Authored-By), never build after changes, response length contract |

Read the convention files listed above for project-specific patterns and rules. All referenced paths have been extracted — no need to read index files to discover more.
