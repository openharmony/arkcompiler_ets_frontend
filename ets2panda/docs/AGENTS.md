# Documentation Agent Guide

Use this file for work under `docs/` together with the repository-level `AGENTS.md`.

## Core Metadata

| Attribute | Value |
|-----------|--------|
| **Name** | Documentation |
| **Purpose** | Contributor-facing docs for frontend architecture, rules, workflows, and onboarding. |
| **Primary Language** | Markdown |

## Scope

- Keep docs aligned with current specification-first policy.
- Keep commands, paths, and options accurate for the current tree/build flow.
- Use concise, actionable guidance with runnable command examples.
- Keep docs aligned with the latest technical preview release feed: <https://gitcode.com/igelhaus/arkcompiler_runtime_core/releases/>.

## Rules

- Do not document behavior that is not in the latest technical preview spec.
- When implementation and spec diverge, call out the mismatch explicitly.
- Do not remove hard review constraints from docs (tests required, no assertion removal, no speculative features).
- Prefer repository-relative paths in links.

## When Updating Docs

- Update `docs/README.md` when adding or renaming major docs.
- Keep onboarding guidance consistent with root `AGENTS.md`.
- Keep root `AGENTS.md`, component `AGENTS.md`, and `docs/frontend-onboarding.md` consistent on hard rules.
- If a change modifies component process/rules, update the closest component `AGENTS.md` in the same patch.
