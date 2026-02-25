# AST Verifier Agent Guide

Use this file for work under `ast_verifier/` together with the repository-level `AGENTS.md`.

## Core Metadata

| Attribute | Value |
|-----------|--------|
| **Name** | AST Verifier |
| **Purpose** | Encodes AST invariants and validates that parser/lowering output remains structurally correct. |
| **Primary Language** | C++ |

## Responsibilities

- Define and enforce AST integrity checks.
- Catch invalid AST states before code generation.
- Guard lowering output with explicit verifier rules.

## Hard Rules

- Never disable existing AST verifier checks in a patch.
- If new AST node kinds are introduced, add verifier checks for them.
- If a lowering creates new structural patterns, add verifier checks for those patterns.
- If a parser/lowering bug produced invalid AST that passed verification, extend AST verifier accordingly.
- Treat temporarily disabled checks as still normative for new code; do not add patches that rely on bypassing invariants.

## Running

- In debug builds, AST verifier runs after lowering and before code generation.
- Useful options:
  - `--ast-verifier:phases=each`
  - `--ast-verifier:full-program`
  - `--ast-verifier:errors=...`
  - `--ast-verifier:warnings=...`

## References

- Component README: `ast_verifier/README.md`
- Repository policy: `AGENTS.md`
