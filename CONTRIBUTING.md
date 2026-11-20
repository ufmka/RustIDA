# Contributing to RustIDA

RustIDA is an independent, open-source reverse-engineering tool written in Rust.
This document describes how to work on the project.

## Principles

1. **Correctness before features.** Do not merge a feature that hides bugs or
   panics on malformed input.
2. **No destructive changes.** Do not delete or rewrite working code without a
   documented reason. Prefer additive changes and ADRs.
3. **Clean room.** Never copy source code, resources, algorithms or assets from
   IDA Pro or any other proprietary product. Public specifications and open
   projects are valid references; their code is not.
4. **One owner per file.** Before editing, check `docs/architecture.md` for the
   crate owner. Do not edit a file another agent is editing.
5. **Tested work is done work.** A change without a test is a proposal, not a
   contribution.

## Development setup

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

On some distributions (for example Void Linux) the `cargo fmt` and
`cargo clippy` aliases may not resolve even though the components are installed.
Use the direct binaries in that case:

```bash
/usr/bin/cargo-fmt --all -- --check
/usr/bin/cargo-clippy --workspace --all-targets -- -D warnings
```

## Crate boundaries

- `rustida-core` owns fundamental types and traits. It must not depend on
  loaders, disassemblers, UI or platform-specific code.
- `rustida-loader` parses container formats and produces a normalized
  `Binary`. It must not perform analysis.
- `rustida-project` owns persistence and the project manifest. It must not
  parse executable formats.
- The `rustida` binary is the composition root. It wires crates together and
  provides the CLI.

New crates are added only when they have real code and tests. Empty placeholder
crates are not accepted.

## Tests

- Unit tests live next to the code (`#[cfg(test)]`).
- Integration tests live in each crate's `tests/` directory.
- Workspace-level integration tests live in `tests/`.
- Fixtures are generated locally or committed under `tests/fixtures/` with a
  note explaining their provenance and license.
- Never commit proprietary binaries or IDA Pro data.

Every bug fix must include a regression test that fails before the fix.

## Commits

Use short, imperative subject lines:

```
core: add Address newtype with checked arithmetic
loader: reject ELF files with out-of-bounds program headers
ci: run clippy on all three platforms
```

Reference issues in the body, not in the subject.

## ADRs

Significant architectural changes require an ADR in `docs/adr/`. Copy
`docs/adr/0000-template.md`, fill in the sections and open a pull request.
Do not change an accepted ADR; add a new one that supersedes it.

## Security

Do not commit secrets, API keys, tokens or local credentials. `key.txt` is
ignored by Git and must stay local. See `SECURITY.md`.