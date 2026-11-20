# Licensing options for RustIDA

RustIDA is intended to be an independent, open-source project. The license
must be chosen by the project owner. This document compares the realistic
options; it does **not** choose one.

## Option A — MIT

- Short, permissive, widely understood.
- Allows proprietary reuse; only requires attribution and the warranty
  disclaimer.
- Simple to combine with MIT/BSD/Apache-2.0 dependencies.
- Weak protection against a closed-source fork.

## Option B — Apache-2.0

- Permissive, with an explicit patent grant and patent termination clause.
- Requires attribution and a NOTICE file when applicable.
- Compatible with MIT/BSD dependencies; incompatible with GPL-2.0-only code.
- More text and more compliance work than MIT.

## Option C — MIT OR Apache-2.0 (dual)

- Common in the Rust ecosystem.
- Gives downstream users a choice.
- Same patent and attribution considerations as Apache-2.0.
- Recommended default for a new Rust tool that wants broad adoption.

## Option D — GPL-3.0

- Strong copyleft: derivative works must remain GPL-3.0.
- Discourages proprietary reuse and closed forks.
- Incompatible with permissive-only dependencies in some combinations.
- A poor fit for a plugin ecosystem that may include proprietary plugins.

## Recommendation

For RustIDA, **MIT OR Apache-2.0** is the most practical default: it matches
the Rust ecosystem, keeps dependencies permissive, and allows both open and
commercial plugins. MIT alone is simpler if the owner wants minimal legal
overhead. GPL-3.0 should be chosen only if the owner explicitly wants
copyleft.

## Before choosing

- Confirm the project owner's intent.
- Check that all dependencies allow the chosen license.
- Add a `LICENSE` file and, if Apache-2.0 is chosen, a `NOTICE` file.
- Record the decision in `docs/adr/0008-license.md`.

No `LICENSE` file is added until the owner decides.