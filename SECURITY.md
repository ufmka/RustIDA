# Security Policy

## Supported versions

RustIDA is in early development (0.1.x). Security fixes are applied to the
`master` branch. There are no long-term support branches yet.

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability.

Report privately via GitHub Security Advisories ("Report a vulnerability" on
the repository's Security tab), or contact the maintainer directly. Include:

- a description of the issue and its impact;
- a minimal reproduction (input file, command, platform);
- the RustIDA version or commit;
- any suggested mitigation.

We aim to acknowledge a report within 5 working days and to provide a fix or
mitigation plan within 30 days. Please give us a reasonable period to fix the
issue before public disclosure.

## Handling secrets

- `key.txt` is a local, Git-ignored file. It must never be committed.
- API keys and tokens belong in environment variables or a local secret store,
  not in source code, tests, fixtures or CI configuration.
- CI must not print secret values. Use `env:` with GitHub secrets and avoid
  `set -x` around commands that consume them.
- If a secret is committed, rotate it first, then remove it from history. Do
  not rely on deletion alone.

## Dependencies

- Only dependencies with a permissive license (MIT, Apache-2.0, BSD, zlib or
  similar) are allowed in `rustida-core` and other libraries.
- `cargo deny` is used in CI to check licenses and known advisories.
- A new dependency requires a short justification in the pull request: what it
  provides, why the alternatives are worse, and which license it uses.

## Fixtures and test data

Do not commit proprietary binaries, IDA Pro databases or other restricted
material. Test binaries must be generated from source or come from an openly
licensed corpus, with provenance documented in `tests/fixtures/README.md`.