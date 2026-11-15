# AGENTS.md — Engineering, Co-Maintainer & AI Contributor Guidelines

Welcome to the **TotalDrop** multi-repository ecosystem (`https://github.com/totaldrop-app`).
Every human engineer and AI coding agent working in this repository MUST follow
these rules without exception:

1. **Co-Maintainers & Mandatory Mutual Review (`GOVERNANCE.md`):**
   - The two Core Maintainers of TotalDrop are **Ozan (`@ozdil`)** and **Sadık (`@sadikkuzu`)**.
   - **NEVER push directly to `main`.** Direct pushes, force-pushes, and self-merges
     are forbidden (`main` and `main review` repository rulesets enforce linear
     rebase merges with zero bypass actors).
   - Every change (code, CI workflows, packaging recipes, localization, security
     policy, or documentation) MUST start from an English GitHub Issue, run on a
     short-lived topic branch (`feat/...`, `fix/...`, `pkg/...`, `gov/...`), open an
     English Pull Request requesting the co-maintainer (`--reviewer sadikkuzu` when
     authored under `@ozdil`, and `--reviewer ozdil` when authored under `@sadikkuzu`),
     pass the required `CI` status check (`100% GREEN`), and **obtain the other
     maintainer's explicit `APPROVED` review before rebase-merging**.

2. **100% English on GitHub (`ADR 0019`):**
   - Write all code, comments, docstrings, commit messages, branch names, pull
     requests, issues, review comments, CI workflows, and documentation in
     **English**.
   - Never introduce non-English filenames or governance documents inside any
     repository (user-facing 35-language translations under `l10n/`, `public/i18n/`,
     `privacy/`, and `docs/readme/` are the sole intentional localization files).

3. **Security & Architecture Invariants:**
   - All cryptography, PAKE (`CPace`), post-quantum hybrid handshakes
     (`Noise XXpsk3` + `ML-KEM-768`), Ghost Ring primitives (`Ed25519 + ML-DSA-65`,
     `X-Wing`), and wire parsers live strictly in Rust (`totaldrop-crypto`,
     `totaldrop-proto`, `totaldrop-core`) with `unsafe_code = "forbid"`.
   - Native UI layers (`Qt 6`, `Flutter`, `WinUI 3`, `SwiftUI`, `Web DOM`) NEVER
     implement cryptography or bypass path-confinement / sanitization helpers.
   - Untrusted strings (filenames, peer labels, errors) must be sanitized against
     control and Bidi characters before terminal or UI rendering.
   - Every new wire/manifest/IPC parser requires unit tests for specific error
     variants and a `cargo-fuzz` harness in `totaldrop-formal-fuzz`.

4. **Sub-Platform × CPU Isolation (`ADR 0020`):**
   - Keep every `subplatforms/<format>/<arch>/` recipe reproducible
     (`SOURCE_DATE_EPOCH`), isolated from sibling formats/architectures, and
     verified via Sigstore build provenance + `SHA256SUMS`.

5. **35-Language Parity (`ADR 0008`):**
   - `totaldrop-core/l10n/` is the Single Source of Truth for all 35 languages
     (including RTL `ar`, `fa`, `he`, `ur`). Never hardcode user-visible UI
     strings or weaken `l10n/status.json` critical security string gates.

6. **Quality Gates Before Every Commit:**
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --locked -- -D warnings`
   - `cargo test --workspace --locked`
   - `./tools/check-spdx.sh` (every new `.rs`, `.ts`, `.js`, `.mjs`, `.sh`,
     `.py`, `.css` file must include `SPDX-FileCopyrightText` and
     `SPDX-License-Identifier` in its top 6 lines).
   - Never commit signing keys, tokens, or `.gitleaksignore`, and never probe or
     load-test live production endpoints (`totaldrop.app`, `rendezvous.totaldrop.app`,
     `relay.totaldrop.app`) outside approved deployment health probes.
