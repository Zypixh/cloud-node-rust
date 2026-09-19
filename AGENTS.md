# AGENTS.md

Entry constraints for AI agents (Claude Code, Codex, Cursor, …) working in this
repository. Detailed engineering background:
[docs/agents/project-profile.md](docs/agents/project-profile.md).

## Project

CloudNode Rust is a high-performance CDN edge node built on
[Pingora](https://github.com/cloudflare/pingora): L7/L4 proxying, hybrid cache, WAF,
dynamic certificates, logging and statistics, local observability, and an XDP/AF_XDP
bypass dataplane on Linux. See [README.md](README.md) for the full introduction and
[docs/README.md](docs/README.md) for the documentation index.

The production target is Linux; local development often happens on macOS. Platform
differences must be handled explicitly — never assume the two are equivalent.

## Hard constraints

### 1. No functional degradation without explicit approval

Do not silently degrade anything to make a test, request, or task "succeed": disabling a
feature or protocol path, rewriting errors into cache misses / origin fallback / empty
results / dropped events / best-effort success, swallowing errors or ignoring failed
return values, weakening validation, shortening timeouts, reducing retries, or masking a
root cause behind a catch block or a default value.

When you find existing degradation, report its trigger conditions, impact, and evidence
first — do not extend the pattern. A fail-closed rejection required by a security policy
is not degradation, but it must still leave observable logs, metrics, or error state.

Any degradation requires explicit user approval of the specific plan before it is
implemented, and that approval covers only the scope it describes.

Full rule and approval requirements:
[docs/agents/no-unapproved-degradation.md](docs/agents/no-unapproved-degradation.md).

### 2. Do not modify vendored or upstream code

`pingora-main/`, `toa-main/`, `toa-sender/`, and `vendor/` are vendored checkouts or
controlled forks. Unless a task explicitly targets them, changes belong in `src/` and
`crates/`. `vendor/smoltcp-edge/` is a controlled fork of smoltcp 0.14.0 whose every
divergence is recorded in `vendor/smoltcp-edge/DIVERGENCE.md` — read that before changing
anything there.

### 3. Config compatibility is deliberate, not dead code

Unknown legacy keys, nullable fields, lenient numeric/string input, and serde camelCase
serialization names may all be relied on by live configuration. Do not "clean up" config
fields that merely look unused. Hot reload must preserve snapshot atomicity — no
partially applied intermediate state.

### 4. Keep hot paths allocation-aware

On the request path, watch for per-request `String`/`Vec`, `format!`, `Regex::new`, deep
`clone`, blocking I/O, and coarse-grained locks. Performance claims must be backed by data
from the matching bench under `benches/`, never asserted from intuition.

### 5. Keep repository constraints separate from personal preferences

This file holds only repository-level constraints that apply to **every** collaborator.
Personal machine and tooling habits — local disk headroom, whether a full local build is
acceptable, editor and shell configuration — are individual working style and do not
belong here or in committed documentation.

### 6. Commit and PR conventions

Author and committer must be the owner's identity only (`Zypixh <moying8259@gmail.com>`).
Commit messages must contain **no third-party attribution**: `Co-Authored-By` trailers
naming anyone else, `Generated with …` generator lines, tool or bot identities, or `🤖`
markers.

This repository has already been polluted by exactly that: Devin injected attribution
trailers on 88 commits and Cursor set itself as author on 39, all of it pushed to `main`.
History is not rewritten; the ban applies to future commits only.
**A branch name may carry a tool name; a commit signature may not.**

Use `<scope>: <summary>` for the subject, and make the body state root cause, behavior
change, and measured data rather than restating the diff. Fill PRs from
`.github/pull_request_template.md`; the four-part results report is mandatory.

The local hook and CI share `scripts/git-hooks/check-attribution.sh`. Install it with:

```bash
git config core.hooksPath scripts/git-hooks
```

Full rules, scope vocabulary, and known gaps:
[docs/agents/commit-and-pr-conventions.md](docs/agents/commit-and-pr-conventions.md).

## Build and verification

The toolchain is pinned to **1.98.1** by `rust-toolchain.toml`, edition 2024.
`configs/`, `data/`, `api_node.yaml`, and `runtime/` are not version-controlled — do not
assume they exist.

| Purpose | Command |
| --- | --- |
| Everyday changes | `cargo check --all-targets` |
| Unit tests | `cargo test --lib --bins` |
| Integration tests | `cargo test --no-fail-fast --test '*'` |
| Lint (CI gate) | `cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious` |
| Vendored pingora | `cargo check --manifest-path pingora-main/Cargo.toml -p pingora-core -p pingora-http -p pingora-cache -p pingora-proxy --all-targets` |
| Project tooling | `cargo xtask <subcommand>` |

**Local and CI use different CPU baselines.** `.cargo/config.toml` sets
`rustflags = ["-C", "target-cpu=native"]`, while CI overrides it with
`RUSTFLAGS="-C target-cpu=x86-64-v2"` (rationale in the header comment of
`.github/workflows/ci.yml`; this has caused a proc-macro SIGILL in the past). A passing
local build does not imply a passing CI build — verify against the CI baseline whenever
build configuration or dependencies change.

## How to work

- Read nearby code before changing anything, and match the repository's existing error
  handling, tracing, locking, and async style.
- Do not silence compiler errors with broad `.clone()`, `Arc<Mutex<_>>`, `Box<dyn Trait>`,
  `'static`, or `unwrap()` unless that matches the domain and its cost model.
- Treat ownership problems as API design problems, and async problems as scheduling and
  cancellation problems.
- Final reports must separate: problems fixed, problems remaining, design limitations,
  and any approved degradation.
