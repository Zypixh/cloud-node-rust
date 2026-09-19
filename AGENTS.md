# AGENTS.md

Constraints for AI agents (Claude Code, Codex, Cursor, …) working in this repository.
Only repository-level rules live here — personal machine or tooling habits (local disk
headroom, whether a full local build is acceptable, editor and shell config) do not.
Rationale, history, and procedures live in [docs/agents/](docs/agents/), and engineering
background (module map, dependencies, priorities, search patterns) in
[project-profile.md](docs/agents/project-profile.md).

## Project

CloudNode Rust is a high-performance CDN edge node built on
[Pingora](https://github.com/cloudflare/pingora): L7/L4 proxying, hybrid cache, WAF,
dynamic certificates, logging and statistics, local observability, and an XDP/AF_XDP
bypass dataplane on Linux. See [README.md](README.md) and [docs/README.md](docs/README.md).

Production targets Linux while local development often happens on macOS. Handle platform
differences explicitly — never assume the two are equivalent.

## Hard constraints

### 1. No functional degradation without explicit approval

Never silently degrade anything to make a test, request, or task "succeed": disabling a
feature or protocol path; rewriting errors into cache misses, origin fallback, empty
results, dropped events, or best-effort success; swallowing errors or ignoring failed
return values; weakening validation; shortening timeouts; reducing retries; masking a root
cause behind a catch block or a default value.

Report existing degradation (trigger, impact, evidence) instead of extending it. A
fail-closed rejection required by a security policy is not degradation, but it must still
leave observable logs, metrics, or error state. Degradation needs approval of the specific
plan first, covering only the scope it describes.
→ [no-unapproved-degradation.md](docs/agents/no-unapproved-degradation.md)

### 2. Never modify vendored or upstream code

`pingora-main/`, `toa-main/`, `toa-sender/`, `vendor/`. Changes belong in `src/` and
`crates/` unless a task explicitly targets them. `vendor/smoltcp-edge/` is a controlled
fork of smoltcp 0.14.0 — read `vendor/smoltcp-edge/DIVERGENCE.md` before touching it.

### 3. Config compatibility is deliberate, not dead code

Unknown legacy keys, nullable fields, lenient numeric/string input, and serde camelCase
names may all be load-bearing for live configuration. Never "clean up" fields that merely
look unused. Hot reload must preserve snapshot atomicity — no partially applied state.

### 4. Hot paths stay allocation-aware

On the request path, watch for per-request `String`/`Vec`, `format!`, `Regex::new`, deep
`clone`, blocking I/O, and coarse-grained locks. Performance claims need data from the
matching bench under `benches/`, never intuition.

### 5. Eliminate warnings, never suppress them

Do not add `#[allow(...)]`, `#![allow(...)]`, `#[cfg_attr(..., allow(...))]`, `--cap-lints`,
`RUSTFLAGS="-A warnings"`, `-A <lint>`, or `= "allow"` in a `[lints.*]` table. Fix the root
cause; for platform or feature conditionals put `#[cfg(...)]` on the item, not on the lint.
`#[expect(lint, reason = "…")]` is the sanctioned form — it errors once the lint stops
firing. Otherwise record an approved exception in the commit message:
`Warning-Suppression-Approved: <why the root cause cannot be eliminated>`.
78 pre-existing sites are not retroactively rewritten, but clear them when you touch a file.
→ [warning-and-lint-policy.md](docs/agents/warning-and-lint-policy.md)

### 6. Commits are attributed to the owner only

Author and committer: `Zypixh <moying8259@gmail.com>`. No `Co-Authored-By` naming anyone
else, no `Generated with …` lines, no tool or bot identities, no `🤖`. A branch name may
carry a tool name; a commit signature may not. History is not rewritten — the ban is
forward-only.

Subject is `<scope>: <summary>`; the body states root cause, behavior change, and measured
data rather than restating the diff. Fill PRs from `.github/pull_request_template.md` — the
four-part results report is mandatory. Local hook:
`git config core.hooksPath scripts/git-hooks`.
→ [commit-and-pr-conventions.md](docs/agents/commit-and-pr-conventions.md)

## Build and verification

Toolchain pinned to **1.98.1** by `rust-toolchain.toml`, edition 2024.
`configs/`, `data/`, `api_node.yaml`, `runtime/` are not version-controlled — do not assume
they exist.

| Purpose | Command |
| --- | --- |
| Everyday changes | `cargo check --all-targets` |
| Unit tests | `cargo test --lib --bins` |
| Integration tests | `cargo test --no-fail-fast --test '*'` |
| Lint (CI gate) | `cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious` |
| Vendored pingora | `cargo check --manifest-path pingora-main/Cargo.toml -p pingora-core -p pingora-http -p pingora-cache -p pingora-proxy --all-targets` |
| Project tooling | `cargo xtask <subcommand>` |

**Local and CI use different CPU baselines.** `.cargo/config.toml` sets
`rustflags = ["-C", "target-cpu=native"]`; CI overrides with
`RUSTFLAGS="-C target-cpu=x86-64-v2"`. A passing local build does not imply a passing CI
build — re-verify against the CI baseline when build config or dependencies change.

## How to work

- Read nearby code first, and match the repository's existing error handling, tracing,
  locking, and async style.
- Don't silence compiler errors with broad `.clone()`, `Arc<Mutex<_>>`, `Box<dyn Trait>`,
  `'static`, or `unwrap()` unless that matches the domain and its cost model.
- Treat ownership problems as API design problems, and async problems as scheduling and
  cancellation problems.
- Final reports separate: fixed, still broken, design limitations, approved degradation.
