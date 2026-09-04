# Implementation Plan: Cache Correctness and Isolation

## Overview

Harden the shared HTTP cache so that only representations safe to share are
looked up or stored, and ensure that response transformations, invalidation,
concurrent writers, and partial-range assembly cannot publish the wrong body or
metadata.

## Architecture Decisions

- Prefer correctness and tenant/privacy isolation over cache hit rate while the
  existing response pipeline performs transformations after the cache write
  hook.
- Keep cache policy configuration compatible, but apply a conservative runtime
  safety gate for methods, request credentials, response directives, cookies,
  and `Vary`.
- Make cache key, body, and metadata publication atomic with respect to a key;
  stale writers must not republish data after purge or a newer generation.
- Treat partial content as a versioned representation. Without a reliable
  validator, do not merge ranges from different origin versions.

## Task List

### Phase 1: Request and response admission

- [ ] Unify cache-control parsing and shared-cache safety checks in the legacy
  and compiled policy paths.
- [ ] Restrict shared cache admission to safe requests and reject transformed
  or `Vary` responses until their representation/key contract is correct.
- [ ] Stop rewriting origin cache directives and move `Location` rewriting to
  the origin-response stage, with a defensive HIT-path rewrite.

### Phase 2: Storage publication correctness

- [ ] Fix memory-only L1 misses, empty compressed objects, and L1 metadata
  invalidation.
- [ ] Add per-key writer serialization and purge/generation fencing across the
  hybrid storage path.

### Phase 3: Partial cache correctness

- [ ] Hold the root-key lock across range body publication and metadata merge.
- [ ] Record and validate ETag/Last-Modified (or reject unsafe merges) and fence
  partial writes after purge.

### Checkpoint: Regression coverage

- [ ] Add deterministic tests for request/response admission, cache keys,
  transformed responses, location rewriting, compression, L1/L2 behavior,
  purge races, and partial validators.
- [ ] Run focused tests, all-target checks, formatting, and the complete test
  suite.

## Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Conservative admission lowers hit rate | Medium | Preserve configuration and remove bypasses only after representation-safe tests exist |
| Pingora callback ordering differs by version | High | Verify against the checked-in Pingora implementation and add callback-level reasoning/tests |
| Concurrent file writers publish stale data | High | Serialize publication and use a generation token checked before metadata commit |
| Existing partial metadata lacks validators | High | Treat legacy metadata as non-mergeable until refreshed |

## Open Questions

- None required for the correctness-first implementation; the safe defaults can
  be relaxed later with explicit representation-aware keys and tests.
