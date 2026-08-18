# Mace 上游 Issue #1 归档

- 上游仓库: `abbycin/mace`
- Issue: [#1 Possible ABA corruption in CCPool during concurrent Bucket::view() churn / 并发 view 时 CCPool 可能发生 ABA 损坏](https://github.com/abbycin/mace/issues/1)
- 依赖版本: 本仓库仍钉在 `mace-kv 0.1.0`；上游已在 `mace-kv 0.1.1` 修复
- 状态: 上游已确认并合并 [PR #2](https://github.com/abbycin/mace/pull/2)，issue 已关闭。静态审计见 [mace-0.1.1-audit.md](mace-0.1.1-audit.md)

## 上游结论（2026-08-18）

上游用 per-shard `Mutex<Vec<Handle<CCNode>>>` 替换无 tag 的 Treiber 空闲栈，并补了 16 线程 `view/get/drop` 回归。crates.io 已发布 `0.1.1`（checksum `19de80b237aecbfe52e8a3ec9919185aa776ef74447237e1b91d288f7f4cf94b`）。本仓库适配层的全局 `operation_lock` 和点查事务规避在钉到 0.1.1 之前仍应保留。

以下内容与已提交的上游 issue 一致。

---

## English

### Summary

With `mace-kv 0.1.0` and default features, repeatedly creating and dropping short-lived `Bucket::view()` values from multiple OS threads triggers reproducible internal invariant failures:

```text
CCNode::begin_reg: state is not Idle
CCPool::maybe_shrink_one: registry pointer mismatch
```

This reproduced in a Debug workload with 16 concurrent readers. Each operation is `Bucket::view() -> view.get() -> drop(view)`. It did not reproduce at 1 or 4 readers in the same run. A Release build makes the timing less deterministic; that is not evidence that the path is safe.

### Reproduction Shape

Seed `b"k"` first, then run 16 OS threads. Each loops many times:

```rust
let view = bucket.view().unwrap();
let _ = view.get(b"k");
// view is dropped here
```

The production adapter originally used this same short-lived view pattern for point reads. Under sustained Debug churn, the assertion is triggered.

### Suspected Root Cause (Static Analysis, Please Confirm)

`CCPool::try_pop_shard` and `CCPool::push_shard` implement a Treiber-style free list with only `AtomicPtr<CCNode>` (`src/cc/context.rs:717-746`). The head has no version/tag, while a popped node may be pushed back before a stalled pop CAS resumes.

`crossbeam_epoch::pin()` protects deferred reclamation but does not prevent ABA reuse of a still-allocated node.

Possible schedule:

```text
Initial free list: A -> B

T1 reads head=A and next=B in try_pop_shard(), then pauses.
T2 pops A for view A.
T3 pops B for view B; B is Active.
T2 drops view A and pushes A back.
T1 resumes; CAS(A -> B) succeeds because head is A again.
B is published as free while view B is still Active.
A later allocation gets B; CCNode::begin_reg() asserts because B is not Idle.
```

This directly matches `CCNode::begin_reg: state is not Idle` (`context.rs:653-660`). The registry mismatch in `maybe_shrink_one` appears to be a downstream symptom after the pool/registry invariant has been broken. We have not claimed observed data corruption, but removing assertions would not make the underlying lifetime issue safe.

### Temporary Workaround and Requested Direction

We temporarily serialized adapter operations and changed point reads to `Bucket::begin() -> get() -> commit()`. It avoids concurrent view-pin churn but serializes all reads/writes and is not an acceptable long-term solution.

Please consider a free-list design with ABA protection, such as tagged pointers, an epoch-integrated atomic list, or a lock-protected pool. A regression test should force the stalled-pop / pop / return / resumed-CAS schedule and prove that no active `CCNode` can re-enter the free list.

---

## 中文

### 概要

在默认 feature 的 `mace-kv 0.1.0` 中，多线程高频创建和释放短生命周期 `Bucket::view()` 会触发内部不变量失败：

```text
CCNode::begin_reg: state is not Idle
CCPool::maybe_shrink_one: registry pointer mismatch
```

该问题在 Debug 构建、16 个并发读线程下复现。每次操作均为 `Bucket::view() -> view.get() -> drop(view)`；同一轮 1 和 4 线程未复现。Release 仅使竞态更难稳定命中，不能视为安全。

### 触发方式

先写入 `b"k"`，再运行 16 个操作系统线程，每个线程循环：

```rust
let view = bucket.view().unwrap();
let _ = view.get(b"k");
// 此处释放 view
```

生产适配层原本也对点查使用该短生命周期 view 模式；持续 Debug churn 后即可触发断言。

### 推测根因（静态分析，待上游确认）

`CCPool::try_pop_shard` 和 `CCPool::push_shard` 以不带版本/tag 的 `AtomicPtr<CCNode>` 实现 Treiber 空闲栈（`src/cc/context.rs:717-746`）。节点可以在被暂停的 pop CAS 恢复前重新压回栈，因此存在 ABA。

`crossbeam_epoch::pin()` 只能保护延迟回收，不能阻止仍已分配节点的 ABA 重用。

可能交错：

```text
初始空闲栈: A -> B

T1 在 try_pop_shard() 中读到 head=A、next=B 后暂停。
T2 弹出 A 用于 view A。
T3 弹出 B 用于 view B；B 为 Active。
T2 释放 view A，并将 A 压回栈。
T1 恢复；栈顶再次为 A，CAS(A -> B) 成功。
B 在 view B 仍存活时被重新发布为空闲节点。
后续分配取得 B；begin_reg() 发现 B 不是 Idle，断言失败。
```

这与 `CCNode::begin_reg: state is not Idle` 直接吻合（`context.rs:653-660`）。`maybe_shrink_one` 的 registry 指针不匹配推测是 pool/registry 不变量被破坏后的后继症状。尚未声明已观察到数据损坏，但只移除断言并不能使该生命周期问题安全。

### 临时规避与建议

临时规避是将适配层操作串行化，并将点查改为 `Bucket::begin() -> get() -> commit()`。这能规避并发 view-pin churn，但会串行化全部读写，不适合作为长期方案。

建议采用具备 ABA 保护的空闲表，例如 tagged pointer、与 epoch 正确集成的原子链表或受锁保护的 pool；并加入强制 stalled-pop / pop / return / resumed-CAS 调度的回归测试，确保活跃 `CCNode` 不会重新进入空闲栈。
