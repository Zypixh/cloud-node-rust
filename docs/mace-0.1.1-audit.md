# mace-kv 0.1.1 静态审计

审计日期: 2026-08-18。本轮按要求未执行任何 `cargo` 命令，也未改 `Cargo.toml` / `Cargo.lock`。

对照物：

- 本地已锁定的 `mace-kv 0.1.0`（`Cargo.lock` checksum `f6cad3e8c66c0effbe2e279ec7a403d280eab42f53c6fcc0a27909b34b1fdd8c`）
- crates.io `mace-kv 0.1.1`（发布于 2026-08-18T04:13:50Z，checksum `19de80b237aecbfe52e8a3ec9919185aa776ef74447237e1b91d288f7f4cf94b`）
- 上游 [PR #2](https://github.com/abbycin/mace/pull/2)（merge `e04c0cb7126d099eb30bb059fbad1455ea8b5d00`），关闭 [issue #1](https://github.com/abbycin/mace/issues/1)

结论：**issue #1 的根因修复在源码层面成立，可以在下一轮把依赖精确钉到 `=0.1.1`，并拆除适配层串行锁和点查事务规避。** 本轮不把该钉入 lockfile。0.1.1 没有改公开 API 或 changelog 中的存储格式。

## 上游修了什么

0.1.0 → 0.1.1 是三处并发/弱内存修复，没有功能面或 schema 变更。

### 1. CCPool ABA（对应 issue #1，阻塞我们的并发 view）

0.1.0 用无 tag 的 `AtomicPtr<CCNode>` Treiber 栈做分片空闲表。`Handle<CCNode>` 是 `Copy` 裸指针包装，节点被压回后仍可能被暂停的 pop CAS 当成旧 head，把仍 Active 的节点重新发布为空闲项。这与 `CCNode::begin_reg: state is not Idle` 和 `maybe_shrink_one` 的 registry mismatch 一致。

0.1.1 把每个 shard 改成 `Mutex<Vec<Handle<CCNode>>>`，删掉 `CCNode::next`。`try_pop_shard` / `push_shard` 都在同一把 shard mutex 里完成。这正是 issue 里建议的 lock-protected pool：同一 shard 上 pop/push 有 happens-before，stale CAS 不再存在。

生命周期仍是 `alloc_view_pin` → `begin_reg` → sample oracle → `activate`，Drop 时 `clear_idle` 再 `free`。mutex 的释放/获取保证下一个 `begin_reg` 能看到 Idle。collector shrink 仍然只从空闲表 pop，不会回收仍被 view 持有的节点。

回归测试 `tests/cc.rs::concurrent_short_lived_views_never_reuse_active_pins` 就是 issue 的 16 线程 `view/get/drop` 负载，每线程 100_000 次。这是统计性回归，不是强制 stalled-CAS 调度；对 mutex 实现来说结构上已经排除 ABA，该测试主要防回退和其它 view churn 断言。

### 2. collector 安全边界与 writer begin 的 SeqCst 全局序

0.1.0 里 writer `start_reg` 用 Relaxed 发布 `txn_seq`，`alloc_oracle` 用 AcqRel 取 begin 时间戳，collector cut 却是 SeqCst load。弱内存上 AcqRel RMW 不必进入 SeqCst 全序，collector 可能切到一个尚未看见的 writer，随后该 writer 的 `start_ts` 仍小于 cut。

0.1.1 把这条链收进同一 SeqCst 全序：

- `WriterGroup::start_reg`：`txn_seq` 改为 SeqCst store
- `WriterGroup::stable_ts`：`txn_seq` 改为 SeqCst load
- 新增 `Context::alloc_begin_oracle`：`oracle.fetch_add(1, SeqCst)`，仅用于 `TxnKV::begin`
- commit 仍走原来的 `alloc_oracle`（AcqRel），不参与 begin/cut 证明

collector 注释同步改成：cut、writer 注册、begin 时间戳分配、reader 注册共享一个全局序。未进入本轮扫描的 writer，其 start_ts 只能 ≥ cut。`reg_start_ts` 仍是 Release；若 collector 已看到奇数 `txn_seq` 但还没看到 `stable_ts`，会得到 `Pending` 并阻止本轮发布，方向正确。

### 3. PageMap::get 的 Acquire

`PageMap::map_to` 一直用 Release 发布 slot。0.1.0 的 `get()` 是 Relaxed，ARM 上可能先看到 pid 映射再看到页内容。0.1.1 改为 Acquire，与 Release 配对。`tree.rs` / `buffer.rs` / `evictor.rs` 的 `table.get()` 都会受益。`index()` 里高层间接层本身已是 Acquire load。

## 残留与限度

这些不否定 issue #1 的修复，但下一轮钉版本时要带着看。

1. **回归是负载测试，不是强制调度。** mutex 使 ABA 在结构上消失，但没有 litmus 测试去重放 stalled-pop 交错。可接受，不能当成形式证明。
2. **`tests/gc.rs` 的 abort-clean 用例被削弱。** 5 秒内到不了可删除状态时改为 `println!` 后继续循环，而不再 `assert`。这是测试质量问题，不是生产路径缺陷。
3. **PageMap 间接层 CAS 失败序仍是 Relaxed。** `Layer::{1,2}::get` 在 `compare_exchange(null, new, AcqRel, Relaxed)` 失败后直接解引用 `curr`。热路径 `index()` 先做 Acquire load，只有 Acquire 看到 null 才进 `get()`。这是同类弱内存边角，0.1.1 没动。置信度低于已修的 `PageMap::get`。
4. **`Handle<T>` 仍是 Copy 裸指针。** 所有权靠“registry 一份 + 空闲表或调用方一份”的约定。mutex 让空闲表成员关系互斥，shrink 的 `epoch::defer(reclaim)` 仍然成立。
5. **changelog 写 format/API 在 0.1.0 已基本稳定。** 0.1.1 未声明格式变更。已有 `metrics.mace` 目录按补丁升级处理，但仍需在允许跑 cargo 后做一次 reopen 冒烟。
6. **license / MSRV。** 仍是 MIT，`rust-version = 1.95`；本仓库是 1.96.0 / edition 2024。feature 仍是 `default` / `extra_check` / `failpoints`。
7. **本轮未核验 crate tarball 与 git tree 逐文件一致。** crates.io 元数据、PR diff 和 changelog 对齐到 0.1.1。精确 pin 时应让 lockfile 使用上述 checksum。

## 对本仓库适配层的含义

Codex 已完成的替换是：运行时去掉 `rust-rocksdb`，用 `src/metrics/mace_backend.rs` 保持旧扁平 key，七个 Mace bucket，xtask 只读导入 `metrics.db` → `metrics.mace`。根 crate 已无 RocksDB；`xtask` 仍依赖 `rust-rocksdb = 0.50.0` 做迁移，这是合理边界。

为规避 0.1.0 的 view churn，适配层目前：

- 全局 `parking_lot::Mutex<()>` 串行化 get/write/iterator/prefix_iterator
- 点查走 `Bucket::begin() -> get() -> commit()`，而不是 `Bucket::view()`
- `scan_bucket` 仍用 `view()`，但外面被同一把锁包住
- 测试 `serializes_concurrent_reads_without_view_churn` 只证明锁下的串行读

0.1.1 之后这些规避不再有上游依据。继续留着会把七个 bucket 的读写打成单飞，并让只读点查看成写事务。

建议的下一轮（仍需显式允许 cargo）按这个顺序：

1. 把根 crate 和 `xtask` 的 `mace-kv` 精确钉到 `=0.1.1`，更新 lockfile。
2. 去掉 `operation_lock`；点查改回短生命周期 `view()`；保留事务只用于 put/delete/merge。
3. 把并发测试改成 16 线程 view/get/drop，对齐上游回归，而不是“有锁所以不炸”。
4. `scan_bucket` 在 `view()` 失败时不要吞成空结果。
5. 跑适配层测试、xtask 迁移测试，以及一次已有 `metrics.mace` 的 reopen。不要默认跑全量 `cargo test --all-targets`。

计划里尚未做、且本轮也不做的部分：类型化 repository、dual-write、PersistenceService、XDP/Tokio 项。当前落地是 drop-in 引擎替换，不是 `tasks/mace-kv-xdp-tokio-plan.md` 的完整目标架构。

## 公开 API 兼容（静态）

PR #2 不改 `Mace` / `Bucket` / `TxnKV` / `TxnView` / `Options` / `BucketOptions` / `OpCode`。本地适配层的 `Mace::new`、`new_bucket`、`get_bucket`、`begin`、`view`、`upsert`/`get`/`del`/`commit`、`range`/`seek` 在 0.1.1 仍然有效。升级本身不需要改调用签名；需要改的是我们自己的规避用法。
