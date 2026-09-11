# 性能测试基线报告（2026-09-11）

环境：8 vCPU / 31GB，Ubuntu 22.04，loopback 单机拓扑
`oha → bench-proxy:8080 (Pingora + HybridStorage 512MB mem + disk) → nginx:8081`

原始数据：`perf-results/20260911-060037/`（oha JSON + 进程采样 JSON）。

## 结果汇总

| 工况 | QPS | p50 | p99 | 吞吐 | proxy CPU | 说明 |
|---|---|---|---|---|---|---|
| A 直连 nginx，1KB，c200 | 330,884 | 0.30ms | 4.5ms | 339 MB/s | — (nginx 58%) | 基线上限（oha 侧已接近瓶颈） |
| B 热键命中 1KB c50 | 18,932 | 1.9ms | 46ms | 19 MB/s | 291% | 同 key 串行化 |
| B 热键命中 1KB c200 | 3,722 | 22ms | 194ms | 4 MB/s | 420% | 锁竞争恶化（见发现 2） |
| B 热键命中 1KB c500 | 13,721 | 36ms | 48ms | 14 MB/s | 117% | |
| B 热键命中 1KB c1000 | 17,301 | 56ms | 72ms | 18 MB/s | 116% | |
| C 命中 10KB c200 | 16,392 | 8.9ms | 67ms | 168 MB/s | 304% | |
| C 命中 100KB c200 | 6,469 | 15.7ms | 74ms | 661 MB/s | 419% | |
| C 命中 1MB c200 | 3,876 | 50ms | 66ms | 4,050 MB/s | 89% | |
| C 命中 10MB c200 | 652 | 312ms | 337ms | 6,694 MB/s | 98% | 逼近内存拷贝带宽 |
| D miss 流（1.1GB 键空间 256KB 文件） | 35,224 | 4.9ms | 20ms | 9,230 MB/s | 525% | 回源+写盘+元数据发布 |
| E churn（每请求新建连接） | 15,437 | 12.6ms | 20ms | 16 MB/s | 124% | oha --disable-keepalive |
| E pymatrix churn c200 | 6,744 | 25.2ms | 35.6ms | — | — | 纯 Python 客户端，下限参考 |
| E pymatrix keepalive c200 | 13,146 | 12.9ms | 34.1ms | — | — | |
| F 多键命中（2000×4KB） c200 | 111,254 | 1.7ms | 4.5ms | 456 MB/s | 546% | 多键并行扩展良好 |

## 发现

### 1. 同 key 并发缓存锁死锁（已修复）

**现象**：缓存启用后，任何 ≥2 并发的同 key 请求永久挂死（该 key 后续请求全部超时），
其他 key 不受影响。

**根因**：`HybridStorage::lookup` 的 L2-hit→L1 promotion 分支在持有 key 文件锁
（`handler._process_lock`，flock LOCK_EX）的情况下又获取 `cache_write_lock_for_key`
的 tokio mutex；而 lookup/fill 路径一律先抢 mutex 再抢 flock。两个并发同 key 请求
互持对方所需锁 → ABBA 死锁。复现：`oha -n 20 -c 2 <同一URL>`。

**修复**：promotion 分支先释放 `MemoryHitHandler` 的 `_process_lock` 再拿 write_lock。
handler body 已物化为内存 `Bytes`，流式输出期间不再访问磁盘文件，无需持锁。
见 `src/cache_hybrid.rs` lookup() 的 L2 hit promotion 块。

### 2. 热键吞吐受排他 flock 串行化限制（待优化）

同 key 命中在整个「查找 + 响应流式输出」期间持有该 key 的排他文件锁
（`acquire_cache_process_read_lock` 对 key 锁文件始终 LOCK_EX），
加上 lookup 期间的 per-key tokio mutex，单热键被完全串行化：

- 峰值约 17k–23k QPS（c50–c1000 非单调，c200 出现竞争恶化拐点 3.7k QPS / p99 194ms）。
- 对照：多键命中 111k QPS；nginx 直连 331k QPS。

**优化方向**：L1 `MemoryHitHandler` 的 body 同样是内存 `Bytes`，与发现 1 同理可在
校验完成后提前释放 `l1_process_lock`（本次未改，需先验证跨进程 purge 时序语义）。
更彻底的方案是把跨进程 key 锁降级为「仅填充/校验期持有」或用 try-lock+回退。

> **后续已实现（本 PR 第二轮改动）**：未选择提前释放，而是把读路径的
> key 锁由 `LOCK_EX` 改为 `LOCK_SH` 并对锁 fd 做按 (roots,key) 缓存 +
> 进程内引用计数（见 `src/cache/process_lock.rs`）。热键并发读者共享同一把
> `LOCK_SH`，流式输出期间仍持有交付栅栏（语义不变），稳态下每请求
> 0 文件锁 syscall、无 spawn_blocking；写者经 `exclusive_pending` 门控保持
> 内核 FIFO 公平，容量/fd 预算耗尽时回退到逐请求私有 fd（计数可观测）。

### 3. bench-proxy 缺少缓存元数据写入器初始化（已修复）

`start_cache_access_flusher()`（加载 meta 索引 + 启动 Mace writer 线程 + bloom 预热）
只在 `main.rs` 启动；bench-proxy 未调用 → fill 的元数据发布失败被丢弃 → 100% miss。
已在 bench-proxy 中以独立 tokio runtime 启动该 flusher，并补上 tracing 初始化。

## 数据判读

- **Miss 路径能力**：35k QPS @ 9.2GB/s，proxy CPU 525% —— 回源+写盘+meta 发布
  流水线的 CPU 上限约 5.5 核。
- **多键命中**：111k QPS @ 546% CPU —— 仍未打满 8 核，受 oha 单进程限制；
  更大压力需多 loadgen 或跨机。
- **大文件**：10MB 命中 6.7GB/s ≈ loopback 内存带宽，磁盘读路径（页缓存命中）
  不构成瓶颈。
- **建连开销**：churn 相对 keepalive 折损约 50%（pymatrix: 6.7k vs 13.1k）。
