# Proxy CPU 占用分析报告（bench-proxy, 2026-09-11）

方法：`perf record -F 999 -p <pid>`（cycles:u，用户态）在三种工况下各采样 10s，
`strace -c -f` 统计 syscall 构成。原始 perf data：`/tmp/perf-{hit,miss,hotkey}.data`。

## 每请求 CPU 成本对比

| 工况 | QPS | proxy CPU | ≈CPU/请求 | 对照 |
|---|---|---|---|---|
| nginx 直连 1K | 331k | 58%（nginx） | ~1.8 µs | sendfile 零拷贝直达 |
| 多键命中 4K c200 | 111k | 546% | ~49 µs | 约为 nginx 的 28 倍 |
| miss 流 256K c200 | 35k | 525% | ~150 µs | +回源+写盘+meta 发布 |
| 热键 1K c200 | 3.7k | 420% | ~1130 µs | 锁竞争空转放大 |
| 命中 10M c200 | 652 | 98% | ~1500 µs | 以 10MB 内存拷贝为主 |

## CPU 消耗构成（多键命中 profile，57k 采样）

| 类别 | 占比 | 来源 |
|---|---|---|
| 内存分配器 | ~12% | `cfree` 5.2% + `malloc` 3.8% + `realloc` 3.1% —— 每请求大量小对象分配（header map、task、Bytes、key 字符串等） |
| 数据拷贝/引用计数 | ~10% | libc memmove/memcpy 系列 + `bytes::shared_clone/drop` ~4% —— 响应 body 多次拷贝、HeaderMap clone ~1.9% |
| 跨进程文件锁路径 | ~6–8% | `acquire_cache_process_lock` 的 spawn_blocking 任务 + flock + condvar 唤醒 |
| 元数据索引 | ~4–5% | `mace::Bucket::view`、`imtree::Leaf::visit_from` —— 每请求对 Mace 内存索引做 meta 查询（含 key 的 MD5） |
| tokio 调度/锁竞争 | ~6% | task poll、blocking pool 调度、`parking_lot` condvar/mutex slow path、`notify` |
| Pingora 请求生命周期 | ~5% | `process_new_http`、`read_request`、`process_request` 等框架路径 |
| 缓存判定 | ~2% | `response_headers_allow_shared_cache`、bloom filter、`TinyUfoL1` |
| 时钟 | ~1% | vdso `clock_gettime` —— 每请求多处时间戳 |

其余为长尾（h2 帧处理、字符串解析、epoll 封装等）。

## syscall 证据（strace -c，6s 窗口，~21.7k 请求）

| syscall | 次数 | 每请求 | 说明 |
|---|---|---|---|
| `mkdir` | 129,879 | ~6 | `create_dir_all` 每次全路径尝试，**全部 EEXIST 失败** —— 纯浪费 |
| `statx` | 129,877 | ~6 | lock 文件路径检查 |
| `openat` | 129,876 | ~6 | 每请求打开 barrier/key `.lock` 文件 |
| `flock` | 129,875 | ~6 | 每请求一次 LOCK_EX |
| `close` | 130,076 | ~6 | 关闭 lock fd |
| `sendto`/`recvfrom` | ~195k | ~9 | 正常网络 I/O |
| `futex` | 181,365 | ~8 | tokio mutex、spawn_blocking 交接、mpsc/condvar —— 85% syscall 耗时 |

**核心结论：每个请求（包括纯内存缓存命中）都执行约 5–6 次文件系统 syscall**
（barrier.lock + key.lock 的 `create_dir_all`/`open`/`flock`/`close`），且全部走
`spawn_blocking` 跨线程交接（往返一次 blocking pool = 2 次任务调度 + futex）。
这是相对 nginx 每请求 ~1.8µs 成本的最大结构性差异：nginx 命中路径 0 次文件锁。

## 逐工况归因

1. **多键命中 111k QPS @546% CPU**：锁 syscall 开销 + 分配器 + mace meta 查询 + task 调度，
   尚余 ~2.5 核余量（oha 单机先到极限）。
2. **miss 流 35k QPS @525%**：在命中路径之上叠加——回源连接复用、body 落盘写、
   mpsc 元数据发布（writer 线程串行写 Mace）、`TinyUfoL1::put`、bloom 插入。
   CPU 打满前吞吐 ~9.2GB/s。
3. **热键 1K**：吞吐被 per-key 排他 flock 串行化在 ~20k QPS 以下；
   高并发时空转 CPU（spawn_blocking 队列 + futex 竞争）反而冲高到 420%，
   即"排队也烧 CPU"。
4. **大文件**：CPU 几乎全花在 body 内存拷贝（无 sendfile/零拷贝路径），
   10M 命中 6.7GB/s ≈ 内存带宽，属预期。

## 优化方向（仅建议，未改代码）

1. **跨进程锁惰性化/分层**：单进程部署时 skip 文件锁（`roots` 只有一个且独占时
   flock 无意义）；或按 key 缓存打开的 lock fd 避免 open/mkdir/stat/close 四连。
   预计可省 ~5 syscall + 1 次 spawn_blocking/请求。
2. **热键 flock 提前释放**：见 `perf-baseline-report.md` 发现 2（内存 body 不需持锁流式）。
3. **减少每请求分配**：HeaderMap clone、CacheKey/字符串分配可池化；
   命中路径 response header 复用。
4. **mace meta 查询短路**：内存索引前可加一层更快的 DashMap/probe 或直接由
   TinyUfoL1 entry 携带校验信息，减少 B-tree view 构建。
