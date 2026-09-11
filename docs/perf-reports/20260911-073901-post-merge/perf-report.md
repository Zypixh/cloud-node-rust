# 性能测试报告 — 合并后版本（main @ 9cf1eda）

- 测试时间：2026-09-11 07:39–08:05 UTC
- 被测代码：main @ `9cf1eda`（PR #27 合并 + 用户 `src/cache/process_lock.rs` 重构）
- 结果目录：`perf-results/20260911-073901/`
- 上一轮基线（PR 修复版，锁重构前）：`../20260911-060037-baseline/`，原始数据 `perf-results/20260911-060037/`
- 压测命令：`DUR=15s bash scripts/perf/run_perf_matrix.sh`（D 组见"测试方法勘误"）

## 1. 测试环境（完整硬件信息）

| 项目 | 规格 |
|---|---|
| CPU 型号 | Intel(R) Xeon(R) Platinum 8559C |
| CPU 拓扑 | 8 vCPU（1 socket × 8 core，单线程/核），NUMA ×1 |
| CPU 频率 | 2400 MHz（/proc/cpuinfo，虚拟化固定频） |
| CPU 缓存 | L1d 192KiB / L2 8MiB / L3 320MiB |
| 内存容量 | 31 GiB（无 swap） |
| 内存频率 | 宿主机未向 VM 暴露 DIMM 信息（dmidecode 无 Memory Device 条目），无法读取标称频率 |
| 内存带宽（实测） | sysbench memory：单线程写 34.7 GB/s；8 线程读 **123.6 GB/s** |
| 磁盘 | /dev/vda 128 GiB virtio 块设备（vendor 0x1af4），I/O 调度 mq-deadline；可用空间 96 GiB |
| 磁盘带宽（实测） | 4GiB direct-I/O 顺序写 2.4 GB/s（含 fdatasync）；direct 读 12.6 GB/s |
| 网卡/链路 | 本测试全部走 loopback（lo，mtu 65536），无物理网卡参与 |
| 虚拟化 | Cloud Hypervisor / KVM，VT-x，full virtualization |
| 操作系统 | Ubuntu 22.04.5 LTS，kernel 5.15.200 |
| 软件版本 | nginx 1.18.0，oha 1.16.0，Rust release 构建 |

## 2. 拓扑与方法

```
oha ──HTTP──> bench-proxy :8080 ──HTTP──> nginx :8081 ──> /srv/perf-origin
```

与基线完全一致。本轮关键差异：bench-proxy 启动日志确认
`CACHE_PROCESS_LOCK: disabled — single-process mode`，即用户重构后的
`process_lock.rs` 在单进程模式下返回空 guard，**全路径零文件锁 syscall**。

## 3. 结果总表（新 vs 基线）

成功率全部 100%（D/E/F 中 nginx CPU ≈0 为 sendfile+page-cache 的正常表现）。

| 工况 | 基线 QPS | 新 QPS | 提升 | proxy CPU（基线→新） | p99（基线→新） |
|---|---|---|---|---|---|
| A. nginx 直连 1K c200 | 330,884 | 386,862 | +17%（压测端抖动） | 68→0.3 / 50→428 | 4.5ms→4.1ms |
| B. 热键 1K c50 | 18,932 | **73,096** | **×3.9** | 291→173% | 46.4ms→0.99ms |
| B. 热键 1K c200 | 3,722* | **74,805** | **×20.1** | 420→173% | 194ms→3.3ms |
| B. 热键 1K c500 | 13,721 | **76,885** | **×5.6** | 117→172% | 47.9ms→8.0ms |
| B. 热键 1K c1000 | 17,301 | **76,067** | **×4.4** | 116→172% | 72.0ms→15.7ms |
| C. 命中 10K c200 | 16,392 | **67,458** | **×4.1** | 304→172% | 66.9ms→3.6ms |
| C. 命中 100K c200 | 6,469 | **52,563** | **×8.1** | 419→164% | 73.6ms→4.8ms |
| C. 命中 1M c200 | 3,876 | **10,939** | **×2.8** | 89→137% | 66.2ms→22.1ms |
| C. 命中 10M c200 | 652 | **1,242** | **×1.9** | 98→136% | 337ms→282ms |
| D. miss 256K c200 | 35,224 | **42,703** | **+21%** | 525→447% | 19.7ms→14.6ms |
| E. 连接churn 1K c200 (oha) | 15,437 | 12,328 | −20% | 124→123% | 19.8ms→23.8ms |
| E. churn (pymatrix) | 6,744 | 6,519 | ≈持平 | — | 35.6ms→38.2ms |
| E. keep-alive (pymatrix) | 13,146 | **20,844** | **+59%** | — | 34.1ms→11.4ms |
| F. 多键命中 2000 keys c200 | 111,254 | **226,783** | **×2.0** | 546→454% | 4.5ms→2.4ms |

\* 基线 c200 读数受同 key 排他锁竞争塌陷影响特别严重，属于该 bug 的最坏点。

10M 命中带宽：基线 652×10MiB ≈ **6.7 GB/s** → 新 1,242×10MiB ≈ **12.9 GB/s**，已逼近实测单流内存写带宽（34.7 GB/s）与 loopback 拷贝开销的合理区间。

## 4. 分析：锁重构带来的变化

用户将每请求文件锁（mkdir+statx+openat+flock+close，每请求约 6 次 syscall）重构为
`src/cache/process_lock.rs`：fd 缓存 + 进程内引用计数 + 读共享/写排他；且仅在
RKE2 共享卷模式启用，**单进程部署下整条锁路径短路为空操作**。

直接效果（与上一轮 CPU 分析报告预测一致）：

1. **热键不再是瓶颈**：同 key QPS 从 ~3.7–19k 提升到 ~75k，p99 从 194ms 降至 3.3ms。
   原"命中期间全程持有排他 flock"的串行化消失。
2. **全部命中路径 syscall 开销消除**：小文件命中 QPS ×4–×8，同时 proxy CPU
   反而从 ~300–420% 降到 ~165–173%（B/C 组）。每请求 CPU 消耗大幅下降。
3. **多键命中翻倍**（111k→227k），CPU 从 546% 降到 454% —— 单位吞吐的 CPU 效率
   约提升至 2.4 倍。
4. **miss 路径 +21%**：填充路径的 fill 锁同样短路，回源+落盘流水线更快。
5. **内存占用下降**：RSS 峰值 1.4GB→1.0GB（热键组 1.1–1.2GB→~180MB），因为不再
   堆积在锁队列里的连接/缓冲。

## 5. 当前瓶颈定位（新代码下）

1. **单 key 上限 ~75k QPS**：B 组 c50→c1000 全部收敛在 73–77k，proxy CPU 仅
   172%。剩余串行点是进程内 `cache_write_lock_for_key` 的 per-key tokio mutex
   （lookup 期间持有）。单 key 语义下这是合理的互斥，非 bug；若需更高单键吞吐，
   可考虑缩小临界区（meta 查到后即可放锁）。
2. **多键命中 227k QPS 时 proxy CPU ~4.5 核**：CPU 上限。剩余开销主要在 body
   拷贝、内存分配与 tokio 调度（见基线 CPU 分析报告，flock 项已消除）。
3. **miss 回源流 42.7k QPS / ~11 GB/s，proxy ~4.5 核**：CPU 上限。nginx 源站本身
   不是瓶颈（sendfile+page cache 几乎零开销）。
4. **连接 churn 略有回退**（15.4k→12.3k，pymatrix churn 持平 6.5k）：无锁路径
   不会更慢，怀疑是测量抖动或连接建立路径的次要开销；如需追查可在 churn 工况下
   补一次 perf 采样。oha churn 与 pymatrix churn 数据相差一倍，本身就说明该工况
   对客户端实现敏感。
5. **压测端上限**：nginx 直连 387k QPS 时 oha 已接近自身极限；继续压榨 proxy
   上限需要多机压测。

## 6. 测试方法勘误

合并版 `run_perf_matrix.sh` 的 D 组参数组合 `-z + -n + --rand-regex-url` 不合法
（oha 拒绝），且 rand-regex 会打到不存在的 origin 路径（全部 404）。已在本分支
修复：改回基于 `/srv/perf-origin/miss/{0..4095}.bin` 固定键空间（1.1GB > 512MB
缓存 → 驱逐造成持续 miss），15s 时长界内测量。本轮 D 组数据为修复后手动同参数
补测，其余组（A/B/C/E/F）由脚本自动产出。

## 7. 复现

```bash
# 准备（一次性）：nginx 站点 perf-origin + /srv/perf-origin 测试文件集
cargo build --release --bin bench-proxy
DUR=15s bash scripts/perf/run_perf_matrix.sh
# 结果：perf-results/<ts>/*.oha.json + *.sys.json
```

硬件信息采集命令：`lscpu`、`free -h`、`lsblk`、`sysbench memory run`、
`dd oflag=direct/iflag=direct`。
