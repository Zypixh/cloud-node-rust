# 性能测试报告 — 多协议轮（HTTP/1.1 明文 / HTTP/1.1+TLS / HTTP/2 / HTTP/3）

- 测试时间：2026-09-11 16:51–18:30 UTC
- 被测代码：main @ `d875f8a`（含 PR #28 报告与 PR #29「移除命中路径剩余串行化与拷贝」）
- 结果目录：`perf-results/20260911-165103-{h1,h1s,h2,h3}/`
- 压测命令：`for P in h1 h1s h2 h3; do DUR=15s MISS_REQUESTS=32768 PROTO=$P bash scripts/perf/run_perf_matrix.sh perf-results/20260911-165103-$P; done`
- 上一报告（锁重构复测，main @ 9cf1eda）：`../20260911-073901-post-merge/perf-report.md`

## 1. 测试环境（完整硬件信息）

| 项目 | 规格 |
|---|---|
| CPU 型号 | Intel(R) Xeon(R) Platinum 8559C |
| CPU 拓扑 | 8 vCPU（1 socket × 8 core，单线程/核），NUMA ×1 |
| CPU 频率 | 2400 MHz（/proc/cpuinfo，虚拟化固定频） |
| CPU 缓存 | L1d 192KiB / L2 8MiB / L3 320MiB |
| AES-NI / AVX | 具备（aes、avx2、avx512f 在 lscpu flags 中可见，TLS 与 QUIC 加密走硬件加速路径） |
| 内存容量 | 31 GiB（无 swap） |
| 内存频率 | 宿主机未向 VM 暴露 DIMM 信息（dmidecode 无 Memory Device 条目），无法读取标称频率 |
| 内存带宽（实测） | sysbench memory：单线程写 34.7 GB/s；8 线程读 **123.6 GB/s** |
| 磁盘 | /dev/vda 128 GiB virtio 块设备（vendor 0x1af4），I/O 调度 mq-deadline；可用空间 96 GiB |
| 磁盘带宽（实测） | 4GiB direct-I/O 顺序写 2.4 GB/s（含 fdatasync）；direct 读 12.6 GB/s |
| 网卡/链路 | 本测试全部走 loopback（lo，mtu 65536），无物理网卡参与；H3 走 UDP loopback |
| 虚拟化 | Cloud Hypervisor / KVM，VT-x，full virtualization |
| 操作系统 | Ubuntu 22.04.5 LTS，kernel 5.15.200 |
| 软件版本 | nginx 1.18.0，oha 1.16.0，curl 7.81，Rust release 构建；H3 负载端为本仓库新写的 `bench-h3-load`（quinn + h3） |

## 2. 拓扑与方法

```
loadgen ──{协议}──> bench-proxy ──HTTP/1.1──> nginx :8081 ──> /srv/perf-origin

bench-proxy 监听（本轮新增）：
  h1  : 0.0.0.0:8080  cleartext HTTP/1.1（原有）
  h1s : 0.0.0.0:8443  TLS，ALPN=http/1.1        （TlsSettings::intermediate + enable_h2）
  h2  : 0.0.0.0:8443  TLS，ALPN=h2              （同一端口，ALPN 分流）
  h3  : 0.0.0.0:8443  UDP/QUIC，ALPN=h3         （quinn Endpoint → h3::server → H3DownstreamSession → process_new_http）

源站：所有四轮共用同一个 HTTP/1.1 nginx :8081（用户要求"源站默认为同一个http协议"），
A 组为直连 nginx 的每轮参考基线（oha h1），不计入协议对比。
```

### 并发口径归一化

各组 `-c N` 表示**在途请求数 N**：
- h1/h1s：N 条连接 × 1 流；
- h2：⌈N/4⌉ 条连接 × 4 流/连接（oha `-p 4`）；
- h3：⌈N/4⌉ 条 QUIC 连接 × 4 双向流/连接（bench-h3-load `--conns N/4 --streams 4`）。

缓存与协议无关，所有轮的 warmup 统一走 h1 :8080（避免 TLS 握手成本污染预热）。

### 逐组说明与已知口径差异

| 组 | 含义 | 口径备注 |
|---|---|---|
| A | oha→nginx 直连 1K | 四轮均为 h1，仅作压测端基准 |
| B | 热键 1K 命中扫描（c50/200/500/1000） | 同一 URL，测 per-key 并发上限 |
| C | 命中尺寸扫描 10K/100K/1M/10M | 测吞吐/拷贝路径 |
| D | miss 回源 256K 随机键（32,768 请求） | h1/h1s/h2 用 `--rand-regex-url`；h3 用预生成 100k 唯一键 URL 文件（键空间 25.6GB > 16GB L2，重复仍 miss） |
| D2 | L2 磁盘命中 256K 固定键空间 | 先驱逐预热后回放 URL 文件 |
| E | 连接 churn 1K（每请求新连接） | h1/h1s：oha `--disable-keepalive`；h3：`--churn`（每请求完整 QUIC 握手）；**h2 不支持，跳过** |
| F | 2000 键多键命中 | — |
| E-pymatrix | 第三方 churn/keepalive | 仅 h1 轮执行（python 仅支持 h1） |

## 3. 结果总表（QPS，成功率全部 100%）

| 工况 | h1 明文 | h1s (TLS) | h2 (TLS) | h3 (QUIC) |
|---|---|---|---|---|
| A. nginx 直连 1K c200 | 375,578 | 376,813 | 355,300 | 374,420 |
| B. 热键 1K c50 | 152,626 | 151,239 | **221,196** | 71,174 |
| B. 热键 1K c200 | 263,181 | 228,183 | 257,311 | 78,191 |
| B. 热键 1K c500 | 362,137 | 303,481 | 278,167 | 67,331 |
| B. 热键 1K c1000 | **373,779** | 322,732 | 291,376 | 82,172 |
| C. 命中 10K c200 | 222,245 | 166,491 | 222,112 | 52,843 |
| C. 命中 100K c200 | 148,410 | 75,675 | 46,489 | 12,338 |
| C. 命中 1M c200 | 31,148 | 13,504 | 8,707 | 1,293 |
| C. 命中 10M c200 | 3,294 | 1,268 | 1,062 | 125 |
| D. miss 256K c200 | 7,664 | 6,804 | 6,639 | 4,914 |
| D2. L2 命中 256K c200 | 52,766 | 27,384 | 21,962 | 4,429 |
| E. churn 1K c200 | 15,701 | 13,257 | — (不支持) | 4,415 |
| F. 多键命中 c200 | 224,719 | 181,806 | **226,768** | 65,889 |

p99 延迟（ms）：

| 工况 | h1 | h1s | h2 | h3 |
|---|---|---|---|---|
| B. 热键 c200 | 3.0 | 3.7 | 3.0 | 6.5 |
| B. 热键 c1000 | 9.9 | 11.0 | 11.0 | **116.8** |
| C. 命中 100K | 4.9 | 7.2 | 8.1 | 113.7 |
| C. 命中 10M | 110.7 | 280.0 | 342.5 | 3159.5 |
| D. miss 256K | 83.5 | 84.6 | 86.3 | 249.1 |
| F. 多键 | 3.5 | 4.1 | 3.2 | 29.9 |

有效吞吐（C 组大文件，按总字节/采样时长折算）：

| 尺寸 | h1 | h1s | h2 | h3 |
|---|---|---|---|---|
| 100K | 121.6 Gbps | 62.0 | 38.1 | 10.1 |
| 1M | 261.4 Gbps | 113.3 | 83.9 | 10.8 |
| 10M | **275.5 Gbps** | 105.3 | 88.2 | 10.5 |

proxy CPU 占用（% of one core，采样均值）：

| 工况 | h1 | h1s | h2 | h3 |
|---|---|---|---|---|
| B. 热键 c200 | 313 | 294 | 431 | 215 |
| B. 热键 c1000 | 434 | 414 | 462 | 215 |
| C. 命中 10K | 314 | 261 | 392 | 217 |
| C. 命中 10M | 405 | 308 | 317 | 176 |
| D. miss 256K | 349(+28% nginx) | 340(+26%) | 334(+26%) | 215(+1%) |
| F. 多键 | 320 | 290 | 412 | 224 |

## 4. 与上一轮（同代码基线 h1 口径，PR #29 前）对比

同机同矩阵 h1 轮与 post-merge 报告对比，验证 PR #29 收益：

| 工况 | 上轮（#28） | 本轮 h1 | 变化 |
|---|---|---|---|
| B. 热键 c200 | 74,805 | **263,181** | **×3.5** |
| B. 热键 c1000 | 76,067 | **373,779** | **×4.9** |
| C. 命中 10M | 1,242 (12.9 GB/s) | **3,294 (34.5 GB/s)** | **×2.7**，已达单线程内存写带宽 |
| F. 多键 | 226,783 | 224,719 | 持平（CPU 上限） |
| D. miss | 42,703* | 7,664 | 口径不同：上轮为固定键空间 L2 命中向，本轮 rand-regex 为真 miss 回源（nginx CPU 26–28% 佐证） |

\* 上轮 D 组使用有界键空间，命中 L2 后近似 D2；本轮 D2（52,766）与上轮 D（42,703）同口径可比，+24%。

## 5. 分析

### h1 → h1s（TLS 成本）

- 小对象（1K/10K）：QPS 损失 ~13–25%（每连接握手摊薄 + 每 16KB 一条 TLS record 的 AES-GCM 加密封装）；p50 仅 +0.1–0.3ms。
- 大对象：损失随尺寸放大（100K −49%、1M −57%、10M −62%）——加密吞吐是主约束，loopback 上 AES-NI 下单连接 TLS 加密 ~1.3 GB/s/核的量级。
- churn 工况 h1s 只比 h1 低 16%（13.3k vs 15.7k）：握手成本被连接建立/销毁的固定开销掩盖。

### h2

- 小对象高并发下与 h1 持平或略优：B-c50 221k vs h1 152k（同 50 在途，h2 只用 12 条 TCP，连接级内核开销更低）；F 组 226k 持平。
- 大对象明显劣于 h1s（100K −39%、1M −36%）：16KB DATA frame 切分 + 流控窗口 + 单连接 HoL；p99 全面走高。
- 但 proxy CPU 反而更高（B 组 403–462% vs h1 313–434%）：h2 帧层解析/HPACK 解码每请求 CPU 更贵，吞吐持平意味着单位 QPS 成本更高。
- oha 不支持 h2 连接 churn，E 组缺测。

### h3

- 全面显著低：1K 命中 ~80k（h1 的 21%），10M 吞吐 ~10.5 Gbps（h1 的 4%）。
- proxy CPU 被钉在 ~2.1–2.2 核且不再随并发增长——瓶颈不是会话/缓存层，而是 QUIC 数据面：每 1200B UDP 数据报的 sendmsg/recvmsg syscall、AEAD 封包、h3 帧解析全在用户态（quinn），无 GRO/GSO/内核加速，单连接吞吐上限低；c500/c1000 时 p99 出现 66–117ms 排队尾巴，呈典型 CPU-数据面饱和形态。
- E-churn 4,415 QPS：每请求一次完整 QUIC 握手（1-RTT + 证书校验 + AEAD 密钥推导），符合预期量级；连接复用后 B 组立刻到 ~80k，说明握手面与数据面成本占比悬殊。
- 定位：当前实现功能正确（100% 成功率），但数据面距生产可用差距大。优化方向（仅记录）：quinn 开 `gso`/增大 UDP 批处理、提升 `max_concurrent_bidi_streams` 上限、零拷贝 SEND 路径、H3 负载端多线程分摊。

### 横切结论

- 缓存/锁/回源层对协议完全透明：协议差异全部体现在接入层 CPU 与每流吞吐上，D/D2 组四协议同序（miss 都受回源 CPU 限制）。
- 单位 QPS CPU 成本排序：h1 ≈ h1s < h2 ≪ h3（h3 数据面 ~4.5× h1）。
- 生产建议（不改动）：小规模密钥/高 QPS 场景 h2 接入划算（连接数省内核）；大对象分发 h1s 仍最优；h3 当前仅建议用于真实有 QUIC 需求的边缘接入，且需压测数据面后再放量。

## 6. 本轮代码变更（支撑四协议测试）

- `src/bin/bench-proxy.rs`：`BENCH_TLS_CERT`/`BENCH_TLS_KEY` 环境变量存在时启用 `TlsSettings::intermediate` + `enable_h2()` + `add_tls_with_settings(:8443)`，并新增 `bench_h3` 模块在 UDP :8443 起 quinn Endpoint，逐连接 `h3::server` → `H3DownstreamSession` → `ServerSession::new_custom` → `process_new_http`（复用生产 `src/http3_proxy_manager.rs` 的移交模式；不依赖 ConfigStore）。
- `src/bin/bench-h3-load.rs`（新增）：oha 无 h3 支持，按 oha JSON 输出格式自写 QUIC 压测端（多连接 × 多流 round-robin、`--churn` 每请求新握手、`--urls-file`）。
- `scripts/perf/run_perf_matrix.sh`：`PROTO` 环境变量驱动四轮；并发归一化（在途=恒定）；h2/h3 churn 与 rand-regex 的降级映射；A 组强制 h1 直连；自签名证书按轮生成于 `$RESULTS/tls/`。
- `/etc/nginx/sites-available/perf-origin`：`location /miss/` 改用 `try_files /miss-payload-256K.bin =404`（修复 alias 拼接 URI 导致 404），任意 miss key 均回 256K 固定体。

## 7. 复现

```bash
sudo nginx                                    # 源站 :8081
cargo build --release --bin bench-proxy --bin bench-h3-load
for P in h1 h1s h2 h3; do
  DUR=15s MISS_REQUESTS=32768 PROTO=$P \
    bash scripts/perf/run_perf_matrix.sh perf-results/<ts>-$P
done
```
