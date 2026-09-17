# 合并版本性能对比报告（memory-governance merge vs 1.2.7 vs AF_XDP）

- 日期：2026-09-18
- 被测对象：
  - **v1.2.7**：发行版基线，XDP 关闭（该版本的 XDP 实现不完整，按要求不启用）。源码导出 `/root/cloud-node-v127`，`cloud-node-rust` sha256 `f5e7a55b40163d4eab4b8234b79f341f6c2ef91ac54cdd4b8fb7f2177bbfa091`，`bench-proxy` sha256 `dd22a07f1a60d740f860c1e11ba5e9707bfc6f65e196fe20cd5ef679e2e19b01`
  - **merged**：`main @ e4ff329`（合并 `feat/memory-governance-hardening` 后的 main，含 `--kernel` 对照补丁）＝ 本次合并推送结果。`cloud-node-rust` sha256 `f61ca375ee5713e45735cf7a014147d2ca923b631362bcc2c6a3375c6c4b88d8`，`bench-proxy` sha256 `2337a8dc77af0360b86b17981d5ac30a7925fa2b8f5f5bb6dd4cc9708d5785c8`
- 工具链：rustc 1.98.1，release profile `lto = "fat"`、`codegen-units = 1`、`panic = "abort"`
- 原始数据：`perf-results.tar.gz`（本目录，1.4MB，含全部 oha JSON / 系统采样 / 节点计数器快照）

## 硬件与环境

| 项 | 值 |
|---|---|
| 主机 | devin-build-90（KVM 虚机） |
| CPU | 8 vCPU |
| 内存 | 15 GiB |
| OS/内核 | Debian，kernel 6.1.0-41-amd64 |
| 网卡 | virtio；dataplane 测试使用 veth 对 + network namespace |
| 工具 | oha 1.16.0、nginx（origin :8081）、h3_probe/bench-h3-load、自研 TCP/UDP prober |

## 测试拓扑

两层基准分开测量，结论不可互相套用：

**A. 协议/缓存矩阵（bench-proxy）** — Pingora 层基准，不挂生产 XDP：

```
oha (netns "bp") → bench-proxy :8080 → nginx :8081 → /srv/perf-origin
```

v127 与 merged 均以 XDP-off 运行；merged 额外跑 h1s/h2/h3 四协议全矩阵。

**B. 真实数据面 A/B（proxy-smoke）** — 同一 EdgeProxy 栈、同一组内嵌后端，唯一变量是入包路径：

```
loadgen (netns "cnpeer") → veth → [ kernel socket 监听 | XDP→AF_XDP 用户态栈 ]
                                      → in-process backends (h1/h1s/tcp/udp/h3/sni/quic)
```

kernel 臂 = `proxy-smoke --kernel`（本次新增的对照模式，非运行时回退）；xdp 臂 = `proxy-smoke`（attach skb，XdpRuntimeMode=proxy）。

**veth 前置条件（本次实测确认）**：veth 默认不做真校验和，AF_XDP 用户态 TCP 栈会丢弃校验和无效包。必须两端关 offload 后测试才有意义：

```bash
ethtool -K $HOST_IF tx off rx off tso off gso off gro off
ip netns exec $NS ethtool -K $PEER_IF tx off rx off tso off gso off gro off
```

未关 offload 时表现为：包全部 redirect 进 XSK、`drop=0`，但 TCP `accepted=0` —— 属测试环境配置问题而非代码缺陷。

## A. 协议/缓存矩阵：v1.2.7 vs merged（均 XDP-off，HTTP/1.1）

oha，c200（标记者除外），每轮独立进程、采样 CPU/RSS。成功率两侧均为 1.0。

| run | v127 rps | merged rps | 比值 | v127 p50ms | m p50ms | v127 p99ms | m p99ms | v127 cpu% | m cpu% | v127 rssMB | m rssMB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A-origin-1k-c200 | 23935 | 23776 | 0.99x | 7.1 | 7.0 | 27.2 | 27.3 | 3.7 | 3.9 | 36.2 | 104.7 |
| B-hit-1k-c50 | 542 | 28641 | 52.81x | 62.9 | 1.3 | 454.5 | 16.9 | 128.6 | 437.5 | 45.1 | 120.7 |
| B-hit-1k-c200 | 543 | 29052 | 53.50x | 270.5 | 5.4 | 1537.1 | 29.2 | 195.6 | 445.4 | 55.6 | 137.4 |
| B-hit-1k-c500 | 443 | 27191 | 61.43x | 696.2 | 14.7 | 5796.0 | 58.4 | 288.5 | 464.1 | 82.7 | 162.4 |
| B-hit-1k-c1000 | 121 | 27637 | 228.16x | 6292.4 | 30.2 | 19027.1 | 116.6 | 169.8 | 448.0 | 124.0 | 208.0 |
| C-hit-10K-c200 | 481 | 24616 | 51.23x | 313.1 | 6.4 | 1735.3 | 33.1 | 187.3 | 454.4 | 122.8 | 168.4 |
| C-hit-100K-c200 | 389 | 14624 | 37.60x | 381.5 | 10.9 | 2108.2 | 50.5 | 179.0 | 413.2 | 123.8 | 134.8 |
| C-hit-1M-c200 | 118 | 2551 | 21.69x | 1261.9 | 74.0 | 7205.6 | 188.3 | 146.9 | 425.0 | 125.3 | 134.1 |
| C-hit-10M-c200 | 24 | 263 | 10.82x | 6108.7 | 751.7 | 19192.0 | 1638.1 | 132.6 | 414.9 | 125.5 | 143.0 |
| D-miss-256k-c200 | 1027 | 681 | **0.66x** | 167.6 | 220.2 | 501.7 | 1496.8 | 452.6 | 399.0 | 170.9 | 337.4 |
| D2-l2hit-256k-c200 | 1118 | 6486 | 5.80x | 156.3 | 25.5 | 531.3 | 94.2 | 473.8 | 419.8 | 203.9 | 942.1 |
| E-hit-1k-churn-c200 | 459 | 1375 | 2.99x | 326.0 | 136.1 | 1763.7 | 356.9 | 194.6 | 131.2 | 204.2 | 954.7 |
| F-hit-many-c200 | 2841 | 21203 | 7.46x | 61.2 | 7.6 | 206.9 | 34.1 | 487.1 | 474.7 | 204.2 | 956.1 |
| G-dynamic-1k-c200 | 1558 | 1705 | 1.09x | 107.4 | 81.6 | 366.4 | 449.6 | 511.6 | 418.8 | 218.6 | 1073.6 |

**解读**：

- **缓存命中路径数量级提升**（52–228×）：v127 在 warm-hit 下吞吐被压到 ~120–540 rps 且 p99 秒级；merged 稳定 27–29k rps、p99 < 120ms。这是本轮工作的主要收益。
- **A-origin 持平**（0.99×）：两侧都打到 nginx origin 上限 ~24k rps，代理转发开销不占优也不劣化。
- **D-miss 出现 0.66× 回退**：merged 681 vs v127 1027 rps，p99 1497 vs 502ms。纯 miss 透传路径变慢，疑似与内存准入记账/队列治理有关（merged 引入了 TCP queued-byte 预算与准入票据）。**这是真实回退，不掩盖**，建议后续定位。
- **RSS 全面更高**：merged 105–1074MB vs v127 36–219MB。mimalloc + 治理账本 + 更大的缓存留存是主因；churn/L2-hit 场景 ~950MB 峰值仍受内存治理上限约束、无失控迹象，但与 v127 对比属成本项。
- CPU：merged 在命中场景主动烧满多核换吞吐（430–470% vs 130–290%），属预期（吞吐 50× 的代价）；miss/dynamic 场景 cpu% 反而更低。

## B. merged 四协议矩阵（h1 / h1s / h2 / h3，均 XDP-off）

| run | h1 rps | h1s rps | h2 rps | h3 rps | h1 p99 | h1s p99 | h2 p99 | h3 p99 |
|---|---|---|---|---|---|---|---|---|
| A-origin-1k-c200 | 23776 | 22893 | 24936 | 24479 | 27.3 | 27.5 | 27.2 | 27.3 |
| B-hit-1k-c50 | 28641 | 25158 | 20877 | 16587 | 16.9 | 17.9 | 18.3 | 15.7 |
| B-hit-1k-c200 | 29052 | 25224 | 21374 | 20473 | 29.2 | 32.6 | 38.0 | 40.5 |
| B-hit-1k-c500 | 27191 | 22719 | 22444 | 19246 | 58.4 | 72.0 | 71.1 | 204.6 |
| B-hit-1k-c1000 | 27637 | 23876 | 12735 | 18174 | 116.6 | 133.7 | 245.3 | 544.3 |
| C-hit-10K-c200 | 24616 | 12626 | 16184 | 11969 | 33.1 | 57.9 | 43.7 | 141.8 |
| C-hit-100K-c200 | 14624 | 5892 | 4716 | 2173 | 50.5 | 88.5 | 111.1 | 577.1 |
| C-hit-1M-c200 | 2551 | 767 | 615 | 232 | 188.3 | 601.2 | 637.3 | 2138.0 |
| C-hit-10M-c200 | 263 | 45 | 65 | 27 | 1638.1 | 7515.2 | 5718.3 | 13115.1 |
| D-miss-256k-c200 | 681 | 638 | 778 | 549 | 1496.8 | 993.5 | 704.6 | 1262.5 |
| D2-l2hit-256k-c200 | 6486 | 2467 | 1699 | 880 | 94.2 | 218.3 | 380.9 | 961.1 |
| E-hit-1k-churn-c200 | 1375 | 1091 | 0* | 826 | 356.9 | 479.7 | - | 3051.0 |
| F-hit-many-c200 | 21203 | 19359 | 19110 | 15351 | 34.1 | 39.5 | 39.9 | 65.7 |
| G-dynamic-1k-c200 | 1705 | 2217 | 2096 | 9484 | 449.6 | 329.0 | 307.5 | 53.4 |

\* h2 的 churn 轮 `E-hit-1k-churn-c200` 未产出有效 oha 结果（0 rps），其余组全部完成。

观察：h1 全面最优；h1s 在小对象上损耗 ~13%；h2 在中并发 hit 与 h1 接近、c1000 与大对象上劣化；h3 小对象可用（16–24k rps）但 ≥1MB 对象吞吐塌陷（232/27 rps）、延迟秒级——大响应体的 QUIC 发送路径仍是已知短板。G-dynamic 上 h3（9484）反而最高，说明瓶颈在大对象流控而非 QUIC 本身。

## C. 真实数据面 A/B：kernel vs AF_XDP（同一 merged 栈）

### c50（正确性基线，全部 ~100% 成功）

| 协议 | kernel | AF_XDP | Δ吞吐 |
|---|---|---|---|
| h1 | 897 rps / ok 100% | 1099 rps / ok 100% | +22.5% |
| h1s | 860 rps / ok 100% | 988 rps / ok 100% | +15.0% |
| tcp | 981 cps / 0 err / conn 1.9ms | 799 cps / 0 err / conn 7.9ms | −18.6% |
| udp | 6080 eps / 0 lost / rtt 2.6ms | 5490 eps / 0 lost / rtt 2.9ms | −9.7% |
| h3 | 804 rps / 50000 ok | 859 rps / 50000 ok | +6.8% |
| sni | 891 rps / ok 100% | 635 rps / ok 99.6% | −28.7% |

节点资源（cpu% / rssMB，% 为核占比）：

| 协议 | kernel c50 | xdp c50 | kernel c200 | xdp c200 |
|---|---|---|---|---|
| h1 | 100.6 / 461 | 119.0 / 449 | 101.7 / 466 | 118.5 / 466 |
| h1s | 99.6 / 463 | 116.3 / 455 | 101.7 / 471 | 115.8 / 476 |
| tcp | 99.5 / 466 | 114.7 / 461 | 101.2 / 469 | 115.7 / 474 |
| udp | 92.0 / 463 | 104.5 / 457 | 93.3 / 465 | 110.1 / 469 |
| h3 | 100.6 / 476 | 117.7 / 471 | 102.1 / 482 | 118.4 / 485 |
| sni | 179.7 / 509 | 170.9 / 507 | 142.6 / 531 | 156.5 / 555 |

### c200（饱和点探测）

| 协议 | kernel | AF_XDP |
|---|---|---|
| h1 | 1449 rps / **ok 52.4%** | 1065 rps / **ok 86.6%** |
| h1s | 1305 rps / ok 54.3% | 901 rps / ok 86.4% |
| sni | 2619 rps / ok 15.6% | 673 rps / ok 65.4% |
| tcp | 810 cps / 0 err | 734 cps / 0 err |
| udp | 5974 eps / 0 lost | 6140 eps / 0 lost |
| h3 | 780 rps / 50000 ok | 843 rps / 50000 ok |

错误构成（oha errorDistribution）：

- kernel h1：`connection error` 13,709（accept 通道饱和导致的 connect 失败）
- xdp h1：`connection closed before message completed` 2,834 + `aborted due to deadline` 200（用户态 TCP 会话生命周期在 keep-alive 复用下的早关/超时）

AF_XDP 侧计数器（c200 全程）：`packets=435974 / redirect=435970 / drop=0 / xskDrops=0 / parseErrors=0 / mapMiss=0`；`tcpDiag.accepted=248,890`、`preProxyTimeout=50`；`tcpProxyDiag.backendConnectOk=14678 / backendConnectFail=0 / relayErrors=0`；`tcpQueueBytes=5111`（队列几乎排空）。**结论：c200 的错误是用户态 TCP 会话层并发饱和，不是丢包、不是 eBPF 丢包、不是后端连接失败。**

### 数据面结论

- c50 下 AF_XDP 对 HTTP/HTTPS/H3 有 +7~22% 吞吐优势，对裸 TCP/UDP/SNI 略慢（−10~29%）——内核 socket 对纯 L4 relay 仍更高效；代价是 +10~18% CPU，RSS 持平。
- c200 下 AF_XDP 的 HTTP 成功率（86.6%）显著好于 kernel accept 路径（52.4%）——XSK 批量收包绕过了 accept 瓶颈；但两侧均未完全消化 c200，属容量边界而非正确性问题。
- **不声称 zero-copy**：veth/virtio 不具备 ZC 能力，本次只验证了 skb 模式正确性与相对吞吐。真实 NIC + drv/native 模式待硬件验证。

## 发现并修复的问题

1. **veth offload 必须关闭**（环境配置，非代码 bug）：未关时 AF_XDP 全零成功，已固化进 `scripts/xdp-netns-smoke.sh` 同等要求。
2. **本次新增 `proxy-smoke --kernel`**：同栈内核 socket 对照模式，是显式 A/B 基准臂（非运行时回退），已随本报告提交。

## 已知问题 / 不回退项清单

- **D-miss 0.66× 回退**（merged vs v127）：纯透传 miss 路径变慢，待定位；与内存治理账本相关方向待查。
- **merged RSS 全面抬升**（~3–5× 于 v127）：mimalloc 与治理缓存的成本，数值有界。
- **h3 大对象塌陷**（≥1MB）：沿用已知限制，未恶化也未修复。
- **c200 双臂饱和**：kernel 败在 accept 通道、xdp 败在用户态 TCP 会话生命周期；非丢包。
- **h2 churn 轮无数据**：单轮跑空，不补报。
- **zero-copy 未验证**：无真实 NIC 证据，仅软件路径。

## 复现方式

```bash
# 协议矩阵（远端 /root/cloud-node-rust 与 /root/cloud-node-v127）
bash scripts/perf/run_perf_matrix.sh <h1|h1s|h2|h3>   # 结果落 /tmp/res-<tag>-<proto>/
# 数据面 A/B（veth+netns，先关两端 offload）
bash /tmp/run_dp_matrix.sh kernel 200                  # kernel 臂
bash /tmp/run_dp_matrix.sh xdp 200                     # AF_XDP 臂
# --kernel 对照：cloud-node-rust xdp proxy-smoke --kernel --duration-ms 230000
```

原始 JSON/计数器/系统采样：`docs/perf-reports/20260918-memgov-merge-xdp/perf-results.tar.gz`
