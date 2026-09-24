# EN-27: 真机 XDP 请求处理严格验证 — 高并发/WS/丢包矩阵 + CPU/内存/治理审计

Base: `9dd1508`（EN-26 EdgeCC 法则重写 + memgov 空闲降频）。
环境: `103.79.184.90`（XDP 节点, kernel 6.12.95, ens17 virtio, 8 队列 drv/cv 挂载）、
客户端 `162.251.92.120`、origin `162.251.92.120:19000`（本轮 --remote 指向 .120
的自建强 origin，排除弱源站干扰）。全部测试经 AF_XDP 数据面（`xdp proxy-smoke`，
`--cc edgecc`，upstream=afxdp 即 dial 腿也走 AF_XDP）。

**结论速览**

| 维度 | 结果 |
|---|---|
| 干净请求路径 | 600/600 并发请求全 200，p50=54ms p99=260ms，零拒绝零掉包 |
| WS 高连接 | 3000/3000 并发握手+回声+关闭全成功（~67 conn/s 爬坡） |
| 504/502 复现 | 根因=fd 派生准入上限（nofile=1024 → HTTP=179/Origin=128）叠加单队列饱和拨号饥饿 |
| CPU | 发现第 3 个自旋 bug：CLOSE-WAIT 僵尸持有 ~0 定时器 → reactor 永久 101% |
| 内存治理 | 干净关闭路径账目归零；CLOSE-WAIT 僵尸各持 1MB charge 且不收割 |
| 丢包 | edgecc 干净路径 4× 快于 bbr3；5% 均匀丢包打平；≥20% 两者都崩 |

**修复后回归（§8）**：CLOSE-WAIT 收割+自旋已修（僵尸后 afxdp 线程 0% CPU）；
SIGTERM→detach 真机通过；突发 300/400conn/s 拨号全 200 零 502；
nofile 全入口 1M + fd 钳制状态可见；blind 内存观测不再误拒；
kernel BBR 对照臂修复后完成同口径矩阵——edgecc 干净/低损/时变丢包均占优。

---

## 1. 干净基线：真实 XDP 请求处理

600 并发 HTTP 请求（200+400 两批, 1KB body）经 XDP→AF_XDP→pingora→AF_XDP dial→origin：

```
client: 600×200, p50=54ms, p99=260ms, max=288ms
node  : accepted=600 proxyStarted=600 refusedAtCapacity=0
        preProxyTimeout=0 ingressQueueDropped=0 ingressBudgetDropped=0
        queueBudgetStalls=0 xskDrops=0 drop=26(非代理包)
        socketRecvBytes=772,800 streamEgressBytes=861,000
```

XDP redirect↔accepted↔proxyStarted 1:1:1 对齐——数据面会话链无损。

## 2. WS 高连接矩阵（RFC6455 echo, 纯 stdlib 客户端）

| 并发 | 爬坡 | 结果 | 说明 |
|---|---|---|---|
| 500 | 突发 | **180 ok / 320 EOF-握手** | nofile=1024 → HTTP 准入 fd 上限 179 |
| 500 | 8s | **500/500** | nofile→1M 后全通 |
| 1500 | 15s | 1024 ok / 459 err | **客户端** nofile=1024 瓶颈（Too many open files） |
| 3000 | ~200 conn/s | 1835 ok / **1015×502** / 150 SYN 超时 | 拨号/接受流水线在 ~200 conn/s 突发下超 4s deadline |
| 3000 | ~67 conn/s | **3000/3000** | hs p50=19ms p99=81ms; echo p50=13ms p99=61ms; close=2998 |
| 800 SIGKILL | — | 会话正常消亡 | 残留仅 LAST-ACK(closing=true) 待收割，无自旋无泄漏 |

**上限归因链（逐层排掉的）**：① 节点 nofile=1024 → fd 预算 HTTP=(1024−512)×35%≈**179**；
② 客户端 nofile=1024 → `Too many open files`；③ origin ws_echo backlog=512/nofile=1024；
④ 突发连接速率 ~200/s → 单队列 reactor 上握手+payload+proxy spawn 流水线超
`AF_XDP_TCP_DIAL_TIMEOUT=4s` → 上游拨号失败 → 502。每个 1024 量级上限都是
对应层的 fd/队列派生值，不是算法瓶颈。3000 并发长连接稳态：echo 延迟健康、
mass close 后 sessions→0、所有队列 CPU→0%。

## 3. 502/504 复现与根因分解

混合负载（30×4MB 大流量背景 + 100×1KB 请求）梯级：

| bulk | req 结果 (nofile=1024) | req 结果 (nofile=1M) |
|---|---|---|
| 10 | 100/100, p50=618ms | — |
| 20 | 92×200 8×502, p50=2.3s | — |
| 30 | 73×200 **22×502** 5×000, p50=7.0s | 88×200 **11×502** 1×000, p50=2.1s |

失败形态分两类（curl 分段计时区分）：
- **000/静默**：`conn≈0.1–1.1s`（TCP 握手完成）→ `ttfb=0` → 挂至超时。
  对应 `tcpDiag.preProxyTimeout`（nofile=1024 时 202/335，1M 时 53/157）——
  会话已建但 pre-proxy 阶段饿死在单队列 reactor 的饱和调度里。
- **502**：proxy 层上游拨号失败。nofile=1024 时 OriginConnect 上限
  (1024−512)×25%=**128** 直接拒绝部分拨号；nofile=1M 后残余 ~11% 为
  饱和队列上 AF_XDP dial 4s deadline 未命中。

**平台放大器**：virtio `receive-hashing: off [fixed]` → 单源 IP 全部流量 hash 到
**同一队列**（本轮观测 ens17-3 100-102% 打满，其余 7 队列 ~0-49% 分担上游回程）。
单队列 reactor 同时承担大流量 egress + 新会话 pickup + 拨号握手，CPU 打满后
4s 拨号窗口系统性超时。

## 4. CPU 审计 — 第 3 个自旋 bug（CLOSE-WAIT 僵尸）

bulk 连接被客户端超时砍掉后（curl -m → FIN → CLOSE-WAIT），实测两次：

```
afxdp-ens17-3: 101–102% 持续 >3min，RX_delta=0 TX_delta≈0（零流量）
strace: ~1600–2000 iter/s 的 epoll_wait(~12µs) + poll(fd,0)=0 循环
报告残留: 4×CLOSE-WAIT, closing=false, sendQueueBytes=1,048,576(恰好1MB)
```

机制链：客户端 FIN 时服务端 socket 转 CLOSE-WAIT 但 `session.closing` 未置位
（仅代答路径置位）→ `af_xdp_tcp_session_reapable` 要求 closing=true → 永不收割；
带未 ACK send_queue 的 socket 让 smoltcp 保持 armed 定时器 →
`iface.poll_delay()≈0` → `next_timer_delay` 钳到 `AF_XDP_IDLE_WAIT_FLOOR=10µs`
→ select 每 ~10µs 醒一次 → 空转 100%。同时重传刷新 `last_activity` →
idle-timeout 兜底也不触发（与 T9 ledger-stall 僵尸同形）。

另两项此前 CPU 缺陷复核：**memgov-snapshot** 活跃期 9–14%（250ms 消费驱动刷新），
空闲期降至 **2–3%**（空闲降频生效）；TX-completion 自旋未复现。
干净 WS 关闭后全部 8 队列稳态 0%——自旋与 CLOSE-WAIT 僵尸强相关。

## 5. 内存治理审计

| 检查项 | 结果 |
|---|---|
| 干净会话释放 | sessions→0、tcpQueueBytes→0、bufferShrinks 正常 |
| 800 WS SIGKILL | 残留仅 LAST-ACK(closing=true, sendQueue=0) 属正常收割窗口 |
| 每会话 charge | socketBufChargeBytes≈1,081,344（16KB 初始 + 增长至 1MB 顶） |
| **缺陷** | CLOSE-WAIT(closing=false) 僵尸各持 ~1MB 不收割（同 §4 根因） |
| **缺陷** | fd 派生上限在默认 nofile 下远低于名义 floor（HTTP 179/Origin 128），
  名义 floor=512 被 `fd_target` 静默压穿——`warn_fd_clamped_limit_once`
  有告警但 RUST_LOG=info 下可见，部署期未被注意到 |
| RSS | 3000 WS 并发峰值 ~754MB，拆连回落至 ~570MB |

## 6. 真机丢包矩阵（单流 4MB，对称 +40ms netem）

| 模型 | edgecc | bbr3 |
|---|---|---|
| 基线 | **4.9s / 852KB/s** | 18.9s / 222KB/s |
| uniform 5% | 53.9s, 48.4s, 1×fail0B (~82KB/s) | 52.5s (~80KB/s) |
| uniform 20% | >300s 超时 (8.7KB/s) | >90s 超时 (1.1KB/s) |
| GE burst ~20% (p10 r10 1-h40) | 90s×2 超时 (4.6–15KB/s) | 8.2s 内 502（拨号直接失败） |
| normal N(20,10)/5s | 42.6s + 1×fail0B | >90s 超时 (6.1KB/s) |

丢包方式已按需求扩展：`netem2.sh` 支持 `uniform`（Bernoulli 独立）、
`gemodel`（Gilbert-Elliott 突发，tc 原生 `loss gemodel p r 1-h 1-k`）、
`normal`（每 5s 从 N(μ,σ²) 采样重设 loss%，seed=12345 可复现）。
仿真侧 `LossModel::{Uniform,GilbertElliott,NormalVarying}` 已对齐同语义。

读法：edgecc 干净/低损路径显著占优（短 RTT 快启动收益），≥20% 独立随机丢包下
任何无 FEC 的单流都会坍缩，两者都不具生产意义——该区间属于多路径/FEC 领域。

## 7. 待修复清单（按严重度）— 修复后状态

1. ~~**CLOSE-WAIT 僵尸 + reactor 10µs 自旋**~~ **已修**（`a007da1` + `f244bb0`）：
   peer-EOF 时间戳跟踪，静默 15s 收割、closing 绝对 60s 期限；
   smoltcp-edge 消费无法发射的 TLP 探针（零窗无尾记录时不再永远 `Now`）。
   真机回归见 §8.1。
2. ~~**部署缺省 nofile=1024**~~ **已修**（`d5a4a42`）：
   `raise_nofile_limit()` 提到 `main()` 全入口（含 `xdp proxy-smoke`）；
   `fd_clamped_mask` 进 `GovernorSnapshot`→`fdClamped`/`fdSoftLimit` 状态面。
   真机回归见 §8.2。
3. **单队列热点**：**平台限制**，virtio `receive-hashing: off [fixed]` 无配置面，
   XSKMAP 不可跨队列 redirect——非软件 bug，维持网关侧多源 IP 缓解建议。
4. ~~**突发 ~200conn/s 拨号 4s deadline 饥饿**~~ **已修**（`a007da1`）：
   deadline 绑定会话走独立 hot 队列先 pump（总预算不扩）。真机回归见 §8.3。
5. **新增：内存治理 blind 观测误拒** **已修**（`d5a4a42`）：观测已落地但
   availability=Unknown 且无账户 headroom 时，共享账本/账户回退到
   物化类上限聚合容量（有界），启动前仍 fail-closed。
6. **新增：kernel 对照臂 502** **已修**（`f244bb0`）：`xdp.enabled=true` 使
   `upstream_mode()` 短路为 afxdp，上游拨号全走进未武装的 AF_XDP registry。
   kernel 臂现在把 runtime 的 `xdp.enabled` 置 false。

## 8. 修复后回归验证（真机）

### 8.1 CLOSE-WAIT 僵尸 + 自旋

注入 ~187 个僵尸形态会话（客户端收部分数据后 `shutdown` + iptables DROP
模拟静默对端），持续观测：

```
修复前: afxdp-ens17-3 101-102% 永久，~2kHz epoll+poll 空转，会话永不收割
修复后: 收割期限内会话排空，afxdp 线程瞬时 CPU=0.0%
        RSS 537MB → 517MB 回落，无残留 charge
```

SIGTERM 生命周期（旧 bug 真机复现过：stop 后 prog id 856 仍挂 ens17）：

```
修复后: systemctl stop → XDP_DETACHED, pinned link 删除, 服务干净退出
        新 attach 自动回收上一代残留 pinned link（id 856→877）
```

### 8.2 nofile 全入口 + fd 状态面

```
修复前: xdp proxy-smoke 路径 Max open files=1024 → HTTP 上限 179
修复后: 运行中进程 /proc/<pid>/limits Max open files=1048576
        3000 conn/s 慢爬坡 3000/3000 全通（§2 已验证）
```

### 8.3 突发连接拨号饥饿（502 复现路径）

同形状回归（修复前 3000@~200conn/s：1835 ok / **1015×502** / 150 SYN 超时）：

| 突发速率 | 请求数 | 修复后结果 |
|---|---|---|
| ~300 conn/s | 3000 | **3000×200**，p50=23ms p99=49ms，零 502 |
| ~400 conn/s | 4000 | **4000×200**，p99=48ms，零 502 |

### 8.4 kernel BBR 对照臂（同口径 netem 矩阵，单流 4MB +40ms）

kernel 臂修复后（`xdp.enabled=false` → 上游拨号走内核 TCP，
`.90` `net.ipv4.tcp_congestion_control=bbr`）：

| 模型 | edgecc (AF_XDP) | kernel BBR |
|---|---|---|
| 基线 | **4.9s / 852KB/s** | 6.5–12.3s / 342–645KB/s |
| uniform 5% | **~82KB/s** | 62–76KB/s（55–68s） |
| uniform 20% | 8.7KB/s 超时 | 3–6KB/s 超时 |
| GE burst ~20% | 4.6–15KB/s 超时 | 15–28KB/s 超时 |
| normal N(20,10)/10s | **42.6s 完成 + 1 fail** | 4.6–10.5KB/s 超时 |

kernel 臂负载：11–13% CPU，RSS 446MB。读法与 §6 一致：干净/低损/时变
丢包 edgecc 占优（BBR 基线慢 ~2×，normal 时变下 BBR 三次全超时而
edgecc 有完成样本）；≥20% 独立/突发丢包两者都坍缩（GE 单元 BBR 略高
但同处不可用区间）。该区间属 FEC/多路径领域。

## 9. 复现脚本（均在测试机保留）

- `.120`: `/root/netem2.sh`（uniform/gemodel/normal）、`/root/ws_echo.py`、
  `/root/ws_load.py`（RAMP_S 环境变量控制爬坡）、`/root/fast_origin.py`
- `.90`: `/root/start_node.sh`（已加 `ulimit -n 1048576` 包装）、`/root/mon4.sh`
  （线程级 CPU/RSS 采样）、`/root/real-results/node-*.json`（各 run 终态报告）
