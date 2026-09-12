# 防御性能测试报告（WAF / CC / UAM + L4 攻击防御）

- 日期：2026-09-12（基线 commit `f8e1fe9`，即 PR #30 合并后的 main）
- 目标：验证并量化 WAF（规则匹配/CC 限速/UAM 挑战）与 L4 防御（空连接洪水、慢首字节、慢头、tiny-request、TLS 握手耗尽、连接保持、SYN 洪水、UDP 洪水）的拦截效果、代价与对合法流量的影响。

## 测试拓扑

```
oha / bench-l4-attack / hping3 / socat
      │
      ▼  bench-defense（root，完整 HttpProxyManager + TcpProxyManager + UdpProxyManager
      │    + WafStateManager + kernel_syn_defense SYNPROXY 自动调和）
      ▼
  nginx :8081（HTTP 源站）  socat echo :8054（UDP 源站）
```

`bench-defense` 暴露 `:8080 HTTP`、`:8443 TLS`、`:9000 TCP 透传`、`:8053 UDP 透传`，并挂 5 个测试 vhost：

| server | 域名 | 防护 |
|---|---|---|
| 100 | plain.bench | 仅集群 L4 策略（all 端口） |
| 101 | waf.bench | WAF 规则：`${requestPath}` 前缀 `/deny` → block；`${userAgent}` 含 `attackbot` → block |
| 102 | cc.bench | CCPolicy：per_ip_max_qps=500、block_ip、show_page（block 30s） |
| 103 | uam.bench | UAM js_cookie 挑战页 |
| 104 | udp.bench | UDP :8053 → echo :8054 |

集群 L4 策略（cluster 1）：`empty_connection_flood`（200 次/10s → 封 30s）、`tls_exhaustion_attack`（32 次失败 → 封）、`syn_flood`（SYNPROXY 自动启用）。所有 server 均属 cluster 1。

合法流量探针固定源 `127.0.0.1`（8 条 keep-alive 长连接，限速重连）；每个攻击阶段使用独立的 `127.0.0.x` 源 IP 池（loopback 全 127/8 本地路由），保证 per-IP 封禁不串扰阶段间数据与合法流量。

## 硬件与环境

| 项 | 值 |
|---|---|
| CPU | Intel Xeon Platinum 8559C，8 vCPU @ 2.4GHz（L1d 192KiB / L2 8MiB / L3 320MiB，aes+avx2+avx512f） |
| 内存 | 31GiB，无 swap；实测带宽：单线程写 34.7GB/s、8 线程读 123.6GB/s |
| 磁盘 | virtio vda 128GiB；实测写 2.4GB/s、读 12.6GB/s |
| OS | Ubuntu 22.04.5，kernel 5.15.200，ip_local_port_range 32768-60999，tcp_syncookies=1 |
| 软件 | nginx 1.18.0、oha 1.16.0、hping3、nftables（SYNPROXY）、socat |

## 发现并顺带修复的 bug

**`kernel_syn_defense.rs`：SYNPROXY 规则永远装不上。** nftables 规则注释（`cloud-node synproxy …`）经 argv 拼接成单行命令后未加引号，`nft` 解析到多词注释即报 `syntax error, unexpected synproxy` → 整个自动防护在生产上形同虚设。已修复（`with_rule_comment` 以带引号形式追加注释，`synproxy_rule_args` 末尾改为 `"comment"` 占位走统一补注释路径）。修复后实测 SYNPROXY 三条规则（notrack / synproxy / drop-invalid）与 sysctl 调和全部生效。`kernel_syn_defense` 单测 10/10 通过。

## L7 / WAF 组结果

### WAF 规则求值开销（keep-alive，32 连接，`file-1K.bin`）

| 路径 | 总请求 | 吞吐 | 节点 CPU |
|---|---|---|---|
| plain.bench（仅集群策略） | 698,429 / 20s | **34,921 req/s** | ~5.2 核 |
| waf.bench（2 条规则 eval） | 639,601 / 20s | **31,980 req/s** | ~5.0 核 |

WAF 求值开销 ≈ **吞吐 −8.4%**（每请求 ~+4.4µs）。规则数少（prefix + contains），属合理量级。

### WAF block 请求

`/deny/x` 命中 block：首个 403 返回 14,106B 拦截页，**之后服务端主动关闭连接**（响应头虽声明 keep-alive，实际每个 403 后连接即断）。因此 per-IP 拦截速率天然受 accept 通道约束：每个 IP 约 800 个 403/10s 后，`tcp_accepted_churn` 将其 L4 封禁 30s——拦截行为本身完成了对"持续打 block 路径"客户端的自动掐断。

### CC 攻击（重点）

| 场景 | 攻击形态 | 结果 |
|---|---|---|
| 单 IP 大流量（keep-alive 8 连接打满） | 127.0.0.66 → cc.bench | 服务端放行 ~506×200（≈500/IP/s 窗口额度）→ 403/429 → 每个被拒响应即断连 → 重连风暴触发 `tcp_accepted_churn` → **L4 封 30s**；期间合法流量 548×200（45 req/s 全通） |
| 分布式（16 IP，conn-per-req） | 127.0.0.96-111 → cc.bench | 共 ~6,398×200 后全部源 IP 被 accept-churn 封禁——L4 兜底了每连接一请求的慢速 CC |

CC 链路（L7 限额 → 关连接 → L4 重连风暴封 IP）工作正常且形成纵深防御。**注意**：`max_qps`（全局限额）=0 未启用；若攻击者在 ~80 conn/s/IP 以内用 keep-alive 分布式低速打请求且每 IP <500 req/s，现有 per-IP 限额拦不住（无全局限额兜底）——值得知悉。

### UAM 挑战

UAM js_cookie 挑战为一次性响应 + 关连接（客户端需带 UAM-Token cookie 重试），故挑战发放率天然被 per-IP accept 限额约束（~80 conn/s/IP 持续、800 突发/10s）。8 IP 攻击下挑战发放被 L4 掐在 ~1k 页后全部封禁，节点 CPU 均值 ~0.9 核——挑战页生成代价低，L4 先行拦截使七层几乎无消耗。

## L4 攻击防御组结果

| 攻击 | 强度 | 防御动作（L4METRICS 增量 / 日志） | 攻击期合法流量 goodput |
|---|---|---|---|
| **churn**（connect 即断，空连接洪水） | 150,506 conn / 18s（~8.4k/s，8 IP） | 8 个源 IP 全部 `EMPTY_CONNECTION_FLOOD` 封 30s（~201 hits/10s/IP 触发）；blocked=8；内核侧 ListenDrops +332 | 隔离复测 ~1.3k req/s（基线 ~30k+/s）——洪峰窗口内合法新建连接被 accept 通道挤压严重下降；攻击源封禁后 accept 压力缓解 |
| **hold**（连上不发数据，慢首字节） | 200 并发 ×4s hold，1,434 次 | slow_close 计数 +1,132，被 slow-first-byte 超时（2s）逐个清掉；未触发封禁（速率低于 churn 阈值） | **423,373 次（28.2k/s）≈ 正常水平** |
| **slowhdr**（慢速滴灌头部） | 100 连接，300ms/行 | slow_close +68；连接被正常掐掉 | **423,477 次 ≈ 正常** |
| **tinyreq**（write 16B 即断） | 713,595 次 / 18s（39.4k/s） | `http_early_close_or_tiny_request` 封 11 个 IP；slow_close +813；admission_reject +1,847 | 220,936 次（14.7k/s，~50%） |
| **tls-fail**（TLS 端口打垃圾字节） | 285,141 conn / 20s | `TLS_EXHAUSTION_ATTACK`：8 个源 IP 各 ~33-34 hits 即封 | 127,539 次（8.5k/s） |
| **conn-hold**（保持 3000 长连接） | 3000 尝试 → 1,015 成功（4 IP） | per-IP 活跃连接上限生效：每 IP ~250 后 errors=1,985 拒连；slow_close +111 | **452,040 次（30.1k/s）= 满速** |
| **SYN 洪水**（hping3 --rand-source --flood） | **3,681,347 SYN / 15s ≈ 245k pps** | SYNPROXY + syncookies 内核兜底：SyncookiesSent +276k、ListenDrops +3.39M、EmbryonicRsts +599；syn_pressure 短暂 elevated；节点进程基本无感 | **392,311 次（26.1k/s）≈ 满速** |
| **UDP 洪水** | 22,714,368 数据报 / 15s ≈ 1.5M pps | `udp_session_flood` 封 127.0.0.212 等 | **合法 UDP echo 0/100** —— 单进程 UDP relay 在百万 pps 下入队耗尽，合法 UDP 被饿死（见结论） |

TCP 侧另观测到 per-IP `tcp_admission_reject` 计数与 `admission` 许可门禁：攻击压力下合法连接偶发被拒，被拒计入合法 IP 自身计数，可能形成短暂自我封禁（反馈回路），实测中合法探针（限速重连 ≤16 conn/s）未越线。

### 封禁隔离验证

每阶段结束后立即检查：`curl --interface <攻击源>` → `000`（连接被 drain），`127.0.0.1` → `200`。churn/tinyreq 阶段验证通过——**per-IP 封禁不殃及其他源 IP**。

### 资源占用

| 阶段 | 节点 CPU 均值/峰值 | RSS 峰值 |
|---|---|---|
| WAF 满速（plain/rules） | ~5.0-5.2 核 | 5.0GB |
| churn | 0.13 / 1.2 核（封禁后纯 drain 极廉价） | 5.2GB |
| hold / slowhdr | ~3.0-3.5 核 | 7.0-8.9GB（保持的连接状态） |
| conn-hold | 3.5 / 5.0 核 | 12.6GB |
| synflood | 3.1 / 5.0 核 | 14.3GB |
| udpflood | 1.0 / 2.7 核 | 14.4GB |

## 结论与风险点

1. **L4 防御整体有效**：8 类攻击全部触发对应检测并隔离攻击源 IP；内核 SYNPROXY/syncookies 在 245k pps SYN 洪水中保住握手通道，合法流量满速通过。
2. **修复的真实 bug**：SYNPROXY 注释未加引号导致规则从未真正安装（本次修复）。
3. **CC 纵深良好但缺全局限额**：per-IP 500 req/s + block_ip + L4 churn 兜底有效；`max_qps`（全局）=0 未启用时，低于每 IP 阈值的低速分布式 CC 没有防线。
4. **accept 通道是公共瓶颈**：合法流量与攻击共享同一 accept 路径——在 ~8-40k conn/s 连接类攻击的洪峰窗口内，合法新建连接的 goodput 可降至 ~5%（连接被拒/超时）。攻击源被封禁后恢复。多 accept worker 数（当前每监听 2 个）与压力期准入策略有优化空间。
5. **UDP 洪水无本地限速兜底**：udp_session_flood 能封源，但 1.5M pps 的 socket 队列饿死发生在线程内调度层，合法 UDP 丢包 100%。建议上游/内核侧（nftables limit、SO_REUSEPORT 分散）缓解。
6. **WAF 求值 ~8%** 吞吐开销，路径健康。
7. block/挑战响应"连接即断"语义使每个拦截消耗一次 accept 周期——封禁叠加 L4 后等价于自动掐断，属合理设计但值得知晓（错误响应体的 keep-alive 头与实际关连接行为不一致，可视为小 bug）。

## 复现方式

```bash
cargo build --release --bin bench-defense --bin bench-l4-attack
sudo bash scripts/perf/run_defense_matrix.sh           # 输出至 perf-results/<ts>-defense/
# 可调环境变量：BENCH_CC_PER_IP_QPS / BENCH_L4_EMPTY_THRESHOLD / BENCH_L4_PERIOD /
#   BENCH_L4_BLOCK_SECS / BENCH_TLS_FAIL_THRESHOLD / BENCH_SYN_MIN_ATTEMPTS / BENCH_UAM_MODE
```

原始数据：`perf-results/20260912-023659-defense/`（attack/legit JSON、L4METRICS 增量、nstat、CPU 采样、bench-defense 全量日志）。攻击工具 `src/bin/bench-l4-attack.rs` 支持 8 种攻击模式与多源 IP 轮换。
