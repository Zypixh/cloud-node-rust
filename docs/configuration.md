# 配置说明

CloudNode Rust 的本地配置很少，主要配置来自控制面。节点本地只需要知道 API 节点地址、节点 ID 和密钥。

## configs/api_node.yaml

默认配置文件位于运行目录的 `configs/api_node.yaml`：

```yaml
rpc.endpoints: [ "http://127.0.0.1:8001" ]
nodeId: "your-node-id"
secret: "your-node-secret"
# 可选，默认 false，保持 FlexCDN/GoEdge 只按下行计费口径
billing.countInboundTraffic: false
# 可选，默认 false。SNI/TCP relay 默认使用稳定 async copy 路径。
relay:
  zeroCopy: false
```

字段说明：

- `rpc.endpoints`：API 节点 RPC 地址列表。节点会连接其中可用 endpoint，兼容 `http` 和 `https`；远程 `http` 明文地址应放在私网或隧道内，生产环境优先使用 `https`。
- `nodeId`：节点身份标识。
- `secret`：节点认证密钥。
- `billing.countInboundTraffic`：是否把客户端上传到节点的上行流量也计入控制面带宽和日统计计费流量。默认 `false`，只按节点下行流量计费；设为 `true` 后当前节点按上下行合计计费。
- `relay.zeroCopy`：是否启用 Linux `splice` 零拷贝 TCP/SNI relay。默认 `false`，优先稳定性；需要追求极限转发性能时可显式设为 `true`。

未启用零拷贝时，TCP/SNI relay 的用户态 copy buffer 由内存治理器自动计算。程序会按当前内存压力和活动 TCP 连接数在 `16KiB` 到 `256KiB` 之间为新连接选档；用户不需要也不能通过配置手动设置 buffer。

可使用内置命令交互或非交互调整零拷贝：

```bash
cloud-node zerocopy
cloud-node zerocopy --enable --yes
cloud-node zerocopy --disable --yes
```

修改后需要重启正在运行的节点进程，已有连接不会切换 relay 模式。

不要把真实生产密钥提交到公开仓库。

## configs/runtime.yaml

`configs/runtime.yaml` 用于本机运行时开关，不从控制面自动推断网卡。XDP/AF_XDP 默认关闭，需要在该文件中显式启用：

```yaml
xdp:
  enabled: false
  attachMode: auto
  fallback: pass
  interfaces:
    - name: eth0
      queues: [0, 1]
      mode: proxy
      localIps: []
      frameSize: 2048
  proxy:
    protocols: ["http", "https", "tcp", "udp", "h3"]
    ports:
      - protocol: https
        port: 443
      - protocol: h3
        port: 443
```

`fallback: pass` 表示 attach、XSK 或 map 同步失败时回退到现有 socket 路径；`fallback: fail-start` 表示启动条件不满足时返回错误。完整说明见 [XDP/AF_XDP 旁路数据面](xdp-af-xdp.md)。

## 控制面配置

大部分运行时配置由控制面下发，包括：

- 节点基础配置。
- 监听端口和协议。
- HTTP server、域名和站点配置。
- 反向代理和源站配置。
- 缓存策略。
- WAF 策略。
- SSL 证书。
- 访问日志配置。
- 统计和节点任务配置。

节点会将 PB 消息中的配置反序列化为运行时模型，并更新 `ConfigStore`。

## 配置兼容原则

配置模型需要兼容历史控制面字段和不同版本的 JSON 形态。代码中大量使用：

- `serde(rename = "...")`
- `serde(alias = "...")`
- `deserialize_null_default`
- 布尔、数字、字符串混合类型兼容。

兼容目标是让控制面没有显式下发某些字段时，节点能使用合理默认值，而不是因为字段缺失导致功能关闭。

## 目录和数据文件

常见目录和文件：

- `configs/api_node.yaml`：API 节点连接配置。
- `configs/runtime.yaml`：本机运行时配置，例如 RKE2 模式和 XDP/AF_XDP 显式网卡配置。
- `data/GeoLite2-City.mmdb`：GeoIP 城市库。
- `data/GeoLite2-ASN.mmdb`：ASN 数据库。
- `data/GeoLite2-Country.mmdb`：国家数据库。
- `data/cache`：默认磁盘缓存目录。
- `data/state.json`、`data/blocked_ips.json`、`data/metrics.db`：运行状态、封禁和统计数据。
- `logs/run.log`：节点运行日志；systemd 和内置后台模式都会追加写入。

旧版根目录 `api_node.yaml`、`../data/*` 和工作目录下的 `GeoLite2-*.mmdb` 会作为迁移兼容读取，新写入统一使用 `configs/`、`data/`、`logs/`。GeoIP 文件缺失时，地区类 WAF、地区统计和 ASN 识别能力会受限。

## 缓存配置

缓存配置通常由控制面下发。节点侧会读取：

- 缓存主目录。
- 子目录。
- 磁盘容量限制。
- 最小剩余空间。
- sendfile 开关。
- file cache 开关。
- cacheRefs 和 cachePolicy。

生产场景建议将缓存目录放在独立磁盘或独立分区，便于容量管理和故障隔离。

当前 `openFileCache` 会影响小对象磁盘命中是否读入内存并参与 L1 提升；关闭后小对象也走文件流式读取。`enableSendfile` 会被记录到运行时统计，并影响磁盘命中读取块大小，但 Pingora cache storage 当前只向上返回 `Bytes` 分块，不向 storage handler 暴露下游 socket，因此节点现有路径还不能直接执行 Linux `sendfile(2)` 零拷贝。真正的内核 sendfile 需要扩展 Pingora cache serving path，或实现同时持有文件 FD 与下游连接的自定义响应路径。

### `enableReadingOriginAsync`

控制面缓存规则里的 `enableReadingOriginAsync` 字段目前在 cloud-node 中可以被接收和解析，但不会按单条 `cacheRef` 独立生效。

cloud-node 的 HTTP 缓存写入由 Pingora cache 状态机接管。Pingora 的默认行为取决于底层 cache storage 是否支持 `support_streaming_partial_write()`：

- 支持时，缓存 miss 的响应一旦判定可缓存，Pingora 会把源站读取和客户端写出解耦；客户端中断连接后，状态机会忽略 downstream error，继续读取源站并填充缓存。
- 不支持时，客户端中断通常会结束当前代理链路，不会继续为了缓存单独读完整个源站响应。

因此当前 cloud-node 中该能力是 storage 级别的统一行为，不是 `enableReadingOriginAsync` 可单独开启或关闭的规则级行为。严格按单条缓存规则控制该字段，需要后续改造 Pingora cache/代理状态机或在 cloud-node 中实现独立的响应体读取与缓存写入路径。

## 访问日志配置

访问日志由全局配置和站点配置共同决定。可控制：

- 是否启用访问日志。
- 是否记录 Cookie。
- 是否记录请求 header。
- 是否记录响应 header。
- 是否记录请求 body。
- server not found 是否上报。

高 QPS 环境下应谨慎开启请求 body 记录。上传端会在消息过大时尝试剥离 request body 后重试，但最好的做法仍是在配置侧避免大 body 日志。

普通 TCP/UDP L4 和 `@quic` UDP 透传不生成访问日志。TCP SNI 透传会复用对应 L7 服务的访问日志配置，并同时遵守全局访问日志开关。

## `@sni_passthrough` 和 `@quic` 服务标记

控制面服务域名可以通过后缀标记启用透传模式：

- `example.com@sni_passthrough`：TCP TLS SNI 透传，运行时按 `example.com` 建立路由索引。
- `example.com@quic`：UDP QUIC 透传，运行时按 `example.com` 建立路由索引。

标记不会作为真实域名参与匹配；运行时会移除后缀并统一小写。`@quic` 路由按 `SNI + UDP 监听端口` 匹配，不使用端口 `0` 兜底；同一端口只有一个 `@quic` 服务时，才会在没有普通 UDP 服务命中后作为 fallback。

端口范围会完整展开到运行时监听和索引中，例如 `443-445` 会同时覆盖 `443`、`444` 和 `445`。

## 系统参数

启动时会尝试进行部分内核参数调优。生产环境仍建议显式配置：

```bash
ulimit -n 1048576
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w net.core.netdev_max_backlog=250000
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.tcp_fin_timeout=10
sysctl -w net.ipv4.tcp_slow_start_after_idle=0
sysctl -w net.ipv4.tcp_mtu_probing=1
sysctl -w net.core.rmem_max=134217728
sysctl -w net.core.wmem_max=134217728
sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_congestion_control=bbr
```

`net.core.default_qdisc=fq` 和 `net.ipv4.tcp_congestion_control=bbr` 依赖内核支持；不支持时节点会跳过该项，其他参数仍按健康目标值管理。

具体值需要结合机器规格、连接规模、conntrack、负载均衡模式和上游连接池评估。

## 配置验证

验证本地 `configs/api_node.yaml`：

```bash
cloud-node test
```

该命令只验证本地 API 配置是否能解析，不代表控制面连接一定成功。
