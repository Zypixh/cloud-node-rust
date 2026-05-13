# 配置说明

CloudNode Rust 的本地配置很少，主要配置来自控制面。节点本地只需要知道 API 节点地址、节点 ID 和密钥。

## configs/api_node.yaml

默认配置文件位于运行目录的 `configs/api_node.yaml`：

```yaml
rpc.endpoints: [ "http://127.0.0.1:8001" ]
nodeId: "your-node-id"
secret: "your-node-secret"
```

字段说明：

- `rpc.endpoints`：API 节点 RPC 地址列表。节点会连接其中可用 endpoint。
- `nodeId`：节点身份标识。
- `secret`：节点认证密钥。

不要把真实生产密钥提交到公开仓库。

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
- `data/GeoLite2-City.mmdb`：GeoIP 城市库。
- `data/GeoLite2-ASN.mmdb`：ASN 数据库。
- `data/GeoLite2-Country.mmdb`：国家数据库。
- `data/cache`：默认磁盘缓存目录。
- `data/state.json`、`data/blocked_ips.json`、`data/metrics.db`：运行状态、封禁和统计数据。
- `logs/run.log`：后台启动模式的 stdout/stderr 日志。

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

## 访问日志配置

访问日志由全局配置和站点配置共同决定。可控制：

- 是否启用访问日志。
- 是否记录 Cookie。
- 是否记录请求 header。
- 是否记录响应 header。
- 是否记录请求 body。
- server not found 是否上报。

高 QPS 环境下应谨慎开启请求 body 记录。上传端会在消息过大时尝试剥离 request body 后重试，但最好的做法仍是在配置侧避免大 body 日志。

## 系统参数

启动时会尝试进行部分内核参数调优。生产环境仍建议显式配置：

```bash
ulimit -n 1048576
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=16384
sysctl -w net.core.netdev_max_backlog=16384
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
```

具体值需要结合机器规格、连接规模、conntrack、负载均衡模式和上游连接池评估。

## 配置验证

验证本地 `configs/api_node.yaml`：

```bash
cloud-node test
```

该命令只验证本地 API 配置是否能解析，不代表控制面连接一定成功。
