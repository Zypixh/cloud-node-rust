# 功能说明

本文件按功能域介绍 CloudNode Rust 已实现的主要能力和运行边界。

## HTTP/HTTPS 代理

HTTP 代理是 L7 能力的主入口，支持：

- Host 和 wildcard Host 匹配。
- HTTP/1.1 和 HTTP/2。
- TLS 证书动态选择。
- 上游 SNI 和 Host 策略。
- 请求和响应 header policy。
- 标准回源头 `X-Real-IP`、`X-Forwarded-Host`、`X-Forwarded-Proto` 和 `X-Forwarded-For`。
- URL rewrite 和 host redirect，支持递归 rewrite、break、proxyHost 和 URL/domain/port redirect。
- 自定义错误页和状态页。
- 条件响应头策略、HSTS 和 OPTIONS CORS 预检响应。

请求会先经过站点路由，再进入请求过滤、缓存判断、WAF 判断和上游选择。

## HTTP/3

HTTP/3 面向支持 QUIC 的客户端。运行时会根据配置开启监听，并在日志和统计中标记 HTTP/3 流量，方便和 HTTP/1.1、HTTP/2 做区分。

当同一 UDP 端口同时存在 HTTP/3 站点和 `@quic` 透传服务时，节点会使用共享 UDP demux 绑定单个 socket：QUIC Initial 中 ALPN 为 H3 且命中 L7 站点的流量进入 HTTP/3，命中 `@quic` 的非 H3 流量进入 UDP 透传，避免端口绑定冲突。

## gRPC 和 WebSocket

gRPC 和 WebSocket 属于长连接协议，运行时会优先识别协议特征，并根据站点配置决定是否允许转发。

行为要点：

- WebSocket 未开启时，gRPC 不会被误放行。
- WebSocket 可按 Origin allowlist 或同源策略拦截异常握手，并支持上游 Origin 模板覆盖。
- gRPC 请求会强制使用上游 H2。
- 长连接统计和普通 HTTP 请求分开处理。
- 访问日志会保留协议标识和上游信息。

## TCP、TCP-TLS 和 UDP

四层代理用于非 HTTP 场景：

- TCP 透明转发。
- TCP-TLS 按 SNI 或端口路由。
- UDP 双向转发和会话维护。
- `@quic` UDP 透传，支持通过 QUIC Initial TLS SNI 按域名路由。
- L4 流量统计和连接状态记录。

四层代理不执行 HTTP header、WAF 规则和页面能力，但会参与节点级统计和连接状态记录。普通 L4 和 `@quic` 不生成访问日志；SNI 透传访问日志由对应 L7 服务配置控制。

## SNI 透传

共享 `443` 端口下，运行时会解析 TCP TLS ClientHello 并判断是否进入 SNI 透传逻辑。透传模式不会终止 TLS，而是直接将连接转发到目标上游。精确 L7 HTTPS 站点优先于通配 SNI 透传，精确 SNI 透传可优先于通配 L7 站点。

适用场景：

- 需要保持上游证书和 TLS 握手。
- 需要在同一入口同时承载普通 HTTPS 和透明 TLS 服务。
- 需要降低边缘层对特定 TLS 流量的干预。

## `@quic` UDP 透传

服务域名以 `@quic` 结尾时，节点会把该服务作为 QUIC UDP 透传入口。节点从 QUIC Initial CRYPTO frame 中提取 TLS SNI，并按 `SNI + UDP 监听端口` 命中对应服务。

行为边界：

- `@quic` 只用于 UDP 透传，不作为 HTTP/3 L7 站点加入 H3 desired ports。
- 同端口存在 HTTP/3 站点时，H3 ALPN 且命中 L7 站点的流量优先进入 HTTP/3。
- 同端口存在普通 UDP 服务时，未能按 SNI 命中 `@quic` 的流量先匹配普通 UDP；只有该端口唯一配置了一个 `@quic` 服务时才作为 fallback。
- `@quic` 不支持 obfs 流量的域名识别，也不生成访问日志。

## 源站和多级分发

源站能力包括：

- 主源和备源。
- 源站权重，数字越大分配的请求比例越高。
- 健康检查。
- Random 和 RoundRobin 调度，未显式配置时默认使用 Random。
- 源站失败状态跟踪，连续失败后短暂摘除并自动恢复探测。
- HTTPS 源站可按单个源站启用 HTTP/2 回源。
- 单个 HTTPS/TLS 源站可配置 TLS 证书校验模式：auto、force、skip。
- 自定义 Host 和 SNI。
- follow host 和 follow port。
- 连接、读取和空闲超时。

多级分发场景下，节点可以根据层级和父节点配置回源到上级节点，并记录父节点压力。

## 缓存

缓存系统支持：

- Memory + Disk 混合缓存。
- 多缓存策略。
- 按 method、status、URL、query、header、cookie 等条件匹配。
- Range 和部分内容缓存。
- Cache-Control 规则处理。
- 磁盘空间保护。
- 后台清理和过期淘汰。
- 缓存元数据持久化。

缓存命中路径会优先读取内存索引，减少 RocksDB 热路径读写。缓存写入使用临时文件和 rename，降低并发写同一对象造成的数据损坏风险。

图片 WebP 变体使用独立缓存 key。只有站点 WebP 规则匹配、请求 `Accept` 支持 `image/webp`、命中缓存策略且响应最终允许缓存时，节点才会在写缓存前完成转换。后续请求命中同一 WebP 缓存变体时直接返回缓存对象，不会再次执行图片解码和编码。

## 内容处理

内容处理能力包括：

- WebP 图片转换。
- HTML/CSS/JS 优化。
- HLS 播放列表重写。
- HLS 分片加密。
- 自定义错误页。
- 模板变量替换。

这些能力通常发生在响应阶段。WebP 会作为可缓存的响应变体写入缓存；HTML/CSS/JS 优化和加密等 CPU 密集型处理仍应谨慎开启，并配合监控观察延迟。

## WAF 和访问控制

WAF 能力包括：

- 规则组和规则集。
- IP、CIDR、地区、User-Agent、Referer、URI、Header、Cookie、Query 条件。
- 正则匹配、字符串操作符和 SQLi/XSS 检测操作符。
- SQLi/XSS 主检测使用本仓库内 patched libinjectionrs，保留受限正则兜底。
- block、log、allow、captcha、JS challenge 等动作。
- UAM 和 PoW 挑战。
- CC 策略。
- 观察模式。
- 本地封禁状态。

WAF 状态管理会维护 IP 和网段封禁快照。请求热路径使用快照匹配，避免每次请求扫描所有规则。

## 防盗链和访问限制

站点安全还包括：

- Referer 防盗链。
- User-Agent 过滤。
- URL 鉴权。
- 请求频率限制。
- 带宽限制。
- 流量限制。
- 站点关停页。
- 区域访问限制。

这些能力通常在请求进入上游前执行，能够减少无效回源和异常流量成本。

## 证书、ACME 和 OCSP

证书能力包括：

- 动态证书加载。
- 单服务多个证书。
- SNI 到证书映射。
- ACME HTTP-01 challenge 代理查询。
- OCSP 同步。
- 证书热更新和删除生效。
- TLS 噪音日志收敛。

证书更新由控制面同步任务触发，运行时选择器负责在 TLS 握手阶段返回合适证书。证书匹配会使用证书 SAN、CN 和控制面下发的 `dnsNames`，因此同一服务绑定多个域名时可以按 SNI 返回对应证书。服务级证书不会写入全局证书池；删除证书或移除服务后，下一次配置/服务更新会按当前配置重建证书快照，旧证书不会继续被选择。

ACME HTTP-01 请求命中 `/.well-known/acme-challenge/` 时，节点会向 API 查询 token 对应 key；查询成功时直接返回 challenge 内容，查询不到或 RPC 失败时继续正常站点请求流程。

## 访问日志

访问日志由请求处理阶段生成，后台批量上传。支持：

- 请求和响应 header。
- Cookie。
- 源站地址和源站状态。
- 缓存命中标识。
- HTTP/3 标识。
- 请求耗时和流量。
- 站点、域名、节点元数据。

日志通道使用非阻塞投递，避免控制面异常反压请求热路径。上传失败时会进入有限 retry buffer。

普通 TCP/UDP L4 和 `@quic` UDP 透传不生成访问日志。TCP SNI 透传会沿用对应 L7 服务的访问日志配置，并遵守全局访问日志开关；时间字段统一按 UTC 输出。

## 节点日志和统计

节点会持续上报：

- 节点日志。
- 节点值和资源状态。
- 实时统计。
- 日统计。
- Top IP。
- L4/L7 流量。
- 缓存大小和缓存命中。
- 攻击请求统计。

统计数据以聚合方式上报，避免每个请求都执行远程写入。

## 控制面实时命令

节点通过 `nodeStream` 接收控制面实时命令。收到消息后会按 `code` 分发并执行对应动作，执行完成后以同一 `requestId` 回复结果。

已支持：

- API 节点连接确认和在线状态触发。
- 节点任务、配置变更通知。
- 缓存预热、缓存读取、缓存统计、缓存清理。
- 节点运行状态采集。
- API endpoint 切换。
- systemd 服务启用状态检查。
- 本地防火墙能力检查。

暂未支持或被明确标记为暂不支持的能力，会在代码占位页和回复中说明，不会伪装成已执行。
