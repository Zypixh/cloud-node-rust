# 接收配置审计：全局配置、网站配置与优先级

审计日期：2026-05-26。范围是当前 Rust 数据面从控制面接收、解析、存储和在请求路径中使用的配置。主要依据：

- 配置模型：`src/config_models.rs`
- 全量配置同步：`src/rpc/node.rs`
- 单站点/用户站点/更新中站点同步：`src/rpc/server.rs`、`src/rpc/api_node.rs`
- 运行时存储：`src/config.rs`
- 请求处理：`src/proxy.rs`、`src/tcp_proxy.rs`
- 编译计划：`src/compiled.rs`、`src/cache/compiled.rs`、`src/headers.rs`、`src/rewrite.rs`
- 实测 gRPC/JSON 形状记录：`docs/grpc-api.md`

## 总体结论

当前接收链路的主体是正确的：全量 `nodeJSON` 被解析为 `NodeConfigPayload`，站点 JSON 被解析为 `ServerConfig`，再写入 `ConfigStore` 并重建路由、源站 LB、缓存、WAF、页面、证书、访问日志和 compiled plan。请求热路径基本只读 `ConfigStore` 快照。

但不能判定为“所有接收配置都正确”。审计发现以下明确风险：

1. `nodeJSON.plans`、站点 `userPlan`、`aliasServerNames`、顶层 `tls`、`web.accessLog`、`redirectToHTTPS`、顶层 `httpCachePolicy`/`httpFirewallPolicy`/`*Ref` 等实测字段没有被当前模型完整承接；serde 会静默忽略未知字段。若控制面没有同时把这些配置预合成到已支持的内联字段，运行时会缺功能。
2. 套餐同步当前依赖 `FindServerUserPlan`，而真实节点凭据会返回 `not supported node type: 'node'`；同时 `nodeJSON.plans` 未进入 `ConfigStore`，所以 `userPlanId` 相关的上传大小、CC 限额、流量提示页、带宽算法可能无法生效。
3. `matchCertFromAllServers` 已解析并写入全局 HTTP 配置，但证书选择器实际总是从全局证书、全局 SSLPolicy 和所有启用站点 SSLPolicy 收集证书，未按该开关限制。
4. 集群级策略 fallback 使用 `HashMap::values().next()`，当没有当前集群和 `0` 默认策略时，选中哪个策略不稳定；gRPC 还会先取任意策略，再 fallback `primaryGRPCPolicy`。
5. `web.isOn`、`web.statRef`、多个 `isPrior` 字段被解析但多数没有参与运行时优先级判断。当前真正使用 `isPrior` 的主要是 UAM 的 `server.uam` 与 `web.uam` 选择。
6. `WebPImagePolicy.requireCache` 被解析但未按开关使用；当前 WebP 转换总是要求已经命中缓存规则，相当于始终 require cache。

## 接收入口

| 入口 | 接收内容 | 解析模型 | 应用方式 | 审计结论 |
|---|---|---|---|---|
| `NodeService.FindCurrentNodeConfig` | 全局配置、站点列表、策略列表、证书、页面、TOA、节点信息 | `NodeConfigPayload` | `fetch_and_apply_config()` 解压 Brotli、解析 JSON、构建路由/LB/compiled plan、写入 `ConfigStore` | 主链路正确，但部分实测顶层字段未建模 |
| `ServerService.ComposeServerConfig` | 单个站点配置 | `ServerConfig` | 替换单站点或该用户站点，重建站点路由/LB/compiled plan | 主链路正确，但依赖控制面输出已内联配置 |
| `ServerService.ComposeAllUserServersConfig` | 用户全部站点 | `Vec<ServerConfig>` | 用户维度替换站点集合 | 主链路正确，同样依赖字段内联 |
| `UpdatingServerListService.FindUpdatingServerLists` | 更新中的站点列表 | `Vec<ServerConfig>` | 按 server id 删除旧项，再插入新站点 | 主链路正确 |
| `NodeTaskService.FindNodeTasks` / `nodeStream` | 配置变更通知 | proto task/message | 触发全量配置、单站点、用户站点、IP item、套餐等同步 | 只是触发器，不直接承载配置 |

## 全局配置对照

| 控制面字段 | 当前模型/存储 | 实际使用 | 与网站配置的优先级 | 结论 |
|---|---|---|---|---|
| `id` / `version` | `NodeConfigPayload.id/version` -> `NodeConfig.id/version` | numeric node id、配置游标、日志和状态上报 | 全局身份，无网站覆盖 | 正确 |
| `nodeId` | 已解析 | 不写入运行时，实际认证使用本地 `api_node.yaml` | 无 | 仅校验/兼容字段，未生效 |
| `isOn` | `NodeConfig.is_on` | 每个请求先检查，false 直接拒绝 | 全局最高优先级，先于所有站点 | 正确 |
| `enableIPLists` | `NodeConfig.enable_ip_lists` | 控制 `IPItemService.ListIPItemsAfterVersion` 增量同步 | 全局开关 | 正确 |
| `dataMap` | `DataMapConfig` | 当前只恢复 SSL 证书和源站客户端证书里的 `_DATA_MAP` 引用 | 辅助字段，无网站覆盖 | 证书场景正确；其他字段若使用 dataMap 不会恢复 |
| `metricItems` | `NodeConfig.metric_items` | 指定节点指标上报维度 | 全局 | 正确 |
| `updatingServerListId` | `NodeConfig.updating_server_list_id` | 更新中站点同步 baseline | 全局 | 正确 |
| `level` / `parentNodes` | `level`、`parent_nodes`、`parent_routes` | L1/L2 分层回源、父节点 LB | 全局；站点源站构建时使用 | 正确 |
| `nodeRegion` / `nodeCluster` | `node_region_id`、`node_cluster_id` | 区域统计、集群策略选择 | 全局；策略按集群挑选 | 正确 |
| `globalServerConfig.httpAll.forceLnRequest` / `lnRequestSchedulingMethod` | `global_http_config` | 分层回源是否强制走父节点、调度方式 | 全局控制，站点无覆盖 | 正确 |
| `globalServerConfig.httpAll.allowLANIP` / `allowLocalOrigins` | `global_http_config.allow_lan_ip` | 构建源站和父节点 LB 时是否允许 LAN 地址 | 全局控制所有站点源站 | 正确 |
| `connTimeout/readTimeout/idleTimeout/writeTimeout` | `global_http_config` | 源站连接/读/空闲/写超时 | 源站单项非 0 配置优先，否则用全局 | 正确 |
| `autoReadTimeout/autoWriteTimeout` | `global_http_config` | 下游会话读写超时 | 全局 | 正确 |
| `supportsLowVersionHTTP` | `global_http_config` | false 时拒绝 HTTP/1.0 等低版本请求 | 全局最高，站点无覆盖 | 正确 |
| `serverName` | `global_http_config.server_name` | 覆盖响应 `Server` header | 全局覆盖所有站点响应 | 正确 |
| `enableServerAddrVariable` | `global_http_config.enable_server_addr_variable` | 控制模板变量 `${serverAddr}` 是否返回本地地址 | 全局 | 正确 |
| `requestOriginsWithEncodings` | `global_http_config` | 回源请求自动补 `Accept-Encoding` | 全局 | 正确 |
| `xffMaxAddresses` | `global_http_config` | 限制 `X-Forwarded-For` 链长度 | 全局 | 正确 |
| `matchDomainStrictly` / `nodeIPShowPage` / `domainMismatchAction` | `global_http_config` | 未命中站点时计数封禁、返回页面/跳转/状态 | 全局，仅在站点未命中时使用 | 正确 |
| `matchCertFromAllServers` | 已解析并存储 | 未在证书选择器里判断 | 预期应影响站点证书选择范围 | 不完整 |
| `globalServerConfig.httpAccessLog` | `global_access_log` | 访问日志总开关、请求/响应头、Cookie、404、firewallOnly、499 | 全局开关先判断；站点 `accessLogRef` 再关闭或限制字段 | 主逻辑正确；需确认 `web.accessLog` alias |
| `globalPages` | `global_pages` | 自定义错误页候选 | 站点页面先匹配；仅 `web.enableGlobalPages=true` 时追加全局页面 | 正确 |
| `httpPagesPolicies` | `http_pages_policies` | 集群级页面策略 | 同 `globalPages`，追加在站点页面之后 | 正确，但策略 fallback 不稳定 |
| `grpcPolicies` / `primaryGRPCPolicy` | `grpc_policy` | gRPC 请求体检查上限 | 站点 `server.grpc.isOn` 只启用协议；全局 policy 提供大小限制 | 可用，但 fallback 不稳定 |
| `httpCachePolicies` | `cache_policies` / compiled global cache | 全局缓存策略池 | 网站 cache refs -> 网站 cache policy -> 全局 policies | 正确 |
| `httpFirewallPolicies` | `firewall_policies` / compiled global firewall | 全局 WAF 策略池 | 只有网站 `firewallRef.isOn` 时才使用；网站 policy 先于全局，`ignoreGlobalRules` 可关闭全局追加 | 正确 |
| `wafActions` | `waf_actions` / `global_waf_block_options` | WAF 默认动作参数 | 作为全局动作默认值，具体 WAF policy/action 可覆盖 | 基本正确 |
| `uamPolicies` | `uam_policies` | 全局 UAM | 网站 UAM 优先；无网站 UAM 时用全局 | 正确，但策略 fallback 不稳定 |
| `httpCCPolicies` | `http_cc_policies` | 全局 CC | 网站 `web.ccPolicy` 先执行，未拦截再执行全局；无 HTTPCC 时可 fallback WAF policy `ccConfig` | 正确，但策略 fallback 不稳定 |
| `http3Policies` | `http3_policies` | 集群 HTTP/3 能力和 Alt-Svc 端口 | 全局 HTTP/3 policy 必须开启，且网站 HTTPS 也要开启 HTTP/3 | 正确，但策略 fallback 不稳定 |
| `webpImagePolicies` | `webp_image_policies` | WebP 全局质量和全局尺寸限制 | 必须同时有网站 `web.webP` 和全局 WebP policy；尺寸取更严格范围 | 基本正确；`requireCache` 未按开关使用 |
| `sslCerts` / `sslPolicy` | `ssl_certs` / `ssl_policy` | 证书收集和 TLS SNI selector | 全局证书、全局 SSLPolicy、所有启用站点 SSLPolicy 全部收集 | 可用；未实现 `matchCertFromAllServers` 限制 |
| `toa` | `toa` | HTTP/TCP 回源连接使用 TOA 端口映射 | 全局 | 正确 |
| `kernelFirewallMode` | WAF state kernel filter | nft/kernel firewall 能力选择 | 全局 | 正确 |
| `plans` | 未建模 | 未写入 `ConfigStore.plans/user_plans` | 应给网站 `userPlanId` 提供套餐派生配置 | 缺失 |
| `edition` / `lnAddrs` / `bypassMobile` / `isCenter` | 已解析 | 当前未使用 | 无 | 已接收但未生效 |
| `networkSecurityPolicy` / `systemServices` / `clock` / `commonScripts` / `productConfig` / `ocspVersion` 等实测顶层字段 | 未建模 | 当前未使用 | 无 | 若控制面要求节点执行这些功能，则缺失 |

## 网站配置对照

| 控制面字段 | 当前模型/存储 | 实际使用 | 与全局配置的优先级 | 结论 |
|---|---|---|---|---|
| `id` / `userId` / `isOn` | `ServerConfig` | 路由、统计、用户维度替换；`isOn=false` 不进入运行时 | 网站级开关，低于全局 `node.isOn` | 正确 |
| `serverNames[].name/subNames` | `server_names` | Host/SNI 路由；`@sni_passthrough` 和 `@quic` 标记会被剥离 | 请求先按 Host/SNI 命中网站 | 正确 |
| `aliasServerNames` | 未建模 | 不参与路由 | 应与 `serverNames` 同级 | 缺失，除非控制面已合并到 `serverNames` |
| `http` / `https` | `HTTPConfig` / `HTTPSConfig` | HTTP/HTTPS listener、TLS、HTTP/3 站点开关 | listener 是网站级；HTTP/3 还受全局 policy 约束 | 基本正确 |
| `https.sslPolicy` | `HTTPSConfig.ssl_policy` | 站点证书、HSTS、HTTP/2 | 站点证书参与全局证书选择器；HSTS 只对本站响应 | 正确 |
| `https.sslPolicyRef` | 未建模 | 不解析引用 | 需要控制面内联 `sslPolicy` | 依赖控制面预合成 |
| 顶层 `tls` | 未建模 | 不启动独立 TLS L4 listener | 应作为 TCP/TLS 站点配置时生效 | 缺失，除非控制面放入 `tcp.tls` |
| `tcp` / `udp` | `TCPConfig` / `UDPConfig` | L4 listener 和回源转发 | 网站级 | 基本正确 |
| `enableProxyProtocol` | `ServerConfig.enable_proxy_protocol` | TCP/HTTP 接入可解析 PROXY protocol 后替换真实 IP | 先于 `remoteAddr` 原始 IP；后续 `remoteAddr` 仍可按头覆盖 | 正确 |
| `reverseProxy` | `ReverseProxyConfig` | 源站 LB、Host/SNI、源站 TLS、健康检查 | 网站源站优先；location 可覆盖 | 正确 |
| `reverseProxyRef` | 未建模 | 不解析引用 | 需要控制面内联 `reverseProxy` | 依赖控制面预合成 |
| `locations[]` | `LocationConfig` | 当前支持 location 级 `reverseProxy` 和 `cache` | location 命中后覆盖网站 reverseProxy/cache | 正确但范围有限 |
| `web.isOn` | `WebConfig.is_on` | 当前没有在请求路径中统一判断 | 应控制网站 Web 功能是否启用 | 已解析但未生效 |
| `web.remoteAddr` | `HTTPRemoteAddrConfig` | 按请求头/表达式解析真实 IP | 网站级，覆盖 socket/PROXY protocol 得到的 IP | 正确；`isPrior` 仅预留 |
| `web.requestLimit` | `HTTPRequestLimitConfig` | 请求体大小、连接数、单 IP 连接数、出带宽 | 网站级；无全局同类配置 | 正确 |
| `web.cache` | `WebCacheConfig` | 缓存规则和策略 | location cache > 网站 cacheRefs > 网站 cachePolicy > 全局 cachePolicies | 正确 |
| 顶层 `httpCachePolicy` / `httpCachePolicyId` | 未建模 | 不直接使用 | 需要控制面内联到 `web.cache.cachePolicy` | 依赖控制面预合成 |
| `web.firewallRef` / `web.firewallPolicy` | `HTTPFirewallRef` / `HTTPFirewallPolicy` | WAF 入站/出站、地区、候选规则 | 网站 policy 先执行；`ignoreGlobalRules=false` 时再执行全局 WAF | 正确 |
| 顶层 `httpFirewallPolicy` / `httpFirewallPolicyId` | 未建模 | 不直接使用 | 需要控制面内联到 `web.firewallPolicy`/`firewallRef` | 依赖控制面预合成 |
| `web.pages` / `web.enableGlobalPages` | `pages` / `enable_global_pages` | 自定义错误页 | 网站页面先匹配；`enableGlobalPages=false` 时禁止全局页面 | 正确 |
| `web.shutdown` | `HTTPShutdownConfig` | 网站关闭页/跳转 | 网站级，先于回源 | 正确 |
| `web.auth` | `HTTPAuthConfig` | Basic Auth | 网站级 | 正确 |
| `web.websocket` | `WebSocketConfig` | WebSocket Origin 校验和上游 Origin 设置 | 网站级 | 正确 |
| `web.uam` / `server.uam` | `UAMConfig` | UAM challenge | 默认 `web.uam` 优先；若 `server.uam.isPrior=true` 则 `server.uam` 优先；网站 UAM 优先于全局 UAM | 正确 |
| `web.ccPolicy` | `CCPolicy` | 网站 CC | 网站先执行；套餐派生限制可覆盖网站 CC 数值；再执行全局 CC | 正确 |
| `web.webP` | `WebPConfig` | WebP 请求/类型匹配和站点尺寸限制 | 网站和全局 WebP policy 都必须开启 | 正确，但依赖缓存；全局 `requireCache` 未真正分支 |
| `web.userAgentConfig` / `userAgent` | `UserAgentConfig` | UA allow/deny | 网站级 | 正确 |
| `web.refererConfig` / `referers` | `ReferersConfig` | Referer/Origin 防盗链 | 网站级 | 正确 |
| `web.hostRedirects` | `HTTPHostRedirectConfig[]` | 域名/端口跳转 | 网站级，先于 rewrite | 正确 |
| `web.rewriteRefs` / `rewriteRules` | `HTTPRewriteRef[]` / `HTTPRewriteRule[]` | URL rewrite/redirect/proxy host | 网站级；按数组顺序和 ref 开关 | 正确 |
| `web.requestHeaderPolicy` / `responseHeaderPolicy` | `HTTPHeaderPolicy` | 上游请求头和响应头/CORS | 网站级；全局只会额外覆盖 `Server` header | 正确 |
| `web.accessLogRef` | `HTTPAccessLogRef` | 站点日志开关和字段白名单 | 全局 access log 先开；站点可关闭或缩小字段 | 正确 |
| `web.accessLog` | 未作为 alias | 若控制面发 `accessLog` 而不是 `accessLogRef` 会被忽略 | 应等价站点日志配置 | 缺失 |
| `web.statRef` | `HTTPStatRef` | 当前没有用于 HTTP metrics gating | 应控制统计上报时未生效 | 已解析但未使用 |
| `web.charset` | `HTTPCharsetConfig` | 响应 `Content-Type` charset | 网站级 | 正确 |
| `web.optimization` | `HTTPPageOptimizationConfig` | HTML/CSS/JS 优化 | 网站级 | 正确 |
| `web.hls` | `HLSConfig` | HLS playlist/key/segment 加密 | 网站级 | 正确 |
| `web.preferWWW` / `trailingSlash` | `prefer_www` / `trailing_slash` | www 和尾斜杠跳转 | 网站级 | 正确 |
| `redirectToHTTPS` | 当前只声明 `redirectToHttps` | 大写 HTTPS 形态可能被忽略 | 网站级 | 需要 alias 兼容 |
| `trafficLimit` / `trafficLimitStatus` | `TrafficLimitConfig` / `TrafficLimitStatus` | 超限时返回 509；站点 notice body 优先 | 网站配置优先于套餐 notice body | 正确，但依赖套餐数据 |
| `userPlanId` | `ServerConfig.user_plan_id` | 统计、套餐派生配置 key | 网站引用套餐；套餐数据缺失时派生值为 0 | 接收正确，应用依赖套餐同步 |
| `userPlan` | 未建模 | 不写入套餐缓存 | 应可作为套餐数据来源 | 缺失 |
| `group` | 未建模 | 不参与合并 | 如果控制面未预合成 group 配置则无效 | 依赖控制面预合成 |

## 优先级规则

### Host 和站点选择

1. 请求进入后先按 Host 查 `ConfigStore.servers` 精确匹配。
2. 未命中时尝试 `*.domain` 通配匹配。
3. 同一个 Host 被多个站点写入时，后写入的站点覆盖前者，并只记录 warning。
4. `@sni_passthrough` 和 `@quic` 后缀只作为透传标记，运行时会从真实域名中剥离。

### location、网站、全局

1. location 目前只覆盖 `reverseProxy` 和 `cache`。
2. location 匹配顺序：exact > regex > prefix；prefix 再按更长路径优先；最后按 `priority` 降序。
3. 没有 location 覆盖时，使用网站级配置。
4. 全局配置通常不是“覆盖网站”，而是提供开关、默认值或策略池。

### 缓存

1. `location.cache` 命中时优先于 `web.cache`。
2. 缓存规则优先级：直接 `cacheRefs` > 网站 `cachePolicy` > 全局 `httpCachePolicies`。
3. `disablePolicyRefs=true` 时，不再 fallback 网站 policy 或全局 policy。
4. `cacheRef.isReverse=true` 表示命中后跳过缓存。

### WAF

1. 全局 WAF 不是无条件生效；网站必须有 `web.firewallRef.isOn=true`。
2. 网站 `web.firewallPolicy` 先执行。
3. `firewallRef.ignoreGlobalRules=false` 时，再追加执行全局 `httpFirewallPolicies`。
4. `ignoreGlobalRules=true` 时只执行网站 WAF。

### 页面

1. 站点 `web.pages` 先匹配。
2. `web.enableGlobalPages=false` 时停止，不查全局页面。
3. `web.enableGlobalPages=true` 时，追加 `globalPages` 和当前集群 `httpPagesPolicies.pages`。
4. 站点未命中时，域名不匹配流程可使用全局页面/域名不匹配动作。

### UAM

1. `web.uam` 通常优先。
2. 如果 `server.uam.isPrior=true`，则 `server.uam` 优先于 `web.uam`。
3. 只要有站点 UAM，就不使用全局 UAM。
4. 没有站点 UAM 时，使用当前集群全局 UAM。

### CC

1. 网站 `web.ccPolicy` 先执行。
2. 若有套餐派生 CC 限额，覆盖网站 CC 中对应数值。
3. 网站 CC 未拦截后，再执行全局 HTTP CC。
4. 没有全局 HTTP CC 时，可从全局 WAF policy 的 `ccConfig` fallback。

### HTTP/3

1. 当前集群全局 `http3Policies` 必须 `isOn=true`。
2. 网站 `https.supportsHTTP3/http3Enabled` 也必须开启。
3. 两者任一关闭都不会发布 Alt-Svc，也不会允许该 Host 走 H3。

### gRPC

1. 网站 `server.grpc.isOn=true` 只负责识别该请求为 gRPC。
2. gRPC 消息大小限制来自全局 `grpcPolicies`/`primaryGRPCPolicy`。
3. 当前选择顺序：当前 `nodeClusterId` -> `0` -> 任意 map value -> `primaryGRPCPolicy`。其中“任意 map value”不稳定，应调整。

### WebP

1. 网站 `web.webP.isOn=true` 和全局 `webpImagePolicies.isOn=true` 都必须满足。
2. 请求必须接受 WebP、响应必须是可转换图片、必须已经匹配缓存规则。
3. 尺寸范围取网站和全局的交集：min 取更大值，max 取更小的非 0 值。
4. 质量使用全局 `quality`。

### 访问日志

1. 全局 `httpAccessLog.isOn=false` 会关闭 HTTP 访问日志。
2. 网站 `accessLogRef.isOn=false` 会关闭本站日志。
3. 网站 `accessLogRef.fields` 非空时作为字段白名单。
4. 全局 `enableCookies/enableRequestHeaders/enableResponseHeaders` 再对对应字段做总开关。
5. TCP SNI 透传复用对应 L7 站点日志配置，并检查全局日志原子开关。

### 证书

1. 当前证书池由全局 `sslCerts`、全局 `sslPolicy.certs` 和所有启用站点 `https.sslPolicy.certs` 合并。
2. SNI 选择按 cert SAN/CN/dnsNames 建索引，找不到时使用第一个证书作为 default。
3. 当前没有按 `matchCertFromAllServers` 限制“只从当前站点证书中匹配”。

## 建议修复顺序

1. 先补齐实测字段 alias/模型：`aliasServerNames`、`web.accessLog`、`redirectToHTTPS`、顶层 `tls`、顶层 `httpCachePolicy/httpFirewallPolicy`、`userPlan`、`nodeJSON.plans`。
2. 把 `nodeJSON.plans` 和站点 `userPlan` 转入 `ConfigStore.plans/user_plans`，避免节点凭据无法调用 `FindServerUserPlan` 时套餐能力失效。
3. 把集群策略 fallback 改成确定性选择，或去掉“任意策略” fallback，优先使用 `primaryGRPCPolicy`。
4. 明确实现或删除未生效开关：`matchCertFromAllServers`、`web.isOn`、`statRef`、`WebPImagePolicy.requireCache`、未使用的 `isPrior`。
5. 对控制面可能只下发引用的字段增加单测：只给 `sslPolicyRef`/`reverseProxyRef`/`httpCachePolicyId`/`httpFirewallPolicyId` 时应失败显式报警，或在模型层支持引用解析。
