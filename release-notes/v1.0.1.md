# cloud-node-rust 1.0.1

本版本是一次以“运行时协议对齐、站点安全能力补齐、HTTP/3 与特殊转发能力落地”为核心的发布。

## 重点更新

- 补齐并修正了控制面协议运行时接入
  - 接通缺失的同步器、日志上传、统计上报链路
  - 补齐 `PlanService`、`PingService`、`NodeLogService`、`ServerDailyStatService`、`OCSP` 等主链路
  - 修复多处“已实现但未真正运行”或“收到任务但未生效”的假对齐问题

- 补齐了网站级与全局级安全/防护能力
  - 网站级与全局级 `UAM / 5 秒盾`
  - 网站级与全局级 `CC`
  - WAF 命中事件上报
  - 自定义页面与全局页面回退逻辑
  - `requestLimit` 主链路与带宽限制
  - `remoteAddr` 真实客户端地址解析
  - `trafficLimitStatus` 本地执行与统计上报修正

- 增强了流量统计、日志与计费相关上报
  - 完整补齐 HTTP/TCP/UDP 的统计闭环
  - 回源流量已进入带宽统计上报
  - `ServerDailyStat.bytes` 按当前 PB 能力折叠纳入回源流量
  - 访问日志增加缓存命中细分标记与 HTTP/3 传输标识

- 完成了 HTTP/3 运行时接入
  - 使用 `quinn + h3 + h3-quinn` 增加真实 H3 入口
  - 复用现有 HTTPS 业务链路
  - 支持动态证书快照与 H3 证书选择
  - H3 请求透传真实客户端地址到内部桥接链路

- 补齐了网站级功能模型与执行层
  - `redirectToHttps`
  - `shutdown`
  - `charset`
  - `optimization`
  - `hls`
  - `webp`
  - `HTTP3` 网站级开关兼容

- 补齐了 TCP 上游双向 TLS 能力
  - 支持 TCP 上游 mTLS 客户端证书
  - 修复 OCSP 只同步不实际挂载的问题

- 新增特殊站点模式：`@sni_passthrough`
  - 通过站点 `description` 中的特殊标记启用
  - 在共享 HTTPS 端口上基于客户端 SNI 做 TLS 原始透传
  - 不进入 L7 HTTP/WAF/缓存链路
  - 保留基础连接统计、流量统计与计费上报
  - 自动排除该类站点的 HTTP/3 广告与 H3 接入

## HLS 相关

- 增加 HLS AES-128 加密能力
  - `.m3u8` 自动注入 `#EXT-X-KEY`
  - `.ts` 内容加密
  - 使用短时会话型 token 方案保护 key 获取

- 修正 HLS 与缓存的兼容性问题
  - 剥离 HLS 会话参数对默认缓存 key 的污染
  - 避免会话化 HLS 输出被错误复用缓存

## 修复项

- 修复 `requestLimit` 被重复执行导致连接计数可能重复累加的问题
- 修复多项站点级/全局级能力层级接错的问题，例如：
  - `WebP`
  - `enableGlobalPages`
  - `UAM`
  - `HTTP3`

## 兼容性说明

- `ScriptService` 相关边缘脚本能力仍不支持
- IP 库自动同步仍未启用
- `TOA`、`fastcgi` 等非当前主线能力未纳入本次发布范围
- `ServerDailyStat` 由于 PB 无独立回源流量字段，当前仍采用折叠统计口径

## 验证情况

- `cargo check` 已通过
- `cargo test --lib` 已通过（当前仓库无 lib 单测用例）
