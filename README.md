# CloudNode Rust Implementation

[![Release](https://github.com/Zypixh/cloud-node-rust/actions/workflows/release.yml/badge.svg)](https://github.com/Zypixh/cloud-node-rust/actions/workflows/release.yml)

这是一个基于 Rust 语言重新实现的 `cloud-node` (EdgeNode) 边缘节点程序。本项目利用 [Pingora](https://github.com/cloudflare/pingora) 框架，实现了高性能、低内存占用的边缘计算与安全防御能力。

## 项目主页
GitHub: [https://github.com/Zypixh/cloud-node-rust](https://github.com/Zypixh/cloud-node-rust)

## 核心功能

### 1. 高性能缓存系统
*   **多层级策略**：完美对齐“网站规则 > 全局策略”的匹配逻辑，支持 `disablePolicyRefs` 开关。
*   **动态 Key 生成**：支持基于 `${host}`, `${requestPath}`, `${cookie:NAME}`, `${arg:NAME}` 等 20+ 种变量的自定义 Key 模板。
*   **分片内容缓存**：支持 `206 Partial Content` 状态码的缓存与读取。
*   **智能过期控制**：实现了 `Expires` 和 `Cache-Control` Header 的自动计算与注入。
*   **高级回源控制**：支持强制 Range 回源、客户端 `no-cache` 刷新及 MISS 时自动剥离条件请求 Header。

### 2. 实战级 WAF 防御体系
*   **12 种执行动作**：完整实现 Block, Page, Captcha, JS Cookie, Redirect, Allow (三级作用域), Log, Tag, Notify, Get302, Post307, GoGroup/GoSet。
*   **高性能规则引擎**：基于正则实现的 `Group -> Set -> Rule` 匹配架构，支持 `in`, `matches`, `wildcard`, `version` 等全量操作符。
*   **预制防御集**：内置 SQL 注入（普通/严格）、XSS、命令注入、恶意 UA 等实战规则。
*   **精细化封禁**：支持**随机封禁时长**、**C 段网段封禁**、**局域网/搜索引擎旁路**以及白名单秒级放行。
*   **特殊防御**：强制执行空连接泛滥防御、TLS 资源耗尽防御及 CC 攻击频率限制。

### 3. 配置与同步
*   **协议对齐**：完全适配 `cloud-node` 最新的 gRPC PB 协议，支持 `httpCachePolicies` 和 `httpFirewallPolicies` 数组解析。
*   **自动发现**：支持节点 ID 的自动注册与动态 endpoint 切换。

## 部署说明

### 配置优先级
程序启动时会按照以下顺序探测配置文件 `api_node.yaml`：
1. `../configs/api_node.yaml` （**推荐**，适用于 `bin/` + `configs/` 部署结构）
2. `configs/api_node.yaml`
3. `api_node.yaml` （程序当前目录）

### 快速开始

#### 安装构建依赖 (Linux)
```bash
sudo apt-get update
sudo apt-get install cmake golang-go build-essential
```

#### 编译与运行
```bash
# 编译高性能发布版本
cargo build --release

# 启动程序
./target/release/cloud-node-rust
```

## 自动化发布
本项目已集成 GitHub Actions。每当推送以 `v` 开头的 Git Tag（例如 `v1.1.5`）到仓库时，系统会自动构建适用于 **Linux (x64)**, **macOS (Intel/M1)** 和 **Windows (x64)** 的多平台版本并发布。

## 技术致谢 (Credits)
本项目基于 [Cloudflare Pingora](https://github.com/cloudflare/pingora) 框架构建。我们对 Cloudflare 开源这一卓越的高性能网络框架表示由衷的感谢。
*   Pingora 采用 [Apache License 2.0](https://github.com/cloudflare/pingora/blob/main/LICENSE) 授权。
*   本项目同样遵循 Apache License 2.0 协议。

## 开源协议 (License)
本项目遵循 Apache License 2.0 协议。详情请参阅 [LICENSE](LICENSE) 文件。
