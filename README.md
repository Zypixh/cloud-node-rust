# CloudNode Rust

本项目基于 Cloudflare Pingora 框架构建。我们对 Cloudflare 开源这一卓越的高性能网络框架表示由衷的感谢。

**CloudNode Rust** 是一款基于 Cloudflare [Pingora](https://github.com/cloudflare/pingora) 框架构建的高性能 CDN 边缘节点。它旨在提供超越原版 Go 实现的吞吐能力、更低的延迟以及更智能的集群自愈机制。

## 🚀 核心特性

### 1. 极致转发性能
*   **多协议支持**：原生支持 HTTP/1.1、HTTP/2、gRPC、WebSocket、TCP、TCP-TLS 及 UDP 转发。
*   **网络栈优化**：全链路强制开启 `TCP_NODELAY`，支持基于 `libc` 定制的 `SO_KEEPALIVE` 探测，在 Linux 环境下自动激活 **BBR 拥塞控制算法**。
*   **硬件加速**：支持针对 x86_64 (AVX2, AVX-512) 和 ARM64 (NEON, LSE) 的指令集深度优化。

### 2. 智能感知型分发 (Smart Tiered-Origin)
*   **负载避让**：通过私有协议头 `X-Cloud-Node-Pressure` 实时感知 L2 父节点的 CPU 和连接压力。当节点过载（>0.9）时，自动执行哈希漂移寻找空闲节点。
*   **一致性哈希**：支持 `urlMapping`（Ketama 算法），显著提升集群 L2 缓存命中率。
*   **强制 Ln 模式**：支持集群级配置，可强制所有或仅可缓存请求通过 L2 分发。

### 3. 电信级混合缓存 (Hybrid Cache)
*   **二级存储**：Memory (L1) + Disk (L2) 混合架构，热点数据秒级内存响应。
*   **流式压缩**：根据内容类型自动执行异步 Zstd 压缩存储，大幅节省磁盘 IO 和空间。
*   **原子更新**：基于 **RocksDB** 的元数据持久化，支持单机千万级文件索引与热启动。
*   **安全保护**：内置磁盘水位预警，自动防止缓存撑爆文件系统。

### 4. 全球配置与安全
*   **PB 协议同步**：深度对接官方 Protobuf 协议，支持配置热更新与动态证书同步。
*   **安全风控**：内置 WAF 引擎、IP 名单同步、局域网源站拦截、XFF 长度限制及非法 HTTP 版本过滤。
*   **身份还原**：支持 `X-Cloud-Real-Ip` 穿透，确保多级分发下 L2 节点的统计与安全策略 100% 准确。

---

## 🛠 编译指南

为了获得最佳性能，建议根据目标机器的 CPU 架构进行编译。

### x86_64 (Intel / AMD)
```bash
# 主流服务器 (支持 AVX2)
RUSTFLAGS="-C target-cpu=x86-64-v3 -C opt-level=3 -C lto=fat" cargo build --release

# 高端服务器 (支持 AVX-512)
RUSTFLAGS="-C target-cpu=x86-64-v4 -C opt-level=3 -C lto=fat" cargo build --release
```

### ARM64 (鲲鹏 / 倚天 / Graviton)
```bash
# 开启 NEON 与 LSE 锁优化
RUSTFLAGS="-C target-cpu=neoverse-n1 -C opt-level=3 -C lto=fat" cargo build --release
```

---

## 📦 部署与管理

### 1. 快速安装
将编译好的二进制文件上传至服务器，运行以下命令完成系统集成：
```bash
sudo ./cloud-node install
```
该命令会自动：
*   在 `/usr/bin/cloud-node` 创建全局命令。
*   注册并启用 `systemd` 服务。

### 2. 常用命令
```bash
cloud-node start    # 后台启动
cloud-node status   # 查看状态
cloud-node stop     # 停止服务
cloud-node restart  # 重启
cloud-node test     # 检查配置文件 (api_node.yaml)
```

---

## ⚙️ 系统要求
*   **OS**: Linux (推荐 Debian 12+, Ubuntu 20.04+, CentOS 7+)。
*   **内核**: 建议 5.0+ 以获得最佳 BBR 性能。
*   **内存**: 建议 4GB+，针对千万级缓存切片建议 64GB+。

## 📜 开源协议
本项目基于 Apache License 2.0 协议开源。

---

**注意**：请确保在生产环境部署前，已根据业务规模调优系统 `ulimit -n` 限制（建议 1,048,576）。
