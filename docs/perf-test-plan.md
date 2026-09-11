# CloudNode Rust 性能测试方案

面向 `bench-proxy`（Pingora 数据面 + 混合缓存热路径）与 nginx 源站的本地化性能测试方案。
目标：在不同工况下量化边缘代理的 QPS、延迟分位、吞吐与资源占用，并追踪各组成部分（nginx 源站 / 代理转发 / 缓存命中）的性能。

## 拓扑

```
loadgen (oha / http_load_matrix.py)
    │  HTTP/1.1
    ▼
bench-proxy  :8080        ← 被测对象：Pingora proxy + CACHE(512MB mem) + CacheLock
    │  回源 HTTP/1.1 keepalive
    ▼
nginx        :8081        ← 源站：/srv/perf-origin，sendfile on，access_log off
```

- `bench-proxy`：仓库内置的最小化压测代理（`src/bin/bench-proxy.rs`），
  回源固定指向 `127.0.0.1:8081`，所有响应标记为可缓存 1h，缓存键为 URI path。
- nginx 源站：`/etc/nginx/sites-available/perf-origin`，`worker_processes auto`。
- 压测机：8 vCPU / 31GB RAM，三者同机（loopback），结果反映数据面相对能力，
  跨机部署时需重测基线。

## 测试文件集（/srv/perf-origin）

| 文件 | 大小 | 用途 |
|---|---|---|
| `file-1K.bin` … `file-10M.bin` | 1KB–10MB 梯度 | 尺寸梯度/吞吐测试 |
| `many/{0..1999}.bin` | 2000 × 4KB | 多键空间缓存命中测试 |
| `miss/{0..4095}.bin` | 4096 × 256KB ≈ 1.1GB | 超过 512MB 缓存容量，稳定 miss + 逐出 |

## 指标

- **oha（JSON）**：QPS（requestsPerSec）、延迟 p50/p90/p99、吞吐 B/s、成功率、状态码分布。
- **pid_sampler.py**：被测进程 CPU%（avg/max）与峰值 RSS，0.5s 粒度，同时采样 proxy 与 nginx worker。
- **http_load_matrix.py**：连接流失（churn）、慢头、畸形请求等压力工况的延迟样本与错误分类。

## 工况矩阵

| 组 | 名称 | 工况 | 目的 |
|---|---|---|---|
| A | `A-origin-1k-c200` | 直连 nginx，1KB，c=200 | 源站/基线上限，用于计算代理开销 |
| B | `B-hit-1k-c{50,200,500,1000}` | 缓存命中 1KB，并发扫描 | QPS 饱和曲线、单连接吞吐 |
| C | `C-hit-{10K,100K,1M,10M}-c200` | 缓存命中，尺寸梯度，c=200 | 大文件吞吐、内存带宽、写路径开销 |
| D | `D-miss-256k-c200` | 1.1GB 键空间随机回源，c=200 | miss 路径：回源 + 缓存写入 + 逐出 |
| E | `E-hit-1k-churn-c200` + pymatrix churn/keepalive | 每请求新建连接 vs 长连接 | 建连开销、accept/握手路径 |
| F | `F-hit-many-c200` | 2000 键随机命中，c=200 | 缓存索引/查找开销 |

每组默认时长 15s（`DUR` 环境变量可调）。

## 运行方法

```bash
# 1. 构建
cargo build --release --bin bench-proxy

# 2. 部署 nginx 源站（首次）
sudo tee /etc/nginx/sites-available/perf-origin <<'EOF'
server {
    listen 127.0.0.1:8081;
    root /srv/perf-origin;
    access_log off; sendfile on; gzip off;
    location / { add_header Cache-Control "public, max-age=3600"; try_files $uri =404; }
}
EOF
sudo ln -sf /etc/nginx/sites-available/perf-origin /etc/nginx/sites-enabled/
sudo nginx

# 3. 执行全矩阵（结果写入 perf-results/<ts>/）
DUR=15s scripts/perf/run_perf_matrix.sh
```

## 结果文件

- `<name>.oha.json`：oha 完整 JSON 结果（QPS、延迟直方图/分位、状态码分布）。
- `<name>.sys.json`：运行期间 proxy/nginx 的 CPU% 时间序列与峰值 RSS。
- `E-*-pymatrix.json`：连接流失工况的延迟样本统计。

## 判定关注点

- B 组：随并发上升 QPS 是否线性扩展直至 CPU 饱和；p99 拐点。
- C 组：10MB 命中时吞吐是否逼近 loopback/sendfile 上限；大文件是否触发落盘路径。
- D 组：miss 流量下代理 CPU 与 nginx CPU 之比；逐出是否引发延迟毛刺。
- E 组：churn 模式相对 keepalive 的 QPS 折损（accept/握手成本）。
- F vs B：键查找随键空间规模的开销变化。
