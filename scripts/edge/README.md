# scripts/edge — 分层测试与证据工具（EN-02）

边界：本目录只使用独立资源——netns `en2-ns`、veth `en2-a`/`en2-b`、配置
`configs/en2-api-node.yaml`（运行时临时提升为 `configs/api_node.yaml`，结束
还原）。不触碰现有公共接口、生产网卡或 smoke 的 `cn-*` 资源。

## 组成

- `pktgen.py` — 确定性报文语料：构造/发送（AF_PACKET）/计数观察/写 pcap。
  同一 case 名永远产生同一批字节，结果可重放。
- `runner.py` — 矩阵执行器：建隔离拓扑 → attach XDP → 逐 case 发包 →
  读取 pinned `XDP_COUNTERS` 差值断言 → 统一 JSON 结果。
- `matrix.json` — T01–T18 可追踪入口：每条记录 status
  （runnable/partial/pending）、前置条件、断言、owner 任务。pending 行
  描述计划入口，不伪装成已覆盖。

## 用法

```bash
# 列出全部测试契约
sudo python3 scripts/edge/runner.py --list

# 单功能拓扑（本机 netns，自动建/拆，自动 attach/detach）
sudo python3 scripts/edge/runner.py --only T01 --mode protect \
    --node-bin target/debug/cloud-node-rust --out results.json

# 独立发包机拓扑（不 attach；只发包并读对端快照）
sudo python3 scripts/edge/runner.py --topology external \
    --send-iface eth0 --status-file /path/xdp-state.json
```

## 结果契约

每次运行输出：`ebpf_sha256`（实际加载对象摘要）、每 case 的
`send.{sent_packets,achieved_pps}`、对端 `observed` 帧计数、
`counter_delta`、逐条断言结果。退出码：0 全过 / 1 断言失败 / 3 环境或
前置失败（不静默吞错）。
