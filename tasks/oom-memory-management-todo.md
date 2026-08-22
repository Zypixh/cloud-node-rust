# OOM 内存管理清单

- [x] 建立 ResidentCategory、owner replacement/remove、category/global snapshot。
- [x] metadata 与 access log 使用保守估算，并同时受 bytes/entries 限制。
- [x] 过期 metadata 不进入 resident；不因 resident 饱和删除磁盘。
- [x] surrogate tag/member/total/长度/每响应 tag 限制的第一版。
- [x] Bloom 维持单调语义，增加估算记账脚手架；negative cache 可回收记账。
- [x] 接入 cgroup effective memory.max/high/swap.max（沿祖先目录取 min）。
- [x] 增加 RSS/PSS/anon 采样；governor 与 RPC 暴露，不把 resident estimate 当 RSS。
- [x] 完成 Bloom 双代 rotation 与原子切换（live ArcSwap + stale 延迟回收）。
- [x] 完成 saturated surrogate purge 的有界全量扫描补偿。
- [x] 增加 DB 启动 reconciliation：损坏条目隔离、过期跳过、resident 饱和不删盘。
- [ ] 运行 soak/fault/压力测试并建立 rollout rollback dashboard。

验收依赖：cgroup/RSS 已进入 snapshot；Bloom rotation 与 saturated tag scan 已落地。生产阈值仍需 soak 校准。
