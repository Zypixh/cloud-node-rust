# CloudNode Rust 文档

这个目录保存 CloudNode Rust 的长期维护文档。README 只保留项目入口信息，具体功能、运行时、配置和运维细节统一放在这里。

## 文档目录

- [架构概览](architecture.md)：说明控制面、代理运行时、缓存、WAF、日志统计和四层代理之间的关系。
- [运行时说明](runtime.md)：说明进程启动、任务调度、配置热更新、证书、缓存后台任务和性能监控。
- [功能说明](features.md)：逐项介绍协议代理、缓存、WAF、内容处理、日志统计、证书和多级分发能力。
- [配置说明](configuration.md)：说明 `configs/api_node.yaml`、运行目录、数据文件、缓存目录和控制面配置兼容。
- [XDP/AF_XDP 旁路数据面](xdp-af-xdp.md)：说明 Linux XDP protect/proxy 配置、CLI、回退、协议接入和集成测试。
- [接收配置审计](config-receive-audit.md)：对照全局配置、网站配置、实际应用路径和优先级，并列出当前接收缺口。
- [部署与运维](operations.md)：说明构建、安装、systemd、系统参数、监控、日志和排障建议。
- [RKE2 部署文档](rke2-deployment.md)：说明 RKE2 多副本部署流程，以及复用/新建 Longhorn 的缓存存储配置。
- [gRPC API 使用文档](grpc-api.md)：说明节点当前调用的控制面 gRPC 接口、请求、响应和配置应用方式。

## 阅读顺序

新接触项目时建议按以下顺序阅读：

1. 先读 [架构概览](architecture.md)，理解节点整体数据流。
2. 再读 [配置说明](configuration.md)，确认节点如何连接控制面。
3. 然后读 [功能说明](features.md)，理解各类能力边界。
4. 最后读 [运行时说明](runtime.md) 和 [部署与运维](operations.md)，用于上线和排障。

## 文档维护原则

- README 保持简洁，避免堆叠所有实现细节。
- 功能变更需要同步更新对应文档。
- 文档中的命令必须能对应当前 CLI。
- 不在文档中暴露真实节点密钥、内网地址或生产账号信息。
