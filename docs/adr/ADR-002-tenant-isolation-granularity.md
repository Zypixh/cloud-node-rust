# ADR-002 — EN-16 隔离粒度：本仓库无 tenant 概念，listener 池为当前边界

状态：Accepted（EN-16 切片）。

## 背景

EN-16 验收要求"node→listener/tenant/service→worker 配额"。本仓库的配置
模型里**不存在 tenant**：转发规则、listener、服务都没有 tenant 身份
字段，API 也不携带租户凭据。把所有客户流量默认视为同一可信身份并
宣称"多租户完成"是不允许的——这是明确的合同缺口，如实记录。

## 决策

当前的公平隔离粒度为 **(listener, class)** 池：

- `MemoryGovernor::try_admit_listener(key, class)`：节点级 class permit
  之外要求 per-(listener, class) 槽位；cap = ceil(class_limit /
  活跃 listener 数)，下限 `LISTENER_POOL_FLOOR=16`。
- 池只约束新准入，不抢占在途连接；map 有界（4096 项），满时先回收
  空闲池仍满则显式拒绝并计数。
- 已接入全部 6 个准入点（HTTP/TCP kernel+AF_XDP、H3、UDP session）。

未识别租户流量落在 listener 池上——任一 listener 上的突发不能饿死
其他 listener 的准入，满足 EN-16"未识别租户流量进入 listener 池"
的验收意图。

## 明确不是 tenant 配额的部分

- 同一 listener 下的不同客户之间无隔离：一个恶意客户吃满该 listener
  池会殃及同 listener 的正常客户。这是设计限制。
- 若未来引入 tenant 身份（如按 SNI/证书/网段归属），listener 池是
  其下的二级粒度，不冲突；届时需要：(1) 身份字段进配置与 ABI；
  (2) 池 key 扩展为 (tenant, listener, class)；(3) tenant 级预算注册。

## 影响

- 正确性：无——隔离是新增的约束，不改变既有准入语义。
- 可观测性：`listener_pool_{active,tracked,rejects}` 透出到
  GovernorSnapshot 与 perf monitor。
- 恢复：无状态迁移——池为纯内存结构，重启后自然重建。

## 备选（未采用）

- 引入完整 tenant 模型：超出本阶段范围，且无身份来源可定义。
- 维持节点级单一池：被"未识别租户流量进入 listener 池"验收排除。
