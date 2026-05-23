# RKE2 部署文档

本文档说明如何把 CloudNode Rust 以多副本方式部署到 RKE2 集群，并覆盖两种存储路径：复用已有 Longhorn，以及从零安装/创建 Longhorn 后再部署。

## 1. 部署架构

RKE2 模式使用 Kubernetes Deployment 运行多个 `cloud-node` Pod。公网流量通过 `LoadBalancer` Service 进入节点，集群内 Pod 之间通过 Headless Service 调用内部 API。

当前 manifest 位于 `deploy/rke2/`：

- `namespace.yaml`：创建 `cloud-node` namespace。
- `secret.yaml.example`：控制面连接配置和集群内部 token 示例。
- `configmap-runtime.yaml`：RKE2 runtime 配置。
- `deployment.yaml`：cloud-node 多副本 Deployment。
- `service-public.yaml`：公网入口，暴露 TCP/80、TCP/443、UDP/443。
- `service-internal-headless.yaml`：Pod 间内部 API 服务，默认 TCP/19090。
- `networkpolicy.yaml`：限制内部 API 只允许 cloud-node Pod 访问，同时开放公网服务端口。
- `rbac-lease.yaml`：ServiceAccount、Lease Role 和 RoleBinding，用于 Leader 选举。
- `longhorn-storageclass-cache-replica2.yaml`：Longhorn RWX 缓存 StorageClass 示例。
- `longhorn-pvc-shard-00.yaml`、`longhorn-pvc-shard-01.yaml`：两个共享缓存分片 PVC。

运行时关键点：

- `CLOUD_NODE_MODE=rke2` 启用集群模式。
- `runtime.yaml` 中 `cluster.enabled=true`。
- Leader 选举使用 Kubernetes Lease，避免多 Pod 重复处理配置任务、缓存任务和关键统计上报。
- 内部 API 用 `CLOUD_NODE_CLUSTER_INTERNAL_TOKEN` 鉴权。
- 缓存数据使用 Longhorn RWX PVC，按 shard 挂载到 `/cache-shards/shard-00`、`/cache-shards/shard-01`。
- 本地 cache metadata 使用 `emptyDir` 挂载到 `/var/lib/cloud-node/cache-meta`，不放进共享缓存分片。
- `service-public.yaml` 使用 `externalTrafficPolicy: Local`，尽量保留客户端源 IP。

## 2. 前置条件

部署前确认：

1. 已有可用 RKE2 集群。
2. `kubectl` 当前 context 指向目标集群。
3. 集群有可用的 LoadBalancer 实现，例如 MetalLB、云厂商 LB 或其他 RKE2 负载均衡方案。
4. 集群节点已开放入口端口：
   - TCP/80
   - TCP/443
   - UDP/443
5. 已准备 CloudNode Rust 镜像，并推送到集群可拉取的镜像仓库。
6. 已在控制面创建或确认节点凭据：
   - `rpc.endpoints`
   - `nodeId`
   - `secret`
7. 若启用缓存，准备 Longhorn 或其他支持 RWX 的存储类。

## 3. 准备镜像

构建并推送镜像的方式取决于实际 CI/CD。Deployment 中默认占位镜像为：

```yaml
image: YOUR_REGISTRY/cloud-node-rust:latest
```

部署前必须改成真实镜像地址，例如：

```yaml
image: registry.example.com/cloud-node-rust:1.1.2
```

如果集群需要私有仓库凭据，先创建 imagePullSecret，并在 `deploy/rke2/deployment.yaml` 的 Pod spec 中加入：

```yaml
imagePullSecrets:
  - name: your-registry-secret
```

## 4. 配置 Secret

复制示例文件：

```bash
cp deploy/rke2/secret.yaml.example deploy/rke2/secret.yaml
```

编辑 `deploy/rke2/secret.yaml`：

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloud-node-secret
  namespace: cloud-node
type: Opaque
stringData:
  api_node.yaml: |
    rpc.endpoints:
      - https://YOUR_API_NODE_ENDPOINT
    nodeId: "YOUR_LOGICAL_NODE_ID"
    secret: "YOUR_LOGICAL_NODE_SECRET"
    accessLogPipeline:
      queueCapacity: 100000
      batchSize: 10000
      flushIntervalMs: 5000
      uploadConcurrency: 0
      retryQueueCapacity: 0
      requestTimeoutMs: 30000
      warningIntervalMs: 5000
  internal-token: "CHANGE_ME_TO_A_LONG_RANDOM_TOKEN"
```

字段说明：

- `rpc.endpoints`：控制面 gRPC endpoint。
- `nodeId`：控制面分配的逻辑节点 ID。
- `secret`：节点密钥。
- `accessLogPipeline`：访问日志队列、批量、并发和重试参数。
- `internal-token`：Pod 间内部 API 鉴权 token，应使用长随机字符串。

不要提交真实的 `deploy/rke2/secret.yaml`。

## 5. 配置 runtime.yaml

`deploy/rke2/configmap-runtime.yaml` 默认内容如下：

```yaml
runtime:
  mode: rke2
cluster:
  enabled: true
  type: rke2
  name: edge-rke2-01
  namespace: cloud-node
  serviceName: cloud-node-internal
  podNameEnv: POD_NAME
  podIpEnv: POD_IP
  internalApi:
    bind: 0.0.0.0:19090
    tokenEnv: CLOUD_NODE_CLUSTER_INTERNAL_TOKEN
  leaderElection:
    leaseName: cloud-node-leader
    leaseDurationSeconds: 15
    renewDeadlineSeconds: 10
    retryPeriodSeconds: 2
  cache:
    localMetaDir: /var/lib/cloud-node/cache-meta
    maxFastL1Bytes: 0
    sharedMaxBytes: 15TiB
    minFreeBytes: 500GiB
    ignoreControlPlaneStorageOptions: true
    shardStrategy: hash_mod
    shards:
      - id: shard-00
        path: /cache-shards/shard-00
        weight: 1
        replicas: 2
      - id: shard-01
        path: /cache-shards/shard-01
        weight: 1
        replicas: 2
```

需要按实际环境调整：

- `cluster.name`：集群名称，用于内部 API 校验和日志识别。
- `cluster.namespace`：必须与 manifest namespace 一致。
- `sharedMaxBytes`：共享缓存总容量上限。
- `minFreeBytes`：共享缓存保留空闲空间。
- `shards[].path`：必须与 Deployment volumeMount 路径一致。
- `shards[].replicas`：表达缓存 shard 期望副本数，需与 Longhorn volume replica 策略一致。

## 6. 方式一：复用已有 Longhorn

适用于集群已经安装 Longhorn，并已有可用 RWX StorageClass 的场景。

### 6.1 检查 Longhorn 状态

```bash
kubectl get pods -n longhorn-system
kubectl get storageclass
```

确认：

- `longhorn-system` Pod 正常运行。
- 已存在支持 RWX 的 StorageClass。
- 节点磁盘空间满足缓存容量规划。

### 6.2 选择已有 StorageClass

查看 StorageClass：

```bash
kubectl get storageclass -o wide
kubectl describe storageclass <EXISTING_LONGHORN_STORAGECLASS>
```

如果已有 StorageClass 满足要求，可以不应用 `longhorn-storageclass-cache-replica2.yaml`，直接修改两个 PVC 文件中的：

```yaml
storageClassName: longhorn-cache-rwx-replica2
```

改为现有 StorageClass 名称，例如：

```yaml
storageClassName: longhorn
```

### 6.3 确认 PVC 容量

默认两个 PVC 各申请 `5Ti`：

```yaml
resources:
  requests:
    storage: 5Ti
```

按集群实际容量调整。容量应与 `configmap-runtime.yaml` 中：

```yaml
sharedMaxBytes: 15TiB
minFreeBytes: 500GiB
```

保持一致。`sharedMaxBytes` 不应大于实际可用缓存总容量。

### 6.4 应用 PVC

如果复用现有 StorageClass：

```bash
kubectl apply -f deploy/rke2/longhorn-pvc-shard-00.yaml
kubectl apply -f deploy/rke2/longhorn-pvc-shard-01.yaml
```

检查：

```bash
kubectl get pvc -n cloud-node
```

两个 PVC 都应进入 `Bound`。

## 7. 方式二：重新创建 Longhorn 存储类

适用于希望为 CloudNode 缓存单独创建 Longhorn StorageClass 的场景。这里不安装 Longhorn 本体，只创建 CloudNode 使用的 StorageClass；Longhorn 本体仍需先由集群管理员安装完成。

### 7.1 确认 Longhorn provisioner 可用

```bash
kubectl get pods -n longhorn-system
kubectl get csidriver | grep longhorn
```

确认存在 Longhorn CSI driver，例如：

```text
driver.longhorn.io
```

### 7.2 创建专用 StorageClass

应用：

```bash
kubectl apply -f deploy/rke2/longhorn-storageclass-cache-replica2.yaml
```

默认配置：

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: longhorn-cache-rwx-replica2
provisioner: driver.longhorn.io
allowVolumeExpansion: true
reclaimPolicy: Retain
volumeBindingMode: Immediate
parameters:
  numberOfReplicas: "2"
  staleReplicaTimeout: "30"
  fromBackup: ""
  fsType: ext4
  migratable: "false"
  recurringJobSelector: "[]"
```

说明：

- `numberOfReplicas: "2"`：Longhorn volume 存储副本数为 2。
- `reclaimPolicy: Retain`：删除 PVC 后 PV/底层数据默认保留，避免误删缓存数据。
- `allowVolumeExpansion: true`：允许后续扩容 PVC。
- `volumeBindingMode: Immediate`：立即绑定，适合明确容量和节点资源的缓存盘。

### 7.3 创建缓存 PVC

```bash
kubectl apply -f deploy/rke2/longhorn-pvc-shard-00.yaml
kubectl apply -f deploy/rke2/longhorn-pvc-shard-01.yaml
```

检查：

```bash
kubectl get pvc -n cloud-node
kubectl describe pvc cloud-node-cache-shard-00 -n cloud-node
kubectl describe pvc cloud-node-cache-shard-01 -n cloud-node
```

两个 PVC 应为 `Bound`。

### 7.4 扩容缓存 PVC

如需扩容，将 PVC 中的 `resources.requests.storage` 改大后应用：

```bash
kubectl apply -f deploy/rke2/longhorn-pvc-shard-00.yaml
kubectl apply -f deploy/rke2/longhorn-pvc-shard-01.yaml
```

然后检查：

```bash
kubectl get pvc -n cloud-node
```

同时更新 `configmap-runtime.yaml` 中 `sharedMaxBytes`，并重启 Deployment 让运行时读取新配置。

## 8. 部署 CloudNode

### 8.1 应用基础资源

```bash
kubectl apply -f deploy/rke2/namespace.yaml
kubectl apply -f deploy/rke2/rbac-lease.yaml
kubectl apply -f deploy/rke2/secret.yaml
kubectl apply -f deploy/rke2/configmap-runtime.yaml
```

如果使用新建 StorageClass：

```bash
kubectl apply -f deploy/rke2/longhorn-storageclass-cache-replica2.yaml
```

应用 PVC：

```bash
kubectl apply -f deploy/rke2/longhorn-pvc-shard-00.yaml
kubectl apply -f deploy/rke2/longhorn-pvc-shard-01.yaml
```

### 8.2 应用服务和网络策略

```bash
kubectl apply -f deploy/rke2/service-internal-headless.yaml
kubectl apply -f deploy/rke2/service-public.yaml
kubectl apply -f deploy/rke2/networkpolicy.yaml
```

### 8.3 应用 Deployment

部署前修改 `deploy/rke2/deployment.yaml` 中镜像地址。

```bash
kubectl apply -f deploy/rke2/deployment.yaml
```

查看 rollout：

```bash
kubectl rollout status deployment/cloud-node -n cloud-node
kubectl get pods -n cloud-node -o wide
```

## 9. 验证部署

### 9.1 Pod 和探针

```bash
kubectl get pods -n cloud-node
kubectl describe pod -n cloud-node -l app=cloud-node
```

确认：

- Pod 状态为 `Running`。
- startup/readiness/liveness probe 通过。
- PVC 已正常挂载。

### 9.2 内部 API 健康检查

```bash
kubectl exec -n cloud-node deploy/cloud-node -- sh -c 'wget -qO- http://127.0.0.1:19090/internal/v1/health'
```

期望返回类似：

```json
{"ok":true,"cluster":"edge-rke2-01"}
```

### 9.3 Leader 选举

```bash
kubectl get lease -n cloud-node
kubectl describe lease cloud-node-leader -n cloud-node
```

确认 `holderIdentity` 对应某个 cloud-node Pod。

### 9.4 公网 Service

```bash
kubectl get svc -n cloud-node
```

确认 `cloud-node-public` 有可访问的 EXTERNAL-IP 或由本地 LoadBalancer 分配地址。

测试 HTTP：

```bash
curl -H 'Host: your-domain.example' http://<EXTERNAL-IP>/
```

测试 HTTPS：

```bash
curl -k --resolve your-domain.example:443:<EXTERNAL-IP> https://your-domain.example/
```

测试 HTTP/3 需要客户端支持 QUIC，并确认 UDP/443 已从 LB 到 Pod 打通。

## 10. 更新和回滚

### 10.1 更新镜像

修改 `deploy/rke2/deployment.yaml` 中镜像 tag 后：

```bash
kubectl apply -f deploy/rke2/deployment.yaml
kubectl rollout status deployment/cloud-node -n cloud-node
```

### 10.2 重启读取 ConfigMap/Secret

ConfigMap 或 Secret 修改后：

```bash
kubectl rollout restart deployment/cloud-node -n cloud-node
kubectl rollout status deployment/cloud-node -n cloud-node
```

### 10.3 回滚

```bash
kubectl rollout history deployment/cloud-node -n cloud-node
kubectl rollout undo deployment/cloud-node -n cloud-node
kubectl rollout status deployment/cloud-node -n cloud-node
```

## 11. 卸载

先删除 Deployment 和 Service：

```bash
kubectl delete -f deploy/rke2/deployment.yaml
kubectl delete -f deploy/rke2/service-public.yaml
kubectl delete -f deploy/rke2/service-internal-headless.yaml
kubectl delete -f deploy/rke2/networkpolicy.yaml
kubectl delete -f deploy/rke2/rbac-lease.yaml
```

如果要保留缓存数据，不要删除 PVC。默认 StorageClass 使用 `Retain`，但 PVC 删除仍可能影响后续挂载流程。

如确认删除缓存数据：

```bash
kubectl delete -f deploy/rke2/longhorn-pvc-shard-00.yaml
kubectl delete -f deploy/rke2/longhorn-pvc-shard-01.yaml
```

如果专用 StorageClass 不再使用：

```bash
kubectl delete -f deploy/rke2/longhorn-storageclass-cache-replica2.yaml
```

最后删除 Secret、ConfigMap、Namespace：

```bash
kubectl delete -f deploy/rke2/secret.yaml
kubectl delete -f deploy/rke2/configmap-runtime.yaml
kubectl delete -f deploy/rke2/namespace.yaml
```

## 12. 常见问题

### PVC 一直 Pending

检查：

```bash
kubectl describe pvc -n cloud-node
kubectl get storageclass
kubectl get pods -n longhorn-system
```

常见原因：StorageClass 名称不正确、Longhorn CSI 不可用、节点磁盘不足、RWX 依赖组件异常。

### Pod 无法启动并提示 runtime.mode=rke2 配置错误

检查 `/etc/cloud-node/configs/runtime.yaml` 对应的 ConfigMap：

```bash
kubectl get configmap cloud-node-runtime -n cloud-node -o yaml
```

确认：

- `cluster.enabled=true`
- `cluster.type=rke2`
- `cluster.name` 非空
- `cluster.namespace` 非空
- `cluster.serviceName` 非空
- `cluster.cache.localMetaDir` 非空
- 至少有一个 `cluster.cache.shards` 条目
- `CLOUD_NODE_CLUSTER_INTERNAL_TOKEN` 环境变量非空
- `POD_NAME` 和 `POD_IP` 可由 Downward API 注入

### 内部 API 403

检查：

- 请求是否带正确内部 token。
- `cluster.name` 是否一致。
- NetworkPolicy 是否允许 cloud-node Pod 之间访问 TCP/19090。

### HTTP 可访问但 HTTP/3 不通

检查：

- `service-public.yaml` 是否暴露 UDP/443。
- LoadBalancer 是否支持 UDP。
- 控制面全局 HTTP/3 policy 是否启用。
- 站点 HTTPS 是否启用。
- 防火墙或安全组是否放行 UDP/443。

### 源 IP 不正确

确认 `service-public.yaml`：

```yaml
externalTrafficPolicy: Local
```

同时确认 LoadBalancer 没有额外 SNAT。如果仍经过反向代理或四层 LB，需要按实际链路配置真实 IP 头或 PROXY protocol 支持。
