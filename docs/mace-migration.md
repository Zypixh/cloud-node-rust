# RocksDB 到 Mace 元数据迁移

运行时从 RocksDB 切换到 Mace 后，节点使用新的 `metrics.mace` 目录。它不会尝试打开或修改旧的 `metrics.db`，因为两种存储格式不兼容。

## 上线步骤

1. 停止节点，确保旧 RocksDB 在迁移期间没有写入。
2. 为 `data/metrics.db` 做文件系统级备份。
3. 把数据导入同级的新目录：

```bash
cd /path/to/cloud-node
migration_target="$(mktemp -d)"
trap 'cargo clean --target-dir "$migration_target"' EXIT
CARGO_TARGET_DIR="$migration_target" cargo xtask migrate-metrics-to-mace \
  --source data/metrics.db \
  --destination data/metrics.mace
```

4. 检查每个 `metrics`、`unique_ip`、`cache_meta`、`firewall`、`waf_token`、`client_agent` 和 `runtime_stats` bucket 都输出 `Imported` 或 `Verified`，且没有错误。
5. 部署包含 Mace 的新二进制后启动节点。运行时会使用 `data/metrics.mace`。

RKE2 部署将上面的 `data/` 替换为 `cluster.cache.localMetaDir`；源目录是 `metrics.db`，目标目录是 `metrics.mace`。

## 可恢复性与回滚

导入器以只读方式打开 RocksDB，不会删除、压缩或改写源数据库。每个 Mace bucket 在完成时会保存记录数、字节数和源数据 SHA-256；重复执行相同命令会验证已完成 bucket，未完成 bucket 会从头以幂等 upsert 继续导入。

如果导入失败，先解决错误后对相同源和目标重跑命令。不要把导入目标设在 RocksDB 源目录内，也不要把已有业务数据的 Mace 目录作为导入目标。

回滚时停止新节点，保留 `metrics.mace` 供排查，并启动仍使用 `metrics.db` 的旧二进制。由于源库未修改，回滚不需要反向转换。
