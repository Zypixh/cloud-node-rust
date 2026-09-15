# R0 — 验证入口可信化 + pin 隔离

日期: 2026-09-15。环境: `.110` (ser790960344190) 构建机, `.120` (ser591614511633) 探针机,
均为 Debian 12 / kernel 6.1.0-10-amd64 / 2c/2GiB。本机仅编辑+传输，无本地编译测试。

## 修复内容

### `scripts/edge/vps_remote_build.sh`（重写）

- 入口门禁：`uname -s`=Linux、`/root/.cn-authorized-vps` 注册标记、
  `$TASK_DIR/.cn-task-owner` 任务目录所有权标记、目录内含 `Cargo.toml`。
- `flock -n` 单构建互斥：争用立即 `exit 75`，不排队。
- 每步真实退出码：`rc=0; cargo build > build.log 2>&1 || rc=$?`，
  非零即打印 `BUILD FAILED rc=N` + tail 展示（完整日志保留在 build.log/
  test.log），退出码原样外传；管道不再吞错。
- 资源约束：`CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 RUSTFLAGS=-C debuginfo=0`。

### `scripts/edge/vps_sync.sh`（重写）

- 单一文件清单驱动：`rsync --files-from`、SHA256 manifest、远端
  extra-sweep 共用同一份 `cn-files.txt`（排除 `.git/target/data/
  credentials*/.env/*.pem`(非 pingora 示例钥) 等）。
- Manifest 生成失败即退出（文件数 ≤100 视为损坏拒绝）。
- 远端先验主机登记（`/root/.cn-authorized-vps`）与任务目录所有权
  （`.cn-task-owner`）；目录存在但无 marker → 拒绝，不传输不删除。
- 远端 sweep 仅删清单外文件且排除 `.cn-task-owner`/`.build.lock`/
  `cn-files.txt`/`SOURCE-SHA256.txt`/`*.log`，`LC_ALL=C comm` 排序对齐。
- `shasum -a 256 -c` 全量校验，任何 mismatch → `VERIFY FAILED` + rc=4。

### `scripts/edge/en14_cookie_probe.py` + `src/xdp/{linux,mod}.rs`

- 新增 `CLOUD_NODE_XDP_PIN_DIR` 覆盖（默认 `/sys/fs/bpf/cloud-node-xdp`
  不变），探针使用唯一 per-run 目录 `/sys/fs/bpf/en14-probe-<pid>`。
- 启动前断言 `PIN_DIR != PROD_PIN_DIR && PIN_DIR.startswith(en14-probe-)`；
  `clean_pins()` 对越界路径 raise 而非执行 rm。
- 所有子进程（node / dump-maps / sender）经 `os.environ` 继承隔离 pin 根。
- 报告记录 `prod_pin_dir_untouched`（运行前后存在性对比）。

## 负路径验收（实际执行，真实退出码）

| 负例 | 命令/注入 | 期望 | 实测 |
|---|---|---|---|
| 构建失败传播 | eBPF 源缺 import 时 `vps_remote_build.sh` | 非零 | `BUILD FAILED rc=101`，未打印 done 标记 ✓ |
| 构建锁争用 | 构建进行中第二次调用同脚本 | 快速拒绝 | `refusing: another build holds .build.lock`，rc=75 ✓ |
| 外来目录保护 | 移走 `.120:/root/cloud-node-dev/.cn-task-owner` 后 `vps_sync.sh 120` | 拒绝 | `refusing: ... exists without .cn-task-owner marker`，rc=3 ✓ |
| 同步文件损坏 | 远端 `build.rs` 单字节 dd 改写（保持 size+mtime 使 rsync 跳过） | 校验失败 | `VERIFY FAILED: shasum rc=1` + 点名 `build.rs: FAILED`，rc=4 ✓ |
| 恢复 | 删除远端损坏文件后重跑 | 修复 | `verified: all checksums OK`，rc=0 ✓ |
| 未授权主机 | 脚本内置 host 白名单（.110/.120） | 拒绝 | case 分支 `exit 2`（代码审查 + 负例一致） |

## 正路径基线

- `vps_sync.sh .110` / `.120`：`verified: all checksums OK`，1000 文件。
- `vps_remote_build.sh .110`：eBPF 对象 `sha256=1ed952a1…` +
  userspace `sha256=7734a375…`（见 R1/R2 记录，构建后复测）。
- 测试失败传播已证实（memory_reclaim 断言失败 → 脚本非零退出、无 done 标记）。

## 遗留

- 主机登记 bootstrap 为一次性人工 SSH（凭据不出密录），已在两台执行。
- `cargo test --workspace` 期间做过一次中途同步（rsync 源替换）——
  该轮测试结果作废重跑，不作为证据。
