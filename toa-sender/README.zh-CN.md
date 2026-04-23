# TOA Sender

这个目录实现的是 **发送侧 TOA**，和 [toa-main](/Users/moying/Documents/project/cloud-node-rust/toa-main/toa.c:1) 的接收侧内核模块配套。

语义是：

1. 边缘节点用户态代理知道真实客户端 `IP:port`
2. 用户态通过 `Generic Netlink` 把 `local_port -> real_client_addr` 注册进发送侧模块
3. 发送侧模块在 `NF_INET_LOCAL_OUT` 的 TCP SYN 上写入 `TCPOPT_TOA=254`
4. 后端机器加载 `toa-main` 这样的接收侧模块，在 accept/getname 路径恢复真实客户端地址

## 当前实现

- `kernel/cloud_toa_sender_main.c`
  - Generic Netlink 控制面
  - `LOCAL_OUT` 的 IPv4/IPv6 netfilter hook
  - 在出站 SYN 上尝试注入 TOA option

- `kernel/cloud_toa_sender_map.[ch]`
  - 按本地源端口维护映射表

- `include/uapi/cloud_toa_sender_uapi.h`
  - 用户态和内核态共享的 UAPI

## 当前边界

这版已经是**真正的 sender-side TOA 方向**，但还没有在 Linux 上实际编译联调，所以下面这些点仍需要实测确认：

- skb 改写和 checksum 在目标内核版本上的兼容性
- IPv6 `LOCAL_OUT` 路径的稳定性
- 主 Rust 代理里的用户态分配器和内核 sender 模块的 Linux 实测联调

## 构建

```bash
cd toa-sender
make KDIR=/lib/modules/$(uname -r)/build
```

## 控制面设计

当前 sender 模块期望用户态通过 Generic Netlink family `CLOUD_TOA_SENDER` 发这几类命令：

- `ADD`
- `DEL`
- `GET`
- `FLUSH`

主键是：

- `local_port`

映射内容是：

- `family`
- `client_addr`
- `client_port`

现在主代理内部走的正确链路是：

1. 主 Rust 代理从本地端口池分配一个 `local_port`
2. 主 Rust 代理通过 Generic Netlink 向 sender 模块执行 `ADD(local_port, real_client_addr)`
3. 主代理 `bind(local_port)` 再 `connect(origin)`
4. sender 模块在出站 SYN 上写入 `TCPOPT_TOA=254`
5. 后端 `toa-main` 在 accept/getname 路径恢复真实客户端地址
6. 连接结束后主代理执行 `DEL(local_port)`
