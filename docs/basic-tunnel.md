# 基础隧道：已实现规格与使用方法

更新日期：2026-10-02。用户最新要求先实现基础 QUIC + TUN 隧道，并在两台专用 PVE 虚拟机验证。本文件定义这次交付；多路径完整设计继续保留在其他设计文档中。

## 范围

Linux 客户端和服务端，各一个 TUN、一个授权 peer、一条 QUIC 连接。内层只支持 IPv4，两端主机可以通过隧道地址双向使用 ICMP、TCP 和 UDP。外层配置使用 IP 字面量，不做 DNS 解析。macOS 可生成密钥、校验配置和执行协议测试，尚无 TUN 数据面。

程序只创建自己的 TUN 和对应连接路由，退出关闭 TUN fd 后由内核删除。已有同名接口会被拒绝。需要自行选择未被其他业务使用的隧道网段。程序不修改默认路由、DNS、NAT、防火墙或 IP forwarding。不支持经隧道转发第三方子网、多 peer、IPv6 内层、多路径或 HTTP/3 网站外观。

## 构建与运行

```sh
cargo build --release --locked
sudo install -m 755 target/release/quicwire /usr/local/bin/quicwire
sudo install -d -m 700 /etc/quicwire
```

两台机器分别生成自己的私钥（命令只输出对应公钥）：

```sh
# 服务端
sudo quicwire keygen --out /etc/quicwire/server.key
# 客户端
sudo quicwire keygen --out /etc/quicwire/client.key
```

各自把 `examples/server.toml` / `examples/client.toml` 保存为 `/etc/quicwire/quicwire.toml`，将 `peer_public_key` 替换为另一台机器的完整公钥，并修改客户端 `endpoint`。通过可信渠道核对交换的公钥。私钥留在生成它的机器。

```sh
sudo quicwire check --config /etc/quicwire/quicwire.toml
sudo quicwire run --config /etc/quicwire/quicwire.toml
```

先运行服务端，再运行客户端。服务端需要允许指定 UDP 端口，默认示例为 4433。客户端会自动重连。连接日志出现“隧道已连接”后，从客户端执行 `ping 10.77.0.1`，从服务端执行 `ping 10.77.0.2`。

`check` 只检查配置及密钥，不创建接口或连接。`pubkey --private-key PATH` 可重新输出已有私钥对应的公钥。`keygen` 不覆盖已有文件。

配置字段全部见示例。未知字段视为错误；私钥相对路径按配置所在目录解析；隧道前缀限 `/24` 至 `/30`，两个地址必须在同一网段且不同。`mtu` 默认 1100，允许 576–1100，两端必须一致。客户端外层 endpoint 不得在隧道网段内，避免递归路由。

## systemd

配置和密钥就绪后：

```sh
sudo install -m 644 contrib/quicwire.service /etc/systemd/system/quicwire.service
sudo systemctl daemon-reload
sudo systemctl enable --now quicwire
sudo journalctl -u quicwire -f
```

服务需要 `/dev/net/tun` 和 `CAP_NET_ADMIN`，按示例以受限 capability 的 root 运行。配置修改通过 `systemctl restart quicwire` 生效；不支持在线重载。更换或撤销 peer 公钥必须重启服务，旧连接随之关闭。停止命令为 `systemctl stop quicwire`。

## 公私钥与协议

- 身份密钥为 Ed25519；公钥编码 `quicwire-public-v1:` + Base64 的 32 字节公钥；私钥编码 `quicwire-private-v1:` + Base64 PKCS#8。使用独立格式，不与 WireGuard 的 X25519 密钥互通。
- QUIC 使用 TLS 1.3 双向 Raw Public Key（RFC 7250），公钥用 RFC 8410 SPKI 编码。没有 CA、X.509 签发或业务 API。
- 双方精确匹配配置中的 peer 公钥，并由 TLS CertificateVerify 校验对端持有对应私钥。复制公钥而没有私钥无法通过认证。禁止 TLS 1.2、0-RTT 和会话恢复。
- 私钥以排他创建方式保存，Unix 权限为 0600；加载时拒绝 group/world 权限、符号链接、超过 4 KiB 的文件。不输出私钥内容。私钥未采用口令加密，文件存储安全由主机负责。
- ALPN 为 `quicwire/0.1`。TLS 完成后交换控制 HELLO，再交付内层数据。

HELLO 占 16 字节，通过客户端开启的唯一双向 stream 交换，发送后 FIN。字段依次为 `QW01`（4 字节）、发送方 IPv4（4）、预期接收方 IPv4（4）、MTU（2，大端）、保留零（2）。地址必须互相对应，MTU 必须相等，长度及保留字段严格检查。不匹配关闭连接，应用错误码为 1。正常关闭使用错误码 0。

一个完整 IPv4 包对应一个 QUIC DATAGRAM。DATAGRAM 不重传、不拆分，依赖内层 TCP 自身的恢复机制。收发方向都检查 IPv4 头长度、总长度、MTU、来源地址和目的地址；只允许配置的两个隧道主机地址。合法 IPv4 分片可通过，由接收主机内核重组。内层 IP 校验和由操作系统处理。

## 资源与失败行为

外层 UDP payload 固定初始及最小大小 1200，关闭路径 MTU 探测；内层 MTU 1100 留出 QUIC 开销。路径必须承载标准 QUIC 最小 UDP payload。运行前检查协商后的 DATAGRAM 容量足够。

拥塞控制使用 Quinn 默认 Cubic。DATAGRAM 发送缓冲 64 KiB、接收缓冲 256 KiB；发送缓冲不足时丢弃当前包，不阻塞 TUN 读取。断开期间读取并丢弃 TUN 包，不保存待恢复流量。QUIC 自身的接收缓冲丢包不包含在应用丢包计数中。

TLS 和 HELLO 各有 10 秒上限，空闲超时 6 秒，保活间隔 2 秒。客户端失败后按 1、2、4、8 秒退避，最高 8 秒；成功建立隧道后重置。实际恢复时间受超时、退避、RTT 和调度影响，不承诺亚秒切换。服务端有活动隧道时拒绝新连接；客户端意外重启可能要等旧连接超时。服务端最多容纳 16 个待处理 incoming，串行认证，尚未提供公网抗拒绝服务的完整防护。

每 10 秒输出累计收发及丢弃计数；`tx_queued` 表示进入 QUIC 队列，`rx_delivered` 表示写入 TUN，不代表应用实际消费或远端确认。SIGINT/SIGTERM 正常关闭 QUIC 并释放 TUN，进程异常退出时内核也会关闭非持久 TUN fd。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
# Linux，需 root、iproute2 和 ping；只在临时 namespace 创建接口和路由
cargo build --locked
sudo bash scripts/linux-smoke.sh target/debug/quicwire
```

协议测试覆盖真实双向 TLS、公钥错误、仅复制公钥的私钥冒用、HELLO 配置不匹配与超长消息；同时检查配置、密钥文件及 IP 包校验。Linux smoke 测试覆盖真实双向 TUN、MTU 边界、退出清理和服务端重启恢复。PVE 双机实测另行记录。
