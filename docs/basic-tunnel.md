# 基础隧道：已实现规格与使用方法

更新日期：2026-10-03。用户最新要求先实现基础 QUIC + TUN 隧道，并在两台专用 PVE 虚拟机验证。本文件定义这次交付；多路径完整设计继续保留在其他设计文档中。

## 范围

Linux 客户端和服务端，各一个 TUN、一个授权 peer、一条 QUIC 连接。内层只支持 IPv4，两端主机可以通过隧道地址双向使用 ICMP、TCP 和 UDP。外层 endpoint 使用 IP 字面量，不做 DNS 解析；可选 server_name 仅用于 TLS SNI 与 HTTP authority。macOS 可生成密钥、校验配置和执行协议测试，尚无 TUN 数据面。

程序只创建自己的 TUN 和对应连接路由，退出关闭 TUN fd 后由内核删除。已有同名接口会被拒绝。需要自行选择未被其他业务使用的隧道网段。程序不修改默认路由、DNS、NAT、防火墙或 IP forwarding。不支持经隧道转发第三方子网、多 peer、IPv6 内层、多路径或面向未授权浏览器的普通网站服务。

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

配置字段全部见示例。`server_name` 为可选的客户端 DNS 名称；未配置时 TLS 使用 endpoint IP，不发送项目 SNI。它不改变网络连接目的地，也不代替公钥验证。未知字段视为错误；私钥相对路径按配置所在目录解析；隧道前缀限 `/24` 至 `/30`，两个地址必须在同一网段且不同。`mtu` 默认 1100，允许 576–1100，两端必须一致。客户端外层 endpoint 不得在隧道网段内，避免递归路由。`tun_offload` 默认 `true`，启用 Linux TUN 的分段／合并；不支持的环境可设为 `false`，两端不必一致。

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
- QUIC 使用 TLS 1.3 双向认证。启动时用原有 Ed25519 私钥生成自签 X.509 容器；对端提取 RFC 8410 SPKI 并与预配置公钥精确比较。没有 CA 依赖或业务 API，证书域名／签发机构不承担信任判断。
- 双方精确匹配配置中的 peer 公钥，并由 TLS CertificateVerify 校验对端持有对应私钥。复制公钥而没有私钥无法通过认证。禁止 TLS 1.2、0-RTT 和会话恢复。
- 私钥以排他创建方式保存，Unix 权限为 0600；加载时拒绝 group/world 权限、符号链接、超过 4 KiB 的文件。不输出私钥内容。私钥未采用口令加密，文件存储安全由主机负责。
- ALPN 为 `h3`。TLS 完成后等待 HTTP/3 SETTINGS，使用 CONNECT-IP 和 HTTP Datagrams；细节与兼容边界见 [HTTP/3 文档](http3.md)。

HTTP/3 控制流与 QPACK 由 h3 库维护。客户端以 Extended CONNECT 请求 `/.well-known/masque/ip/*/*/`，携带 `:protocol=connect-ip` 与 `capsule-protocol: ?1`；双方用加密的 `x-tunnel-address`、`x-tunnel-peer`、`x-tunnel-mtu` 头核对静态配置，成功响应为 200。请求流在整个隧道生命周期保持打开，流或连接关闭即终止会话并触发重连。

一个完整 IPv4 包对应一个 HTTP Datagram，编码为 Quarter Stream ID + Context ID 0 + IP 包，再放入 QUIC DATAGRAM。发送不重传、不拆分，依赖内层 TCP 自身恢复。接收兼容 DATAGRAM Capsule，未知 Context 或未知 Capsule 按协议忽略；静态地址模式拒绝会话内动态地址与路由变更。收发方向都检查 IPv4 头长度、总长度、MTU、来源地址和目的地址；只允许配置的两个隧道主机地址。合法 IPv4 分片由接收主机内核重组。

## 资源与失败行为

外层 UDP payload 固定初始及最小大小 1200，关闭路径 MTU 探测；内层 MTU 1100 留出 QUIC 开销。路径必须承载标准 QUIC 最小 UDP payload。运行前检查协商后的 DATAGRAM 容量足够。

拥塞控制使用 Quinn 默认 Cubic。DATAGRAM 发送缓冲 64 KiB、接收缓冲 1 MiB；发送缓冲不足时等待空间，对 TUN 读取施加背压。TUN 发送队列限制为 64，避免无限积压；过载时内核队列或 QUIC 接收队列仍可能丢包。断开期间读取并丢弃 TUN 包，不保存待恢复流量。等待发送可被连接关闭或进程退出打断。QUIC 自身的接收缓冲丢包不包含在应用丢包计数中。

数据面使用单线程 Tokio 事件循环，以及 tun-rs 的 GSO 分段／GRO 合并；接收合并每批最多处理 128 包；发送分段缓冲按 MTU 留足容量，包括低 MTU 和较长 IP/TCP options 的情况。收到第一个 QUIC DATAGRAM 后只合并已经就绪的数据，不为凑批而等待。大 TUN 包在发送前拆成独立、经过地址与 MTU 校验的 IPv4 包，每个 IP 包增加 HTTP Datagram 请求标识与 Context ID（首个请求通常共 2 字节）。

程序为自身 UDP socket 请求各 7 MiB 收发缓冲，并在具备 `CAP_NET_ADMIN` 时使用 Linux 的 `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE`。权限不足时保留系统允许的普通设置，不修改全局 sysctl。启动日志输出实际缓冲大小，Linux 返回值包含内部加倍的部分。缓冲是容量上限，不是预先填充的固定延迟；满载延迟仍需要单独测量。

TLS 和 HTTP/3 隧道协商各有 10 秒上限，空闲超时 6 秒，保活间隔 2 秒。客户端失败后按 1、2、4、8 秒退避，最高 8 秒；成功建立隧道后重置。实际恢复时间受超时、退避、RTT 和调度影响，不承诺亚秒切换。服务端有活动隧道时拒绝新连接；客户端意外重启可能要等旧连接超时。服务端最多容纳 16 个待处理 incoming，串行认证，尚未提供公网抗拒绝服务的完整防护。

每 10 秒输出累计收发及丢弃计数，以及 QUIC RTT、拥塞窗口、发送／丢失包数和接收 DATAGRAM 数；`tx_queued` 表示进入 QUIC 队列，`rx_delivered` 表示写入 TUN，不代表应用实际消费或远端确认。SIGINT/SIGTERM 正常关闭 QUIC 并释放 TUN，进程异常退出时内核也会关闭非持久 TUN fd。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
# Linux，需 root、iproute2、ping 和 Python 3；只在临时 namespace 创建接口和路由
cargo build --locked
sudo bash scripts/linux-smoke.sh target/debug/quicwire
```

协议测试覆盖真实双向 TLS、公钥错误、仅复制公钥的私钥冒用、HTTP/3 配置不匹配、非法请求帧、缺失 SETTINGS、Capsule 跨 DATA 帧接收、会话取消与关闭；同时检查配置、密钥文件及 IP 包校验。Linux smoke 测试覆盖真实双向 TUN、MTU 边界、4 MiB TCP 双向内容校验、UDP 小包及 IPv4 分片回传、退出清理和服务端重启恢复。PVE 双机结果见 [实测记录](testing.md)。
