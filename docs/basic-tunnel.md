# 基础隧道：已实现规格与使用方法

更新日期：2026-10-03。用户最新要求先实现基础 QUIC + TUN 隧道，并在两台专用 PVE 虚拟机验证。本文件定义这次交付；多路径完整设计继续保留在其他设计文档中。

## 范围

Linux 客户端和服务端，各一个 TUN、一个授权 peer，多条独立 QUIC/H3 连接承载同一个逻辑隧道。内层只支持 IPv4，两端主机可以通过隧道地址双向使用 ICMP、TCP 和 UDP。外层 endpoint 使用 IP 字面量，不做 DNS 解析；可选 server_name 仅用于 TLS SNI 与 HTTP authority。macOS 可生成密钥、校验配置和执行协议测试，尚无 TUN 数据面。

程序只创建自己的 TUN 和对应连接路由，退出关闭 TUN fd 后由内核删除。已有同名接口会被拒绝。需要自行选择未被其他业务使用的隧道网段。程序不修改默认路由、DNS、NAT、防火墙或 IP forwarding。从 0.3.10 起支持经隧道转发第三方 IPv4 子网和 NAT 回程，需由 Linux 配置路由、转发及访问控制，见 [IPv4 路由与 NAT](routing.md)。不支持多 peer、IPv6 内层或面向未授权浏览器的普通网站服务。

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

各自把 `examples/server.toml` / `examples/client.toml` 保存为 `/etc/quicwire/quicwire.toml`，将 `peer_public_key` 替换为另一台机器的完整公钥，并修改客户端 `endpoints`。通过可信渠道核对交换的公钥。私钥留在生成它的机器。

```sh
sudo quicwire check --config /etc/quicwire/quicwire.toml
sudo quicwire run --config /etc/quicwire/quicwire.toml
```

先运行服务端，再运行客户端。服务端需要允许指定 UDP 端口，默认示例为 4433–4440。客户端会自动重连。连接日志出现“隧道已连接”后，从客户端执行 `ping 10.77.0.1`，从服务端执行 `ping 10.77.0.2`。

`check` 只检查配置及密钥，不创建接口或连接。`pubkey --private-key PATH` 可重新输出已有私钥对应的公钥。`keygen` 不覆盖已有文件。

配置字段全部见示例。`server_name` 为可选的客户端 DNS 名称；未配置时 TLS 使用 endpoint IP，不发送项目 SNI。它不改变网络连接目的地，也不代替公钥验证。未知字段视为错误；私钥相对路径按配置所在目录解析；隧道前缀限 `/24` 至 `/30`，两个地址必须在同一网段且不同。`mtu` 默认 1100，允许 576–1100，两端必须一致。客户端外层所有 endpoint 不得在隧道网段内，避免递归路由。`tun_offload` 默认 `true`，启用 Linux TUN 的分段／合并；不支持的环境可设为 `false`，两端不必一致。

多连接配置、N/K 语义、备用轮转、健康选路、监控和边界见 [多路径文档](multipath.md)。旧的 endpoint/bind 单连接配置仍可用，默认 N=K=1。

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
- ALPN 为 `h3`。TLS 完成后等待 HTTP/3 SETTINGS，使用私有 quicwire Extended CONNECT 和 HTTP Datagrams；细节与兼容边界见 [HTTP/3 文档](http3.md)。

HTTP/3 控制流与 QPACK 由 h3 库维护。客户端使用 Extended CONNECT，请求头携带 `:protocol=quicwire`、`capsule-protocol: ?1` 和版本 3。双方通过加密头核对静态地址和 MTU，成功后再用已认证数据通道绑定运行代际和路径 ID。请求流在路径整个生命周期保持打开。

原始 IPv4 包前增加 64 位序号，同一个包复制到 K 条激活路径。接收端跨路径去重后写入 TUN；所有方向统一校验 IPv4 版本、头长度、总长度和 MTU。内层源地址和目的地址不再限制为两个 TUN 端点，访问范围交给 Linux 防火墙控制。去重帧属于私有 H3 扩展协议，不能当作 RFC 9484 的裸 IP 数据格式。

外层 UDP payload 固定初始及最小大小 1200，关闭路径 MTU 探测；内层 MTU 1100 留出 QUIC 开销。路径必须承载标准 QUIC 最小 UDP payload。运行前检查协商后的 DATAGRAM 容量足够。

拥塞控制使用 Quinn 默认 Cubic，每条连接独立拥塞窗口。每路径 QUIC DATAGRAM 发送缓冲 64 KiB、接收缓冲 1 MiB；应用发送队列最多 128 包，聚合接收队列最多 4096 包。队列满时丢弃该慢路径副本，全部激活路径都满才对 TUN 施加背压。TUN 队列限制为 64。断连期间丢弃新业务包。

数据面保留 tun-rs GSO 分段/GRO 合并与 MTU 校验。去重采用 65536 包位图窗口；窗口内乱序接收一次，过旧副本丢弃，不等待慢路径。每个客户端连接独立 UDP socket，请求各 7 MiB 收发缓冲，具备 CAP_NET_ADMIN 时使用 FORCE；不修改全局 sysctl。

TLS、HTTP/3 和多路径绑定各有 10 秒上限，QUIC 空闲超时 6 秒。双向探测每 500 ms 一次，允许多个未决探测；1.5 秒无有效响应判为不可用。客户端维护激活集合，重复发送带版本的控制状态；质量改善需至少 20%、持续 3 秒、距上次切换至少 5 秒，故障替换不受质量滞后限制。重连按 1–8 秒退避；计划轮转立即尝试下一候选并更换源端口。故障不保证任何条件下零丢包。

`quicwire status --config ... [--json]` 从本地受权限限制的 Unix socket 读取状态。每 10 秒输出 JSON 统计，分别记录唯一包、副本、重复/过旧丢弃、路径队列丢弃、TUN 内核队列丢弃、连接失败、切换和轮转。每路径提供 RTT、抖动、探测超时、QUIC 累计丢失，以及约 1 秒采样的数据速率。发送成功表示入队，不代表远端到达。SIGINT/SIGTERM 关闭连接、释放监听和本进程创建的 TUN。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
# Linux，需 root、iproute2、ping 和 Python 3；只在临时 namespace 创建接口和路由
cargo build --locked
sudo bash scripts/linux-smoke.sh target/debug/quicwire
sudo env QUICWIRE_TEST_MULTIPATH=true bash scripts/linux-smoke.sh target/debug/quicwire
```

协议测试覆盖真实双向 TLS、公钥错误、仅复制公钥的私钥冒用、HTTP/3 配置不匹配、非法请求帧、缺失 SETTINGS、Capsule 跨 DATA 帧接收、会话取消与关闭；同时检查配置、密钥文件及 IP 包校验。Linux smoke 测试覆盖真实双向 TUN、MTU 边界、4 MiB TCP 双向内容校验、UDP 小包及 IPv4 分片回传、退出清理和服务端重启恢复。PVE 双机结果见 [实测记录](testing.md)。
