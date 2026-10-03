# HTTP/3 协议与流量外观

当前版本：0.3.0，2026-10-03。

0.3 保留实际 HTTP/3 与公钥信任模型；为承载跨连接序号、探测和控制消息，守护进程使用私有 `:protocol=quicwire`、`x-tunnel-version: 3`。这些内容处于加密 HTTP 请求中，外层仍为 ALPN h3。HTTP Datagram 内 Context 0 后是私有消息，不再宣称符合 RFC 9484 的原始 IP 负载。多路径格式及行为见 [多路径文档](multipath.md)。0.3 要求两端一起升级，私钥无需更换。

下文 CONNECT-IP 描述记录 0.2 的协议基础和保留的独立协议测试；当前运行入口使用上面的私有多路径扩展。

## 已实现

- ALPN `h3`，合法 HTTP/3 控制流、SETTINGS、QPACK HEADERS 与长驻请求流，由 hyperium/h3 0.0.8 与 h3-quinn 0.0.10 实现。
- Extended CONNECT 使用 `:protocol=connect-ip`、HTTPS scheme、`/.well-known/masque/ip/*/*/` 路径。服务端必须声明 ENABLE_CONNECT_PROTOCOL；双方必须声明 H3_DATAGRAM。请求开始前等待实际 SETTINGS，不以固定延时猜测能力。
- 静态地址配置使用加密的三个扩展头双向核对：x-tunnel-address、x-tunnel-peer、x-tunnel-mtu。重复、缺失或不匹配均拒绝。这些头是本项目的静态配置约束，因此不是任意 MASQUE 客户端无需配置即可互通的通用代理。
- IP 数据遵循 HTTP Datagrams 的 Quarter Stream ID 与 CONNECT-IP Context ID=0 格式。未知请求标识和 Context 不进入 TUN。DATAGRAM 不转成可靠 STREAM 数据发送；接收端支持 RFC 9297 DATAGRAM Capsule 后备编码。
- Capsule 支持跨 HTTP DATA 帧解析，单个 Capsule 和解析缓冲设有上限；未知类型忽略。地址由带外静态配置确定，不动态安装 peer 提供的地址或路由；动态地址及路由 Capsule 触发会话拒绝。
- CONNECT 请求／响应流保持打开，关闭或错误会结束隧道。取消协商会终止后台 H3 驱动，避免残留连接。

## 公钥信任模型

现有 Ed25519 私钥与公钥编码不变。每次启动生成包含同一身份公钥的自签 X.509 证书，证书只充当 TLS 标准容器。对端精确固定证书内 SPKI，随后验证 TLS CertificateVerify。无需购买证书、部署 CA 或认证 API。改变证书容器没有增加一层业务加密。

不使用 RFC 7250 Raw Public Key 类型协商，因此 ClientHello 不再主动携带此前的 client_certificate_type / server_certificate_type RPK 扩展。证书生命周期或域名不代替公钥信任；未知 key 和持有另一把私钥的冒用者都会失败。TLS 1.2、0-RTT、会话恢复保持禁用。

## SNI 与连接地址

```toml
endpoint = "192.0.2.1:4433"
# 可选，填你控制的服务域名
server_name = "vpn.example.com"
```

endpoint 仍是实际连接 IP 和端口；server_name 不触发 DNS 查询。配置域名时以该名字发送 SNI 和 HTTP authority，未配置时使用 endpoint IP，TLS 不发送 SNI。程序不再硬编码项目名作为 SNI。

## 外观边界

这是实际的 HTTP/3 隧道协议，而不只是更换 ALPN 字符串。旁路仍能识别 QUIC，以及时间、包长、连接行为等特征。Rustls/Quinn 的实现指纹不等同于 Chrome；不保证与普通浏览器不可区分，也不提供规避某个具体 DPI 的保证。

当前保留双向公钥认证，不提供未授权浏览器访问的公共网站。自签证书也不是浏览器默认信任的 Web PKI 证书。需要普通网站共存时，应单独设计网站 TLS 信任与隧道认证边界。

## 兼容与升级

0.2.0 与原来 ALPN quicwire/0.1、QW01 HELLO、裸 IP DATAGRAM 的 0.1.x 不兼容。两端必须一起升级，公私钥文件无需更换；旧配置无需增加字段。保留旧程序可回退，但回退也要同时恢复两端。

内层仍为 IPv4，MTU 576–1100，默认 1100；单 peer，0.3 支持同一实例的多连接冗余，不自动配置默认路由。吞吐和延迟必须以 H3 版实测为准，不能直接引用旧版结果。

## 依赖补丁

vendor/h3 保留上游 MIT 许可和原始实现，仅补充 CONNECT_IP 协议枚举、解析，以及只读的对端 SETTINGS 查询接口。补丁说明在 vendor/h3/QUICWIRE-PATCH.md；Cargo.lock 固定依赖。后续上游提供等价接口时可以移除本地补丁。

## 协议参考

- RFC 9114：https://www.rfc-editor.org/rfc/rfc9114.html
- RFC 9220：https://www.rfc-editor.org/rfc/rfc9220.html
- RFC 9297：https://www.rfc-editor.org/rfc/rfc9297.html
- RFC 9484：https://www.rfc-editor.org/rfc/rfc9484.html
