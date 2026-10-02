# 技术选型：Rust + Quinn

日期：2026-10-02。状态：独立开发方向已确定，具体协议仍在设计。

## 决策

quicwire 使用 Rust + Quinn + Tokio，作为独立项目开发。第一版以多条独立 QUIC 连接承载一个逻辑 session，在应用层复制和去重 IP 包。

## 理由

- Quinn 提供 DATAGRAM、TLS exporter、连接统计和可替换拥塞控制接口，符合本项目的数据面及路径绑定需求。
- `send_datagram` 的队列行为和 `send_datagram_wait` 有区别，可根据实时性设计丢弃策略。
- Rust 无追踪式 GC，适合明确控制多发缓冲区生命周期和内存边界。
- 独立开发无需承担现有 Go 内核的迁移或混合语言接入成本。

这些理由不是性能实测结论。吞吐、延迟与内存收益需要在相同硬件、包长、网络条件和算法配置下验证。

## 备选方案

| 方案 | 优势 | 本项目的取舍 |
| --- | --- | --- |
| Go + quic-go | 工具链与 HTTP/3、CONNECT-IP 配套直接 | 上游可插拔拥塞控制尚待提供；v0.63.0 的 DATAGRAM 发送队列满时阻塞，需要隔离 |
| Go + Hysteria 维护分支 | 提供可替换拥塞控制 | 适合复用 Go 内核；独立项目优先采用 Quinn 的公开接口 |
| Rust + TQUIC | 提供原生多路径及多种拥塞控制 | 核对的冗余调度实现复制 STREAM 帧，RFC 9221 DATAGRAM PR 尚未合并，不作为首版依赖 |
| Rust + quiche | 提供 QUIC 与 HTTP/3，暴露较底层接口 | 可作为后续备选；首版优先验证 Quinn 的异步接口及队列模型 |

## 需要验证的成本

Quinn 是 QUIC 传输库，不是现成 IP VPN。TUN、多路径 session、去重、认证配置、地址和路由管理仍需实现。

HTTP/3 与 MASQUE CONNECT-IP 也不因选用 Quinn 自动具备。若选用 `hyperium/h3`，须验证其接口稳定性、HTTP DATAGRAM、capsule、CONNECT-IP 和普通网站共存。

移动端还需要 Android VPN 权限与 socket 保护、iOS Packet Tunnel 集成；Windows 需要对应的隧道接口与路由实现。

## 参考依据

- [Quinn](https://github.com/quinn-rs/quinn)
- [Quinn DATAGRAM 接口](https://docs.rs/quinn/0.11.12/quinn/struct.Connection.html#method.send_datagram)
- [Quinn 拥塞控制配置](https://docs.rs/quinn/0.11.12/quinn/struct.TransportConfig.html#method.congestion_controller_factory)
- [quic-go 拥塞控制](https://quic-go.net/docs/quic/congestion-control/)
- [quic-go v0.63.0 队列源码](https://github.com/quic-go/quic-go/blob/v0.63.0/datagram_queue.go)
- [connect-ip-go](https://github.com/quic-go/connect-ip-go)
- [h3 项目状态](https://github.com/hyperium/h3#status)
- [TQUIC 冗余调度源码](https://github.com/Tencent/tquic/blob/0169abde20c6701c68b1ac5021c3e64702f20cfa/src/multipath_scheduler/scheduler_redundant.rs)
- [TQUIC DATAGRAM PR #520](https://github.com/Tencent/tquic/pull/520)
- [RFC 9221：QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221)
- [RFC 9484：CONNECT-IP](https://www.rfc-editor.org/rfc/rfc9484)
