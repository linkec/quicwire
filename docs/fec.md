# FEC 前向纠错

从 0.3.6 起，客户端与服务端顶层配置支持 `fec = 0 | 1 | 2 | 3`，默认 0。两端必须取相同值；H3 协商会拒绝参数不一致，不能与未支持 FEC 的旧端静默混用。关闭 FEC 时保留原有 K 路同包多发协议。

| 配置 | 行为 |
| --- | --- |
| `fec = 0` | 关闭 FEC，原始包向所有激活路径复制 |
| `fec = 1` | 原始包单发，每组校验发送 1 份 |
| `fec = 2` | 原始包单发，每组相同校验发送 2 份 |
| `fec = 3` | 原始包单发，每组相同校验发送 3 份 |

客户端启用 FEC 要求 `active_sessions >= 2`。例如：

```toml
# 客户端，在原有地址和密钥配置上增加：
max_sessions = 8
active_sessions = 2
selection_policy = "hybrid"
fec = 2
```

```toml
# 服务端，在原有 listen、地址和密钥配置上增加：
fec = 2
```

## 发送与恢复

- 固定系统式 XOR 编码：最多 4 个原始 IPv4 包一组，生成 1 个校验包；首包入队后目标 5 ms 内封闭不足 4 包的组。定时器独立于新 TUN 数据；调度、发送排队和网络仍会增加实际到达时间。
- 正常数据立即单发，不等待组满。每组优先使用激活路径中 RTT 最低的一条；发送队列不可用时尝试其它激活路径。
- 校验副本优先发到不同于原始数据的激活路径，再分散到其它激活路径；份数超过可用路径数时循环使用。两路 FEC2 通常是备用路 1 份、原始数据路 1 份；不是把 2 份都塞到备用路。严格遵守已选择的激活集合和互斥组约束，不擅自激活同组备用路径。
- 仅剩一条激活路径时，数据与校验都可经该路径发送，状态显示激活数量降级。校验不等待满队列，失败计数，不阻塞新业务。
- `fec = 2/3` 复制的是同一个校验包，不是多个独立校验方程；每组仍最多恢复一个缺失原始包。两包同时缺失时等待原始包晚到，最多保留 500 ms，不主动重传。
- 接收端原始包立即交付；恢复包仍经过 IPv4 校验、全局序号去重和接收队列。不按组阻塞后续正常包。重复校验用完成组墓碑抑制，防止重复恢复和虚假的未恢复组。
- 解码组数及完成墓碑总量最多 8192，保存时间最多 500 ms，资源不足时淘汰最旧组；peer 运行代际变化会清空解码状态。

## 带宽与测量

等长连续流量、每组恰好 4 包时，FEC1/2/3 的编码数据量约为原始数据的 1.25/1.50/1.75 倍，另加长度表、协议头、填充、探测。稀疏业务可能每组只有 1 包，退化为约 2/3/4 倍。因此低频 ping 只能观察稀疏流量时延和丢包，不能证明连续流量的带宽收益。

FEC 无须等待缺包反馈往返，但仍需等待足够数据与校验到达。恢复计数表示利用校验成功交付，原始包可能只是迟到，不能直接把该值解释为确认的网络丢包数。所有原始数据都集中在主路时，主路整段中断会超出每组一包的恢复能力。

`status --json` 新增：

- `fec`：校验发送份数。
- `counters.fec_tx_packets / fec_tx_bytes`：已交给 QUIC 的校验份数与 QW 帧字节，包括重复校验。
- `counters.fec_rx_packets`：收到并解析有效的校验份数。
- `counters.fec_recovered_packets / fec_recovered_bytes`：恢复后校验、去重且成功进入本端接收队列的包数与 IP 字节。
- `counters.fec_queue_drops`：没有任何激活路径成功接收的校验发送份数。
- `fec_expired_groups`：已收到校验、仍缺数据且过期或被容量淘汰的组；不包含连校验也没收到的未知缺口。
- `fec_evictions`：因容量上限淘汰的未完成解码组。
- `counters.tx_data_bytes`：已交给 QUIC 的原始数据 QW 帧总字节，关闭 FEC 时包括多发的副本。`tx_copies` 仅计算原始数据副本，不混入校验。

数据面字节倍率可用 `(tx_data_bytes + fec_tx_bytes) / tx_bytes` 的时间段增量计算；不含 H3、QUIC、外层 UDP/IP、探测和握手，所以不是出口计费总倍率。

## 验证

`cargo test --all-targets` 包含：变长包逐一丢失恢复、校验先到、重复校验、两包缺失、过期、缓存上限、无效帧、真实双向 H3 多路径恢复、迟到包去重、FEC1/2/3 发送份数及握手参数不匹配。

Linux 独立 network namespace 检查：

```sh
sudo env QUICWIRE_TEST_FEC=1 QUICWIRE_TEST_SELECTION_POLICY=hybrid bash scripts/linux-smoke.sh target/release/quicwire
sudo env QUICWIRE_TEST_FEC=2 QUICWIRE_TEST_SELECTION_POLICY=hybrid bash scripts/linux-smoke.sh target/release/quicwire
```

覆盖真实 TUN、MTU 边界、TCP/UDP 内容一致性、双向 8% 随机外层丢包中的恢复、服务端重启后恢复。故障注入仅作用于脚本创建的独立命名空间。
