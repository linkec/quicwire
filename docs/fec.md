# FEC 前向纠错

从 0.3.6 起，客户端与服务端顶层配置支持 `fec = 0 | 1 | 2 | 3`，默认 0。两端必须取相同值；H3 协商会拒绝参数不一致，不能与未支持 FEC 的旧端静默混用。关闭 FEC 时保留原有 K 路同包多发协议。

| 配置 | 行为 |
| --- | --- |
| `fec = 0` | 关闭 FEC，原始包向所有激活路径复制 |
| `fec = 1` | 原始包单发，每组校验发送 1 份 |
| `fec = 2` | 原始包单发，每组相同校验发送 2 份 |
| `fec = 3` | 原始包单发，每组相同校验发送 3 份 |

从 **0.3.7** 起，FEC 使用持续的主备角色：`active_sessions` 包含 **1 条主路 + K−1 条校验备用**。两端须一起升级；FEC H3 协商版本已更新，拒绝与 0.3.6 混用。`fec = 0` 的协议和多发行为不变。

客户端启用 FEC 要求 `active_sessions >= 2`。`endpoints` 的对象格式支持 `backup = true`，把该地址或端口范围限定为备用；未设置或 `false` 的端点组成主路候选池，也可补充自动备用。必须至少配置一个主路候选，N 个槽位须覆盖所有互斥组与主备角色组合。轮转保持槽位的角色与互斥组。

例如客户端配置（与已有密钥、TUN 配置合并）：

```toml
# 客户端，在原有地址和密钥配置上增加：
endpoints = [
  { address = "192.0.2.10:4433-4436" },
  { address = "198.51.100.20:4433-4436", backup = true },
]
max_sessions = 8
active_sessions = 2
selection_policy = "hybrid"
fec = 2
fec_backup_failover = false
```

```toml
# 服务端，在原有 listen、地址和密钥配置上增加：
fec = 2
```

## 发送与恢复

- 固定系统式 XOR 编码：最多 4 个原始 IPv4 包一组，生成 1 个校验包；首包入队后目标 5 ms 内封闭不足 4 包的组。定时器独立于新 TUN 数据；调度、发送排队和网络仍会增加实际到达时间。
- 正常数据立即单发，不等待组满；所有原始包只走控制面指定的主路，跨编码组保持该角色，发送队列拥堵不会偷偷借用备用发原始包。
- 客户端统一指定双向主路，通过带代际号的激活列表同步服务端；服务端不按自己的 RTT 重新挑主路。启动按配置槽位顺序选择可用主路，后续保持评分切换阈值、观察时间和 TTL 质量约束。FEC hybrid 的主路按低延迟评估，校验备用按低丢包评估，优化或 TTL 不能牺牲其中一项来掩盖另一项劣化。
- 手动 `backup = true` 的健康端点优先占用校验备用席位，正常时不参与主路竞争。`exclusive_group` 继续严格生效，不能用同组会话补齐数量。
- 校验只走激活备用，先分散到不同备用；份数超过备用条数时在备用上重复发送。两路 FEC2 是主路发原始包、同一备用发两份校验；四路 FEC2 是 1 主 + 3 备，每组向前两条备用各发 1 份，另一条备用保持探测和接替能力。
- `fec_backup_failover = false`（默认，仅客户端）：全部主路候选不可用时停止发原始业务，手动备用不接管。`true`：允许手动备用临时成为主路；任一正常主路恢复健康后回切。服务端跟随客户端的角色，识别故障仍依赖探测时效，不能保证切换零丢包。
- 仅有主路可用时仍发送原始数据，但不在主路补发校验，未发出的校验计入 `fec_queue_drops`。校验队列满时只尝试其它激活备用，不阻塞新业务。
- `fec = 2/3` 复制的是同一个校验包，不是多个独立校验方程；每组仍最多恢复一个缺失原始包。两包同时缺失时等待原始包晚到，最多保留 500 ms，不主动重传。
- 接收端原始包立即交付；恢复包仍经过 IPv4 校验、全局序号去重和接收队列。不按组阻塞后续正常包。重复校验用完成组墓碑抑制，防止重复恢复和虚假的未恢复组。
- 解码组数及完成墓碑总量最多 8192，保存时间最多 500 ms，资源不足时淘汰最旧组；peer 运行代际变化会清空解码状态。

## 带宽与测量

等长连续流量、每组恰好 4 包时，FEC1/2/3 的编码数据量约为原始数据的 1.25/1.50/1.75 倍，另加长度表、协议头、填充、探测。稀疏业务可能每组只有 1 包，退化为约 2/3/4 倍。因此低频 ping 只能观察稀疏流量时延和丢包，不能证明连续流量的带宽收益。

FEC 无须等待缺包反馈往返，但仍需等待足够数据与校验到达。恢复计数表示利用校验成功交付，原始包可能只是迟到，不能直接把该值解释为确认的网络丢包数。所有原始数据都集中在主路时，主路整段中断会超出每组一包的恢复能力。

`status --json` 新增：

- `fec`：校验发送份数。
- `fec_primary`：当前控制面指定的主路 ID；无主路时为 null。`paths[].selection_role` 在 FEC 下为 `primary` / `backup`，未激活候选为 null。
- `paths[].endpoint_backup`：该端点是否手动指定备用，服务端为 null（服务端只接收实际角色）。`fec_backup_failover`、`fec_failover_active` 分别是客户端接管开关与接管状态，服务端为 null。
- `paths[].fec_tx_packets / fec_tx_bytes`：逐会话校验发送量，可与 `tx_copies` 对照确认实际主备分工。
- `counters.fec_tx_packets / fec_tx_bytes`：已交给 QUIC 的校验份数与 QW 帧字节，包括重复校验。
- `counters.fec_rx_packets`：收到并解析有效的校验份数。
- `counters.fec_recovered_packets / fec_recovered_bytes`：恢复后校验、去重且成功进入本端接收队列的包数与 IP 字节。
- `counters.fec_queue_drops`：没有健康激活备用或备用队列未成功接收的校验发送份数。
- `fec_expired_groups`：已收到校验、仍缺数据且过期或被容量淘汰的组；不包含连校验也没收到的未知缺口。
- `fec_evictions`：因容量上限淘汰的未完成解码组。
- `counters.tx_data_bytes`：已交给 QUIC 的原始数据 QW 帧总字节，关闭 FEC 时包括多发的副本。`tx_copies` 仅计算原始数据副本，不混入校验。

数据面字节倍率可用 `(tx_data_bytes + fec_tx_bytes) / tx_bytes` 的时间段增量计算；不含 H3、QUIC、外层 UDP/IP、探测和握手，所以不是出口计费总倍率。

## 验证

`cargo test --all-targets` 包含：变长包逐一丢失恢复、校验先到、重复校验、两包缺失、过期、缓存上限、无效帧、真实双向 H3 多路径恢复、迟到包去重、FEC1/2/3 发送份数及握手参数不匹配，以及手动备用的双向主备分工、满主队列不借用备用、故障接管开关与回切、角色保持与配置冲突。

Linux 独立 network namespace 检查：

```sh
sudo env QUICWIRE_TEST_FEC=1 QUICWIRE_TEST_SELECTION_POLICY=hybrid bash scripts/linux-smoke.sh target/release/quicwire
sudo env QUICWIRE_TEST_FEC=2 QUICWIRE_TEST_SELECTION_POLICY=hybrid bash scripts/linux-smoke.sh target/release/quicwire
```

覆盖真实 TUN、MTU 边界、TCP/UDP 内容一致性、双向 8% 随机外层丢包中的恢复、服务端重启后恢复。故障注入仅作用于脚本创建的独立命名空间。
