# WireGuard 与 quicwire 双机对比

日期：2026-10-02。quicwire 测试源码为 `d65e7f5`，与基础隧道实测使用同一二进制。本轮只测量，不修改隧道实现或参数。

## 结论

相同 MTU 1100、相同两台 VM，Linux 内核 WireGuard 的 TCP 单流吞吐中位数约为当前 quicwire 的 **7.67 倍（正向）和 6.78 倍（反向）**。空闲平均 RTT 分别为 quicwire **1.294 ms**、WireGuard **0.763 ms**。现阶段 quicwire 尚未达到 WireGuard 的单路径性能。

## 环境与方法

- 两台既有专用 PVE VM，同一宿主机与虚拟网桥，各 2 vCPU、2 GiB 内存；Ubuntu 24.04，Linux `6.8.0-134-generic`，VirtIO 网卡。
- WireGuard 使用 Linux 内核模块，`wireguard-tools 1.0.20210914`；不是 wireguard-go。quicwire 使用 Rust + Quinn 用户态实现和默认 Cubic/64 KiB 发送队列。
- 主对照组两者 MTU 均为 1100；另测 WireGuard MTU 1420。quicwire 地址段 `10.77.0.0/30`，WireGuard 地址段 `10.78.0.0/30`，均只配置对端主机地址。WireGuard 默认未启用 PersistentKeepalive。
- iperf3 `3.16`，所有负载串行运行。TCP 每次预热 2 秒，再统计 10 秒，每个方向 3 轮。1100 对照组第 1、3 轮先 quicwire 后 WG，第 2 轮交换顺序；1420 组在其后执行。没有调整 CPU 亲和性或网卡 offload。
- UDP payload 均为 1000 字节，分别以 10、100、300 Mbps 发送，每方向每档 8 秒，单次结果。报表采用接收端数据。
- ping 每组 200 包，间隔 20 ms，测量前先发 3 包预热；三组均无丢包。

## 空闲延迟

| 路径 | 平均 RTT | 最大 RTT |
| --- | ---: | ---: |
| 外层直连 | 0.353 ms | 0.491 ms |
| quicwire，MTU 1100 | 1.294 ms | 1.998 ms |
| WireGuard，MTU 1100 | 0.763 ms | 1.108 ms |

## TCP 吞吐

单位 Mbps，三轮取中位数。外层直连基线单次为 13413.9 Mbps。

| 实现 | 方向 | 中位数 | 三轮范围 | 三轮发送端重传次数 |
| --- | --- | ---: | ---: | --- |
| quicwire | 客户端 → 服务端 | 189.2 | 185.8–190.1 | 461/450/364 |
| quicwire | 服务端 → 客户端 | 199.9 | 194.5–207.1 | 618/500/493 |
| wg1100 | 客户端 → 服务端 | 1452.0 | 1339.3–1530.8 | 45/67/14 |
| wg1100 | 服务端 → 客户端 | 1355.1 | 1343.9–1577.5 | 52/1/0 |
| wg1420 | 客户端 → 服务端 | 2000.1 | 1842.4–2014.2 | 31/0/469 |
| wg1420 | 服务端 → 客户端 | 1807.4 | 1742.4–2038.5 | 84/0/301 |

`wg1100` / `wg1420` 分别表示 WireGuard MTU 1100 / 1420。即使内层 MTU 完全一致，吞吐差距仍然明显，不能把差距全部归因于 quicwire 的 MTU 较小。

## UDP 接收速率与丢包

每格为接收 Mbps / iperf3 报告丢包率。UDP 没有协议外的主动重传；高于可处理速率的负载用于观察过载行为。

| 发送目标 Mbps | 方向 | quicwire，MTU 1100 | WireGuard，MTU 1100 |
| ---: | --- | ---: | ---: |
| 10 | 客户端 → 服务端 | 10.00 / 0.000% | 10.00 / 0.000% |
| 10 | 服务端 → 客户端 | 10.00 / 0.000% | 10.00 / 0.000% |
| 100 | 客户端 → 服务端 | 99.96 / 0.000% | 99.95 / 0.000% |
| 100 | 服务端 → 客户端 | 100.00 / 0.000% | 100.00 / 0.000% |
| 300 | 客户端 → 服务端 | 291.25 / 2.876% | 299.79 / 0.046% |
| 300 | 服务端 → 客户端 | 278.75 / 7.051% | 299.74 / 0.079% |

## 相同 100 Mbps UDP 负载下的 CPU

统计各 VM `/proc/stat` 的 user、nice、system、irq、softirq 增量，除以包含 idle、iowait、steal 的总增量。100% 表示该 VM 的两颗 vCPU 全忙，包含系统、iperf3、SSH 采样及隧道开销。这样也包含 WireGuard 内核处理，避免用 quicwire 进程 CPU 与不存在的 WG 用户态进程比较。

| 实现 | 方向 | 客户端 VM CPU | 服务端 VM CPU |
| --- | --- | ---: | ---: |
| quicwire | 客户端 → 服务端 | 70.2% | 47.7% |
| wg1100 | 客户端 → 服务端 | 53.9% | 5.5% |
| quicwire | 服务端 → 客户端 | 38.6% | 74.0% |
| wg1100 | 服务端 → 客户端 | 9.7% | 52.3% |

采样包围整个 iperf 调用，含 SSH 启停开销；TCP CPU 样本还包含 2 秒预热。未扣除背景负载，不包含 PVE 宿主机处理开销。空闲基线为服务端 3.9%、客户端 4.2%；发包器本身占用明显，不能把表中数值当作纯隧道 CPU 开销。空闲基线、steal 及全部吞吐样本见 [脱敏测量数据](wireguard-comparison-data.json)。

## 解释与下一步

这是成熟 Linux 内核 WireGuard 与当前基础版 quicwire 的工程实现对比，不能从中推断 Rust 与 Go 的语言性能，或 QUIC 隧道的最终上限。WireGuard 的内核数据路径见 [官方说明](https://www.wireguard.com/)；当前 quicwire 则逐包经过 TUN、用户态校验与拷贝、Quinn 队列和拥塞控制。[Quinn DATAGRAM 文档](https://docs.rs/quinn/0.11.12/quinn/struct.Connection.html#method.send_datagram)也明确说明其不可靠传输和发送缓冲行为。

上述路径差异是需要进一步剖析的候选因素，不是本轮已经定量分离的瓶颈。本轮未进行 perf 火焰图、批量收发或队列参数 A/B。若目标是提高当前单路径性能，下一步应先剖析 CPU 热点、系统调用、分配和队列丢包，再用本组基线验证优化。

同宿主机短测没有高 RTT、常态丢包或跨运营商路径，不能推断弱网、多路径冗余或跨境收益。TCP 仅三轮，UDP 每档仅一次；报告范围只是当前机器和配置。

## 测试后状态与重现

quicwire 保持原样运行；WireGuard `wgbench` 接口保留，已恢复 MTU 1100，未设置开机自动创建。两端密钥仅保存在各自 VM，未上传仓库。临时 iperf 服务已停止，默认路由未修改。

在服务端运行 `iperf3 -s -p 5201`，客户端对 `10.77.0.1` 或 `10.78.0.1` 执行：

```sh
# TCP；反向增加 -R
iperf3 -c 10.78.0.1 -p 5201 -t 10 -O 2 -J
# UDP；分别替换 10M / 100M / 300M，反向增加 -R
iperf3 -c 10.78.0.1 -p 5201 -u -b 100M -l 1000 -t 8 -J
```

改变 WG MTU 时两端都执行 `sudo ip link set wgbench mtu 1420`，结束后恢复为 1100。安装与密钥配置遵循 [WireGuard 官方快速入门](https://www.wireguard.com/quickstart/)，iperf 参数定义见 [ESnet 官方文档](https://software.es.net/iperf/invoking.html)。
