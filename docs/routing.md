# IPv4 路由与 NAT

从 0.3.10 起，Quicwire 可以承载普通 IPv4 路由流量。`tun_address` 和 `peer_address` 用于配置隧道两端地址，不再是内层数据包源地址、目的地址的固定白名单。发送、普通接收和 FEC 恢复路径统一校验 IPv4 版本、头长度、总长度和 MTU；保留 IPv4 选项及分片支持。公钥认证仍决定允许建立隧道的对端。

路由、转发、NAT 和访问范围由 Linux 管理。此版本不会自动修改默认路由、开启 IP 转发或添加防火墙规则。已认证的对端可以承载其它网段，实际部署需要使用 Linux 防火墙约束其可访问范围。IPv6 尚不支持。两端都须升级，旧版本仍会拒绝目的地址或源地址不是 TUN 端点的数据包。

以下为示例：客户端 `qw0=10.77.0.2/30`，服务端 `qw0=10.77.0.1/30`，服务端公网出口 `eth0`。`198.51.100.7` 是文档示例地址，须替换为实际目的地址。

客户端为目的地址增加路由：

```sh
ip route add 198.51.100.7/32 via 10.77.0.1 dev qw0
curl --noproxy '*' --interface qw0 --limit-rate 1M \
  'https://实际域名/实际下载地址' -o /dev/null
```

服务端开启转发，并只允许该客户端访问指定目的地址：

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -I FORWARD -i qw0 -o eth0 -s 10.77.0.2/32 -d 198.51.100.7/32 -j ACCEPT
iptables -I FORWARD -i eth0 -o qw0 -s 198.51.100.7/32 -d 10.77.0.2/32 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s 10.77.0.2/32 -d 198.51.100.7/32 -o eth0 -j MASQUERADE
```

路由只决定下一跳，不改变原始目的地址；服务端解封装后把包交给内核转发，SNAT 将源地址改为出口地址。回包由连接跟踪还原客户端地址，再经隧道返回。客户端 HTTPS 仍直接连接目标服务，不需要代理或 DNAT。

同时测试多个隧道访问同一目的地址时，可使用按源地址选择的策略路由：为每个 TUN 源地址创建独立路由表，在各表中添加指定目的地址经各自 TUN 的路由；curl 绑定对应的 TUN 源地址。避免覆盖主路由表的同一条目的路由，也不要把 QUIC 外层对端的路由导入自身隧道。

验证覆盖：非法 IPv4/长度/MTU 拒绝、跨网段数据与 NAT 回程地址、IPv4 选项与分片、真实 H3 的跨网段 FEC 恢复，以及隔离 network namespace 内的双向跨网段 ICMP、4 MiB TCP 内容和 UDP 分片回传。NAT 测试删除远端到私网的回程路由，并检查远端实际看到的 SNAT 源地址。
