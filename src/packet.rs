use std::net::Ipv4Addr;

/// 点对点基础版只接受两端隧道地址之间的完整 IPv4 包（允许 IP 分片）。
pub fn valid_ipv4(packet: &[u8], source: Ipv4Addr, destination: Ipv4Addr, mtu: u16) -> bool {
    if packet.len() < 20 || packet.len() > usize::from(mtu) || packet[0] >> 4 != 4 {
        return false;
    }
    let header = usize::from(packet[0] & 15) * 4;
    if header < 20
        || header > packet.len()
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
    {
        return false;
    }
    packet[12..16] == source.octets() && packet[16..20] == destination.octets()
}
