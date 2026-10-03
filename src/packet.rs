/// 验证完整 IPv4 包（包括选项与分片），不把内层地址限制为 TUN 两端。
/// 对端身份由 QUIC 公钥认证约束；路由和访问策略由 Linux 路由表、防火墙管理。
pub fn valid_ipv4(packet: &[u8], mtu: u16) -> bool {
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
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(source: [u8; 4], destination: [u8; 4], len: usize) -> Vec<u8> {
        let mut p = vec![0; len];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        p[12..16].copy_from_slice(&source);
        p[16..20].copy_from_slice(&destination);
        p
    }

    #[test]
    fn routed_destinations_sources_and_nat_return_are_valid() {
        for (src, dst) in [
            ([10, 77, 0, 2], [198, 51, 100, 7]),
            ([198, 51, 100, 7], [10, 77, 0, 2]),
            ([192, 168, 8, 9], [198, 51, 100, 7]),
            ([198, 51, 100, 7], [192, 168, 8, 9]),
        ] {
            assert!(valid_ipv4(&packet(src, dst, 1100), 1100));
        }
    }

    #[test]
    fn malformed_and_oversized_packets_remain_invalid() {
        let good = packet([10, 77, 0, 2], [198, 51, 100, 7], 64);
        for len in 0..20 {
            assert!(!valid_ipv4(&good[..len], 1100));
        }
        for first in [0x65, 0x44, 0x4f] {
            let mut p = good.clone();
            p[0] = first;
            if first == 0x4f {
                p.truncate(40);
                p[2..4].copy_from_slice(&40u16.to_be_bytes());
            }
            assert!(!valid_ipv4(&p, 1100));
        }
        for len in [63u16, 65] {
            let mut p = good.clone();
            p[2..4].copy_from_slice(&len.to_be_bytes());
            assert!(!valid_ipv4(&p, 1100));
        }
        assert!(!valid_ipv4(
            &packet([10, 0, 0, 1], [10, 0, 0, 2], 1101),
            1100
        ));
    }

    #[test]
    fn options_and_non_initial_fragments_are_accepted() {
        let mut p = packet([192, 168, 8, 9], [198, 51, 100, 7], 64);
        p[0] = 0x46;
        p[6..8].copy_from_slice(&0x2001u16.to_be_bytes());
        assert!(valid_ipv4(&p, 1100));
    }
}
