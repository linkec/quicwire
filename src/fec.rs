//! 有界的系统式 XOR(最多 4+1) 编码。原始包不等编码组，校验最多等待 5 ms。
use bytes::Bytes;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::{Duration, Instant},
};

pub const DATA: u8 = 9;
pub const REPAIR: u8 = 10;
pub const GROUP_SIZE: usize = 4;
pub const FLUSH_AFTER: Duration = Duration::from_millis(5);
pub const RETAIN: Duration = Duration::from_millis(500);
const MAX_GROUPS: usize = 8192;

#[derive(Default)]
pub struct Encoder {
    packets: Vec<Bytes>,
    base: u64,
    started: Option<Instant>,
}
impl Encoder {
    pub fn deadline(&self) -> Option<Instant> {
        self.started.map(|t| t + FLUSH_AFTER)
    }
    pub fn accepts(&self, seq: u64) -> bool {
        self.packets.is_empty() || self.base.checked_add(self.packets.len() as u64) == Some(seq)
    }
    pub fn data(&self, seq: u64, packet: &[u8]) -> Bytes {
        let mut b = vec![DATA];
        b.extend_from_slice(
            &if self.packets.is_empty() {
                seq
            } else {
                self.base
            }
            .to_be_bytes(),
        );
        b.push(self.packets.len() as u8);
        b.extend_from_slice(packet);
        b.into()
    }
    pub fn push(&mut self, seq: u64, packet: Bytes, now: Instant) -> Option<Bytes> {
        assert!(self.accepts(seq));
        if self.packets.is_empty() {
            self.base = seq;
            self.started = Some(now);
        }
        self.packets.push(packet);
        if self.packets.len() == GROUP_SIZE {
            self.flush()
        } else {
            None
        }
    }
    pub fn flush(&mut self) -> Option<Bytes> {
        if self.packets.is_empty() {
            return None;
        }
        let size = self.packets.iter().map(Bytes::len).max().unwrap();
        let mut b = vec![REPAIR];
        b.extend_from_slice(&self.base.to_be_bytes());
        b.push(self.packets.len() as u8);
        for p in &self.packets {
            b.extend_from_slice(&(p.len() as u16).to_be_bytes());
        }
        let offset = b.len();
        b.resize(offset + size, 0);
        for p in self.packets.drain(..) {
            for (out, v) in b[offset..].iter_mut().zip(p.iter()) {
                *out ^= v;
            }
        }
        self.started = None;
        Some(b.into())
    }
}

pub enum Frame {
    Data {
        base: u64,
        index: usize,
        packet: Bytes,
    },
    Repair {
        base: u64,
        lengths: Vec<usize>,
        parity: Bytes,
    },
}
impl Frame {
    pub fn parse(b: &[u8], mtu: usize) -> Option<Self> {
        if b.len() < 10 {
            return None;
        }
        let base = u64::from_be_bytes(b[1..9].try_into().ok()?);
        let n = b[9] as usize;
        match b[0] {
            DATA if n < GROUP_SIZE
                && base.checked_add(n as u64).is_some()
                && (20..=mtu).contains(&(b.len() - 10)) =>
            {
                Some(Self::Data {
                    base,
                    index: n,
                    packet: Bytes::copy_from_slice(&b[10..]),
                })
            }
            REPAIR
                if (1..=GROUP_SIZE).contains(&n)
                    && base.checked_add(n as u64 - 1).is_some()
                    && b.len() >= 10 + n * 2 =>
            {
                let lengths: Vec<_> = b[10..10 + n * 2]
                    .chunks_exact(2)
                    .map(|v| u16::from_be_bytes([v[0], v[1]]) as usize)
                    .collect();
                if lengths.iter().any(|l| !(20..=mtu).contains(l))
                    || b.len() != 10 + n * 2 + *lengths.iter().max()?
                {
                    return None;
                }
                Some(Self::Repair {
                    base,
                    lengths,
                    parity: Bytes::copy_from_slice(&b[10 + n * 2..]),
                })
            }
            _ => None,
        }
    }
}
struct Group {
    created: Instant,
    data: [Option<Bytes>; GROUP_SIZE],
    repair: Option<(Vec<usize>, Bytes)>,
}
#[derive(Default)]
pub struct Decoder {
    groups: BTreeMap<u64, Group>,
    finished: BTreeSet<u64>,
    order: VecDeque<(u64, Instant)>,
    pub expired_missing: u64,
    pub evictions: u64,
}
impl Decoder {
    fn missing(g: &Group) -> bool {
        g.repair
            .as_ref()
            .is_some_and(|(ls, _)| g.data[..ls.len()].iter().any(Option::is_none))
    }
    pub fn expire(&mut self, now: Instant) {
        while let Some(&(id, t)) = self.order.front() {
            if now.duration_since(t) < RETAIN {
                break;
            }
            self.order.pop_front();
            self.finished.remove(&id);
            if self.groups.get(&id).is_some_and(|g| g.created == t) {
                let g = self.groups.remove(&id).unwrap();
                self.expired_missing += u64::from(Self::missing(&g));
            }
        }
    }
    /// 仅返回恢复包。原始包由调用者立即交付；最终仍经过统一 IPv4 校验和去重。
    pub fn receive(
        &mut self,
        frame: Frame,
        now: Instant,
    ) -> Result<Option<(u64, Bytes)>, &'static str> {
        self.expire(now);
        let base = match &frame {
            Frame::Data { base, .. } | Frame::Repair { base, .. } => *base,
        };
        if self.finished.contains(&base) {
            return Ok(None);
        }
        if !self.groups.contains_key(&base) {
            // order 包含已完成组的墓碑，也必须有界。
            while self.order.len() >= MAX_GROUPS {
                if let Some((id, t)) = self.order.pop_front() {
                    self.finished.remove(&id);
                    if self.groups.get(&id).is_some_and(|g| g.created == t) {
                        let g = self.groups.remove(&id).unwrap();
                        self.expired_missing += u64::from(Self::missing(&g));
                        self.evictions += 1;
                    }
                }
            }
            self.order.push_back((base, now));
            self.groups.insert(
                base,
                Group {
                    created: now,
                    data: Default::default(),
                    repair: None,
                },
            );
        }
        let g = self.groups.get_mut(&base).unwrap();
        match frame {
            Frame::Data { index, packet, .. } => {
                if let Some((ls, _)) = &g.repair
                    && (index >= ls.len() || ls[index] != packet.len())
                {
                    return Err("FEC 数据长度冲突");
                }
                if let Some(old) = &g.data[index] {
                    if old != &packet {
                        return Err("FEC 同序号数据冲突");
                    }
                } else {
                    g.data[index] = Some(packet);
                }
            }
            Frame::Repair {
                lengths, parity, ..
            } => {
                if g.data.iter().enumerate().any(|(i, p)| {
                    p.as_ref()
                        .is_some_and(|p| i >= lengths.len() || lengths[i] != p.len())
                }) {
                    return Err("FEC 校验长度冲突");
                }
                if let Some((ls, p)) = &g.repair {
                    if ls != &lengths || p != &parity {
                        return Err("FEC 校验冲突");
                    }
                } else {
                    g.repair = Some((lengths, parity));
                }
            }
        }
        let Some((lengths, parity)) = &g.repair else {
            return Ok(None);
        };
        let missing: Vec<_> = (0..lengths.len())
            .filter(|i| g.data[*i].is_none())
            .collect();
        if missing.len() > 1 {
            return Ok(None);
        }
        let recovered = missing.first().map(|&i| {
            let mut out = parity.to_vec();
            for p in g.data[..lengths.len()].iter().flatten() {
                for (b, v) in out.iter_mut().zip(p.iter()) {
                    *b ^= v;
                }
            }
            out.truncate(lengths[i]);
            (base + i as u64, Bytes::from(out))
        });
        // 完成组留有界墓碑，重复校验不能重新创建一个“全缺包”的组。
        self.groups.remove(&base);
        self.finished.insert(base);
        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn group() -> (Vec<Bytes>, Bytes) {
        let now = Instant::now();
        let mut e = Encoder::default();
        let mut packets = Vec::new();
        let mut repair = None;
        for i in 0..4 {
            let p = Bytes::from(vec![i as u8 + 1; 20 + i * 113]);
            packets.push(e.data(10 + i as u64, &p));
            repair = e.push(10 + i as u64, p, now);
        }
        (packets, repair.unwrap())
    }
    #[test]
    fn recover_each_loss_with_parity_before_or_after_variable_length_sources() {
        for lost in 0..4 {
            for early in [false, true] {
                let (ps, r) = group();
                let mut d = Decoder::default();
                let now = Instant::now();
                let mut recovered = None;
                let frames: Vec<_> = if early {
                    std::iter::once(&r)
                        .chain(
                            ps.iter()
                                .enumerate()
                                .filter(|(i, _)| *i != lost)
                                .map(|(_, p)| p),
                        )
                        .collect()
                } else {
                    ps.iter()
                        .enumerate()
                        .filter(|(i, _)| *i != lost)
                        .map(|(_, p)| p)
                        .chain(std::iter::once(&r))
                        .collect()
                };
                for p in frames {
                    if let Some(p) = d.receive(Frame::parse(p, 1100).unwrap(), now).unwrap() {
                        assert!(recovered.is_none());
                        recovered = Some(p);
                    }
                }
                assert_eq!(
                    recovered,
                    Some((
                        10 + lost as u64,
                        Bytes::from(vec![lost as u8 + 1; 20 + lost * 113])
                    ))
                );
            }
        }
    }
    #[test]
    fn sparse_flush_two_losses_expiry_and_bounds() {
        let now = Instant::now();
        let mut e = Encoder::default();
        let p = Bytes::from(vec![7; 1100]);
        assert!(e.push(1, p.clone(), now).is_none());
        assert_eq!(e.deadline(), Some(now + FLUSH_AFTER));
        let r = e.flush().unwrap();
        assert_eq!(r.len(), 1112);
        let mut d = Decoder::default();
        assert_eq!(
            d.receive(Frame::parse(&r, 1100).unwrap(), now).unwrap(),
            Some((1, p))
        );
        let (ps, r) = group();
        let mut d = Decoder::default();
        for p in [&ps[0], &ps[3], &r] {
            assert!(
                d.receive(Frame::parse(p, 1100).unwrap(), now)
                    .unwrap()
                    .is_none()
            );
        }
        d.expire(now + RETAIN);
        assert_eq!(d.expired_missing, 1);
        assert!(d.groups.is_empty());
        for i in 0..MAX_GROUPS + 1 {
            d.receive(
                Frame::Data {
                    base: i as u64,
                    index: 0,
                    packet: Bytes::from_static(b"abcdefghijklmnopqrst"),
                },
                now + RETAIN,
            )
            .unwrap();
        }
        assert_eq!(d.groups.len(), MAX_GROUPS);
        assert_eq!(d.evictions, 1);
    }
    #[test]
    fn repeated_parity_does_not_recover_twice_or_create_false_expiry() {
        let now = Instant::now();
        let mut e = Encoder::default();
        let mut d = Decoder::default();
        e.push(1, Bytes::from(vec![7; 84]), now);
        let repair = e.flush().unwrap();
        assert!(
            d.receive(Frame::parse(&repair, 1100).unwrap(), now)
                .unwrap()
                .is_some()
        );
        for _ in 0..3 {
            assert!(
                d.receive(Frame::parse(&repair, 1100).unwrap(), now)
                    .unwrap()
                    .is_none()
            );
        }
        d.expire(now + RETAIN);
        assert_eq!(d.expired_missing, 0);
        assert!(d.finished.is_empty());
    }
    #[test]
    fn malformed_frames_and_conflicting_metadata_are_rejected() {
        let (ps, r) = group();
        for n in 0..10 {
            assert!(Frame::parse(&r[..n], 1100).is_none());
        }
        let mut b = r.to_vec();
        b[9] = 5;
        assert!(Frame::parse(&b, 1100).is_none());
        let mut b = ps[0].to_vec();
        b[9] = 4;
        assert!(Frame::parse(&b, 1100).is_none());
        let mut b = r.to_vec();
        b[1..9].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Frame::parse(&b, 1100).is_none());
        let mut d = Decoder::default();
        let now = Instant::now();
        d.receive(Frame::parse(&ps[0], 1100).unwrap(), now).unwrap();
        let mut b = r.to_vec();
        b[11] += 1;
        assert!(d.receive(Frame::parse(&b, 1100).unwrap(), now).is_err());
    }
}
