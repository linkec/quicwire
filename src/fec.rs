//! 系统式 GF(256) Cauchy 编码：最多 4 个原始包、1–4 份独立校验。
//! 第 0 行归一化为 XOR，单校验保持旧协议；原始包不等待编码组。
use bytes::Bytes;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::OnceLock,
    time::{Duration, Instant},
};

pub const DATA: u8 = 9;
pub const REPAIR: u8 = 10;
pub const INDEPENDENT_REPAIR: u8 = 11;
pub const GROUP_SIZE: usize = 4;
pub const MAX_REPAIR_SHARDS: usize = 4;
pub const FLUSH_AFTER: Duration = Duration::from_millis(5);
pub const RETAIN: Duration = Duration::from_millis(500);
const MAX_GROUPS: usize = 8192;

pub fn is_repair(kind: Option<&u8>) -> bool {
    matches!(kind, Some(&REPAIR) | Some(&INDEPENDENT_REPAIR))
}

// GF(2^8)，本原多项式 x^8+x^4+x^3+x^2+1 (0x11d)。
fn product(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            out ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1d;
        }
        b >>= 1;
    }
    out
}
fn products() -> &'static [[u8; 256]; 256] {
    static TABLE: OnceLock<Box<[[u8; 256]; 256]>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Box::new([[0u8; 256]; 256]);
        for (a, row) in table.iter_mut().enumerate() {
            for (b, value) in row.iter_mut().enumerate() {
                *value = product(a as u8, b as u8);
            }
        }
        table
    })
}
fn mul(a: u8, b: u8) -> u8 {
    products()[a as usize][b as usize]
}
fn inv(a: u8) -> u8 {
    assert_ne!(a, 0);
    // a^254，固定有限步；只用于小矩阵系数。
    let mut out = 1;
    let mut base = a;
    let mut power = 254;
    while power > 0 {
        if power & 1 != 0 {
            out = mul(out, base);
        }
        base = mul(base, base);
        power >>= 1;
    }
    out
}
fn coefficient(row: usize, column: usize) -> u8 {
    // x={0,1,2,3}, y={4,5,6,7} 两组不交。Cauchy 矩阵任意方形子矩阵可逆。
    // 按列乘 y 把第 0 行归一化为全 1，保留 XOR 兼容性与 MDS 性质。
    let y = (GROUP_SIZE + column) as u8;
    mul(y, inv((row as u8) ^ y))
}
fn add_scaled(out: &mut [u8], packet: &[u8], scale: u8) {
    if scale == 1 {
        for (out, v) in out.iter_mut().zip(packet) {
            *out ^= v;
        }
    } else if scale != 0 {
        let table = &products()[scale as usize];
        for (out, v) in out.iter_mut().zip(packet) {
            *out ^= table[*v as usize];
        }
    }
}
fn inverse(mut matrix: Vec<Vec<u8>>) -> Option<Vec<Vec<u8>>> {
    let size = matrix.len();
    let mut result: Vec<Vec<u8>> = (0..size)
        .map(|i| (0..size).map(|j| u8::from(i == j)).collect())
        .collect();
    for column in 0..size {
        let pivot = (column..size).find(|&row| matrix[row][column] != 0)?;
        matrix.swap(column, pivot);
        result.swap(column, pivot);
        let scale = inv(matrix[column][column]);
        for value in &mut matrix[column] {
            *value = mul(*value, scale);
        }
        for value in &mut result[column] {
            *value = mul(*value, scale);
        }
        let source = matrix[column].clone();
        let decoded = result[column].clone();
        for row in 0..size {
            if row != column {
                let scale = matrix[row][column];
                add_scaled(&mut matrix[row], &source, scale);
                add_scaled(&mut result[row], &decoded, scale);
            }
        }
    }
    Some(result)
}

pub struct Encoder {
    packets: Vec<Bytes>,
    base: u64,
    started: Option<Instant>,
    repair_shards: usize,
}
impl Default for Encoder {
    fn default() -> Self {
        Self::new(1)
    }
}
impl Encoder {
    pub fn new(repair_shards: usize) -> Self {
        assert!((1..=MAX_REPAIR_SHARDS).contains(&repair_shards));
        Self {
            packets: Vec::new(),
            base: 0,
            started: None,
            repair_shards,
        }
    }
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
    pub fn push(&mut self, seq: u64, packet: Bytes, now: Instant) -> Option<Vec<Bytes>> {
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
    pub fn flush(&mut self) -> Option<Vec<Bytes>> {
        if self.packets.is_empty() {
            return None;
        }
        let size = self.packets.iter().map(Bytes::len).max().unwrap();
        let result = (0..self.repair_shards)
            .map(|row| {
                let mut b = vec![if row == 0 { REPAIR } else { INDEPENDENT_REPAIR }];
                b.extend_from_slice(&self.base.to_be_bytes());
                b.push(self.packets.len() as u8);
                if row > 0 {
                    b.push(row as u8);
                }
                for p in &self.packets {
                    b.extend_from_slice(&(p.len() as u16).to_be_bytes());
                }
                let offset = b.len();
                b.resize(offset + size, 0);
                for (column, p) in self.packets.iter().enumerate() {
                    add_scaled(
                        &mut b[offset..],
                        p,
                        if row == 0 {
                            1
                        } else {
                            coefficient(row, column)
                        },
                    );
                }
                Bytes::from(b)
            })
            .collect();
        self.packets.clear();
        self.started = None;
        Some(result)
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
        index: usize,
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
            REPAIR | INDEPENDENT_REPAIR
                if (1..=GROUP_SIZE).contains(&n) && base.checked_add(n as u64 - 1).is_some() =>
            {
                let (index, offset) = if b[0] == REPAIR {
                    (0, 10)
                } else {
                    let index = *b.get(10)? as usize;
                    if !(1..MAX_REPAIR_SHARDS).contains(&index) {
                        return None;
                    }
                    (index, 11)
                };
                let lengths: Vec<_> = b
                    .get(offset..offset + n * 2)?
                    .chunks_exact(2)
                    .map(|v| u16::from_be_bytes([v[0], v[1]]) as usize)
                    .collect();
                if lengths.iter().any(|l| !(20..=mtu).contains(l))
                    || b.len() != offset + n * 2 + *lengths.iter().max()?
                {
                    return None;
                }
                Some(Self::Repair {
                    base,
                    index,
                    lengths,
                    parity: Bytes::copy_from_slice(&b[offset + n * 2..]),
                })
            }
            _ => None,
        }
    }
}
struct Group {
    created: Instant,
    data: [Option<Bytes>; GROUP_SIZE],
    lengths: Option<Vec<usize>>,
    repair: BTreeMap<usize, Bytes>,
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
        g.lengths
            .as_ref()
            .is_some_and(|ls| g.data[..ls.len()].iter().any(Option::is_none))
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
    /// 仅返回恢复包；原始包即时交付，恢复结果仍通过统一 IPv4 校验和去重。
    pub fn receive(
        &mut self,
        frame: Frame,
        now: Instant,
    ) -> Result<Vec<(u64, Bytes)>, &'static str> {
        self.expire(now);
        let base = match &frame {
            Frame::Data { base, .. } | Frame::Repair { base, .. } => *base,
        };
        if self.finished.contains(&base) {
            return Ok(Vec::new());
        }
        if !self.groups.contains_key(&base) {
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
                    lengths: None,
                    repair: BTreeMap::new(),
                },
            );
        }
        let g = self.groups.get_mut(&base).unwrap();
        match frame {
            Frame::Data { index, packet, .. } => {
                if index >= GROUP_SIZE || base.checked_add(index as u64).is_none() {
                    return Err("FEC 数据序号无效");
                }
                if let Some(ls) = &g.lengths
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
                index,
                lengths,
                parity,
                ..
            } => {
                if index >= MAX_REPAIR_SHARDS
                    || lengths.is_empty()
                    || lengths.len() > GROUP_SIZE
                    || base.checked_add(lengths.len() as u64 - 1).is_none()
                    || lengths.iter().max().copied() != Some(parity.len())
                {
                    return Err("FEC 校验元数据无效");
                }
                if g.data.iter().enumerate().any(|(i, p)| {
                    p.as_ref()
                        .is_some_and(|p| i >= lengths.len() || lengths[i] != p.len())
                }) || g.lengths.as_ref().is_some_and(|ls| ls != &lengths)
                {
                    return Err("FEC 校验长度冲突");
                }
                if let Some(old) = g.repair.get(&index) {
                    if old != &parity {
                        return Err("FEC 同序号校验冲突");
                    }
                } else {
                    g.repair.insert(index, parity);
                }
                g.lengths = Some(lengths);
            }
        }
        let Some(lengths) = &g.lengths else {
            return Ok(Vec::new());
        };
        let missing: Vec<_> = (0..lengths.len())
            .filter(|i| g.data[*i].is_none())
            .collect();
        if missing.len() > g.repair.len() {
            return Ok(Vec::new());
        }
        let mut recovered = Vec::new();
        if missing.len() == 1 && g.repair.contains_key(&0) {
            let column = missing[0];
            let mut out = g.repair[&0].to_vec();
            for packet in g.data[..lengths.len()].iter().flatten() {
                add_scaled(&mut out, packet, 1);
            }
            out.truncate(lengths[column]);
            recovered.push((base + column as u64, Bytes::from(out)));
        } else if !missing.is_empty() {
            let rows: Vec<_> = g.repair.iter().take(missing.len()).collect();
            let matrix = rows
                .iter()
                .map(|(row, _)| {
                    missing
                        .iter()
                        .map(|column| coefficient(**row, *column))
                        .collect()
                })
                .collect();
            let inverse = inverse(matrix).ok_or("FEC 校验矩阵不可逆")?;
            let residual: Vec<_> = rows
                .iter()
                .map(|(row, parity)| {
                    let mut out = parity.to_vec();
                    for (column, p) in g.data[..lengths.len()].iter().enumerate() {
                        if let Some(p) = p {
                            add_scaled(&mut out, p, coefficient(**row, column));
                        }
                    }
                    out
                })
                .collect();
            for (position, &column) in missing.iter().enumerate() {
                let mut out = vec![0; *lengths.iter().max().unwrap()];
                for (scale, bytes) in inverse[position].iter().zip(&residual) {
                    add_scaled(&mut out, bytes, *scale);
                }
                out.truncate(lengths[column]);
                recovered.push((base + column as u64, Bytes::from(out)));
            }
        }
        // 完成组墓碑抑制重复校验，副本不增加矩阵秩或产生虚假的过期组。
        self.groups.remove(&base);
        self.finished.insert(base);
        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encoded(count: usize, repairs: usize) -> (Vec<Bytes>, Vec<Bytes>, Vec<Bytes>) {
        let mut encoder = Encoder::new(repairs);
        let originals: Vec<_> = (0..count)
            .map(|i| {
                Bytes::from(
                    (0..[20, 257, 1100, 799][i])
                        .map(|j| ((j * 37 + i * 71) % 256) as u8)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let mut frames = Vec::new();
        let mut parity = None;
        for (i, p) in originals.iter().enumerate() {
            frames.push(encoder.data(100 + i as u64, p));
            parity = encoder.push(100 + i as u64, p.clone(), Instant::now());
        }
        (
            originals,
            frames,
            parity.or_else(|| encoder.flush()).unwrap(),
        )
    }
    #[test]
    fn cauchy_all_survivor_subsets_sparse_and_full_groups() {
        // 穷举 1–4 原始包、1–4 校验，以及任意不少于 K 份的存活组合。
        for count in 1..=4 {
            for repairs in 1..=4 {
                let (originals, data, parity) = encoded(count, repairs);
                for mask in 0u16..(1 << (count + repairs)) {
                    if mask.count_ones() < count as u32 {
                        continue;
                    }
                    for reverse in [false, true] {
                        let mut order: Vec<_> = (0..count + repairs)
                            .filter(|i| mask & (1 << i) != 0)
                            .collect();
                        if reverse {
                            order.reverse();
                        }
                        let mut decoder = Decoder::default();
                        let mut delivered = BTreeMap::new();
                        let mut recovered_ids = BTreeSet::new();
                        for i in order {
                            if i < count {
                                delivered.insert(i, originals[i].clone());
                            }
                            let frame = if i < count {
                                &data[i]
                            } else {
                                &parity[i - count]
                            };
                            for _ in 0..2 {
                                for (seq, packet) in decoder
                                    .receive(Frame::parse(frame, 1100).unwrap(), Instant::now())
                                    .unwrap()
                                {
                                    assert!(recovered_ids.insert(seq), "重复恢复");
                                    assert_eq!(packet, originals[(seq - 100) as usize]);
                                    delivered.insert((seq - 100) as usize, packet);
                                }
                            }
                        }
                        assert_eq!(
                            delivered.into_values().collect::<Vec<_>>(),
                            originals,
                            "k={count} r={repairs} mask={mask:x}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn repeated_equation_cannot_replace_independent_repair_and_late_source_helps() {
        let (originals, data, parity) = encoded(4, 2);
        let now = Instant::now();
        let mut decoder = Decoder::default();
        for p in [&data[0], &data[3], &parity[1], &parity[1], &parity[1]] {
            assert!(
                decoder
                    .receive(Frame::parse(p, 1100).unwrap(), now)
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(
            decoder
                .receive(Frame::parse(&parity[0], 1100).unwrap(), now)
                .unwrap(),
            vec![(101, originals[1].clone()), (102, originals[2].clone())]
        );
        decoder.expire(now + RETAIN);
        assert_eq!(decoder.expired_missing, 0);
        let mut decoder = Decoder::default();
        for p in [&data[0], &data[3], &parity[1]] {
            assert!(
                decoder
                    .receive(Frame::parse(p, 1100).unwrap(), now)
                    .unwrap()
                    .is_empty()
            );
        }
        assert_eq!(
            decoder
                .receive(Frame::parse(&data[1], 1100).unwrap(), now)
                .unwrap(),
            vec![(102, originals[2].clone())]
        );
        let mut decoder = Decoder::default();
        for p in [&data[0], &parity[0], &parity[1]] {
            assert!(
                decoder
                    .receive(Frame::parse(p, 1100).unwrap(), now)
                    .unwrap()
                    .is_empty()
            );
        }
        decoder.expire(now + RETAIN);
        assert_eq!(decoder.expired_missing, 1);
    }
    #[test]
    fn independent_repair_validation_and_xor_wire_compatibility() {
        let (originals, data, parity) = encoded(4, 4);
        let mut expected = vec![0u8; 1100];
        for p in &originals {
            for (a, b) in expected.iter_mut().zip(p) {
                *a ^= b;
            }
        }
        assert_eq!(parity[0][0], REPAIR);
        assert_eq!(&parity[0][18..], expected);
        for (row, frame) in parity.iter().enumerate().skip(1) {
            assert_eq!(frame[0], INDEPENDENT_REPAIR);
            assert_eq!(frame[10], row as u8);
            for n in 0..19 {
                assert!(Frame::parse(&frame[..n], 1100).is_none());
            }
            for invalid in [0, 4, 255] {
                let mut b = frame.to_vec();
                b[10] = invalid;
                assert!(Frame::parse(&b, 1100).is_none());
            }
        }
        let now = Instant::now();
        let mut decoder = Decoder::default();
        decoder
            .receive(Frame::parse(&parity[1], 1100).unwrap(), now)
            .unwrap();
        let mut conflict = parity[1].to_vec();
        *conflict.last_mut().unwrap() ^= 1;
        assert!(
            decoder
                .receive(Frame::parse(&conflict, 1100).unwrap(), now)
                .is_err()
        );
        let mut conflict = parity[2].to_vec();
        conflict[12] += 1;
        assert!(
            decoder
                .receive(Frame::parse(&conflict, 1100).unwrap(), now)
                .is_err()
        );
        assert!(
            decoder
                .receive(Frame::parse(&data[0], 1100).unwrap(), now)
                .unwrap()
                .is_empty()
        );
    }
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
        (packets, repair.unwrap().remove(0))
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
                    for p in d.receive(Frame::parse(p, 1100).unwrap(), now).unwrap() {
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
        let r = e.flush().unwrap().remove(0);
        assert_eq!(r.len(), 1112);
        let mut d = Decoder::default();
        assert_eq!(
            d.receive(Frame::parse(&r, 1100).unwrap(), now).unwrap(),
            vec![(1, p)]
        );
        let (ps, r) = group();
        let mut d = Decoder::default();
        for p in [&ps[0], &ps[3], &r] {
            assert!(
                d.receive(Frame::parse(p, 1100).unwrap(), now)
                    .unwrap()
                    .is_empty()
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
        let repair = e.flush().unwrap().remove(0);
        assert!(
            d.receive(Frame::parse(&repair, 1100).unwrap(), now)
                .unwrap()
                .len()
                == 1
        );
        for _ in 0..3 {
            assert!(
                d.receive(Frame::parse(&repair, 1100).unwrap(), now)
                    .unwrap()
                    .is_empty()
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
