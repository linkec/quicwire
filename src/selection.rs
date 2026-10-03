//! 客户端选路预设。探测超时只作为丢包倾向估计，不等于业务丢包率。
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionPolicy {
    #[default]
    Balanced,
    LowLatency,
    LowLoss,
    Hybrid,
}

#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    pub id: u64,
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub probe_loss: f64,
}

impl SelectionPolicy {
    pub fn score(self, rtt_ms: f64, jitter_ms: f64, probe_loss: f64) -> f64 {
        match self {
            Self::Balanced => rtt_ms + 4.0 * jitter_ms + 100.0 * probe_loss,
            Self::LowLatency => rtt_ms,
            // 1 个百分点的近期探测超时增加 100 分，优先避开不稳定路径。
            Self::LowLoss | Self::Hybrid => rtt_ms + 4.0 * jitter_ms + 10_000.0 * probe_loss,
        }
    }

    pub fn rank(self, paths: &[Candidate]) -> Vec<Candidate> {
        let mut sorted = paths.to_vec();
        sorted.sort_by(|a, b| {
            self.score(a.rtt_ms, a.jitter_ms, a.probe_loss)
                .total_cmp(&self.score(b.rtt_ms, b.jitter_ms, b.probe_loss))
                .then(a.id.cmp(&b.id))
        });
        if self == Self::Hybrid && sorted.len() > 1 {
            // 第一条承担低丢包保障，其余位置按 RTT 补齐；同一会话不能占两个位置。
            sorted[1..].sort_by(|a, b| a.rtt_ms.total_cmp(&b.rtt_ms).then(a.id.cmp(&b.id)));
        }
        sorted
    }

    pub fn group_scores(self, paths: &[Candidate]) -> Vec<f64> {
        let ranked = self.rank(paths);
        if self == Self::Hybrid {
            let Some(guard) = ranked.first() else {
                return Vec::new();
            };
            let mut scores = vec![self.score(guard.rtt_ms, guard.jitter_ms, guard.probe_loss)];
            // 保障路径本身也可能最快；比较整个组合的最快 K-1 档，不能遗漏它。
            let mut latency: Vec<_> = paths.iter().map(|p| p.rtt_ms).collect();
            latency.sort_by(f64::total_cmp);
            scores.extend(latency.into_iter().take(paths.len().saturating_sub(1)));
            scores
        } else {
            ranked
                .iter()
                .map(|p| self.score(p.rtt_ms, p.jitter_ms, p.probe_loss))
                .collect()
        }
    }

    pub fn ttl_allows(
        self,
        current: &[Candidate],
        candidate: &[Candidate],
        tolerance: f64,
    ) -> bool {
        if current.is_empty() || current.len() != candidate.len() {
            return false;
        }
        self.group_scores(current)
            .iter()
            .zip(self.group_scores(candidate))
            .all(|(old, new)| new <= *old || new - old <= old * tolerance / 100.0)
    }

    pub fn improves(self, current: &[f64], candidate: &[f64], threshold: f64) -> bool {
        if current.is_empty() || current.len() != candidate.len() {
            return false;
        }
        let better = |old: f64, new: f64| new < old * (1.0 - threshold / 100.0);
        match self {
            Self::Balanced | Self::LowLoss => better(current.iter().sum(), candidate.iter().sum()),
            Self::LowLatency | Self::Hybrid => {
                // 双发取先到副本。保护按 RTT 排序后的每一档，避免总和改善挤掉快路径。
                let mut old = current.to_vec();
                let mut new = candidate.to_vec();
                if self == Self::LowLatency {
                    old.sort_by(f64::total_cmp);
                    new.sort_by(f64::total_cmp);
                }
                old.iter().zip(&new).all(|(a, b)| b <= a)
                    && old.iter().zip(&new).any(|(a, b)| better(*a, *b))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_prefer_different_paths_for_the_same_measurements() {
        let paths = [(20.0, 10.0, 0.02), (35.0, 1.0, 0.01), (55.0, 1.0, 0.0)];
        for (policy, expected) in [
            (SelectionPolicy::LowLatency, 0),
            (SelectionPolicy::Balanced, 1),
            (SelectionPolicy::LowLoss, 2),
        ] {
            let scores: Vec<_> = paths
                .iter()
                .map(|&(r, j, l)| policy.score(r, j, l))
                .collect();
            let selected = (0..scores.len())
                .min_by(|&a, &b| scores[a].total_cmp(&scores[b]))
                .unwrap();
            assert_eq!(selected, expected);
        }
    }

    #[test]
    fn latency_preserves_fast_path_and_uses_rank_improvement() {
        use SelectionPolicy::{Balanced, LowLatency};
        assert!(Balanced.improves(&[100.0, 200.0], &[106.0, 150.0], 5.0));
        assert!(!LowLatency.improves(&[100.0, 200.0], &[106.0, 150.0], 5.0));
        assert!(LowLatency.improves(&[200.0, 100.0], &[94.0, 200.0], 5.0));
        assert!(!Balanced.improves(&[100.0, 200.0], &[94.0, 200.0], 5.0));
        assert!(LowLatency.improves(&[100.0, 200.0], &[100.0, 180.0], 5.0));
        for policy in [Balanced, LowLatency, SelectionPolicy::LowLoss] {
            assert!(!policy.improves(&[100.0], &[95.0], 5.0));
            assert!(!policy.improves(&[100.0], &[100.0], 0.0));
            assert!(policy.improves(&[100.0], &[99.0], 0.0));
            assert!(!policy.improves(&[], &[], 0.0));
            assert!(!policy.improves(&[100.0], &[10.0, 10.0], 0.0));
        }
    }

    #[test]
    fn hybrid_keeps_loss_guard_and_fast_replicas_with_ttl_limits() {
        let fast = Candidate {
            id: 1,
            rtt_ms: 20.0,
            jitter_ms: 10.0,
            probe_loss: 0.02,
        };
        let balanced = Candidate {
            id: 2,
            rtt_ms: 35.0,
            jitter_ms: 1.0,
            probe_loss: 0.01,
        };
        let guard = Candidate {
            id: 3,
            rtt_ms: 55.0,
            jitter_ms: 1.0,
            probe_loss: 0.0,
        };
        let policy = SelectionPolicy::Hybrid;
        assert_eq!(
            policy
                .rank(&[fast, balanced, guard])
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![3, 1, 2]
        );
        assert_eq!(policy.group_scores(&[guard]), vec![59.0]);
        assert_eq!(policy.group_scores(&[fast, guard]), vec![59.0, 20.0]);
        assert!(!policy.improves(&[59.0, 20.0], &[50.0, 21.0], 5.0));
        assert!(!policy.improves(&[59.0, 20.0], &[60.0, 10.0], 5.0));
        assert!(policy.improves(&[59.0, 20.0], &[58.0, 18.0], 5.0));
        assert!(policy.ttl_allows(
            &[fast, guard],
            &[
                Candidate {
                    rtt_ms: 22.0,
                    ..fast
                },
                guard
            ],
            10.0
        ));
        assert!(!policy.ttl_allows(&[fast, guard], &[balanced, guard], 10.0));
        assert!(!policy.ttl_allows(&[fast, guard], &[fast, balanced], 10.0));
        let fast_guard = Candidate {
            rtt_ms: 10.0,
            ..guard
        };
        assert_eq!(
            policy.group_scores(&[fast_guard, balanced]),
            vec![14.0, 10.0]
        );
        assert!(!policy.ttl_allows(
            &[fast_guard, balanced],
            &[
                Candidate {
                    rtt_ms: 12.0,
                    ..fast_guard
                },
                fast
            ],
            10.0
        ));
    }

    #[test]
    fn policy_config_defaults_and_rejects_unknown_values() {
        #[derive(Deserialize)]
        struct Settings {
            #[serde(default)]
            selection_policy: SelectionPolicy,
        }
        assert_eq!(
            toml::from_str::<Settings>("").unwrap().selection_policy,
            SelectionPolicy::Balanced
        );
        for (text, policy) in [
            ("balanced", SelectionPolicy::Balanced),
            ("low_latency", SelectionPolicy::LowLatency),
            ("low_loss", SelectionPolicy::LowLoss),
            ("hybrid", SelectionPolicy::Hybrid),
        ] {
            let config: Settings = toml::from_str(&format!("selection_policy = '{text}'")).unwrap();
            assert_eq!(config.selection_policy, policy);
            assert_eq!(serde_json::to_value(policy).unwrap(), text);
        }
        assert!(toml::from_str::<Settings>("selection_policy = 'fastest'").is_err());
    }
}
