//! Quorum evaluation and governance logic per §7.

use valence_core::types::FixedPoint;
use valence_core::constants::*;
use valence_core::message::VoteStance;

/// A vote with its associated weight.
#[derive(Debug, Clone)]
pub struct WeightedVote {
    pub node_id: String,
    pub stance: VoteStance,
    /// Voter's reputation at vote creation time.
    pub weight: FixedPoint,
}

/// Network governance phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernancePhase {
    /// < 16 nodes: content only, governance frozen.
    Frozen,
    /// ≥ 16 nodes sustained, first 30 days: headcount voting.
    ColdStart,
    /// Standard governance active.
    Standard,
    /// ≥ 1024 nodes sustained 30 days: constitutional governance unlocked.
    Constitutional,
}

/// Result of quorum evaluation.
#[derive(Debug, Clone)]
pub struct QuorumResult {
    pub weighted_endorse: FixedPoint,
    pub weighted_reject: FixedPoint,
    pub weighted_abstain: FixedPoint,
    pub total_voters: usize,
    pub quorum_met: bool,
    pub threshold_met: bool,
    pub ratified: bool,
    /// For cold-start-submitted proposals: headcount floor met?
    pub headcount_floor_met: bool,
}

/// Evaluate quorum for a standard proposal.
pub fn evaluate_standard(
    votes: &[WeightedVote],
    active_nodes: usize,
    total_known_reputation: FixedPoint,
    is_cold_start_submitted: bool,
) -> QuorumResult {
    let (weighted_endorse, weighted_reject, weighted_abstain, total_voters) = tally(votes);

    // Quorum: max(active_nodes × 0.1, total_rep × 0.10)
    let node_quorum = FixedPoint::from_raw((active_nodes as i64 * FixedPoint::SCALE) / 10);
    let rep_quorum = total_known_reputation.mul(FixedPoint::from_f64(0.10));
    let quorum = if node_quorum.raw() > rep_quorum.raw() { node_quorum } else { rep_quorum };

    let total_voting_weight = weighted_endorse.saturating_add(weighted_reject).saturating_add(weighted_abstain);
    let quorum_met = total_voting_weight.raw() >= quorum.raw() && total_voters >= MINIMUM_VOTERS;

    // Threshold: endorse / (endorse + reject) >= 0.67
    let endorse_plus_reject = weighted_endorse.saturating_add(weighted_reject);
    let threshold_met = if endorse_plus_reject.raw() > 0 {
        // Fixed-point: endorse × 10000 / (endorse + reject) >= 6700
        let ratio_raw = (weighted_endorse.raw() as i128 * FixedPoint::SCALE as i128)
            / endorse_plus_reject.raw() as i128;
        ratio_raw >= STANDARD_THRESHOLD.raw() as i128
    } else {
        false
    };

    // Cold-start-submitted proposals need 50% headcount even under weighted voting
    let headcount_floor_met = if is_cold_start_submitted {
        total_voters * 2 >= active_nodes // 50% of active nodes
    } else {
        true
    };

    let ratified = quorum_met && threshold_met && headcount_floor_met;

    QuorumResult {
        weighted_endorse,
        weighted_reject,
        weighted_abstain,
        total_voters,
        quorum_met,
        threshold_met,
        ratified,
        headcount_floor_met,
    }
}

/// Evaluate quorum for a constitutional proposal.
pub fn evaluate_constitutional(
    votes: &[WeightedVote],
    _active_nodes: usize,
    total_known_reputation: FixedPoint,
) -> QuorumResult {
    let (weighted_endorse, weighted_reject, weighted_abstain, total_voters) = tally(votes);

    // Constitutional quorum: 30% of total network reputation
    let quorum = total_known_reputation.mul(CONSTITUTIONAL_QUORUM_FRACTION);

    let total_voting_weight = weighted_endorse.saturating_add(weighted_reject).saturating_add(weighted_abstain);
    let quorum_met = total_voting_weight.raw() >= quorum.raw() && total_voters >= MINIMUM_VOTERS;

    // Constitutional threshold: 0.90
    let endorse_plus_reject = weighted_endorse.saturating_add(weighted_reject);
    let threshold_met = if endorse_plus_reject.raw() > 0 {
        let ratio_raw = (weighted_endorse.raw() as i128 * FixedPoint::SCALE as i128)
            / endorse_plus_reject.raw() as i128;
        ratio_raw >= CONSTITUTIONAL_THRESHOLD.raw() as i128
    } else {
        false
    };

    let ratified = quorum_met && threshold_met;

    QuorumResult {
        weighted_endorse,
        weighted_reject,
        weighted_abstain,
        total_voters,
        quorum_met,
        threshold_met,
        ratified,
        headcount_floor_met: true,
    }
}

/// Evaluate during cold start (headcount mode).
pub fn evaluate_cold_start(
    votes: &[WeightedVote],
    active_nodes: usize,
) -> QuorumResult {
    let total_voters = votes.len();
    let endorse_count = votes.iter().filter(|v| v.stance == VoteStance::Endorse).count();
    let reject_count = votes.iter().filter(|v| v.stance == VoteStance::Reject).count();

    // Majority of known nodes must vote
    let quorum_met = total_voters * 2 > active_nodes;

    // >67% endorse (by count, not weight)
    let threshold_met = if endorse_count + reject_count > 0 {
        endorse_count * 10000 / (endorse_count + reject_count) >= 6700
    } else {
        false
    };

    let ratified = quorum_met && threshold_met;

    // Report as fixed-point for consistency (1.0 per vote in headcount mode)
    let fp_one = FixedPoint::ONE;
    QuorumResult {
        weighted_endorse: FixedPoint::from_raw(endorse_count as i64 * fp_one.raw()),
        weighted_reject: FixedPoint::from_raw(reject_count as i64 * fp_one.raw()),
        weighted_abstain: FixedPoint::from_raw(
            (total_voters - endorse_count - reject_count) as i64 * fp_one.raw(),
        ),
        total_voters,
        quorum_met,
        threshold_met,
        ratified,
        headcount_floor_met: quorum_met,
    }
}

/// Tally votes by weight.
fn tally(votes: &[WeightedVote]) -> (FixedPoint, FixedPoint, FixedPoint, usize) {
    let mut endorse = FixedPoint::ZERO;
    let mut reject = FixedPoint::ZERO;
    let mut abstain = FixedPoint::ZERO;

    for vote in votes {
        match vote.stance {
            VoteStance::Endorse => endorse = endorse.saturating_add(vote.weight),
            VoteStance::Reject => reject = reject.saturating_add(vote.weight),
            VoteStance::Abstain => abstain = abstain.saturating_add(vote.weight),
        }
    }

    (endorse, reject, abstain, votes.len())
}

/// Compute the activity multiplier for governance activation timing.
/// Per §7: multiplier = 1.0 + min(1.33, adopted × 0.33 + earned × 2.0 + challenges × 0.1)
pub fn activity_multiplier(
    adopted_proposals: usize,
    earned_rep_delta: f64,
    challenge_pairs: usize,
) -> f64 {
    let earned_capped = earned_rep_delta.min(1.0);
    let challenges_capped = challenge_pairs.min(10) as f64;
    let score = adopted_proposals as f64 * 0.33 + earned_capped * 2.0 + challenges_capped * 0.1;
    1.0 + score.min(1.33)
}

/// Compute sustain days from activity multiplier.
/// sustain_days = max(3, 7 / activity_multiplier)
pub fn sustain_days(multiplier: f64) -> f64 {
    (7.0 / multiplier).max(3.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_quorum_ratified() {
        let votes = vec![
            WeightedVote { node_id: "a".into(), stance: VoteStance::Endorse, weight: FixedPoint::from_f64(0.8) },
            WeightedVote { node_id: "b".into(), stance: VoteStance::Endorse, weight: FixedPoint::from_f64(0.7) },
            WeightedVote { node_id: "c".into(), stance: VoteStance::Endorse, weight: FixedPoint::from_f64(0.6) },
            WeightedVote { node_id: "d".into(), stance: VoteStance::Reject, weight: FixedPoint::from_f64(0.2) },
        ];
        // quorum = max(20*0.1, 5.2*0.1) = max(2.0, 0.52) = 2.0
        // total weight = 0.8+0.7+0.6+0.2 = 2.3 > 2.0 ✓
        // endorse = 2.1, reject = 0.2, ratio = 2.1/2.3 = 0.913 > 0.67 ✓
        let result = evaluate_standard(&votes, 20, FixedPoint::from_f64(5.2), false);
        assert!(result.quorum_met);
        assert!(result.threshold_met);
        assert!(result.ratified);
    }

    #[test]
    fn standard_quorum_not_met() {
        let votes = vec![
            WeightedVote { node_id: "a".into(), stance: VoteStance::Endorse, weight: FixedPoint::from_f64(0.2) },
            WeightedVote { node_id: "b".into(), stance: VoteStance::Endorse, weight: FixedPoint::from_f64(0.2) },
            WeightedVote { node_id: "c".into(), stance: VoteStance::Endorse, weight: FixedPoint::from_f64(0.2) },
        ];
        // quorum = max(20*0.1, 5.2*0.1) = max(2.0, 0.52) = 2.0
        // total weight = 0.6, < 2.0
        let result = evaluate_standard(&votes, 20, FixedPoint::from_f64(5.2), false);
        assert!(!result.quorum_met);
        assert!(!result.ratified);
    }

    #[test]
    fn cold_start_headcount() {
        let votes: Vec<WeightedVote> = (0..11)
            .map(|i| WeightedVote {
                node_id: format!("node_{}", i),
                stance: if i < 8 { VoteStance::Endorse } else { VoteStance::Reject },
                weight: FixedPoint::from_f64(0.2),
            })
            .collect();
        let result = evaluate_cold_start(&votes, 20);
        assert!(result.quorum_met); // 11/20 > 50%
        assert!(result.threshold_met); // 8/11 = 72.7% > 67%
        assert!(result.ratified);
    }

    #[test]
    fn activity_multiplier_high() {
        let m = activity_multiplier(2, 0.3, 5);
        assert!((m - 2.33).abs() < 0.01);
        assert!((sustain_days(m) - 3.0).abs() < 0.1);
    }

    #[test]
    fn activity_multiplier_zero() {
        let m = activity_multiplier(0, 0.0, 0);
        assert_eq!(m, 1.0);
        assert_eq!(sustain_days(m), 7.0);
    }
}
