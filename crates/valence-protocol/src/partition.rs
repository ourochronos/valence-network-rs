//! Partition detection and merge per §11.

use valence_core::canonical::merkle_root;
use valence_core::constants;

/// Partition severity per §11.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PartitionSeverity {
    /// < 5% proposal set difference
    Info,
    /// 5-20% difference
    Warning,
    /// > 20% difference
    Critical,
}

/// Compare two proposal sets and determine partition severity.
pub fn classify_divergence(local_ids: &[String], remote_ids: &[String]) -> PartitionSeverity {
    let local_set: std::collections::HashSet<&str> = local_ids.iter().map(|s| s.as_str()).collect();
    let remote_set: std::collections::HashSet<&str> = remote_ids.iter().map(|s| s.as_str()).collect();

    let union_size = local_set.union(&remote_set).count();
    if union_size == 0 {
        return PartitionSeverity::Info;
    }

    let symmetric_diff = local_set.symmetric_difference(&remote_set).count();
    let diff_pct = symmetric_diff as f64 / union_size as f64;

    if diff_pct > 0.20 {
        PartitionSeverity::Critical
    } else if diff_pct >= 0.05 {
        PartitionSeverity::Warning
    } else {
        PartitionSeverity::Info
    }
}

/// Compute the Merkle root over the active proposal set per §11.
/// Leaves: SHA-256 hash of each active proposal's `id`, sorted lexicographically.
pub fn active_proposal_merkle_root(proposal_ids: &[String]) -> String {
    let mut sorted = proposal_ids.to_vec();
    sorted.sort();
    merkle_root(&sorted)
}

/// Determine if a proposal should be archived per §11 retention policy.
/// Returns true if the proposal should be removed from the active set.
pub fn should_archive(
    status: &ProposalArchiveStatus,
    status_since_ms: i64,
    now_ms: i64,
) -> bool {
    let age = now_ms - status_since_ms;
    match status {
        ProposalArchiveStatus::Expired => age > constants::EXPIRED_PROPOSAL_ARCHIVE_MS,
        ProposalArchiveStatus::Withdrawn => age > constants::WITHDRAWN_PROPOSAL_ARCHIVE_MS,
        ProposalArchiveStatus::Rejected => age > constants::REJECTED_PROPOSAL_ARCHIVE_MS,
        ProposalArchiveStatus::Ratified => age > constants::RATIFIED_PROPOSAL_ARCHIVE_MS,
        ProposalArchiveStatus::ProtocolChange => false, // Never auto-archived
        ProposalArchiveStatus::Active => false,
    }
}

/// Proposal status for archival decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalArchiveStatus {
    Active,
    Expired,
    Withdrawn,
    Rejected,
    Ratified,
    ProtocolChange,
}

/// Partition merge: resolve conflicting protocol proposals per §11.
/// Returns the winning proposal ID.
pub fn resolve_protocol_conflict(
    proposal_a: &ProtocolProposalInfo,
    proposal_b: &ProtocolProposalInfo,
) -> &'static str {
    // §11: If one supersedes the other, superseding proposal wins
    if proposal_a.supersedes.as_deref() == Some(&proposal_b.id) {
        return "a";
    }
    if proposal_b.supersedes.as_deref() == Some(&proposal_a.id) {
        return "b";
    }

    // Otherwise: earlier voting_deadline wins
    if proposal_a.voting_deadline_ms < proposal_b.voting_deadline_ms {
        return "a";
    }
    if proposal_b.voting_deadline_ms < proposal_a.voting_deadline_ms {
        return "b";
    }

    // Equal deadlines: lower id (lexicographic) wins
    if proposal_a.id <= proposal_b.id {
        "a"
    } else {
        "b"
    }
}

/// Info needed for protocol conflict resolution.
#[derive(Debug, Clone)]
pub struct ProtocolProposalInfo {
    pub id: String,
    pub voting_deadline_ms: i64,
    pub supersedes: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divergence_none() {
        let local = vec!["a".to_string(), "b".to_string()];
        let remote = vec!["a".to_string(), "b".to_string()];
        assert_eq!(classify_divergence(&local, &remote), PartitionSeverity::Info);
    }

    #[test]
    fn divergence_small() {
        // 1 out of 21 differs = ~4.8% < 5% → Info
        let local: Vec<String> = (0..20).map(|i| format!("p{i}")).collect();
        let mut remote = local.clone();
        remote.push("extra".to_string());
        assert_eq!(classify_divergence(&local, &remote), PartitionSeverity::Info);
    }

    #[test]
    fn divergence_warning() {
        // 2 out of 12 differ = ~16.7% → Warning
        let mut local: Vec<String> = (0..10).map(|i| format!("p{i}")).collect();
        let mut remote: Vec<String> = (0..10).map(|i| format!("p{i}")).collect();
        local.push("only_local".to_string());
        remote.push("only_remote".to_string());
        assert_eq!(classify_divergence(&local, &remote), PartitionSeverity::Warning);
    }

    #[test]
    fn divergence_critical() {
        let local = vec!["a".to_string(), "b".to_string()];
        let remote = vec!["c".to_string(), "d".to_string()];
        // 4 out of 4 differ = 100% → Critical
        assert_eq!(classify_divergence(&local, &remote), PartitionSeverity::Critical);
    }

    #[test]
    fn divergence_empty() {
        let empty: Vec<String> = vec![];
        assert_eq!(classify_divergence(&empty, &empty), PartitionSeverity::Info);
    }

    #[test]
    fn merkle_root_deterministic() {
        let ids = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        let r1 = active_proposal_merkle_root(&ids);
        let r2 = active_proposal_merkle_root(&ids);
        assert_eq!(r1, r2);

        // Order shouldn't matter (sorted internally)
        let ids2 = vec!["b".to_string(), "c".to_string(), "a".to_string()];
        let r3 = active_proposal_merkle_root(&ids2);
        assert_eq!(r1, r3);
    }

    #[test]
    fn archival_timing() {
        let now = 1_000_000_000i64;

        // Expired proposal: archived after 7 days
        assert!(!should_archive(
            &ProposalArchiveStatus::Expired,
            now - 6 * 24 * 60 * 60 * 1000,
            now
        ));
        assert!(should_archive(
            &ProposalArchiveStatus::Expired,
            now - 8 * 24 * 60 * 60 * 1000,
            now
        ));

        // Ratified proposal: archived after 180 days
        assert!(!should_archive(
            &ProposalArchiveStatus::Ratified,
            now - 179 * 24 * 60 * 60 * 1000,
            now
        ));
        assert!(should_archive(
            &ProposalArchiveStatus::Ratified,
            now - 181 * 24 * 60 * 60 * 1000,
            now
        ));

        // Protocol change: never archived
        assert!(!should_archive(
            &ProposalArchiveStatus::ProtocolChange,
            0, // ancient
            now
        ));
    }

    #[test]
    fn protocol_conflict_supersession() {
        let a = ProtocolProposalInfo {
            id: "aaa".to_string(),
            voting_deadline_ms: 2000,
            supersedes: Some("bbb".to_string()),
        };
        let b = ProtocolProposalInfo {
            id: "bbb".to_string(),
            voting_deadline_ms: 1000,
            supersedes: None,
        };
        // a supersedes b → a wins regardless of deadline
        assert_eq!(resolve_protocol_conflict(&a, &b), "a");
    }

    #[test]
    fn protocol_conflict_earlier_deadline() {
        let a = ProtocolProposalInfo {
            id: "aaa".to_string(),
            voting_deadline_ms: 2000,
            supersedes: None,
        };
        let b = ProtocolProposalInfo {
            id: "bbb".to_string(),
            voting_deadline_ms: 1000,
            supersedes: None,
        };
        // b has earlier deadline → b wins
        assert_eq!(resolve_protocol_conflict(&a, &b), "b");
    }

    #[test]
    fn protocol_conflict_equal_deadline_lexicographic() {
        let a = ProtocolProposalInfo {
            id: "aaa".to_string(),
            voting_deadline_ms: 1000,
            supersedes: None,
        };
        let b = ProtocolProposalInfo {
            id: "bbb".to_string(),
            voting_deadline_ms: 1000,
            supersedes: None,
        };
        // Equal deadlines, lower id wins → a
        assert_eq!(resolve_protocol_conflict(&a, &b), "a");
    }
}
