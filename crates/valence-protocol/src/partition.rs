//! Partition detection and merge per §12.

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

/// Content state merge per §12: union semantics.
/// Content active on *either* partition survives (most alive state wins).
/// - Active/Replicated > GracePeriod > Decayed
/// - Withdrawn: only applies if both sides withdrew
/// - For same-variant Replicated: earliest replication timestamp wins (first writer)
/// - Flags: union (accumulated from both sides)
/// - Provenance (`origin_share_id`): earliest SHARE timestamp wins
pub fn merge_content_state(
    a: crate::content::ContentState,
    b: crate::content::ContentState,
) -> crate::content::ContentState {
    use crate::content::ContentState;

    // Union semantics: the "most alive" state wins
    // Replicated (active) > GracePeriod > Hosted > Decayed
    // Withdrawn only wins if BOTH sides withdrew
    match (&a, &b) {
        // If either side is actively Replicated, content survives
        (ContentState::Replicated { locked_multiplier: _lm_a, replication_timestamp: ts_a },
         ContentState::Replicated { locked_multiplier: _lm_b, replication_timestamp: ts_b }) => {
            // Keep earlier replication (first writer wins for provenance)
            if ts_a <= ts_b { a } else { b }
        }
        (ContentState::Replicated { .. }, _) => a,
        (_, ContentState::Replicated { .. }) => b,

        // If one side is Hosted (active) and the other is degraded, keep active
        (ContentState::Hosted, ContentState::Decayed) |
        (ContentState::Hosted, ContentState::GracePeriod { .. }) |
        (ContentState::Hosted, ContentState::Withdrawn { .. }) => a,
        (ContentState::Decayed, ContentState::Hosted) |
        (ContentState::GracePeriod { .. }, ContentState::Hosted) |
        (ContentState::Withdrawn { .. }, ContentState::Hosted) => b,

        // Both withdrawn: earlier effective_after wins
        (ContentState::Withdrawn { effective_after: ea }, ContentState::Withdrawn { effective_after: eb }) => {
            ContentState::Withdrawn { effective_after: (*ea).min(*eb) }
        }
        // One withdrawn, other in grace — grace is "more alive"
        (ContentState::GracePeriod { .. }, ContentState::Withdrawn { .. }) => a,
        (ContentState::Withdrawn { .. }, ContentState::GracePeriod { .. }) => b,
        // One withdrawn, other decayed — withdrawn at least has intent
        (ContentState::Withdrawn { .. }, ContentState::Decayed) => a,
        (ContentState::Decayed, ContentState::Withdrawn { .. }) => b,

        // GracePeriod vs GracePeriod: lower miss count is "healthier"
        (ContentState::GracePeriod { entered_at: ea, miss_count: ma },
         ContentState::GracePeriod { entered_at: eb, miss_count: mb }) => {
            if ma <= mb {
                ContentState::GracePeriod { entered_at: *ea, miss_count: *ma }
            } else {
                ContentState::GracePeriod { entered_at: *eb, miss_count: *mb }
            }
        }
        // GracePeriod vs Decayed: grace is more alive
        (ContentState::GracePeriod { .. }, ContentState::Decayed) => a,
        (ContentState::Decayed, ContentState::GracePeriod { .. }) => b,

        // Both Decayed
        (ContentState::Decayed, ContentState::Decayed) => ContentState::Decayed,

        // Both Hosted
        _ => a,
    }
}

/// Merge flag sets from both partitions (union semantics per §12).
pub fn merge_flags(
    flags_a: &[(String, i64)], // (flagger_id, timestamp)
    flags_b: &[(String, i64)],
) -> Vec<(String, i64)> {
    let mut merged: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for (id, ts) in flags_a.iter().chain(flags_b.iter()) {
        merged.entry(id.clone())
            .and_modify(|existing| *existing = (*existing).min(*ts))
            .or_insert(*ts);
    }
    let mut result: Vec<_> = merged.into_iter().collect();
    result.sort_by_key(|(_, ts)| *ts);
    result
}

/// Merge content provenance: earliest SHARE timestamp wins per §12.
pub fn merge_provenance(
    share_a: Option<(String, i64)>, // (share_id, timestamp)
    share_b: Option<(String, i64)>,
) -> Option<(String, i64)> {
    match (share_a, share_b) {
        (Some(a), Some(b)) => {
            if a.1 <= b.1 { Some(a) } else { Some(b) }
        }
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Invalidate votes cast by revoked keys per §12.
/// Returns the set of vote IDs that should be invalidated.
pub fn invalidate_revoked_votes(
    votes: &[(String, String, i64)], // (vote_id, voter_key, vote_timestamp)
    revocations: &[(String, i64)],    // (revoked_key, revocation_timestamp)
) -> Vec<String> {
    let revocation_map: std::collections::HashMap<&str, i64> = revocations
        .iter()
        .map(|(key, ts)| (key.as_str(), *ts))
        .collect();

    votes
        .iter()
        .filter(|(_, voter_key, vote_ts)| {
            // Invalidate if the voter key was revoked BEFORE the vote timestamp
            if let Some(&revoke_ts) = revocation_map.get(voter_key.as_str()) {
                *vote_ts >= revoke_ts
            } else {
                false
            }
        })
        .map(|(vote_id, _, _)| vote_id.clone())
        .collect()
}

/// Identity merge: DID_REVOKE wins (revocation is permanent).
pub fn merge_identity_state(_linked: bool, revoked: bool) -> bool {
    revoked
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
    fn merge_content_union_active_survives() {
        use crate::content::ContentState;
        use valence_core::types::FixedPoint;
        // Replicated on one side, Decayed on other → Replicated wins (union)
        let a = ContentState::Replicated {
            locked_multiplier: FixedPoint::ONE,
            replication_timestamp: 1000,
        };
        let b = ContentState::Decayed;
        let merged = merge_content_state(a.clone(), b);
        assert_eq!(merged, a);
    }

    #[test]
    fn merge_content_union_grace_over_decayed() {
        use crate::content::ContentState;
        let a = ContentState::GracePeriod { entered_at: 5000, miss_count: 1 };
        let b = ContentState::Decayed;
        let merged = merge_content_state(a.clone(), b);
        assert_eq!(merged, a);
    }

    #[test]
    fn merge_content_replicated_earliest_wins() {
        use crate::content::ContentState;
        use valence_core::types::FixedPoint;
        let a = ContentState::Replicated { locked_multiplier: FixedPoint::ONE, replication_timestamp: 2000 };
        let b = ContentState::Replicated { locked_multiplier: FixedPoint::ONE, replication_timestamp: 1000 };
        let merged = merge_content_state(a, b.clone());
        assert_eq!(merged, b); // earlier timestamp
    }

    #[test]
    fn merge_flags_union() {
        let flags_a = vec![("alice".to_string(), 100), ("bob".to_string(), 200)];
        let flags_b = vec![("bob".to_string(), 150), ("carol".to_string(), 300)];
        let merged = merge_flags(&flags_a, &flags_b);
        assert_eq!(merged.len(), 3);
        // bob should have earliest timestamp
        let bob = merged.iter().find(|(id, _)| id == "bob").unwrap();
        assert_eq!(bob.1, 150);
    }

    #[test]
    fn merge_provenance_earliest_share_wins() {
        let a = Some(("share_1".to_string(), 2000));
        let b = Some(("share_2".to_string(), 1000));
        let result = merge_provenance(a, b);
        assert_eq!(result.unwrap().0, "share_2");
    }

    #[test]
    fn invalidate_votes_by_revoked_keys() {
        let votes = vec![
            ("vote1".to_string(), "key_a".to_string(), 5000),
            ("vote2".to_string(), "key_a".to_string(), 3000),
            ("vote3".to_string(), "key_b".to_string(), 6000),
        ];
        // key_a revoked at timestamp 4000
        let revocations = vec![("key_a".to_string(), 4000)];
        let invalidated = invalidate_revoked_votes(&votes, &revocations);
        // vote1 (ts=5000 >= 4000): invalidated
        // vote2 (ts=3000 < 4000): NOT invalidated
        // vote3 (key_b not revoked): NOT invalidated
        assert_eq!(invalidated, vec!["vote1".to_string()]);
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
