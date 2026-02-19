//! Content lifecycle, storage economics, and capability ramp per §6 and §9.

use valence_core::types::FixedPoint;
use valence_core::constants::*;

/// Content lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentState {
    /// Content is hosted locally (not yet replicated).
    Hosted,
    /// Content is replicated with a locked scarcity multiplier.
    Replicated {
        /// Scarcity multiplier locked at replication time.
        locked_multiplier: FixedPoint,
        /// Timestamp when replication completed.
        replication_timestamp: i64,
    },
    /// Content is in grace period after missed rent.
    GracePeriod {
        /// When the grace period started.
        entered_at: i64,
        /// Number of times content entered grace within 90 days.
        miss_count: u32,
    },
    /// Content has decayed (garbage collected after grace expiry).
    Decayed,
    /// Content is being withdrawn (24h delay).
    Withdrawn {
        /// Timestamp after which withdrawal takes effect.
        effective_after: i64,
    },
}

/// Protocol actions gated by reputation per §9 capability ramp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolAction {
    /// Store shards (any reputation).
    StoreShards,
    /// Sync, browse, adopt (any reputation).
    SyncBrowseAdopt,
    /// Submit proposals (≥ 0.3).
    Propose,
    /// Vote on proposals (≥ 0.3).
    Vote,
    /// Replicate content (≥ 0.3).
    Replicate,
    /// Flag content as dispute (≥ 0.3).
    FlagDispute,
    /// Flag content as illegal (≥ 0.5).
    FlagIllegal,
}

/// Compute scarcity multiplier from network utilization.
/// Formula: 1 + 99 × utilization^4, cap at 100×.
/// When total_allocated = 0, returns 1.0.
///
/// L-2: `total_available` is the remaining free space within `total_allocated`.
/// It should always be <= `total_allocated`. When it exceeds `total_allocated`,
/// utilization is clamped to 0 (no scarcity).
pub fn scarcity_multiplier(total_allocated: u64, total_available: u64) -> FixedPoint {
    if total_allocated == 0 {
        return FixedPoint::ONE;
    }
    debug_assert!(
        total_available <= total_allocated,
        "total_available ({total_available}) should not exceed total_allocated ({total_allocated})"
    );
    let utilization = 1.0 - (total_available as f64 / total_allocated as f64);
    let utilization = utilization.clamp(0.0, 1.0);
    let mult = 1.0 + 99.0 * utilization.powi(4);
    FixedPoint::from_f64(mult.min(100.0))
}

/// Monthly rent = (content_size_bytes / 1 MiB) × base_rate × scarcity_multiplier.
/// Uses i128 intermediates to avoid overflow.
pub fn monthly_rent(content_size_bytes: u64, multiplier: FixedPoint) -> FixedPoint {
    // rent = (size_bytes / 1048576) * 0.001 * multiplier
    // In fixed-point: (size_bytes * base_rate_raw * multiplier_raw) / (1048576 * SCALE)
    let numerator = content_size_bytes as i128
        * STORAGE_BASE_RATE.raw() as i128
        * multiplier.raw() as i128;
    let denominator = 1_048_576i128 * FixedPoint::SCALE as i128;
    FixedPoint::from_raw((numerator / denominator) as i64)
}

/// Compute effective multiplier with convergence per §6.
///
/// Normal: locked + (current - locked) × min(1, cycles / 5)
/// Accelerated (>10× divergence): locked + (current - locked) × min(1, cycles × 3 / 10)
pub fn effective_multiplier(locked: FixedPoint, current: FixedPoint, cycles_elapsed: u32) -> FixedPoint {
    let diff = current.saturating_sub(locked);
    let divergence_ratio = if locked.raw() > 0 {
        current.raw() / locked.raw()
    } else {
        100
    };

    let factor = if divergence_ratio > RENT_CONVERGENCE_ACCEL_THRESHOLD {
        // Accelerated: cycles × 3 / 10
        let f = (cycles_elapsed as i64 * 3 * FixedPoint::SCALE) / 10;
        FixedPoint::from_raw(f.min(FixedPoint::SCALE))
    } else {
        // Normal: cycles / 5
        let f = (cycles_elapsed as i64 * FixedPoint::SCALE) / RENT_CONVERGENCE_CYCLES;
        FixedPoint::from_raw(f.min(FixedPoint::SCALE))
    };

    // effective = locked + diff * factor
    let product = (diff.raw() as i128 * factor.raw() as i128) / FixedPoint::SCALE as i128;
    locked.saturating_add(FixedPoint::from_raw(product as i64))
}

/// Max active replicated content per identity in MiB.
/// max_active = base_allowance × (reputation / 0.2)^2
pub fn max_storage_mib(reputation: FixedPoint) -> u64 {
    let ratio = reputation.to_f64() / 0.2;
    (STORAGE_BASE_ALLOWANCE_MIB as f64 * ratio * ratio) as u64
}

/// Grace period duration based on how many times content has entered grace within 90 days.
pub fn grace_period_ms(miss_count_within_90d: u32) -> i64 {
    match miss_count_within_90d {
        0 => RENT_GRACE_PERIOD_1_MS,
        1 => RENT_GRACE_PERIOD_2_MS,
        _ => RENT_GRACE_PERIOD_3_MS,
    }
}

/// Check if a reputation level permits a given action per §9.
pub fn can_perform(reputation: FixedPoint, action: ProtocolAction) -> bool {
    match action {
        ProtocolAction::StoreShards | ProtocolAction::SyncBrowseAdopt => true,
        ProtocolAction::Propose
        | ProtocolAction::Vote
        | ProtocolAction::Replicate
        | ProtocolAction::FlagDispute => reputation >= MIN_REP_TO_PROPOSE,
        ProtocolAction::FlagIllegal => reputation >= MIN_REP_TO_FLAG_ILLEGAL,
    }
}

/// Compute adoption reward split with provenance per §6.
/// Returns (proposer_share, host_share, storage_provider_share).
pub fn adoption_reward_split(
    total_reward: FixedPoint,
    has_provenance: bool,
    host_reputation: Option<FixedPoint>,
) -> (FixedPoint, FixedPoint, FixedPoint) {
    // Storage providers always get 30% of total
    let provider_share_raw =
        (total_reward.raw() as i128 * PROVENANCE_HOST_SHARE.raw() as i128) / FixedPoint::SCALE as i128;
    let provider_share = FixedPoint::from_raw(provider_share_raw as i64);
    let author_side = total_reward.saturating_sub(provider_share);

    if has_provenance {
        let host_rep = host_reputation.unwrap_or(FixedPoint::ZERO);
        let host_share_raw =
            (author_side.raw() as i128 * PROVENANCE_HOST_SHARE.raw() as i128) / FixedPoint::SCALE as i128;
        let host_share_full = FixedPoint::from_raw(host_share_raw as i64);

        let host_share = if host_rep >= MIN_REP_TO_PROPOSE {
            host_share_full
        } else {
            host_share_full.clamp(FixedPoint::ZERO, PROVENANCE_BELOW_THRESHOLD_CAP)
        };
        let proposer_share = author_side.saturating_sub(host_share);
        (proposer_share, host_share, provider_share)
    } else {
        (author_side, FixedPoint::ZERO, provider_share)
    }
}

/// Compute a provider's share of the 80% rent pool.
/// Pro-rated by (shards_held / total_shards) × min(1, challenges_passed / MIN_CHALLENGES_PER_CYCLE).
pub fn provider_rent_share(
    total_rent: FixedPoint,
    challenges_passed: u32,
    shards_held: u32,
    total_shards: u32,
) -> FixedPoint {
    if challenges_passed == 0 || total_shards == 0 {
        return FixedPoint::ZERO;
    }
    let capped_challenges = challenges_passed.min(MIN_CHALLENGES_PER_CYCLE as u32);
    // provider_pool = total_rent * 0.8
    // share = provider_pool * (shards_held / total_shards) * (capped_challenges / MIN_CHALLENGES)
    // Use i128 for the whole thing:
    let numerator = total_rent.raw() as i128
        * PROVIDER_RENT_SHARE.raw() as i128
        * shards_held as i128
        * capped_challenges as i128;
    let denominator = FixedPoint::SCALE as i128
        * total_shards as i128
        * MIN_CHALLENGES_PER_CYCLE as i128;
    FixedPoint::from_raw((numerator / denominator) as i64)
}

/// Compute a single validator's share of the 20% rent pool.
/// Capped at VALIDATOR_EARNINGS_CAP challenges per content per cycle.
/// Found-failure challenges count 2×.
pub fn validator_rent_share(
    total_rent: FixedPoint,
    challenges_by_this_validator: u32,
    total_challenges_all_validators: u32,
    found_failure: bool,
) -> FixedPoint {
    if total_challenges_all_validators == 0 {
        return FixedPoint::ZERO;
    }
    let capped = challenges_by_this_validator.min(VALIDATOR_EARNINGS_CAP as u32);
    let multiplier: i128 = if found_failure { 2 } else { 1 };
    let effective = capped as i128 * multiplier;

    // share = total_rent * VALIDATOR_RENT_SHARE * effective / (SCALE * total_challenges)
    let numerator = total_rent.raw() as i128
        * VALIDATOR_RENT_SHARE.raw() as i128
        * effective;
    let denominator = FixedPoint::SCALE as i128 * total_challenges_all_validators as i128;
    FixedPoint::from_raw((numerator / denominator) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── scarcity_multiplier ──

    #[test]
    fn scarcity_zero_allocated() {
        assert_eq!(scarcity_multiplier(0, 0), FixedPoint::ONE);
    }

    #[test]
    fn scarcity_zero_utilization() {
        // total_available == total_allocated → utilization = 0
        let m = scarcity_multiplier(1000, 1000);
        assert_eq!(m, FixedPoint::ONE);
    }

    // ── L-2: scarcity_multiplier documents expected relationship ──

    #[test]
    fn scarcity_equal_available_and_allocated_is_one() {
        // L-2: When total_available == total_allocated, utilization = 0, multiplier = 1
        let m = scarcity_multiplier(1000, 1000);
        assert_eq!(m, FixedPoint::ONE);
    }

    #[test]
    #[should_panic(expected = "total_available")]
    fn scarcity_debug_asserts_on_available_exceeding_allocated() {
        // L-2: debug_assert fires when total_available > total_allocated
        let _ = scarcity_multiplier(100, 200);
    }

    #[test]
    fn scarcity_20_percent() {
        // utilization = 0.2, mult = 1 + 99*0.0016 = 1.1584
        let m = scarcity_multiplier(1000, 800);
        assert!((m.to_f64() - 1.1584).abs() < 0.01);
    }

    #[test]
    fn scarcity_50_percent() {
        // utilization = 0.5, mult = 1 + 99*0.0625 = 7.1875
        let m = scarcity_multiplier(1000, 500);
        assert!((m.to_f64() - 7.1875).abs() < 0.01);
    }

    #[test]
    fn scarcity_80_percent() {
        // utilization = 0.8, mult = 1 + 99*0.4096 = 41.5504
        let m = scarcity_multiplier(1000, 200);
        assert!((m.to_f64() - 41.5504).abs() < 0.1);
    }

    #[test]
    fn scarcity_100_percent() {
        // utilization = 1.0, mult = 1 + 99 = 100
        let m = scarcity_multiplier(1000, 0);
        assert_eq!(m, SCARCITY_MULTIPLIER_CAP);
    }

    // ── monthly_rent ──

    #[test]
    fn rent_1mib_base() {
        // 1 MiB at 1× multiplier = 0.001
        let rent = monthly_rent(1_048_576, FixedPoint::ONE);
        assert_eq!(rent.raw(), STORAGE_BASE_RATE.raw()); // 10 = 0.001
    }

    #[test]
    fn rent_10mib_base() {
        let rent = monthly_rent(10 * 1_048_576, FixedPoint::ONE);
        assert_eq!(rent.raw(), 100); // 0.01
    }

    #[test]
    fn rent_with_multiplier() {
        // 1 MiB at 10× = 0.01
        let rent = monthly_rent(1_048_576, FixedPoint::from_f64(10.0));
        assert_eq!(rent.raw(), 100);
    }

    // ── effective_multiplier ──

    #[test]
    fn convergence_normal_partial() {
        // locked=1.0, current=6.0, 2 cycles → 1 + (6-1)*2/5 = 3.0
        let eff = effective_multiplier(
            FixedPoint::ONE,
            FixedPoint::from_f64(6.0),
            2,
        );
        assert_eq!(eff.raw(), 30000); // 3.0
    }

    #[test]
    fn convergence_normal_full() {
        // locked=1.0, current=6.0, 5 cycles → fully converged to 6.0
        let eff = effective_multiplier(
            FixedPoint::ONE,
            FixedPoint::from_f64(6.0),
            5,
        );
        assert_eq!(eff.raw(), 60000);
    }

    #[test]
    fn convergence_accelerated() {
        // locked=1.0, current=15.0 (15× > 10×), 2 cycles → 1 + 14*0.6 = 9.4
        let eff = effective_multiplier(
            FixedPoint::ONE,
            FixedPoint::from_f64(15.0),
            2,
        );
        assert_eq!(eff.raw(), 94000); // 9.4
    }

    #[test]
    fn convergence_accelerated_full() {
        // locked=1.0, current=15.0, 4 cycles → 3*4/10 = 1.2 capped to 1.0 → 15.0
        let eff = effective_multiplier(
            FixedPoint::ONE,
            FixedPoint::from_f64(15.0),
            4,
        );
        assert_eq!(eff.raw(), 150000);
    }

    // ── max_storage_mib ──

    #[test]
    fn storage_at_initial_rep() {
        // rep=0.2, ratio=1.0, max = 10 * 1 = 10
        assert_eq!(max_storage_mib(INITIAL_REPUTATION), STORAGE_BASE_ALLOWANCE_MIB);
    }

    #[test]
    fn storage_at_half_rep() {
        // rep=0.5, ratio=2.5, max = 10 * 6.25 = 62
        assert_eq!(max_storage_mib(FixedPoint::from_f64(0.5)), 62);
    }

    #[test]
    fn storage_at_max_rep() {
        // rep=1.0, ratio=5.0, max = 10 * 25 = 250
        assert_eq!(max_storage_mib(REPUTATION_CAP), 250);
    }

    #[test]
    fn storage_at_floor() {
        // rep=0.1, ratio=0.5, max = 10 * 0.25 = 2
        assert_eq!(max_storage_mib(REPUTATION_FLOOR), 2);
    }

    // ── grace_period_ms ──

    #[test]
    fn grace_first_miss() {
        assert_eq!(grace_period_ms(0), RENT_GRACE_PERIOD_1_MS);
    }

    #[test]
    fn grace_second_miss() {
        assert_eq!(grace_period_ms(1), RENT_GRACE_PERIOD_2_MS);
    }

    #[test]
    fn grace_third_miss() {
        assert_eq!(grace_period_ms(2), RENT_GRACE_PERIOD_3_MS);
        assert_eq!(grace_period_ms(5), RENT_GRACE_PERIOD_3_MS);
    }

    // ── can_perform ──

    #[test]
    fn anyone_can_store_and_sync() {
        assert!(can_perform(REPUTATION_FLOOR, ProtocolAction::StoreShards));
        assert!(can_perform(REPUTATION_FLOOR, ProtocolAction::SyncBrowseAdopt));
        assert!(can_perform(FixedPoint::ZERO, ProtocolAction::StoreShards));
    }

    #[test]
    fn propose_requires_03() {
        assert!(!can_perform(FixedPoint::from_f64(0.29), ProtocolAction::Propose));
        assert!(can_perform(FixedPoint::from_f64(0.3), ProtocolAction::Propose));
        assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::Vote));
        assert!(can_perform(FixedPoint::from_f64(0.3), ProtocolAction::Replicate));
        assert!(can_perform(FixedPoint::from_f64(0.3), ProtocolAction::FlagDispute));
    }

    #[test]
    fn flag_illegal_requires_05() {
        assert!(!can_perform(FixedPoint::from_f64(0.49), ProtocolAction::FlagIllegal));
        assert!(can_perform(FixedPoint::from_f64(0.5), ProtocolAction::FlagIllegal));
    }

    // ── adoption_reward_split ──

    #[test]
    fn split_no_provenance() {
        let total = FixedPoint::from_f64(1.0);
        let (proposer, host, provider) = adoption_reward_split(total, false, None);
        assert_eq!(provider.raw(), 3000); // 0.3
        assert_eq!(host, FixedPoint::ZERO);
        assert_eq!(proposer.raw(), 7000); // 0.7
    }

    #[test]
    fn split_with_provenance_high_rep() {
        let total = FixedPoint::from_f64(1.0);
        let (proposer, host, provider) =
            adoption_reward_split(total, true, Some(FixedPoint::from_f64(0.5)));
        assert_eq!(provider.raw(), 3000); // 0.3
        // host gets 30% of author_side (0.7) = 0.21
        assert_eq!(host.raw(), 2100);
        assert_eq!(proposer.raw(), 4900); // 0.7 - 0.21
    }

    #[test]
    fn split_with_provenance_low_rep() {
        let total = FixedPoint::from_f64(1.0);
        let (proposer, host, provider) =
            adoption_reward_split(total, true, Some(FixedPoint::from_f64(0.2)));
        assert_eq!(provider.raw(), 3000);
        // host capped at PROVENANCE_BELOW_THRESHOLD_CAP (0.002 = 20)
        assert_eq!(host.raw(), PROVENANCE_BELOW_THRESHOLD_CAP.raw());
        assert_eq!(proposer.raw(), 7000 - PROVENANCE_BELOW_THRESHOLD_CAP.raw());
    }

    // ── provider_rent_share ──

    #[test]
    fn provider_share_basic() {
        // total_rent=1.0, 10 challenges, 5/10 shards
        let share = provider_rent_share(
            FixedPoint::ONE,
            10,
            5,
            10,
        );
        // pool = 1.0 * 0.8 = 0.8
        // shard_frac = 0.5, challenge_frac = 1.0
        // share = 0.8 * 0.5 * 1.0 = 0.4
        assert_eq!(share.raw(), 4000);
    }

    #[test]
    fn provider_share_partial_challenges() {
        // Only 5 out of 10 required challenges
        let share = provider_rent_share(
            FixedPoint::ONE,
            5,
            10,
            10,
        );
        // pool=0.8, shard=1.0, challenge=0.5 → 0.4
        assert_eq!(share.raw(), 4000);
    }

    #[test]
    fn provider_share_zero_challenges() {
        assert_eq!(
            provider_rent_share(FixedPoint::ONE, 0, 5, 10),
            FixedPoint::ZERO
        );
    }

    #[test]
    fn provider_share_zero_shards() {
        assert_eq!(
            provider_rent_share(FixedPoint::ONE, 10, 5, 0),
            FixedPoint::ZERO
        );
    }

    // ── validator_rent_share ──

    #[test]
    fn validator_share_basic() {
        // total_rent=1.0, 10 challenges by this validator, 100 total, no failure
        let share = validator_rent_share(FixedPoint::ONE, 10, 100, false);
        // pool = 0.2, effective = 10, share = 0.2 * 10/100 = 0.02
        assert_eq!(share.raw(), 200);
    }

    #[test]
    fn validator_share_with_failure() {
        // Same but found failure → 2×
        let share = validator_rent_share(FixedPoint::ONE, 10, 100, true);
        // effective = 20, share = 0.2 * 20/100 = 0.04
        assert_eq!(share.raw(), 400);
    }

    #[test]
    fn validator_share_capped() {
        // 50 challenges, capped at VALIDATOR_EARNINGS_CAP=30
        let share = validator_rent_share(FixedPoint::ONE, 50, 100, false);
        let share_at_cap = validator_rent_share(FixedPoint::ONE, 30, 100, false);
        assert_eq!(share, share_at_cap);
    }

    #[test]
    fn validator_share_zero_total() {
        assert_eq!(
            validator_rent_share(FixedPoint::ONE, 10, 0, false),
            FixedPoint::ZERO
        );
    }

    // ── ContentState ──

    #[test]
    fn content_state_equality() {
        let a = ContentState::Replicated {
            locked_multiplier: FixedPoint::ONE,
            replication_timestamp: 1000,
        };
        let b = ContentState::Replicated {
            locked_multiplier: FixedPoint::ONE,
            replication_timestamp: 1000,
        };
        assert_eq!(a, b);
        assert_ne!(ContentState::Hosted, ContentState::Decayed);
    }
}
