//! Core types for the Valence Network v0 protocol.

use serde::{Deserialize, Serialize};

/// Fixed-point reputation value (×10,000 internally).
/// Multiply by 10,000 and truncate per §2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FixedPoint(i64);

impl FixedPoint {
    pub const SCALE: i64 = 10_000;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(10_000);

    /// Create from float, truncating (not rounding) per §2.
    pub fn from_f64(val: f64) -> Self {
        Self((val * Self::SCALE as f64) as i64)
    }

    /// Create from raw scaled integer.
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    /// Get the raw scaled integer value.
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Convert to f64 (for display/debugging only — not for protocol computation).
    pub fn to_f64(self) -> f64 {
        self.0 as f64 / Self::SCALE as f64
    }

    /// Add two fixed-point values.
    pub fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }

    /// Subtract two fixed-point values.
    pub fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }

    /// Multiply two fixed-point values. Intermediate uses i128 to avoid overflow.
    /// Truncation only on final result per §2/§8.
    pub fn mul(self, other: Self) -> Self {
        let result = (self.0 as i128 * other.0 as i128) / Self::SCALE as i128;
        Self(result as i64)
    }

    /// Divide two fixed-point values. Intermediate uses i128.
    pub fn div(self, other: Self) -> Self {
        if other.0 == 0 {
            return Self::ZERO;
        }
        let result = (self.0 as i128 * Self::SCALE as i128) / other.0 as i128;
        Self(result as i64)
    }

    /// Clamp to [min, max].
    pub fn clamp(self, min: Self, max: Self) -> Self {
        Self(self.0.clamp(min.0, max.0))
    }
}

impl std::fmt::Display for FixedPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:.4}", self.to_f64())
    }
}

/// Node identity — hex-encoded Ed25519 public key.
pub type NodeId = String;

/// Message ID — SHA-256 hex digest of the signing body.
pub type MessageId = String;

/// Unix timestamp in milliseconds.
pub type Timestamp = i64;

/// Protocol constants from v0 spec.
pub mod constants {
    use super::FixedPoint;

    // §1 Identity
    pub const KEY_ROTATION_GRACE_PERIOD_MS: i64 = 3_600_000; // 1 hour

    // §2 Message format
    pub const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024; // 8 MiB
    pub const TIMESTAMP_TOLERANCE_MS: i64 = 5 * 60 * 1000; // 5 minutes
    pub const INLINE_CONTENT_LIMIT: usize = 1024 * 1024; // 1 MiB

    // §4 Peer discovery
    pub const PEER_ANNOUNCE_INTERVAL_MS: i64 = 5 * 60 * 1000; // 5 minutes
    pub const PEER_EXPIRY_MS: i64 = 30 * 60 * 1000; // 30 minutes
    pub const ANTI_FRAG_INTERVAL_MS: i64 = 10 * 60 * 1000; // 10 minutes
    pub const MAX_ASN_FRACTION: f64 = 0.25;
    pub const MIN_DISTINCT_ASNS: usize = 4;

    // §5 Gossip
    pub const DEDUP_CACHE_SIZE: usize = 100_000;
    pub const GOSSIP_MAX_AGE_MS: i64 = 24 * 60 * 60 * 1000; // 24 hours

    // §6 Proposals
    pub const VOTING_DEADLINE_DEFAULT_MS: i64 = 14 * 24 * 60 * 60 * 1000; // 14 days
    pub const VOTING_DEADLINE_MAX_MS: i64 = 90 * 24 * 60 * 60 * 1000; // 90 days
    pub const PROPOSAL_RATE_LIMIT: usize = 3; // per 7-day window
    pub const PROPOSAL_RATE_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;

    // §7 Votes
    pub const MINIMUM_VOTERS: usize = 3;
    pub const STANDARD_THRESHOLD: FixedPoint = FixedPoint::from_raw(6_700); // 0.67
    pub const CONSTITUTIONAL_THRESHOLD: FixedPoint = FixedPoint::from_raw(9_000); // 0.90
    pub const CONSTITUTIONAL_QUORUM_FRACTION: FixedPoint = FixedPoint::from_raw(3_000); // 0.30
    pub const COLD_START_DAYS: i64 = 30;
    pub const COLD_START_HEADCOUNT_FLOOR: FixedPoint = FixedPoint::from_raw(5_000); // 0.50
    pub const GOVERNANCE_MIN_NODES: usize = 16;
    pub const CONSTITUTIONAL_MIN_NODES: usize = 1024;
    pub const CONSTITUTIONAL_SUSTAIN_DAYS: i64 = 30;
    pub const CONSTITUTIONAL_VOTE_MIN_MS: i64 = 90 * 24 * 60 * 60 * 1000;
    pub const CONSTITUTIONAL_COOLING_MS: i64 = 30 * 24 * 60 * 60 * 1000;

    // §8 Reputation
    pub const INITIAL_REPUTATION: FixedPoint = FixedPoint::from_raw(2_000); // 0.2
    pub const REPUTATION_FLOOR: FixedPoint = FixedPoint::from_raw(1_000); // 0.1
    pub const REPUTATION_CAP: FixedPoint = FixedPoint::from_raw(10_000); // 1.0
    pub const MAX_DAILY_GAIN: FixedPoint = FixedPoint::from_raw(200); // 0.02
    pub const MAX_WEEKLY_GAIN: FixedPoint = FixedPoint::from_raw(800); // 0.08
    pub const INACTIVITY_DECAY: FixedPoint = FixedPoint::from_raw(200); // 0.02/month
    pub const INACTIVITY_THRESHOLD_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    pub const ALPHA_MAX: FixedPoint = FixedPoint::from_raw(6_000); // 0.6
    pub const ALPHA_RAMP_DIVISOR: i64 = 10;
    pub const PEER_INFORMED_CAP_MIN_ASSESSORS: usize = 3;
    pub const REP_GOSSIP_INTERVAL_MS: i64 = 15 * 60 * 1000;
    pub const REP_GOSSIP_BATCH: usize = 10;

    // §9 Sybil resistance
    pub const VDF_DIFFICULTY: u64 = 1_000_000;
    pub const VDF_CHECKPOINT_INTERVAL: u64 = 100_000;
    pub const VDF_MIN_VERIFY_SEGMENTS: usize = 5;
    pub const VDF_MAX_VERIFICATIONS_PER_DAY: usize = 50;
    pub const MAX_NEW_PEERS_PER_HOUR: usize = 5;

    // §10 Anti-gaming
    pub const VOTE_CORRELATION_THRESHOLD: f64 = 0.95;
    pub const VOTE_CORRELATION_MIN_PROPOSALS: usize = 20;
    pub const COLLUSION_PENALTY: FixedPoint = FixedPoint::from_raw(500); // 0.05
    pub const TENURE_PENALTY_ONSET: usize = 6; // cycles
    pub const TENURE_PENALTY_FACTOR: FixedPoint = FixedPoint::from_raw(9_500); // 0.95
    pub const VOTING_CYCLE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

    // §11 Partition detection
    pub const EXPIRED_PROPOSAL_ARCHIVE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
    pub const WITHDRAWN_PROPOSAL_ARCHIVE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
    pub const REJECTED_PROPOSAL_ARCHIVE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    pub const RATIFIED_PROPOSAL_ARCHIVE_MS: i64 = 180 * 24 * 60 * 60 * 1000;

    // §12 Protocol evolution
    pub const MINOR_EOL_MIN_MS: i64 = 30 * 24 * 60 * 60 * 1000;
    pub const MAJOR_EOL_MIN_MS: i64 = 90 * 24 * 60 * 60 * 1000;

    // §13 Error handling
    pub const UNKNOWN_TYPE_RATE_LIMIT: usize = 10; // per sender per hour
    pub const PEER_BACKOFF_MAX_MS: i64 = 10 * 60 * 1000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_from_f64_truncates() {
        // §2: truncate, not round
        assert_eq!(FixedPoint::from_f64(0.67891).raw(), 6789);
        assert_eq!(FixedPoint::from_f64(0.8).raw(), 8000);
        assert_eq!(FixedPoint::from_f64(0.67).raw(), 6700);
        assert_eq!(FixedPoint::from_f64(1.0).raw(), 10000);
        assert_eq!(FixedPoint::from_f64(0.0).raw(), 0);
    }

    #[test]
    fn fixed_point_mul() {
        let a = FixedPoint::from_f64(0.6);
        let b = FixedPoint::from_f64(0.5);
        let result = a.mul(b);
        assert_eq!(result.raw(), 3000); // 0.6 × 0.5 = 0.3
    }

    #[test]
    fn fixed_point_div() {
        let a = FixedPoint::from_f64(0.6);
        let b = FixedPoint::from_f64(0.3);
        let result = a.div(b);
        assert_eq!(result.raw(), 20000); // 0.6 / 0.3 = 2.0
    }

    #[test]
    fn fixed_point_clamp() {
        let val = FixedPoint::from_f64(1.5);
        let clamped = val.clamp(constants::REPUTATION_FLOOR, constants::REPUTATION_CAP);
        assert_eq!(clamped, constants::REPUTATION_CAP);

        let val = FixedPoint::from_f64(0.05);
        let clamped = val.clamp(constants::REPUTATION_FLOOR, constants::REPUTATION_CAP);
        assert_eq!(clamped, constants::REPUTATION_FLOOR);
    }
}
