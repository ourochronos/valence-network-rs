//! Message envelope types per §2.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::types::{FixedPoint, MessageId, NodeId, Timestamp};

/// All message types defined in v0.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    // §1 Identity
    KeyRotate,
    KeyConflict,
    DidLink,
    DidRevoke,
    // §3 Transport
    AuthChallenge,
    AuthResponse,
    // §4 Peer discovery
    PeerAnnounce,
    PeerListRequest,
    PeerListResponse,
    // §5 Gossip
    SyncRequest,
    SyncResponse,
    StateSnapshot,
    // §6 Content
    Share,
    ReplicateRequest,
    ReplicateAccept,
    ShardAssignment,
    ShardReceived,
    ContentRequest,
    ContentResponse,
    ContentWithdraw,
    RentPayment,
    Flag,
    StorageChallenge,
    StorageProof,
    ShardQuery,
    ShardQueryResponse,
    ChallengeResult,
    // §7 Proposals
    Request,
    Propose,
    Withdraw,
    Adopt,
    Comment,
    // §8 Votes
    Vote,
    // §9 Reputation
    ReputationGossip,
}

impl MessageType {
    /// Whether this message type uses GossipSub (vs stream protocol).
    pub fn is_gossipsub(&self) -> bool {
        matches!(
            self,
            // §1 Identity — /valence/peers
            MessageType::KeyRotate
                | MessageType::KeyConflict
                | MessageType::DidLink
                | MessageType::DidRevoke
                // §4 Peer discovery — /valence/peers
                | MessageType::PeerAnnounce
                // §6 Content — /valence/peers
                | MessageType::Share
                | MessageType::Flag
                // §6 Content — /valence/proposals
                | MessageType::ReplicateRequest
                | MessageType::ReplicateAccept
                | MessageType::ShardAssignment
                | MessageType::ShardReceived
                | MessageType::ContentWithdraw
                | MessageType::RentPayment
                | MessageType::ChallengeResult
                // §7 Proposals — /valence/proposals
                | MessageType::Request
                | MessageType::Propose
                | MessageType::Withdraw
                | MessageType::Adopt
                | MessageType::Comment
                // §8 Votes — /valence/votes
                | MessageType::Vote
                // §9 Reputation — /valence/peers
                | MessageType::ReputationGossip
        )
    }

    /// GossipSub topic for this message type (None for stream-only messages).
    pub fn gossipsub_topic(&self) -> Option<&'static str> {
        match self {
            // /valence/peers
            MessageType::PeerAnnounce
            | MessageType::ReputationGossip
            | MessageType::KeyRotate
            | MessageType::KeyConflict
            | MessageType::DidLink
            | MessageType::DidRevoke
            | MessageType::Share
            | MessageType::Flag => Some("/valence/peers"),

            // /valence/proposals
            MessageType::Request
            | MessageType::Propose
            | MessageType::Withdraw
            | MessageType::Adopt
            | MessageType::Comment
            | MessageType::ReplicateRequest
            | MessageType::ReplicateAccept
            | MessageType::ShardAssignment
            | MessageType::ShardReceived
            | MessageType::ContentWithdraw
            | MessageType::RentPayment
            | MessageType::ChallengeResult => Some("/valence/proposals"),

            // /valence/votes
            MessageType::Vote => Some("/valence/votes"),

            // Stream-only
            _ => None,
        }
    }
}

/// Signed message envelope per §2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version. MUST be 0 for v0.
    pub version: u32,
    /// Message type.
    #[serde(rename = "type")]
    pub msg_type: MessageType,
    /// SHA-256 hex of the signing body. Content address.
    pub id: MessageId,
    /// Hex-encoded Ed25519 public key of sender.
    pub from: NodeId,
    /// Unix time in milliseconds.
    pub timestamp: Timestamp,
    /// Type-specific payload.
    pub payload: Value,
    /// Hex-encoded Ed25519 signature over signing body.
    pub signature: String,
}

/// Vote stance per §8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VoteStance {
    Endorse,
    Reject,
    Abstain,
}

/// Proposal tier per §7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProposalTier {
    Standard,
    Constitutional,
}

/// Erasure coding level per §6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErasureCoding {
    Minimal,
    Standard,
    Resilient,
}

impl ErasureCoding {
    pub fn data_shards(&self) -> usize {
        match self {
            ErasureCoding::Minimal => 3,
            ErasureCoding::Standard => 5,
            ErasureCoding::Resilient => 8,
        }
    }

    pub fn parity_shards(&self) -> usize {
        match self {
            ErasureCoding::Minimal => 2,
            ErasureCoding::Standard => 3,
            ErasureCoding::Resilient => 4,
        }
    }
}

// ─── Typed payload structs ───────────────────────────────────────────

/// §6 Content — Flag severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlagSeverity {
    Dispute,
    Illegal,
}

/// §6 Content — Flag category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlagCategory {
    Dmca,
    Spam,
    Malware,
    Csam,
    Other,
}

/// §6 Content — SHARE payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharePayload {
    /// Content entries being shared.
    pub entries: Vec<ShareEntry>,
}

/// §6 Content — Single entry in a SHARE payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareEntry {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// MIME type of the content.
    pub content_type: String,
    /// Size of the content in bytes.
    pub content_size: u64,
    /// Optional filename.
    pub filename: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Tags for discovery.
    pub tags: Vec<String>,
}

/// §6 Content — REPLICATE_REQUEST payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicateRequestPayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// MIME type of the content.
    pub content_type: String,
    /// Size of the content in bytes.
    pub content_size: u64,
    /// Optional filename.
    pub filename: Option<String>,
    /// Optional description.
    pub description: Option<String>,
    /// Tags for discovery.
    pub tags: Vec<String>,
    /// Erasure coding level.
    pub coding: ErasureCoding,
    /// Reputation staked for storage.
    pub reputation_stake: FixedPoint,
}

/// §6 Content — REPLICATE_ACCEPT payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicateAcceptPayload {
    /// SHA-256 hex of the content being accepted.
    pub content_hash: String,
    /// Shard indices the provider is willing to store.
    pub shard_indices: Vec<u32>,
    /// Available storage capacity in bytes.
    pub capacity_available: u64,
}

/// §6 Content — SHARD_ASSIGNMENT payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardAssignmentPayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Shard-to-provider assignments.
    pub assignments: Vec<ShardAssignmentEntry>,
}

/// §6 Content — Single shard assignment entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardAssignmentEntry {
    /// Shard index.
    pub shard_index: u32,
    /// Provider node ID.
    pub provider: NodeId,
}

/// §6 Content — SHARD_RECEIVED payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardReceivedPayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Shard index received.
    pub shard_index: u32,
    /// SHA-256 hex of the shard data.
    pub shard_hash: String,
}

/// §6 Content — CONTENT_REQUEST payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRequestPayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Byte offset to start reading from.
    pub offset: u64,
    /// Number of bytes to read.
    pub length: u64,
}

/// §6 Content — CONTENT_RESPONSE payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentResponsePayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Byte offset of this chunk.
    pub offset: u64,
    /// Base64-encoded chunk data.
    pub data: String,
    /// Total size of the content in bytes.
    pub total_size: u64,
}

/// §6 Content — CONTENT_WITHDRAW payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentWithdrawPayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Timestamp after which the withdrawal takes effect.
    pub effective_after: Timestamp,
    /// Optional reason for withdrawal.
    pub reason: Option<String>,
}

/// §6 Content — RENT_PAYMENT payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RentPaymentPayload {
    /// SHA-256 hex of the content.
    pub content_hash: String,
    /// Billing cycle number.
    pub billing_cycle: u32,
    /// Total rent amount for this cycle.
    pub amount: FixedPoint,
    /// Per-provider rent distribution.
    pub providers: Vec<RentProviderShare>,
}

/// §6 Content — Per-provider share in a RENT_PAYMENT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RentProviderShare {
    /// Provider node ID.
    pub node_id: NodeId,
    /// Number of shards held by this provider.
    pub shards_held: u32,
    /// Rent amount for this provider.
    pub amount: FixedPoint,
}

/// §6 Content — FLAG payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlagPayload {
    /// SHA-256 hex of the flagged content.
    pub content_hash: String,
    /// Severity of the flag.
    pub severity: FlagSeverity,
    /// Category of the flag.
    pub category: FlagCategory,
    /// Details explaining the flag.
    pub details: String,
    /// Optional known-bad hash match.
    pub hash_match: Option<String>,
}

/// §7 Proposals — COMMENT payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentPayload {
    /// Message ID of the proposal being commented on.
    pub target_id: MessageId,
    /// Comment body text.
    pub body: String,
    /// Optional parent comment ID for threading.
    pub parent_comment_id: Option<MessageId>,
}
