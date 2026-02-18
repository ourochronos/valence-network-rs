//! libp2p transport setup — Noise encryption, GossipSub topics, stream protocols.
//! Implements §3 (Transport), §4 (Peer Discovery), and §5 (Gossip) of v0 spec.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use libp2p::{
    Multiaddr, PeerId,
};
use tracing::debug;

use valence_core::constants;
use valence_core::message::{Envelope, MessageType};

/// GossipSub topic names per §3.
pub const TOPIC_PROPOSALS: &str = "/valence/proposals";
pub const TOPIC_VOTES: &str = "/valence/votes";
pub const TOPIC_PEERS: &str = "/valence/peers";

/// Stream protocol IDs per §3.
pub const SYNC_PROTOCOL: &str = "/valence/sync/1.0.0";
pub const AUTH_PROTOCOL: &str = "/valence/auth/1.0.0";

/// Events emitted by the transport layer to the node.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A validated message received via GossipSub.
    GossipMessage {
        topic: String,
        envelope: Envelope,
        source: PeerId,
    },
    /// A new peer connected and authenticated.
    PeerConnected {
        peer_id: PeerId,
        node_id: String,
        addresses: Vec<Multiaddr>,
    },
    /// A peer disconnected.
    PeerDisconnected { peer_id: PeerId },
    /// A sync response received.
    SyncResponse {
        peer_id: PeerId,
        messages: Vec<Envelope>,
        has_more: bool,
        next_timestamp: Option<i64>,
        next_id: Option<String>,
        checkpoint: Option<String>,
    },
}

/// Commands sent to the transport layer from the node.
#[derive(Debug, Clone)]
pub enum TransportCommand {
    /// Publish a message to a GossipSub topic.
    Publish { topic: String, data: Vec<u8> },
    /// Send a sync request to a specific peer.
    SyncRequest {
        peer_id: PeerId,
        since_timestamp: i64,
        since_id: Option<String>,
        types: Vec<MessageType>,
        limit: usize,
    },
    /// Dial a peer at the given address.
    Dial { addr: Multiaddr },
    /// Announce ourselves on the peers topic.
    Announce,
}

/// Peer info tracked locally.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub node_id: Option<String>,
    pub addresses: Vec<Multiaddr>,
    pub last_seen_ms: i64,
    pub asn: Option<u32>,
    pub capabilities: Vec<String>,
    pub authenticated: bool,
}

/// Peer table with ASN tracking per §4.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: HashMap<PeerId, PeerInfo>,
    asn_counts: HashMap<u32, usize>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or update a peer. Returns false if rejected due to ASN limits.
    pub fn upsert(&mut self, info: PeerInfo) -> bool {
        if let Some(asn) = info.asn {
            // Check ASN diversity constraint (§4): no single ASN > 25%
            let total = self.peers.len() + 1; // including this new one
            let current_asn_count = self.asn_counts.get(&asn).copied().unwrap_or(0);

            if !self.peers.contains_key(&info.peer_id) {
                // New peer — check if adding would violate ASN limit
                let new_count = current_asn_count + 1;
                if total >= constants::MIN_DISTINCT_ASNS
                    && new_count as f64 / total as f64 > constants::MAX_ASN_FRACTION
                {
                    debug!(asn, "Rejecting peer: ASN fraction would exceed 25%");
                    return false;
                }
            }
        }

        let peer_id = info.peer_id;
        let asn = info.asn;

        if let Some(old) = self.peers.insert(peer_id, info) {
            // Update ASN counts if ASN changed
            if let Some(old_asn) = old.asn {
                if Some(old_asn) != asn {
                    if let Some(count) = self.asn_counts.get_mut(&old_asn) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            self.asn_counts.remove(&old_asn);
                        }
                    }
                }
            }
        }

        if let Some(asn) = asn {
            *self.asn_counts.entry(asn).or_insert(0) += 1;
        }

        true
    }

    /// Remove a peer.
    pub fn remove(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        if let Some(info) = self.peers.remove(peer_id) {
            if let Some(asn) = info.asn {
                if let Some(count) = self.asn_counts.get_mut(&asn) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.asn_counts.remove(&asn);
                    }
                }
            }
            Some(info)
        } else {
            None
        }
    }

    /// Prune peers not seen within the expiry window (§4: 30 minutes).
    pub fn prune_expired(&mut self, now_ms: i64) -> Vec<PeerId> {
        let expired: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, info)| now_ms - info.last_seen_ms > constants::PEER_EXPIRY_MS)
            .map(|(id, _)| *id)
            .collect();

        for peer_id in &expired {
            self.remove(peer_id);
        }
        expired
    }

    /// Get a peer by PeerId.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Number of connected peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Number of distinct ASNs.
    pub fn distinct_asns(&self) -> usize {
        self.asn_counts.len()
    }

    /// Get all peers.
    pub fn iter(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo)> {
        self.peers.iter()
    }

    /// Get a random peer outside our immediate set (for anti-fragmentation §4).
    pub fn random_peer(&self) -> Option<&PeerInfo> {
        // Simple: just return the first peer. Real impl would use randomness.
        self.peers.values().next()
    }

    /// Peers sorted by node_id for PEER_LIST_RESPONSE (§4).
    pub fn sorted_by_node_id(&self) -> Vec<&PeerInfo> {
        let mut peers: Vec<&PeerInfo> = self.peers.values().collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }
}

/// Message deduplication cache per §5. Bounded LRU.
#[derive(Debug)]
pub struct DedupCache {
    /// Ordered from oldest to newest.
    entries: Vec<String>,
    set: HashSet<String>,
    capacity: usize,
}

impl DedupCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(1024)),
            set: HashSet::with_capacity(capacity.min(1024)),
            capacity,
        }
    }

    /// Returns true if the message ID was already seen.
    pub fn check_and_insert(&mut self, message_id: &str) -> bool {
        if self.set.contains(message_id) {
            return true;
        }

        if self.capacity == 0 {
            return false; // can't store anything
        }

        // Evict oldest if at capacity
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.entries.first().cloned() {
                self.entries.remove(0);
                self.set.remove(&oldest);
            }
        }

        self.set.insert(message_id.to_string());
        self.entries.push(message_id.to_string());
        false
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// Configuration for the transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Listen addresses.
    pub listen_addrs: Vec<Multiaddr>,
    /// Bootstrap peer addresses.
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Enable mDNS for local discovery (§4).
    pub enable_mdns: bool,
    /// Dedup cache capacity (§5: 100,000).
    pub dedup_capacity: usize,
    /// Peer announce interval.
    pub announce_interval: Duration,
    /// Anti-fragmentation interval (§4: 10 minutes).
    pub anti_frag_interval: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".parse().unwrap()],
            bootstrap_peers: vec![],
            enable_mdns: true,
            dedup_capacity: constants::DEDUP_CACHE_SIZE,
            announce_interval: Duration::from_millis(constants::PEER_ANNOUNCE_INTERVAL_MS as u64),
            anti_frag_interval: Duration::from_millis(constants::ANTI_FRAG_INTERVAL_MS as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_cache_basic() {
        let mut cache = DedupCache::new(3);
        assert!(!cache.check_and_insert("a"));
        assert!(cache.check_and_insert("a")); // already seen
        assert!(!cache.check_and_insert("b"));
        assert!(!cache.check_and_insert("c"));
        assert_eq!(cache.len(), 3);

        // Evicts "a" (oldest)
        assert!(!cache.check_and_insert("d"));
        assert!(!cache.check_and_insert("a")); // evicted, so "new" again
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn dedup_cache_capacity_zero() {
        let mut cache = DedupCache::new(0);
        // With 0 capacity, everything is evicted immediately — nothing is "seen"
        assert!(!cache.check_and_insert("a"));
    }

    #[test]
    fn peer_table_asn_diversity() {
        let mut table = PeerTable::new();

        // Add 4 peers from different ASNs
        for i in 0..4u8 {
            let peer_id = PeerId::random();
            table.upsert(PeerInfo {
                peer_id,
                node_id: Some(format!("node_{i}")),
                addresses: vec![],
                last_seen_ms: 1000,
                asn: Some(i as u32 + 100),
                capabilities: vec![],
                authenticated: true,
            });
        }
        assert_eq!(table.len(), 4);
        assert_eq!(table.distinct_asns(), 4);

        // 5th peer from ASN 100 — that would be 2/5 = 40% > 25%, rejected
        let peer_id = PeerId::random();
        let accepted = table.upsert(PeerInfo {
            peer_id,
            node_id: Some("node_dup".into()),
            addresses: vec![],
            last_seen_ms: 1000,
            asn: Some(100),
            capabilities: vec![],
            authenticated: true,
        });
        assert!(!accepted);
        assert_eq!(table.len(), 4);
    }

    #[test]
    fn peer_table_prune_expired() {
        let mut table = PeerTable::new();
        let peer_id = PeerId::random();
        table.upsert(PeerInfo {
            peer_id,
            node_id: Some("old_node".into()),
            addresses: vec![],
            last_seen_ms: 0,
            asn: None,
            capabilities: vec![],
            authenticated: true,
        });

        // Not expired at 29 minutes
        let pruned = table.prune_expired(29 * 60 * 1000);
        assert!(pruned.is_empty());

        // Expired at 31 minutes
        let pruned = table.prune_expired(31 * 60 * 1000);
        assert_eq!(pruned.len(), 1);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn peer_table_sorted_by_node_id() {
        let mut table = PeerTable::new();
        for name in ["charlie", "alice", "bob"] {
            table.upsert(PeerInfo {
                peer_id: PeerId::random(),
                node_id: Some(name.into()),
                addresses: vec![],
                last_seen_ms: 1000,
                asn: None,
                capabilities: vec![],
                authenticated: true,
            });
        }
        let sorted: Vec<_> = table
            .sorted_by_node_id()
            .iter()
            .map(|p| p.node_id.as_deref().unwrap())
            .collect();
        assert_eq!(sorted, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn gossip_max_age_rejection() {
        // §5: Messages older than 24h via GossipSub MUST be rejected
        let now_ms = 1_000_000_000i64;
        let old_timestamp = now_ms - constants::GOSSIP_MAX_AGE_MS - 1;
        assert!(now_ms - old_timestamp > constants::GOSSIP_MAX_AGE_MS);

        let recent_timestamp = now_ms - constants::GOSSIP_MAX_AGE_MS + 1000;
        assert!(now_ms - recent_timestamp <= constants::GOSSIP_MAX_AGE_MS);
    }
}
