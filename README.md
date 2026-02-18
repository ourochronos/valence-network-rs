# valence-network-rs

Rust reference implementation of the [Valence Network v0 protocol](https://github.com/ourochronos/valence-network).

## Crates

| Crate | Description |
|-------|-------------|
| `valence-core` | Types, JCS canonicalization, content addressing, Merkle trees |
| `valence-crypto` | Ed25519 identity, VDF, message signing/verification |
| `valence-protocol` | Reputation, quorum evaluation, proposal lifecycle |
| `valence-network` | libp2p transport, GossipSub, sync protocol (WIP) |
| `valence-node` | Binary — the actual node (WIP) |

## Status

Foundation crates implemented with conformance test coverage:
- ✅ JCS canonicalization (RFC 8785)
- ✅ Content addressing (SHA-256 signing body)
- ✅ Ed25519 identity (keypair generation, signing, verification)
- ✅ VDF (iterated SHA-256 with checkpoints, compute + verify)
- ✅ Message envelope (signing, validation, timestamp checks)
- ✅ Fixed-point arithmetic (×10,000, truncation semantics)
- ✅ Merkle trees (empty, 1-N proposals, left-biased)
- ✅ Reputation (scoring, α ramp, velocity limits, peer formula)
- ✅ Quorum evaluation (standard, constitutional, cold start, activity multiplier)
- 🔲 libp2p networking (GossipSub, sync, auth handshake)
- 🔲 Peer discovery (bootstrap, mDNS, peer exchange)
- 🔲 Gossip (dedup, propagation, age validation)
- 🔲 Storage (erasure coding, shard challenges)
- 🔲 Anti-gaming (collusion detection, tenure)
- 🔲 Node binary (CLI, config, lifecycle)

## Build

```bash
cargo build
cargo test
```

## License

MIT OR Apache-2.0
