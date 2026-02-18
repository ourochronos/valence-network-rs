//! Valence Network v0 node — reference implementation.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::info;

use valence_crypto::identity::NodeIdentity;
use valence_network::swarm::ValenceSwarm;
use valence_network::transport::TransportConfig;

/// Node configuration.
#[derive(Debug, Clone)]
struct NodeConfig {
    /// Path to the identity key file.
    identity_path: Option<PathBuf>,
    /// Listen addresses.
    listen_addrs: Vec<String>,
    /// Bootstrap peer addresses.
    bootstrap_peers: Vec<String>,
    /// Enable mDNS for local discovery.
    enable_mdns: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            identity_path: None,
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/9090".to_string()],
            bootstrap_peers: vec![],
            enable_mdns: true,
        }
    }
}

fn parse_args() -> NodeConfig {
    let mut config = NodeConfig::default();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" | "-l" => {
                if let Some(addr) = args.next() {
                    config.listen_addrs = vec![addr];
                }
            }
            "--bootstrap" | "-b" => {
                if let Some(addr) = args.next() {
                    config.bootstrap_peers.push(addr);
                }
            }
            "--identity" | "-i" => {
                if let Some(path) = args.next() {
                    config.identity_path = Some(PathBuf::from(path));
                }
            }
            "--no-mdns" => {
                config.enable_mdns = false;
            }
            "--help" | "-h" => {
                eprintln!("Valence Network v0 Node");
                eprintln!();
                eprintln!("USAGE:");
                eprintln!("  valence-node [OPTIONS]");
                eprintln!();
                eprintln!("OPTIONS:");
                eprintln!("  -l, --listen <ADDR>      Listen address (default: /ip4/0.0.0.0/tcp/9090)");
                eprintln!("  -b, --bootstrap <ADDR>   Bootstrap peer (repeatable)");
                eprintln!("  -i, --identity <PATH>    Identity key file");
                eprintln!("  --no-mdns                Disable mDNS discovery");
                eprintln!("  -h, --help               Show this help");
                std::process::exit(0);
            }
            _ => {
                eprintln!("Unknown argument: {arg}");
                std::process::exit(1);
            }
        }
    }

    config
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,valence=debug".into()),
        )
        .init();

    let config = parse_args();

    // Load or generate identity
    let identity = if let Some(path) = &config.identity_path {
        if path.exists() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("Failed to read identity from {}", path.display()))?;
            let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow::anyhow!("Identity file must be exactly 32 bytes")
            })?;
            let id = NodeIdentity::from_seed(&seed);
            info!(node_id = %id.node_id(), path = %path.display(), "Loaded identity");
            id
        } else {
            let id = NodeIdentity::generate();
            std::fs::write(path, id.signing_key().to_bytes())
                .with_context(|| format!("Failed to write identity to {}", path.display()))?;
            info!(node_id = %id.node_id(), path = %path.display(), "Generated new identity");
            id
        }
    } else {
        let id = NodeIdentity::generate();
        info!(node_id = %id.node_id(), "Generated ephemeral identity (use --identity to persist)");
        id
    };

    // Build transport config
    let transport_config = TransportConfig {
        listen_addrs: config
            .listen_addrs
            .iter()
            .map(|a| a.parse().expect("Invalid listen address"))
            .collect(),
        bootstrap_peers: config
            .bootstrap_peers
            .iter()
            .map(|a| a.parse().expect("Invalid bootstrap address"))
            .collect(),
        enable_mdns: config.enable_mdns,
        ..Default::default()
    };

    // Create and start the swarm
    let (mut swarm, _cmd_tx, mut _event_rx) =
        ValenceSwarm::new(identity, transport_config).context("Failed to create swarm")?;

    swarm.start_listening().context("Failed to start listening")?;

    info!("Valence Network v0 node running. Press Ctrl+C to stop.");

    // Run the event loop
    swarm.run().await
}
