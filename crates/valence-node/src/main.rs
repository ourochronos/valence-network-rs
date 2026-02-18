use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("Valence Network v0 node starting...");

    // TODO: Parse CLI args, load config, initialize identity, start network
    tracing::info!("Node implementation pending. Core crates ready.");

    Ok(())
}
