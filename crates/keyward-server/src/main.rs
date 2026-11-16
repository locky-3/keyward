//! `keyward-server` binary. Configure with `KW_*` environment variables
//! (see `config.rs` / docs/server.md). Serve plain HTTP behind a TLS
//! reverse proxy such as Caddy.
#![forbid(unsafe_code)]

use std::net::SocketAddr;

use anyhow::{Context, Result};
use keyward_server::{Config, build, system_clock};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("keyward_server=info,tower_http=info")),
        )
        .init();

    let config = Config::from_env()?;
    let bind = config.bind;
    tracing::info!(
        %bind,
        registration_open = config.registration_open,
        trust_proxy = config.trust_proxy,
        "starting keyward-server"
    );
    let app = build(config, system_clock()).await?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    axum::serve(
        listener,
        app.router
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    tracing::info!("stopped");
    Ok(())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}
