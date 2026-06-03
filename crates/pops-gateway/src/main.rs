//! `pops-gateway` binary entry point.
//!
//! Reads ONE declarative TOML (default `/etc/pops-gateway/config.toml`, override
//! with `POPS_GATEWAY_CONFIG`), fail-fast validates it (structured
//! `config field <X>: <reason>` to stderr + nonzero exit; NEVER a panic /
//! stacktrace), emits the LOUD `proofs_sink` value-at-risk warning, then serves
//! the reverse proxy with JSON structured logs.

use std::process::ExitCode;
use std::sync::Arc;

use pops_gateway::build_router;
use pops_gateway::config::{Config, ValidatedConfig};
use pops_gateway::gateway::AppState;
use pops_gateway::proofs_sink::ProofsSink;

/// Default config path inside the container (the Dockerfile mounts the
/// operator's config here).
const DEFAULT_CONFIG_PATH: &str = "/etc/pops-gateway/config.toml";

fn main() -> ExitCode {
    // Structured JSON logs (plan §4.2) so an agent/operator can parse outcomes.
    // `env-filter` honours RUST_LOG; default to `info`.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .init();

    // ── Load + validate config (fail-fast, structured, nonzero exit). ──
    let validated = match load_config() {
        Ok(v) => v,
        Err(msg) => {
            // Structured message to stderr; NEVER a panic.
            eprintln!("{msg}");
            return ExitCode::FAILURE;
        }
    };

    // ── LOUD proofs_sink warning (refinement #1). ──
    tracing::warn!(
        proofs_sink = %validated.proofs_sink.display(),
        "proofs_sink={} holds BEARER ecash = received value; ensure this is a PERSISTENT mount or you will lose received value.",
        validated.proofs_sink.display()
    );

    // ── Open the durable sink (a sink open failure is also fail-fast). ──
    let sink = match ProofsSink::open(&validated.proofs_sink) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("config field proofs_sink: cannot open for append: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Hand off to the async runtime to bind + serve.
    let listen = validated.listen.clone();
    match run(validated, sink, listen) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "gateway exited with error");
            ExitCode::FAILURE
        }
    }
}

/// Resolve the config path, read it, parse it, and validate it. Any failure is
/// returned as a fully-formed stderr message string (already structured).
fn load_config() -> Result<ValidatedConfig, String> {
    let path =
        std::env::var("POPS_GATEWAY_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string());

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("config file {path}: could not read: {e}"))?;

    let config = Config::from_toml_str(&raw)
        .map_err(|e| format!("config file {path}: invalid TOML: {e}"))?;

    config.validate().map_err(|e| e.to_string())
}

/// Build the runtime, bind the listener, and serve until shutdown.
fn run(validated: ValidatedConfig, sink: ProofsSink, listen: String) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    runtime.block_on(async move {
        let state = Arc::new(AppState::production(validated, sink));
        let app = build_router(state);

        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .map_err(|e| format!("failed to bind {listen}: {e}"))?;

        tracing::info!(%listen, "pops-gateway listening");

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| format!("server error: {e}"))
    })
}

/// Resolve on SIGINT/SIGTERM for a clean shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
