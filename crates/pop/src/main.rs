//! `pop` — a funder-side CLI wallet for PoP (Proof-of-Power) Cashu credentials.
//!
//! PoP credentials are Cashu bearer tokens backed by a CLTV-locked Bitcoin
//! UTXO. This wallet owns the funder lifecycle: lock BTC (`mint`), and
//! unilaterally reclaim it after the timelock (`recover`). The minted ecash is
//! printed as a `cashuB` token and NOT managed here — this wallet manages
//! deposits and recovery, not a balance.
//!
//! The two on-chain realities the funder must understand (surfaced by `mint`):
//! funding is ~1-confirmation on-chain (not instant), and recovery uses this
//! wallet's OWN seed-derived key (no consumer-wallet dependency).

#![warn(missing_docs)]

mod chain;
mod commands;
mod config;
mod db;
mod derive;
mod error;
mod mint_client;
mod network;
mod recovery;
mod seed;
mod signer;
mod wallet;

pub use error::{PopError, SCHEMA_VERSION};

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};

// `recovery_address` (the P2TR wrap of an already-tweaked output key) now lives
// in the `pops-core-funder` kernel as `pops_core_funder::recovery_address`; the
// recovery flow calls it through the kernel.

/// Funder-side CLI wallet for PoP credentials.
#[derive(Debug, Parser)]
#[command(
    name = "pop",
    version,
    about = "Funder-side PoP wallet: lock BTC, mint credentials, and recover after the CLTV.",
    long_about = "pop is the funder's single tool for the PoP loop: `init` creates a seed; \
`mint` locks BTC in a CLTV-backed P2TR, polls for funding, and prints the issued cashuB token; \
`recover` reclaims the locked BTC after the timelock via a taproot script-path spend; \
`list`/`status` show deposits. The minted ecash is printed, not stored. Recovery needs only \
this wallet's seed + the per-deposit recovery file (or Bitcoin Core with the descriptor)."
)]
struct Cli {
    /// Wallet directory (default `~/.pop-wallet/`).
    #[arg(long, value_name = "PATH", global = true)]
    wallet_dir: Option<PathBuf>,

    /// Emit human-readable text instead of the default machine-readable JSON.
    /// In human mode, success prints to stdout and failures print to stderr.
    #[arg(long, alias = "pretty", global = true)]
    human: bool,

    /// Deprecated no-op: JSON is now the DEFAULT output. Kept as an accepted
    /// alias so existing `--json` invocations don't break. Use `--human` to opt
    /// into text output.
    #[arg(long, global = true, hide = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a BIP-39 seed, store it (plaintext, 0600), and show the mnemonic once.
    Init(commands::init::InitArgs),
    /// Create + verify a funding quote, persist it, and EXIT (no funding poll).
    Quote(commands::quote::QuoteArgs),
    /// Lock BTC, poll for funding, and print the issued cashuB token.
    Mint(commands::mint::MintArgs),
    /// Reclaim CLTV-matured deposits via a taproot script-path spend.
    Recover(commands::recover::RecoverArgs),
    /// List deposits and their lifecycle state.
    List(commands::list::ListArgs),
    /// Show a deposit dashboard (alias-ish to `list` with detail).
    Status(commands::list::StatusArgs),
    /// Summarize the ledger: total locked, per-state counts/sats, mintable/recoverable now.
    Balance(commands::balance::BalanceArgs),
}

#[tokio::main]
async fn main() {
    // Parse the global `--human` flag once, up front, so the error path knows
    // which surface to write to even if a command fails. Clap usage errors
    // (exit 2) are handled inside `Cli::parse()` before we get here.
    let cli = Cli::parse();

    // Post-parse usage validation that clap's ArgGroup can't express. A fresh
    // `pop mint` (no --resume) MUST pick a unit/lifetime via exactly one of
    // {--duration, --unit}; missing both is a clap USAGE error (exit 2), not a
    // mint-side "Unit unsupported" surprise. (A resume loads the unit from the
    // deposit, so it's exempt — mirrors `quote`'s required group.)
    if let Cmd::Mint(margs) = &cli.cmd {
        if margs.missing_required_unit_group() {
            Cli::command()
                .error(
                    clap::error::ErrorKind::MissingRequiredArgument,
                    "a fresh `pop mint` requires exactly one of --duration <DUR> or --unit pop_<ts> \
                     (or use --resume <deposit_id> to reload the unit from a persisted deposit)",
                )
                .exit();
        }
    }

    let human = cli.human;

    if let Err(e) = run(cli).await {
        let pe = error::from_boxed(e);
        if human {
            // Human mode: the human message to STDERR, no json, non-zero exit.
            eprintln!("error: {}", pe.message());
        } else {
            // JSON mode (default): the single failure envelope to STDOUT.
            // stdout stays pure-parseable; nothing else is printed here.
            match serde_json::to_string_pretty(&pe.to_envelope()) {
                Ok(s) => println!("{s}"),
                // A serialization failure of our own envelope is itself internal;
                // fall back to a minimal hand-written envelope so stdout is still
                // a single valid JSON object.
                Err(_) => println!(
                    "{{\"schema_version\":{SCHEMA_VERSION},\"error\":{{\"code\":\"internal_error\",\"retriable\":false,\"message\":\"failed to serialize error envelope\"}}}}"
                ),
            }
        }
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let wallet_dir = wallet::resolve_wallet_dir(cli.wallet_dir.as_deref())?;
    // `json` is the command-level "emit machine output" flag. JSON is the
    // DEFAULT; `--human` (alias `--pretty`) flips to text. The deprecated
    // `--json` flag is an accepted no-op (json is already default).
    let json = !cli.human;

    match &cli.cmd {
        Cmd::Init(args) => commands::init::run(args, &wallet_dir, json),
        Cmd::Quote(args) => commands::quote::run(args, &wallet_dir, json).await,
        Cmd::Mint(args) => commands::mint::run(args, &wallet_dir, json).await,
        Cmd::Recover(args) => commands::recover::run(args, &wallet_dir, json).await,
        Cmd::List(args) => commands::list::run_list(args, &wallet_dir, json),
        Cmd::Status(args) => commands::list::run_status(args, &wallet_dir, json).await,
        Cmd::Balance(args) => commands::balance::run(args, &wallet_dir, json).await,
    }
}
