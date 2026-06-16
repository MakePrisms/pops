//! `pop quote` — the non-blocking half of `pop mint`.
//!
//! Does the pre-poll work — resolve the unit, derive a fresh funder key, create
//! the quote, independently verify the funding address, persist the deposit
//! (Unpaid), and write the recovery file — then prints the funding instruction
//! and exits without waiting for funding:
//!
//! ```text
//! pop quote ... --json    # -> {deposit_id, funding_address, bip21_uri, ...}
//! # (fund the address)
//! pop mint --resume <deposit_id> --json   # -> the cashuB token
//! ```
//!
//! It reuses `mint`'s `create_and_persist_quote` helper, so the crypto —
//! including the independent address verification and recovery-file write — is
//! identical.

use std::path::Path;

use clap::Parser;

use crate::commands::mint::{create_and_persist_quote, MintArgs};
use crate::recovery::utc_iso8601;
use crate::wallet::Wallet;

/// Arguments for `pop quote`. These mirror the relevant `pop mint` args; the
/// funding-poll, token-output, and resume knobs do not apply (quote never polls).
#[derive(Debug, Parser)]
#[command(group(
    // A quote ALWAYS needs a unit/lifetime, so exactly one of duration|unit is
    // required here (unlike mint, which can resume one from a deposit). Missing
    // both is a clean clap usage error (exit 2) instead of the mint-side
    // "Unit unsupported" (11013) failure.
    clap::ArgGroup::new("unit_or_duration")
        .args(["duration", "unit"])
        .required(true)
        .multiple(false)
))]
pub struct QuoteArgs {
    /// Mint base URL (e.g. `https://mint.example`).
    #[arg(long, value_name = "URL")]
    pub mint_url: String,

    /// Amount to lock + mint, in sats.
    #[arg(long, value_name = "SATS")]
    pub amount: u64,

    /// Credential lifetime as a duration (e.g. `30d`, `12h`). `ts = now + dur`.
    /// Mutually exclusive with `--unit`.
    #[arg(long, value_name = "DUR", conflicts_with = "unit")]
    pub duration: Option<String>,

    /// Explicit unit `pop_<ts_expiry>`. Mutually exclusive with `--duration`.
    #[arg(long, value_name = "pop_<ts>")]
    pub unit: Option<String>,

    /// The mint's 33-byte compressed identity pubkey (66 hex chars), available
    /// from the mint's `GET /v1/info` endpoint. REQUIRED on first use of a mint
    /// (TOFU-pinned into config.toml); it is the value committed into `cm` and is
    /// needed to independently verify the funding address.
    #[arg(long, value_name = "HEX33")]
    pub mint_pubkey: Option<String>,

    /// Optional human label for the deposit.
    #[arg(long, value_name = "TEXT")]
    pub label: Option<String>,
}

impl QuoteArgs {
    /// Projects the quote args onto a `MintArgs` so the shared pre-poll helper
    /// can be reused. The poll, token-out, and resume fields are unused by
    /// `create_and_persist_quote` and are left at inert defaults.
    fn as_mint_args(&self) -> MintArgs {
        MintArgs {
            mint_url: Some(self.mint_url.clone()),
            amount: Some(self.amount),
            duration: self.duration.clone(),
            unit: self.unit.clone(),
            mint_pubkey: self.mint_pubkey.clone(),
            label: self.label.clone(),
            poll_interval: 0,
            poll_timeout: 0,
            token_out: None,
            resume: None,
        }
    }
}

/// Runs `pop quote`: the pre-poll half of `mint`, then exits.
///
/// # Errors
///
/// Propagates every step's errors; aborts on an address-verification mismatch.
pub async fn run(
    args: &QuoteArgs,
    wallet_dir: &Path,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = Wallet::open(wallet_dir)?;
    let base = args.mint_url.trim_end_matches('/').to_string();
    let http = reqwest::Client::new();
    let seed = wallet.load_seed()?;

    let mint_args = args.as_mint_args();
    let outcome =
        create_and_persist_quote(&mut wallet, &http, &base, &seed, &mint_args, wallet_dir).await?;

    if json {
        let out = serde_json::json!({
            "schema_version": crate::SCHEMA_VERSION,
            "deposit_id": outcome.deposit_id,
            "funding_address": outcome.construction.address,
            "amount_sats": outcome.amount,
            "unit": outcome.unit_str,
            "ts_expiry": outcome.ts_expiry,
            "recover_after_utc": utc_iso8601(outcome.ts_expiry),
            // SWAP / spend-by deadline (the mint's keyset final_expiry), distinct
            // from and earlier than recover_after. null ⟹ the keyset sets none.
            "usable_until": outcome.usable_until,
            "usable_until_utc": outcome.usable_until.map(utc_iso8601),
            "bip21_uri": outcome.bip21_uri(),
            "mint_url": base,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        crate::commands::mint::print_funding_instruction(
            &outcome.construction.address,
            outcome.amount,
            outcome.ts_expiry,
            &outcome.derivation_path,
        );
        println!(
            "\nQuote persisted as deposit {}. When you've funded the address, run:\n  \
             pop mint --resume {} --mint-url {}",
            outcome.deposit_id, outcome.deposit_id, base
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `quote` must forward exactly the funding-relevant args onto the shared
    /// `MintArgs`, with the poll/token/resume knobs left inert (quote never
    /// polls or mints). This is what guarantees `quote` and `mint` build the
    /// SAME deposit via the SAME helper.
    #[test]
    fn as_mint_args_forwards_funding_fields() {
        let q = QuoteArgs {
            mint_url: "https://mint.example".to_string(),
            amount: 12_345,
            duration: Some("30d".to_string()),
            unit: None,
            mint_pubkey: Some("02ab".to_string()),
            label: Some("rent".to_string()),
        };
        let m = q.as_mint_args();
        assert_eq!(m.mint_url.as_deref(), Some("https://mint.example"));
        assert_eq!(m.amount, Some(12_345));
        assert_eq!(m.duration.as_deref(), Some("30d"));
        assert_eq!(m.unit, None);
        assert_eq!(m.mint_pubkey.as_deref(), Some("02ab"));
        assert_eq!(m.label.as_deref(), Some("rent"));
        // Inert for quote (no funding poll, no mint, no resume).
        assert_eq!(m.poll_interval, 0);
        assert_eq!(m.poll_timeout, 0);
        assert!(m.token_out.is_none());
        assert!(m.resume.is_none());
    }
}
