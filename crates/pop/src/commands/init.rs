//! `pop init` — generate (or import) a BIP-39 seed, write it (plaintext, 0600)
//! plus config and an empty db, and show the mnemonic exactly once.

use std::io::Write;
use std::path::Path;

use bip39::Mnemonic;
use bitcoin::Network;
use clap::Parser;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::db::Db;
use crate::error::PopError;
use crate::network::{network_name, parse_network};
use crate::seed::{self, write_seed};
use crate::wallet::is_initialized;
use crate::SCHEMA_VERSION;

/// Arguments for `pop init`.
#[derive(Debug, Parser)]
pub struct InitArgs {
    /// Mnemonic word count (for a freshly generated seed). Ignored when
    /// `--mnemonic` is supplied (the imported phrase dictates its own length).
    #[arg(long, value_name = "12|24", default_value_t = 12, conflicts_with = "mnemonic")]
    pub words: u32,

    /// Import an existing BIP-39 mnemonic instead of generating one
    /// (restore / provision-from-own-seed). The phrase is validated; an
    /// invalid checksum or unknown word is a hard error.
    #[arg(long, value_name = "WORDS")]
    pub mnemonic: Option<String>,

    /// Bitcoin network (pinned for the wallet's life). Default mainnet.
    #[arg(long, value_name = "NET", default_value = "mainnet")]
    pub network: String,

    /// Override the default esplora URL.
    #[arg(long, value_name = "URL")]
    pub esplora_url: Option<String>,

    /// Overwrite an existing wallet (DESTROYS the only secret; requires a
    /// typed confirmation unless `--yes` is also given).
    #[arg(long)]
    pub force: bool,

    /// Skip the interactive typed-path confirmation for `--force` (so an agent
    /// can re-init headlessly). No effect without `--force`.
    #[arg(long)]
    pub yes: bool,

    /// ALSO include the BIP-39 mnemonic in the stdout JSON (explicit opt-in for a
    /// caller that really wants to capture the secret programmatically). By
    /// DEFAULT the mnemonic is NEVER on stdout — it is printed to STDERR only,
    /// and stdout carries `"mnemonic_delivery": "stderr"` instead. Passing this
    /// flag puts the secret on the same channel agents are told to parse/log, so
    /// only use it deliberately.
    #[arg(long)]
    pub show_mnemonic: bool,
}

/// Runs `pop init`.
///
/// # Errors
///
/// Errors if a wallet already exists (without `--force` + confirmation), the
/// word count is invalid, an imported mnemonic fails validation, or any write
/// fails.
pub fn run(args: &InitArgs, wallet_dir: &Path, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let network = parse_network(&args.network).map_err(PopError::invalid_input)?;

    if is_initialized(wallet_dir) {
        if !args.force {
            return Err(PopError::WalletExists {
                message: format!(
                    "a wallet already exists at {} — refusing to overwrite. \
                     Use --force to destroy and re-init (this erases the only secret).",
                    wallet_dir.display()
                ),
            }
            .into());
        }
        confirm_destructive(wallet_dir, args.yes)?;
    }

    std::fs::create_dir_all(wallet_dir)
        .map_err(|e| format!("failed to create wallet dir {}: {e}", wallet_dir.display()))?;

    // Build the mnemonic: import the supplied phrase, or generate a fresh one.
    let (mnemonic, imported) = if let Some(phrase) = &args.mnemonic {
        // NEVER echo the phrase (or bip39's error, which can name a bad word)
        // into the error — invalid_mnemonic is message-only and must not leak
        // the secret.
        let m = Mnemonic::parse(phrase.trim()).map_err(|_| PopError::InvalidMnemonic {
            message: "--mnemonic is not a valid BIP-39 phrase. \
                      Provide the full space-separated word list (12 or 24 words)."
                .to_string(),
        })?;
        (m, true)
    } else {
        let word_count = match args.words {
            12 | 24 => args.words as usize,
            other => {
                return Err(PopError::invalid_input(format!(
                    "--words must be 12 or 24 (got {other})"
                ))
                .into());
            }
        };
        // Generate the mnemonic from a CSPRNG.
        let entropy_bytes = (word_count / 3) * 4; // 12->16, 24->32
        let mut entropy = Zeroizing::new(vec![0u8; entropy_bytes]);
        use rand::RngCore;
        rand::rng().fill_bytes(&mut entropy);
        let m = Mnemonic::from_entropy(&entropy)
            .map_err(|e| format!("failed to build mnemonic: {e}"))?;
        (m, false)
    };
    let word_count = mnemonic.word_count();
    let seed = Zeroizing::new(mnemonic.to_seed("").to_vec());

    // Write the seed in plaintext with owner-only (0600) perms. The mnemonic is
    // the cold backup; there is no at-rest encryption (see `seed` module).
    write_seed(wallet_dir, &seed)?;

    // Write config + empty db.
    let config = Config::new(network, args.esplora_url.clone());
    config.write(wallet_dir)?;
    // Opening the db creates + migrates it.
    let _db = Db::open(wallet_dir)?;

    // Create the recovery sub-dir up front.
    std::fs::create_dir_all(crate::wallet::recovery_dir(wallet_dir))
        .map_err(|e| format!("failed to create recovery dir: {e}"))?;

    // SECURITY: the mnemonic is the only secret and MUST NOT land on the stdout
    // parse channel (the channel agents are told to parse AND log) by default. We
    // always write it to STDERR as a clearly-labelled human line, and only echo
    // it into the stdout JSON when `--show-mnemonic` is an explicit opt-in.
    eprintln!("mnemonic (write this down, shown once): {mnemonic}");

    if json {
        let out = init_json(
            wallet_dir,
            network,
            &config.esplora_url,
            &mnemonic.to_string(),
            imported,
            args.show_mnemonic,
        );
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_success(
            wallet_dir,
            network,
            &config.esplora_url,
            word_count,
            imported,
        );
    }
    Ok(())
}

/// Builds the stdout JSON object for a completed init/import. Extracted so the
/// exact output shape can be asserted in a test.
///
/// SECURITY: by default the secret `mnemonic` is OMITTED from this object (it is
/// delivered on stderr only) and a non-secret `"mnemonic_delivery": "stderr"`
/// marker tells the caller where it went. When `show_mnemonic` is set the caller
/// has explicitly opted in to capturing the secret on stdout, so the `mnemonic`
/// field is included instead (and `mnemonic_delivery` becomes `"stdout"`).
fn init_json(
    wallet_dir: &Path,
    network: Network,
    esplora_url: &str,
    mnemonic: &str,
    imported: bool,
    show_mnemonic: bool,
) -> serde_json::Value {
    let mut out = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "wallet_dir": wallet_dir.to_string_lossy(),
        "network": network_name(network),
        "esplora_url": esplora_url,
        "imported": imported,
    });
    if show_mnemonic {
        // Explicit opt-in: the secret is on stdout AND we mark that fact.
        out["mnemonic"] = serde_json::json!(mnemonic);
        out["mnemonic_delivery"] = serde_json::json!("stdout");
    } else {
        // Default: secret stays off the parse channel; mark where it was sent.
        out["mnemonic_delivery"] = serde_json::json!("stderr");
    }
    out
}

/// Requires the user to type the wallet path to confirm a destructive re-init,
/// unless `assume_yes` is set (headless `--force --yes`).
fn confirm_destructive(
    wallet_dir: &Path,
    assume_yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if assume_yes {
        // Headless override: skip the prompt, still remove the old seed below.
        let _ = std::fs::remove_file(seed::seed_path(wallet_dir));
        return Ok(());
    }
    eprintln!(
        "DANGER: --force will erase the existing wallet at {} and its only secret.",
        wallet_dir.display()
    );
    eprint!("Type the wallet path to confirm: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| PopError::invalid_input(format!("failed to read confirmation: {e}")))?;
    if line.trim() != wallet_dir.to_string_lossy() {
        return Err(PopError::invalid_input("confirmation did not match; aborting").into());
    }
    // Remove the existing seed so is_initialized flips; leave the db so
    // historical deposits aren't silently lost (the user can inspect them).
    let _ = std::fs::remove_file(seed::seed_path(wallet_dir));
    Ok(())
}

fn print_success(
    wallet_dir: &Path,
    network: Network,
    esplora_url: &str,
    word_count: usize,
    imported: bool,
) {
    let verb = if imported { "imported at" } else { "initialized at" };
    println!("Wallet {verb} {}", wallet_dir.display());
    println!("  network:  {}", network_name(network));
    println!("  esplora:  {esplora_url}");
    println!();
    println!("==================== WRITE THIS DOWN — THE ONLY SECRET ====================");
    println!("Your {word_count}-word recovery mnemonic was printed ABOVE on stderr");
    println!("(line `mnemonic (write this down, shown once): ...`) — it is shown ONCE and");
    println!("is kept off stdout so it can't be captured by a stdout-parsing/logging tool.");
    println!();
    println!("This mnemonic is the ONLY backup. It reproduces the seed and every deposit's");
    println!("recovery key. Back it up OFFLINE — the per-deposit recovery files are NOT");
    println!("secret and alone CANNOT move funds. Lose this mnemonic and every deposit");
    println!("becomes unrecoverable.");
    println!();
    println!("NOTE: the wallet dir stores the seed UNENCRYPTED (file `seed`, perms 0600).");
    println!("There is no passphrase. Anyone who can read the wallet directory can derive");
    println!("your keys — protect the directory (and its disk), and rely on the mnemonic");
    println!("as your cold backup.");
    println!("==========================================================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::derive_funder_key;
    use crate::seed::load_seed;

    /// The canonical BIP-39 test vector ("abandon ... about"). Its seed is the
    /// `TEST_SEED` pinned in `derive::tests`, so the mainnet idx-0 x-only key
    /// it derives is the pinned `875851f8…` canary.
    const KNOWN_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const PINNED_MAINNET_IDX0_XONLY: &str =
        "875851f8d6c12eaa9eb74393b69c7c6225156ff69bad896b490dbdf8a6aa5d8d";

    fn args_import(mnemonic: &str, network: &str) -> InitArgs {
        InitArgs {
            words: 12,
            mnemonic: Some(mnemonic.to_string()),
            network: network.to_string(),
            esplora_url: None,
            force: false,
            yes: false,
            show_mnemonic: false,
        }
    }

    /// Importing a known mnemonic must write a seed that derives the SAME
    /// funder key as deriving directly from that mnemonic's seed — i.e. the
    /// `--mnemonic` import path is a faithful provision-from-own-seed and the
    /// frozen derivation is unchanged. Pinned against `derive`'s canary.
    #[test]
    fn import_mnemonic_roundtrip_matches_derivation() {
        let dir = tempfile::tempdir().unwrap();
        run(&args_import(KNOWN_MNEMONIC, "mainnet"), dir.path(), true).unwrap();

        // The seed on disk must match the known mnemonic's seed.
        let parsed = Mnemonic::parse(KNOWN_MNEMONIC).unwrap();
        let expected_seed = parsed.to_seed("");
        let loaded = load_seed(dir.path()).unwrap();
        assert_eq!(loaded.as_slice(), &expected_seed[..]);

        // And the funder key derived from the imported wallet's seed matches
        // both the direct derivation and the pinned canary.
        let from_import = derive_funder_key(&loaded, Network::Bitcoin, 0).unwrap();
        let from_direct = derive_funder_key(&expected_seed, Network::Bitcoin, 0).unwrap();
        assert_eq!(from_import.xonly, from_direct.xonly);
        assert_eq!(
            hex::encode(from_import.xonly.serialize()),
            PINNED_MAINNET_IDX0_XONLY,
            "imported-seed funder x-only drifted from the frozen derivation canary"
        );
    }

    /// An invalid mnemonic (bad checksum / wrong word count) is a hard error,
    /// not a silently-generated wallet.
    #[test]
    fn import_invalid_mnemonic_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = run(&args_import("abandon abandon abandon", "mainnet"), dir.path(), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid BIP-39 phrase"), "got: {err}");
    }

    /// DEFAULT (no `--show-mnemonic`): the stdout JSON object carries exactly the
    /// documented keys and — critically — does NOT include the secret `mnemonic`;
    /// instead it marks `mnemonic_delivery: "stderr"`. `imported` reflects the
    /// import vs generate path.
    #[test]
    fn init_json_default_omits_mnemonic_and_marks_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let v = init_json(
            dir.path(),
            Network::Signet,
            "https://mutinynet.com/api",
            KNOWN_MNEMONIC,
            true,
            false, // show_mnemonic = false (default)
        );
        let obj = v.as_object().expect("init_json must be a JSON object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "esplora_url",
                "imported",
                "mnemonic_delivery",
                "network",
                "schema_version",
                "wallet_dir"
            ],
            "default stdout JSON must NOT carry the `mnemonic` field"
        );
        assert!(
            !obj.contains_key("mnemonic"),
            "SECURITY: the mnemonic must never be on the default stdout channel"
        );
        assert_eq!(obj["mnemonic_delivery"], serde_json::json!("stderr"));
        assert_eq!(obj["schema_version"], serde_json::json!(crate::SCHEMA_VERSION));
        assert_eq!(obj["imported"], serde_json::json!(true));
        assert_eq!(obj["network"], serde_json::json!("signet"));
    }

    /// With `--show-mnemonic`, the caller has explicitly opted in: the stdout
    /// JSON DOES carry the `mnemonic`, and `mnemonic_delivery` flips to `stdout`.
    #[test]
    fn init_json_show_mnemonic_includes_mnemonic_on_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let v = init_json(
            dir.path(),
            Network::Signet,
            "https://mutinynet.com/api",
            KNOWN_MNEMONIC,
            false,
            true, // show_mnemonic = true (explicit opt-in)
        );
        let obj = v.as_object().expect("init_json must be a JSON object");
        assert_eq!(obj["mnemonic"], serde_json::json!(KNOWN_MNEMONIC));
        assert_eq!(obj["mnemonic_delivery"], serde_json::json!("stdout"));
        assert_eq!(obj["imported"], serde_json::json!(false));
    }
}
