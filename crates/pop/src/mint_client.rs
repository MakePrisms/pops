//! Mint HTTP client — the PoP quote/mint/swap/keyset flows.
//!
//! Lifted verbatim (logic-for-logic) from `cdk-pop`'s `pop_test_tool` example
//! so the wallet drives the EXACT same proven wire format the live mint
//! expects: quote-create with the NUT-20 lock pubkey + x-only `funder_pubkey`,
//! poll-until-paid, active-keyset selection, NUT-20-signed blinded outputs,
//! unblind into proofs. The crypto goes through the same `cdk_common`
//! primitives the mint verifies against, so the signed message cannot drift.

use std::str::FromStr;
use std::time::Duration;

use cdk_common::amount::SplitTarget;
use cdk_common::dhke::construct_proofs;
use cdk_common::mint_url::MintUrl;
use cdk_common::nuts::{
    BlindSignature, CurrencyUnit, Id, KeySet, KeySetInfo, Keys, MintRequest, MintResponse,
    PreMintSecrets, Token,
};
use cdk_common::{Amount as CdkAmount, SecretKey as CdkSecretKey};

use crate::error::PopError;
use crate::signer::Signer;

/// Wire body for `POST /v1/mint/pop`: a NUT-04 `MintRequest` with a string
/// quote id and a NUT-20 signature.
type PopMintRequest = MintRequest<String>;

/// PoP mint-quote response (`POST`/`GET /v1/mint/quote/pop[/<id>]`).
///
/// A custom quote has no `state` field on the wire — the lifecycle is derived
/// from `amount_paid` vs `amount_issued`. The PoP reconstruction fields
/// (`nonce`/`internal_key`/`leaf_script`/`funder_pubkey`) arrive flattened.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PopQuoteResponse {
    /// Quote id.
    pub quote: String,
    /// bech32m funding address.
    pub request: String,
    /// Quoted amount (sats). Echoed by the mint; the wallet drives off its own
    /// requested amount, so this is kept for wire fidelity / debugging.
    #[allow(dead_code)]
    pub amount: Option<u64>,
    /// Amount the mint has credited from on-chain funding.
    #[serde(default)]
    pub amount_paid: u64,
    /// Amount already issued as ecash.
    #[serde(default)]
    pub amount_issued: u64,
    /// Unit (`pop_<ts>`). Echoed by the mint; the wallet uses its own resolved
    /// unit, so this is kept for wire fidelity / debugging.
    #[allow(dead_code)]
    pub unit: Option<String>,
    /// Quote expiry (unix seconds).
    pub expiry: Option<u64>,
    /// 32-byte mint-sampled nonce (hex).
    pub nonce: Option<String>,
    /// Taproot internal key (x-only hex).
    pub internal_key: Option<String>,
    /// Recovery leaf script (hex).
    pub leaf_script: Option<String>,
    /// Funder x-only pubkey echoed back (hex).
    pub funder_pubkey: Option<String>,
}

impl PopQuoteResponse {
    /// Credited but not yet issued (custom-quote `state == PAID`).
    pub fn is_paid(&self) -> bool {
        self.amount_paid > self.amount_issued
    }

    /// Fully issued for the paid amount.
    pub fn is_issued(&self) -> bool {
        self.amount_issued > 0 && self.amount_paid == self.amount_issued
    }
}

#[derive(Debug, serde::Deserialize)]
struct KeysetListResponse {
    keysets: Vec<KeySetInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct KeysResponseBody {
    keysets: Vec<KeySet>,
}

/// Creates a PoP mint quote. Sends the funder's full compressed pubkey as the
/// NUT-20 lock (`pubkey`) and the x-only pubkey as `funder_pubkey` (the
/// Bitcoin commitment key). Both derive from the same secret — EXACTLY the
/// wire format `pop_test_tool quote` uses.
///
/// # Errors
///
/// Propagates HTTP and parse errors; a non-2xx status is an error.
pub async fn create_quote(
    http: &reqwest::Client,
    base: &str,
    amount: u64,
    unit: &str,
    funder_secret: &CdkSecretKey,
) -> Result<PopQuoteResponse, Box<dyn std::error::Error>> {
    let full_pubkey = funder_secret.public_key();
    let xonly_hex = hex::encode(full_pubkey.x_only_public_key().serialize());
    let base = base.trim_end_matches('/');
    let url = format!("{base}/v1/mint/quote/pop");

    let body = serde_json::json!({
        "amount": amount,
        "unit": unit,
        "pubkey": full_pubkey.to_hex(),
        "funder_pubkey": xonly_hex,
    });

    let resp = http.post(&url).json(&body).send().await.map_err(|e| {
        eprintln!("POST {url} failed: {e}");
        PopError::MintUnreachable {
            mint_url: base.to_string(),
        }
    })?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PopError::MintError {
            status: Some(status.as_u16()),
            mint_message: text,
        }
        .into());
    }
    let quote: PopQuoteResponse = serde_json::from_str(&text)
        .map_err(|e| format!("quote response parse failed: {e}\nbody: {text}"))?;
    Ok(quote)
}

/// Fetches the current state of a quote (one GET, no polling).
///
/// # Errors
///
/// Propagates HTTP and parse errors.
pub async fn get_quote(
    http: &reqwest::Client,
    base: &str,
    quote_id: &str,
) -> Result<PopQuoteResponse, Box<dyn std::error::Error>> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/v1/mint/quote/pop/{quote_id}");
    let resp = http.get(&url).send().await.map_err(|e| {
        eprintln!("GET {url} failed: {e}");
        PopError::MintUnreachable {
            mint_url: base.to_string(),
        }
    })?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PopError::MintError {
            status: Some(status.as_u16()),
            mint_message: text,
        }
        .into());
    }
    let quote: PopQuoteResponse = serde_json::from_str(&text)
        .map_err(|e| format!("quote response parse failed: {e}\nbody: {text}"))?;
    Ok(quote)
}

/// Polls `GET /v1/mint/quote/pop/<id>` until credited (PAID), the quote
/// expires, or `timeout` elapses. Mirrors `pop_test_tool::poll_until_paid`.
///
/// `funding_address` is used only to populate the `funding_pending` error
/// details when the poll times out without crediting (still-pending is the
/// transient, keep-polling case). `network` selects the non-mainnet
/// `faucet_hint` carried in those same details (None on mainnet).
///
/// Progress is logged to STDERR (json mode keeps stdout pure).
///
/// # Errors
///
/// - [`PopError::QuoteExpired`] when the quote window closes before credit.
/// - [`PopError::FundingPending`] when `timeout` elapses with funding still
///   uncredited (transient — keep polling).
/// - [`PopError::MintError`] if the mint reports the quote already issued.
/// - mint HTTP errors propagate from [`get_quote`].
pub async fn poll_until_paid(
    http: &reqwest::Client,
    base: &str,
    quote_id: &str,
    funding_address: &str,
    network: bitcoin::Network,
    interval: Duration,
    timeout: Duration,
) -> Result<PopQuoteResponse, Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + timeout;
    let interval = interval.max(Duration::from_secs(1));

    loop {
        let quote = get_quote(http, base, quote_id).await?;

        if quote.is_issued() {
            return Err(PopError::MintError {
                status: None,
                mint_message: format!(
                    "quote {quote_id} is already ISSUED (amount_issued={}); \
                     credentials were already minted",
                    quote.amount_issued
                ),
            }
            .into());
        }
        if quote.is_paid() {
            return Ok(quote);
        }

        if let Some(expiry) = quote.expiry {
            let now = now_unix();
            if now >= expiry {
                return Err(PopError::QuoteExpired {
                    quote_id: quote_id.to_string(),
                    expired_at: expiry,
                }
                .into());
            }
        }

        if std::time::Instant::now() >= deadline {
            return Err(PopError::FundingPending {
                address: funding_address.to_string(),
                // Use the quote's own expiry when known; else 0 (unknown window).
                expires_at: quote.expiry.unwrap_or(0),
                confs_seen: None,
                confs_required: None,
                // Non-mainnet: tell the caller where to get test coins. Mainnet → None.
                faucet_hint: crate::network::faucet_hint(network).map(str::to_string),
            }
            .into());
        }

        eprintln!(
            "  quote {quote_id} not yet credited (amount_paid={}); retrying in {}s ...",
            quote.amount_paid,
            interval.as_secs()
        );
        tokio::time::sleep(interval).await;
    }
}

/// Fetches `/v1/keysets` and returns the single active keyset id for `unit`.
///
/// # Errors
///
/// Errors if zero or multiple active keysets match the unit.
pub async fn active_keyset_for_unit(
    http: &reqwest::Client,
    base: &str,
    unit: &CurrencyUnit,
) -> Result<Id, Box<dyn std::error::Error>> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/v1/keysets");
    let resp = http.get(&url).send().await.map_err(|e| {
        eprintln!("GET {url} failed: {e}");
        PopError::MintUnreachable {
            mint_url: base.to_string(),
        }
    })?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PopError::MintError {
            status: Some(status.as_u16()),
            mint_message: text,
        }
        .into());
    }
    let list: KeysetListResponse = serde_json::from_str(&text)
        .map_err(|e| format!("/v1/keysets parse failed: {e}\nbody: {text}"))?;

    let mut matches = list
        .keysets
        .into_iter()
        .filter(|k| k.active && &k.unit == unit);
    let chosen = matches
        .next()
        .ok_or_else(|| format!("no active keyset for unit `{unit}`"))?;
    if matches.next().is_some() {
        return Err(format!("multiple active keysets for unit `{unit}`; cannot disambiguate").into());
    }
    Ok(chosen.id)
}

/// Fetches `/v1/keys/<keyset_id>` and returns its amount -> pubkey map.
///
/// # Errors
///
/// Propagates HTTP and parse errors.
pub async fn fetch_keys(
    http: &reqwest::Client,
    base: &str,
    keyset_id: &Id,
) -> Result<Keys, Box<dyn std::error::Error>> {
    let base = base.trim_end_matches('/');
    let url = format!("{base}/v1/keys/{keyset_id}");
    let resp = http.get(&url).send().await.map_err(|e| {
        eprintln!("GET {url} failed: {e}");
        PopError::MintUnreachable {
            mint_url: base.to_string(),
        }
    })?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PopError::MintError {
            status: Some(status.as_u16()),
            mint_message: text,
        }
        .into());
    }
    let body: KeysResponseBody = serde_json::from_str(&text)
        .map_err(|e| format!("/v1/keys parse failed: {e}\nbody: {text}"))?;
    let keyset = body
        .keysets
        .into_iter()
        .find(|k| &k.id == keyset_id)
        .ok_or_else(|| format!("/v1/keys/{keyset_id} did not return keyset {keyset_id}"))?;
    Ok(keyset.keys)
}

/// Best-effort DLEQ check on returned blind signatures (missing proof
/// tolerated, present-but-invalid aborts). Mirrors `pop_test_tool`.
fn verify_blind_signatures(
    signatures: &[BlindSignature],
    premint_secrets: &PreMintSecrets,
    keys: &Keys,
) -> Result<(), Box<dyn std::error::Error>> {
    for (sig, premint) in signatures.iter().zip(premint_secrets.secrets.iter()) {
        let key = keys
            .amount_key(sig.amount)
            .ok_or_else(|| format!("keyset has no key for amount {}", sig.amount))?;
        match sig.verify_dleq(key, premint.blinded_message.blinded_secret) {
            Ok(()) | Err(cdk_common::nuts::nut12::Error::MissingDleqProof) => {}
            Err(e) => return Err(format!("DLEQ verification failed: {e}").into()),
        }
    }
    Ok(())
}

/// Mints the ecash for a PAID quote into a `cashuB` token. Selects the active
/// keyset, builds NUT-20-signed blinded outputs for the exact amount, posts
/// `POST /v1/mint/pop`, unblinds, and assembles the token. Mirrors
/// `pop_test_tool mint` steps 2-8.
///
/// NUT-20 signing is routed through the funder [`Signer`] seam (custody stays
/// behind the signer): the request is assembled here, then
/// [`Signer::sign_mint_request`] signs + self-verifies it in place for the
/// deposit at `funder_index`.
///
/// # Errors
///
/// Propagates HTTP, signing, and unblinding errors.
pub async fn mint_token(
    http: &reqwest::Client,
    base: &str,
    quote_id: &str,
    unit: &CurrencyUnit,
    amount: u64,
    signer: &dyn Signer,
    funder_index: u32,
) -> Result<Token, Box<dyn std::error::Error>> {
    let base = base.trim_end_matches('/');

    // Select the active keyset + fetch its amount->pubkey map.
    let keyset_id = active_keyset_for_unit(http, base, unit).await?;
    let keys = fetch_keys(http, base, &keyset_id).await?;

    // Build blinded outputs (least-proofs power-of-2 split) for `amount`.
    let amount_cdk = CdkAmount::from(amount);
    let amounts: Vec<u64> = keys.keys().keys().map(|a| a.to_u64()).collect();
    let fee_and_amounts = (0u64, amounts).into();
    let premint_secrets =
        PreMintSecrets::random(keyset_id, amount_cdk, &SplitTarget::None, &fee_and_amounts)
            .map_err(|e| format!("failed to build premint secrets: {e}"))?;

    // Assemble the request, then NUT-20-sign (+ self-verify) it through the
    // signer seam for this deposit's funder index.
    let mut request: PopMintRequest = MintRequest {
        quote: quote_id.to_string(),
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };
    signer
        .sign_mint_request(funder_index, &mut request)
        .map_err(|e| format!("NUT-20 sign failed: {e}"))?;

    // POST /v1/mint/pop.
    let mint_url = format!("{base}/v1/mint/pop");
    let resp = http.post(&mint_url).json(&request).send().await.map_err(|e| {
        eprintln!("POST {mint_url} failed: {e}");
        PopError::MintUnreachable {
            mint_url: base.to_string(),
        }
    })?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(PopError::MintError {
            status: Some(status.as_u16()),
            mint_message: text,
        }
        .into());
    }
    let mint_response: MintResponse = serde_json::from_str(&text)
        .map_err(|e| format!("mint response parse failed: {e}\nbody: {text}"))?;

    // Unblind into proofs, then assemble the cashuB token.
    verify_blind_signatures(&mint_response.signatures, &premint_secrets, &keys)?;
    let proofs = construct_proofs(
        mint_response.signatures,
        premint_secrets.rs(),
        premint_secrets.secrets(),
        &keys,
    )
    .map_err(|e| format!("unblind (construct_proofs) failed: {e}"))?;

    let mint_url_typed = MintUrl::from_str(base)
        .map_err(|e| format!("mint url `{base}` is not a valid MintUrl: {e}"))?;
    let token = Token::new(mint_url_typed, proofs, None, unit.clone());
    Ok(token)
}

/// Parse a 64-hex funder secret into a `cdk_common` secret key (NUT-20 key).
///
/// # Errors
///
/// Errors if the hex is not a valid secp256k1 scalar.
pub fn parse_cdk_secret(hex_str: &str) -> Result<CdkSecretKey, Box<dyn std::error::Error>> {
    CdkSecretKey::from_hex(hex_str.trim())
        .map_err(|e| format!("funder secret is not a valid secp256k1 secret key: {e}").into())
}

/// Current unix time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
