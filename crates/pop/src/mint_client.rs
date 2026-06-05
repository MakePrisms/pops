//! Mint HTTP client — the PoP quote/mint/swap/keyset flows. The crypto goes
//! through the same `cdk_common` primitives the mint verifies against, so the
//! signed message cannot drift from the live mint's expected wire format.

use std::str::FromStr;
use std::time::Duration;

use cdk_common::amount::SplitTarget;
use cdk_common::dhke::construct_proofs;
use cdk_common::mint_url::MintUrl;
use cdk_common::nuts::{
    BlindSignature, BlindedMessage, CurrencyUnit, Id, KeySet, KeySetInfo, Keys, MintRequest,
    MintResponse, PreMintSecrets, Proof, Proofs, SwapRequest, SwapResponse, Token,
};
use cdk_common::{Amount as CdkAmount, SecretKey as CdkSecretKey};

use crate::error::PopError;
use crate::signer::Signer;

/// Wire body for `POST /v1/mint/pop`: a NUT-04 `MintRequest` (string quote id +
/// NUT-20 signature).
type PopMintRequest = MintRequest<String>;

/// PoP mint-quote response. A custom quote has NO `state` field on the wire —
/// the lifecycle is derived from `amount_paid` vs `amount_issued`. The PoP
/// reconstruction fields arrive flattened.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PopQuoteResponse {
    /// Quote id.
    pub quote: String,
    /// bech32m funding address.
    pub request: String,
    /// Echoed; the wallet drives off its own requested amount (kept for wire
    /// fidelity / debugging).
    #[allow(dead_code)]
    pub amount: Option<u64>,
    /// Amount credited from on-chain funding.
    #[serde(default)]
    pub amount_paid: u64,
    /// Amount already issued as ecash.
    #[serde(default)]
    pub amount_issued: u64,
    /// Echoed; the wallet uses its own resolved unit.
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

/// Creates a PoP mint quote. Sends the full compressed pubkey as the NUT-20 lock
/// (`pubkey`) and the x-only pubkey as `funder_pubkey` (the Bitcoin commitment
/// key) — both from the same secret.
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

/// Polls `GET /v1/mint/quote/pop/<id>` until credited (PAID), expired, or
/// `timeout`. `funding_address` + `network` only populate the `funding_pending`
/// error details (incl. a non-mainnet `faucet_hint`). Progress goes to STDERR.
///
/// # Errors
///
/// - [`PopError::QuoteExpired`] when the window closes before credit.
/// - [`PopError::FundingPending`] when `timeout` elapses uncredited (transient).
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
                expires_at: quote.expiry.unwrap_or(0), // 0 ⇒ unknown window
                confs_seen: None,
                confs_required: None,
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

/// Fetches `/v1/keysets`. The list resolves a token's SHORT keyset ids to FULL
/// ids (which [`Token::proofs`] requires) and supplies the active keyset's
/// `input_fee_ppk` for the swap fee math.
///
/// # Errors
///
/// Propagates HTTP and parse errors.
pub async fn fetch_keyset_infos(
    http: &reqwest::Client,
    base: &str,
) -> Result<Vec<KeySetInfo>, Box<dyn std::error::Error>> {
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
    Ok(list.keysets)
}

/// Selects the single ACTIVE [`KeySetInfo`] for `unit` from a fetched list.
///
/// # Errors
///
/// Errors if zero or multiple active keysets match the unit.
pub fn select_active_keyset<'a>(
    keysets: &'a [KeySetInfo],
    unit: &CurrencyUnit,
) -> Result<&'a KeySetInfo, Box<dyn std::error::Error>> {
    let mut matches = keysets.iter().filter(|k| k.active && &k.unit == unit);
    let chosen = matches
        .next()
        .ok_or_else(|| format!("no active keyset for unit `{unit}`"))?;
    if matches.next().is_some() {
        return Err(
            format!("multiple active keysets for unit `{unit}`; cannot disambiguate").into(),
        );
    }
    Ok(chosen)
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
    let keysets = fetch_keyset_infos(http, base).await?;
    Ok(select_active_keyset(&keysets, unit)?.id)
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

/// Best-effort DLEQ check on returned blind signatures: a MISSING proof is
/// tolerated, but a present-but-INVALID one aborts — it means the mint signed
/// with a key other than the one it advertised, so the unblinded ecash would be
/// worthless. Shared by [`mint_token`] and [`swap`].
pub(crate) fn verify_blind_signatures(
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

/// Mints the ecash for a PAID quote into a `cashuB` token. NUT-20 signing routes
/// through the funder [`Signer`] seam (custody stays behind the signer).
///
/// Returns BOTH the [`Token`] AND the raw [`Proofs`] it was built from, so the
/// caller can pre-serialize the proofs for value-recovery BEFORE stringifying
/// the token: the mint has ALREADY issued the ecash by the time this returns, so
/// a failing `cashuB` encode would leave the value surviving ONLY as these proofs.
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
) -> Result<(Token, Proofs), Box<dyn std::error::Error>> {
    let base = base.trim_end_matches('/');

    let keyset_id = active_keyset_for_unit(http, base, unit).await?;
    let keys = fetch_keys(http, base, &keyset_id).await?;

    // Blinded outputs (least-proofs power-of-2 split) for `amount`.
    let amount_cdk = CdkAmount::from(amount);
    let amounts: Vec<u64> = keys.keys().keys().map(|a| a.to_u64()).collect();
    let fee_and_amounts = (0u64, amounts).into();
    let premint_secrets =
        PreMintSecrets::random(keyset_id, amount_cdk, &SplitTarget::None, &fee_and_amounts)
            .map_err(|e| format!("failed to build premint secrets: {e}"))?;

    // NUT-20-sign (+ self-verify) through the signer seam.
    let mut request: PopMintRequest = MintRequest {
        quote: quote_id.to_string(),
        outputs: premint_secrets.blinded_messages(),
        signature: None,
    };
    signer
        .sign_mint_request(funder_index, &mut request)
        .map_err(|e| format!("NUT-20 sign failed: {e}"))?;

    let mint_url = format!("{base}/v1/mint/pop");
    let resp = http
        .post(&mint_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| {
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
    // Build from a CLONE so the raw proofs can be returned for value-recovery
    // (sets are tiny).
    let token = Token::new(mint_url_typed, proofs.clone(), None, unit.clone());
    Ok((token, proofs))
}

/// Performs a NUT-03 swap and unblinds into one proof set PER output bucket,
/// preserving order. The mint returns signatures in the SAME order as the
/// concatenated `output_buckets`, so this splits them back by length,
/// DLEQ-verifies each bucket, and unblinds each SEPARATELY (e.g.
/// `[send_proofs, change_proofs]`).
///
/// UNSIGNED NUT-03 (no NUT-20 funder signature — that is a NUT-04 issuance
/// concept), so it takes no signer and `pay` never loads the wallet seed.
///
/// A pure wire+crypto primitive: it does NOT enforce the exact-amount invariant
/// — the caller ([`crate::commands::pay`]) asserts the send-set sum.
///
/// # Errors
///
/// - [`PopError::MintUnreachable`] / [`PopError::MintError`] on the swap HTTP.
/// - an error on a wrong signature count, a failed DLEQ, or failed unblinding.
pub async fn swap(
    http: &reqwest::Client,
    base: &str,
    inputs: Proofs,
    output_buckets: &[PreMintSecrets],
    keys: &Keys,
) -> Result<Vec<Proofs>, Box<dyn std::error::Error>> {
    let base = base.trim_end_matches('/');

    // Concatenate every bucket's blinded messages, in order, into `outputs`.
    let outputs: Vec<BlindedMessage> = output_buckets
        .iter()
        .flat_map(|b| b.blinded_messages())
        .collect();
    let expected_sigs = outputs.len();

    let request = SwapRequest::new(inputs, outputs);

    let url = format!("{base}/v1/swap");
    let resp = http.post(&url).json(&request).send().await.map_err(|e| {
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
    let swap_response: SwapResponse = serde_json::from_str(&text)
        .map_err(|e| format!("swap response parse failed: {e}\nbody: {text}"))?;

    if swap_response.signatures.len() != expected_sigs {
        return Err(format!(
            "swap returned {} signatures, expected {expected_sigs} (one per blinded output)",
            swap_response.signatures.len()
        )
        .into());
    }

    // Split the signatures back per bucket (same order), DLEQ-verify, unblind.
    let mut sigs = swap_response.signatures.into_iter();
    let mut out: Vec<Proofs> = Vec::with_capacity(output_buckets.len());
    for bucket in output_buckets {
        let n = bucket.blinded_messages().len();
        let bucket_sigs: Vec<BlindSignature> = (&mut sigs).take(n).collect();
        verify_blind_signatures(&bucket_sigs, bucket, keys)?;
        let proofs = construct_proofs(bucket_sigs, bucket.rs(), bucket.secrets(), keys)
            .map_err(|e| format!("swap unblind (construct_proofs) failed: {e}"))?;
        out.push(proofs);
    }
    Ok(out)
}

/// Sums the sat value of a proof set (a PoP total is far below `u64::MAX`).
pub fn proofs_value(proofs: &[Proof]) -> u64 {
    proofs.iter().map(|p| p.amount.to_u64()).sum()
}

/// Stringifies a [`Token`] to `cashuB…` WITHOUT the `.to_string()` panic:
/// `Token`'s `Display` can return a CBOR `fmt::Error`, on which `to_string`
/// PANICS — which on an already-issued path would VAPORIZE bearer ecash. Writing
/// through [`std::fmt::Write`] surfaces it as an `Err` so the caller recovers the
/// proofs.
pub fn token_to_string(token: &Token) -> Result<String, String> {
    use std::fmt::Write as _;
    let mut s = String::new();
    write!(&mut s, "{token}").map_err(|_| "cashuB encoding (CBOR) failed".to_string())?;
    Ok(s)
}

/// Serializes a proof set to a JSON array (the wire `Proof` shape) for recovery
/// surfacing. A last-ditch value-recovery aid: falls back to a diagnostic
/// placeholder rather than ever erroring.
pub fn proofs_to_json(proofs: &Proofs) -> String {
    serde_json::to_string(proofs)
        .unwrap_or_else(|e| format!("<proofs unserializable: {e}; {} proof(s)>", proofs.len()))
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
