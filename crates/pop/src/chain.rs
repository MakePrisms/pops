//! Esplora chain I/O — UTXO lookup, tip MTP (CLTV maturity gates on
//! median-time-past per BIP-113), fee estimates, and broadcast.
//!
//! Error split: a transport failure on a GET/read → the transient
//! [`PopError::ChainUnreachable`] (the chain-read mirror of
//! [`PopError::MintUnreachable`]); the POST/broadcast path →
//! [`PopError::BroadcastFailed`]. A non-network esplora error (non-2xx,
//! malformed body) is NOT "unreachable" — it stays a plain boxed
//! `internal_error`.

use bitcoin::ScriptBuf;

use crate::error::PopError;

/// One output of a transaction, as Esplora returns it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Vout {
    /// Output value in sats.
    pub value: u64,
    /// scriptPubKey, hex.
    pub scriptpubkey: String,
}

/// Esplora `/tx/<txid>` (the subset we use).
#[derive(Debug, Clone, serde::Deserialize)]
struct TxResponse {
    vout: Vec<Vout>,
}

/// One UTXO from `/address/<addr>/utxo`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AddressUtxo {
    /// Funding txid (hex).
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Value in sats.
    pub value: u64,
    /// Confirmation status.
    pub status: UtxoStatus,
}

/// Confirmation status of a UTXO.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct UtxoStatus {
    /// Whether the funding tx is confirmed.
    pub confirmed: bool,
}

/// A recent-block summary from `/blocks` (tip first); carries `mediantime` for
/// the MTP-based CLTV gate.
#[derive(Debug, Clone, serde::Deserialize)]
struct BlockSummary {
    mediantime: u64,
    height: u64,
}

/// The mempool-relay floor we never go below. 1 sat/vB is Bitcoin Core's
/// historical min-relay *policy* default (not consensus, not a BIP). Core 29.1
/// (2025) lowered the default to 0.1 sat/vB; we keep 1 so the tx still relays
/// on the majority of nodes that have not yet adopted the lower floor.
pub const MIN_RELAY_FEERATE_SAT_PER_VB: f64 = 1.0;

/// Conservative feerate (sat/vB) used when `/fee-estimates` cannot be fetched
/// or parsed. The spend is RBF-enabled, so a low-but-reasonable estimate is
/// safe — the funds are not at risk and the tx can be fee-bumped if it stalls.
pub const FALLBACK_FEERATE_SAT_PER_VB: f64 = 2.0;

/// Hard ceiling on an AUTO-ESTIMATED feerate (sat/vB). The `/fee-estimates`
/// endpoint is a fully-trusted third party; a hostile or misconfigured one can
/// return an absurd rate, and the recovery spend auto-broadcasts. Capping the
/// mempool-derived feerate bounds the worst-case miner fee on that un-prompted
/// broadcast. 1000 sat/vB is far above any real mempool peak, so it never blocks
/// a legitimate estimate; a funder who genuinely needs more passes an explicit
/// `--fee <sats>` (the `Absolute` policy), which never flows through here.
pub const MAX_SANE_FEERATE_SAT_PER_VB: f64 = 1_000.0;

/// An esplora client bound to a base URL.
pub struct Esplora {
    base: String,
    http: reqwest::Client,
}

impl Esplora {
    /// Builds a client for `base` (trailing slash trimmed).
    pub fn new(base: &str) -> Self {
        Esplora {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Maps a GET/read transport failure to the transient
    /// [`PopError::ChainUnreachable`] (`operation` ∈ `tip_mtp`/`utxo_fetch`/
    /// `fee_estimate`). The raw error goes to stderr (stdout stays pure
    /// envelope). Non-network failures are NOT routed here.
    fn unreachable(
        &self,
        operation: &str,
        url: &str,
        err: &reqwest::Error,
    ) -> Box<dyn std::error::Error> {
        eprintln!("esplora GET {url} failed: {err}");
        PopError::ChainUnreachable {
            esplora_url: self.base.clone(),
            operation: Some(operation.to_string()),
        }
        .into()
    }

    /// Fetches a transaction's outputs.
    ///
    /// # Errors
    ///
    /// Transport failure → [`PopError::ChainUnreachable`] (`utxo_fetch`); a
    /// non-2xx / parse failure → `internal_error` (see the module split).
    pub async fn tx_vouts(&self, txid: &str) -> Result<Vec<Vout>, Box<dyn std::error::Error>> {
        let url = format!("{}/tx/{txid}", self.base);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| self.unreachable("utxo_fetch", &url, &e))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("esplora GET {url} returned {status}: {text}").into());
        }
        let parsed: TxResponse = serde_json::from_str(&text)
            .map_err(|e| format!("esplora tx parse failed: {e}\nbody: {text}"))?;
        Ok(parsed.vout)
    }

    /// Returns a specific output's `(value, scriptPubKey)`.
    ///
    /// # Errors
    ///
    /// Errors if the output index is out of range or hex decode fails.
    pub async fn utxo_value_and_script(
        &self,
        txid: &str,
        vout: u32,
    ) -> Result<(u64, ScriptBuf), Box<dyn std::error::Error>> {
        let vouts = self.tx_vouts(txid).await?;
        let idx = usize::try_from(vout).map_err(|_| "vout does not fit usize")?;
        let v = vouts
            .get(idx)
            .ok_or_else(|| format!("funding tx has no vout[{vout}]"))?;
        let bytes = hex::decode(&v.scriptpubkey)
            .map_err(|e| format!("esplora scriptpubkey hex decode failed: {e}"))?;
        Ok((v.value, ScriptBuf::from_bytes(bytes)))
    }

    /// Lists the UTXOs currently at an address.
    ///
    /// # Errors
    ///
    /// Transport failure → [`PopError::ChainUnreachable`] (`utxo_fetch`); a
    /// non-2xx / parse failure → `internal_error` (see the module split).
    pub async fn address_utxos(
        &self,
        address: &str,
    ) -> Result<Vec<AddressUtxo>, Box<dyn std::error::Error>> {
        let url = format!("{}/address/{address}/utxo", self.base);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| self.unreachable("utxo_fetch", &url, &e))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("esplora GET {url} returned {status}: {text}").into());
        }
        let parsed: Vec<AddressUtxo> = serde_json::from_str(&text)
            .map_err(|e| format!("esplora utxo parse failed: {e}\nbody: {text}"))?;
        Ok(parsed)
    }

    /// The chain tip's `(median_time_past, height)`. `/blocks` returns recent
    /// blocks (tip first), each carrying `mediantime`.
    ///
    /// # Errors
    ///
    /// Transport failure → [`PopError::ChainUnreachable`] (`tip_mtp`); a non-2xx /
    /// parse failure / empty `/blocks` → `internal_error`.
    pub async fn tip_mtp_and_height(&self) -> Result<(u64, u64), Box<dyn std::error::Error>> {
        let url = format!("{}/blocks", self.base);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| self.unreachable("tip_mtp", &url, &e))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("esplora GET {url} returned {status}: {text}").into());
        }
        let blocks: Vec<BlockSummary> = serde_json::from_str(&text)
            .map_err(|e| format!("esplora /blocks parse failed: {e}\nbody: {text}"))?;
        let tip = blocks
            .first()
            .ok_or("esplora /blocks returned no blocks")?;
        Ok((tip.mediantime, tip.height))
    }

    /// Fetches `/fee-estimates` (a `{ target-blocks-string: sat/vB }` object,
    /// e.g. `{"1":12.3,"6":4.1}`) into a `target -> sat/vB` map; select via
    /// `pick_feerate`.
    ///
    /// # Errors
    ///
    /// Transport failure → [`PopError::ChainUnreachable`] (`fee_estimate`); a
    /// non-2xx / parse failure → `internal_error`. NOTE: `recover` treats ANY
    /// fee-estimate failure as non-fatal (warns + uses a fallback feerate).
    pub async fn fee_estimates(&self) -> Result<FeeEstimates, Box<dyn std::error::Error>> {
        let url = format!("{}/fee-estimates", self.base);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| self.unreachable("fee_estimate", &url, &e))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(format!("esplora GET {url} returned {status}: {text}").into());
        }
        parse_fee_estimates(&text)
    }

    /// Broadcasts a raw transaction (hex); returns the body (txid on success).
    ///
    /// # Errors
    ///
    /// [`PopError::BroadcastFailed`] on a network failure or non-2xx rejection.
    /// Retriable: the recovery spend is RBF-enabled and the funds stay safe in
    /// the UTXO.
    pub async fn broadcast(&self, tx_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/tx", self.base);
        let resp = self
            .http
            .post(&url)
            .body(tx_hex.to_string())
            .send()
            .await
            .map_err(|e| {
                eprintln!("esplora POST {url} failed: {e}");
                PopError::BroadcastFailed {
                    reject_reason: Some(format!("could not reach esplora at {url}: {e}")),
                    txid: None,
                }
            })?;
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(PopError::BroadcastFailed {
                reject_reason: Some(body.trim().to_string()),
                txid: None,
            }
            .into());
        }
        Ok(body.trim().to_string())
    }
}

/// Parse a `/fee-estimates` JSON body (`{ "<target>": <sat/vB>, … }`) into
/// [`FeeEstimates`], keeping only the numeric `target -> feerate` entries.
/// Tolerates non-numeric metadata fields: mempool.space appends a `"warning"`
/// string while deprecating this endpoint, and a strict `HashMap<String, f64>`
/// would reject the whole body on that field — forcing the conservative fee
/// fallback even though the estimates themselves are present.
fn parse_fee_estimates(text: &str) -> Result<FeeEstimates, Box<dyn std::error::Error>> {
    let raw: std::collections::HashMap<String, serde_json::Value> = serde_json::from_str(text)
        .map_err(|e| format!("esplora /fee-estimates parse failed: {e}\nbody: {text}"))?;
    let mut by_target = std::collections::BTreeMap::new();
    for (k, v) in raw {
        if let (Ok(target), Some(feerate)) = (k.parse::<u32>(), v.as_f64()) {
            by_target.insert(target, feerate);
        }
    }
    if by_target.is_empty() {
        return Err(format!("esplora /fee-estimates: no usable targets\nbody: {text}").into());
    }
    Ok(FeeEstimates { by_target })
}

/// Parsed `/fee-estimates`: confirmation-target-in-blocks -> feerate (sat/vB).
#[derive(Debug, Clone)]
pub struct FeeEstimates {
    /// Sorted (ascending target) estimate map.
    by_target: std::collections::BTreeMap<u32, f64>,
}

impl FeeEstimates {
    /// Picks the feerate (sat/vB) for `target` confirmation blocks. Esplora keys
    /// are sparse, so an absent `target` falls to the nearest HIGHER key (never a
    /// slower one); a `target` above every key uses the largest (slowest) key.
    /// Clamped to `[MIN_RELAY, MAX_SANE]`: the floor keeps the tx relayable, the
    /// ceiling bounds a hostile/misconfigured endpoint (also coerces a negative
    /// rate up to min-relay).
    pub fn pick_feerate(&self, target: u32) -> f64 {
        // First key >= target (nearest higher).
        let chosen = self
            .by_target
            .range(target..)
            .next()
            .map(|(_, v)| *v)
            // None ⇒ target exceeds all keys: take the largest (slowest).
            .or_else(|| self.by_target.values().next_back().copied())
            .unwrap_or(MIN_RELAY_FEERATE_SAT_PER_VB);
        chosen.clamp(MIN_RELAY_FEERATE_SAT_PER_VB, MAX_SANE_FEERATE_SAT_PER_VB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn estimates(pairs: &[(u32, f64)]) -> FeeEstimates {
        FeeEstimates {
            by_target: pairs.iter().copied().collect(),
        }
    }

    #[test]
    fn parse_fee_estimates_keeps_numeric_targets() {
        let fe = parse_fee_estimates(r#"{"1":12.3,"6":4.1,"144":1.0}"#)
            .expect("plain estimates parse");
        assert_eq!(fe.pick_feerate(1), 12.3);
        assert_eq!(fe.pick_feerate(6), 4.1);
    }

    #[test]
    fn parse_fee_estimates_tolerates_warning_field() {
        // mempool.space appends a `"warning"` string when deprecating the
        // endpoint; the numeric targets MUST still parse (regression: a strict
        // map rejected the whole body → silent fee fallback to the default).
        let body = r#"{"1":3.148,"6":2.131,"144":0.737,"warning":"This endpoint is deprecated and will be removed in a future release. Please use /api/v1/fees/recommended"}"#;
        let fe = parse_fee_estimates(body).expect("warning field must not break the parse");
        assert_eq!(fe.pick_feerate(1), 3.148);
        assert_eq!(fe.pick_feerate(6), 2.131);
    }

    #[test]
    fn parse_fee_estimates_errors_when_no_numeric_targets() {
        let err = parse_fee_estimates(r#"{"warning":"deprecated"}"#)
            .expect_err("no usable targets must error");
        assert!(err.to_string().contains("no usable targets"), "got: {err}");
    }

    #[test]
    fn pick_feerate_exact_target_hits() {
        let fe = estimates(&[(1, 12.3), (6, 4.1), (144, 1.0)]);
        assert_eq!(fe.pick_feerate(6), 4.1);
        assert_eq!(fe.pick_feerate(1), 12.3);
    }

    #[test]
    fn pick_feerate_falls_to_nearest_higher_target() {
        // No "6" key: target 6 should pick the next-higher available key (10).
        let fe = estimates(&[(1, 20.0), (3, 12.0), (10, 5.0), (144, 1.5)]);
        assert_eq!(fe.pick_feerate(6), 5.0);
    }

    #[test]
    fn pick_feerate_above_all_keys_uses_largest_target() {
        let fe = estimates(&[(1, 20.0), (6, 5.0), (144, 1.5)]);
        // target 1008 exceeds every key -> the slowest (largest-target) quote.
        assert_eq!(fe.pick_feerate(1008), 1.5);
    }

    #[test]
    fn pick_feerate_floors_at_min_relay() {
        // A server quoting below 1 sat/vB must still be floored to min-relay.
        let fe = estimates(&[(144, 0.5), (1008, 0.1)]);
        assert_eq!(fe.pick_feerate(144), MIN_RELAY_FEERATE_SAT_PER_VB);
        assert_eq!(fe.pick_feerate(1008), MIN_RELAY_FEERATE_SAT_PER_VB);
    }

    #[test]
    fn pick_feerate_caps_a_hostile_estimate() {
        // A hostile/misconfigured endpoint quoting an absurd rate is capped at
        // MAX_SANE so the auto-broadcast can't burn the UTXO to miner fee.
        let fe = estimates(&[(1, 9_999_999.0), (6, 50_000.0)]);
        assert_eq!(fe.pick_feerate(6), MAX_SANE_FEERATE_SAT_PER_VB);
        assert_eq!(fe.pick_feerate(1), MAX_SANE_FEERATE_SAT_PER_VB);
        // A negative quote is coerced up to the floor (clamp lower bound).
        let neg = estimates(&[(6, -5.0)]);
        assert_eq!(neg.pick_feerate(6), MIN_RELAY_FEERATE_SAT_PER_VB);
    }
}
