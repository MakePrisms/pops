//! Esplora chain I/O — UTXO lookup, tip MTP (for CLTV maturity), and
//! broadcast.
//!
//! Uses raw reqwest against the Esplora REST API, mirroring `pop_test_tool`'s
//! proven calls (`/tx/<txid>`, `/tx`) so the wire behavior is identical. Adds
//! address-history lookup (to discover the funding outpoint after funding) and
//! tip-MTP fetch (recovery maturity gates on median-time-past, not wall-clock,
//! per BIP-113).
//!
//! Error split: a transport failure reaching esplora on a **GET/read**
//! (tip-MTP, UTXO lookup, fee estimate) surfaces as the typed, transient
//! [`PopError::ChainUnreachable`] (the chain-read mirror of
//! [`PopError::MintUnreachable`]); the **POST/broadcast** path is
//! [`PopError::BroadcastFailed`] instead. A non-network esplora error (non-2xx
//! status, malformed body) is NOT "unreachable" — it stays a plain boxed error
//! that resolves to `internal_error`.

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

/// Esplora `/blocks/tip/height` returns a bare integer; `/block/<hash>` and
/// `/blocks/tip/hash` give us the path to MTP. We instead use
/// `/blocks/tip/height` then `/block-height/<h>` then `/block/<hash>` to get
/// `mediantime`. To keep it simple and robust we read the latest block summary
/// from `/blocks` (array of recent blocks) whose first element is the tip.
#[derive(Debug, Clone, serde::Deserialize)]
struct BlockSummary {
    mediantime: u64,
    height: u64,
}

/// The mempool-relay floor we never go below (BIP-141 min-relay is 1 sat/vB).
pub const MIN_RELAY_FEERATE_SAT_PER_VB: f64 = 1.0;

/// Conservative feerate (sat/vB) used when `/fee-estimates` cannot be fetched
/// or parsed. The spend is RBF-enabled, so a low-but-reasonable estimate is
/// safe — the funds are not at risk and the tx can be fee-bumped if it stalls.
pub const FALLBACK_FEERATE_SAT_PER_VB: f64 = 2.0;

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

    /// Maps a `reqwest` transport failure on a GET/read to the typed, transient
    /// [`PopError::ChainUnreachable`] (the chain-read mirror of
    /// [`PopError::MintUnreachable`]). `esplora_url` in `details` is the
    /// configured base; `operation` is the read that failed (`"tip_mtp"`,
    /// `"utxo_fetch"`, `"fee_estimate"`). The raw error goes to stderr so the
    /// human sees the cause while stdout stays the pure envelope. (Non-network
    /// failures — non-2xx, malformed bodies — are NOT routed here; they stay
    /// `internal_error`.)
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
    /// A transport failure reaching esplora is [`PopError::ChainUnreachable`]
    /// (transient, `operation = "utxo_fetch"`). A non-2xx or a parse failure is a
    /// plain boxed error (→ `internal_error`).
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
    /// A transport failure reaching esplora is [`PopError::ChainUnreachable`]
    /// (transient, `operation = "utxo_fetch"`). A non-2xx or a parse failure is a
    /// plain boxed error (→ `internal_error`).
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

    /// Returns the chain tip's `(median_time_past, height)`.
    ///
    /// CLTV maturity is evaluated against MTP per BIP-113. `/blocks` returns
    /// the most recent blocks (tip first), each carrying `mediantime`.
    ///
    /// # Errors
    ///
    /// A transport failure reaching esplora is [`PopError::ChainUnreachable`]
    /// (transient, `operation = "tip_mtp"`). A non-2xx, parse failure, or empty
    /// `/blocks` response is a plain boxed error (→ `internal_error`).
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

    /// Fetches the mempool fee estimates from `/fee-estimates`.
    ///
    /// Esplora returns a JSON object mapping a confirmation target (in blocks,
    /// as a string key) to the estimated feerate in sat/vB, e.g.
    /// `{"1":12.3,"6":4.1,"144":1.0}`. We parse it into a `target -> sat/vB`
    /// map; use [`pick_feerate`] to select a target.
    ///
    /// # Errors
    ///
    /// A transport failure reaching esplora is [`PopError::ChainUnreachable`]
    /// (transient, `operation = "fee_estimate"`). A non-2xx or a parse failure is
    /// a plain boxed error (→ `internal_error`). NOTE: `recover` treats ANY
    /// fee-estimate failure as non-fatal (it warns + falls back to a conservative
    /// feerate), so this typed error is informational there rather than aborting.
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
        // Keys are block-target strings, values are sat/vB floats.
        let raw: std::collections::HashMap<String, f64> = serde_json::from_str(&text)
            .map_err(|e| format!("esplora /fee-estimates parse failed: {e}\nbody: {text}"))?;
        let mut by_target = std::collections::BTreeMap::new();
        for (k, v) in raw {
            if let Ok(target) = k.parse::<u32>() {
                by_target.insert(target, v);
            }
        }
        if by_target.is_empty() {
            return Err(format!("esplora /fee-estimates: no usable targets\nbody: {text}").into());
        }
        Ok(FeeEstimates { by_target })
    }

    /// Broadcasts a raw transaction (hex). Returns the server response body
    /// (the txid on success).
    ///
    /// # Errors
    ///
    /// [`PopError::BroadcastFailed`] (transient) on a network failure reaching
    /// esplora or a non-2xx rejection (the node's message is the reject reason).
    /// The recovery spend is RBF-enabled and the funds stay safe in the UTXO, so
    /// a rejected broadcast is retriable.
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

/// Parsed `/fee-estimates`: confirmation-target-in-blocks -> feerate (sat/vB).
#[derive(Debug, Clone)]
pub struct FeeEstimates {
    /// Sorted (ascending target) estimate map.
    by_target: std::collections::BTreeMap<u32, f64>,
}

impl FeeEstimates {
    /// Picks the feerate (sat/vB) for `target` confirmation blocks.
    ///
    /// Esplora keys are sparse (commonly 1,2,3,4,5,6,...,144,504,1008). If the
    /// exact `target` is absent we fall to the nearest available *higher*
    /// target (a more-confident / higher feerate, never a slower one). If
    /// `target` is larger than every key (i.e. the user asked for a very slow
    /// confirmation the server doesn't quote), we use the largest available
    /// target (the slowest/cheapest quote on offer). The result is floored at
    /// the min-relay feerate so we never emit a sub-relay tx.
    pub fn pick_feerate(&self, target: u32) -> f64 {
        // First key whose target is >= the requested target (nearest higher).
        let chosen = self
            .by_target
            .range(target..)
            .next()
            .map(|(_, v)| *v)
            // None means target exceeds all keys: take the largest (slowest) key.
            .or_else(|| self.by_target.values().next_back().copied())
            .unwrap_or(MIN_RELAY_FEERATE_SAT_PER_VB);
        chosen.max(MIN_RELAY_FEERATE_SAT_PER_VB)
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
}
