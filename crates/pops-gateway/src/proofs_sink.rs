//! Durable persistence of redeemed bearer proofs.
//!
//! On every successful charge the gateway appends ONE JSONL line to
//! `proofs_sink` and `flush()` + `sync_all()`s it to disk BEFORE forwarding the
//! request upstream (spec refinement #2: a crash between forward and persist
//! would lose already-consumed proofs = lost operator value). The file is a
//! WALLET — each `fresh_proofs` value is a spendable `cashuB…` bearer token.
//!
//! Serialization is hand-rolled (not `serde_json::to_writer` over a struct)
//! only to keep the record shape pinned + obvious; the line is valid JSON.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use pops_core_types::RedeemedProofs;

/// One persisted settlement record. Mirrors the spec's required shape:
/// `{received_at, token_hash, amount, unit, active_keyset_id, fresh_proofs}`.
///
/// `received_at` is Unix seconds at persist time. `fresh_proofs` is the
/// spendable bearer token (the operator's money); `token_hash` is the SHA-256
/// receipt reference of the PRESENTED token (safe to share, exposes no secret).
#[derive(Debug, serde::Serialize)]
pub struct ProofsRecord<'a> {
    /// Unix-seconds timestamp when the proofs were persisted.
    pub received_at: u64,
    /// SHA-256 (lowercase hex) of the presented credential — the receipt ref.
    pub token_hash: &'a str,
    /// Net value received (the requested `amount`).
    pub amount: u64,
    /// Unit of the redeemed value (`pop_<ts>`).
    pub unit: &'a str,
    /// Keyset id the fresh proofs are signed under.
    pub active_keyset_id: &'a str,
    /// The fresh bearer proofs as a `cashuB…` token string. SPENDABLE VALUE.
    pub fresh_proofs: &'a str,
}

/// Append-only, fsync-on-every-write durable sink for redeemed proofs.
///
/// Holds the open file under a [`Mutex`] so concurrent gated requests serialize
/// their appends (each line atomic; no interleaving). `append(true)` means the
/// OS positions every write at EOF, so even multi-process operators do not
/// clobber, though a single gateway process is the v1 shape.
#[derive(Debug)]
pub struct ProofsSink {
    file: Mutex<File>,
}

/// A failure to durably persist redeemed proofs. The caller treats this as
/// fatal-for-this-request (must NOT forward) and emits the lost `fresh_proofs`
/// + `token_hash` to stderr as a last resort (spec step 3).
#[derive(Debug)]
pub struct PersistError {
    /// What went wrong (open / write / flush / fsync).
    pub message: String,
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to persist redeemed proofs: {}", self.message)
    }
}

impl std::error::Error for PersistError {}

impl ProofsSink {
    /// Open (creating if absent) `path` for append. The parent dir is assumed
    /// validated already (see `config::validate_proofs_sink`).
    pub fn open(path: &Path) -> Result<Self, PersistError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| PersistError {
                message: format!("open {path:?} for append: {e}"),
            })?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Durably append one record built from `redeemed`, then `flush` +
    /// `sync_all` so the value is on stable storage before the caller forwards.
    ///
    /// Returns `Ok(())` only once the bytes are fsynced. Any failure leaves the
    /// caller responsible for the last-resort stderr emission.
    pub fn persist(&self, redeemed: &RedeemedProofs) -> Result<(), PersistError> {
        let received_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let record = ProofsRecord {
            received_at,
            token_hash: &redeemed.token_hash,
            amount: redeemed.amount,
            unit: &redeemed.unit,
            active_keyset_id: &redeemed.active_keyset_id,
            fresh_proofs: &redeemed.fresh_proofs,
        };

        let mut line = serde_json::to_string(&record).map_err(|e| PersistError {
            message: format!("serialize record: {e}"),
        })?;
        line.push('\n');

        // One lock spans write→flush→fsync so a record is fully durable before
        // another request's append begins.
        let mut guard = self.file.lock().map_err(|_| PersistError {
            message: "proofs_sink mutex poisoned".to_string(),
        })?;
        guard.write_all(line.as_bytes()).map_err(|e| PersistError {
            message: format!("write record: {e}"),
        })?;
        guard.flush().map_err(|e| PersistError {
            message: format!("flush record: {e}"),
        })?;
        guard.sync_all().map_err(|e| PersistError {
            message: format!("fsync record: {e}"),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn sample_redeemed() -> RedeemedProofs {
        RedeemedProofs {
            fresh_proofs: "cashuBdeadbeef".to_string(),
            amount: 7,
            unit: "pop_1782668279".to_string(),
            active_keyset_id: "0114c426".to_string(),
            token_hash: "a".repeat(64),
        }
    }

    #[test]
    fn persist_appends_one_jsonl_line_with_required_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("proofs.jsonl");
        let sink = ProofsSink::open(&path).expect("open");

        sink.persist(&sample_redeemed()).expect("persist");

        let mut contents = String::new();
        File::open(&path)
            .expect("reopen")
            .read_to_string(&mut contents)
            .expect("read");

        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 1, "exactly one record line");

        let v: serde_json::Value = serde_json::from_str(lines[0]).expect("valid JSON line");
        assert!(v["received_at"].is_number());
        assert_eq!(v["token_hash"], "a".repeat(64));
        assert_eq!(v["amount"], 7);
        assert_eq!(v["unit"], "pop_1782668279");
        assert_eq!(v["active_keyset_id"], "0114c426");
        assert_eq!(v["fresh_proofs"], "cashuBdeadbeef");
    }

    #[test]
    fn persist_appends_not_truncates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("proofs.jsonl");
        let sink = ProofsSink::open(&path).expect("open");

        sink.persist(&sample_redeemed()).expect("persist 1");
        sink.persist(&sample_redeemed()).expect("persist 2");

        let mut contents = String::new();
        File::open(&path)
            .expect("reopen")
            .read_to_string(&mut contents)
            .expect("read");
        assert_eq!(contents.lines().count(), 2, "appends accumulate");
    }

    #[test]
    fn open_fails_on_nonexistent_parent() {
        let err = ProofsSink::open(Path::new("/no/such/dir/x/proofs.jsonl"))
            .expect_err("must fail on missing parent");
        assert!(err.to_string().contains("open"));
    }
}
