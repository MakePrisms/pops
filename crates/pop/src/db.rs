//! `wallet.db` — the operational SQLite state store (standalone rusqlite, not
//! cdk-sqlite). Holds one row per deposit plus the monotonic derivation
//! counter. No tokens are stored (ecash is spat out as a cashuB token and not
//! managed by this wallet).

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

/// File name of the SQLite db inside the wallet dir.
pub const DB_FILE: &str = "wallet.db";

/// Deposit lifecycle state, persisted as a string in the `state` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositState {
    /// Quote created, address shown, no confirmed funding yet.
    Unpaid,
    /// Funding credited by the mint; credentials not yet issued.
    Paid,
    /// Credentials issued (token printed); BTC locked until `ts_expiry`.
    Minted,
    /// The script-path recovery spend was broadcast.
    Recovered,
    /// Funding deadline passed without crediting (terminal for issuance), but
    /// still recoverable if BTC was sent.
    Expired,
}

impl DepositState {
    /// Canonical lowercase name stored in the DB.
    pub fn as_str(self) -> &'static str {
        match self {
            DepositState::Unpaid => "unpaid",
            DepositState::Paid => "paid",
            DepositState::Minted => "minted",
            DepositState::Recovered => "recovered",
            DepositState::Expired => "expired",
        }
    }

    /// Parses a stored state string.
    pub fn parse(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(match s {
            "unpaid" => DepositState::Unpaid,
            "paid" => DepositState::Paid,
            "minted" => DepositState::Minted,
            "recovered" => DepositState::Recovered,
            "expired" => DepositState::Expired,
            other => return Err(format!("unknown deposit state `{other}` in db").into()),
        })
    }
}

/// A full deposit row.
#[derive(Debug, Clone)]
pub struct Deposit {
    /// Wallet-local deposit id (uuid).
    pub id: String,
    /// Optional human label.
    pub label: Option<String>,
    /// Mint base URL.
    pub mint_url: String,
    /// Credential unit, `pop_<ts_expiry>`.
    pub unit: String,
    /// CLTV expiry (unix seconds).
    pub ts_expiry: u64,
    /// Funded amount, sats.
    pub amount: u64,
    /// BIP-32 child index under the PoP path.
    pub funder_index: u32,
    /// Funder x-only pubkey (hex).
    pub funder_pubkey: String,
    /// NUT-20 quote-lock pubkey (compressed hex) — same key, other encoding.
    pub quote_lock_pubkey: String,
    /// Taproot internal key `P_internal` (x-only hex).
    pub p_internal: String,
    /// Recovery leaf script (hex).
    pub leaf_script: String,
    /// 32-byte mint-sampled nonce (hex).
    pub nonce: String,
    /// Mint identity key the address was verified against (compressed hex).
    pub mint_pubkey: String,
    /// bech32m funding address.
    pub funding_address: String,
    /// Mint quote id.
    pub quote_id: String,
    /// Lifecycle state.
    pub state: DepositState,
    /// Funding txid (hex), when seen on-chain.
    pub funding_txid: Option<String>,
    /// Funding vout, when seen on-chain.
    pub funding_vout: Option<u32>,
    /// Recovery txid (hex), when recovered.
    pub recovery_txid: Option<String>,
    /// Creation time, unix seconds.
    pub created_at: u64,
}

impl Deposit {
    /// Whether this deposit holds LOCKED BTC: funding was sent and it isn't yet
    /// recovered. The single source of truth shared by `balance` and `status`, so
    /// they can't drift. FUNDING-gated, not state-gated: `Paid`/`Minted` always
    /// carry funding, but `Expired` only holds BTC if funding was sent; `Unpaid`/
    /// `Recovered` never.
    pub fn is_locked(&self) -> bool {
        matches!(self.state, DepositState::Paid | DepositState::Minted)
            || (self.state == DepositState::Expired && self.funding_txid.is_some())
    }

    /// Whether this deposit can be swept NOW at chain-tip `mtp`: locked
    /// ([`Self::is_locked`]) AND matured (`mtp >= ts_expiry`, BIP-113).
    pub fn is_recoverable_now(&self, mtp: u64) -> bool {
        self.is_locked() && mtp >= self.ts_expiry
    }
}

/// The state store.
pub struct Db {
    conn: Connection,
}

impl Db {
    /// Path of the db inside `wallet_dir`.
    pub fn path_in(wallet_dir: &Path) -> PathBuf {
        wallet_dir.join(DB_FILE)
    }

    /// Opens (creating if needed) and migrates the db at `wallet_dir`.
    ///
    /// # Errors
    ///
    /// Propagates SQLite errors.
    pub fn open(wallet_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(Self::path_in(wallet_dir))
            .map_err(|e| format!("failed to open wallet.db: {e}"))?;
        // WAL + synchronous NORMAL = the standard durable combo; busy-timeout
        // makes concurrent invocations well-behaved.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| format!("failed to set WAL: {e}"))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| format!("failed to set synchronous: {e}"))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(|e| format!("failed to set busy timeout: {e}"))?;
        let db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Opens an in-memory db (tests).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        let db = Db { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.conn
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS deposits (
                    id                TEXT PRIMARY KEY,
                    label             TEXT,
                    mint_url          TEXT NOT NULL,
                    unit              TEXT NOT NULL,
                    ts_expiry         INTEGER NOT NULL,
                    amount            INTEGER NOT NULL,
                    funder_index      INTEGER NOT NULL,
                    funder_pubkey     TEXT NOT NULL,
                    quote_lock_pubkey TEXT NOT NULL,
                    p_internal        TEXT NOT NULL,
                    leaf_script       TEXT NOT NULL,
                    nonce             TEXT NOT NULL,
                    mint_pubkey       TEXT NOT NULL,
                    funding_address   TEXT NOT NULL,
                    quote_id          TEXT NOT NULL,
                    state             TEXT NOT NULL,
                    funding_txid      TEXT,
                    funding_vout      INTEGER,
                    recovery_txid     TEXT,
                    created_at        INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_deposits_state ON deposits(state);
                CREATE INDEX IF NOT EXISTS idx_deposits_address ON deposits(funding_address);

                -- Single-row table holding the next-unused derivation index.
                CREATE TABLE IF NOT EXISTS derivation_counter (
                    id        INTEGER PRIMARY KEY CHECK (id = 0),
                    next_index INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO derivation_counter (id, next_index) VALUES (0, 0);
                "#,
            )
            .map_err(|e| format!("db migration failed: {e}"))?;
        Ok(())
    }

    /// Atomically reserves and returns the next unused derivation index,
    /// advancing the counter. Never reuses an index.
    ///
    /// # Errors
    ///
    /// Propagates SQLite errors.
    pub fn next_derivation_index(&mut self) -> Result<u32, Box<dyn std::error::Error>> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| format!("failed to begin tx: {e}"))?;
        let current: i64 = tx
            .query_row(
                "SELECT next_index FROM derivation_counter WHERE id = 0",
                [],
                |r| r.get(0),
            )
            .map_err(|e| format!("failed to read derivation counter: {e}"))?;
        let index = u32::try_from(current)
            .map_err(|_| "derivation counter overflowed u32".to_string())?;
        tx.execute(
            "UPDATE derivation_counter SET next_index = ?1 WHERE id = 0",
            params![current + 1],
        )
        .map_err(|e| format!("failed to advance derivation counter: {e}"))?;
        tx.commit().map_err(|e| format!("failed to commit: {e}"))?;
        Ok(index)
    }

    /// Inserts a new deposit row.
    ///
    /// # Errors
    ///
    /// Propagates SQLite errors (including a duplicate id).
    pub fn insert_deposit(&self, d: &Deposit) -> Result<(), Box<dyn std::error::Error>> {
        self.conn
            .execute(
                r#"INSERT INTO deposits (
                    id, label, mint_url, unit, ts_expiry, amount, funder_index,
                    funder_pubkey, quote_lock_pubkey, p_internal, leaf_script, nonce,
                    mint_pubkey, funding_address, quote_id, state,
                    funding_txid, funding_vout, recovery_txid, created_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                    ?15, ?16, ?17, ?18, ?19, ?20
                )"#,
                params![
                    d.id,
                    d.label,
                    d.mint_url,
                    d.unit,
                    d.ts_expiry,
                    d.amount,
                    d.funder_index,
                    d.funder_pubkey,
                    d.quote_lock_pubkey,
                    d.p_internal,
                    d.leaf_script,
                    d.nonce,
                    d.mint_pubkey,
                    d.funding_address,
                    d.quote_id,
                    d.state.as_str(),
                    d.funding_txid,
                    d.funding_vout,
                    d.recovery_txid,
                    d.created_at,
                ],
            )
            .map_err(|e| format!("failed to insert deposit: {e}"))?;
        Ok(())
    }

    /// Sets a deposit's state.
    pub fn set_state(
        &self,
        id: &str,
        state: DepositState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.conn
            .execute(
                "UPDATE deposits SET state = ?1 WHERE id = ?2",
                params![state.as_str(), id],
            )
            .map_err(|e| format!("failed to set deposit state: {e}"))?;
        Ok(())
    }

    /// Records the funding outpoint (the state transition is the caller's job).
    pub fn set_funding_outpoint(
        &self,
        id: &str,
        txid: &str,
        vout: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.conn
            .execute(
                "UPDATE deposits SET funding_txid = ?1, funding_vout = ?2 WHERE id = ?3",
                params![txid, vout, id],
            )
            .map_err(|e| format!("failed to set funding outpoint: {e}"))?;
        Ok(())
    }

    /// Records the recovery txid.
    pub fn set_recovery_txid(
        &self,
        id: &str,
        txid: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.conn
            .execute(
                "UPDATE deposits SET recovery_txid = ?1 WHERE id = ?2",
                params![txid, id],
            )
            .map_err(|e| format!("failed to set recovery txid: {e}"))?;
        Ok(())
    }

    /// Fetches one deposit by id.
    pub fn get_deposit(&self, id: &str) -> Result<Option<Deposit>, Box<dyn std::error::Error>> {
        let dep = self
            .conn
            .query_row(
                &format!("SELECT {COLUMNS} FROM deposits WHERE id = ?1"),
                params![id],
                row_to_deposit,
            )
            .optional()
            .map_err(|e| format!("failed to query deposit: {e}"))?;
        match dep {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Lists all deposits, newest first.
    pub fn list_deposits(&self) -> Result<Vec<Deposit>, Box<dyn std::error::Error>> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM deposits ORDER BY created_at DESC"
            ))
            .map_err(|e| format!("failed to prepare list query: {e}"))?;
        let rows = stmt
            .query_map([], row_to_deposit)
            .map_err(|e| format!("failed to query deposits: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("row read failed: {e}"))??);
        }
        Ok(out)
    }

    /// Lists deposits in a given state.
    pub fn list_deposits_by_state(
        &self,
        state: DepositState,
    ) -> Result<Vec<Deposit>, Box<dyn std::error::Error>> {
        let mut stmt = self
            .conn
            .prepare(&format!(
                "SELECT {COLUMNS} FROM deposits WHERE state = ?1 ORDER BY created_at DESC"
            ))
            .map_err(|e| format!("failed to prepare list query: {e}"))?;
        let rows = stmt
            .query_map(params![state.as_str()], row_to_deposit)
            .map_err(|e| format!("failed to query deposits: {e}"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| format!("row read failed: {e}"))??);
        }
        Ok(out)
    }
}

/// The column list in canonical order (shared by every SELECT).
const COLUMNS: &str = "id, label, mint_url, unit, ts_expiry, amount, funder_index, \
    funder_pubkey, quote_lock_pubkey, p_internal, leaf_script, nonce, mint_pubkey, \
    funding_address, quote_id, state, funding_txid, funding_vout, recovery_txid, created_at";

/// Maps a SQLite row (in `COLUMNS` order) to a `Deposit`. The inner Result
/// surfaces a bad state string without panicking.
fn row_to_deposit(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<Deposit, Box<dyn std::error::Error>>> {
    let state_str: String = row.get(15)?;
    let ts_expiry: i64 = row.get(4)?;
    let amount: i64 = row.get(5)?;
    let funder_index: i64 = row.get(6)?;
    let funding_vout: Option<i64> = row.get(17)?;
    let created_at: i64 = row.get(19)?;

    let build = || -> Result<Deposit, Box<dyn std::error::Error>> {
        Ok(Deposit {
            id: row.get(0)?,
            label: row.get(1)?,
            mint_url: row.get(2)?,
            unit: row.get(3)?,
            ts_expiry: u64::try_from(ts_expiry).map_err(|_| "negative ts_expiry in db")?,
            amount: u64::try_from(amount).map_err(|_| "negative amount in db")?,
            funder_index: u32::try_from(funder_index)
                .map_err(|_| "funder_index out of range in db")?,
            funder_pubkey: row.get(7)?,
            quote_lock_pubkey: row.get(8)?,
            p_internal: row.get(9)?,
            leaf_script: row.get(10)?,
            nonce: row.get(11)?,
            mint_pubkey: row.get(12)?,
            funding_address: row.get(13)?,
            quote_id: row.get(14)?,
            state: DepositState::parse(&state_str)?,
            funding_txid: row.get(16)?,
            funding_vout: match funding_vout {
                Some(v) => Some(u32::try_from(v).map_err(|_| "funding_vout out of range")?),
                None => None,
            },
            recovery_txid: row.get(18)?,
            created_at: u64::try_from(created_at).map_err(|_| "negative created_at in db")?,
        })
    };
    Ok(build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, index: u32) -> Deposit {
        Deposit {
            id: id.to_string(),
            label: Some("l".to_string()),
            mint_url: "https://mint.example".to_string(),
            unit: "pop_1782259200".to_string(),
            ts_expiry: 1_782_259_200,
            amount: 10_000,
            funder_index: index,
            funder_pubkey: "aa".repeat(32),
            quote_lock_pubkey: "02".to_string() + &"bb".repeat(32),
            p_internal: "cc".repeat(32),
            leaf_script: "dd".repeat(20),
            nonce: "42".repeat(32),
            mint_pubkey: "02".to_string() + &"ee".repeat(32),
            funding_address: "tb1pexample".to_string(),
            quote_id: "quote-1".to_string(),
            state: DepositState::Unpaid,
            funding_txid: None,
            funding_vout: None,
            recovery_txid: None,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn derivation_counter_is_monotonic_and_unique() {
        let mut db = Db::open_in_memory().unwrap();
        assert_eq!(db.next_derivation_index().unwrap(), 0);
        assert_eq!(db.next_derivation_index().unwrap(), 1);
        assert_eq!(db.next_derivation_index().unwrap(), 2);
    }

    #[test]
    fn insert_get_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let d = sample("dep-1", 0);
        db.insert_deposit(&d).unwrap();
        let back = db.get_deposit("dep-1").unwrap().unwrap();
        assert_eq!(back.id, "dep-1");
        assert_eq!(back.amount, 10_000);
        assert_eq!(back.ts_expiry, 1_782_259_200);
        assert_eq!(back.state, DepositState::Unpaid);
        assert_eq!(back.nonce, "42".repeat(32));
    }

    #[test]
    fn state_and_outpoint_updates() {
        let db = Db::open_in_memory().unwrap();
        db.insert_deposit(&sample("dep-2", 1)).unwrap();
        db.set_funding_outpoint("dep-2", "ab".repeat(32).as_str(), 0)
            .unwrap();
        db.set_state("dep-2", DepositState::Paid).unwrap();
        db.set_state("dep-2", DepositState::Minted).unwrap();
        let back = db.get_deposit("dep-2").unwrap().unwrap();
        assert_eq!(back.state, DepositState::Minted);
        assert_eq!(back.funding_vout, Some(0));
        assert!(back.funding_txid.is_some());
    }

    #[test]
    fn list_by_state_filters() {
        let db = Db::open_in_memory().unwrap();
        db.insert_deposit(&sample("a", 0)).unwrap();
        let mut b = sample("b", 1);
        b.state = DepositState::Minted;
        db.insert_deposit(&b).unwrap();
        assert_eq!(db.list_deposits().unwrap().len(), 2);
        assert_eq!(db.list_deposits_by_state(DepositState::Minted).unwrap().len(), 1);
        assert_eq!(db.list_deposits_by_state(DepositState::Unpaid).unwrap().len(), 1);
    }

    #[test]
    fn missing_deposit_is_none() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.get_deposit("nope").unwrap().is_none());
    }

    /// `is_locked` is funding-gated: Paid/Minted always hold BTC, Expired only if
    /// funded, Unpaid/Recovered never (the shared `balance`/`status` definition).
    #[test]
    fn is_locked_is_funding_gated() {
        let mut d = sample("x", 0);

        d.state = DepositState::Paid;
        assert!(d.is_locked(), "paid holds locked BTC");
        d.state = DepositState::Minted;
        assert!(d.is_locked(), "minted holds locked BTC");

        d.state = DepositState::Unpaid;
        assert!(!d.is_locked(), "unpaid was never funded");
        d.state = DepositState::Recovered;
        assert!(!d.is_locked(), "recovered was swept back out");

        // Expired: locked IFF funding was actually sent.
        d.state = DepositState::Expired;
        d.funding_txid = None;
        assert!(!d.is_locked(), "unfunded-expired holds no BTC");
        d.funding_txid = Some("ab".repeat(32));
        assert!(d.is_locked(), "funded-expired still holds locked BTC");
    }

    /// `is_recoverable_now` = locked AND matured (inclusive boundary); an
    /// unfunded-expired deposit never recovers.
    #[test]
    fn is_recoverable_now_gates_on_lock_and_maturity() {
        let mut d = sample("y", 0); // ts_expiry = 1_782_259_200
        d.state = DepositState::Minted;

        assert!(!d.is_recoverable_now(d.ts_expiry - 1), "immature: mtp < ts_expiry");
        assert!(d.is_recoverable_now(d.ts_expiry), "boundary is inclusive");
        assert!(d.is_recoverable_now(d.ts_expiry + 1), "matured: mtp > ts_expiry");

        // Unfunded-expired never recovers, even far past maturity.
        d.state = DepositState::Expired;
        d.funding_txid = None;
        assert!(!d.is_recoverable_now(d.ts_expiry + 10_000), "unfunded holds nothing to sweep");
        d.funding_txid = Some("cd".repeat(32));
        assert!(d.is_recoverable_now(d.ts_expiry + 10_000), "funded-expired recovers once matured");
    }
}
