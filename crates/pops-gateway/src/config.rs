//! Gateway configuration: the ONE declarative TOML an operator mounts.
//!
//! Five facts are REQUIRED (any missing → fail-fast structured error + nonzero
//! exit, never a panic): `upstream_url`, `mint_url`, `[charge].unit`,
//! `[charge].amount`, `proofs_sink`. `proofs_sink` has NO default on purpose: a
//! silent default would, on a restart of an unmounted container, LOSE received
//! bearer value — so the operator is forced to land a conscious path.
//!
//! Parsing ([`Config::from_toml_str`]) is pure serde; [`Config::validate`]
//! produces a field-named [`ConfigError`] (`config field <X>: <reason>`).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cashu::nuts::CurrencyUnit;
use cashu::{Amount, MintUrl};
use serde::Deserialize;

use pops_core_verify::challenge::CashuRequirement;

/// The default listen address when `listen` is omitted.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";

/// Default cap on a buffered request body (1 MiB). The gateway buffers each body
/// in full before forwarding, so without a cap an attacker on a PUBLIC path
/// could stream an unbounded body and OOM the process. Over this → `413`.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Default upstream request timeout (30s). Bounds a hung upstream so a request
/// whose pop was already redeemed isn't stranded, and makes the `504` reachable.
pub const DEFAULT_UPSTREAM_TIMEOUT_SECS: u64 = 30;

/// Default cap on proofs per credential. An exact-amount token needs only a
/// handful (power-of-two split), so 64 is generous headroom while bounding a
/// swap-DoS by a token stuffed with tiny proofs. Over → a pre-swap 402.
pub const DEFAULT_MAX_PROOFS: usize = 64;

/// Top-level gateway config from the mounted TOML. Required fields are plain (no
/// `Option`) so a missing key is a serde error before semantic validation;
/// `proofs_sink` is deliberately required with no default.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The operator's existing API; every gated request is forwarded here on a
    /// successful charge.
    pub upstream_url: String,

    /// The pops mint the credential is redeemed against (NUT-03 swap); also the
    /// `/readyz` probe target.
    pub mint_url: String,

    /// Where redeemed bearer proofs are persisted. REQUIRED, NO default — this
    /// path is a WALLET holding received value.
    pub proofs_sink: PathBuf,

    /// Listen address for the gateway's own HTTP listener.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Max buffered request-body size; over → `413` (before any charge). Caps an
    /// unbounded-body OOM on public paths.
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,

    /// Upstream request timeout (s). `0` disables it (NOT recommended — a hung
    /// upstream then strands a request whose pop is already spent).
    #[serde(default = "default_upstream_timeout_secs")]
    pub upstream_timeout_secs: u64,

    /// The charge advertised on the 402 + enforced on retry.
    pub charge: ChargeConfig,

    /// Per-path gating rules. Absent ⇒ gate EVERY path; otherwise `public = true`
    /// paths forward without gating.
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

/// The `[charge]` table: what a holder must present per request.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChargeConfig {
    /// Currency unit the credential must carry — `pop_<unix_ts>`.
    pub unit: String,

    /// Exact net value required per request (must be > 0).
    pub amount: u64,

    /// Mints the verifier accepts. Defaults to `[mint_url]` when omitted.
    #[serde(default)]
    pub mints: Vec<String>,

    /// Optional human-readable description shown in the challenge.
    #[serde(default)]
    pub description: Option<String>,

    /// Max proofs per credential — a pre-swap DoS guard; over → a 402 BEFORE any
    /// swap. Must be > 0 when set.
    #[serde(default = "default_max_proofs")]
    pub max_proofs: usize,
}

/// A single `[[routes]]` rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Glob (`*`/`?`) matched against the request path; `*` matches across `/`
    /// too (a simple suffix/prefix glob).
    pub path: String,
    /// `true` ⇒ public (forwarded WITHOUT gating). Defaults to gated.
    #[serde(default)]
    pub public: bool,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

fn default_upstream_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_TIMEOUT_SECS
}

fn default_max_proofs() -> usize {
    DEFAULT_MAX_PROOFS
}

/// A semantic config failure, naming the field and the human reason. Rendered
/// by `main` as `config field <field>: <reason>` to stderr before a nonzero
/// exit (never a panic / stacktrace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The offending config field (e.g. `charge.amount`, `proofs_sink`).
    pub field: String,
    /// Why it was rejected.
    pub reason: String,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "config field {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for ConfigError {}

impl ConfigError {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

/// The validated, ready-to-serve form of [`Config`]: raw strings parsed into
/// typed forms and the `CashuRequirement` pre-built. Produced by
/// [`Config::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// Parsed upstream base URL (the proxy target).
    pub upstream_url: reqwest::Url,
    /// Parsed mint URL (swap + readiness probe target).
    pub mint_url: MintUrl,
    /// The persistent sink for redeemed proofs.
    pub proofs_sink: PathBuf,
    /// Listen address.
    pub listen: String,
    /// Max buffered request-body size (over → `413`).
    pub max_body_bytes: usize,
    /// Upstream request timeout (`None` ⇒ no timeout, from `0`).
    pub upstream_timeout: Option<std::time::Duration>,
    /// The cashu requirement advertised on the 402 + enforced on retry.
    pub requirement: CashuRequirement,
    /// Per-token max proof count (pre-swap DoS guard; over → 402).
    pub max_proofs: usize,
    /// Per-path gating rules (empty ⇒ gate all).
    pub routes: Vec<RouteConfig>,
}

impl Config {
    /// Parse a config from a TOML string (pure serde; structural errors only).
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Semantically validate the parsed config and produce a [`ValidatedConfig`]
    /// (each check → a field-named [`ConfigError`]; documented inline below). The
    /// notable one is `proofs_sink`: a REAL write-probe, not a mode-bit check.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        // upstream_url — absolute http(s).
        let upstream_url = reqwest::Url::parse(self.upstream_url.trim())
            .map_err(|e| ConfigError::new("upstream_url", format!("not a valid URL: {e}")))?;
        if !matches!(upstream_url.scheme(), "http" | "https") {
            return Err(ConfigError::new(
                "upstream_url",
                format!(
                    "scheme must be http or https, got {:?}",
                    upstream_url.scheme()
                ),
            ));
        }

        // mint_url — a cashu MintUrl (from_str enforces http(s)).
        let mint_url = MintUrl::from_str_checked(self.mint_url.trim())?;

        // charge.unit — keep the parsed ts so the advertised requirement carries
        // the CANONICAL `format_pop_unit(ts)`, never the raw operator spelling.
        let charge_ts = pops_core_verify::unit::parse_pop_unit(self.charge.unit.trim()).map_err(|e| {
            ConfigError::new("charge.unit", format!("not a valid pop_<ts> unit: {e}"))
        })?;

        if self.charge.amount == 0 {
            return Err(ConfigError::new("charge.amount", "must be greater than 0"));
        }

        // 0 would reject every request.
        if self.max_body_bytes == 0 {
            return Err(ConfigError::new("max_body_bytes", "must be greater than 0"));
        }

        // 0 would reject EVERY token (a valid token always carries ≥ 1 proof).
        if self.charge.max_proofs == 0 {
            return Err(ConfigError::new(
                "charge.max_proofs",
                "must be greater than 0",
            ));
        }

        // 0 ⇒ no timeout.
        let upstream_timeout = if self.upstream_timeout_secs == 0 {
            None
        } else {
            Some(std::time::Duration::from_secs(self.upstream_timeout_secs))
        };

        // Default to [mint_url] when empty; otherwise parse each.
        let mints: Vec<MintUrl> = if self.charge.mints.is_empty() {
            vec![mint_url.clone()]
        } else {
            let mut out = Vec::with_capacity(self.charge.mints.len());
            for (i, m) in self.charge.mints.iter().enumerate() {
                let parsed = MintUrl::from_str_for_field(m.trim(), &format!("charge.mints[{i}]"))?;
                out.push(parsed);
            }
            out
        };

        // We never create dirs: a missing parent is almost always an un-mounted
        // volume — the exact "lose received value" failure we guard against.
        validate_proofs_sink(&self.proofs_sink)?;

        let unit = CurrencyUnit::Custom(pops_core_verify::unit::format_pop_unit(charge_ts));
        let requirement = CashuRequirement {
            unit,
            mints,
            amount: Amount::from(self.charge.amount),
            payment_id: None,
            description: self.charge.description.clone(),
            single_use: true,
        };

        Ok(ValidatedConfig {
            upstream_url,
            mint_url,
            proofs_sink: self.proofs_sink,
            listen: self.listen,
            max_body_bytes: self.max_body_bytes,
            upstream_timeout,
            requirement,
            max_proofs: self.charge.max_proofs,
            routes: self.routes,
        })
    }
}

/// `proofs_sink` parent-dir existence + REAL writability check. The sink file
/// need not pre-exist; its parent must exist and be writable by the running uid
/// now (a missing parent = un-mounted volume; an unwritable dir = chown failure).
///
/// Checked with an ACTUAL write-probe ([`probe_writable`]), NOT the inode's
/// `readonly` mode bit: that bit reflects the OWNER's permission, so a dir owned
/// by root mode-0755 reports "not readonly" yet a non-root `pops` uid gets EACCES
/// on the first redeemed proof = silent value loss past a passing fail-fast.
fn validate_proofs_sink(path: &std::path::Path) -> Result<(), ConfigError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = match parent {
        Some(p) => p,
        None => std::path::Path::new("."), // bare filename resolves against CWD
    };
    let meta = std::fs::metadata(dir).map_err(|e| {
        ConfigError::new(
            "proofs_sink",
            format!("parent directory {dir:?} does not exist or is unreadable: {e}"),
        )
    })?;
    if !meta.is_dir() {
        return Err(ConfigError::new(
            "proofs_sink",
            format!("parent path {dir:?} is not a directory"),
        ));
    }
    probe_writable(dir)
}

/// Real write-probe: create → write → fsync → remove a temp file in `dir` as the
/// running uid; any error ⇒ not writable. The name
/// `.pops-gateway-writecheck-<pid>-<nanos>` avoids concurrent-boot collisions and
/// is harmless if a kill leaves it behind.
fn probe_writable(dir: &std::path::Path) -> Result<(), ConfigError> {
    use std::io::Write;

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = dir.join(format!(".pops-gateway-writecheck-{pid}-{nanos}"));

    let not_writable = |what: &str, e: &dyn std::fmt::Display| {
        ConfigError::new(
            "proofs_sink",
            format!(
                "parent directory {dir:?} is not writable by the running uid \
                 ({} {probe:?}: {e}); if running in Docker, chown the mounted \
                 volume to the container uid",
                what
            ),
        )
    };

    let mut file = std::fs::File::create(&probe).map_err(|e| not_writable("create", &e))?;
    let write_then_sync = file
        .write_all(b"pops-gateway-writecheck")
        .and_then(|()| file.sync_all());
    if let Err(e) = write_then_sync {
        let _ = std::fs::remove_file(&probe); // best-effort cleanup
        return Err(not_writable("write", &e));
    }
    drop(file);

    // A failure to remove still signals a broken dir, so surface it.
    std::fs::remove_file(&probe).map_err(|e| not_writable("remove", &e))?;
    Ok(())
}

/// Small helpers to map cashu/url parse failures into field-named
/// [`ConfigError`]s without leaking the cashu error type into call sites.
trait MintUrlFieldExt: Sized {
    fn from_str_checked(s: &str) -> Result<Self, ConfigError>;
    fn from_str_for_field(s: &str, field: &str) -> Result<Self, ConfigError>;
}

impl MintUrlFieldExt for MintUrl {
    fn from_str_checked(s: &str) -> Result<Self, ConfigError> {
        Self::from_str_for_field(s, "mint_url")
    }
    fn from_str_for_field(s: &str, field: &str) -> Result<Self, ConfigError> {
        use std::str::FromStr;
        MintUrl::from_str(s)
            .map_err(|e| ConfigError::new(field, format!("not a valid mint URL: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid config body, parameterized so a field can be broken
    /// per-test.
    fn valid_toml(proofs_sink: &str) -> String {
        format!(
            r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "{proofs_sink}"

[charge]
unit = "pop_1782668279"
amount = 1
"#
        )
    }

    #[test]
    fn valid_config_parses_and_validates() {
        let cfg = Config::from_toml_str(&valid_toml("/tmp/pops-proofs.jsonl")).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.listen, DEFAULT_LISTEN);
        assert_eq!(v.requirement.amount, Amount::from(1));
        assert_eq!(
            v.requirement.unit,
            CurrencyUnit::Custom("pop_1782668279".to_string())
        );
        assert_eq!(v.requirement.mints.len(), 1); // defaulted to [mint_url]
        assert!(v.routes.is_empty());
    }

    #[test]
    fn unit_is_canonicalized_in_requirement() {
        // A whitespace-padded unit still advertises a CANONICAL trimmed `pop_<ts>`
        // (built from format_pop_unit(parsed_ts), not the raw string).
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "  pop_1782668279  "
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(
            v.requirement.unit,
            CurrencyUnit::Custom("pop_1782668279".to_string()),
            "advertised unit must be the canonical, trimmed pop_<ts>"
        );
    }

    #[test]
    fn non_canonical_unit_is_rejected_at_gateway() {
        // A leading-zero spelling (same numeric value) is rejected as a
        // charge.unit error, never silently advertised as a divergent unit.
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_01782668279"
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let err = cfg.validate().expect_err("leading-zero unit must fail");
        assert_eq!(err.field, "charge.unit");
    }

    #[test]
    fn missing_proofs_sink_is_structural_error() {
        // No proofs_sink key at all → serde rejects (required, no default).
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"

[charge]
unit = "pop_1782668279"
amount = 1
"#;
        let err = Config::from_toml_str(toml).expect_err("missing proofs_sink must fail");
        assert!(
            err.to_string().contains("proofs_sink"),
            "error should name proofs_sink, got: {err}"
        );
    }

    #[test]
    fn zero_amount_is_named_field_error() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 0
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let err = cfg.validate().expect_err("amount=0 must fail");
        assert_eq!(err.field, "charge.amount");
    }

    #[test]
    fn malformed_unit_is_named_field_error() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "sat"
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let err = cfg.validate().expect_err("non-pop unit must fail");
        assert_eq!(err.field, "charge.unit");
    }

    #[test]
    fn bad_upstream_url_is_named_field_error() {
        let toml = r#"
upstream_url = "not a url"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let err = cfg.validate().expect_err("bad upstream must fail");
        assert_eq!(err.field, "upstream_url");
    }

    #[test]
    fn missing_parent_dir_proofs_sink_is_named_field_error() {
        let cfg = Config::from_toml_str(&valid_toml("/no/such/dir/anywhere/proofs.jsonl"))
            .expect("parses");
        let err = cfg.validate().expect_err("nonexistent parent must fail");
        assert_eq!(err.field, "proofs_sink");
    }

    /// Best-effort root detection: root bypasses DAC bits, so the read-only-dir
    /// probe test below would not hold. Detect by probing a `0o000` temp dir.
    fn running_as_root() -> bool {
        use std::os::unix::fs::PermissionsExt;
        let Ok(dir) = tempfile::tempdir() else {
            return false;
        };
        let sub = dir.path().join("noperm");
        if std::fs::create_dir(&sub).is_err() {
            return false;
        }
        let _ = std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o000));
        // Writable in a 0o000 dir ⇒ root.
        let can_write = std::fs::File::create(sub.join("probe")).is_ok();
        let _ = std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755));
        can_write
    }

    #[test]
    fn defaults_present_when_omitted() {
        let cfg = Config::from_toml_str(&valid_toml("/tmp/pops-proofs.jsonl")).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(
            v.upstream_timeout,
            Some(std::time::Duration::from_secs(
                DEFAULT_UPSTREAM_TIMEOUT_SECS
            ))
        );
    }

    #[test]
    fn max_proofs_defaults_when_omitted() {
        let cfg = Config::from_toml_str(&valid_toml("/tmp/pops-proofs.jsonl")).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.max_proofs, DEFAULT_MAX_PROOFS);
    }

    #[test]
    fn explicit_max_proofs_overrides_default() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 1
max_proofs = 8
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.max_proofs, 8);
    }

    #[test]
    fn zero_max_proofs_is_named_field_error() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 1
max_proofs = 0
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let err = cfg.validate().expect_err("max_proofs=0 must fail");
        assert_eq!(err.field, "charge.max_proofs");
    }

    #[test]
    fn zero_max_body_bytes_is_named_field_error() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"
max_body_bytes = 0

[charge]
unit = "pop_1782668279"
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let err = cfg.validate().expect_err("max_body_bytes=0 must fail");
        assert_eq!(err.field, "max_body_bytes");
    }

    #[test]
    fn zero_upstream_timeout_means_no_timeout() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"
upstream_timeout_secs = 0

[charge]
unit = "pop_1782668279"
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.upstream_timeout, None, "0 disables the timeout");
    }

    #[test]
    fn custom_body_cap_and_timeout_round_trip() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"
max_body_bytes = 2048
upstream_timeout_secs = 60

[charge]
unit = "pop_1782668279"
amount = 1
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.max_body_bytes, 2048);
        assert_eq!(v.upstream_timeout, Some(std::time::Duration::from_secs(60)));
    }

    /// The write-probe must FAIL FAST on an unwritable proofs_sink dir, not pass
    /// at boot and only hit EACCES on the first redeemed proof.
    #[test]
    fn readonly_proofs_sink_dir_fails_fast() {
        use std::os::unix::fs::PermissionsExt;

        if running_as_root() {
            eprintln!("skipping readonly_proofs_sink_dir_fails_fast: running as root");
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let ro = dir.path().join("readonly");
        std::fs::create_dir(&ro).expect("mkdir");
        // r-xr-xr-x: readable + traversable, NOT writable.
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).expect("chmod 0555");

        let sink = ro.join("proofs.jsonl");
        let err = validate_proofs_sink(&sink)
            .expect_err("a read-only proofs_sink dir must fail fast at startup");
        assert_eq!(err.field, "proofs_sink");
        assert!(
            err.reason.contains("not writable"),
            "reason should name the writability failure, got: {}",
            err.reason
        );

        let _ = std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755));
    }

    /// The write-probe passes and leaves nothing behind on a writable dir.
    #[test]
    fn writable_proofs_sink_dir_probe_passes_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = dir.path().join("proofs.jsonl");
        validate_proofs_sink(&sink).expect("writable dir passes the probe");
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe must clean up after itself, found: {leftovers:?}"
        );
    }

    #[test]
    fn explicit_mints_override_default() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 5
mints = ["https://mint-a.example.com", "https://mint-b.example.com"]
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.requirement.mints.len(), 2);
        assert_eq!(v.requirement.amount, Amount::from(5));
    }

    #[test]
    fn routes_parse() {
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"

[charge]
unit = "pop_1782668279"
amount = 1

[[routes]]
path = "/free/*"
public = true

[[routes]]
path = "/api/*"
"#;
        let cfg = Config::from_toml_str(toml).expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.routes.len(), 2);
        assert!(v.routes[0].public);
        assert!(!v.routes[1].public);
    }

    #[test]
    fn unknown_field_is_rejected() {
        // deny_unknown_fields catches typos in the operator's TOML.
        let toml = r#"
upstream_url = "http://127.0.0.1:9999"
mint_url = "https://mint.example.com"
proofs_sink = "/tmp/pops-proofs.jsonl"
typo_field = "oops"

[charge]
unit = "pop_1782668279"
amount = 1
"#;
        let err = Config::from_toml_str(toml).expect_err("unknown field must fail");
        assert!(err.to_string().contains("typo_field") || err.to_string().contains("unknown"));
    }
}
