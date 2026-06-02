//! Gateway configuration: the ONE declarative TOML an operator mounts.
//!
//! Five facts are REQUIRED (missing/empty any → fail-fast structured error +
//! nonzero exit, never a panic): `upstream_url`, `mint_url`, `[charge].unit`,
//! `[charge].amount`, and `proofs_sink`. `proofs_sink` has NO default on
//! purpose (spec refinement #1): a silent in-container default would, on a
//! restart of an unmounted container, lose received bearer value — so the
//! operator is forced to land a conscious path.
//!
//! Parsing ([`Config::from_toml_str`]) is pure serde; semantic validation
//! ([`Config::validate`]) produces a [`ConfigError`] naming the exact field and
//! the reason, which `main` renders as `config field <X>: <reason>` to stderr.

use std::path::PathBuf;

use cashu::nuts::CurrencyUnit;
use cashu::{Amount, MintUrl};
use serde::Deserialize;

use pops_core_verify::challenge::CashuRequirement;

/// The default listen address when `listen` is omitted.
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";

/// Top-level gateway config, deserialized from the mounted TOML.
///
/// Required fields are plain (no `Option`) so a missing key is a serde error
/// surfaced before semantic validation; `proofs_sink` is deliberately required
/// with no default. Optional fields carry `#[serde(default)]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The operator's existing API, unmodified. Every gated request is
    /// forwarded here on a successful charge.
    pub upstream_url: String,

    /// The pops mint the presented credential is redeemed against (NUT-03
    /// swap). Also the target of the `/readyz` reachability probe.
    pub mint_url: String,

    /// Where redeemed bearer proofs are persisted. REQUIRED, NO default — this
    /// path is a WALLET holding received value (spec refinement #1).
    pub proofs_sink: PathBuf,

    /// Listen address for the gateway's own HTTP listener.
    #[serde(default = "default_listen")]
    pub listen: String,

    /// The charge requirement advertised on the 402 challenge + enforced on
    /// retry.
    pub charge: ChargeConfig,

    /// Optional per-path gating rules. Absent ⇒ gate EVERY path. When present,
    /// only paths matching a non-`public` rule are gated; `public = true` paths
    /// forward without gating.
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
}

/// A single `[[routes]]` rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Glob (`*` / `?`) matched against the request path. `*` matches any run
    /// of non-`/` characters is NOT assumed — `*` here matches across `/` too
    /// (a simple suffix/prefix glob), matching the documented "<glob>" surface.
    pub path: String,
    /// `true` ⇒ this path is public (forwarded WITHOUT gating). Defaults to
    /// `false` (the path is gated).
    #[serde(default)]
    pub public: bool,
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
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

/// The validated, ready-to-serve form of [`Config`]: the raw strings have been
/// parsed into their typed forms and the `CashuRequirement` (the challenge the
/// 402 advertises) is pre-built. Produced by [`Config::validate`].
#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    /// Parsed upstream base URL (the proxy target).
    pub upstream_url: reqwest::Url,
    /// Parsed mint URL (swap target + readiness probe target).
    pub mint_url: MintUrl,
    /// The persistent sink for redeemed proofs.
    pub proofs_sink: PathBuf,
    /// Listen address.
    pub listen: String,
    /// The pre-built cashu requirement advertised on the 402 + enforced on
    /// retry. Built once at startup.
    pub requirement: CashuRequirement,
    /// Per-path gating rules (possibly empty ⇒ gate all).
    pub routes: Vec<RouteConfig>,
}

impl Config {
    /// Parse a config from a TOML string (pure serde; structural errors only).
    pub fn from_toml_str(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Semantically validate the parsed config and produce a [`ValidatedConfig`].
    ///
    /// Checks (each → a field-named [`ConfigError`]):
    /// - `mint_url` parses as a cashu `MintUrl`;
    /// - `upstream_url` parses as an absolute http(s) URL;
    /// - `charge.unit` is a well-formed `pop_<ts>` (via `parse_pop_unit`);
    /// - `charge.amount > 0`;
    /// - every `charge.mints` entry parses as a `MintUrl`;
    /// - `proofs_sink` has an existing, writable parent directory.
    pub fn validate(self) -> Result<ValidatedConfig, ConfigError> {
        // upstream_url — absolute http(s).
        let upstream_url = reqwest::Url::parse(self.upstream_url.trim())
            .map_err(|e| ConfigError::new("upstream_url", format!("not a valid URL: {e}")))?;
        if !matches!(upstream_url.scheme(), "http" | "https") {
            return Err(ConfigError::new(
                "upstream_url",
                format!("scheme must be http or https, got {:?}", upstream_url.scheme()),
            ));
        }

        // mint_url — a cashu MintUrl (also parseable as a reqwest URL for the
        // readiness probe; MintUrl::from_str enforces http(s)).
        let mint_url = MintUrl::from_str_checked(self.mint_url.trim())?;

        // charge.unit — a well-formed pop_<ts>.
        pops_core_types::parse_pop_unit(self.charge.unit.trim()).map_err(|e| {
            ConfigError::new("charge.unit", format!("not a valid pop_<ts> unit: {e}"))
        })?;

        // charge.amount — strictly positive.
        if self.charge.amount == 0 {
            return Err(ConfigError::new("charge.amount", "must be greater than 0"));
        }

        // charge.mints — default to [mint_url] when empty; otherwise parse each.
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

        // proofs_sink — parent must exist + be writable (we never create dirs:
        // a missing parent is almost always an un-mounted volume, which is the
        // exact "lose received value" failure refinement #1 guards against).
        validate_proofs_sink(&self.proofs_sink)?;

        // Build the cashu requirement ONCE.
        let unit = CurrencyUnit::Custom(self.charge.unit.trim().to_string());
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
            requirement,
            routes: self.routes,
        })
    }
}

/// `proofs_sink` parent-dir existence + writability check. The sink FILE itself
/// need not pre-exist (it is created append-wise at first write), but its parent
/// directory must exist and be writable now — a missing parent is the
/// un-mounted-volume failure mode.
fn validate_proofs_sink(path: &std::path::Path) -> Result<(), ConfigError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = match parent {
        Some(p) => p,
        // A bare filename (no parent component) resolves against CWD.
        None => std::path::Path::new("."),
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
    // Writability: check the directory permissions are not read-only. A
    // belt-and-braces probe (creating a temp file) would mutate the operator's
    // volume, so we inspect the mode instead.
    let readonly = meta.permissions().readonly();
    if readonly {
        return Err(ConfigError::new(
            "proofs_sink",
            format!("parent directory {dir:?} is not writable (read-only)"),
        ));
    }
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

    /// A minimal valid config body, parameterized so individual fields can be
    /// broken per-test. `proofs_sink` points at `/tmp` (exists + writable in
    /// CI/containers).
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
        let cfg = Config::from_toml_str(&valid_toml("/tmp/pops-proofs.jsonl"))
            .expect("parses");
        let v = cfg.validate().expect("validates");
        assert_eq!(v.listen, DEFAULT_LISTEN);
        assert_eq!(v.requirement.amount, Amount::from(1));
        // mints defaulted to [mint_url].
        assert_eq!(v.requirement.mints.len(), 1);
        assert!(v.routes.is_empty());
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
        let cfg =
            Config::from_toml_str(&valid_toml("/no/such/dir/anywhere/proofs.jsonl"))
                .expect("parses");
        let err = cfg.validate().expect_err("nonexistent parent must fail");
        assert_eq!(err.field, "proofs_sink");
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
