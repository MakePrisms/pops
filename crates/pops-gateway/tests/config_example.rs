//! The shipped `config.example.toml` must stay STRUCTURALLY parseable by the
//! gateway's `Config` so the operator-facing example can't silently rot (a
//! renamed field or changed table nesting would break it here).
//!
//! This is a STRUCTURAL parse only (`Config::from_toml_str` = pure serde). It
//! deliberately does NOT call `validate()`, which touches the filesystem
//! (`proofs_sink` parent dir) and would couple a docs check to the environment.

use pops_gateway::config::Config;

#[test]
fn config_example_parses_structurally() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml");
    let toml = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e}"));
    Config::from_toml_str(&toml)
        .unwrap_or_else(|e| panic!("config.example.toml must parse via Config::from_toml_str: {e}"));
}
