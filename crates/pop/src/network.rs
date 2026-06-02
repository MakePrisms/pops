//! Network-name parsing shared by the CLI and config.

use bitcoin::Network;

/// Parses a user-facing network name into a `bitcoin::Network`.
///
/// Accepts `mainnet`/`bitcoin`, `testnet`, `signet`, `regtest`
/// (case-insensitive).
///
/// # Errors
///
/// Returns an error string for an unrecognized name.
pub fn parse_network(s: &str) -> Result<Network, String> {
    match s.trim().to_lowercase().as_str() {
        "mainnet" | "bitcoin" | "main" => Ok(Network::Bitcoin),
        "testnet" | "test" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!(
            "unknown network `{other}` (expected mainnet|testnet|signet|regtest)"
        )),
    }
}

/// The user-facing lowercase name for a network.
pub fn network_name(net: Network) -> &'static str {
    match net {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_networks() {
        assert_eq!(parse_network("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("BITCOIN").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
        assert_eq!(parse_network("Regtest").unwrap(), Network::Regtest);
        assert_eq!(parse_network("testnet").unwrap(), Network::Testnet);
    }

    #[test]
    fn parse_unknown_errors() {
        assert!(parse_network("liquid").is_err());
    }
}
