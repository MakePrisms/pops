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

/// A machine-readable on-ramp hint for funding a deposit on a NON-mainnet
/// network — where the funder needs test coins, not real BTC. Returns `None` for
/// mainnet (real BTC has no faucet) and any unknown network.
///
/// Surfaced in `funding_pending.details.faucet_hint` so an agent waiting on a
/// signet/testnet/regtest deposit can point the human at where to get coins.
pub fn faucet_hint(net: Network) -> Option<&'static str> {
    match net {
        // Mainnet: real bitcoin, no faucet.
        Network::Bitcoin => None,
        // Signet here means Mutinynet (the project's signet), whose faucet is:
        Network::Signet => Some("https://faucet.mutinynet.com"),
        Network::Testnet => Some("https://mempool.space/testnet4/faucet"),
        Network::Regtest => Some("fund via your regtest node / generatetoaddress"),
        _ => None,
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

    #[test]
    fn faucet_hint_is_none_on_mainnet_and_some_on_test_networks() {
        // Mainnet (real BTC) has no faucet.
        assert_eq!(faucet_hint(Network::Bitcoin), None);
        // Signet here = Mutinynet.
        assert_eq!(faucet_hint(Network::Signet), Some("https://faucet.mutinynet.com"));
        // Testnet + regtest both provide a hint (URL resp. a node note).
        assert!(faucet_hint(Network::Testnet).is_some());
        assert!(faucet_hint(Network::Regtest).is_some());
    }
}
