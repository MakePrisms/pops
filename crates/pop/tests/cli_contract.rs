//! Black-box tests for the FROZEN output & error contract, driving the real
//! `pop` binary against a throwaway wallet dir:
//!
//! - json is the DEFAULT; stdout is EXACTLY ONE JSON object (diagnostics → stderr);
//! - every output carries top-level `schema_version`;
//! - failures are the `{schema_version, error:{code, retriable, message, details?}}`
//!   envelope on stdout, exit 1;
//! - `--human` switches to text; clap usage errors stay exit 2.

use std::path::Path;
use std::process::Command;

/// Path to the compiled `pop` binary under test.
fn pop_bin() -> &'static str {
    env!("CARGO_BIN_EXE_pop")
}

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Runs `pop <args>` with a fresh wallet dir, returning split stdout/stderr +
/// exit code. `HOME` is cleared so a missing `--wallet-dir` can't escape to a
/// real `~/.pop-wallet`.
fn run_pop(wallet_dir: &Path, args: &[&str]) -> Output {
    let out = Command::new(pop_bin())
        .args(args)
        .arg("--wallet-dir")
        .arg(wallet_dir)
        .env_remove("HOME")
        .output()
        .expect("failed to spawn pop");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code().unwrap_or(-1),
    }
}

/// Parses stdout as a single JSON object, asserting it is pure (the whole of
/// stdout is exactly one JSON value, nothing trailing).
fn parse_single_json(stdout: &str) -> serde_json::Value {
    let trimmed = stdout.trim_end_matches('\n');
    // A single object: serde_json must consume the ENTIRE string.
    let v: serde_json::Value = serde_json::from_str(trimmed)
        .unwrap_or_else(|e| panic!("stdout is not a single JSON value: {e}\nstdout was:\n{stdout}"));
    v
}

/// A success command emits a `schema_version` JSON object on stdout, exit 0.
/// SECURITY: by default the mnemonic is NOT on stdout (it goes to stderr,
/// `mnemonic_delivery: "stderr"`).
#[test]
fn success_emits_json_with_schema_version_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_pop(
        dir.path(),
        &["init", "--network", "regtest"],
    );
    assert_eq!(out.code, 0, "init should succeed; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    // init success fields preserved.
    assert_eq!(v["network"], serde_json::json!("regtest"));
    assert_eq!(v["imported"], serde_json::json!(false));
    // SECURITY: the secret mnemonic is NOT on stdout by default.
    assert!(
        v.get("mnemonic").is_none(),
        "default stdout JSON must not carry the mnemonic; got:\n{}",
        out.stdout
    );
    assert_eq!(v["mnemonic_delivery"], serde_json::json!("stderr"));
    // The actual mnemonic line went to stderr (clearly labelled, shown once).
    assert!(
        out.stderr.contains("mnemonic (write this down, shown once):"),
        "the mnemonic should be printed to stderr; got:\n{}",
        out.stderr
    );
}

/// (item 1, SECURITY) With `--show-mnemonic` the caller explicitly opts in to
/// capturing the secret on stdout: the stdout JSON DOES carry `mnemonic` and
/// `mnemonic_delivery` flips to `"stdout"`.
#[test]
fn init_show_mnemonic_puts_mnemonic_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_pop(dir.path(), &["init", "--network", "regtest", "--show-mnemonic"]);
    assert_eq!(out.code, 0, "init --show-mnemonic should succeed; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert!(
        v["mnemonic"].is_string() && !v["mnemonic"].as_str().unwrap().is_empty(),
        "with --show-mnemonic the stdout JSON must carry the mnemonic; got:\n{}",
        out.stdout
    );
    assert_eq!(v["mnemonic_delivery"], serde_json::json!("stdout"));
}

/// (a) `list` is the canonical pure-json default: an envelope with
/// schema_version + a deposits array. JSON is the DEFAULT (no flag).
#[test]
fn list_is_json_by_default_with_envelope() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);

    let out = run_pop(dir.path(), &["list"]);
    assert_eq!(out.code, 0, "stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    assert!(v["deposits"].is_array(), "list envelope has a deposits array");
    assert_eq!(v["deposits"].as_array().unwrap().len(), 0);
}

/// `balance` degrades gracefully on an unreachable chain: `recoverable_now` null
/// + `mtp_available` false, but still EXITS 0 with a single JSON object (a chain
/// read never hard-fails balance); the warning lands on stderr.
#[test]
fn balance_degrades_to_null_recoverable_when_chain_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    // Unroutable esplora so the tip-MTP fetch deterministically fails.
    assert_eq!(
        run_pop(
            dir.path(),
            &["init", "--network", "regtest", "--esplora-url", "http://127.0.0.1:1"],
        )
        .code,
        0
    );

    let out = run_pop(dir.path(), &["balance"]);
    assert_eq!(out.code, 0, "balance must not hard-fail on a chain read; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    assert_eq!(v["mtp_available"], serde_json::json!(false));
    assert_eq!(v["recoverable_now"], serde_json::json!(null));
    assert_eq!(v["total_locked_sats"], serde_json::json!(0));
    assert_eq!(v["mintable_now"], serde_json::json!({ "count": 0, "sats": 0 }));
    assert_eq!(v["by_state"]["paid"], serde_json::json!({ "count": 0, "sats": 0 }));
    assert!(
        out.stderr.contains("esplora"),
        "expected an esplora-unreachable warning on stderr; got:\n{}",
        out.stderr
    );
}

/// `status` degrades like `balance`: `mtp_available: false`, exit 0, a single
/// JSON object with a `deposits` array (flag present even for an empty ledger).
#[test]
fn status_signals_mtp_available_false_when_chain_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        run_pop(
            dir.path(),
            &["init", "--network", "regtest", "--esplora-url", "http://127.0.0.1:1"],
        )
        .code,
        0
    );

    let out = run_pop(dir.path(), &["status"]);
    assert_eq!(out.code, 0, "status must not hard-fail on a chain read; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    // The degrade flag is present at the envelope level (empty ledger here).
    assert_eq!(v["mtp_available"], serde_json::json!(false));
    assert!(v["deposits"].is_array());
    assert_eq!(v["deposits"].as_array().unwrap().len(), 0);
    // The warning is on stderr, keeping stdout a pure envelope.
    assert!(
        out.stderr.contains("esplora"),
        "expected an esplora-unreachable warning on stderr; got:\n{}",
        out.stderr
    );
}

/// (d) `balance --human` prints a readable summary to stdout (not json), exit 0,
/// even when the chain tip is unavailable (recoverable shows as "unknown").
#[test]
fn balance_human_prints_text_summary() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        run_pop(
            dir.path(),
            &["init", "--network", "regtest", "--esplora-url", "http://127.0.0.1:1"],
        )
        .code,
        0
    );

    let out = run_pop(dir.path(), &["balance", "--human"]);
    assert_eq!(out.code, 0, "stderr:\n{}", out.stderr);
    assert!(
        out.stdout.contains("total locked"),
        "human balance should print a totals summary; got:\n{}",
        out.stdout
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(out.stdout.trim()).is_err(),
        "human stdout must not be json"
    );
}

/// The deprecated `--json` flag is still accepted as a no-op (json is already
/// default), so old invocations don't break.
#[test]
fn deprecated_json_flag_is_accepted_noop() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    let out = run_pop(dir.path(), &["list", "--json"]);
    assert_eq!(out.code, 0, "stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    assert!(v["deposits"].is_array());
}

/// (b) Error envelope shape — `wallet_not_initialized` (message-only): running a
/// command before `init` yields the failure envelope on stdout, exit 1.
#[test]
fn error_envelope_wallet_not_initialized() {
    let dir = tempfile::tempdir().unwrap();
    // No init → list must fail with wallet_not_initialized.
    let out = run_pop(dir.path(), &["list"]);
    assert_eq!(out.code, 1, "expected app-error exit 1; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    assert_eq!(v["error"]["code"], serde_json::json!("wallet_not_initialized"));
    assert_eq!(v["error"]["retriable"], serde_json::json!(false));
    assert!(v["error"]["message"].is_string());
    // message-only code → no details key.
    assert!(v["error"].get("details").is_none());
}

/// (b) Error envelope with REQUIRED details — `deposit_not_found{deposit_id}`:
/// recovering an unknown id surfaces the structured id.
#[test]
fn error_envelope_deposit_not_found_has_required_details() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);

    let out = run_pop(
        dir.path(),
        &[
            "recover",
            "--deposit",
            "no-such-id",
            "--dest",
            // a valid regtest address so the failure is the id, not the dest.
            "bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd",
        ],
    );
    assert_eq!(out.code, 1, "stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["error"]["code"], serde_json::json!("deposit_not_found"));
    assert_eq!(v["error"]["details"]["deposit_id"], serde_json::json!("no-such-id"));
}

/// (b) Error envelope with REQUIRED details — `network_mismatch{expected, got}`:
/// a mainnet dest against a regtest wallet.
#[test]
fn error_envelope_network_mismatch_has_required_details() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);

    let out = run_pop(
        dir.path(),
        &[
            "recover",
            "--all",
            "--dest",
            // a mainnet bech32 address — wrong network for a regtest wallet.
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        ],
    );
    assert_eq!(out.code, 1, "stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["error"]["code"], serde_json::json!("network_mismatch"));
    assert_eq!(v["error"]["details"]["expected"], serde_json::json!("regtest"));
    assert_eq!(v["error"]["details"]["got"], serde_json::json!("mainnet"));
    assert_eq!(v["error"]["retriable"], serde_json::json!(false));
}

/// invalid_input (message-only, exit 1) for a bad `--network` at `init`. (The
/// `--state` filter is now a clap ValueEnum, so a bad `--state` is instead a clap
/// usage error exit 2 — covered by `invalid_state_filter_is_clap_exit_2`.)
#[test]
fn error_envelope_invalid_input() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_pop(dir.path(), &["init", "--network", "bogus"]);
    assert_eq!(out.code, 1, "stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["error"]["code"], serde_json::json!("invalid_input"));
    assert!(v["error"].get("details").is_none());
}

/// (item 8) `--state` is a clap ValueEnum: an unknown value is a clap USAGE error
/// (exit 2, no envelope), and `--help` enumerates the accepted values.
#[test]
fn invalid_state_filter_is_clap_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    let out = run_pop(dir.path(), &["list", "--state", "bogus"]);
    assert_eq!(out.code, 2, "bad --state must be a clap usage error; stderr:\n{}", out.stderr);
    // The accepted values are enumerated in the clap error/help.
    assert!(
        out.stderr.contains("unpaid") && out.stderr.contains("expired"),
        "clap should list the valid --state values; got:\n{}",
        out.stderr
    );
    // A valid value still works (exit 0).
    assert_eq!(run_pop(dir.path(), &["list", "--state", "minted"]).code, 0);
}

/// stdout-purity: even with diagnostics, json-mode stdout stays a single JSON
/// object (human/progress text goes to stderr).
#[test]
fn json_mode_stdout_is_pure_progress_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let first = run_pop(dir.path(), &["init", "--network", "regtest"]);
    assert_eq!(first.code, 0);
    let v = parse_single_json(&first.stdout);
    assert!(v["schema_version"].is_u64());

    // A second init fails (wallet_exists); stdout stays pure (the human `message`
    // lives INSIDE the envelope — what's forbidden is loose prose OUTSIDE it).
    let second = run_pop(dir.path(), &["init", "--network", "regtest"]);
    assert_eq!(second.code, 1);
    let v = parse_single_json(&second.stdout);
    assert_eq!(v["error"]["code"], serde_json::json!("wallet_exists"));
    assert!(
        !second.stdout.contains("DANGER"),
        "human banner leaked to stdout: {}",
        second.stdout
    );
}

/// (d) `--human` mode: success prints TEXT to stdout (not json), exit 0.
#[test]
fn human_mode_prints_text_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);

    let out = run_pop(dir.path(), &["list", "--human"]);
    assert_eq!(out.code, 0, "stderr:\n{}", out.stderr);
    // Not json: the human "(no deposits)" line.
    assert!(
        out.stdout.contains("(no deposits)"),
        "human list should print the no-deposits line; got:\n{}",
        out.stdout
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(out.stdout.trim()).is_err(),
        "human stdout must not be json"
    );
}

/// (d) `--human` mode failure: the human message goes to STDERR (NOT json), and
/// stdout is empty; exit 1. `--pretty` is an accepted alias.
#[test]
fn human_mode_failure_message_on_stderr_no_json() {
    let dir = tempfile::tempdir().unwrap();
    // No init → list --pretty fails; message on stderr, nothing on stdout.
    let out = run_pop(dir.path(), &["list", "--pretty"]);
    assert_eq!(out.code, 1);
    assert!(out.stdout.trim().is_empty(), "human-mode failure must not write stdout: {:?}", out.stdout);
    assert!(
        out.stderr.contains("error:"),
        "human-mode failure should print to stderr; got:\n{}",
        out.stderr
    );
    // And it must NOT be a json envelope.
    assert!(serde_json::from_str::<serde_json::Value>(out.stderr.trim()).is_err());
}

/// clap usage errors keep exit code 2 (we must not touch them).
#[test]
fn clap_usage_error_is_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    // `recover` requires --dest; omitting it is a clap usage error.
    let out = run_pop(dir.path(), &["recover", "--all"]);
    assert_eq!(out.code, 2, "clap usage error must be exit 2; stderr:\n{}", out.stderr);
}

/// An unknown subcommand is also a clap usage error (exit 2), not our envelope.
#[test]
fn unknown_subcommand_is_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let out = run_pop(dir.path(), &["frobnicate"]);
    assert_eq!(out.code, 2);
}

/// `pop pay` is now a real subcommand (the HTTP-402 client dance): `--help`
/// succeeds (exit 0), and the bare form WITHOUT a `<URL>` is a clap usage error
/// (exit 2 — a missing required positional, not our envelope). It reads no
/// wallet state, so it does not need `init`.
#[test]
fn pay_subcommand_exists_help_ok_missing_url_is_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    // `--help` exits 0 now that the command exists.
    assert_eq!(run_pop(dir.path(), &["pay", "--help"]).code, 0);
    // Bare `pop pay` is missing the required <URL> positional → clap exit 2.
    assert_eq!(run_pop(dir.path(), &["pay"]).code, 2);
}

/// (item 2) `pop mint --resume <id>` parses WITHOUT --mint-url/--amount/--unit:
/// it gets PAST clap (exit != 2) and fails at runtime with the app-level
/// `deposit_not_found` envelope (exit 1) for an unknown id — proving the bare
/// resume form is accepted at the arg-parse layer.
#[test]
fn mint_resume_parses_without_mint_url_or_amount() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);

    let out = run_pop(dir.path(), &["mint", "--resume", "no-such-deposit-id"]);
    // NOT a clap usage error: bare `--resume` is a valid invocation.
    assert_ne!(out.code, 2, "bare `mint --resume <id>` must parse; stderr:\n{}", out.stderr);
    assert_eq!(out.code, 1, "expected an app-level error; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["error"]["code"], serde_json::json!("deposit_not_found"));
    assert_eq!(v["error"]["details"]["deposit_id"], serde_json::json!("no-such-deposit-id"));
}

/// (item 2) A FRESH `pop mint` (no --resume) WITHOUT --mint-url/--amount is a
/// clap usage error (exit 2): those are required for a fresh mint.
#[test]
fn fresh_mint_without_required_args_is_clap_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    // No --mint-url, no --amount, no --resume → clap usage error.
    let out = run_pop(dir.path(), &["mint", "--duration", "30d"]);
    assert_eq!(out.code, 2, "fresh mint missing --mint-url/--amount must be exit 2; stderr:\n{}", out.stderr);
}

/// (item 3) A fresh `pop mint` with NEITHER --duration NOR --unit is a clap usage
/// error (exit 2) — never the mint-side "Unit unsupported" (11013).
#[test]
fn fresh_mint_without_unit_group_is_clap_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    let out = run_pop(
        dir.path(),
        &["mint", "--mint-url", "https://mint.example", "--amount", "1000"],
    );
    assert_eq!(out.code, 2, "missing unit/duration must be exit 2; stderr:\n{}", out.stderr);
}

/// (item 3) `pop quote` with NEITHER --duration NOR --unit is a clap usage error
/// (exit 2) via the required ArgGroup.
#[test]
fn quote_without_unit_group_is_clap_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    let out = run_pop(
        dir.path(),
        &["quote", "--mint-url", "https://mint.example", "--amount", "1000", "--mint-pubkey", "02ab"],
    );
    assert_eq!(out.code, 2, "quote missing unit/duration must be exit 2; stderr:\n{}", out.stderr);
}

/// (item 3) Supplying BOTH --duration and --unit is mutually exclusive (clap exit
/// 2), for both quote and mint.
#[test]
fn duration_and_unit_together_is_clap_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    let out = run_pop(
        dir.path(),
        &[
            "quote", "--mint-url", "https://mint.example", "--amount", "1000",
            "--mint-pubkey", "02ab", "--duration", "30d", "--unit", "pop_1788000000",
        ],
    );
    assert_eq!(out.code, 2, "duration+unit together must be exit 2; stderr:\n{}", out.stderr);
}

/// `recover --all` with NO funded candidates is an empty SUCCESS (exit 0) that
/// makes NO chain call (so it can't fail chain_unreachable).
#[test]
fn recover_all_empty_is_success_with_no_chain_call() {
    let dir = tempfile::tempdir().unwrap();
    // Unroutable esplora: the empty sweep must NOT touch the chain.
    assert_eq!(
        run_pop(
            dir.path(),
            &["init", "--network", "regtest", "--esplora-url", "http://127.0.0.1:1"],
        )
        .code,
        0
    );

    let out = run_pop(
        dir.path(),
        &["recover", "--all", "--dest", "bcrt1psjw4ymy3cl0a2cp32nnh4kjj9fus8m5daust4kd4hzwnkm7ctmhq29z2wd"],
    );
    assert_eq!(out.code, 0, "empty --all sweep must succeed; stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["schema_version"], serde_json::json!(1));
    assert_eq!(v["tip_height"], serde_json::json!(null));
    assert_eq!(v["tip_mtp"], serde_json::json!(null));
    assert!(v["results"].as_array().unwrap().is_empty());
    // No chain call ⇒ no esplora warning.
    assert!(
        !out.stderr.contains("esplora"),
        "empty --all sweep must not touch the chain; got stderr:\n{}",
        out.stderr
    );
}

/// (item 7) A malformed `--dest` surfaces a clear `invalid_input` message that
/// does NOT leak the misleading raw "base58" prose for a bad bech32 string.
#[test]
fn recover_malformed_dest_message_is_clear_no_base58() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(run_pop(dir.path(), &["init", "--network", "regtest"]).code, 0);
    let out = run_pop(dir.path(), &["recover", "--all", "--dest", "not-an-address"]);
    assert_eq!(out.code, 1, "stderr:\n{}", out.stderr);
    let v = parse_single_json(&out.stdout);
    assert_eq!(v["error"]["code"], serde_json::json!("invalid_input"));
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("not a valid bitcoin address"),
        "expected a clear address message; got: {msg}"
    );
    assert!(
        !msg.to_lowercase().contains("base58"),
        "must not leak the misleading base58 prose; got: {msg}"
    );
}
