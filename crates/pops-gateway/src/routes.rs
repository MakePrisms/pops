//! Per-path gating policy.
//!
//! If the operator supplied no `[[routes]]`, every path is gated. Otherwise the
//! FIRST matching rule decides: a `public = true` match ⇒ forward without
//! gating; a non-public match ⇒ gate. A path matching NO rule falls through to
//! the default (gate) — fail-closed, so an un-listed path is never accidentally
//! free.
//!
//! The glob is intentionally tiny: `*` matches any run of characters (including
//! `/`), `?` matches exactly one. That covers the documented `<glob>` surface
//! (`/free/*`, `*.png`, `/api/v1/*`) without a regex dependency.

use crate::config::RouteConfig;

/// The gating decision for a request path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Run the payment gate before forwarding.
    Charge,
    /// Forward straight to upstream, no gate.
    Public,
}

/// Decide whether `path` is gated, given the configured rules.
///
/// Empty `routes` ⇒ always [`Gate::Charge`]. Otherwise the first rule whose
/// glob matches wins; no match ⇒ [`Gate::Charge`] (fail-closed).
pub fn gate_for(path: &str, routes: &[RouteConfig]) -> Gate {
    for rule in routes {
        if glob_match(&rule.path, path) {
            return if rule.public {
                Gate::Public
            } else {
                Gate::Charge
            };
        }
    }
    Gate::Charge
}

/// Minimal glob: `*` = zero-or-more of any char, `?` = exactly one. Anchored at
/// both ends (the whole path must match). Backtracking handled iteratively so a
/// pattern like `*/x` is linear-ish, not exponential, on typical paths.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();

    // Two-pointer with star backtracking (classic wildcard match).
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t): (Option<usize>, usize) = (None, 0);

    while t < txt.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == txt[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == '*' {
            star_p = Some(p);
            star_t = t;
            p += 1;
        } else if let Some(sp) = star_p {
            // Mismatch but we have a star to expand: consume one more text char.
            p = sp + 1;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }
    // Trailing stars in the pattern match empty.
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(path: &str, public: bool) -> RouteConfig {
        RouteConfig {
            path: path.to_string(),
            public,
        }
    }

    #[test]
    fn no_routes_gates_everything() {
        assert_eq!(gate_for("/anything", &[]), Gate::Charge);
        assert_eq!(gate_for("/", &[]), Gate::Charge);
    }

    #[test]
    fn public_route_forwards() {
        let routes = vec![route("/free/*", true)];
        assert_eq!(gate_for("/free/health", &routes), Gate::Public);
        // Non-matching path falls through to gate (fail-closed).
        assert_eq!(gate_for("/paid/data", &routes), Gate::Charge);
    }

    #[test]
    fn non_public_route_gates() {
        let routes = vec![route("/api/*", false)];
        assert_eq!(gate_for("/api/v1/x", &routes), Gate::Charge);
    }

    #[test]
    fn first_match_wins() {
        let routes = vec![route("/a/*", true), route("/a/secret", false)];
        // First rule matches first, so /a/secret is public via the broader rule.
        assert_eq!(gate_for("/a/secret", &routes), Gate::Public);
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("*", "anything/at/all"));
        assert!(glob_match("/free/*", "/free/x/y"));
        assert!(glob_match("*.png", "/img/cat.png"));
        assert!(glob_match("/api/v1/?", "/api/v1/x"));
        assert!(!glob_match("/api/v1/?", "/api/v1/xy"));
        assert!(!glob_match("/free/*", "/paid/x"));
        assert!(glob_match("/exact", "/exact"));
        assert!(!glob_match("/exact", "/exacto"));
    }
}
