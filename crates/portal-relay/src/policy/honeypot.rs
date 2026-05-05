//! R10 v0.1 honeypot path matcher.
//!
//! Production tenants do not request `/.env`, `/.git/config`, or
//! `/wp-admin/setup-config.php` — those are well-known scanning
//! signatures.  When a request path matches a configured honeypot
//! pattern, the listener pipeline calls
//! [`crate::policy::ReputationEngine::record_signal`] with
//! [`SignalKind::HoneypotHit`] and the per-signal weight from
//! ADR-0007 (default 25.0).  Four honeypot hits in a 24 h decay window
//! cross [`crate::policy::REPUTATION_BLOCK_THRESHOLD`] and any
//! subsequent request from that identity returns
//! [`crate::policy::ReputationDecision::Block`].
//!
//! ## Match semantics
//!
//! The matcher accepts:
//!
//! - **Exact paths.** `/.env` matches `/.env` only — case-sensitive
//!   (HTTP path components are case-sensitive per RFC 7230 §2.7.3).
//! - **Trailing-segment globs.** `/.git/*` matches every path whose
//!   first two segments equal `.git`, regardless of what follows.
//!   Implemented as a literal prefix match against `/.git/`.
//!
//! Anything more sophisticated — wildcards in the middle, regex,
//! query-string matching — is intentionally excluded from v0.1.  The
//! per-signal weight is high enough (25.0 = block-threshold / 4) that
//! a small set of high-precision patterns catches the noisy adversarial
//! shapes; broader matching invites false positives that the v0.1
//! reputation engine has no operator-tuneable bypass for (the ENS-
//! Sybil-gating bypass is itself a TODO(R10-followup)).
//!
//! ## Construction
//!
//! [`HoneypotMatcher::with_defaults`] returns the workspace-default
//! pattern set — exactly `/.env`, `/.git/*`, and `/wp-admin/*` per
//! Phase 5 plan U12.  Broader scanner-target coverage
//! (`/phpmyadmin/*`, `/wp-login.php`, `/server-status`, etc.) is
//! intentionally opt-in: those paths can be legitimate tenant traffic
//! (a tenant running phpMyAdmin or exposing an admin landing page)
//! and a 25.0-weighted signal at the v0.1 ENS-Sybil-bypass-pending
//! state would block them after four hits.  Operators tune via
//! [`HoneypotMatcher::from_patterns`] at config-load time (consumed
//! by U13 hot-reload alongside `arc-swap<HoneypotMatcher>`).
//!
//! ## Out-of-scope (TODO follow-up)
//!
//! - Hot-reload via `arc-swap<HoneypotMatcher>` lands with U13
//!   alongside `arc-swap<ReputationConfig>`.
//! - Listener-pipeline integration (the actual `record_signal` call
//!   site) lands when the discovery / SDK API surfaces have their
//!   request handlers wired through `PolicyRuntime`.

use compact_str::CompactString;

/// Workspace-default honeypot pattern set.
///
/// Exactly the three entries Phase 5 plan U12 §Approach names — every
/// other scanner-target pattern is operator-configurable rather than a
/// workspace default.  The 25.0 per-signal weight (ADR-0007) means a
/// single false-positive default pattern blocks a cooperating tenant
/// after four hits in a 24h window; v0.1's defaults stay narrow until
/// the ENS-Sybil-gating bypass lands and gives blocked tenants an
/// escape hatch.
pub const HONEYPOT_DEFAULT_PATTERNS: &[&str] = &["/.env", "/.git/*", "/wp-admin/*"];

/// Compiled honeypot pattern matcher.
///
/// Each pattern is normalised at construction time into one of two
/// shapes and stored separately so the hot-path lookup is a single
/// linear scan over the smaller of the two slices (exact paths are
/// usually fewer).  v0.1 sticks with the unsorted-vec lookup because
/// the pattern set is small (≤16 entries in any realistic deployment);
/// a perfect-hash table or radix-trie are v0.2 candidates if the set
/// grows past the linear-scan break-even point.
#[derive(Debug, Clone)]
pub struct HoneypotMatcher {
    /// Exact-match paths (`/.env`, `/.git/HEAD`, `/admin.php`).
    exact: Vec<CompactString>,
    /// Trailing-glob prefixes (`/.git/`, `/wp-admin/`, `/phpmyadmin/`).
    /// The leading slash is preserved; the trailing `/*` is stripped.
    prefixes: Vec<CompactString>,
}

impl HoneypotMatcher {
    /// Construct with the workspace-default pattern set
    /// ([`HONEYPOT_DEFAULT_PATTERNS`]).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::from_patterns(HONEYPOT_DEFAULT_PATTERNS.iter().copied())
    }

    /// Construct from an iterator of operator-supplied pattern strings.
    /// Empty / whitespace-only / non-path-shaped patterns (those not
    /// starting with `/`) are silently dropped — operator-config is
    /// tolerant of typos, and the listener pipeline still sees the
    /// non-tolerant path through `record_signal`.
    pub fn from_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut exact: Vec<CompactString> = Vec::new();
        let mut prefixes: Vec<CompactString> = Vec::new();
        for pat in patterns {
            let s = pat.as_ref().trim();
            if s.is_empty() || !s.starts_with('/') {
                continue;
            }
            if let Some(prefix) = s.strip_suffix("/*") {
                if prefix.is_empty() {
                    // `/*` alone matches everything — refuse, the
                    // signal weight is 25.0 and a catch-all would
                    // block every legitimate tenant in 4 requests.
                    continue;
                }
                let mut p = CompactString::new(prefix);
                p.push('/');
                prefixes.push(p);
            } else {
                exact.push(CompactString::new(s));
            }
        }
        Self { exact, prefixes }
    }

    /// Returns `true` iff `path` matches any configured honeypot
    /// pattern.  Path comparison is case-sensitive; query strings (if
    /// present) MUST be stripped by the caller before matching — we
    /// do not split on `?` here so the matcher remains a pure path
    /// predicate.
    #[must_use]
    pub fn matches(&self, path: &str) -> bool {
        if self.exact.iter().any(|p| p.as_str() == path) {
            return true;
        }
        if self.prefixes.iter().any(|p| path.starts_with(p.as_str())) {
            return true;
        }
        false
    }

    /// Number of compiled exact-path patterns.  Test + admin
    /// observability surface; not load-bearing on the hot path.
    #[must_use]
    pub const fn exact_pattern_count(&self) -> usize {
        self.exact.len()
    }

    /// Number of compiled trailing-glob prefix patterns.  Same purpose
    /// as [`Self::exact_pattern_count`].
    #[must_use]
    pub const fn prefix_pattern_count(&self) -> usize {
        self.prefixes.len()
    }
}

impl Default for HoneypotMatcher {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_plan_u12_set() {
        let m = HoneypotMatcher::with_defaults();
        // Exactly the three patterns plan U12 names.
        assert!(m.matches("/.env"));
        assert!(m.matches("/.git/HEAD"));
        assert!(m.matches("/.git/config"));
        assert!(m.matches("/wp-admin/setup-config.php"));
        assert!(m.matches("/wp-admin/admin.php"));
    }

    #[test]
    fn defaults_pass_legitimate_paths() {
        let m = HoneypotMatcher::with_defaults();
        assert!(!m.matches("/"));
        assert!(!m.matches("/index.html"));
        assert!(!m.matches("/api/v1/health"));
        assert!(!m.matches("/v1/sdk/register"));
        assert!(!m.matches("/v1/keyless/sign"));
        assert!(!m.matches("/healthz"));
        assert!(!m.matches("/metrics"));
    }

    #[test]
    fn defaults_do_not_extend_beyond_plan_u12_set() {
        // Patterns that v0.1 deliberately leaves operator-configurable
        // rather than as workspace defaults.  A tenant exposing
        // phpMyAdmin or a wp-login admin landing page is NOT blocked
        // by the workspace default set.
        let m = HoneypotMatcher::with_defaults();
        assert!(!m.matches("/phpmyadmin/index.php"));
        assert!(!m.matches("/wp-login.php"));
        assert!(!m.matches("/admin.php"));
        assert!(!m.matches("/server-status"));
        assert!(!m.matches("/etc/passwd"));
        assert!(!m.matches("/.env.local"));
        assert!(!m.matches("/.env.production"));
        assert!(!m.matches("/.aws/credentials"));
        assert!(!m.matches("/.ssh/authorized_keys"));
    }

    #[test]
    fn operator_can_extend_pattern_set() {
        // Operators who want broader scanner-target coverage configure
        // it via from_patterns at config-load time.
        let m = HoneypotMatcher::from_patterns([
            "/.env",
            "/.git/*",
            "/wp-admin/*",
            "/phpmyadmin/*",
            "/wp-login.php",
        ]);
        assert!(m.matches("/.env"));
        assert!(m.matches("/.git/HEAD"));
        assert!(m.matches("/wp-admin/setup-config.php"));
        assert!(m.matches("/phpmyadmin/index.php"));
        assert!(m.matches("/wp-login.php"));
    }

    #[test]
    fn case_sensitive_matching() {
        let m = HoneypotMatcher::with_defaults();
        // /.env and /.ENV are distinct paths per RFC 7230 §2.7.3.
        assert!(m.matches("/.env"));
        assert!(!m.matches("/.ENV"));
        assert!(m.matches("/wp-admin/foo"));
        assert!(!m.matches("/WP-ADMIN/foo"));
    }

    #[test]
    fn glob_does_not_match_root() {
        // `/.git/*` should NOT match `/.git` (no trailing slash) — the
        // pattern requires a sub-path.
        let m = HoneypotMatcher::with_defaults();
        assert!(!m.matches("/.git"));
        assert!(m.matches("/.git/"));
        assert!(m.matches("/.git/HEAD"));
    }

    #[test]
    fn glob_matches_deep_subpaths() {
        let m = HoneypotMatcher::with_defaults();
        assert!(m.matches("/.git/refs/heads/main"));
        assert!(m.matches("/wp-admin/includes/plugin.php"));
    }

    #[test]
    fn glob_matches_query_bearing_paths_against_default_set() {
        // Coverage contract: scanners commonly probe with query strings
        // (e.g. `/wp-admin/admin-ajax.php?action=...`).  The matcher
        // documents that callers MUST strip query strings before
        // calling, but if a caller forgets, the unsplit string still
        // starts with the configured prefix and the match fires —
        // accept-on-the-side-of-blocking-an-attacker is the v0.1
        // posture.  This test pins the behaviour against the default
        // set so a future change that flips the matcher to refuse
        // query-bearing inputs is caught.
        let m = HoneypotMatcher::with_defaults();
        assert!(m.matches("/wp-admin/admin-ajax.php?action=heartbeat"));
        assert!(m.matches("/.git/HEAD?refresh=1"));
    }

    #[test]
    fn operator_extension_handles_query_bearing_phpmyadmin_probe() {
        // When operators opt-in to phpMyAdmin coverage (it's NOT a
        // workspace default — see defaults_do_not_extend_beyond_plan_u12_set),
        // a query-bearing probe must still register.
        let m = HoneypotMatcher::from_patterns(["/phpmyadmin/*"]);
        assert!(m.matches("/phpmyadmin/sql.php?action=insert"));
        assert!(m.matches("/phpmyadmin/index.php"));
    }

    #[test]
    fn from_patterns_drops_invalid_entries() {
        let m = HoneypotMatcher::from_patterns([
            "/valid",
            "",                 // empty
            "no-leading-slash", // not path-shaped
            "  /also-valid  ",  // whitespace trimmed
            "/*",               // catch-all refused
            "/glob/*",          // valid glob
        ]);
        assert_eq!(m.exact_pattern_count(), 2, "/valid + /also-valid");
        assert_eq!(m.prefix_pattern_count(), 1, "/glob/*");
        assert!(m.matches("/valid"));
        assert!(m.matches("/also-valid"));
        assert!(m.matches("/glob/anything"));
        assert!(!m.matches("/anything-else"));
    }

    #[test]
    fn empty_pattern_set_matches_nothing() {
        let m = HoneypotMatcher::from_patterns(std::iter::empty::<&str>());
        assert_eq!(m.exact_pattern_count(), 0);
        assert_eq!(m.prefix_pattern_count(), 0);
        assert!(!m.matches("/.env"));
        assert!(!m.matches("/anything"));
    }

    #[test]
    fn default_impl_uses_workspace_defaults() {
        let m = HoneypotMatcher::default();
        let m2 = HoneypotMatcher::with_defaults();
        assert_eq!(m.exact_pattern_count(), m2.exact_pattern_count());
        assert_eq!(m.prefix_pattern_count(), m2.prefix_pattern_count());
    }

    #[test]
    fn prefix_match_requires_exact_segment_boundary() {
        // `/wp-admin/*` must match `/wp-admin/foo` but NOT a
        // path that merely starts with `/wp-admin` (e.g.
        // `/wp-administrator-spelled-differently`).  The compiled
        // prefix carries the trailing slash, so `starts_with` does
        // the right thing.
        let m = HoneypotMatcher::with_defaults();
        assert!(m.matches("/wp-admin/foo"));
        assert!(!m.matches("/wp-administrator-something"));
    }

    #[test]
    fn workspace_default_set_matches_plan_u12() {
        // Plan U12 §Approach names exactly three default patterns:
        // /.env, /.git/*, /wp-admin/*.  Any change to this set is an
        // ADR-0007 amendment surface (workspace defaults are pinned;
        // operators extend via from_patterns).
        assert_eq!(
            HONEYPOT_DEFAULT_PATTERNS.len(),
            3,
            "defaults must match plan U12 — extend via from_patterns, not const"
        );
        assert!(HONEYPOT_DEFAULT_PATTERNS.contains(&"/.env"));
        assert!(HONEYPOT_DEFAULT_PATTERNS.contains(&"/.git/*"));
        assert!(HONEYPOT_DEFAULT_PATTERNS.contains(&"/wp-admin/*"));
    }
}
