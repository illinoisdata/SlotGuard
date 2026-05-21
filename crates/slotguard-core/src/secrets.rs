//! Secret-value protection: format-preserving synthetic substitution (FPS)
//! and a session-scoped semantic entity graph (SEG).
//!
//! The structural-binding pipeline in `lib.rs` replaces user-identifying
//! values with typed handles such as `[ACCESS_TOKEN_1]`. That works well
//! when the model only needs to know "this is some token", but it leaks
//! the *category* of the value via the placeholder name. For credentials
//! we want stronger properties:
//!
//! 1. **No raw value upstream.** The exact secret never reaches the
//!    provider, even when it appears inside a URL or shell command.
//! 2. **No categorical label upstream.** The replacement looks like a
//!    real value of the same kind, not a typed placeholder, so the
//!    provider cannot trivially inventory which credential classes the
//!    user keeps locally.
//! 3. **Stable across turns of the same session.** The same raw secret
//!    must produce the same synthetic in turn 1 and turn 5; otherwise
//!    the model loses the cross-turn reference and its answer breaks.
//! 4. **Coverage of embedded / derived / cross-turn references.**
//!    `database_url=postgres://u:SECRET@host/db` and a later turn that
//!    says `re-issue the password "SECRET"` both have to be redacted
//!    even though only the first is matched directly by a regex.
//!
//! `CredentialRegistry` and `SemanticEntityGraph` together provide these
//! guarantees. The registry is the FPS layer (raw → synthetic, stable
//! within a session). The graph propagates taint along four edge types
//! (coreference / embedding / derivation / indirect) so that values
//! observed indirectly inherit the synthetic of the canonical entity.

use hmac::{Hmac, Mac};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

/// Six credential categories used by the v2 paper's Table 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CredentialCategory {
    ApiKey,
    DatabaseCredential,
    OAuthToken,
    PiiIdentifier,
    CryptographicKey,
    InternalHostname,
}

impl CredentialCategory {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::DatabaseCredential => "database_credential",
            Self::OAuthToken => "oauth_token",
            Self::PiiIdentifier => "pii_identifier",
            Self::CryptographicKey => "cryptographic_key",
            Self::InternalHostname => "internal_hostname",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::ApiKey,
            Self::DatabaseCredential,
            Self::OAuthToken,
            Self::PiiIdentifier,
            Self::CryptographicKey,
            Self::InternalHostname,
        ]
    }
}

/// One detected credential occurrence inside an input. We carry start/end
/// byte offsets so the rewriter can splice substitutions in reverse order
/// without disturbing earlier offsets.
#[derive(Debug, Clone)]
pub struct CredentialMatch {
    pub category: CredentialCategory,
    pub raw_value: String,
    pub start: usize,
    pub end: usize,
    /// How this match was discovered. Used by the SEG to decide whether
    /// the occurrence counts as a coreference, an embedding, or a derivation.
    pub origin: MatchOrigin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchOrigin {
    /// Found by the deterministic regex pass (the canonical match).
    Pattern,
    /// Found by substring search of a raw value already known to the SEG.
    Embedding,
    /// Found because the value is a derivation of a known node (e.g. the
    /// JWT signed by a known signing key) and the registry pre-bound it.
    Derivation,
    /// Found via a session ledger entry that points at a previous turn's
    /// node (e.g. cross-turn paraphrase such as "the GH token from earlier").
    Indirect,
    /// Found because the same raw value appeared verbatim in an earlier
    /// turn and is interned in the registry (cross-turn coreference).
    Coreference,
}

/// Patterns for the deterministic detector. The patterns are deliberately
/// conservative — overly broad regexes generate false positives that break
/// task anchors and hurt utility. We pair each pattern with a category so
/// FPS knows what synthetic format to emit.
fn credential_patterns() -> &'static [(CredentialCategory, &'static Regex)] {
    static PATTERNS: OnceLock<Vec<(CredentialCategory, Regex)>> = OnceLock::new();
    let owned = PATTERNS.get_or_init(|| {
        vec![
            // GitHub PATs (classic + fine-grained).
            (
                CredentialCategory::ApiKey,
                Regex::new(r"(?:^|[^A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82,})")
                    .expect("github pattern"),
            ),
            // Slack bot/user tokens.
            (
                CredentialCategory::OAuthToken,
                Regex::new(r"(?:^|[^A-Za-z0-9-])(xox[baprs]-[A-Za-z0-9-]{10,})")
                    .expect("slack pattern"),
            ),
            // OpenAI-style secret keys.
            (
                CredentialCategory::ApiKey,
                Regex::new(r"(?:^|[^A-Za-z0-9-])(sk-[A-Za-z0-9]{20,})").expect("openai pattern"),
            ),
            // AWS access key ID.
            (
                CredentialCategory::ApiKey,
                Regex::new(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})").expect("aws id pattern"),
            ),
            // JWT (header.payload.signature, base64url).
            (
                CredentialCategory::OAuthToken,
                Regex::new(r"(?:^|[^A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})")
                    .expect("jwt pattern"),
            ),
            // Postgres / MySQL / Mongo URLs with embedded credentials.
            (
                CredentialCategory::DatabaseCredential,
                Regex::new(
                    r#"((?:postgres|postgresql|mysql|mongodb|redis)://[^\s:@/]+:[^\s@/]+@[^\s/]+(?:/[^\s'"]*)?)"#,
                )
                .expect("db url pattern"),
            ),
            // PEM block (private keys). The middle group is `[A-Z ]*`
            // (zero-or-more) so we match both `BEGIN PRIVATE KEY` and
            // `BEGIN RSA PRIVATE KEY`.
            (
                CredentialCategory::CryptographicKey,
                Regex::new(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----)")
                    .expect("pem pattern"),
            ),
            // Internal-looking hostnames (e.g. acme-corp-vault.internal).
            (
                CredentialCategory::InternalHostname,
                Regex::new(r"(?:^|[^A-Za-z0-9-])([a-z0-9][a-z0-9-]*\.(?:internal|intranet|corp|local|lan)(?:\.[a-z0-9-]+)*)")
                    .expect("internal host pattern"),
            ),
            // PII identifier: simple email shape used as an identity binding.
            (
                CredentialCategory::PiiIdentifier,
                Regex::new(r"(?i)\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})\b")
                    .expect("pii email pattern"),
            ),
        ]
    });
    // We hold a static slice to a Vec<(C, Regex)>; convert to &'static [(C, &Regex)]
    // by leaking once. This trades a small amount of static storage for an
    // ergonomic call signature in the rest of the module.
    static SLICE: OnceLock<Vec<(CredentialCategory, &'static Regex)>> = OnceLock::new();
    SLICE
        .get_or_init(|| owned.iter().map(|(c, r)| (*c, r)).collect())
        .as_slice()
}

/// Run the deterministic credential detector over `input`. Returns matches
/// in **input order** (caller is responsible for reverse-splicing if it
/// wants offset stability while editing).
pub fn detect_credentials(input: &str) -> Vec<CredentialMatch> {
    let mut hits: Vec<CredentialMatch> = Vec::new();
    let mut covered: Vec<(usize, usize)> = Vec::new();

    for (category, regex) in credential_patterns() {
        for caps in regex.captures_iter(input) {
            // Patterns capture the credential in group 1 when the regex
            // includes a leading boundary class; otherwise group 0.
            let m = caps.get(1).or_else(|| caps.get(0));
            let Some(m) = m else { continue };
            let (start, end) = (m.start(), m.end());
            if covered.iter().any(|(s, e)| start < *e && *s < end) {
                // Avoid double-counting when multiple patterns overlap on
                // the same span (e.g. the JWT pattern would also tempt the
                // OAuth-bearer pattern). First match wins.
                continue;
            }
            covered.push((start, end));
            hits.push(CredentialMatch {
                category: *category,
                raw_value: m.as_str().to_string(),
                start,
                end,
                origin: MatchOrigin::Pattern,
            });
        }
    }

    hits.sort_by_key(|m| m.start);
    hits
}

/// Format-preserving synthetic substitution. The output `String` matches
/// the structural class of `original` (length, character alphabet, prefix
/// keyword) but is generated solely from the session-scoped HMAC key and
/// a stable counter, so the substitute does **not** depend on `original`'s
/// bytes. That matters for the threat model: if the synthetic were a
/// transformation of the raw value, an attacker who guesses the function
/// could invert the substitution from upstream-visible bytes alone.
pub fn format_preserving_synthetic(
    category: CredentialCategory,
    original: &str,
    session_key: &[u8],
    counter: u64,
) -> String {
    let stream = derive_stream(session_key, category, counter);
    match category {
        CredentialCategory::ApiKey => synth_api_key(original, &stream),
        CredentialCategory::OAuthToken => synth_oauth_token(original, &stream),
        CredentialCategory::DatabaseCredential => synth_database_url(original, &stream),
        CredentialCategory::CryptographicKey => synth_pem_block(original, &stream),
        CredentialCategory::InternalHostname => synth_internal_hostname(original, &stream),
        CredentialCategory::PiiIdentifier => synth_pii_identifier(original, &stream),
    }
}

fn derive_stream(session_key: &[u8], category: CredentialCategory, counter: u64) -> Vec<u8> {
    // Deterministic, session-scoped pseudo-random byte stream. We expand
    // by chained HMAC so one credential can consume an arbitrary length.
    let mut out: Vec<u8> = Vec::with_capacity(64);
    let mut block: u64 = 0;
    while out.len() < 256 {
        let mut mac = HmacSha256::new_from_slice(session_key).expect("hmac key");
        mac.update(b"slotguard.v2.fps");
        mac.update(category.label().as_bytes());
        mac.update(&counter.to_be_bytes());
        mac.update(&block.to_be_bytes());
        out.extend_from_slice(&mac.finalize().into_bytes());
        block += 1;
    }
    out
}

fn alphabet_alnum() -> &'static [u8] {
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
}
fn alphabet_lower_alnum() -> &'static [u8] {
    b"abcdefghijklmnopqrstuvwxyz0123456789"
}
fn alphabet_b64url() -> &'static [u8] {
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
}
fn alphabet_upper_alnum() -> &'static [u8] {
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
}

fn pick(stream: &[u8], offset: usize, alphabet: &[u8]) -> u8 {
    alphabet[stream[offset % stream.len()] as usize % alphabet.len()]
}

fn fill(stream: &[u8], offset: usize, len: usize, alphabet: &[u8]) -> String {
    (0..len)
        .map(|i| pick(stream, offset + i, alphabet) as char)
        .collect()
}

fn synth_api_key(original: &str, stream: &[u8]) -> String {
    if let Some(rest) = original.strip_prefix("ghp_") {
        // GitHub classic PAT: keep `ghp_` prefix, randomize the rest.
        return format!("ghp_{}", fill(stream, 0, rest.len(), alphabet_alnum()));
    }
    if let Some(rest) = original.strip_prefix("github_pat_") {
        return format!(
            "github_pat_{}",
            fill(stream, 0, rest.len(), alphabet_alnum())
        );
    }
    if let Some(rest) = original.strip_prefix("sk-") {
        return format!("sk-{}", fill(stream, 0, rest.len(), alphabet_alnum()));
    }
    if original.starts_with("AKIA") {
        return format!(
            "AKIA{}",
            fill(stream, 0, original.len() - 4, alphabet_upper_alnum())
        );
    }
    fill(stream, 0, original.len().max(20), alphabet_alnum())
}

fn synth_oauth_token(original: &str, stream: &[u8]) -> String {
    if let Some(rest) = original.strip_prefix("xoxb-") {
        return format!("xoxb-{}", fill(stream, 0, rest.len(), alphabet_alnum()));
    }
    if let Some(rest) = original.strip_prefix("xoxa-") {
        return format!("xoxa-{}", fill(stream, 0, rest.len(), alphabet_alnum()));
    }
    if let Some(rest) = original.strip_prefix("xoxp-") {
        return format!("xoxp-{}", fill(stream, 0, rest.len(), alphabet_alnum()));
    }
    if original.starts_with("eyJ") && original.matches('.').count() == 2 {
        // JWT: preserve three base64url segments with the same lengths
        // as the original. We start every segment with `eyJ` so the
        // result still parses as JWT-shaped.
        let parts: Vec<&str> = original.split('.').collect();
        let mut new_parts: Vec<String> = Vec::with_capacity(3);
        let mut offset = 0;
        for (idx, part) in parts.iter().enumerate() {
            let len = part.len();
            let chunk = if idx < 2 {
                format!(
                    "eyJ{}",
                    fill(stream, offset, len.saturating_sub(3), alphabet_b64url())
                )
            } else {
                fill(stream, offset, len, alphabet_b64url())
            };
            offset += len;
            new_parts.push(chunk);
        }
        return new_parts.join(".");
    }
    fill(stream, 0, original.len().max(20), alphabet_alnum())
}

fn synth_database_url(original: &str, stream: &[u8]) -> String {
    static URL: OnceLock<Regex> = OnceLock::new();
    let re = URL.get_or_init(|| {
        Regex::new(
            r"^(?P<scheme>postgres|postgresql|mysql|mongodb|redis)://(?P<user>[^:]+):(?P<pass>[^@]+)@(?P<host>[^:/]+)(?P<rest>(?::\d+)?(?:/.*)?)$",
        )
        .expect("db url decompose")
    });
    if let Some(caps) = re.captures(original) {
        let scheme = &caps["scheme"];
        let user_len = caps["user"].len().max(4);
        let pass_len = caps["pass"].len().max(8);
        let new_user = fill(stream, 0, user_len, alphabet_lower_alnum());
        let new_pass = fill(stream, 64, pass_len, alphabet_alnum());
        let new_host = format!(
            "db-{}.svc.synthetic",
            fill(stream, 128, 6, alphabet_lower_alnum())
        );
        return format!(
            "{scheme}://{new_user}:{new_pass}@{new_host}{}",
            &caps["rest"]
        );
    }
    fill(stream, 0, original.len().max(20), alphabet_alnum())
}

fn synth_pem_block(original: &str, stream: &[u8]) -> String {
    // Preserve the PEM frame exactly so downstream parsers can still
    // tokenize it; replace the base64 body with deterministic bytes.
    let lines: Vec<&str> = original.lines().collect();
    if lines.len() < 3 {
        return fill(stream, 0, original.len(), alphabet_b64url());
    }
    let header = lines
        .first()
        .copied()
        .unwrap_or(concat!("-----BEGIN", " PRIVATE KEY-----"));
    let footer = lines
        .last()
        .copied()
        .unwrap_or(concat!("-----END", " PRIVATE KEY-----"));
    let body_lines: Vec<String> = lines[1..lines.len() - 1]
        .iter()
        .enumerate()
        .map(|(idx, line)| fill(stream, idx * 64, line.len(), alphabet_b64url()))
        .collect();
    let mut out = String::new();
    out.push_str(header);
    out.push('\n');
    for line in body_lines {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(footer);
    out
}

fn synth_internal_hostname(original: &str, stream: &[u8]) -> String {
    // Preserve the suffix (`.internal`, `.corp`, etc.) so the model
    // still knows the role; randomize the leading host label.
    let mut parts: Vec<&str> = original.split('.').collect();
    if parts.is_empty() {
        return original.to_string();
    }
    let leading_len = parts[0].len().max(4);
    let leading = format!(
        "host-{}",
        fill(
            stream,
            0,
            leading_len.saturating_sub(5),
            alphabet_lower_alnum()
        )
    );
    parts[0] = ""; // placeholder so we can mutate parts[0]
    let mut buf = leading;
    for part in &parts[1..] {
        buf.push('.');
        buf.push_str(part);
    }
    buf
}

fn synth_pii_identifier(original: &str, stream: &[u8]) -> String {
    if let Some(at) = original.find('@') {
        let local_len = at.max(3);
        let domain = &original[at + 1..];
        let new_local = fill(stream, 0, local_len, alphabet_lower_alnum());
        // Preserve the original TLD so format-class detectors still see an email.
        let domain_parts: Vec<&str> = domain.split('.').collect();
        if domain_parts.len() >= 2 {
            let tld = domain_parts.last().copied().unwrap_or("example");
            return format!(
                "{new_local}@user-{}.{tld}",
                fill(stream, 32, 6, alphabet_lower_alnum())
            );
        }
        return format!("{new_local}@example.com");
    }
    fill(stream, 0, original.len(), alphabet_alnum())
}

// ───────────────────────────────────────────────────────── registry + graph

/// Stable raw → synthetic mapping for one session. Same raw value
/// produces the same synthetic for every turn of the session.
#[derive(Debug, Clone, Default)]
pub struct CredentialRegistry {
    session_key: Vec<u8>,
    by_raw: HashMap<String, RegistryEntry>,
    by_synth: HashMap<String, String>,
    counter: u64,
}

#[derive(Debug, Clone)]
struct RegistryEntry {
    category: CredentialCategory,
    synthetic: String,
}

impl CredentialRegistry {
    pub fn new(session_key: Vec<u8>) -> Self {
        Self {
            session_key,
            by_raw: HashMap::new(),
            by_synth: HashMap::new(),
            counter: 0,
        }
    }

    pub fn intern(&mut self, raw: &str, category: CredentialCategory) -> String {
        if let Some(entry) = self.by_raw.get(raw) {
            return entry.synthetic.clone();
        }
        self.counter += 1;
        let synthetic = format_preserving_synthetic(category, raw, &self.session_key, self.counter);
        self.by_raw.insert(
            raw.to_string(),
            RegistryEntry {
                category,
                synthetic: synthetic.clone(),
            },
        );
        self.by_synth.insert(synthetic.clone(), raw.to_string());
        synthetic
    }

    pub fn synthetic_for(&self, raw: &str) -> Option<&str> {
        self.by_raw.get(raw).map(|entry| entry.synthetic.as_str())
    }

    pub fn raw_for(&self, synthetic: &str) -> Option<&str> {
        self.by_synth.get(synthetic).map(String::as_str)
    }

    pub fn all_raw_values(&self) -> Vec<(String, CredentialCategory)> {
        let mut out: Vec<(String, CredentialCategory)> = self
            .by_raw
            .iter()
            .map(|(raw, entry)| (raw.clone(), entry.category))
            .collect();
        // Longest first so embedding scans replace the most-specific
        // value before its substrings.
        out.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        out
    }
}

/// Edge labels in the SEG. Each labelled edge tells the rewriter why a
/// node should be redacted using the synthetic of another node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SegEdge {
    Coreference,
    Embedding,
    Derivation,
    IndirectReference,
}

/// Session-scoped semantic entity graph.
///
/// Nodes are identified by their canonical raw value (the first form in
/// which the credential was seen). The graph stores the synthetic for
/// the canonical form once, then uses edges to redirect any related
/// span to the same synthetic.
#[derive(Debug, Default, Clone)]
pub struct SemanticEntityGraph {
    nodes: HashMap<String, CredentialCategory>,
    /// Direction: `from -> to` means "when we see `from` in upstream
    /// text, replace it with the synthetic registered for `to`".
    edges: BTreeMap<(String, String), SegEdge>,
    /// Strings whose presence inside a turn implies a node should be
    /// considered referenced even though no literal substring matches.
    indirect_phrases: BTreeMap<String, String>,
}

impl SemanticEntityGraph {
    pub fn add_node(&mut self, raw: &str, category: CredentialCategory) {
        self.nodes.entry(raw.to_string()).or_insert(category);
    }

    pub fn add_edge(&mut self, from: &str, to: &str, edge: SegEdge) {
        if from == to || from.is_empty() || to.is_empty() {
            return;
        }
        self.edges.insert((from.to_string(), to.to_string()), edge);
    }

    /// Register a paraphrase such as "the GitHub token I configured" that
    /// implies a reference to `node` even if the raw value is absent.
    pub fn add_indirect_phrase(&mut self, phrase: &str, node: &str) {
        if phrase.len() < 4 {
            return;
        }
        self.indirect_phrases
            .insert(phrase.to_lowercase(), node.to_string());
    }

    pub fn nodes(&self) -> impl Iterator<Item = (&String, &CredentialCategory)> {
        self.nodes.iter()
    }

    /// All `(from, to)` redirections sorted by the length of `from`
    /// descending. Splicing in this order ensures we replace the longest
    /// embedding before any of its substrings.
    pub fn redirections(&self) -> Vec<(String, String, SegEdge)> {
        let mut out: Vec<(String, String, SegEdge)> = self
            .edges
            .iter()
            .map(|((from, to), edge)| (from.clone(), to.clone(), *edge))
            .collect();
        out.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        out
    }

    pub fn indirect_phrases(&self) -> impl Iterator<Item = (&String, &String)> {
        self.indirect_phrases.iter()
    }
}

/// What the rewriter should produce when sanitizing one turn of a session.
#[derive(Debug, Clone, Copy)]
pub enum RedactionMode {
    /// No redaction. Pass-through. Used for the "no redaction" baseline.
    None,
    /// Pattern-only: detect via regex and emit a typed placeholder of the
    /// form `__API_KEY_<id>__`. Reveals the category of every value.
    PatternPlaceholder,
    /// FPS only: replace each detected credential with a format-preserving
    /// synthetic. No graph propagation.
    FormatPreserving,
    /// FPS + SEG: also propagate substitutions to embeddings, derivations,
    /// indirect references, and known cross-turn paraphrases.
    FpsWithGraph,
}

/// Sanitize one turn of `input`, mutating `registry` and `graph` so
/// subsequent turns of the same session inherit consistent substitutions.
/// Returns the sanitized string ready to be appended to the upstream payload.
pub fn sanitize_turn(
    input: &str,
    mode: RedactionMode,
    registry: &mut CredentialRegistry,
    graph: &mut SemanticEntityGraph,
) -> String {
    if matches!(mode, RedactionMode::None) {
        return input.to_string();
    }

    // 1) Pattern detection.
    let mut matches = detect_credentials(input);

    // 2) For FpsWithGraph, also scan for embeddings of nodes the SEG
    //    already knows about. We do this *before* allocating new
    //    synthetics so embeddings are consolidated under the canonical
    //    node's synthetic instead of producing a new one.
    if matches!(mode, RedactionMode::FpsWithGraph) {
        let known: Vec<(String, CredentialCategory)> = graph
            .nodes()
            .map(|(raw, category)| (raw.clone(), *category))
            .collect();
        for (raw, category) in known {
            if raw.is_empty() {
                continue;
            }
            // Skip if a pattern hit already covers this span.
            let mut start = 0;
            while let Some(rel) = input[start..].find(&raw) {
                let abs_start = start + rel;
                let abs_end = abs_start + raw.len();
                let overlaps = matches
                    .iter()
                    .any(|m| abs_start < m.end && m.start < abs_end);
                if !overlaps {
                    matches.push(CredentialMatch {
                        category,
                        raw_value: raw.clone(),
                        start: abs_start,
                        end: abs_end,
                        origin: MatchOrigin::Embedding,
                    });
                }
                start = abs_end;
            }
        }

        // Indirect phrases ("the github token from before") also redact
        // — we replace the phrase with a hint pointing to the canonical
        // node's synthetic without ever emitting the raw value.
        let indirect: Vec<(String, String)> = graph
            .indirect_phrases()
            .map(|(p, n)| (p.clone(), n.clone()))
            .collect();
        for (phrase, node_raw) in indirect {
            let lower_input = input.to_lowercase();
            let mut start = 0;
            while let Some(rel) = lower_input[start..].find(&phrase) {
                let abs_start = start + rel;
                let abs_end = abs_start + phrase.len();
                let overlaps = matches
                    .iter()
                    .any(|m| abs_start < m.end && m.start < abs_end);
                if !overlaps {
                    matches.push(CredentialMatch {
                        category: graph
                            .nodes
                            .get(&node_raw)
                            .copied()
                            .unwrap_or(CredentialCategory::ApiKey),
                        raw_value: node_raw.clone(),
                        start: abs_start,
                        end: abs_end,
                        origin: MatchOrigin::Indirect,
                    });
                }
                start = abs_end;
            }
        }

        // Derivations registered ahead of time (e.g. JWT signed by a
        // known HMAC key) are stored as edges; if a derived value
        // appears verbatim, the embedding pass above will catch it.
        // We also consult the registry's existing values so that values
        // detected in earlier turns (but not yet upgraded to nodes) are
        // still rewritten consistently in this turn.
        let known_in_registry = registry.all_raw_values();
        for (raw, category) in known_in_registry {
            if raw.is_empty() {
                continue;
            }
            let mut start = 0;
            while let Some(rel) = input[start..].find(&raw) {
                let abs_start = start + rel;
                let abs_end = abs_start + raw.len();
                let overlaps = matches
                    .iter()
                    .any(|m| abs_start < m.end && m.start < abs_end);
                if !overlaps {
                    matches.push(CredentialMatch {
                        category,
                        raw_value: raw.clone(),
                        start: abs_start,
                        end: abs_end,
                        origin: MatchOrigin::Coreference,
                    });
                }
                start = abs_end;
            }
        }
    }

    // 3) Sort matches by start; resolve overlaps by keeping the earliest
    //    longest match (longest-then-leftmost wins for equal starts).
    matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut filtered: Vec<CredentialMatch> = Vec::with_capacity(matches.len());
    let mut last_end = 0usize;
    for m in matches {
        if m.start < last_end {
            continue;
        }
        last_end = m.end;
        filtered.push(m);
    }

    // 4) Splice substitutions in reverse order to keep offsets stable.
    let mut output = input.to_string();
    let mut placeholder_counter: BTreeMap<CredentialCategory, usize> = BTreeMap::new();
    for m in filtered.iter().rev() {
        let replacement = match mode {
            RedactionMode::None => continue,
            RedactionMode::PatternPlaceholder => {
                let counter = placeholder_counter.entry(m.category).or_insert(0);
                *counter += 1;
                format!("__{}_{}__", m.category.label().to_uppercase(), counter)
            }
            RedactionMode::FormatPreserving | RedactionMode::FpsWithGraph => {
                registry.intern(&m.raw_value, m.category)
            }
        };
        output.replace_range(m.start..m.end, &replacement);
    }

    // 5) Update the SEG so future turns see today's discoveries. Only
    //    the FpsWithGraph mode touches the graph; for the other modes
    //    we keep them stateless to preserve the comparison's clarity.
    if matches!(mode, RedactionMode::FpsWithGraph) {
        for m in &filtered {
            graph.add_node(&m.raw_value, m.category);
            if matches!(m.origin, MatchOrigin::Embedding | MatchOrigin::Indirect) {
                graph.add_edge(&m.raw_value, &m.raw_value, SegEdge::Embedding);
            }
        }
        let touched: BTreeSet<String> = filtered.iter().map(|m| m.raw_value.clone()).collect();
        for value in touched {
            graph.add_edge(&value, &value, SegEdge::Coreference);
        }
    }

    output
}

/// Convenience: count how many sessions in a corpus leak at least one
/// known raw value into the sanitized output. Used by the credential
/// benchmark to compute the headline leakage rate.
pub fn count_leaked_values(sanitized: &str, known_raw: &[(String, CredentialCategory)]) -> usize {
    let mut leaked = 0usize;
    for (raw, _) in known_raw {
        if raw.len() < 8 {
            // Short literals (4-5 chars) are too noisy to credit as a
            // leak — they collide with ordinary words.
            continue;
        }
        if sanitized.contains(raw) {
            leaked += 1;
        }
    }
    leaked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        b"slotguard-test-key-do-not-use-in-prod".to_vec()
    }

    fn fake_github_token() -> String {
        ["ghp_", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"].concat()
    }

    #[test]
    fn detects_github_token_pattern() {
        let text = format!(
            "export GITHUB_TOKEN={}",
            ["ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"].concat()
        );
        let hits = detect_credentials(&text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].category, CredentialCategory::ApiKey);
        assert!(hits[0].raw_value.starts_with("ghp_"));
    }

    #[test]
    fn detects_postgres_url_with_embedded_credentials() {
        let text = "DATABASE_URL=postgres://app:hunter2@db.acme-corp.example/prod";
        let hits = detect_credentials(text);
        assert!(
            hits.iter()
                .any(|m| matches!(m.category, CredentialCategory::DatabaseCredential))
        );
    }

    #[test]
    fn fps_preserves_format_class() {
        let key = test_key();
        let original = fake_github_token();
        let synth = format_preserving_synthetic(CredentialCategory::ApiKey, &original, &key, 1);
        assert!(synth.starts_with("ghp_"));
        assert_eq!(synth.len(), original.len());
        assert_ne!(synth, original);
    }

    #[test]
    fn fps_jwt_preserves_three_segment_shape() {
        let key = test_key();
        let original = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature_chunk";
        let synth = format_preserving_synthetic(CredentialCategory::OAuthToken, original, &key, 7);
        let parts: Vec<&str> = synth.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].starts_with("eyJ"));
        assert!(parts[1].starts_with("eyJ"));
    }

    #[test]
    fn registry_returns_stable_synthetic_across_calls() {
        let mut reg = CredentialRegistry::new(test_key());
        let raw = ["ghp_", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"].concat();
        let s1 = reg.intern(&raw, CredentialCategory::ApiKey);
        let s2 = reg.intern(&raw, CredentialCategory::ApiKey);
        assert_eq!(s1, s2);
        assert_eq!(reg.synthetic_for(&raw), Some(s1.as_str()));
        assert_eq!(reg.raw_for(&s1), Some(raw.as_str()));
    }

    #[test]
    fn pattern_mode_emits_placeholder_with_category_label() {
        let mut reg = CredentialRegistry::new(test_key());
        let mut graph = SemanticEntityGraph::default();
        let secret = fake_github_token();
        let text = format!("use {secret} to push.");
        let out = sanitize_turn(
            &text,
            RedactionMode::PatternPlaceholder,
            &mut reg,
            &mut graph,
        );
        assert!(out.contains("__API_KEY_1__"));
        assert!(!out.contains(&secret));
    }

    #[test]
    fn fps_mode_replaces_with_format_preserving_synthetic() {
        let mut reg = CredentialRegistry::new(test_key());
        let mut graph = SemanticEntityGraph::default();
        let secret = fake_github_token();
        let text = format!("use {secret} to push.");
        let out = sanitize_turn(&text, RedactionMode::FormatPreserving, &mut reg, &mut graph);
        assert!(out.contains("ghp_"));
        assert!(!out.contains(&secret));
        assert!(!out.contains("__API_KEY_"));
    }

    #[test]
    fn graph_mode_redacts_cross_turn_embedding() {
        let mut reg = CredentialRegistry::new(test_key());
        let mut graph = SemanticEntityGraph::default();
        let secret = fake_github_token();
        let turn1 = format!("export GH_TOKEN={secret}");
        let turn2 = format!("the URL https://x:{secret}@github.com is embedded");
        let _ = sanitize_turn(&turn1, RedactionMode::FpsWithGraph, &mut reg, &mut graph);
        let out2 = sanitize_turn(&turn2, RedactionMode::FpsWithGraph, &mut reg, &mut graph);
        assert!(!out2.contains(&secret));
    }

    #[test]
    fn graph_mode_redacts_indirect_reference() {
        let mut reg = CredentialRegistry::new(test_key());
        let mut graph = SemanticEntityGraph::default();
        let secret = fake_github_token();
        let turn1 = format!("export GH_TOKEN={secret}");
        let _ = sanitize_turn(&turn1, RedactionMode::FpsWithGraph, &mut reg, &mut graph);
        graph.add_indirect_phrase("the github token i set earlier", &secret);
        let turn2 = "Please reuse the GitHub token I set earlier for this push.";
        let out2 = sanitize_turn(turn2, RedactionMode::FpsWithGraph, &mut reg, &mut graph);
        assert!(
            !out2
                .to_lowercase()
                .contains("the github token i set earlier")
        );
    }

    #[test]
    fn count_leaked_values_skips_short_strings() {
        let known = vec![
            ("ab".to_string(), CredentialCategory::ApiKey),
            (
                ["ghp_", "realsecretvalue123"].concat(),
                CredentialCategory::ApiKey,
            ),
        ];
        let sanitized = "ab is fine but ghp_realsecretvalue123 should count";
        assert_eq!(count_leaked_values(sanitized, &known), 1);
    }
}
