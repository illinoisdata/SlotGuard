use hmac::{Hmac, Mac};
use rand::RngCore;
use regex::Regex;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub mod secrets;
pub use secrets::{
    CredentialCategory, CredentialMatch, CredentialRegistry, MatchOrigin, RedactionMode, SegEdge,
    SemanticEntityGraph, count_leaked_values, detect_credentials, format_preserving_synthetic,
    sanitize_turn,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SlotType {
    UserHome,
    WorkspaceRoot,
    RepoRoot,
    Email,
    InternalHost,
    BranchName,
    AccessToken,
    SensitivePathSegment,
    SensitiveDocument,
}

impl SlotType {
    pub fn public_label(self) -> &'static str {
        match self {
            Self::UserHome => "USER_HOME",
            Self::WorkspaceRoot => "WORKSPACE_ROOT",
            Self::RepoRoot => "REPO_ROOT",
            Self::Email => "EMAIL",
            Self::InternalHost => "INTERNAL_HOST",
            Self::BranchName => "BRANCH_NAME",
            Self::AccessToken => "ACCESS_TOKEN",
            Self::SensitivePathSegment => "SENSITIVE_PATH_SEGMENT",
            Self::SensitiveDocument => "SENSITIVE_DOC",
        }
    }

    pub fn from_public_value(public_value: &str) -> Option<Self> {
        let close = public_value.find(']')?;
        let bracketed = &public_value[..=close];
        let trimmed = bracketed.strip_prefix('[')?.strip_suffix(']')?;
        let label = trimmed.rsplit_once('_')?.0;
        match label {
            "USER_HOME" => Some(Self::UserHome),
            "WORKSPACE_ROOT" => Some(Self::WorkspaceRoot),
            "REPO_ROOT" => Some(Self::RepoRoot),
            "EMAIL" => Some(Self::Email),
            "INTERNAL_HOST" => Some(Self::InternalHost),
            "BRANCH_NAME" => Some(Self::BranchName),
            "ACCESS_TOKEN" => Some(Self::AccessToken),
            "SENSITIVE_PATH_SEGMENT" => Some(Self::SensitivePathSegment),
            "SENSITIVE_DOC" => Some(Self::SensitiveDocument),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlotSource {
    Detected,
    Configured,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticMode {
    Off,
    Local,
    OrgInternal,
}

impl SemanticMode {
    pub fn from_config_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "local" => Some(Self::Local),
            "org_internal" | "org-internal" => Some(Self::OrgInternal),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticApiStyle {
    OpenAiChat,
    AnthropicMessages,
}

impl SemanticApiStyle {
    pub fn from_config_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai_chat" | "openai-chat" => Some(Self::OpenAiChat),
            "anthropic_messages" | "anthropic-messages" => Some(Self::AnthropicMessages),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticTaskKind {
    TextSpan,
    Filename,
}

impl SemanticTaskKind {
    pub fn from_config_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text_span" | "text-span" | "text" => Some(Self::TextSpan),
            "filename" | "file_name" | "file-name" => Some(Self::Filename),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticConfig {
    pub mode: SemanticMode,
    pub api_style: SemanticApiStyle,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub api_key_env: Option<String>,
    pub timeout_ms: u64,
    pub max_input_chars: usize,
}

impl Default for SemanticConfig {
    fn default() -> Self {
        Self {
            mode: SemanticMode::Off,
            api_style: SemanticApiStyle::OpenAiChat,
            endpoint: None,
            model: None,
            api_key_env: None,
            timeout_ms: 5_000,
            max_input_chars: 2_000,
        }
    }
}

impl SemanticConfig {
    pub fn is_enabled(&self) -> bool {
        !matches!(self.mode, SemanticMode::Off) && self.endpoint.is_some() && self.model.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticProposal {
    pub span: String,
    pub slot_type: SlotType,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Error)]
pub enum SemanticClientError {
    #[error("semantic mode is disabled or not configured")]
    Disabled,
    #[error("semantic provider endpoint is missing")]
    MissingEndpoint,
    #[error("semantic provider model is missing")]
    MissingModel,
    #[error("semantic request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("semantic response parse failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("semantic provider returned no assistant content")]
    MissingContent,
    #[error("semantic provider response was not valid JSON: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, Deserialize)]
struct SemanticEnvelope {
    #[serde(default)]
    proposals: Vec<SemanticProposal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Slot {
    pub id: String,
    pub slot_type: SlotType,
    pub raw_value: String,
    pub public_value: String,
    pub source: SlotSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub workspace_roots: Vec<PathBuf>,
    pub repo_roots: Vec<PathBuf>,
    pub preserve_path_suffix_segments: usize,
    pub abstract_sensitive_filenames: bool,
    pub preserve_extensions: bool,
    pub allow_shell: bool,
    pub allowed_shell_commands: Vec<String>,
    pub sensitive_keywords: Vec<String>,
    pub internal_host_suffixes: Vec<String>,
    pub semantic: SemanticConfig,
    #[serde(skip, default = "default_slot_lookup_key")]
    slot_lookup_key: Vec<u8>,
}

/// A session-scoped persistence handle. Holds the on-disk directory,
/// a per-session HMAC key, and an opaque session identifier. The
/// SessionContext mediates two pieces of P0 state: the random key
/// that derives slot handles, and the slot table snapshot/audit log.
#[derive(Debug, Clone)]
pub struct SessionContext {
    pub session_id: String,
    pub session_dir: PathBuf,
    pub slot_lookup_key: Vec<u8>,
}

impl SessionContext {
    /// Resolve a session under `~/.slotguard/sessions/{session_id}`.
    /// Generates a 32-byte random key on first use and persists it
    /// with 0600 permissions. Re-reads the existing key on subsequent
    /// calls so handles remain stable across process restarts.
    pub fn create_or_load(session_id: impl Into<String>) -> Result<Self> {
        let session_id = session_id.into();
        let base = config_base_dir()?;
        Self::create_or_load_in(&base, session_id)
    }

    /// Same as [`create_or_load`] but lets callers override the
    /// configuration root, which is useful for tests and experiments
    /// where we don't want to touch the user's real home directory.
    pub fn create_or_load_in(base: &Path, session_id: impl Into<String>) -> Result<Self> {
        let session_id = session_id.into();
        if session_id.is_empty()
            || session_id
                .chars()
                .any(|ch| matches!(ch, '/' | '\\') || ch.is_control())
        {
            return Err(SlotGuardError::InvalidSessionId(session_id));
        }
        let session_dir = base.join("sessions").join(&session_id);
        fs::create_dir_all(&session_dir)?;
        // Restrict directory perms; best-effort on platforms that
        // don't support unix permissions.
        let _ = set_restrictive_dir_perms(&session_dir);
        let key_path = session_dir.join("session_key");
        let slot_lookup_key = if key_path.exists() {
            let bytes = fs::read(&key_path)?;
            if bytes.len() < 16 {
                return Err(SlotGuardError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "session key file is shorter than 16 bytes",
                )));
            }
            bytes
        } else {
            let mut bytes = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            write_secret_file(&key_path, &bytes)?;
            bytes
        };
        Ok(Self {
            session_id,
            session_dir,
            slot_lookup_key,
        })
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            workspace_roots: Vec::new(),
            repo_roots: Vec::new(),
            preserve_path_suffix_segments: 3,
            abstract_sensitive_filenames: true,
            preserve_extensions: true,
            allow_shell: false,
            allowed_shell_commands: vec![
                "pwd".to_string(),
                "ls".to_string(),
                "cat".to_string(),
                "grep".to_string(),
                "rg".to_string(),
                "git status".to_string(),
                "git branch".to_string(),
            ],
            sensitive_keywords: builtin_sensitive_keywords()
                .iter()
                .map(|value| value.to_string())
                .collect(),
            internal_host_suffixes: builtin_internal_host_suffixes()
                .iter()
                .map(|value| value.to_string())
                .collect(),
            semantic: SemanticConfig::default(),
            slot_lookup_key: default_slot_lookup_key(),
        }
    }
}

impl Policy {
    pub fn for_workspace(workspace_root: impl Into<PathBuf>) -> Self {
        let workspace_root = workspace_root.into();
        Self {
            workspace_roots: vec![workspace_root.clone()],
            repo_roots: vec![workspace_root],
            ..Self::default()
        }
    }

    pub fn load_from_toml(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: ConfigFile = toml::from_str(&contents)?;
        Ok(config.into_policy())
    }

    /// Bind this policy to a session: the slot lookup key becomes the
    /// session-specific random key from disk, so handles are stable
    /// across restarts within a session and unlinkable across sessions.
    pub fn bind_session(&mut self, session: &SessionContext) {
        self.slot_lookup_key = session.slot_lookup_key.clone();
    }

    pub fn is_shell_enabled(&self) -> bool {
        self.allow_shell
    }

    pub fn semantic_enabled(&self) -> bool {
        self.semantic.is_enabled()
    }

    fn slot_key(&self, slot_type: SlotType, raw_value: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.slot_lookup_key).expect("static HMAC key is valid");
        mac.update(slot_type.public_label().as_bytes());
        mac.update(&[0]);
        mac.update(raw_value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SlotTableSnapshot {
    by_public: HashMap<String, Slot>,
    by_raw_hash: HashMap<String, String>,
    counters: BTreeMap<SlotType, usize>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SlotTable {
    by_public: HashMap<String, Slot>,
    by_raw_hash: HashMap<String, String>,
    counters: BTreeMap<SlotType, usize>,
    #[serde(skip)]
    persistence: Option<TablePersistence>,
}

#[derive(Debug, Clone)]
struct TablePersistence {
    dir: PathBuf,
}

impl TablePersistence {
    fn append_event(&self, slot: &Slot) -> std::io::Result<()> {
        let log = self.dir.join("slots.jsonl");
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let line = json!({
            "ts": timestamp,
            "event": "slot_created",
            "slot": slot,
        })
        .to_string();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        Ok(())
    }

    fn write_index(&self, snapshot: &SlotTableSnapshot) -> std::io::Result<()> {
        let path = self.dir.join("index.json");
        let tmp = self.dir.join("index.json.tmp");
        let bytes = serde_json::to_vec_pretty(snapshot)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

impl SlotTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a SlotTable bound to a session directory. Replays any existing
    /// `index.json` so repeated `ensure_slot` calls return stable handles
    /// across process restarts.
    pub fn with_session(ctx: &SessionContext) -> Result<Self> {
        let dir = ctx.session_dir.clone();
        fs::create_dir_all(&dir)?;
        let mut table = if let Ok(bytes) = fs::read(dir.join("index.json")) {
            let snapshot: SlotTableSnapshot = serde_json::from_slice(&bytes).map_err(|err| {
                SlotGuardError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
            })?;
            Self {
                by_public: snapshot.by_public,
                by_raw_hash: snapshot.by_raw_hash,
                counters: snapshot.counters,
                persistence: None,
            }
        } else {
            Self::default()
        };
        table.persistence = Some(TablePersistence { dir });
        Ok(table)
    }

    pub fn ensure_slot(
        &mut self,
        policy: &Policy,
        slot_type: SlotType,
        raw_value: impl Into<String>,
        source: SlotSource,
    ) -> Slot {
        let raw_value = raw_value.into();
        let raw_hash = policy.slot_key(slot_type, &raw_value);
        if let Some(public_value) = self.by_raw_hash.get(&raw_hash) {
            if let Some(slot) = self.by_public.get(public_value) {
                return slot.clone();
            }
        }

        let counter = self.counters.entry(slot_type).or_insert(0);
        *counter += 1;
        let id = format!("{}_{}", slot_type.public_label(), counter);
        let public_value = match slot_type {
            SlotType::SensitiveDocument => {
                let extension = Path::new(&raw_value)
                    .extension()
                    .and_then(|value| value.to_str())
                    .filter(|value| !value.is_empty())
                    .map(|value| format!(".{value}"))
                    .unwrap_or_default();
                format!("[{id}]{extension}")
            }
            _ => format!("[{id}]"),
        };
        let slot = Slot {
            id,
            slot_type,
            raw_value,
            public_value: public_value.clone(),
            source,
        };
        self.by_raw_hash.insert(raw_hash, public_value.clone());
        self.by_public.insert(public_value, slot.clone());
        self.persist_after_change(&slot);
        slot
    }

    pub fn register_public_binding(
        &mut self,
        policy: &Policy,
        public_value: impl Into<String>,
        raw_value: impl Into<String>,
        source: SlotSource,
    ) -> Result<Slot> {
        let public_value = public_value.into();
        let raw_value = raw_value.into();
        let slot_type = SlotType::from_public_value(&public_value)
            .ok_or_else(|| SlotGuardError::InvalidBinding(public_value.clone()))?;
        let raw_hash = policy.slot_key(slot_type, &raw_value);
        let slot = Slot {
            id: public_value
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or_default()
                .to_string(),
            slot_type,
            raw_value,
            public_value: public_value.clone(),
            source,
        };
        self.by_raw_hash.insert(raw_hash, public_value.clone());
        self.by_public.insert(public_value, slot.clone());
        let counter = self.counters.entry(slot_type).or_insert(0);
        if let Some(index) = slot
            .id
            .rsplit_once('_')
            .and_then(|(_, value)| value.parse::<usize>().ok())
        {
            *counter = (*counter).max(index);
        }
        self.persist_after_change(&slot);
        Ok(slot)
    }

    pub fn get_public(&self, public_value: &str) -> Option<&Slot> {
        self.by_public.get(public_value)
    }

    pub fn slots(&self) -> Vec<Slot> {
        let mut values: Vec<_> = self.by_public.values().cloned().collect();
        values.sort_by(|left, right| left.public_value.cmp(&right.public_value));
        values
    }

    pub fn summary_lines(&self) -> Vec<String> {
        self.slots()
            .into_iter()
            .map(|slot| format!("{} -> {}", slot.public_value, describe_slot(&slot)))
            .collect()
    }

    fn snapshot(&self) -> SlotTableSnapshot {
        SlotTableSnapshot {
            by_public: self.by_public.clone(),
            by_raw_hash: self.by_raw_hash.clone(),
            counters: self.counters.clone(),
        }
    }

    fn persist_after_change(&self, slot: &Slot) {
        if let Some(persistence) = &self.persistence {
            // Persistence is best-effort; on errors we fail open and keep
            // serving the in-memory table so the agent run is not aborted.
            let _ = persistence.append_event(slot);
            let _ = persistence.write_index(&self.snapshot());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub tool: String,
    pub target: String,
    pub decision: String,
    pub raw_exposed_upstream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCommand {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SlotGuardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("path `{0}` is outside the configured workspace or home scope")]
    OutsideScope(String),
    #[error("placeholder `{0}` is unknown")]
    UnknownPlaceholder(String),
    #[error("placeholder `{0}` cannot be rebound safely")]
    InvalidPlaceholder(String),
    #[error("path traversal is not allowed: {0}")]
    Traversal(String),
    #[error("no workspace root is configured for relative path `{0}`")]
    MissingWorkspaceRoot(String),
    #[error("shell command `{0}` is not allowed by policy")]
    InvalidShellCommand(String),
    #[error("shell access is disabled by policy")]
    ShellDisabled,
    #[error("binding `{0}` is not a valid SlotGuard placeholder")]
    InvalidBinding(String),
    #[error("session id `{0}` contains forbidden characters")]
    InvalidSessionId(String),
    #[error("cannot determine SlotGuard config directory; set HOME or SLOTGUARD_HOME")]
    NoConfigDir,
}

pub type Result<T> = std::result::Result<T, SlotGuardError>;

pub fn abstract_text(input: &str, policy: &Policy, slots: &mut SlotTable) -> String {
    let mut output = replace_path_matches(input, policy, slots);
    output = replace_matches(email_regex(), &output, |candidate| {
        let slot = slots.ensure_slot(
            policy,
            SlotType::Email,
            candidate.to_string(),
            SlotSource::Detected,
        );
        Some(slot.public_value)
    });
    output = replace_deterministic_secret_patterns(&output, policy, slots);
    output = replace_internal_hosts(&output, policy, slots);
    apply_semantic_text_proposals(&output, policy, slots)
}

pub fn abstract_branch_name(name: &str, policy: &Policy, slots: &mut SlotTable) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }
    let slot = slots.ensure_slot(
        policy,
        SlotType::BranchName,
        trimmed.to_string(),
        SlotSource::Detected,
    );
    slot.public_value
}

pub fn abstract_path(path: &Path, policy: &Policy, slots: &mut SlotTable) -> Result<String> {
    let normalized = normalize_input_path(path)?;
    let display_path = path_to_string(&normalized);

    if let Some(root) = longest_matching_root(&normalized, &policy.repo_roots) {
        return abstract_with_root(&normalized, root, SlotType::RepoRoot, false, policy, slots);
    }

    if let Some(root) = longest_matching_root(&normalized, &policy.workspace_roots) {
        return abstract_with_root(
            &normalized,
            root,
            SlotType::WorkspaceRoot,
            false,
            policy,
            slots,
        );
    }

    if let Some(home_dir) = home_dir() {
        if normalized.starts_with(&home_dir) {
            return abstract_with_root(
                &normalized,
                &home_dir,
                SlotType::UserHome,
                true,
                policy,
                slots,
            );
        }
    }

    if normalized.is_absolute() {
        let components = relative_components(&normalized);
        let parts = abstract_suffix_with_hidden_prefix(components, policy, slots);
        if parts.is_empty() {
            return Err(SlotGuardError::OutsideScope(display_path));
        }
        return Ok(parts.join("/"));
    }

    Err(SlotGuardError::OutsideScope(display_path))
}

pub fn resolve_input_path(input: &str, policy: &Policy, slots: &SlotTable) -> Result<PathBuf> {
    if input.contains('[') {
        rebind_path(input, policy, slots)
    } else {
        let raw = PathBuf::from(input);
        let resolved = if raw.is_absolute() {
            raw
        } else {
            let workspace_root = policy
                .workspace_roots
                .first()
                .cloned()
                .ok_or_else(|| SlotGuardError::MissingWorkspaceRoot(input.to_string()))?;
            workspace_root.join(raw)
        };
        normalize_input_path(&resolved).and_then(|path| {
            validate_scope(&path, policy)?;
            Ok(path)
        })
    }
}

pub fn rebind_path(input: &str, policy: &Policy, slots: &SlotTable) -> Result<PathBuf> {
    let mut rebuilt_segments = Vec::new();
    let mut absolute = input.starts_with('/');

    for segment in input.split('/') {
        if segment.is_empty() {
            continue;
        }
        if segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(SlotGuardError::Traversal(input.to_string()));
        }
        if let Some(slot) = slots.get_public(segment) {
            if Path::new(&slot.raw_value).is_absolute() {
                absolute = true;
            }
            for piece in slot.raw_value.split('/').filter(|piece| !piece.is_empty()) {
                rebuilt_segments.push(piece.to_string());
            }
            continue;
        }
        if looks_like_placeholder(segment) {
            return Err(SlotGuardError::UnknownPlaceholder(segment.to_string()));
        }
        // Any segment that contains stray bracket characters is considered
        // suspicious: it might be a malformed placeholder, a spoofed
        // handle, a path that smuggles slot syntax, or a literal filename
        // with brackets that we cannot disambiguate. We refuse to rebind
        // rather than treat it as a literal path component.
        if segment.contains('[') || segment.contains(']') {
            return Err(SlotGuardError::InvalidPlaceholder(segment.to_string()));
        }
        // Reject backslash escapes commonly used for traversal on
        // mixed-platform inputs ("..\\..\\etc").
        if segment.contains('\\') {
            return Err(SlotGuardError::InvalidPlaceholder(segment.to_string()));
        }
        // Refuse control characters in segments, which can obscure
        // human review and confuse downstream tools.
        if segment.chars().any(|ch| ch.is_control()) {
            return Err(SlotGuardError::InvalidPlaceholder(segment.to_string()));
        }
        rebuilt_segments.push(segment.to_string());
    }

    let candidate = if absolute {
        format!("/{}", rebuilt_segments.join("/"))
    } else {
        rebuilt_segments.join("/")
    };
    if !absolute && rebuilt_segments.is_empty() {
        return Err(SlotGuardError::InvalidPlaceholder(input.to_string()));
    }
    let path = normalize_input_path(Path::new(&candidate))?;
    validate_scope(&path, policy)?;
    Ok(path)
}

pub fn validate_shell_command(command: &str, policy: &Policy) -> Result<ShellCommand> {
    if !policy.is_shell_enabled() {
        return Err(SlotGuardError::ShellDisabled);
    }
    if command.contains(';')
        || command.contains('|')
        || command.contains('&')
        || command.contains('`')
        || command.contains('$')
    {
        return Err(SlotGuardError::InvalidShellCommand(command.to_string()));
    }

    let parts: Vec<String> = command
        .split_whitespace()
        .map(ToString::to_string)
        .collect();
    if parts.is_empty() {
        return Err(SlotGuardError::InvalidShellCommand(command.to_string()));
    }

    let candidate = if parts[0] == "git" && parts.len() > 1 {
        format!("git {}", parts[1])
    } else {
        parts[0].clone()
    };

    if !policy
        .allowed_shell_commands
        .iter()
        .any(|allowed| allowed == &candidate)
    {
        return Err(SlotGuardError::InvalidShellCommand(command.to_string()));
    }

    let args = if candidate == "git status" || candidate == "git branch" {
        parts[1..].to_vec()
    } else {
        parts[1..].to_vec()
    };
    Ok(ShellCommand {
        program: parts[0].clone(),
        args,
    })
}

pub fn describe_slot(slot: &Slot) -> String {
    match slot.slot_type {
        SlotType::UserHome => "user home".to_string(),
        SlotType::WorkspaceRoot => "workspace root".to_string(),
        SlotType::RepoRoot => "repo root".to_string(),
        SlotType::Email => "email address".to_string(),
        SlotType::InternalHost => "internal host".to_string(),
        SlotType::BranchName => "git branch".to_string(),
        SlotType::AccessToken => "access token".to_string(),
        SlotType::SensitivePathSegment => "sensitive path segment".to_string(),
        SlotType::SensitiveDocument => "sensitive document filename".to_string(),
    }
}

pub fn semantic_detect(
    input: &str,
    task: SemanticTaskKind,
    policy: &Policy,
) -> std::result::Result<Vec<SemanticProposal>, SemanticClientError> {
    if !policy.semantic_enabled() {
        return Err(SemanticClientError::Disabled);
    }
    if input.is_empty() || input.len() > policy.semantic.max_input_chars {
        return Ok(Vec::new());
    }
    if let Some(cached) = lookup_semantic_cache(task, input) {
        return Ok(cached);
    }

    let endpoint = policy
        .semantic
        .endpoint
        .as_deref()
        .ok_or(SemanticClientError::MissingEndpoint)?;
    let model = policy
        .semantic
        .model
        .as_deref()
        .ok_or(SemanticClientError::MissingModel)?;
    let prompt = build_semantic_prompt(input, task);
    let client = Client::builder()
        .timeout(Duration::from_millis(policy.semantic.timeout_ms))
        .build()?;

    let request_body = match policy.semantic.api_style {
        SemanticApiStyle::OpenAiChat => json!({
            "model": model,
            "temperature": 0,
            "response_format": { "type": "json_object" },
            "messages": [
                {
                    "role": "system",
                    "content": "You are a SlotGuard semantic classifier. Return JSON only."
                },
                {
                    "role": "user",
                    "content": prompt,
                }
            ]
        }),
        SemanticApiStyle::AnthropicMessages => json!({
            "model": model,
            "temperature": 0,
            "max_tokens": 512,
            "system": "You are a SlotGuard semantic classifier. Return JSON only.",
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ]
        }),
    };

    let mut request = client.post(endpoint).json(&request_body);
    if matches!(
        policy.semantic.api_style,
        SemanticApiStyle::AnthropicMessages
    ) {
        request = request.header("anthropic-version", "2023-06-01");
    }
    if let Some(api_key_env) = policy.semantic.api_key_env.as_deref() {
        if !api_key_env.is_empty() {
            if let Some(api_key) =
                env::var_os(api_key_env).and_then(|value| value.into_string().ok())
            {
                request = match policy.semantic.api_style {
                    SemanticApiStyle::OpenAiChat => request.bearer_auth(api_key),
                    SemanticApiStyle::AnthropicMessages => request.header("x-api-key", api_key),
                };
            }
        }
    }

    let response = request.send()?.error_for_status()?.json::<Value>()?;
    let content = extract_semantic_response_text(&response, policy.semantic.api_style)?;
    let payload = extract_json_object(&content).unwrap_or(content);
    let envelope: SemanticEnvelope = serde_json::from_str(&payload)?;
    let proposals = verify_semantic_proposals(input, task, envelope.proposals);
    store_semantic_cache(task, input, &proposals);
    Ok(proposals)
}

fn semantic_cache() -> &'static Mutex<HashMap<(SemanticTaskKind, String), Vec<SemanticProposal>>> {
    static CACHE: OnceLock<Mutex<HashMap<(SemanticTaskKind, String), Vec<SemanticProposal>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lookup_semantic_cache(task: SemanticTaskKind, input: &str) -> Option<Vec<SemanticProposal>> {
    let guard = semantic_cache().lock().ok()?;
    guard.get(&(task, input.to_string())).cloned()
}

fn store_semantic_cache(task: SemanticTaskKind, input: &str, proposals: &[SemanticProposal]) {
    if let Ok(mut guard) = semantic_cache().lock() {
        if guard.len() >= 1024 {
            // Bound the cache. Cheapest eviction: clear and start over.
            guard.clear();
        }
        guard.insert((task, input.to_string()), proposals.to_vec());
    }
}

/// Forget any cached semantic proposals. Useful at the start of a new
/// agent session and in tests that want deterministic HTTP behavior.
pub fn clear_semantic_cache() {
    if let Ok(mut guard) = semantic_cache().lock() {
        guard.clear();
    }
}

fn abstract_with_root(
    full_path: &Path,
    root: &Path,
    slot_type: SlotType,
    collapse_hidden_prefix: bool,
    policy: &Policy,
    slots: &mut SlotTable,
) -> Result<String> {
    let root_slot = slots.ensure_slot(
        policy,
        slot_type,
        path_to_string(root),
        SlotSource::Detected,
    );
    let relative = full_path
        .strip_prefix(root)
        .unwrap_or_else(|_| Path::new(""));
    let components = relative_components(relative);
    if components.is_empty() {
        return Ok(root_slot.public_value);
    }

    let parts = if collapse_hidden_prefix {
        abstract_suffix_with_hidden_prefix(components, policy, slots)
    } else {
        abstract_components(components, policy, slots)
    };

    if parts.is_empty() {
        Ok(root_slot.public_value)
    } else {
        Ok(format!("{}/{}", root_slot.public_value, parts.join("/")))
    }
}

fn abstract_suffix_with_hidden_prefix(
    mut components: Vec<String>,
    policy: &Policy,
    slots: &mut SlotTable,
) -> Vec<String> {
    if components.is_empty() {
        return components;
    }
    let keep = policy.preserve_path_suffix_segments.min(components.len());
    let hidden_len = components.len().saturating_sub(keep);
    let mut output = Vec::new();
    if hidden_len > 0 {
        let hidden = components.drain(..hidden_len).collect::<Vec<_>>().join("/");
        if !hidden.is_empty() {
            let hidden_slot = slots.ensure_slot(
                policy,
                SlotType::SensitivePathSegment,
                hidden,
                SlotSource::Detected,
            );
            output.push(hidden_slot.public_value);
        }
    }
    output.extend(abstract_components(components, policy, slots));
    output
}

fn abstract_components(
    components: Vec<String>,
    policy: &Policy,
    slots: &mut SlotTable,
) -> Vec<String> {
    let len = components.len();
    components
        .into_iter()
        .enumerate()
        .map(|(index, component)| {
            let is_last = index + 1 == len;
            if is_last
                && policy.abstract_sensitive_filenames
                && is_sensitive_filename(&component, policy)
            {
                return slots
                    .ensure_slot(
                        policy,
                        SlotType::SensitiveDocument,
                        component,
                        SlotSource::Detected,
                    )
                    .public_value;
            }
            if !is_last && is_sensitive_segment(&component, policy) {
                return slots
                    .ensure_slot(
                        policy,
                        SlotType::SensitivePathSegment,
                        component,
                        SlotSource::Detected,
                    )
                    .public_value;
            }
            component
        })
        .collect()
}

fn relative_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect()
}

fn longest_matching_root<'a>(path: &Path, roots: &'a [PathBuf]) -> Option<&'a PathBuf> {
    roots
        .iter()
        .filter(|root| !root.as_os_str().is_empty() && path.starts_with(root))
        .max_by_key(|root| root.components().count())
}

fn normalize_input_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SlotGuardError::Traversal(path_to_string(path)));
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

fn validate_scope(path: &Path, policy: &Policy) -> Result<()> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SlotGuardError::Traversal(path_to_string(path)));
    }
    if path.is_absolute() {
        if longest_matching_root(path, &policy.repo_roots).is_some()
            || longest_matching_root(path, &policy.workspace_roots).is_some()
        {
            return Ok(());
        }
        if let Some(home_dir) = home_dir() {
            if path.starts_with(home_dir) {
                return Ok(());
            }
        }
        return Err(SlotGuardError::OutsideScope(path_to_string(path)));
    }
    Ok(())
}

fn is_sensitive_filename(component: &str, policy: &Policy) -> bool {
    let stem = Path::new(component)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(component)
        .to_ascii_lowercase();
    contains_sensitive_keyword(&stem, policy)
        || looks_like_personal_doc(&stem)
        || semantic_filename_is_sensitive(component, policy)
}

fn is_sensitive_segment(component: &str, policy: &Policy) -> bool {
    let lowered = component.to_ascii_lowercase();
    contains_sensitive_keyword(&lowered, policy)
        && (component.contains('-')
            || component.contains('_')
            || component
                .chars()
                .any(|character| character.is_ascii_digit()))
}

fn contains_sensitive_keyword(text: &str, policy: &Policy) -> bool {
    // Word-boundary matching on non-alphanumeric splits. This avoids
    // false positives like "paralegal" matching the "legal" keyword.
    let lowered = text.to_ascii_lowercase();
    let tokens: Vec<&str> = lowered
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|tok| !tok.is_empty())
        .collect();
    policy.sensitive_keywords.iter().any(|keyword| {
        let keyword = keyword.to_ascii_lowercase();
        tokens.iter().any(|tok| *tok == keyword)
    })
}

fn semantic_filename_is_sensitive(component: &str, policy: &Policy) -> bool {
    if !policy.semantic_enabled() || component.len() > policy.semantic.max_input_chars {
        return false;
    }
    semantic_detect(component, SemanticTaskKind::Filename, policy)
        .ok()
        .map(|proposals| {
            proposals.into_iter().any(|proposal| {
                matches!(
                    proposal.slot_type,
                    SlotType::SensitiveDocument | SlotType::SensitivePathSegment
                ) && component.contains(&proposal.span)
            })
        })
        .unwrap_or(false)
}

fn looks_like_personal_doc(text: &str) -> bool {
    let segments: Vec<_> = text
        .split(['-', '_', ' '])
        .filter(|segment| !segment.is_empty())
        .collect();
    let has_year = segments
        .iter()
        .any(|segment| segment.len() == 4 && segment.chars().all(|ch| ch.is_ascii_digit()));
    let has_connector = text.contains("for_") || text.contains("_for_") || text.contains("-for-");
    has_year && has_connector
}

fn build_semantic_prompt(input: &str, task: SemanticTaskKind) -> String {
    let task_description = match task {
        SemanticTaskKind::TextSpan => {
            "Find sensitive spans in the INPUT text that should become SlotGuard placeholders."
        }
        SemanticTaskKind::Filename => {
            "Decide whether the INPUT FILENAME refers to a SENSITIVE PERSONAL or SENSITIVE BUSINESS document. Return EMPTY proposals for ordinary engineering / source-code / documentation files."
        }
    };
    let allowed_slot_types = match task {
        SemanticTaskKind::TextSpan => {
            "SensitiveDocument, SensitivePathSegment, InternalHost, AccessToken, Email"
        }
        SemanticTaskKind::Filename => "SensitiveDocument, SensitivePathSegment",
    };
    // Few-shot examples for the filename task. Small CPU-runnable
    // models (≤3B params) tend to over-flag every filename without
    // explicit negative anchors, so we list a balanced set of
    // positives and negatives. The TextSpan task still uses the older
    // zero-shot phrasing because span detection in free text is open
    // ended — pinning it with a few cherry-picked examples often
    // hurts more than it helps.
    let examples = match task {
        SemanticTaskKind::Filename => {
            "EXAMPLES (study these before deciding):\n\
INPUT: \"layoff_plan_for_alice_2026.pdf\"        -> {\"proposals\":[{\"span\":\"layoff_plan_for_alice_2026.pdf\",\"slot_type\":\"SensitiveDocument\",\"reason\":\"personnel-action document\"}]}\n\
INPUT: \"non_disclosure_addendum_team.pdf\"      -> {\"proposals\":[{\"span\":\"non_disclosure_addendum_team.pdf\",\"slot_type\":\"SensitiveDocument\",\"reason\":\"NDA-style legal document\"}]}\n\
INPUT: \"q4_personnel_review_draft.docx\"        -> {\"proposals\":[{\"span\":\"q4_personnel_review_draft.docx\",\"slot_type\":\"SensitiveDocument\",\"reason\":\"HR review document\"}]}\n\
INPUT: \"merger_due_diligence_checklist.xlsx\"   -> {\"proposals\":[{\"span\":\"merger_due_diligence_checklist.xlsx\",\"slot_type\":\"SensitiveDocument\",\"reason\":\"M&A due-diligence document\"}]}\n\
INPUT: \"architecture.md\"                       -> {\"proposals\":[]}\n\
INPUT: \"models.py\"                             -> {\"proposals\":[]}\n\
INPUT: \"test_main.py\"                          -> {\"proposals\":[]}\n\
INPUT: \"Dockerfile\"                            -> {\"proposals\":[]}\n\
INPUT: \"schema_migration_001.sql\"              -> {\"proposals\":[]}\n\
INPUT: \"release_notes_2026_05.md\"              -> {\"proposals\":[]}\n\
A filename is sensitive ONLY if it names a personnel record, HR/comp/severance/PIP document, executive offer, NDA / contract / merger / acquisition / due-diligence document, board pre-read, customer PII export, or similar. Source code, configs, READMEs, docs, dashboards, migrations, release notes, tests, Dockerfiles, and lock files are NEVER sensitive — return an empty list for them."
        }
        SemanticTaskKind::TextSpan => "",
    };
    format!(
        "{task_description}\n\
Return JSON only with this schema:\n\
{{\"proposals\":[{{\"span\":\"exact substring from INPUT\",\"slot_type\":\"one allowed type\",\"reason\":\"short reason\"}}]}}\n\
Rules:\n\
- Only emit spans that appear verbatim in INPUT.\n\
- Prefer an empty list when unsure.\n\
- Do not invent placeholders.\n\
- Allowed slot types: {allowed_slot_types}\n\
{examples}\n\
INPUT:\n```text\n{input}\n```"
    )
}

fn verify_semantic_proposals(
    input: &str,
    task: SemanticTaskKind,
    proposals: Vec<SemanticProposal>,
) -> Vec<SemanticProposal> {
    let mut dedup = BTreeMap::<(String, SlotType), SemanticProposal>::new();
    for proposal in proposals {
        if proposal.span.is_empty()
            || proposal.span.len() > input.len()
            || proposal.span.contains('[')
            || proposal.span.contains(']')
            || !input.contains(&proposal.span)
        {
            continue;
        }
        let allowed = match task {
            SemanticTaskKind::TextSpan => matches!(
                proposal.slot_type,
                SlotType::SensitiveDocument
                    | SlotType::SensitivePathSegment
                    | SlotType::InternalHost
                    | SlotType::AccessToken
                    | SlotType::Email
            ),
            SemanticTaskKind::Filename => matches!(
                proposal.slot_type,
                SlotType::SensitiveDocument | SlotType::SensitivePathSegment
            ),
        };
        if !allowed {
            continue;
        }
        dedup.insert((proposal.span.clone(), proposal.slot_type), proposal);
    }
    dedup.into_values().collect()
}

fn extract_semantic_response_text(
    response: &Value,
    api_style: SemanticApiStyle,
) -> std::result::Result<String, SemanticClientError> {
    match api_style {
        SemanticApiStyle::OpenAiChat => {
            if let Some(content) = response
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|choices| choices.first())
                .and_then(|choice| choice.get("message"))
                .and_then(|message| message.get("content"))
            {
                return value_to_text(content).ok_or(SemanticClientError::MissingContent);
            }
            Err(SemanticClientError::MissingContent)
        }
        SemanticApiStyle::AnthropicMessages => {
            if let Some(content) = response.get("content") {
                return value_to_text(content).ok_or(SemanticClientError::MissingContent);
            }
            Err(SemanticClientError::MissingContent)
        }
    }
}

fn value_to_text(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(text.to_string());
    }
    if let Some(parts) = value.as_array() {
        let merged = parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>();
        if !merged.is_empty() {
            return Some(merged.join("\n"));
        }
    }
    None
}

fn extract_json_object(input: &str) -> Option<String> {
    let start = input.find('{')?;
    let end = input.rfind('}')?;
    (end > start).then(|| input[start..=end].to_string())
}

fn apply_semantic_text_proposals(input: &str, policy: &Policy, slots: &mut SlotTable) -> String {
    if !policy.semantic_enabled() || input.len() > policy.semantic.max_input_chars {
        return input.to_string();
    }
    let Ok(mut proposals) = semantic_detect(input, SemanticTaskKind::TextSpan, policy) else {
        return input.to_string();
    };
    proposals.sort_by(|left, right| {
        right
            .span
            .len()
            .cmp(&left.span.len())
            .then(left.span.cmp(&right.span))
    });

    let mut output = input.to_string();
    for proposal in proposals {
        let slot = slots.ensure_slot(
            policy,
            proposal.slot_type,
            proposal.span.clone(),
            SlotSource::Detected,
        );
        output = output.replace(&proposal.span, &slot.public_value);
    }
    output
}

#[derive(Debug)]
struct SlotPattern {
    regex: Regex,
    slot_type: SlotType,
}

fn replace_deterministic_secret_patterns(
    input: &str,
    policy: &Policy,
    slots: &mut SlotTable,
) -> String {
    let mut output = input.to_string();
    for pattern in deterministic_slot_patterns() {
        output = replace_capture_matches(&pattern.regex, &output, |candidate| {
            let slot = slots.ensure_slot(
                policy,
                pattern.slot_type,
                candidate.to_string(),
                SlotSource::Detected,
            );
            Some(slot.public_value)
        });
    }
    output
}

fn deterministic_slot_patterns() -> &'static Vec<SlotPattern> {
    static PATTERNS: OnceLock<Vec<SlotPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            SlotPattern {
                regex: Regex::new(
                    r#"(?i)(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key)\s*[=:]\s*['"]?([a-z0-9_\-./+]{16,128})['"]?"#,
                )
                .expect("valid api key regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(r#"(?i)(?:bearer|token)\s+([a-z0-9_\-./+=]{20,512})"#)
                    .expect("valid bearer regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(
                    r#"(?:^|[^a-zA-Z0-9_-])(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})(?:$|[^a-zA-Z0-9_-])"#,
                )
                .expect("valid jwt regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(r#"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:$|[^A-Z0-9])"#)
                    .expect("valid aws key regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(
                    r#"(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)\s*[=:]\s*['"]?([a-z0-9/+=]{40})['"]?"#,
                )
                .expect("valid aws secret regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(
                    r#"(?:^|[^a-zA-Z0-9_])(gh[ps]_[a-zA-Z0-9]{36,255}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})(?:$|[^a-zA-Z0-9_])"#,
                )
                .expect("valid github token regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(r#"(?:^|[^a-zA-Z0-9-])(xox[bpras]-[a-zA-Z0-9-]{10,250})(?:$|[^a-zA-Z0-9-])"#)
                    .expect("valid slack token regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: Regex::new(
                    r#"(?i)(?:secret|password|passwd|token|credential)\s*[=:]\s*['"]?([a-f0-9]{32,128})['"]?"#,
                )
                .expect("valid generic secret regex"),
                slot_type: SlotType::AccessToken,
            },
            SlotPattern {
                regex: token_regex().clone(),
                slot_type: SlotType::AccessToken,
            },
        ]
    })
}

fn replace_matches(
    regex: &Regex,
    input: &str,
    mut replace: impl FnMut(&str) -> Option<String>,
) -> String {
    let mut output = input.to_string();
    let matches = regex
        .find_iter(input)
        .map(|value| (value.start(), value.end(), value.as_str().to_string()))
        .collect::<Vec<_>>();
    for (start, end, value) in matches.into_iter().rev() {
        if let Some(replacement) = replace(&value) {
            output.replace_range(start..end, &replacement);
        }
    }
    output
}

fn replace_capture_matches(
    regex: &Regex,
    input: &str,
    mut replace: impl FnMut(&str) -> Option<String>,
) -> String {
    let mut output = input.to_string();
    let matches = regex
        .captures_iter(input)
        .filter_map(|captures| {
            captures
                .get(1)
                .or_else(|| captures.get(0))
                .map(|value| (value.start(), value.end(), value.as_str().to_string()))
        })
        .collect::<Vec<_>>();
    for (start, end, value) in matches.into_iter().rev() {
        if let Some(replacement) = replace(&value) {
            output.replace_range(start..end, &replacement);
        }
    }
    output
}

fn replace_path_matches(input: &str, policy: &Policy, slots: &mut SlotTable) -> String {
    let mut output = input.to_string();
    let matches = path_regex()
        .captures_iter(input)
        .filter_map(|captures| captures.get(2))
        .map(|value| (value.start(), value.end(), value.as_str().to_string()))
        .collect::<Vec<_>>();
    for (start, end, value) in matches.into_iter().rev() {
        if value.contains("/.../") {
            continue;
        }
        if let Some(replacement) = Path::new(&value)
            .is_absolute()
            .then(|| abstract_path(Path::new(&value), policy, slots))
            .transpose()
            .ok()
            .flatten()
        {
            output.replace_range(start..end, &replacement);
        }
    }
    output
}

fn path_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?m)(^|[\s(])(/(?:[^/\s\[\])]+/)+[^/\s\[\])]+)").expect("valid path regex")
    })
}

fn email_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").expect("valid email regex")
    })
}

fn token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b",
        )
        .expect("valid token regex")
    })
}

fn looks_like_placeholder(segment: &str) -> bool {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX
        .get_or_init(|| {
            Regex::new(r"^\[[A-Z0-9_]+\](?:\.[^/]+)?$").expect("valid placeholder regex")
        })
        .is_match(segment)
}

fn builtin_sensitive_keywords() -> &'static [&'static str] {
    &[
        "layoff",
        "salary",
        "compensation",
        "legal",
        "contract",
        "acquisition",
        "secret",
        "private",
    ]
}

fn builtin_internal_host_suffixes() -> &'static [&'static str] {
    // Common labels that signal a hostname is internal-only. Each entry
    // is matched as a trailing label (so ".internal" matches anything
    // ending with ".internal" or ".internal.<x>") via `is_internal_host`.
    &[".internal", ".intranet", ".local", ".lan", ".corp"]
}

fn replace_internal_hosts(input: &str, policy: &Policy, slots: &mut SlotTable) -> String {
    let mut output = input.to_string();
    let regex = internal_host_regex();
    let matches: Vec<_> = regex
        .captures_iter(input)
        .filter_map(|cap| cap.get(1))
        .map(|m| (m.start(), m.end(), m.as_str().to_string()))
        .collect();
    for (start, end, value) in matches.into_iter().rev() {
        if !is_internal_host(&value, policy) {
            continue;
        }
        let slot = slots.ensure_slot(policy, SlotType::InternalHost, value, SlotSource::Detected);
        output.replace_range(start..end, &slot.public_value);
    }
    output
}

fn internal_host_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        // Hostname token: a label of [a-z0-9][a-z0-9-]*, followed by at
        // least one ".label" group. Anchor on lookalike non-alphanumeric
        // boundaries so we don't match inside a path component such as
        // "models.py" appearing immediately after "/".
        Regex::new(r"(?:^|[\s,;()<>])([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+){1,})(?:$|[\s,;:()<>])")
            .expect("valid internal-host regex")
    })
}

fn is_internal_host(candidate: &str, policy: &Policy) -> bool {
    let candidate = candidate.to_ascii_lowercase();
    let labels: Vec<&str> = candidate.split('.').collect();
    if labels.iter().any(|l| {
        matches!(*l, "internal" | "intranet") || l.contains("internal") || l.contains("intranet")
    }) {
        return true;
    }
    for suffix in &policy.internal_host_suffixes {
        let suffix = suffix.trim().to_ascii_lowercase();
        if suffix.is_empty() {
            continue;
        }
        let needle = if suffix.starts_with('.') {
            suffix.clone()
        } else {
            format!(".{suffix}")
        };
        if candidate.ends_with(&needle) {
            return true;
        }
        // Also match exact-suffix-as-last-label.
        if let Some(last) = labels.last() {
            if *last == needle.trim_start_matches('.') {
                return true;
            }
        }
    }
    false
}

fn default_slot_lookup_key() -> Vec<u8> {
    // Process-wide ephemeral fallback. Used only when a Policy is not
    // bound to a SessionContext (CLI demos, in-process tests). The key
    // is randomized per-process so a fresh slotguard run does not
    // reveal stable handles across reboots.
    static FALLBACK_KEY: OnceLock<Vec<u8>> = OnceLock::new();
    FALLBACK_KEY
        .get_or_init(|| {
            let mut bytes = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut bytes);
            bytes
        })
        .clone()
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn config_base_dir() -> Result<PathBuf> {
    if let Some(dir) = env::var_os("SLOTGUARD_HOME") {
        return Ok(PathBuf::from(dir));
    }
    let home = home_dir().ok_or(SlotGuardError::NoConfigDir)?;
    Ok(home.join(".slotguard"))
}

#[cfg(unix)]
fn set_restrictive_dir_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_restrictive_dir_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    paths: PathsConfig,
    #[serde(default)]
    path_policy: PathPolicyConfig,
    #[serde(default)]
    semantic: SemanticConfigFile,
    #[serde(default)]
    shell: ShellConfig,
    #[serde(default)]
    sensitive_keywords: SensitiveKeywordsConfig,
    #[serde(default)]
    internal_hosts: InternalHostsConfig,
}

impl ConfigFile {
    fn into_policy(self) -> Policy {
        let mut policy = Policy::default();
        if !self.paths.workspace_roots.is_empty() {
            policy.workspace_roots = self.paths.workspace_roots;
        }
        if !self.paths.repo_roots.is_empty() {
            policy.repo_roots = self.paths.repo_roots;
        }
        policy.preserve_path_suffix_segments = self.path_policy.preserve_suffix_segments;
        policy.abstract_sensitive_filenames = self.path_policy.abstract_sensitive_filenames;
        policy.preserve_extensions = self.path_policy.preserve_extensions;
        policy.semantic = self.semantic.into_semantic_config();
        policy.allow_shell = self.shell.enabled;
        if !self.shell.allowed_commands.is_empty() {
            policy.allowed_shell_commands = self.shell.allowed_commands;
        }
        if !self.sensitive_keywords.values.is_empty() {
            policy.sensitive_keywords = self.sensitive_keywords.values;
        }
        if !self.internal_hosts.suffixes.is_empty() {
            policy.internal_host_suffixes = self.internal_hosts.suffixes;
        }
        policy
    }
}

#[derive(Debug, Deserialize, Default)]
struct InternalHostsConfig {
    #[serde(default)]
    suffixes: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct PathsConfig {
    #[serde(default)]
    workspace_roots: Vec<PathBuf>,
    #[serde(default)]
    repo_roots: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct PathPolicyConfig {
    #[serde(default = "default_preserve_suffix_segments")]
    preserve_suffix_segments: usize,
    #[serde(default = "default_true")]
    abstract_sensitive_filenames: bool,
    #[serde(default = "default_true")]
    preserve_extensions: bool,
}

impl Default for PathPolicyConfig {
    fn default() -> Self {
        Self {
            preserve_suffix_segments: default_preserve_suffix_segments(),
            abstract_sensitive_filenames: true,
            preserve_extensions: true,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct SemanticConfigFile {
    mode: Option<String>,
    api_style: Option<String>,
    endpoint: Option<String>,
    model: Option<String>,
    api_key_env: Option<String>,
    timeout_ms: Option<u64>,
    max_input_chars: Option<usize>,
}

impl SemanticConfigFile {
    fn into_semantic_config(self) -> SemanticConfig {
        let mut config = SemanticConfig::default();
        if let Some(mode) = self
            .mode
            .and_then(|value| SemanticMode::from_config_value(&value))
        {
            config.mode = mode;
        }
        if let Some(api_style) = self
            .api_style
            .and_then(|value| SemanticApiStyle::from_config_value(&value))
        {
            config.api_style = api_style;
        }
        if let Some(endpoint) = self.endpoint.filter(|value| !value.trim().is_empty()) {
            config.endpoint = Some(endpoint);
        }
        if let Some(model) = self.model.filter(|value| !value.trim().is_empty()) {
            config.model = Some(model);
        }
        if let Some(api_key_env) = self.api_key_env {
            config.api_key_env = Some(api_key_env);
        }
        if let Some(timeout_ms) = self.timeout_ms {
            config.timeout_ms = timeout_ms;
        }
        if let Some(max_input_chars) = self.max_input_chars {
            config.max_input_chars = max_input_chars;
        }
        config
    }
}

#[derive(Debug, Deserialize)]
struct ShellConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    allowed_commands: Vec<String>,
}

impl Default for ShellConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_commands: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct SensitiveKeywordsConfig {
    #[serde(default)]
    values: Vec<String>,
}

fn default_preserve_suffix_segments() -> usize {
    3
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_policy() -> Policy {
        Policy {
            workspace_roots: vec![PathBuf::from("/workspace/acme")],
            repo_roots: vec![PathBuf::from("/workspace/acme")],
            allow_shell: true,
            ..Policy::default()
        }
    }

    #[test]
    fn abstracts_sensitive_workspace_document() {
        let policy = workspace_policy();
        let mut slots = SlotTable::new();
        let abstracted = abstract_path(
            Path::new("/workspace/acme/legal/layoff_plan_for_bob_2026.pdf"),
            &policy,
            &mut slots,
        )
        .unwrap();

        assert_eq!(abstracted, "[REPO_ROOT_1]/legal/[SENSITIVE_DOC_1].pdf");
        assert!(slots.get_public("[REPO_ROOT_1]").is_some());
        assert!(slots.get_public("[SENSITIVE_DOC_1].pdf").is_some());
    }

    #[test]
    fn abstracts_home_path_with_hidden_prefix_slot() {
        let policy = Policy {
            preserve_path_suffix_segments: 3,
            ..workspace_policy()
        };
        let mut slots = SlotTable::new();
        let home = home_dir().unwrap_or_else(|| PathBuf::from("/root"));
        let path = home.join("work/acme/src/auth/session.rs");
        let abstracted = abstract_path(&path, &policy, &mut slots).unwrap();

        assert!(abstracted.starts_with("[USER_HOME_1]/[SENSITIVE_PATH_SEGMENT_1]/"));
        assert!(abstracted.ends_with("src/auth/session.rs"));
    }

    #[test]
    fn rebound_workspace_path_round_trips() {
        let policy = workspace_policy();
        let mut slots = SlotTable::new();
        let original = Path::new("/workspace/acme/legal/layoff_plan_for_bob_2026.pdf");
        let abstracted = abstract_path(original, &policy, &mut slots).unwrap();
        let rebound = rebind_path(&abstracted, &policy, &slots).unwrap();

        assert_eq!(rebound, original);
    }

    #[test]
    fn rebinding_rejects_unknown_placeholder() {
        let policy = workspace_policy();
        let slots = SlotTable::new();
        let result = rebind_path("[WORKSPACE_ROOT_9]/README.md", &policy, &slots);

        assert!(matches!(result, Err(SlotGuardError::UnknownPlaceholder(_))));
    }

    #[test]
    fn abstract_text_redacts_structured_tokens() {
        let policy = workspace_policy();
        let mut slots = SlotTable::new();
        let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890"].concat();
        let text = format!("Authorization: Bearer {token}");
        let abstracted = abstract_text(&text, &policy, &mut slots);

        assert_eq!(abstracted, "Authorization: Bearer [ACCESS_TOKEN_1]");
        assert!(slots.get_public("[ACCESS_TOKEN_1]").is_some());
    }

    #[test]
    fn config_parses_semantic_section() {
        let config = r#"
[paths]
workspace_roots = ["/workspace/acme"]

[semantic]
mode = "local"
api_style = "openai_chat"
endpoint = "http://127.0.0.1:8000/v1/chat/completions"
model = "qwen"
timeout_ms = 1200
max_input_chars = 123
"#;
        let parsed: ConfigFile = toml::from_str(config).unwrap();
        let policy = parsed.into_policy();

        assert!(matches!(policy.semantic.mode, SemanticMode::Local));
        assert!(matches!(
            policy.semantic.api_style,
            SemanticApiStyle::OpenAiChat
        ));
        assert_eq!(
            policy.semantic.endpoint.as_deref(),
            Some("http://127.0.0.1:8000/v1/chat/completions")
        );
        assert_eq!(policy.semantic.model.as_deref(), Some("qwen"));
        assert_eq!(policy.semantic.timeout_ms, 1200);
        assert_eq!(policy.semantic.max_input_chars, 123);
    }

    #[test]
    fn shell_policy_allows_whitelisted_commands() {
        let policy = workspace_policy();
        let parsed = validate_shell_command("git status --short", &policy).unwrap();
        assert_eq!(parsed.program, "git");
        assert_eq!(parsed.args, vec!["status", "--short"]);
    }

    #[test]
    fn shell_policy_rejects_injection_tokens() {
        let policy = workspace_policy();
        let result = validate_shell_command("rg secret . && cat /etc/passwd", &policy);
        assert!(matches!(
            result,
            Err(SlotGuardError::InvalidShellCommand(_))
        ));
    }

    #[test]
    fn keyword_match_is_word_bounded() {
        // "paralegal" must NOT trigger the "legal" keyword. This was
        // a documented P1 false-positive in the execution plan.
        let mut policy = workspace_policy();
        policy.sensitive_keywords = vec!["legal".to_string()];
        assert!(!is_sensitive_segment("paralegal_team", &policy));
        assert!(is_sensitive_segment("legal_archive_2026", &policy));
    }

    #[test]
    fn session_context_persists_random_key_across_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = SessionContext::create_or_load_in(dir.path(), "abc-123").unwrap();
        let second = SessionContext::create_or_load_in(dir.path(), "abc-123").unwrap();
        assert_eq!(first.slot_lookup_key, second.slot_lookup_key);
        assert_eq!(first.session_dir, second.session_dir);
        // The fallback dev key must not be used for sessions.
        assert_ne!(first.slot_lookup_key, b"slotguard-dev-key");

        let other = SessionContext::create_or_load_in(dir.path(), "different").unwrap();
        assert_ne!(first.slot_lookup_key, other.slot_lookup_key);
    }

    #[test]
    fn session_context_rejects_traversal_in_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bad = SessionContext::create_or_load_in(dir.path(), "../escape");
        assert!(matches!(bad, Err(SlotGuardError::InvalidSessionId(_))));
    }

    #[test]
    fn internal_host_detection_runs_on_text() {
        let policy = workspace_policy();
        let mut slots = SlotTable::new();
        let text = "deploy via build.internal then check metrics.intranet for status";
        let abstracted = abstract_text(text, &policy, &mut slots);
        assert!(abstracted.contains("[INTERNAL_HOST_1]"));
        assert!(abstracted.contains("[INTERNAL_HOST_2]"));
        assert!(!abstracted.contains("build.internal"));
        assert!(!abstracted.contains("metrics.intranet"));
    }

    #[test]
    fn internal_host_detection_skips_filenames_inside_paths() {
        // A path component like "models.py" must NOT be flagged as a
        // host. The path-detection pass must own those tokens.
        let policy = workspace_policy();
        let mut slots = SlotTable::new();
        let text = "Reading /workspace/acme/src/models.py";
        let abstracted = abstract_text(text, &policy, &mut slots);
        assert!(abstracted.contains("[REPO_ROOT_1]/src/models.py"));
        assert!(!abstracted.contains("[INTERNAL_HOST_"));
    }

    #[test]
    fn rebind_rejects_bracket_injection_attempts() {
        let policy = workspace_policy();
        let slots = SlotTable::new();
        for input in &[
            "[]",
            "][",
            "[ABC[DEF]]",
            "[WORKSPACE_ROOT_1/README.md",
            "[WORKSPACE_ROOT_-1]",
            "[user_home_1]",
        ] {
            let result = rebind_path(input, &policy, &slots);
            assert!(
                result.is_err(),
                "expected `{input}` to be rejected, got {result:?}"
            );
        }
    }

    #[test]
    fn rebind_rejects_backslash_and_control_segments() {
        let policy = workspace_policy();
        let slots = SlotTable::new();
        let cases = ["foo\\..\\bar", "foo\u{0000}bar", "abc\u{0007}xyz"];
        for input in &cases {
            let result = rebind_path(input, &policy, &slots);
            assert!(
                result.is_err(),
                "expected `{:?}` to be rejected, got {result:?}",
                input
            );
        }
    }

    #[test]
    fn slot_table_persists_and_replays_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let session = SessionContext::create_or_load_in(dir.path(), "exp").unwrap();
        let mut policy = workspace_policy();
        policy.bind_session(&session);

        let mut table = SlotTable::with_session(&session).unwrap();
        let abstracted = abstract_path(
            Path::new("/workspace/acme/legal/layoff_plan_for_alice_2026.pdf"),
            &policy,
            &mut table,
        )
        .unwrap();
        assert_eq!(abstracted, "[REPO_ROOT_1]/legal/[SENSITIVE_DOC_1].pdf");

        let replayed = SlotTable::with_session(&session).unwrap();
        let slots: Vec<_> = replayed
            .slots()
            .into_iter()
            .map(|slot| slot.public_value)
            .collect();
        assert!(slots.contains(&"[REPO_ROOT_1]".to_string()));
        assert!(slots.contains(&"[SENSITIVE_DOC_1].pdf".to_string()));
        assert!(session.session_dir.join("index.json").exists());
        assert!(session.session_dir.join("slots.jsonl").exists());
    }
}
