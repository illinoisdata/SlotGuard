use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use slotguard_core::{
    Policy, SemanticApiStyle, SemanticMode, SemanticTaskKind, SlotSource, SlotTable, abstract_path,
    abstract_text, rebind_path, resolve_input_path, semantic_detect,
};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "slotguard-cli",
    about = "Inspect and demo SlotGuard abstractions locally"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    TestAbstract {
        input: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    InspectSlots {
        input: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    DemoPath {
        path: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    PolicyCheck {
        abstracted_path: String,
        #[arg(long = "bind", value_name = "PUBLIC=RAW")]
        binds: Vec<String>,
        #[command(flatten)]
        policy: PolicyArgs,
    },
    SemanticDetect {
        input: String,
        #[arg(long, default_value = "text_span")]
        kind: String,
        #[command(flatten)]
        policy: PolicyArgs,
    },
}

#[derive(Args, Clone, Default)]
struct PolicyArgs {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long = "workspace-root")]
    workspace_roots: Vec<PathBuf>,
    #[arg(long = "repo-root")]
    repo_roots: Vec<PathBuf>,
    #[arg(long = "sensitive-keyword")]
    sensitive_keywords: Vec<String>,
    #[arg(long)]
    enable_shell: bool,
    #[arg(long = "semantic-mode")]
    semantic_mode: Option<String>,
    #[arg(long = "semantic-api-style")]
    semantic_api_style: Option<String>,
    #[arg(long = "semantic-endpoint")]
    semantic_endpoint: Option<String>,
    #[arg(long = "semantic-model")]
    semantic_model: Option<String>,
    #[arg(long = "semantic-api-key-env")]
    semantic_api_key_env: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::TestAbstract { input, policy } => {
            let policy = load_policy(policy)?;
            let mut slots = SlotTable::new();
            let abstracted = abstract_input(&input, &policy, &mut slots)?;
            println!("{abstracted}");
        }
        Commands::InspectSlots { input, policy } => {
            let policy = load_policy(policy)?;
            let mut slots = SlotTable::new();
            let abstracted = abstract_input(&input, &policy, &mut slots)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "abstracted": abstracted,
                    "slots": slots.slots(),
                }))?
            );
        }
        Commands::DemoPath { path, policy } => {
            let policy = load_policy(policy)?;
            let mut slots = SlotTable::new();
            let abstracted = abstract_path(Path::new(&path), &policy, &mut slots)
                .with_context(|| format!("failed to abstract `{path}`"))?;
            let rebound =
                rebind_path(&abstracted, &policy, &slots).context("failed to rebind path")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "raw": path,
                    "abstracted": abstracted,
                    "rebound": rebound,
                    "slots": slots.slots(),
                }))?
            );
        }
        Commands::PolicyCheck {
            abstracted_path,
            binds,
            policy,
        } => {
            let policy = load_policy(policy)?;
            let mut slots = SlotTable::new();
            for binding in binds {
                let (public, raw) = parse_binding(&binding)?;
                slots.register_public_binding(&policy, public, raw, SlotSource::Configured)?;
            }
            let resolved = if abstracted_path.contains('[') {
                rebind_path(&abstracted_path, &policy, &slots)?
            } else {
                resolve_input_path(&abstracted_path, &policy, &slots)?
            };
            println!("{}", resolved.display());
        }
        Commands::SemanticDetect {
            input,
            kind,
            policy,
        } => {
            let policy = load_policy(policy)?;
            let kind = SemanticTaskKind::from_config_value(&kind)
                .ok_or_else(|| anyhow::anyhow!("unsupported semantic kind `{kind}`"))?;
            let proposals = semantic_detect(&input, kind, &policy)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "kind": kind,
                    "input": input,
                    "proposals": proposals,
                }))?
            );
        }
    }
    Ok(())
}

fn load_policy(args: PolicyArgs) -> Result<Policy> {
    let mut policy = if let Some(ref config_path) = args.config {
        Policy::load_from_toml(&config_path)
            .with_context(|| format!("failed to load config `{}`", config_path.display()))?
    } else {
        Policy::default()
    };

    if !args.workspace_roots.is_empty() {
        policy.workspace_roots = args.workspace_roots.clone();
    }
    if !args.repo_roots.is_empty() {
        policy.repo_roots = args.repo_roots.clone();
    }
    if !args.sensitive_keywords.is_empty() {
        policy
            .sensitive_keywords
            .extend(args.sensitive_keywords.clone());
    }
    if args.enable_shell {
        policy.allow_shell = true;
    }
    apply_semantic_overrides(&mut policy, &args)?;
    if policy.repo_roots.is_empty() && !policy.workspace_roots.is_empty() {
        policy.repo_roots = policy.workspace_roots.clone();
    }
    if policy.workspace_roots.is_empty() {
        policy.workspace_roots.push(std::env::current_dir()?);
    }
    Ok(policy)
}

fn abstract_input(input: &str, policy: &Policy, slots: &mut SlotTable) -> Result<String> {
    if Path::new(input).is_absolute() {
        abstract_path(Path::new(input), policy, slots).map_err(Into::into)
    } else {
        Ok(abstract_text(input, policy, slots))
    }
}

fn parse_binding(value: &str) -> Result<(String, String)> {
    let (public, raw) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("binding `{value}` must look like PUBLIC=RAW"))?;
    if public.trim().is_empty() || raw.trim().is_empty() {
        bail!("binding `{value}` must include both a public and raw value");
    }
    Ok((public.trim().to_string(), raw.trim().to_string()))
}

fn apply_semantic_overrides(policy: &mut Policy, args: &PolicyArgs) -> Result<()> {
    if let Some(mode) = args.semantic_mode.as_deref() {
        policy.semantic.mode = SemanticMode::from_config_value(mode)
            .ok_or_else(|| anyhow::anyhow!("unsupported semantic mode `{mode}`"))?;
    }
    if let Some(api_style) = args.semantic_api_style.as_deref() {
        policy.semantic.api_style = SemanticApiStyle::from_config_value(api_style)
            .ok_or_else(|| anyhow::anyhow!("unsupported semantic api style `{api_style}`"))?;
    }
    if let Some(endpoint) = args.semantic_endpoint.as_ref() {
        policy.semantic.endpoint = Some(endpoint.clone());
    }
    if let Some(model) = args.semantic_model.as_ref() {
        policy.semantic.model = Some(model.clone());
    }
    if let Some(api_key_env) = args.semantic_api_key_env.as_ref() {
        policy.semantic.api_key_env = Some(api_key_env.clone());
    }
    Ok(())
}
