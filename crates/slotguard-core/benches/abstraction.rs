use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use slotguard_core::{
    CredentialCategory, CredentialRegistry, Policy, RedactionMode, SemanticEntityGraph, SlotTable,
    abstract_path, abstract_text, rebind_path, sanitize_turn,
};
use std::path::{Path, PathBuf};

fn workspace_policy() -> Policy {
    let mut policy = Policy::for_workspace(PathBuf::from("/workspace/acme"));
    policy.repo_roots = policy.workspace_roots.clone();
    policy
}

fn sample_transcript() -> String {
    // Mixed-content fragment representative of an agent turn: paths,
    // filenames, an email, an access token, and a few sentences. We
    // build it once and clone for each iteration so the timed work is
    // exclusively the abstraction itself.
    let token = ["ghp_", "abcdefghijklmnopqrstuvwxyz1234567890abcd"].concat();
    let body = format!(
        "Reading /workspace/acme/src/auth/session.rs and \
/workspace/acme/legal/layoff_plan_for_alice_2026.pdf. \
Contact alice@acme-internal.example. \
Authorization: Bearer {token}. \
Branch: feature/migrate-billing-tables. \
Files: /workspace/acme/hr/compensation_review_q3.csv \
       /workspace/acme/docs/architecture.md \
       /workspace/acme/.env"
    );
    body
}

fn bench_abstract_path(c: &mut Criterion) {
    let policy = workspace_policy();
    let path = Path::new("/workspace/acme/legal/layoff_plan_for_alice_2026.pdf");
    c.bench_function("abstract_path/sensitive_doc", |b| {
        b.iter(|| {
            let mut slots = SlotTable::new();
            let result = abstract_path(black_box(path), &policy, &mut slots).unwrap();
            black_box(result);
        });
    });
}

fn bench_rebind_path(c: &mut Criterion) {
    let policy = workspace_policy();
    let mut slots = SlotTable::new();
    let abstracted = abstract_path(
        Path::new("/workspace/acme/legal/layoff_plan_for_alice_2026.pdf"),
        &policy,
        &mut slots,
    )
    .unwrap();
    c.bench_function("rebind_path/sensitive_doc", |b| {
        b.iter(|| {
            let result = rebind_path(black_box(&abstracted), &policy, &slots).unwrap();
            black_box(result);
        });
    });
}

fn bench_abstract_text(c: &mut Criterion) {
    let policy = workspace_policy();
    let transcript = sample_transcript();
    let mut group = c.benchmark_group("abstract_text");
    group.throughput(Throughput::Bytes(transcript.len() as u64));
    group.bench_function("agent_turn", |b| {
        b.iter(|| {
            let mut slots = SlotTable::new();
            let result = abstract_text(black_box(&transcript), &policy, &mut slots);
            black_box(result);
        });
    });
    group.finish();
}

fn bench_per_turn(c: &mut Criterion) {
    let policy = workspace_policy();
    // Concatenate the sample transcript several times to approximate a
    // ~6 KB cumulative turn body.
    let mut turn = String::new();
    for _ in 0..8 {
        turn.push_str(&sample_transcript());
        turn.push('\n');
    }
    c.bench_function("per_turn_6kb", |b| {
        b.iter(|| {
            let mut slots = SlotTable::new();
            let result = abstract_text(black_box(&turn), &policy, &mut slots);
            black_box(result);
        });
    });
}

fn credential_turn_text() -> String {
    // Representative agent turn that contains every credential category
    // FPS+SEG handles. ~700 bytes, covers GitHub PAT, JWT, DB URL, PEM
    // header, internal hostname, and PII email — all in a single turn.
    let mut s = String::new();
    let github_token = ["ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"].concat();
    s.push_str(&format!("export GITHUB_TOKEN={github_token}\n"));
    s.push_str("DATABASE_URL=postgres://app:hunter2pass1234@db-1234.acme-corp.example/prod\n");
    s.push_str(
        "OAUTH=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYiLCJuYW1lIjoiSm9obiJ9.signature_xx\n",
    );
    s.push_str("Owner: alice.4qq2@acme-corp.example\n");
    s.push_str("ssh metrics.internal.acme-corp.example\n");
    s.push_str("Reminder: keep AuthMiddleware intact and re-run parse_token tests.\n");
    s
}

fn bench_sanitize_turn_fps_seg(c: &mut Criterion) {
    let turn = credential_turn_text();
    let mut group = c.benchmark_group("sanitize_turn");
    group.throughput(Throughput::Bytes(turn.len() as u64));
    group.bench_function("fps_with_seg/agent_turn", |b| {
        b.iter(|| {
            let mut registry = CredentialRegistry::new(b"bench-key".to_vec());
            let mut graph = SemanticEntityGraph::default();
            graph.add_node(
                &["ghp_", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"].concat(),
                CredentialCategory::ApiKey,
            );
            let result = sanitize_turn(
                black_box(&turn),
                RedactionMode::FpsWithGraph,
                &mut registry,
                &mut graph,
            );
            black_box(result);
        });
    });
    group.bench_function("fps_only/agent_turn", |b| {
        b.iter(|| {
            let mut registry = CredentialRegistry::new(b"bench-key".to_vec());
            let mut graph = SemanticEntityGraph::default();
            let result = sanitize_turn(
                black_box(&turn),
                RedactionMode::FormatPreserving,
                &mut registry,
                &mut graph,
            );
            black_box(result);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_abstract_path,
    bench_rebind_path,
    bench_abstract_text,
    bench_per_turn,
    bench_sanitize_turn_fps_seg,
);
criterion_main!(benches);
