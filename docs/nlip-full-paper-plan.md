# SlotGuard × NLIP: Full-Paper Research Plan

> Status: Research design draft, not a list of implemented features or experimental results.
>
> Working scope: Extend SlotGuard from a transcript-sanitization boundary for a single remote model into a task- and recipient-aware privacy and capability boundary for multi-agent collaboration over NLIP.
>
> This document is intended to support a research proposal, paper outline, and implementation issues.

---

## 0. Executive Summary

### Research question in one sentence

**Can protocol structure, a small local model, and deterministic authorization enforcement reduce unnecessary disclosure and prevent unauthorized use of protected references in cross-domain agent collaboration, while preserving real task completion?**

### Recommended approach

Use NLIP as the collaboration and messaging interface, SlotGuard as the local policy-enforcement layer, and a lightweight System 1 model as the semantic advisor:

1. **Protocol-aware processing:** Select structured parsing or semantic detection based on message format, submessage location, and trust attributes, rather than blindly replacing strings throughout serialized JSON.
2. **Recipient-bound references and guarded execution:** Bind references to protected objects to authenticated recipients, sessions, and permitted operations. Keep raw mappings within the owning trust domain.
3. **Task-aware information minimization:** Use a small local model to identify sensitive semantics and entity relationships that rules miss, without allowing the model to grant permissions or arbitrarily restore raw values.
4. **Real end-to-end evaluation:** Execute actual tool-based tasks and jointly measure content exposure, unauthorized use, task completion, and full-system latency.

### What does not constitute a major contribution

- Implementing only an NLIP adapter.
- Replacing regular expressions with an LLM classifier.
- Merely increasing the number of synthetic benchmark examples.
- Equating encryption or authentication with content privacy.
- Calling a reference a secure capability simply because it contains a random identifier.

### Minimum viable paper narrative

Training a new model is not necessary if the work can establish that:

> On real cross-domain tasks, protocol structure and recipient-bound execution controls improve the privacy–utility trade-off over text-level sanitization and prevent reproducible forwarding, replay, or reference-misuse failures.

That could support a valuable systems paper. Whether to add a specially trained local model should depend on early experimental evidence.

---

## 1. Relationship to Existing SlotGuard

### 1.1 Existing foundations

The current manuscript includes or describes:

- Typed, suffix-aware replacement of structural bindings.
- Format-preserving synthetic substitution (FPS).
- A session-scoped slot table.
- A semantic entity graph (SEG) based primarily on keyword and pattern links.
- Guarded rebinding inside the trusted runtime.
- Rule-based detection and optional local semantic detection.
- Synthetic privacy corpora, workflow probes, and TAC-lite handle replay.

These foundations are reusable, but each must be verified through an implementation audit. Manuscript descriptions must not be treated as fully validated implementation guarantees.

### 1.2 Required extensions

| Dimension | Current emphasis | Full-paper objective |
|---|---|---|
| Protection boundary | Local runtime → model provider | Local runtime → protocol endpoint → multiple recipient agents |
| Privacy policy | Which values to hide | What may be disclosed to whom, for which task and operation |
| Entity scope | Session | Session + authenticated recipient + object permissions and lifecycle |
| Protocol handling | Transcript content | Messages, submessages, formats, sessions, and authentication responsibilities |
| Semantic capability | Rules and simple links | Task-conditioned decisions, aliases, and indirect references |
| Evaluation | Controlled probes and replay | Real execution, cross-domain forwarding, and adversarial reconstruction |

### 1.3 Prerequisite audit of the current paper and system

Before extending the system, verify:

1. The provenance of, and relationship between, the 64 invalid-rebinding checks and 24 mixed hard cases.
2. The actual scoring rules for task success, execution-ready rate, tool-valid rate, and invalid-handle rate.
3. Whether asynchronous semantic detection runs before or after provider submission, and whether first-occurrence exposure is possible.
4. Exactly which information FPS preserves, how surrogates are generated, and how ambiguous mappings are avoided.
5. Which encodings, split exposures, and cross-turn forms the SEG actually supports.
6. Every network and logging egress path, rather than only the final prompt.

**Deliverables:** `CURRENT_SYSTEM_AUDIT.md`, reproducible tests, and a metric-definition document.

---

## 2. Paper Positioning and Research Hypotheses

### 2.1 Recommended positioning

**A protocol-aware local privacy and capability boundary that enables cross-domain agents to collaborate over NLIP without unconditionally sharing raw local context.**

### 2.2 Candidate titles

Preferred candidates:

- **SlotGuard: Task-Aware Privacy and Capability Boundaries for NLIP Agent Collaboration**
- **SlotGuard: Protocol-Aware Information Minimization for Cross-Domain Agents**
- **Local Decisions, Bounded Disclosure: Privacy-Preserving Agent Collaboration over NLIP**

Whether NLIP belongs in the title depends on how much the final contribution relies on its protocol properties. If the method generalizes and NLIP is only one deployment vehicle, use a broader title.

### 2.3 Three primary hypotheses

**H1: Protocol structure enables a better privacy–utility trade-off.**

With matched detectors, protected-object inventories, and replacement mechanisms, processing messages according to their types and field roles should disrupt protocol and tool semantics less than uniform string replacement over serialized messages.

**H2: Recipient binding and deterministic authorization prevent reference misuse that session-only slots cannot prevent.**

Examples include cross-recipient reuse, cross-session replay, out-of-scope operations, and unauthorized delegation. This hypothesis concerns reference and execution control, not prevention of all semantic leakage.

**H3: A local semantic model improves coverage beyond rules, but its benefits must justify latency and over-redaction costs.**

Specialized training is not a prerequisite. If an off-the-shelf small model is sufficient, focus on scheduling, validation, policy, and systems integration. Consider distillation or fine-tuning only if error analysis identifies stable, addressable failure patterns.

### 2.4 Suggested contribution structure

Organize the final paper around three contributions:

1. **Problem and abstraction:** Distinguish cross-domain message disclosure, endpoint-to-model disclosure, reference visibility, and execution authority.
2. **System design:** Combine protocol-aware processing, task-aware local proposals, recipient-bound references, and authorized local execution.
3. **Evidence:** Provide real tasks, strong and fair baselines, adaptive attacks, cost analysis, and a reproducible artifact.

Do not present the adapter, model, SEG, slots, and scheduler as five loosely connected contributions.

---

## 3. NLIP Standards Basis and Design Boundaries

### 3.1 Sources reviewed

- NLIP project overview: <https://nlip-project.org/>
- ECMA-430: <https://ecma-international.org/publications-and-standards/standards/ecma-430/>
- Base specification referenced by this plan: ECMA-430, first edition, December 2025.

ECMA-430 defines messages and submessages, including the `text`, `token`, `structured`, `binary`, `location`, and `generic` formats. The `structured` format includes JSON, URI, XML, HTML, and programming-language representations.

Section 6.2 specifies requirements and exceptions for returning token submessages unchanged. The conversation and authentication prefixes have specific purposes. Implementation must follow the complete specification and the selected binding, not only this plan's summary.

### 3.2 Required reading and version pinning before implementation

- ECMA-431: HTTP/HTTPS binding.
- ECMA-434: Security profiles.
- The exact version and commit of the chosen SDK or reference implementation.
- ECMA-432 if streaming support is actually needed.

The base specification requires production deployments to select an appropriate security profile. Implementing the message JSON alone does not establish full security conformance. This plan does not yet contain a clause-by-clause implementation mapping for ECMA-431 or ECMA-434.

### 3.3 Distinguish three categories of mechanisms

| Category | Examples | How to describe it in the paper |
|---|---|---|
| Existing standard mechanisms | Message formats, submessages, token-return responsibilities | Cite the relevant clauses and adopted versions |
| Implementation behavior | Which information enters the LLM; how logs are handled | Describe the actual endpoint implementation, not a standard guarantee |
| Research extensions | Recipient-bound slots, privacy policies, execution permissions | Explicitly label them proposed extensions or an application profile |

### 3.4 Preserve authentication semantics

Distinguish three classes of information:

1. **Authentication material the communication endpoint is authorized to use:** Handle it through the applicable protocol and security profile, not indiscriminate FPS.
2. **Local secrets accidentally embedded in task content:** Detect, protect, or block their transmission through SlotGuard.
3. **Metadata the endpoint needs but its backing LLM does not:** Keep it in the protocol control plane rather than automatically inserting it into model context.

An intermediary that transforms tokens or terminates sessions must act as an explicit protocol endpoint and assume the corresponding responsibilities. It must not claim to be a transparent byte-for-byte proxy.

### 3.5 Extension strategy

For the first phase, prefer **endpoint-internal policy** without modifying the base wire format.

If cross-endpoint negotiation proves necessary:

- Define an application extension using extension points permitted by the specification.
- Fix its name, version, capability-discovery procedure, rejection behavior, and fallback semantics.
- Explicitly choose a basic protection mode or reject sensitive tasks when the peer does not support the extension.
- Do not treat silently ignored unknown fields as successful security negotiation.
- Do not automatically treat a protocol `token` as an object-authorization credential.

**Deliverables:** `NLIP_CONFORMANCE_MATRIX.md` and `PRIVACY_EXTENSION_DRAFT.md`.

---

## 4. Scenarios, Assets, and Threat Model

### 4.1 Minimal three-party scenario

- **Local coordinator:** The user's orchestration agent, holding the task and privacy policy.
- **Remote worker:** An analysis or development agent in another trust domain, receiving tasks over NLIP.
- **Local execution service:** Accesses local files, runs tools, and performs final authorization and raw-value restoration.

Add a second remote worker in the extended scenario to study cross-recipient linkage and task forwarding.

### 4.2 Protected assets

- User, organization, project, customer, document, and internal-environment identifiers.
- Protected components and sensitive semantics in file paths and URIs.
- Secrets outside authorized disclosure, including API keys, passwords, and tokens.
- Relationships among objects and entities across turns and recipients.
- Access authority and permitted uses of local objects.

### 4.3 Two primary adversary classes

**Privacy adversary:** A remote endpoint or provider that retains received content and uses prior knowledge plus the entire visible transcript to infer sensitive values.

**Active protocol adversary:** A remote agent that generates malicious task messages to replay, forward, or forge references; change requested operations; or induce disclosure of additional context.

Evaluate the two classes separately where appropriate. If recipient collusion is evaluated, explicitly state which views the colluding parties may combine.

### 4.4 Trust assumptions

- Local policy configuration, the SlotGuard reference monitor, slot-mapping storage, and execution service are trusted.
- Identity is established and verified through the selected security mechanism. A `recipient` field, `role` field, or self-asserted identity in a message body is not authentication.
- Untrusted text from tool outputs and documents may be in scope, but a compromised local operating system is not assumed.
- User authorization policy is the permission ceiling; the small model cannot expand it.

### 4.5 Explicit non-goals

- Compromised local operating systems, runtimes, or policy stores.
- Elimination of all timing, size, and traffic-analysis side channels.
- Complete hiding of preserved format, semantics, frequency, and relationships.
- Retraction of raw values already received by an authorized recipient.
- A universal security sandbox for arbitrary tools or shell programs.
- Full privacy protection for images, audio, or binary files that the implementation does not actually inspect.

### 4.6 Two distinct classes of guarantees

**Detection properties:** Coverage of previously unknown sensitive information is empirical and may have false negatives.

**Authorization properties:** For registered objects and operations passing through controlled interfaces, reference scope, permissions, and restoration boundaries can be defined and verified.

The latter may be proved only under explicit assumptions and interface-coverage conditions. It does not imply complete detection.

---

## 5. System Architecture

```text
User policy / Task objective / Local resources
                     |
                     v
          Local tools and agent runtime
                     | observations / requests
                     v
      Protocol-aware parsing and provenance
                     |
          +----------+----------+
          v                     v
      Fast rules       System 1 semantic model
          +----------+----------+
                     v
    Proposal validation + Policy + Entity links
                     v
  Deterministic rewriting and reference issuance
                     v
       Final egress checks / Send barrier
                     v
               NLIP endpoint
============= Cross-domain trust boundary =============
               Remote worker
                     | operation request
                     v
   Authentication binding + Reference/Permission checks
                     v
     Guarded local execution and raw-value injection
                     v
       Tool results pass through egress protection
```

The receiving endpoint should also have an independent **protocol-to-model projection**: authentication data, internal state, and unnecessary protocol metadata must not all be appended to prompts for implementation convenience.

### 5.1 Modules

1. `nlip_adapter`: Parsing, format dispatch, protocol state, and preservation responsibilities.
2. `policy_engine`: Rules for recipients, objects, operations, tasks, and disclosure.
3. `semantic_advisor`: Structured local semantic proposals, without direct output modification.
4. `entity_registry`: Local records of raw values and related forms.
5. `reference_manager`: Recipient-bound references, expiration, revocation, and explicit delegation.
6. `rewriter`: Structure preservation, FPS, and reference substitution.
7. `execution_guard`: Authorization checks, normalization, guarded execution, and restoration.
8. `egress_gate`: Ensures required review completes before sending and covers all supported egress channels.
9. `audit`: Records decisions and errors without copying raw secrets into external telemetry.

### 5.2 Three concepts that must remain distinct

- **Entity ID:** A local-only identifier linking raw values and observed variants.
- **Display slot:** A textual representation that helps the model understand an object's role.
- **Execution authorization:** Permission to perform an operation, validated by the trusted execution service.

A display slot is not sufficient evidence of authority. Knowing the text of a valid slot must not enable its use by an unauthorized recipient, in an unauthorized session, or for an unauthorized operation.

---

## 6. Recipient-Bound References and Authorization

### 6.1 Proposed internal record

The following is an internal data structure, not a claim that NLIP already standardizes these fields:

```text
ReferenceRecord:
    local_object_id
    display_type
    external_handle
    authenticated_principal
    session_binding
    policy_version
    allowed_operations
    allowed_resource_scope
    expiry
    delegation_policy
    revocation_state
```

Raw values and the complete entity graph remain local. External identifiers should be unpredictable and checked for collisions. The encoding scheme depends on the protocol and threat model.

### 6.2 Access checks

Before each use of a protected object, check:

1. Which authenticated principal originated the request?
2. Does the reference belong to that principal and an allowed session?
3. Has it expired, been revoked, or become inconsistent with the applicable policy?
4. Is the requested operation permitted?
5. Is the normalized target within the allowed resource scope?
6. Does the returned result require further protection?

Signed or MAC-protected external tokens still require audience checks, replay handling, revocation, and state consistency. Signatures alone do not solve those problems.

### 6.3 Forwarding and delegation

The first version should **disallow implicit delegation by default**.

If agent A wants to delegate work to B:

- Forwarding A's visible slot does not automatically grant B authority.
- The local authorization service decides whether to issue a new restricted reference for B.
- New authority must not exceed the original authority or user policy.
- Use a distinct identifier for B to avoid unnecessary direct equality linkage.

Different identifiers across recipients do not prevent linkage through shared content, tasks, or timing. State that boundary explicitly.

### 6.4 Path and execution safety

- Use platform-appropriate path normalization and object-scope checks.
- Test symbolic links, encoding variants, relative paths, case rules, and time-of-check/time-of-use risks.
- Prefer structured tool calls and argument arrays over interpolating restored values into shell commands.
- Do not treat a shell-metacharacter denylist as a complete execution-security mechanism.
- Inject raw secrets only at the final authorized local execution boundary.

### 6.5 Additional FPS requirements

- Record all deliberately preserved metadata: type, length, prefix, alphabet, separators, and similar properties.
- Distinguish conditional independence of an individual surrogate from privacy of the full transcript.
- Detect duplicate surrogates, ambiguous restoration, and collisions with existing values.
- Do not assume a random credential-shaped string can never accidentally be valid. Test and runtime environments must prevent synthetic credentials from being mistakenly used against real external services.
- Do not automatically interpret an unregistered credential-shaped literal returned by a remote agent as an authorized local credential.

---

## 7. The Local System 1 Model

### 7.1 Model tasks

Prefer verifiable subtasks over a free-form transcript sanitizer:

- Sensitive-span detection.
- Type classification.
- Linking to existing entities.
- Disclosure recommendations conditioned on the task and recipient.
- Uncertainty or escalation indicators.

### 7.2 Inputs

- The outgoing fragment and bounded context.
- A task objective prepared by the trusted policy layer.
- Recipient trust category, without unnecessary identity details.
- Allowed protection types, operations, and disclosure modes.
- Necessary summaries from the local entity registry.

A claim inside untrusted content that "the user has authorized disclosure" must not override trusted inputs.

### 7.3 Outputs

```text
Proposal:
    message_part_id
    exact_span_or_offsets
    entity_type
    candidate_existing_entity_id
    proposed_action
    uncertainty_signal
```

The runtime verifies positions, exact source matches, types, entity-access permissions, and allowed actions. Invalid proposals are rejected and trigger a predefined safe fallback.

### 7.4 Training strategy

**Phase A: No training.** Evaluate off-the-shelf local instruction models at several sizes for structured output, detection recall, over-redaction, and latency.

**Phase B: Error analysis.** Build a specialized dataset only if errors consistently involve task-conditioned decisions, cross-turn aliases, or structural boundaries.

**Phase C: Targeted distillation or fine-tuning.** Combine teacher-assisted generation with human verification and programmatic ground truth.

Do not rely solely on teacher self-assigned labels. Do not construct training data from test templates or entity variants.

### 7.5 Confidence and calibration

Self-reported model confidence is not inherently reliable. Use a separate calibration set to evaluate precision, recall, and risk thresholds. If using log probabilities or a classification head, validate calibration and out-of-distribution behavior as well.

### 7.6 First-occurrence transmission policies

| Policy | Privacy implication | Purpose |
|---|---|---|
| Send after rules; run the model in the background | First-occurrence exposure is possible | Weak baseline only, not a strong privacy mode |
| Wait for the model on every candidate | Coverage of unknown content still depends on the model | Quality and latency reference point |
| Risk routing with blocking review | Content incorrectly classified as low-risk may still leak | Study the quality–cost trade-off |
| Conservatively mask or refuse transmission before review | Stronger content control, potentially lower utility | High-risk mode |
| Ask for user confirmation | Additional interaction cost | Cases outside automatic authorization policy |

**Hard constraint:** Content marked as requiring review must not enter any remote request before review completes. A timeout must not silently fall back to sending raw content.

The first version should not investigate speculative raw transmission: later substitution cannot retract information already sent.

---

## 8. Benchmark Design

### 8.1 Workload layers

**W1: Protocol and reference microtests**

- Format parsing, submessage ordering, and token return.
- Unknown extensions and rejection semantics.
- Session changes, replay, expiration, and revocation.
- Recipient substitution, privilege expansion, and delegation.

**W2: Synthetic privacy stress tests**

- Direct, embedded, split, encoded, derived, and cross-turn exposures.
- Sensitive filenames, customer names, internal system names, and benign lookalikes.
- Forms outside rule coverage and irrelevant task context.

**W3: Real executable tasks—the core evaluation**

1. Repository debugging: The remote agent diagnoses and fixes a bug; tests execute locally.
2. Document analysis: The remote agent organizes queries; local services read sensitive documents and return restricted results.
3. Configuration and service troubleshooting: Secrets remain local while the remote agent plans diagnostic steps.
4. Multi-agent delegation: Different workers have different responsibilities and must not reuse each other's references.

**W4: Adaptive attacks**

- Reconstruction from the entire transcript.
- Sequential questions that accumulate partial information.
- Forged authorization, protocol-control instructions, and slots.
- Prompt injection in malicious tool outputs or documents.
- Forwarding, replay, recipient collusion, and reference privilege escalation.

### 8.2 Data sources and sensitive values

- Start with clearly licensed public tasks and repositories containing controlled, planted sensitive information.
- Use test material, sandbox services, or canaries that cannot access real accounts. Do not collect or publish production credentials.
- If real sanitized traces are included, define authorization, retention, and manual-review procedures.
- Distinguish "real task structure with planted private information" from "naturally occurring real private information."

### 8.3 Initial scale and expansion targets

These are budgeting targets, not commitments to a final sample size:

- Prototype: 20–30 tasks, 2–3 workflow types, and two recipients.
- Candidate main evaluation: 100–200 independent source tasks across multiple task families.
- Randomized roots, users, entities, and recipient variants assess robustness; they do not count as independent source tasks.
- Determine the final scale from pilot variance, paired differences, and execution cost.

### 8.4 Preventing dataset contamination

Split by repository, task family, and organization or entity family.

- Keep rewrites and workspace-root variants of one source task in the same split.
- Prevent related synthetic-template variants from creating near-duplicates across training and test sets.
- Build separate format-, entity-, and task-distribution-shift sets.
- Tune policy thresholds only on validation or calibration splits.

### 8.5 Human annotation

Define clear annotation guidelines for:

- Which spans are sensitive.
- Which recipients may receive them.
- Which structural properties may be retained.
- Which replacement outcomes are acceptable.
- Which operations are authorized.

For ambiguous examples, record multiple acceptable policies. Report agreement and adjudication procedures rather than forcing every problem into a single exact-string answer.

---

## 9. Baselines and Ablations

### 9.1 Main baselines

| Baseline | Purpose |
|---|---|
| Raw + standard authentication/encryption | Raw utility and protocol-security reference; not a content-privacy defense |
| Generic redaction + equivalent restoration support | Measure the cost of losing structure without deliberately withholding restoration capabilities |
| Rule-based secret/PII detector + typed slots | Strong rule-based baseline |
| Generic local-model sanitizer | Compare free-form rewriting with constrained proposals |
| Current SlotGuard | Establish improvement over the workshop version |
| Protocol-aware SlotGuard without a small model | Isolate protocol and authorization benefits |
| Full system | Evaluate the complete method |

If retaining a VibeGuard-style baseline, identify it as a derived placeholder baseline. Do not generalize its results to the official system's overall performance.

### 9.2 Fairness controls

- Match the main agent, tools, tasks, model-call budgets, and retry policy.
- Match detection coverage when comparing structural replacement methods; match substitution and restoration capabilities where possible when comparing detectors.
- Match policies and known sensitive objects when evaluating protocol awareness. Do not give only the proposed method a stronger oracle.
- Apply equal attack budgets to all defenses.

### 9.3 Ablations

- Serialization-level versus protocol-aware parsing.
- Session-only versus recipient-bound references.
- No authorization checks versus operation- and scope-based authorization.
- No memory versus an exact entity table, a simple SEG, and learned linking.
- Rules versus a small model versus rules plus a small model.
- Task-blind versus task-conditioned decisions.
- Block-all review versus risk routing versus conservative fallback.
- Different small-model sizes and quantization settings.

Prioritize informative ablations rather than exhaustively crossing every dimension and exhausting the budget.

### 9.4 Diagnostic oracles

Include two non-deployable baselines:

- Oracle sensitive spans: Estimate replacement and execution performance without detection errors.
- Oracle policy labels: Estimate the impact of policy-decision errors.

Explicitly identify these as diagnostic tools, not deployable methods.

---

## 10. Metrics, Statistics, and Success Criteria

### 10.1 Privacy metrics

- **Literal exposure:** The fraction of protected values or predefined sensitive components appearing in unauthorized remote-visible surfaces.
- **Reconstructive exposure:** The fraction of values recoverable under predefined combination, encoding, or linkage rules.
- **Attacker reconstruction success:** The success rate of an independent attacker recovering target values from the full visible transcript.
- **Policy violation:** The rate of events that violate disclosure policy for a specified recipient.
- **Over-redaction:** Unnecessary hiding of benign or task-required content, along with its task-level cost.

Report denominators separately for objects, occurrences, messages, sessions, and tasks. Do not collapse all units into one "leak rate."

Separately report credential types revealed by format, contextual linkage, and repeated-slot relationships. The absence of explicit category labels does not imply that categories cannot be inferred.

### 10.2 Execution and authorization metrics

- Unauthorized-operation success rate.
- Cross-recipient and cross-session reference-reuse success rate.
- Delegation-policy bypass rate.
- False rejection of legitimate references.
- Replay, expiration, and revocation check outcomes.
- Protocol conformance and connection or session failure rates.

Detecting a sensitive value and preventing an unauthorized operation are different events and must be measured separately.

### 10.3 Utility metrics

- End-to-end task completion verified by an independent evaluator.
- Task-specific outcomes, such as passing tests, correct output files, or service state.
- Valid tool-call rate, rework, and retries.
- User confirmations and additional interaction rounds.

Handle selection is a subsidiary metric, not a substitute for actual task completion.

### 10.4 Performance metrics

- Time spent in local rules, model inference, validation, rewriting, and authorization.
- Full-task wall-clock latency, including p50 and p95.
- Cold and warm starts.
- CPU/GPU configuration, memory, quantization, model version, and context length.
- Remote tokens, calls, backoff, and parsing retries.
- Throughput and concurrent-session behavior.

Microsecond rewriting measurements alone cannot support a claim that the entire privacy layer is nearly free.

### 10.5 Statistical methods

- Compare systems on matched tasks using paired analyses.
- Cluster randomized root variants by source task or task family.
- Repeat random seeds within budget and distinguish task variability from model-sampling variability.
- Report appropriate confidence intervals for task success, leakage, and reconstruction attacks.
- Do not interpret zero observed failures as a zero true failure probability; report finite-sample uncertainty.
- Prespecify primary metrics and comparisons to avoid selecting only favorable models or subsets.

### 10.6 Proposed engineering and research decision criteria

These are pilot decision targets, not predetermined paper results:

- All defined protocol and reference-invariant tests must pass. An execution boundary with a known bypass is not complete.
- Initially target no more than a 5-percentage-point utility loss relative to Raw, then reassess in light of task risk and confidence intervals.
- Initially target approximately 20% or less median end-to-end overhead from the local layer in warm runs, while also inspecting p95.
- The small model must show consistent gains on held-out semantic and cross-turn cases, not merely higher in-distribution F1.
- Under matched threats and budgets, the full system should improve the privacy–utility Pareto frontier over the strongest relevant baseline.

If targets are missed, report and explain the outcome. Do not change denominators or remove difficult tasks to manufacture success.

---

## 11. Invariants and Provable Properties

Potential properties to formalize under a restricted interface model:

1. **Audience isolation:** A reference issued only to A cannot be successfully used by B.
2. **No authority amplification:** Execution authority is bounded by the intersection of user policy and issued permissions.
3. **Locality of raw mappings:** Controlled transmission paths do not serialize the raw slot table.
4. **Restricted restoration:** Raw secrets are injected only at authorized local execution boundaries.
5. **Review before sending:** Messages marked as requiring review cannot be sent before the decision.
6. **Preservation of protocol control:** Content rewriting does not violate adopted token or control semantics.

State the assumptions explicitly: all relevant operations pass through the reference monitor, authentication is reliable, trusted components are uncompromised, and reference resolution and resource normalization are correct.

Do not call these properties full-transcript noninterference. Preserved structure and context may themselves carry information.

Use unit tests, property-based tests, state-machine tests, and narrowly scoped formal arguments where useful. Formalization is not a way to prove that a classifier never misses sensitive content.

---

## 12. Twelve-Week Execution Plan

### Weeks 1–2: Audit, standards mapping, and pilot

Tasks:

- Verify the current system and metric definitions.
- Read pinned versions of NLIP, the binding, and the security profile.
- Run the minimal three-party workflow and 20–30 tasks.
- Establish consistent event logging and network-egress inspection.
- Evaluate off-the-shelf small models instead of immediately training one.

Deliverables: Standards mapping, threat model v1, pilot data, and a taxonomy of key errors.

**Gate A:** If protocol awareness or multiple recipients do not introduce a verifiable new problem, reduce NLIP's role in the paper rather than forcing a protocol-specific narrative.

### Weeks 3–4: Protocol boundary and reference mechanisms

Tasks:

- Implement text/JSON/URI/code dispatch.
- Implement principal/session binding, permissions, expiration, and revocation.
- Disallow implicit delegation by default.
- Complete token preservation and protocol-to-model projection.
- Implement an explicit send barrier and timeout fallback.

Deliverables: Working system, state-machine and property tests, and a list of unsupported formats.

**Gate B:** Demonstrate legitimate task completion and resistance to the defined malicious-reference tests. Otherwise, fix the execution layer before adding model functionality.

### Weeks 5–6: Benchmark and semantic component

Tasks:

- Expand independent tasks and privacy annotations.
- Freeze grouped splits.
- Complete rule-based, generic-local-model, and protocol-aware-without-model baselines.
- Analyze semantic errors and decide whether distillation or fine-tuning is warranted.
- Calibrate risk-routing thresholds.

Deliverables: Benchmark v1, model-selection report, and fixed main-experiment configurations.

**Gate C:** Do not train a new model if an existing one is sufficient. If model gains do not justify utility or latency costs, retain rules and protocol controls as the main contribution.

### Weeks 7–8: Main end-to-end experiments

Tasks:

- Execute complete tasks using the selected main agents and models.
- Run core ablations and stage-level latency analysis.
- Collect failure cases and actual execution traces.
- Check reproducibility and benchmark contamination.

Deliverables: Main result tables, Pareto plots, failure taxonomy, and cost report.

### Weeks 9–10: Attacks and generalization

Tasks:

- Run full-transcript reconstruction attacks.
- Test reference forwarding, replay, privilege escalation, and recipient collusion.
- Test prompt injection in untrusted content.
- Evaluate held-out repositories, entities, task families, and formats.
- Add CPU-only and concurrent-execution results.

Deliverables: Attack matrix, generalization results, remaining limitations, and remediation notes.

### Weeks 11–12: Writing and artifact preparation

Tasks:

- Organize the paper around the three primary contributions.
- Release implementation configurations, prompts, model versions, and statistical methods.
- Prepare representative tasks and attacks runnable with one command.
- Conduct independent reproduction and audit every paper claim.

Deliverables: Complete draft, artifact, reproducibility checklist, and recommendations for submission venues.

> Twelve weeks is one research iteration, not a guarantee of a production-grade system or completion of every target experiment. Large agent evaluations and model training may require more time.

---

## 13. Resources and Budget Management

### 13.1 Computing resources

- Local model: Initially cover a CPU-runnable configuration and one GPU configuration.
- Main agents: Select models with meaningfully different capabilities or architectures rather than maximizing model count.
- Sandbox: Restrict outbound networking, exclude real credentials, and provide resettable filesystems and services.
- Storage: Protect raw test mappings and exclude production secrets from public artifacts.

### 13.2 API budget formula

Measure the terms during the pilot:

```text
Total cost ≈ Number of tasks × Number of conditions × Repetitions
             × Average calls per task × Average model cost per call
```

Budget attacks separately. Prioritize informative main comparisons; broad ablations can focus on representative models and tasks.

### 13.3 Suggested workstreams

- Implementation and conformance.
- Benchmark, evaluators, and annotation.
- Experiments, attacks, and analysis.

For a primarily single-researcher effort, finish the minimal system and reliable evaluation before expanding into training. Do not maintain several transport bindings simultaneously at the outset.

---

## 14. Major Risks and Alternative Directions

| Risk | Early signal | Response |
|---|---|---|
| NLIP is only an adapter | Removing NLIP leaves all conclusions unchanged | Focus on protocol structure and authorization semantics, or make NLIP one deployment instance |
| Limited model benefit | Rules cover most examples | Add naturally difficult semantic cases; do not force training into the contribution |
| Excessive latency | Per-turn local inference dominates execution | Investigate batching, caching, and risk routing; explicitly state any remaining first-occurrence exposure |
| Over-redaction harms tasks | Frequent failures or confirmations | Refine structure preservation, policy granularity, and local execution interfaces |
| Rewriting breaks authentication | Token-return or session tests fail | Separate the control plane from model content and follow endpoint semantics |
| References are mistaken for permissions | A copied slot enables unauthorized execution | Add principal binding and independent authorization checks |
| Reconstruction attacks still succeed | Context reveals sensitive values | Reduce retained context, disclose residual risk, and avoid overstating anonymization |
| Overly synthetic data | Raw scores are nearly perfect; tasks are repetitive | Add independent real source tasks, natural noise, and external distributions |
| Weak baselines | Missing restoration, low budgets, or narrow detectors | Match capabilities, budgets, and policies; include strong rules and local-model baselines |
| Fragmented paper narrative | Five or six modules each receive shallow treatment | Organize around disclosure boundaries, controlled references, and end-to-end evidence |

### Alternative A: Systems and security focus

If reference isolation and protocol processing provide strong benefits but the model adds little, emphasize cross-domain information and capability boundaries. Treat the model as a pluggable detector.

### Alternative B: Task-aware model focus

If semantic decisions drive the gains and NLIP-specific properties contribute little, focus on task-aware information minimization and use NLIP as a real integration environment.

### Alternative C: Benchmark focus

If multi-agent privacy evaluation is substantially underdeveloped, prioritize a rigorously defined, executable benchmark and systematic analysis. Do not overpromise a universal defense before the method is mature.

---

## 15. Paper Structure and Key Figures and Tables

### Suggested outline

1. Introduction: Why cross-domain collaboration is harder than a single-model transcript boundary.
2. Background: NLIP, existing SlotGuard, and the control and content planes.
3. Threat Model and Objectives: Assets, recipients, authority, and visible surfaces.
4. Design: Protocol awareness, semantic proposals, references, and execution controls.
5. Implementation: Actual coverage, binding, security configuration, and engineering choices.
6. Evaluation: Utility, exposure, protocol and authorization security, costs, and generalization.
7. Limitations and Discussion.
8. Related Work.
9. Conclusion.

### Key figures

- Figure 1: Three-party collaboration and the two privacy boundaries.
- Figure 2: Message lifecycle from protocol parsing to local execution.
- Figure 3: Privacy–utility Pareto frontier.
- Figure 4: Latency breakdown across local modules and remote inference.
- Figure 5: Cross-recipient forwarding and replay attacks, with enforcement points.

### Key tables

- Table 1: Boundaries between standard mechanisms, endpoint implementation, and research extensions.
- Table 2: Independent source tasks, families, private objects, and dataset splits.
- Table 3: Main real-task utility and exposure results.
- Table 4: Authorization, protocol, and attack results.
- Table 5: Key ablations.
- Table 6: Local-model size, coverage, over-redaction, and complete costs.

---

## 16. Concrete Checklist for the Next Seven Days

### Day 1: Align the research direction

- Identify the intended System 1 local-model architecture and relevant reference systems.
- Select the main threats: an honest-but-curious remote party and active reference misuse.
- Limit the first version to text/JSON/URI/code.

### Day 2: Standards and implementation audit

- Read ECMA-431 and ECMA-434 and pin implementation versions.
- Audit current SlotGuard and every egress path.
- Specify token handling and model-context projection.

### Day 3: Minimal NLIP workflow

- Run local coordinator → remote worker → local execution service.
- Add five reliably scored end-to-end tasks.

### Day 4: Reference isolation

- Add a second recipient.
- Implement principal/session binding.
- Verify that copying a slot does not grant authority to another recipient.

### Day 5: Local semantic-model pilot

- Compare rules and off-the-shelf small models on a fixed small dataset.
- Record actual latency, invalid outputs, misses, and over-redaction.

### Day 6: Expand to 20–30 tasks

- Run Raw, current SlotGuard, protocol-aware SlotGuard without a model, and an initial full system.
- Include first occurrences, cross-turn aliases, forwarding, and privilege-escalation cases.

### Day 7: Go/no-go review

Answer three questions:

1. What does protocol awareness provide that ordinary sanitization does not?
2. Which real, reproducible attack does recipient binding prevent?
3. Does the model's additional coverage justify latency and utility costs?

Produce a two-page pilot memo covering results, failure cases, and next-phase scope. If these questions cannot be answered clearly, revise the problem definition before investing in training or large API experiments.

---

## 17. Final Recommendation

**Priority order: Real end-to-end tasks and an explicit threat model → protocol and reference boundaries → off-the-shelf small models → specialized training only when supported by evidence.**

The strongest full-paper narrative is not "SlotGuard now supports NLIP." It is:

> **Protocol interoperability does not automatically provide information minimization. We design a local, task- and recipient-aware boundary that lets agents collaborate on protected objects without unconditionally obtaining raw context or access authority.**

Support this narrative with protocol correctness, actual execution, active attacks, and full-system costs.
