# Contractual Agents Framework

## Overview

A secure-by-design framework for building personal assistants, companion agents and business automation bots that can act through tools without exposing credentials or taking uncontrolled actions. This README is a condensed, self-contained summary of the full design; the detailed specifications live in the whitepapers.

## Quick Links

- German whitepaper: [whitepaper_de.md](./docs/whitepaper_de.md)
- English whitepaper: [whitepaper_en.md](./docs/whitepaper_en.md)
- Architecture diagram: [architecture_diagram.png](./docs/assets/architecture_diagram.png)
- Compose deployment proposal: [deployment_docker_compose.md](./docs/deployment_docker_compose.md)
- Pseudocode examples: [pseudo_code/](./pseudo_code/)

## Problem and Evidence

OpenClaw-style assistants demonstrate strong UX but expose systemic risk. Typical deployments run a local gateway with a Control UI, store credentials locally, and load skills inside the gateway process. That coupling makes a single compromise catastrophic. Analyses report overly broad permissions (filesystem, shell, long-lived API tokens, network access), misconfigured or publicly exposed web UIs and unvetted skills ecosystems that can carry malware or exfiltrate data ([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). A high-severity 2026 issue (CVE-2026-25253) showed how a crafted link could leak a gateway token via WebSocket and allow remote command execution, highlighting how UI misconfiguration can bypass sandboxing and approvals ([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Recurring failure classes include prompt injection, over-broad integrations with long-lived tokens, supply-chain risk in skills and insecure UI defaults.

## Architecture

The framework replaces implicit trust with explicit contracts and strict isolation. Core components:

- Gateway: user interaction, message ingress, pairing and Control UI. It never executes tools.
- Engine: runs the agent loop and proposes tool calls. It never touches secrets or tools.
- Policy Engine: gates every tool call and enforces contracts, budgets, risk tiers and data guards.
- Runner Pool: executes tools in isolated sandboxes (WASM or containers) with strict egress allowlists.
- Secrets Broker: holds long-lived credentials and issues per-call delegation handles.
- Skill Registry: manages signed skills and per-agent enablement.
- Scheduler: runs reusable contracts for cron, event-driven, conditional and one-shot jobs.
- Audit Log: append-only record of approvals, decisions, tool calls and artifacts.

## Security Invariants and Decisions

- Zero token exposure: the LLM never sees API keys or bearer tokens.
- Deny by default: every capability must be explicitly approved.
- Fine-grained capabilities: permissions are defined per tool and parameter scope.
- Contract-based execution: all tool calls must match an approved contract (one-shot or reusable).
- Step-up approvals: high-risk actions require out-of-band confirmation in the Control UI.
- Isolated execution: tools run in sandboxed runners with strict egress and resource limits.
- Data guards and output redaction: prompt injection, secrets and PII are filtered before results return to the model.
- Artifact-first outputs: large results are stored as artifacts and summarized in chat.
- Full auditability: every decision and action is logged immutably.

## Contracts and Approvals

Contracts are the unit of authorization. They bind tools, parameter constraints, budgets, data handling rules and policy versions. One-shot contracts cover interactive actions, while reusable contracts cover scheduled jobs. Binding modes include exact parameter hashes and bounded ranges for recurring tasks. Policy diffs and version changes pause execution until a user re-approves.

## Skills and Integrations

The default plugin model uses signed WASM skills with manifests that declare tool schemas, required capabilities and allowed network targets. Native access is handled by companion services behind mTLS and policy checks.

As an alternative, MCP servers can be treated as skills. Each MCP server is registered with a manifest, strict authentication and a capability mapping. The policy engine still gates every tool call. Local MCP servers run in sandboxes; remote MCP servers are allowlisted and receive per-call delegated handles from the secrets broker. Tokens never reach the LLM.

## Automation and QoL Features

- Scheduling: cron, event-driven triggers, conditional rules and one-shot timers.
- Job principals: each job runs as its own principal with tight, time-bound budgets.
- Misfire and DST handling: schedules are stored in UTC and evaluated in local time zones.
- Idempotency and outbox: retries check an outbox before sending or mutating data.
- Safe defaults: high-risk tools are disabled for jobs unless explicitly approved.

## Multi-Agent Model

The identity model distinguishes users, agents and principals (session or job). Agents have profiles (persona, enabled skills, policy profile, memory scope, allowed channels). Orchestration patterns include single-engine multi-agent hosting and supervisor-worker pipelines with minimal rights for each step. Cross-agent data exchange happens via artifacts and remains untrusted by default.

## Large Outputs and Coding Tasks

Unknown-length outputs (patches, reports, datasets) are stored as artifacts with size and type limits. The recommended code workflow is plan, generate patch, validate, review, then apply via a separate one-shot approval. This avoids oversized prompts and limits the blast radius of mistakes.

## Reference Workflows

Reference workflows include a nightly ops digest (email search, summary, Slack post) and a coding task pipeline (plan, patch, tests, review, apply), both enforced through reusable and one-shot contracts.

## Pseudocode Examples

See the `pseudo_code/` directory for technology-neutral flows:

- `01_interactive_email_flow.md`
- `02_scheduled_digest_job.md`
- `03_policy_toolcall_pipeline.md`

## Deployment Proposal

See [deployment_docker_compose.md](./docs/deployment_docker_compose.md) for a compose-based deployment proposal with non-root containers and early privilege drop.

## Memory Scopes

Memory is separated into session, agent, workspace and user scopes. Promotion requires explicit user consent, and all retrieved memory is treated as untrusted input with provenance checks.

## Repository Layout (Proposed)

```text
repo/
  docs/
    whitepaper_de.md
    whitepaper_en.md
    deployment_docker_compose.md
    assets/
      architecture_diagram.png
  pseudo_code/
    01_interactive_email_flow.md
    02_scheduled_digest_job.md
    03_policy_toolcall_pipeline.md
  apps/
    gateway/
    control-ui/
    engine/
    policy/
    runner/
    worker/
    broker/
    scheduler/
  packages/
    core/
    agent-runtime/
    contracts/
    policy/
    scheduler-lib/
    queue/
    wasm-runtime/
    tools-sdk/
    skill-sdk/
    artifacts/
    audit/
    memory/
    testing/
  skills/
  companions/
  examples/
```

## Testing and Hardening

- Policy regression tests (allow/deny matrices).
- Contract diff tests and approval replay tests.
- Prompt-injection corpora and red-team scenarios.
- Sandbox escape tests and egress policy verification.
- End-to-end workflows with artifacts and MCP or WASM skills.

Default hardening includes localhost-only gateway access, strict allowlists, no tokens in the browser and enforced output redaction.

## Glossary

- Agent: configured assistant with persona, skills and a policy profile.
- Principal: security identity for a session or job to which tool calls are bound.
- Contract: authorization object defining tools, parameters, budgets and data rules.
- Capability: fine-grained permission for a tool class with parameter bounds.
- Policy Engine: evaluates tool calls against contracts, budgets and risk tiers.
- Runner: isolated execution environment for tools (WASM or containers).
- Secrets Broker: stores long-lived secrets and issues short-lived handles.
- Skill: signed tool package (WASM or MCP server) with a manifest.
- Artifact: externalized output for large data (patches, reports, logs).
- Job Principal: principal for scheduled jobs with tight rights and budgets.
- Control UI: trusted approval and pairing surface.
- Data Guards: filters for prompt injection, PII and secret leakage.

## Roadmap (Summary)

- Policy DSL for human-readable rules.
- Native companion protocol standardization.
- Contract diff algorithms and transparency logs for skills.
- Anomaly detection and multi-tenant hardening.

## Sources

- OpenClaw permissions, UI exposure and skills ecosystem risks: [JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)
- CVE-2026-25253 and token leakage via WebSocket Control UI: [The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)
