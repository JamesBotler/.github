Contractual Agents Framework

This project contains a reference implementation of a contractual agent framework — a secure-by-design system for running language‑model assistants that can act through tools without exposing credentials or taking uncontrolled actions. The framework grew out of a detailed analysis of existing agentic assistants such as OpenClaw, which require broad file‑system, network and shell permissions, often run with misconfigured web interfaces and have been vulnerable to token‑leak attacks (e.g., CVE‑2026‑25253). These weaknesses inspired a new architecture that uses contracts, policy enforcement, isolation and signed WebAssembly (WASM) plugins to deliver similar functionality with dramatically reduced attack surface.

What problem does this solve?

Modern agents are powerful because they can read emails, files and calendars, run shell commands, access cloud APIs and send messages. In practice, they are often over‑permissive: tokens are stored in configuration files or sent to the browser, skills downloaded from the community can be malicious, and scheduled jobs run unsupervised with the same rights as interactive sessions. A single prompt‑injection can trick the model into deleting files or emailing sensitive data. Furthermore, large outputs (e.g. code patches) can blow up context windows or leak secrets.

The contractual agents framework addresses these issues by introducing:

Fine‑grained capabilities: All tools are expressed as explicit capabilities (e.g. read‑only email search, post to a specific Slack channel). Nothing is allowed by default.

Contracts: A tool invocation must belong to a contract — either one‑shot (single use) or reusable (scheduled jobs). Contracts define parameter constraints, budgets and data‑handling rules. They are presented to the user in the Control UI for approval.

Zero token exposure: Secrets remain exclusively in a secrets broker. When a tool needs to call an external API, the runner requests an opaque, short‑lived handle bound to a specific contract. The language model never sees API keys or bearer tokens.

Isolated execution: Tools run in runners that enforce network allowlists, resource limits and filesystem sandboxes. WASM skills are signed modules executed in a sandbox; native functions must be implemented via a companion service behind policy checks.

Safe automation: Scheduled jobs execute under their own principal with a reusable contract. Any change to the contract, policy or skill versions pauses the job for re‑approval. Budgets and idempotency guarantees prevent runaway actions.

Artifact‑first outputs: Large results such as code patches or reports are stored as artifacts with size and type limits. Chat responses contain only summaries and references.

Architecture overview

The framework is composed of several cooperating services:

Component	Responsibility
Gateway	Receives messages from messengers, displays the Control UI, manages sessions and pairing. It has no execution rights.
Engine	Runs the language model, generates plans and proposes tool calls. It never accesses secrets or executes tools.
Policy	Evaluates tool proposals against contracts and capability rules. It enforces budgets, data‑handling policies and approval requirements.
Runner	Executes tools in isolation (WASM sandboxes or containers) and sanitises outputs. It obtains broker handles for API calls.
Secrets Broker	Stores long‑lived credentials and issues short‑lived handles for specific tool calls. Secrets never enter the model context.
Skill Registry	Manages signed WASM skills, their manifests and enablement per agent.
Scheduler	Executes reusable contracts on schedules or in response to events, under strict policy enforcement.
Audit Log	Records all contracts, approvals, decisions, tool executions and artifacts in an append‑only store.

Key design decisions

Minimum privilege: Agents and jobs must request only the specific capabilities they need. By default, everything is denied until explicitly approved.

Contract‑based authorisation: Tools cannot be invoked ad hoc; instead, every call is bound to a contract. The Control UI presents the contract for the user to approve, showing allowed parameters, outputs and budgets. Scheduled tasks (cron jobs, event triggers) use reusable contracts; one‑off actions use one‑shot contracts.

Trusted approvals: High‑risk actions (sending external messages, writing files) require confirmation via the Control UI on a paired device, never via the untrusted chat channel. Tokens are never stored in the browser, avoiding the CVE‑2026‑25253 class of bugs.

Isolated skills: Third‑party functionality is packaged as signed WebAssembly modules. Each skill declares its required capabilities and network allowlists; unknown network access is blocked. If native access is required, a companion service with strict interfaces is used instead of giving the plugin arbitrary host access.

Explicit automation: Jobs run with their own principals and strict budgets (time, calls, cost, data volume). Deviations or upgrades to policies or skills halt the job until the user re‑approves.

Artefact handling: Large outputs are written to artefacts; chat messages only include summaries. This prevents oversized prompts and accidental exposure of secrets.

Repository structure

The GitHub repository is organised to encourage modularity and contributions:

docs/whitepaper/WHITEPAPER.md    # In-depth documentation of the design (this project’s whitepaper)
README.md                       # This file
apps/
  gateway/                      # Channel adapters and Control UI
  engine/                       # Agent loop implementation
  policy/                       # Capability rules and contract enforcement
  runner/                       # Tool execution environment
  broker/                       # Secrets broker service
  scheduler/                    # Scheduled and event-driven job executor
packages/
  core/                         # Shared types, schemas and utilities
  contracts/                    # Contract definition, hashing and diffing
  wasm-runtime/                 # WASM runtime and sandbox
  skill-sdk/                    # Helpers for authoring skills and manifests
  artifacts/                    # Artifact storage and scanning
  audit/                        # Append-only audit log
  memory/                       # Memory scopes and promotion logic
  testing/                      # Test harnesses and security suites
skills/                         # Example skills implemented as WASM modules
companions/                     # Example native companion services
examples/                       # Reference workflows (ops digest, codegen patch)

Getting started

Install dependencies: The repository uses modern TypeScript tooling (pnpm, turborepo) and a Rust or Go backend for the broker and runner. See the individual apps/ READMEs for language‑specific instructions.

Run locally: Start the gateway (pnpm run dev), policy, runner and broker services. The gateway serves the Control UI at http://localhost:3000. Pair a device and enable built‑in skills.

Explore examples: Try the example workflows in examples/, such as the nightly ops digest or code generation patch pipeline. Approve the contracts in the UI and observe how the system enforces boundaries.

Develop skills: Use the packages/skill-sdk to create new WASM skills. Write a manifest declaring your tool schemas and required capabilities. Package and sign the module. Test it against the policy engine before publishing.

Contribute: Contributions are welcome! Please read CONTRIBUTING.md (coming soon) for coding standards, branch policies and how to propose improvements to the policy DSL or broker protocol.

Further reading

The full design rationale, threat analysis, formal models and future roadmap are detailed in the project’s whitepapers. We provide two fully‑authored versions:

German (de): see whitepaper_v3.md (docs/whitepaper/ or download the compiled file) for an in‑depth discussion in the original language. It covers all design decisions, motivations and solutions.

English (en): see whitepaper_v3_en.md for the translated, peer‑reviewed version of the same content. Both versions cite real‑world vulnerabilities such as the CVE‑2026‑25253 token leakage and the risks posed by unvetted skills.

Reading the whitepapers is highly recommended for anyone extending or integrating the framework. They explain the design decisions in detail and provide context for the problems we aim to solve.
