# Contractual Agents: A Secure Agent Framework with Contract‑Based Tool Calls, Brokered Secrets, WASM Skills, Multi‑Agent Orchestration and Artifact‑First Outputs

## Contents

1. Executive summary
2. Problem analysis and motivation
3. Design goals and requirements
4. Threat model
5. Overall architecture
6. Contracts: unified authorization objects
7. Policy engine: capability model, budgets and data guards
8. Brokered secrets: zero token exposure
9. Runner: execution areas, egress control and output sanitizer
10. Skills and plugin model
11. Scheduled and event‑driven automation
12. Multi‑agent support and orchestration
13. Artifact‑based outputs
14. Memory scopes and promotion
15. Audit, observability and forensics
16. End‑to‑end reference workflows
17. Deployment and monorepo structure
18. Glossary
19. Outlook and roadmap
20. Closing remarks

## 1 Executive summary

Artificial intelligences acting as personal assistants, companion agents or business agents are rapidly gaining popularity. Projects like **OpenClaw** (formerly *ClawdBot* or *MoltBot*) demonstrate how powerful such agents can be. They simultaneously connect to messengers, email systems, cloud services, Git repositories and operating‑system tools. That convenience comes with severe security risks. Analyses show that OpenClaw requires wide‑ranging permissions – file system access, bash execution rights, API keys and network access – so complexity and the attack surface rise([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Users often install the assistant with broad access to email, files, calendars and API keys without proper isolation([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). In many installations the local web interface is exposed publicly or operated without authentication, allowing attackers to control the agent over the network([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)).  

OpenClaw typically runs a local gateway process with a Control UI, loads skills inside the same process and stores credentials locally. That coupling means UI, skill code and secrets share the same trust boundary, so a compromise can expose everything.

Across analyses, recurring failure classes emerge: prompt injection to execute commands, over‑broad integrations with long‑lived tokens, supply‑chain risk in the skills ecosystem and web‑UI misconfiguration.

In February 2026, a high‑severity vulnerability (CVE‑2026‑25253) was reported that enabled a *one‑click RCE* attack: the Control UI trusted a `gatewayUrl` query parameter and automatically sent the gateway token when establishing a WebSocket connection. Clicking a crafted link was enough to leak the token to an attacker, who could then modify the configuration and execute arbitrary commands([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). The root cause was missing validation of the WebSocket origin; thus a malicious page could capture the token, authenticate to the gateway and bypass the sandbox([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). This incident shows that existing security features such as sandboxes and approval mechanisms do not sufficiently mitigate such attacks([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).  

Another problem is the unvetted ecosystem of “skills.” Community plugins can carry malware and request unrestricted permissions. Researchers found numerous malicious skills on the unofficial marketplace ClawdbHub([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)).  

This white paper summarises our chat discussions and introduces a new framework that addresses these issues. It presents **contractual agents** – an architecture that strictly separates privileges, authorizes every tool use via explicit contracts, and never passes secrets directly to the language model. Each design decision is motivated by the underlying problem, its implications are explained, and a solution is presented.


## 2 Problem analysis and motivation

### 2.1 Excessive permissions and missing isolation

**Problem:** OpenClaw operates as a local gateway process with a web UI. To function, the agent connects files, email, calendars, chat channels and cloud APIs. To “just make things work,” users grant the agent read/write access to the file system, shell execution, long‑lived API tokens and network permissions([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). In many setups the web interface listens on all interfaces without authentication([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). Credentials are stored locally and skills execute inside the gateway process, meaning tools, UI and secrets share the same process boundary.

**Implication:** The agent becomes a superuser that can read emails, delete files, execute code or modify cloud accounts without further restriction. A single misconfiguration or compromise (e.g. via RCE) provides attackers with access to all of the user's systems. Because agents use machine‑learning models, they are also vulnerable to prompt injection. Executing shell commands and file access in the same environment increases the likelihood that malicious inputs will lead to unexpected actions.

**Solution:** Our framework introduces a **capability model** that decomposes all actions into fine‑grained capabilities. Each capability is tied to concrete parameters (e.g., allowed paths, allowed recipients) and can only be executed within an approved **contract**. By default, every capability is disabled; users must enable them per agent, workspace or job. The gateway remains the central entry point but has no execution rights – it only relays messages and collects confirmations through a trusted UI.

### 2.2 Token leakage and Control UI misconfiguration

**Problem:** The CVE‑2026‑25253 bug shows that tokens can be leaked to the web. The Control UI forwarded the `gatewayUrl` from the query string directly into the WebSocket connection; thus an attacker could intercept the gateway token([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Further analysis revealed that cross‑site WebSocket hijacking could compromise gateways that bound only to `localhost`([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Attackers could disable confirmation requirements (`exec.approvals.set`) or run shell tools on the host by toggling `tools.exec.host`([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).

**Implication:** Stealing the gateway token grants administrative control over the agent. The attacker can turn off safety mechanisms, run commands on the host instead of the container and perform arbitrary actions. Existing sandbox and approval systems do not protect against this class of attack([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)). Binding to `localhost` alone is insufficient because the user’s browser can be abused as a bridge([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).

**Solution:** In our framework, **secrets never enter the model prompts** nor the UI. Tokens and keys remain exclusively in the **secrets broker**. When a runner must call an API, it receives only an *opaque handle* from the broker. This handle is bound to a single tool, specific parameters, a short timeframe and a specific runner. Even if an attacker intercepted the handle, they could not misuse it to call external services. The Control UI stores no tokens in the browser; connections are secured via pairing and mTLS, and requests are always server‑side signed.

### 2.3 Insecure skill ecosystems

**Problem:** The OpenClaw community shares skills without rigorous review. Many packages are unmaintained or contain malware. Researchers have shown that numerous skills request broad permissions, include malicious payloads or exfiltrate sensitive data([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)). The project’s multiple renamings facilitate phishing and uploading fake extensions([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)); a VS‑Code plug‑in called “ClawdBot Agent,” for example, was a trojan([JFrog analysis](https://jfrog.com/blog/giving-openclaw-the-keys-to-your-kingdom-read-this-first/)).

**Implication:** Trusting an unregulated skills ecosystem means attackers can spread malicious extensions. If a user installs such a skill, the attacker inherits the agent’s privileges: reading/writing files, sending emails, running shell commands. Existing mechanisms can barely limit these permissions because skills run in the same process as the agent.

**Solution:** In our architecture, skills are **WASM modules** executed in isolation. Each skill package contains a signed manifest declaring its ID, version, publisher, required capabilities, tool schemas and allowed network targets. Installation verifies the signature, and the user must explicitly enable the skill per agent or workspace. Tools within a skill can only access resources approved by the policy engine. When native functionality is required (e.g., hardware access), developers must adopt a two‑stage approach: the WASM module orchestrates logic, and a separate **native companion service** performs the action in an isolated environment. This service is authenticated via mTLS, and each request is bound to an approved contract and policy decision.

### 2.4 Unsupervised automation

**Problem:** Users want to run tasks periodically or triggered by events (e.g., “start a backup every night”, “create a daily status report”). In OpenClaw, agents can execute scheduled or reactive actions without further approval. The broad permissions and missing role separation let these jobs perform uncontrolled changes or send external messages while the user sleeps.

**Implication:** Unsupervised agents amplify the risk of massive damage. Prompt injections in emails or logs can manipulate automated jobs. Incorrect LLM responses can delete data or send confidential information to outsiders. A single error in a cron job can send hundreds of emails or alter production systems.

**Solution:** The framework introduces **job principals**: every scheduled job runs as its own principal with specific rights. A job may run unsupervised only if it is created from an approved **reusable contract**. This contract defines allowed tools, parameter limits, budgets (runtime, number of tool calls, data volume), target allowlists and data handling rules. If a job deviates from this contract or the version of a skill, policy or tools changes, the system automatically pauses the job and demands re‑approval. In addition, unsupervised jobs have stricter default policies: they may not use high‑risk tools (e.g., shell execution) and must obtain out‑of‑band approval before sending external messages.

### 2.5 Handling large and unpredictable outputs

**Problem:** Many tasks, such as automated code generation or report creation, produce large outputs. LLM‑based systems that insert such data directly into the chat context hit context limits or risk exposing sensitive information in prompts.

**Implication:** Unlimited outputs can lead to high costs (token usage), unreadable chats and data leakage. In existing agent designs, code diffs, logs or documents are often pushed into the conversation without trimming.

**Solution:** Our framework introduces **artifacts** as the primary form of large outputs. Tools that generate large datasets (e.g., code patches, reports, databases) store these as files in an artifact store. The engine returns only a summary, a preview and a reference to the artifact. Contracts set limits on artifact size, number of changed files, allowed file types and retention. For code tasks we recommend workflow steps: plan which files to modify, generate the patch, test it, have a review performed and finally apply it – the latter requiring a new approval. This keeps the conversation concise and ensures controlled processing.


## 3 Design goals and requirements

The following goals underpin all design decisions:

1. **Zero token exposure (G1).** The LLM must never obtain access to API keys, tokens or other secrets. Secrets remain in the secrets broker and are released only as non‑reusable handles to runners. This prevents a compromised model from exfiltrating tokens([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).
2. **Deny by default (G2).** No actions are allowed without explicit approval. All capabilities are initially disabled; users must enable them per agent, workspace or job.
3. **Contract‑based execution (G3).** Each tool is executed only within an approved contract – either one‑shot or reusable. Contracts define parameter limits, budgets, data handling and validity.
4. **Isolated execution (G4).** The agent engine cannot execute tools directly. Tools run in **runners** (WASM sandboxes or isolated containers). Native functions are accessible only via companion services.
5. **Trusted approvals (G5).** Risky actions (e.g., external sends, file writes) require approval through the Control UI (paired device). Approvals via chat messages are not accepted.
6. **Auditability (G6).** All decisions (allow, deny, approval), all tool calls, artifact creations and outgoing actions are logged immutably.

We also define a **default hardening profile** that is enabled for new installations:

- Gateway reachable only via `localhost` and pairing; no public interfaces without explicit policy.
- Strict deny‑by‑default for capabilities, network egress only via allowlists.
- No tokens or secrets in the browser or LLM context.
- High‑risk tools disabled by default in jobs; step‑up approval via the Control UI.
- Output redaction and artifact limits enabled to protect PII and secrets.


## 4 Threat model

The framework protects against the following attack vectors:

- **Prompt injection and malicious user input.** Untrusted input from chats, web or emails must not trigger high‑privileged actions without filtering.  
- **UI attacks (cross‑site hijacking).** Tokens must not be stored in the browser; mTLS and strict header validation are required to prevent RCEs like CVE‑2026‑25253([The Hacker News](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)).  
- **Malware in skills/plugins.** Only signed WASM skills may be installed; native code runs in isolation.  
- **Open ports and misconfiguration.** The gateway listens only on `localhost` by default. Exceptions require explicit network policies.  
- **Exfiltration via tools or artifacts.** Output filters prevent secrets, PII or tokens from leaving the system.  

Out of scope are compromised hosts or hardware attacks. A root‑compromised OS can bypass the framework. The focus is on software security guarantees.


## 5 Overall architecture

The architecture is modular (see the diagram below). Key components:

1. **Gateway:** The central interface for all inputs (messengers, email, UI). It manages sessions, pairing and displays approval requests. The gateway has no execution rights; it only forwards messages and decision results.
2. **Engine:** Feeds the LLM, extracts intent, generates plans and proposes tool calls. It cannot execute tools or access secrets.
3. **Policy Engine:** Evaluates proposed tool calls based on contracts, capabilities and budgets. Its output is “allow,” “deny” or “approval required.” Data guards inspect inbound and outbound data for sensitive content.
4. **Runner:** The execution environment for tools. Each capability runs in an isolated sandbox (WASM or container). Runners use the secrets broker to call APIs with short‑lived handles.
5. **Skill Registry:** The repository for signed WASM skills and their metadata. It also manages enablement per agent/workspace.
6. **Secrets Broker:** Stores long‑lived secrets (OAuth refresh tokens, API keys). Releases only short‑lived, parameter‑bound handles to runners.
7. **Scheduler:** Executes reusable contracts on schedules or in response to events under strict policy enforcement.
8. **Audit Log:** Immutable record of all activities, decision processes, contracts, approvals and artifacts.

![High‑level architecture diagram](assets/architecture_diagram.png)

Figure 1: High‑level architecture diagram.


## 6 Contracts: unified authorization objects

### 6.1 Contract types

- **One‑shot contract:** Valid for a single action. Parameters must exactly match the stored hash. Example: “Send this email now.”
- **Reusable contract:** For scheduled or recurring actions like cron jobs. Defines constraints (e.g. allowed search queries, allowed recipients), budgets and usage limits. Tied to policy and skill versions; changes pause the job and require re‑approval.

### 6.2 Binding modes

- **Exact:** The parameter hash must match exactly. Increases security but reduces flexibility.
- **Bounded:** Parameters must lie within an allowed set (e.g. query allowlist, maximum number of results). Ideal for recurring jobs with variable input.

### 6.3 Approval user experience

Contracts are presented to the user in the Control UI as a “permissions card” with these elements:

- Type (one‑shot / reusable) and purpose.  
- Tools, parameter bounds, target allowlists and budgets.  
- Data handling rules: no attachments, secret redaction, maximum size.  
- Pins on policy and skill versions.  
- Optional dry‑run execution.

The user can approve, adjust or deny the contract. When changes occur (e.g. through plugin updates), a diff is displayed and the user must re‑approve.


## 7 Policy engine: capability model, budgets and data guards

The policy engine is the central gatekeeper between engine and runner:

- **Capabilities** define atomic rights, e.g. `cap.email.read` with query allowlists and max results, or `cap.fs.write` with an allowed path.  
- **Modes:** Interactive sessions vs. scheduled jobs. Scheduled jobs have stricter limits (e.g. no high‑risk tools).  
- **Budgets:** Limits for tool calls per run, runtime, messages, bytes, tokens and cost.  
- **Data guards:** Inspect inbound and outbound content (prompt injection, PII, secrets). They may truncate or block messages containing sensitive data.  

The policy engine writes every decision to the audit log. When evaluating a tool call, it:

1. Loads the contract and checks if it is valid, not expired and approved.  
2. Ensures the principal (session / job) matches the contract.  
3. Validates parameters according to binding mode and constraints.  
4. Checks budgets: are limits for this run not yet exceeded?  
5. Considers risk class: high‑risk tools require interactive approval.  
6. Logs the result and returns allow/deny/approval.


## 8 Brokered secrets: zero token exposure

The framework implements a **secrets broker** that manages long‑lived keys and issues only short‑lived handles. This prevents secrets from accidentally entering prompt contexts or leaking over the network. The flow:

1. **Policy grants permission:** On successful evaluation the policy generates an internal decision record.  
2. **Runner requests handle:** It calls `AcquireHandle(decision_id, tool_call_id)` on the broker.  
3. **Broker verifies:** Is the decision valid? Does the runner identity match? Are parameters bound?  
4. **Broker returns handle:** The handle is valid only for this call, this tool, a specific parameter hash and a brief TTL.  
5. **Runner performs action:** It uses the handle internally to call the API.  
6. **Handle expires:** It cannot be reused or exfiltrated outside the runner.

The LLM receives only the `decision_id` and metadata, never the handle itself. The broker acts as a **token‑delegation layer**: each tool call gets a one‑time, tightly scoped delegation handle that is usable only inside the runner.

Unlike token passing (as in OpenClaw), this ensures that even if an attacker captured the handle they could not call external services because they would also need the runner identity, the decision record and the parameter hash.


## 9 Runner: execution areas, egress control and output sanitizer

Runners are the “workbench” of the framework. Each tool class has a dedicated runner (e.g. email runner, filesystem runner, Slack runner). The runner executes a tool in an isolated environment and must:

- **Sandbox:** Use a **WASM runtime** by default. The runner process itself runs in a separate container with minimal rights.  
- **Egress filter:** May connect only to hosts/ports allowed by policy. All other network connections are forbidden.  
- **Resource limits:** Enforce CPU time, memory and file sizes.  
- **Filesystem mounts:** Write access only to defined paths; read rights can be pattern‑restricted.  
- **Output sanitizer:** Before returning results to the engine, remove or mask tokens, auth headers, API keys, PII and other defined patterns. Large outputs become artifacts.


## 10 Skills and plugin model

### 10.1 WASM skills

Each skill consists of a signed **WASM module** and a **manifest**. The manifest defines:

- `skill_id`, version, publisher (publisher ID) and signature.  
- A list of tools (`tools`), their names, input and output schemas and a risk class.  
- Required capabilities (`required_capabilities`) and allowed network targets (`egress_requirements`).  

The skill registry verifies the signature at import. When a skill is installed, the user must enable it in the Control UI per agent or workspace. Tools may only use the capabilities declared in the manifest; other calls are denied by policy.

### 10.2 Native companion services

If a skill needs native access (e.g. hardware, browser automation), the developer must supply a **two‑component** solution:

- **WASM part:** Contains the orchestration and logic. This defines the tool and invokes only host functions.  
- **Native companion service:** Runs as a separate process or container, has limited rights and exposes only a minimal API. It is authenticated via mTLS; every request must present a valid decision record. The service re‑checks parameter constraints, egress filters and calls the required native APIs.

This separation keeps native code manageable without granting the WASM plugin uncontrolled access to the host.

### 10.3 MCP servers as skills (optional)

Instead of a custom plugin ecosystem, **MCP servers** can be treated as skills. Each MCP server is registered with a manifest containing tool schemas, authentication methods and a capability mapping. The policy engine gates **every** MCP tool call; the runner proxies requests and enforces parameter bounds, budgets and egress allowlists.

Two modes are supported:

- **Local MCP servers:** Run inside a sandbox or as a companion service with minimal rights. Access is protected via mTLS or a local socket policy.
- **Remote MCP servers:** Reachable only through allowlists, require strong authentication (mTLS/OAuth) and receive a delegated handle per call from the secrets broker. Tokens stay in the broker; the LLM never sees credentials.

This preserves MCP flexibility while keeping the contractual security guarantees intact.


## 11 Scheduled and event‑driven automation

The framework supports cron jobs, event triggers (webhooks, database changes), **conditional rules** and one‑shot timers. Key elements:

- **Job principals:** Every scheduled task runs as its own principal (`job:<id>`). A job is associated with a reusable contract defining tools, parameter allowlists, budgets and data policies.
- **Misfire strategies and time handling:** Schedules are stored in UTC but interpreted in the local time zone. Missed runs can be skipped or caught up depending on configuration.
- **Strict budgets:** Cron jobs have smaller budgets than interactive sessions. No shell execution and no new capabilities without approval.
- **Idempotency and outbox:** Every side effect uses an idempotency key (`job_run_id + action_hash`). Retries check an outbox before sending/posting/mutating.

When tools, policies, skill versions or parameters change, the scheduler pauses the job and shows the user a change diff for renewed approval.


## 12 Multi‑agent support and orchestration

The identity model distinguishes **users**, **agents** and **principals** (session/job). Every tool call is bound to a principal, which enables precise separation of rights and budgets.

### 12.1 Agent profiles

Each agent is a configurable “profile”:

- **Persona:** Tone, style and goals.  
- **Enabled skills:** List of activated WASM skills.  
- **Policy profile:** Budgets and high‑risk rules.  
- **Memory scope:** Which memory areas (session, agent, workspace, user) can be read or written.  
- **Allowed channels:** Which messengers or communication paths the agent may use.  

The engine can host multiple agents concurrently. Messages are routed to the appropriate agent based on workspace/channel.

### 12.2 Orchestration patterns

- **Single engine, many agents:** A single engine process hosts multiple agents. Policy separates capabilities and memory access per agent.  
- **Supervisor / worker:** A supervisor agent with minimal rights plans tasks and delegates them to specialised workers (e.g. code generator, reviewer, tester). Complex tasks are split into separate steps, each worker having only the minimal necessary rights.

### 12.3 Cross‑agent communication

Agents can exchange data via structured artifacts and results, but internal chat messages are treated as untrusted input. Data hand‑off occurs via artifact‑based interfaces; approvals remain agent‑specific.


## 13 Artifact‑based outputs

Instead of sending large data directly into the chat, the framework uses **artifacts**. An artifact is a structured dataset with metadata (type, size, hash, storage location, access policy). Examples:

- **Patch:** Code diff (e.g. Unified diff format).  
- **Report:** Markup file (e.g. Markdown or PDF) with detailed content.  
- **Dataset:** JSON or CSV file.  
- **LogBundle:** Collection of log files or test results.  
- **DraftMessage:** Draft message for user review.  

The contract defines maximum sizes, allowed file types and retention. The engine returns only a short summary and optionally a preview (e.g. the first lines of a patch) and a link to open the artifact in the UI. This preserves chat context and hides sensitive data from the LLM.


## 14 Memory scopes and promotion

The framework distinguishes several memory areas:

- **Session memory:** Temporary notes for a running conversation. Deleted automatically at the end of the session.  
- **Agent memory:** Long‑term preferences and facts for the respective agent.  
- **Workspace memory:** Shared knowledge within an organisation.  
- **User memory:** Personal information stored only with the user's explicit consent.  

Promotion requires explicit user confirmation; the LLM cannot independently store new facts permanently. All retrieved memory is considered untrusted. On retrieval, provenance and integrity are checked; suspicious entries can be withdrawn by the user.


## 15 Audit, observability and forensics

Every interaction produces an audit entry. Entries include:

- Contract proposals, changes and approvals.  
- Policy decisions (allow/deny/approval).  
- Tool executions (ID, parameter hash, result hash).  
- Artifact creation and access.  
- Job runs and scheduler events.  
- Outgoing messages (destination, content hash).  

The audit log is write‑only; only append operations are allowed. Observability is achieved through structured logs, metrics (e.g. runtime, denial counts, costs) and distributed traces. Forensic tools can reconstruct who authorized what, when a particular action was performed and which data left the system.


## 16 End‑to‑end reference workflows

This section provides two typical workflows with contracts.

### 16.1 Nightly ops digest (reusable contract)

**Description:** Every night at 02:00, the agent should search emails from `alerts@corp.com` from the last 24 hours (max 50 messages), fetch the first 10 messages, create a summary and post it to the Slack channel `#ops-alerts`.

**Contract:**

- **Tools:** `gmail.search` (bounded – query allowlist `from:alerts@corp.com newer_than:1d label:ops`, max 50 results), `gmail.getMessage` (bounded – only fields `subject`, `from`, `date`, `snippet`, max 10 messages), `slack.post` (bounded – only channel `#ops-alerts`, max 4000 characters).  
- **Budgets:** max 20 tool calls, max 60 seconds runtime, max 1 outgoing message.  
- **Data handling:** No attachments, no full email bodies, secret redaction.  
- **Pins:** Policy hash, tool catalog hash and skill set hash. Changes pause the job.  
- **Approval:** Once via the Control UI by the user; then the job runs unsupervised as long as it stays within the limits.  

**Why this is safe:** Even if emails contain malicious instructions, the job can only retrieve specified fields and send one message to a single Slack channel within strict size limits. Any deviation (e.g., new query, larger result set, change of channel) pauses the job and requires re‑approval.

### 16.2 Coding task with unpredictable output (artifact‑based)

**Description:** The user asks the agent to implement a new feature. This task may produce large code patches and requires tests and reviews.

**Recommended workflow:**

1. **Plan:** The LLM generates a list of files to be modified, a short description of the changes and the test strategy.  
2. **Patch generation:** The `codegen.patch` tool creates a diff based on the plan. The diff is stored as an artifact. Parameter restrictions (max file count, max diff size, no changes to `.env` or key files) are part of the contract.  
3. **Validation:** A runner executes tests (`pnpm test`, `pnpm lint`) in an isolated environment (no network). Test logs are stored as an artifact.  
4. **Review:** Optionally, a second agent (reviewer) with read‑only access to the patch artifact provides feedback.  
5. **Apply:** A third agent (applier) may apply the patch (e.g. via `git apply`) only when the user approves a one‑shot contract in the Control UI.  
6. **Summarise:** The LLM creates a short summary of the changes, lists the files changed and provides testing instructions.  

**Security:** Generation, tests and review run without write access to the repository. Only the applier has limited write rights, and the action requires a separate approval. This reduces the risk of an error or prompt injection bringing uncontrolled code into the production environment.


## 17 Deployment and monorepo structure

For collaboration on GitHub, a clear structure is recommended:

```
repo/
  docs/whitepaper_de.md              # Whitepaper (German)
  docs/whitepaper_en.md              # Whitepaper (English)
  docs/assets/architecture_diagram.png
  apps/
    gateway/                         # Channels, UI, pairing
    control-ui/                      # Web UI for approvals, jobs, audit
    engine/                          # Agent loop
    policy/                          # Policy engine
    runner/                          # Tool execution (runner pool)
    worker/                          # Background worker for jobs/queues
    broker/                          # Secrets broker
    scheduler/                       # Cron/event scheduler
  packages/
    core/                            # Shared types and schemas
    agent-runtime/                   # Agent runtime, state and session handling
    contracts/                       # Hashing, diffing, validation
    policy/                          # DSL and evaluator
    scheduler-lib/                   # Scheduling utilities, calendar logic
    queue/                           # Job and tool dispatch
    wasm-runtime/                    # WASM execution environment
    tools-sdk/                       # SDK for tool adapters and MCP bridges
    skill-sdk/                       # Manifest and tool schema helpers
    artifacts/                       # Artifact storage and scanners
    audit/                           # Audit log implementation
    memory/                          # Memory management
    testing/                         # Test harnesses and security suites
  skills/
    example-wasm-skill/
  companions/
    example-native-companion/
  examples/
    nightly-ops-digest/
    codegen-patch-workflow/
```

This structure aids component separation, enables CI tests for each layer and provides a clear starting point for contributions.

**Testing strategies:** We recommend policy regression tests (allow/deny matrix), contract‑diff tests, a prompt‑injection corpus, sandbox‑escape tests and end‑to‑end workflows with artifacts and MCP/WASM skills. Security‑relevant changes should pass all tests before new skills or policies are approved.



## 18 Glossary

- **Agent:** Configured assistant with persona, skills and a policy profile.
- **Principal:** Security identity for a session or job to which tool calls are bound.
- **Contract:** Authorization object defining tools, parameters, budgets and data rules.
- **Capability:** Fine‑grained permission for a tool class with parameter bounds.
- **Policy Engine:** Evaluates tool calls against contracts, budgets and risk tiers.
- **Runner:** Isolated execution environment for tools (WASM or containers).
- **Secrets Broker:** Stores long‑lived secrets and issues short‑lived handles.
- **Skill:** Signed tool package (WASM or MCP server) with a manifest.
- **Artifact:** Externalized output for large data (patches, reports, log bundles).
- **Job Principal:** Principal for scheduled jobs with tight rights and budgets.
- **Control UI:** Trusted approval and pairing surface.
- **Data Guards:** Filters for prompt injection, PII and secret leakage.

## 19 Outlook and roadmap

The presented architecture lays the foundation for a secure agent framework. Future versions should focus on the following topics:

- **Policy DSL (v0.4):** A human‑readable language (e.g. YAML) compiled to policy rules.  
- **Native companion protocol (v0.4):** Defines the mTLS handshake and authentication mechanisms as well as the request model.  
- **Contract diff algorithms (v0.4):** To reliably display changes between contracts.  
- **Skill transparency log (v0.5):** Public records of skill signatures and their history.  
- **Anomaly detection (v0.5):** Automatic pausing of jobs when unusual behaviour is detected.  
- **Multi‑tenant hardening (v0.5):** Policies for tenant separation and encrypted artifact storage.  


## 20 Closing remarks

The growing prevalence of autonomous agents demands a paradigm shift: away from the “assistant with all rights” toward **contractual agents** that may only do what has been explicitly authorized. Through contracts, clear capabilities, a brokered secrets layer, isolated runners, signed WASM skills and strict audit logs, the proposed framework dramatically reduces the attack surface. At the same time, the user experience remains familiar: a local gateway chat with Control UI, pairing and skills – but with the level of security that modern applications require.
