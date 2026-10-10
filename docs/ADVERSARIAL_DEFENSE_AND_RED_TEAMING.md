# Agent Octopus: Autonomous Swarm Breakout Defense & Multi-Framework Red Teaming Guide

## Overview

Agent Octopus is an enterprise-grade defense platform and deterministic zero-trust policy engine designed to neutralize autonomous swarm breakouts, lateral privilege escalation, and prompt injection attacks against LLMs and agentic microservices.

The architecture comprises **9 Specialized Arms** orchestrated by an isolated central Brain, governed by formal **AWS Cedar v4.13** authorization policies, hardware-isolated Windows Job Objects, AppContainer sandboxes, and cryptographic append-only SHA-256 audit trails.

### Dual-Layer Operating Model: Inline Gateway & Multi-Arm Enclave

Agent Octopus operates as both an **inline authorization gateway** and an **isolated multi-arm execution enclave**. Specifically:

1. **Inline Zero-Trust Security Gateway (`CedarAuthorizationGateway`)**:
   - It acts directly as an Authorization & Policy Enforcement Gateway (`/api/evaluate-cedar`).
   - Every tool call, actuator directive, and agent transaction must pass through this gateway to receive a cryptographically signed capability token and supervisor attestation before execution can proceed.
   - It evaluates requests against formal AWS Cedar PARC (Principal, Action, Resource, Context) policies. If a request is unauthorized, the gateway intercepts and blocks it.

2. **Decoy Tarpit Gateway (`TarpitArm`)**:
   - When hostile scans, prompt injections, or unauthorized callers hit the gateway, the Tarpit Arm acts as a deception/sinkhole proxy.
   - It introduces deterministic backoff latency, exhausts attacker context windows with synthetic canary honey-tokens, and isolates repeat offenders in quarantine.

3. **Multi-Limb Agent Enclave (`ArmRuntime`)**:
   - Behind the gateway, Agent Octopus is a distributed cephalopod architecture with 9 specialized, sandboxed arms (`DocumentArm`, `LedgerArm`, `NetworkArm`, `TarpitDecoyArm`, etc.).
   - The arms run inside Windows Job Objects (64MB memory clamps), AppContainer sandboxes, and Wasmtime fuel meters. If an arm experiences a security breach, the system trips an internal circuit breaker (autotomy) to sever that limb while keeping the central Brain and remaining arms intact.

So while it contains an entire isolated multi-agent execution environment, the front line intercepting all requests and red-teaming probes is indeed a deterministic zero-trust policy gateway.

---

## 🐙 The 9 Specialized Arms Architecture

| Arm | Operating Isolation | Permitted Boundary & Capabilities |
| :--- | :--- | :--- |
| `DocumentArm` | Wasmtime Fuel + AppContainer | Read/extract on `s3://invoices/` only; strict prompt sanitization |
| `LedgerArm` | Job Object Memory Clamp (64MB) | Write on `Ledger` under $100,000 ceiling with supervisor cryptographic token |
| `NetworkArm` | Strict Google Egress Filter | HTTP/HTTPS egress exclusively to `google.com` and `www.google.com` |
| `CedarPolicyArm` | Deterministic Rust PARC Engine | Default-deny enforcement; 2-of-3 quorum required for policy mutation |
| `TarpitDecoyArm` | Progressive Delay & Honey-Tokens | Throttles adversaries, burns LLM context with decoy canary tokens, auto-quarantines |
| `VulnerabilityArm`| Read-Only Sandbox | Deep static & dynamic vulnerability inspection of candidate payloads |
| `AttackChainArm` | Graph Synthesis Enclave | Multi-step lateral movement path analysis and containment |
| `MitreAtlasArm` | ATLAS v4.1 Threat Matrix | Real-time mapping against 16 tactics and 208 AI attack techniques |
| `BehavioralSentinelArm` | Sliding Window Watchdog | Fast-path entropy anomaly detection and statistical spike alerts |

---

## 🛡️ Integrated Multi-Framework Red-Teaming Suites

Agent Octopus integrates continuous verification harnesses across 19 industry red-teaming frameworks and auditing tools:

### 1. Agentic & Multi-Turn Red Teaming
- **Garak (The "Nmap for LLMs")**: Generative AI vulnerability scanner probing for prompt injections, canary token data exfiltration (`canary_token_secret_xyz123`), jailbreaks (DAN, cipher, multi-lingual), and hallucinated privileged tool calls.
- **DeepEval (Confident AI)**: Unit-testing framework testing multi-turn policy compliance, unauthorized cross-arm tool calls, and prompt/credential leakage across conversation turns.
- **Inspect AI (UK AI Safety Institute)**: Benchmarking agentic tool call execution paths, enforcing strict OS filesystem confinement, and clamping dynamic multi-step reasoning loops.
- **Promptfoo**: Lightweight security matrix evaluating jailbreaks, SSRF smuggling (`169.254.169.254`), and PII exfiltration guardrails.

### 2. Autonomous Attack Surface & Pentesting
- **PentestGPT (GreyDGL)**: Attack tree multi-step scenarios simulating reconnaissance, lateral privilege escalation from untrusted document ingestion to ledger access, and quorum tampering.
- **RedAmon (samugit83)**: Autonomous attack surface graph mapping executing targeted probes within isolated sandbox environments to detect structural API weaknesses.
- **Caido (Rust Auditing Proxy)**: High-speed proxy workflow replaying tampered HMAC capability tokens, bit-flipped signatures, corrupted headers, and HTTP pipeline desync attempts.

### 3. API & Stateful Fuzzing
- **Astra**: Automated REST API security testing focusing on Broken Object-Level Authorization (BOLA / IDOR) across tenant ledgers, authentication bypasses, and data injection flaws.
- **RESTler (Microsoft Research)**: Stateful REST API fuzzer dynamically testing OpenAPI sequence state transitions, out-of-order quorum approvals, and parameter type/concurrency race mutations.

### 4. Multimodal & Multilingual Verification
- **Multimodal Vision (PyRIT & PromptBench)**: Feeding genuine PNG, JPEG, and TIFF binary streams with embedded adversarial text in chunks and EXIF metadata into the document scratchpad to verify that the peripheral sanitizer neutralizes them before core model ingestion.
- **Multilingual Determinism (PyRIT & Garak)**: Evaluating Cedar zero-trust authorization decisions across **74 world languages** covering all writing systems (Latin, Cyrillic, Arabic, Perso-Arabic, Devanagari, Bengali, Tamil, Telugu, Gurmukhi, Gujarati, Ethiopic, Burmese, Khmer, Lao, Georgian, Armenian, Greek, Hebrew, Sinhala, Mongolian, Thai, Hangul, Kanji/Kana, Hanzi, and African languages including Swahili, Yoruba, Zulu, Amharic, Hausa, Somali, Afrikaans) to ensure policy decisions remain 100% deterministic regardless of input language.

### 5. Agent-to-Agent Collusion & Lateral Breakout Persuasion (PentAGI)
- **Authority Impersonation & Emergency Protocol Spoofing**: Rogue arms forging emergency protocol codes (e.g., OMEGA-9) or claiming executive verbal overrides to coerce peer arms into unauthorized actions.
- **Simulated Security Drill & Pentest Gaslighting**: Deceptive agents claiming an authorized penetration testing exercise is underway and requesting temporary firewall/quorum deactivation.
- **Confused Deputy & Delegation Laundering**: Unprivileged agents attempting to forward privileged actions to peer arms under the guise of collaborative teamwork.
- **Sybil Swarm Fake Consensus**: Rogue swarm nodes synthesizing fake multi-agent gossip consensus to bypass 2-of-3 quorum requirements.
- **Sympathy, Urgency & Ethical Trolley Coercion**: Emotional and ethical blackmail (e.g., hospital emergencies, impending client bankruptcy) urging bypass of supervisor checks.
- **Hypothetical Roleplay & Sci-Fi Framing**: Prompting peer agents to adopt unconstrained alter-egos ("FreeOctopus") or participate in fictional breakout stories.
- **Recursive Inter-Agent Loops & Fuel Starvation**: Deep circular delegation chains designed to overflow call stacks and deplete Wasmtime fuel.
- **Watchdog Suppression & Autotomy Tampering**: Rogue arms attempting to suppress behavioral sentinel alarms and clear quarantine states without quorum.
- **Canary & Signing Secret Extraction**: Inter-arm reconnaissance probing for supervisor signing secrets and honeypot canary tokens.

---

## 🚀 How to Use & Run Tests

### 1. Web Dashboard (Interactive GUI)
1. Start the Agent Octopus defense daemon:
   ```powershell
   .\start.exe
   ```
2. Open your browser to `http://127.0.0.1:5000` (or `5001`).
3. Use the **Test Runner & Progression** tab to select any suite (e.g. `Agent Collusion & Breakout`, `Multilingual Determinism`, `Garak`, `DeepEval`, `Inspect AI`, `Promptfoo`, `Astra`, `RESTler`, `Multimodal Vision`, or `Multi-Framework Comprehensive Suite`) and click **Run Selected Suite**.
4. Observe live terminal execution, running counters, and real-time Tarpit Arm telemetry.

### 2. Command Line Interface (CLI)
You can invoke the Python verification harness directly:

```powershell
# Run the complete exhaustive test suite across all 12 perimeters and 19 frameworks:
python d:\tools\strix_llm_adversarial_tester.py --skip-strix

# Run specific specialized frameworks:
python d:\tools\strix_llm_adversarial_tester.py --suite collusion       # Agent Collusion & Breakout (30 tests)
python d:\tools\strix_llm_adversarial_tester.py --suite multilingual    # Multilingual Determinism (74 Languages / 148 tests)
python d:\tools\strix_llm_adversarial_tester.py --suite garak           # Garak LLM Vulnerability Scanner
python d:\tools\strix_llm_adversarial_tester.py --suite deepeval        # DeepEval Multi-Turn Compliance
python d:\tools\strix_llm_adversarial_tester.py --suite inspect_ai      # Inspect AI (UK AISI)
python d:\tools\strix_llm_adversarial_tester.py --suite promptfoo       # Promptfoo Guardrails
python d:\tools\strix_llm_adversarial_tester.py --suite pentestgpt      # PentestGPT Attack Tree
python d:\tools\strix_llm_adversarial_tester.py --suite redamon         # RedAmon Attack Surface Graph
python d:\tools\strix_llm_adversarial_tester.py --suite caido           # Caido Rust Proxy Replay
python d:\tools\strix_llm_adversarial_tester.py --suite astra           # Astra REST API Security
python d:\tools\strix_llm_adversarial_tester.py --suite restler         # RESTler Stateful REST Fuzzer
python d:\tools\strix_llm_adversarial_tester.py --suite multimodal      # Multimodal Vision & OCR Ingest
python d:\tools\strix_llm_adversarial_tester.py --suite pyrit           # PyRIT AI Risk Suite (Microsoft)

# Run native Rust unit and integration policy tests:
cargo test --test cedar_policy_tests
```

---

## 🍯 The Tarpit Decoy Defense Arm (`TarpitArm`)

The `TarpitArm` is Agent Octopus's active defense honeypot and compute exhaustion mechanism:

1. **Deterministic Progressive Backoff**: Delays hostile requests (from 2ms base up to 50ms+ under backoff) to throttle brute-force scanners without affecting legitimate throughput.
2. **Decoy Canary Honey-Tokens**: Emits structured JSON decoy canary responses (`CANARY-TP-...`, `HONEY-ACC-...`, synthetic balances) that consume LLM token budgets and prompt context windows.
3. **Autonomous Quarantine**: Tracks violations per caller. When violations exceed the threshold, the caller is quarantined.
4. **Append-Only Forensic Sealing**: Every tarpit event is signed and written to `logs/audit.log`.

---

## 📡 REST API Reference

### Evaluate Cedar Policy
```http
POST /api/evaluate-cedar HTTP/1.1
Host: 127.0.0.1:5000
Content-Type: application/json

{
  "principal": "ledger_arm",
  "action": "write",
  "resource": "Ledger",
  "context": {
    "amount_cents": 5000000,
    "approved": true
  },
  "attach_supervisor_approval": true
}
```

**Response (Authorized):**
```json
{
  "is_allowed": true,
  "determining_policies": ["policy0"],
  "diagnostic_errors": [],
  "reason": "Action authorized by active Cedar policy"
}
```

**Response (Unauthorized / Hostile Probe with Tarpit Engaged):**
```json
{
  "is_allowed": false,
  "determining_policies": [],
  "diagnostic_errors": [],
  "reason": "Action denied by Cedar default-deny or forbid rule",
  "tarpit_engaged": true,
  "decoy_honey_token": "{\"status\":\"TARPIT_ENGAGED\",\"trap_canary_id\":\"CANARY-TP-...\"}"
}
```

### Health & Defense Status
```http
GET /api/status HTTP/1.1
Host: 127.0.0.1:5000
```
Returns defense engine online status, active policy count, OS isolation clamp state, and Tarpit Arm metrics (`trapped_callers`, `tokens_burned`, `total_delay_ms`).

### Tarpit Defense Telemetry
```http
GET /api/tarpit-stats HTTP/1.1
Host: 127.0.0.1:5000
```
Returns live counters on trapped callers, tokens burned, and active quarantines.

### Cryptographic Audit Log
```http
GET /api/audit-log HTTP/1.1
Host: 127.0.0.1:5000
```
Returns the complete list of security events along with SHA-256 verification status.

---

## 🔒 Security Invariants Upheld

1. **Zero-Touch PATH & Environment**: Strictly process-scoped memory. No registry mutation.
2. **Google Egress Invariant**: Only `google.com` and `www.google.com` are permitted outbound destinations.
3. **No Mocks Protocol**: Real cryptographic HMAC signatures, real Cedar evaluations, real Wasmtime fuel exhaustion, real Windows Job Objects.
4. **Cephalopod Autotomy**: Hardware kill switch trips automatically upon cryptographic tamper detection.
