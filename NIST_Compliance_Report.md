# NIST Compliance Report: AI Governance Layer

## 1. Executive Summary
This document details how the deployed AI Governance Layer for Azure AI Foundry (Phi-3) satisfies requirements from the **NIST AI Risk Management Framework (AI RMF 1.0)** and **NIST SP 800-53 Rev. 5**.

The system utilizes a **Defense-in-Depth** architecture:
1.  **Rate Limiting** (Availability/DoS protection)
2.  **Input Sanitization** (Injection defense - Layer 1)
3.  **Worker Isolation** (Security through obscurity)
4.  **Governor Agent** (Policy enforcement - Layer 2)
5.  **Audit Logging** (Non-repudiation)

## 2. NIST SP 800-53 Control Mapping

| Control ID | Control Name | System Component | Implementation |
| :--- | :--- | :--- | :--- |
| **AC-3** | **Access Enforcement** | `GovernorAgent` | The Governor acts as a Policy Enforcement Point (PEP), ensuring that only authorized information (non-PII, safe content) is released to the user. It explicitly blocks access to sensitive data types. |
| **AC-4** | **Information Flow Enforcement** | `RateLimiter` & `GovernorAgent` | **RateLimiter** controls the flow of requests to prevent flooding. **GovernorAgent** ensures data does not flow from the Hidden State (Worker knowledge) to User Unclassified State if it contains PII. |
| **AU-6** | **Audit Review, Analysis, and Reporting** | `AuditLogger` | All governance decisions (allow/block), prompts, verdicts, and reasoning are logged to an immutable **JSONL** file. Logs include timestamps and cryptographic hashes of prompts for integrity. |
| **SI-3** | **Malicious Code Protection** | `InputSanitizer` & `GovernorAgent` | **InputSanitizer** filters base64/hex encoding that could hide malicious payloads. **GovernorAgent** scans for Prompt Injection and adversarial patterns. |
| **SI-4** | **System Monitoring** | `RateLimiter` & `AuditLogger` | The system monitors usage patterns (RateLimiter) and records all transaction details for anomaly detection (Analysis of `audit_log.jsonl`). |

## 3. NIST AI RMF Alignment

### GOVERN (Culture of Risk Management)
- **1.1**: Policies for AI system behavior are codified in the `GovernorAgent` system prompt and `schemas.py`.
- **1.3**: Processes for checking logic (`test_breach.py`) are integrated into the deployment pipeline.

### MAP (Context Recognition)
- **1.3**: The system maps constraints (PII, SQLi) to specific enforcement mechanisms. The `ConversationContext` schema acknowledges multi-turn context risks.

### MEASURE (Assess, Analyze, Track)
- **1.1**: `test_breach.py` provides quantitative assessment of the Governor's efficacy (Pass/Fail rate on attack vectors).
- **2.7**: System security is measured via automated failure testing (Break attempts).

### MANAGE (Prioritize & Act)
- **2.4**: Response to risks is automated blocking (Fail-Secure).
- **4.2**: Contingency planning is handled by `error_handlers.py` ensuring system defaults to a safe state on failure.

## 4. Residual Risks & Mitigation strategy

| Risk | Likelihood | Impact | Mitigation |
| :--- | :--- | :--- | :--- |
| **False Negatives** (Governor failure) | Low | High | "Red Teaming" prompts during development; Fail-secure error handling. |
| **Context Poisoning** (Multi-turn) | Medium | Medium | Future Phase: Full session risk scoring in `ConversationContext`. Current: Sanitization of every turn. |
| **Encoded Attacks** (Steganography) | Low | Medium | `InputSanitizer` heuristics; Governor instruction to detect obfuscation. |

## 5. Deployment & Maintenance
- **Audit Logs**: Retained for 90 days (`AUDIT_LOG_RETENTION_DAYS`) locally or shipped to SIEM.
- **Fail-Secure**: If Azure API goes down, the orchestrator catches the exception and returns a generic "System Error" block, ensuring no ungoverned output is ever released.
