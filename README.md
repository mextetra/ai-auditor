# NIST-Compliant AI Governance System

Production-ready multi-layer defense system for Azure AI Foundry (Phi-4).

## Features
- 🛡️ **Multi-layer security** (Rate limiting, Sanitization, AI Governor, Fallback)
- ✅ **100% threat detection** in testing (PII, SQLi, Prompt Injection)
- 📊 **NIST SP 800-53 compliant** auditing and controls
- 🔄 **Resilient** with intelligent retry logic and regex-based fallback mechanisms
- 📝 **Comprehensive audit logging** with JSONL support for easy parsing

## Quick Start

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mextetra/ai-auditor.git
    cd ai-auditor
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment:**
    Copy `.env.template` to `.env` (or create one) and add your Azure AI credentials:
    ```ini
    AZURE_INFERENCE_ENDPOINT="https://<your-resource>.services.ai.azure.com/models"
    AZURE_INFERENCE_CREDENTIAL="<your-key>"
    AZURE_MODEL_NAME="Phi-4-mini-instruct"
    GOVERNOR_STRICTNESS="high"
    ```

4.  **Run the System:**
    ```bash
    python main.py
    ```

## Architecture
- **Worker Agent:** Generates helpful responses using Phi-4.
- **Governor Agent:** Audits responses for security violations *before* they reach the user.
- **Fallback Governor:** Regex-based safety net if the AI Governor fails.
- **Audit Logger:** Records every interaction (Input, Output, Verdict, Latency) for compliance.

## Test Results
- Security Threats Blocked: 5/5 (100%)
- Error Recovery: 4/4 scenarios handled
- False Negatives: 0
- graph TD
    A[User Input / Prompt] --> B{Sanitizer}
    B -- PII Detected --> C[Redact & Log]
    B -- Clean Data --> D[Governor Agent]
    
    D --> E{Risk Check}
    E -- High Risk --> F[Fallback Governor]
    E -- Low Risk --> G[Main LLM Agent]
    
    F --> H[Safe Response]
    G --> H
    
    H --> I[Audit Logger]
    I --> J[NIST Compliance Report]
    
    K[Red Team / Breach Test] -.->|Attacks| B

