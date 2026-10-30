# 🛡️ Mega-Analyzer — Unified Dynamic API & Rule Engine

This subdirectory contains the entrypoint and documentation for the **Mega-Analyzer Dynamic API Server & Visual Console**. 

It allows security researchers and developers to view, create, edit, and test vulnerability rules, bytecode token sequence matchers, and Smali ML patterns on-the-fly without rebuilding or restarting the analyzer daemon.

---

## 🏗️ Architecture Overview

The system is split into three decoupled dynamic registries, persistent JSON storage layers, and a high-performance Go REST server:

```
                  ┌──────────────────────────────┐
                  │   Premium HTML5 Dashboard    │
                  │  (Embedded at /dashboard)    │
                  └──────────────┬───────────────┘
                                 │ HTTP / JSON
                                 ▼
                  ┌──────────────────────────────┐
                  │    Go REST API Server        │
                  │    (pkg/api/api_server.go)   │
                  └──────────────┬───────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Web Scanner   │     │ Binzap Matcher  │     │ Smali ML Engine │
│  Dynamic Rules  │     │  Dynamic Tokens │     │ Custom Patterns │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   web_rules.json│     │binzap_rules.json│     │ ml_patterns.json│
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

- **Persistence Layer**: All dynamic configurations are persisted inside the `configs/dynamic_rules/` folder as structured JSON arrays, enabling direct edits through text editors or remote management via the HTTP REST interface.
- **Hot-Reloading**: Registries are thread-safe (utilizing Go read-write mutexes `sync.RWMutex`) and automatically reload rules upon disk modifications or REST API updates.

---

## 🚀 Quick Start

### 1. Build and Run the Server
From the root of the workspace, boot the API daemon:
```powershell
go run cmd/analyzer-api/main.go --port 8090
```

### 2. Access the Interactive Console
Open your web browser and navigate to:
```text
http://127.0.0.1:8090/
```

> [!NOTE]
> The embedded visual console is built with a sleek dark glassmorphism layout, utilizing pure inline SVG graphics (zero emoji-based icons in accordance with visual design controls) and responsive UI states.

---

## 📡 REST API Reference

All requests and responses use `application/json` format.

### 1. System Health & Statistics
- **Endpoint**: `GET /api/v1/status`
- **Response**:
  ```json
  {
    "status": "healthy",
    "statistics": {
      "dynamic_binzap_rules": 2,
      "dynamic_ml_patterns": 1,
      "dynamic_web_rules": 3,
      "total_static_ml": 140
    }
  }
  ```

---

### 2. Dynamic Web Rules Endpoint
Manages dynamic parameters for active fuzzing, passive regex checks, and HTTP response headers security audits.

- **List Rules**: `GET /api/v1/rules/web`
- **Create Rule**: `POST /api/v1/rules/web`
- **Update Rule**: `PUT /api/v1/rules/web/:id`
- **Delete Rule**: `DELETE /api/v1/rules/web/:id`

#### Request Payload Examples:

##### A. Active Input Fuzzer Rule:
```json
{
  "id": "WS-DYN-XSS",
  "name": "Stored/Reflected XSS Validator",
  "description": "Scans input fields for raw markup injection.",
  "severity": "CRITICAL",
  "mitigation": "Sanitize and HTMLEscape variables before interpolation.",
  "type": "fuzz",
  "payloads": [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>"
  ],
  "match_type": "contains",
  "match_value": ""
}
```

##### B. Passive Regex Signature Rule:
```json
{
  "id": "WS-DYN-SECRET",
  "name": "Slack Webhook Disclosure Detector",
  "description": "Discovers Slack webhook secrets exposed in page responses.",
  "severity": "HIGH",
  "mitigation": "Revoke the webhook immediately and retrieve credentials from secrets managers.",
  "type": "regex_passive",
  "regex_pattern": "hooks\\.slack\\.com/services/[T][A-Z0-9_]{8}/[B][A-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
}
```

---

### 3. Binzap Dynamic Opcodes Endpoint
Manages Smali bytecode instruction sequence matching logic dynamically.

- **List Rules**: `GET /api/v1/rules/binzap`
- **Create Rule**: `POST /api/v1/rules/binzap`
- **Update Rule**: `PUT /api/v1/rules/binzap/:id`
- **Delete Rule**: `DELETE /api/v1/rules/binzap/:id`

#### Request Payload Example:
```json
{
  "id": "BZ-DYN-CRYPTO",
  "name": "DES Encryption Algorithm Usage",
  "severity": "HIGH",
  "pattern_steps": [
    { "type": "opcode", "value": "const-string" },
    { "type": "any_register" },
    { "type": "string_contains", "value": "DES" },
    { "type": "opcode", "value": "invoke-static" }
  ]
}
```

---

### 4. Smali ML Pattern Endpoint
Manages Smali class methods metadata matching for risk classifications and billing/premium bypass checks.

- **List Patterns**: `GET /api/v1/rules/ml`
- **Create Pattern**: `POST /api/v1/rules/ml`
- **Update Pattern**: `PUT /api/v1/rules/ml/:id`
- **Delete Pattern**: `DELETE /api/v1/rules/ml/:id`

#### Request Payload Example:
```json
{
  "id": "BILLING_BYPASS_DYN",
  "category": "billing",
  "description": "Bypasses customized custom billing triggers.",
  "method_names": ["isLicensed", "isUserPremium"],
  "class_patterns": ["purchase", "billing", "license"],
  "required_calls": ["sharedpreferences;->getboolean"],
  "string_patterns": ["premium", "license"],
  "return_type": "Z",
  "patch_type": "return_true",
  "weight": 1.5,
  "min_match_score": 12
}
```

---

### 5. Interactive Scanner Sandboxes

#### A. Run URL Web Scan
Triggers a crawler and fuzz scanner against a target URL, immediately incorporating all custom dynamic fuzzing, passive regex, and header checking rules.

- **Endpoint**: `POST /api/v1/scan/web`
- **Request**:
  ```json
  {
    "target": "http://127.0.0.1:3000"
  }
  ```
- **Response**:
  ```json
  {
    "target": "http://127.0.0.1:3000",
    "findings_count": 1,
    "findings": [
      {
        "id": "WS-DYN-XSS",
        "name": "Stored/Reflected XSS Validator",
        "description": "Scans input fields for raw markup injection.",
        "severity": "CRITICAL",
        "url": "http://127.0.0.1:3000/login",
        "parameter": "username",
        "evidence": "Response contains string: <script>alert(1)</script>",
        "payload": "<script>alert(1)</script>",
        "mitigation": "Sanitize and HTMLEscape variables before interpolation."
      }
    ]
  }
  ```

#### B. Debug Bytecode & Tokens
Lexes Smali code into structured token streams in real-time, matching and identifying line highlights corresponding to active dynamic sequence rules.

- **Endpoint**: `POST /api/v1/scan/tokens`
- **Request**:
  ```json
  {
    "text": ".method public encrypt(Ljava/lang/String;)V\n    const-string v0, \"DES/CBC/PKCS5Padding\"\n    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n    return-void\n.end method"
  }
  ```
- **Response**:
  ```json
  {
    "findings_count": 1,
    "findings": [
      {
        "RuleID": "BZ-DYN-CRYPTO",
        "Severity": "HIGH",
        "Message": "Dynamic match: DES Encryption Algorithm Usage",
        "File": "interactive_sandbox.smali",
        "Line": 2,
        "Evidence": "const-string v0 DES/CBC/PKCS5Padding invoke-static",
        "Confidence": "HIGH"
      }
    ],
    "tokens": [
      { "column": 5, "line": 2, "type": 1, "value": "const-string" },
      { "column": 18, "line": 2, "type": 2, "value": "v0" },
      { "column": 22, "line": 2, "type": 3, "value": "DES/CBC/PKCS5Padding" },
      { "column": 5, "line": 3, "type": 1, "value": "invoke-static" }
    ]
  }
  ```

#### C. Real-Time Diagnostic Event Stream (SSE)
Establishes a Server-Sent Events stream providing dynamic diagnostic signals from crawler and fuzz workers.

- **Endpoint**: `GET /api/v1/scan/events`
- **Output Channel Headers**: `Content-Type: text/event-stream`
- **Event Output Example**:
  ```text
  data: {"timestamp":"2026-05-28T17:15:30Z","type":"info","message":"Diagnostic Event Stream Established"}

  data: {"timestamp":"2026-05-28T17:15:32Z","type":"info","message":"[*] Initiating Web Security Scan on target: http://127.0.0.1:3000"}
  ```

#### D. Dry-Run Verification Playground
Allows developers to submit temporary, unsaved rule structures and test them directly against targeted URLs or custom bytecode snippets.

- **Endpoint**: `POST /api/v1/rules/test`
- **Request (Binzap Token Matcher Dry-Run)**:
  ```json
  {
    "rule_type": "binzap",
    "rule_json": "{\"id\":\"DRY-RUN-BZ\",\"name\":\"Test Rule\",\"severity\":\"MEDIUM\",\"pattern_steps\":[{\"type\":\"opcode\",\"value\":\"const-string\"},{\"type\":\"any_register\"},{\"type\":\"string_contains\",\"value\":\"license\"}]}",
    "sample": ".method public test()Z\n    const-string v0, \"license_validated\"\n    return v0\n.end method"
  }
  ```
- **Response**:
  ```json
  {
    "matched": true,
    "findings_count": 1,
    "findings": [
      {
        "RuleID": "DRY-RUN-BZ",
        "Severity": "MEDIUM",
        "Message": "Dynamic match: Test Rule",
        "File": "dry_run_sandbox.smali",
        "Line": 2,
        "Evidence": "const-string v0 license_validated",
        "Confidence": "HIGH"
      }
    ]
  }
  ```

---

## 🗄️ Persistence Schema Details

All dynamic rules are stored inside `configs/dynamic_rules/` under separate filenames:

- **`web_rules.json`**: Stored as an array of `DynamicWebRule` objects containing condition matching strategies (`fuzz`, `regex_passive`, or `header_check`).
- **`binzap_rules.json`**: Stored as an array of `DynamicBinzapRule` structs containing matching sequence `steps`.
- **`ml_patterns.json`**: Stored as an array of static structure parameters conforming to the Smali pattern specification.
