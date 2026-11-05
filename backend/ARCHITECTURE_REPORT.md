# CyberGuard AI — Email, URL & Attachment Analysis Report

## Overview

CyberGuard AI is a multi-layer email security investigation platform that combines machine learning, rule-based detection, URL analysis, attachment scanning, and email authentication verification into a unified threat detection system.

---

## 1. Email Analysis Agent

The Email Analysis Agent is responsible for investigating an email and determining whether it contains phishing, fraud, spam, or other malicious indicators.

### Analysis Workflow

```
Email Input
     ↓
Email Agent
     ↓
┌──────────────────────────────┐
│ ML Classification            │
│ Sender Analysis              │
│ Content Analysis             │
│ Email Authentication         │
│ URL Analysis                 │
│ Attachment Analysis          │
└──────────────────────────────┘
     ↓
Finding Aggregation
     ↓
Risk Score + Classification
     ↓
Security Investigation Report
```

### A. Machine Learning Analysis

CyberGuard AI integrates the trained TF-IDF + Logistic Regression classifier into the Email Agent.

**The model:**
- Preprocesses sender, subject and body
- Converts the email into TF-IDF features
- Predicts benign/malicious probability
- Uses a configurable classification threshold
- Provides the ML prediction as an individual finding

**Current held-out test performance:**

| Metric | Result |
|--------|--------|
| Accuracy | 99.70% |
| Precision | 100.00% |
| Recall | 99.40% |
| F1-score | 99.70% |
| ROC-AUC | 1.0000 |

**Confusion matrix:**

```
                      Predicted
                 ┌─────────┬───────────┐
                 │ Benign  │ Malicious │
┌────────────────┼─────────┼───────────┤
│ Actual Benign  │   500   │     0     │
├────────────────┼─────────┼───────────┤
│ Actual Malicious│    3   │    497    │
└────────────────┴─────────┴───────────┘
```

### B. Sender Analysis

The Email Agent examines sender information for suspicious characteristics:

- Suspicious sender domains
- Free/public email providers
- Domain anomalies
- Possible spoofing indicators
- Sender/domain relationships

### C. Content Analysis

The content analyzer checks for indicators including:

- Urgency language
- Credential requests
- Suspicious instructions
- Financial requests
- Brand impersonation
- Suspicious wording
- Excessive capitalization
- Social engineering patterns

### D. Email Authentication

The system supports:

| Protocol | Purpose |
|----------|---------|
| **SPF** | Sender Policy Framework - validates sending server |
| **DKIM** | DomainKeys Identified Mail - validates email integrity |
| **DMARC** | Domain-based Message Authentication - policy enforcement |

Authentication results affect risk assessment:

```
SPF   → PASS / FAIL / SOFTFAIL / NONE
DKIM  → PASS / FAIL / NONE
DMARC → PASS / FAIL / NONE
```

Authentication failures generate security findings and contribute to the overall risk score.

### E. Risk Aggregation

The Email Agent combines findings from multiple security components:

```
ML Result
   +
Authentication
   +
Content
   +
Sender
   +
URL
   +
Attachment
   ↓
Finding Aggregation
   ↓
Risk Score
   ↓
Benign / Suspicious / Malicious
```

This makes the Email Agent a **multi-layer email investigation system**, rather than relying only on the ML classifier.

---

## 2. URL Analysis

The URL Analysis module investigates URLs extracted from emails.

### URL Analysis Pipeline

```
Email
  ↓
Extract URLs
  ↓
URL Analyzer
  ↓
┌─────────────────────────┐
│ URL Pattern Analysis    │
│ Reputation              │
│ Safe Browsing           │
│ URL Expansion           │
│ Link Mismatch           │
└─────────────────────────┘
  ↓
URL Findings
  ↓
Email Risk Aggregation
```

### A. URL Pattern Analysis

The system checks for suspicious URL characteristics:

| Check | Description | Example |
|-------|-------------|---------|
| **Suspicious TLD** | Potentially suspicious top-level domains | `.xyz`, `.top`, `.work` |
| **IP-address URLs** | Direct IP instead of domain | `http://192.168.1.10/login` |
| **Excessive subdomains** | Too many subdomain levels | `login.security.account.verify.example.com` |
| **Suspicious ports** | Non-standard ports | `:8080`, `:4443` |
| **Data URIs** | Embedded data URLs | `data:text/html,...` |
| **Long URLs** | Obfuscation technique | >500 characters |
| **Brand impersonation** | Brand in subdomain | `paypal.attacker.com` |
| **Homograph detection** | Visually confusing characters | `pаypal.com` (Cyrillic 'а') |

### B. URL Reputation

External reputation checking through configured threat-intelligence services:

- VirusTotal URL reputation
- Google Safe Browsing

**Architecture features:**
- Caching (Redis + local)
- Rate limiting
- Circuit breakers
- Graceful degradation

If an external service is unavailable, email analysis continues rather than failing.

### C. URL Expansion

Shortened or redirected URLs are expanded:

| Setting | Value |
|---------|-------|
| Maximum redirects | 5 |
| Timeout | 5 seconds |
| Cache TTL | 86,400 seconds (24h) |

```
Short URL (bit.ly/abc123)
   ↓
Redirect
   ↓
Redirect
   ↓
Final URL (malicious-site.com/phishing)
```

### D. Link Mismatch Detection

Checks whether visible text is inconsistent with actual destination:

```
Visible text:
  https://www.bank-example.com

Actual href:
  https://attacker-example.com/login
```

This generates a URL mismatch finding.

### URL Finding Categories

| Finding ID | Description |
|------------|-------------|
| `URL-THREAT-001` | Known malicious URL |
| `URL-THREAT-002` | Suspicious reputation |
| `URL-PATTERN-001` | Suspicious URL pattern |
| `URL-PATTERN-002` | Brand impersonation |
| `URL-MISMATCH-001` | Display/destination mismatch |
| `URL-EXPAND-001` | Suspicious redirect chain |

---

## 3. Attachment Analysis

The Attachment Analysis module investigates files attached to emails.

### Attachment Analysis Pipeline

```
Email Attachment
       ↓
Attachment Analyzer
       ↓
┌──────────────────────────────┐
│ File Type Detection          │
│ Hash Analysis                │
│ Archive Inspection           │
│ Nested Archive Detection     │
│ Dangerous File Detection     │
│ Macro Detection              │
│ Extension Mismatch           │
└──────────────────────────────┘
       ↓
Attachment Findings
       ↓
Email Risk Score
```

### A. File Type Verification

The system examines file signatures (magic bytes) instead of trusting filename extensions:

```
invoice.pdf  →  Actually contains: application/x-dosexec
```

Detects: `Filename extension ≠ Actual file type`

### B. Hash Analysis

Attachments are hashed and checked against threat-intelligence:

| Hash Type | Length | Use |
|-----------|--------|-----|
| MD5 | 32 chars | Legacy compatibility |
| SHA-1 | 40 chars | Transition format |
| SHA-256 | 64 chars | Primary identifier |

Cached threat-intelligence results reduce repeated external requests.

### C. Archive Inspection

Supported archive formats:

- ZIP
- RAR  
- 7Z
- TAR/GZ

**Detects:**
- Dangerous files inside archives
- Nested archives
- Encrypted archives
- Suspicious archive contents
- Archive expansion risks (zip bombs)

```
invoice.zip
    │
    ├── invoice.pdf
    └── invoice.exe  ← ATTACH-ARCHIVE-001
```

### D. Nested Archive Detection

```
attachment.zip
      ↓
  file.zip
      ↓
 malware.exe  ← ATTACH-ARCHIVE-002
```

### E. Dangerous File Detection

Files flagged as potentially dangerous:

| Category | Extensions |
|----------|------------|
| Executables | `.exe`, `.scr`, `.bat`, `.cmd`, `.com`, `.pif` |
| Scripts | `.vbs`, `.vbe`, `.js`, `.jse`, `.ws`, `.wsf`, `.ps1` |
| Installers | `.msi`, `.msp` |
| Disk Images | `.iso`, `.img`, `.vhd` |
| Shortcuts | `.lnk` |

### F. Macro Detection

Integrates oletools for Office macro analysis:

| Format | Description |
|--------|-------------|
| `.docm` | Word macro-enabled |
| `.xlsm` | Excel macro-enabled |
| `.pptm` | PowerPoint macro-enabled |

**Detects:**
- VBA macro presence
- Auto-execute macros
- Suspicious macro patterns
- IOC extraction from macros

> **Note:** Macro-analysis functionality is implemented, but validation against real macro-enabled malicious samples remains a future testing requirement.

---

## 4. Integration Architecture

The major strength of CyberGuard AI is that these modules do **not** operate independently:

```
                 EMAIL
                   │
                   ▼
            Email Analysis Agent
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
      URL      Attachment    Authentication
   Analysis     Analysis       Analysis
       │           │             │
       └───────────┼─────────────┘
                   ▼
              ML Analysis
                   │
                   ▼
            Finding Aggregator
                   │
                   ▼
               Risk Score
                   │
          ┌────────┴────────┐
          ▼                 ▼
       Benign           Malicious/
                         Suspicious
          │                 │
          └────────┬────────┘
                   ▼
            Investigation Report
```

### Example Investigation

An email containing:

```
Sender: suspicious-domain.com
Subject: URGENT ACCOUNT VERIFICATION
Body: Please verify your account immediately.
URL: http://suspicious-domain.com/login
Attachment: invoice.zip → invoice.exe
```

CyberGuard AI combines:

| Layer | Finding |
|-------|---------|
| ML detection | High malicious probability |
| Urgency detection | CONTENT-001 |
| Sender analysis | EMAIL-003 (suspicious TLD) |
| URL threat detection | URL-PATTERN-001 |
| URL pattern detection | URL-002 (IP-based) |
| Attachment detection | ATTACH-ARCHIVE-001 |
| File-type detection | ATTACH-001 (dangerous extension) |
| Authentication | AUTH-SPF-001 (failure) |

**Result:** Comprehensive investigation report with aggregated risk score.

---

## 5. Graceful Degradation

The system is designed so that failure of one component does **not** stop the entire investigation:

| Component Failure | Expected Behavior |
|-------------------|-------------------|
| ML unavailable | Continue with rule-based analysis |
| Redis unavailable | Continue without cache / fallback to local |
| VirusTotal unavailable | Skip and log warning |
| Safe Browsing unavailable | Skip and log warning |
| SPF/DKIM/DMARC DNS failure | Continue with unknown authentication state |
| URL expansion failure | Continue with original URL |
| Attachment analysis failure | Continue other email analysis |
| Critical rule-analysis failure | Fail safely with partial results |

This behavior is critical for a **real-time cybersecurity system**.

---

## 6. Security & Performance Controls

### Rate Limiting

External services have configured limits:

| Service | Rate Limit |
|---------|------------|
| VirusTotal | 3 requests/minute |
| AbuseIPDB | 60 requests/minute |
| Safe Browsing | 8,000 requests/day |

### Caching

| Cache Type | TTL (Malicious) | TTL (Clean) |
|------------|-----------------|-------------|
| Threat Intel | 1 hour | 24 hours |
| URL Analysis | 1 hour | 24 hours |

### Circuit Breakers

External-service failures transition through:

```
CLOSED → (failures) → OPEN → (timeout) → HALF_OPEN → (success) → CLOSED
                              ↓
                         (failure)
                              ↓
                            OPEN
```

### Security Logging

Events are logged **without** storing:
- Complete email bodies
- Attachment contents
- API keys
- Passwords
- Authentication tokens

### Request Tracking

Every request includes:
- Unique request ID
- Timestamp
- User context (if authenticated)
- Processing duration

---

## 7. API Endpoints

### Email Analysis

```
POST /api/v1/analysis/email
```

### URL Analysis

```
POST /api/v1/analysis/url
GET  /api/v1/analysis/url/{url_id}
```

### Feedback

```
POST /api/v1/feedback
GET  /api/v1/feedback/pending (Admin)
POST /api/v1/feedback/{id}/review (Admin)
```

### Threshold Management

```
GET  /api/v1/training/threshold
POST /api/v1/training/threshold
POST /api/v1/training/threshold/tune
```

---

## 8. Summary

CyberGuard AI provides:

| Capability | Implementation |
|------------|----------------|
| **ML Detection** | TF-IDF + Logistic Regression (99.7% accuracy) |
| **URL Analysis** | Pattern + Reputation + Expansion + Mismatch |
| **Attachment Analysis** | Hash + Archive + Macro + Type verification |
| **Email Authentication** | SPF + DKIM + DMARC |
| **Threat Intelligence** | VirusTotal + AbuseIPDB + Safe Browsing |
| **Feedback Loop** | User feedback → Threshold tuning |
| **Resilience** | Circuit breakers + Graceful degradation |
| **Performance** | Caching + Rate limiting + Async processing |

**Architecture Principle:** Defense in depth — multiple independent detection layers ensure that no single bypass defeats the system.

---

## Document History

| Date | Version | Author | Changes |
|------|---------|--------|---------|
| 2026-09 | 1.0 | CyberGuard Team | Initial report |
