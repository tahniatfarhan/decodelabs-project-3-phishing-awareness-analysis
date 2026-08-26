# 🎣 Phishing Awareness Analysis

## DecodeLabs Cyber Security Internship

This project is part of the **DecodeLabs Cyber Security Internship (Batch 2026)**.

## Project Overview

A rule-based threat indicator analyzer designed for security awareness. Users paste sample emails or communications to detect red flags, extract suspicious links, analyze urgency and social engineering patterns, and view plain-language risk explanations.

> **Note on Specification Source:** Official DecodeLabs PDFs are unavailable in the current Antigravity environment. Existing project READMEs/reports are being used as secondary requirement references.

## Official Requirements

The following core requirements are derived from the official project specification:

- [x] Identify suspicious links or keywords in sample messages
- [x] List red flags found in phishing messages
- [x] Explain why the message is unsafe
- [x] Defensive analysis boundary (no credential harvesting or malicious kit creation)

## Implemented Features

### Official Baseline Features
- Paste-and-analyze text review workflow
- Rule-based detection across key indicator categories (Urgency, Credential requests, Financial requests, Account threats)
- Risk level classification (High, Medium, Low/Review, No Obvious Indicators)
- Explanatory write-ups detailing why flagged items pose risk

### Additional Defensive Enhancements
- **Extended Indicator Categories:** Added detection for sensitive PII requests and generic impersonation language.
- **URL Inspection Engine:** Extracts embedded links, flags URL shorteners (e.g., `bit.ly`, `tinyurl`), detects IP-based hostnames, and checks for login keyword traps.
- **Per-Flag Individual Breakdown:** Displays distinct cards for each detected anomaly rather than concatenated text blocks.
- **Defensive Recommendations Panel:** Provides specific mitigation actions for security analysts or users.
- **Quick-Load Preset Samples:** Includes pre-loaded fictional sample emails (Phishing Warning, Billing Scam, Legitimate Reminder) using safe `example.com` domains.

## Cybersecurity Concepts

- **Social Engineering Tactics:** Urgency, fear, authority, and scarcity manipulation.
- **Credential Harvesting Awareness:** Identifying fake login prompts and unauthorized link destinations.
- **Defensive Detection Engineering:** Rule-based heuristic pattern matching.
- **Zero Trust Principle:** Explicitly communicating that "No Obvious Indicators" does **not** guarantee a message is safe.

## Technology Stack

- **HTML5:** Case-file SOC layout, accessibility attributes.
- **CSS3:** Manila case-file aesthetic, rubber stamp risk badges, responsive layout.
- **Vanilla JavaScript (ES6+):** RegEx-based rule matching, URL parsing, DOM rendering.

## How It Works

1. Input text is normalized and evaluated against pattern rule sets for 6 distinct categories.
2. The regular expression `/(https?:\/\/[^\s<>"']+)/gi` extracts all contained URLs.
3. Extracted URLs are parsed for suspicious patterns (shorteners, credential terms, IP addresses).
4. The risk level is calculated based on category hit count.
5. Detected red flags, tailored risk explanations, URL analysis, and defensive advice are rendered.

## How to Run Locally

1. Clone or download the repository.
2. Open `index.html` in any web browser.
3. Use the sample buttons or paste custom sample text to test.

## GitHub Repository

[https://github.com/tahniatfarhan/decodelabs-project-3-phishing-awareness-analysis](https://github.com/tahniatfarhan/decodelabs-project-3-phishing-awareness-analysis)

## Live GitHub Pages Demo

[https://tahniatfarhan.github.io/decodelabs-project-3-phishing-awareness-analysis/](https://tahniatfarhan.github.io/decodelabs-project-3-phishing-awareness-analysis/)

## Testing

The rule engine was verified against multiple safe synthetic sample messages:

| Sample | Red Flags Matched | Risk Level | Status |
|--------|-------------------|------------|--------|
| `suspicious-email-1.txt` | Urgency, Credential Request, Account Threat, Link | HIGH RISK | PASS |
| `suspicious-email-2.txt` | Urgency, Financial Request, Account Threat, Link | HIGH RISK | PASS |
| `legitimate-email.txt` | None | NO OBVIOUS INDICATORS | PASS |
| Shortener URL Sample | Link, URL Shortener Flag | LOW / REVIEW | PASS |

## Security Considerations

- **Strict Defensive Scope:** Does NOT contain fake login portals, credential harvesting scripts, or malicious tracking.
- All sample domains use standard safe RFC 2606 reserved domains (`example.com`).

## Limitations

- Rule-based pattern matching is subject to false positives and evasions. Sophisticated spear-phishing avoiding target keywords requires deeper header and domain authentication analysis (SPF/DKIM/DMARC).

## Project Structure

```text
decodelabs-project-3-phishing-awareness-analysis/
├── index.html
├── style.css
├── script.js
├── README.md
├── .gitignore
├── .github/
│   └── workflows/
│       └── pages.yml
├── samples/
│   ├── suspicious-email-1.txt
│   ├── suspicious-email-2.txt
│   └── legitimate-email.txt
├── docs/
│   └── PHISHING_ANALYSIS_REPORT.md
└── screenshots/
    └── README.md
```

## Author

**Author:** Tahniat Farhan  
**Role:** Cyber Security Intern, DecodeLabs
