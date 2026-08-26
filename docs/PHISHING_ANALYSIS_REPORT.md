# Phishing Analysis Report

**DecodeLabs Cyber Security Internship — Project 3**
**Author:** Tahniat Farhan

## 1. Objective
Analyze sample messages for phishing indicators; identify suspicious links/keywords, list red flags, and explain why each flagged message is unsafe.

## 2. Threat Analysis Approach
Rule-based keyword/phrase matching across four categories, plus a URL pattern check. Chosen over an ML/AI approach specifically because the brief asks for identifiable, explainable indicators — a rule list can be read, audited, and defended line by line; a trained classifier can't be, at this scope.

## 3. Rule-Based Detection Method
See README.md § Detection Logic for the exact category list and scoring rule.

## 4. Indicators Used
Urgent/time-pressure language · Credential or login request · Financial request · Account-threat language · presence of a link.

## 5. Sample Messages
Three fictional samples in `samples/`, using only `example.com` placeholder links — no real brands, no working malicious URLs.

## 6. Analysis Results — actually executed, including the failure

**First run** (original keyword list):
```
FAIL | samples/suspicious-email-1.txt -> MEDIUM RISK (expected HIGH RISK)
       flags=[Urgent / time-pressure language, Credential or login request, Contains a link]
FAIL | samples/suspicious-email-2.txt -> MEDIUM RISK (expected HIGH RISK)
       flags=[Urgent / time-pressure language, Financial request, Contains a link]
PASS | samples/legitimate-email.txt -> NO OBVIOUS INDICATORS (expected NO OBVIOUS INDICATORS)
       flags=[]
```

**Root cause:** the Account-threat category only listed the exact phrases `"account suspended"` and `"account will be closed"`. The sample text used natural variations instead — *"your account will be suspended"* and *"permanent account closure"* — which don't contain those exact substrings. Two of three samples under-scored as a direct result.

**Fix:** broadened the Account-threat pattern list to `'account suspended'`, `'be suspended'`, `'account locked'`, `'account closure'`, `'account will be closed'`, `'unusual activity'`, `'security alert'` — covering the natural phrasing without going so broad that unrelated text (e.g. "the meeting is suspended") would trigger it.

**Second run** (after the fix):
```
PASS | samples/suspicious-email-1.txt -> HIGH RISK (expected HIGH RISK)
       flags=[Urgent / time-pressure language, Credential or login request, Account-threat language, Contains a link]
PASS | samples/suspicious-email-2.txt -> HIGH RISK (expected HIGH RISK)
       flags=[Urgent / time-pressure language, Financial request, Account-threat language, Contains a link]
PASS | samples/legitimate-email.txt -> NO OBVIOUS INDICATORS (expected NO OBVIOUS INDICATORS)
       flags=[]
```

## 7. Red Flags (by sample)
- **suspicious-email-1.txt:** urgency, credential request, account-threat language, a link — 4 categories, HIGH.
- **suspicious-email-2.txt:** urgency, financial request, account-threat language, a link — 4 categories, HIGH.
- **legitimate-email.txt:** 0 categories matched — reported as "no obvious indicators," explicitly *not* as "safe."

## 8. Why the Flagged Messages Are Unsafe
See each indicator's `why` text in `script.js` / surfaced live in the app's "Why This Might Be Unsafe" panel — reproduced in README.md § Detection Logic.

## 9. Security Awareness Recommendations
Verify unexpected requests (financial, credential, urgent) through a channel you already know and trust — never one the suspicious message itself provides. Treat a "clean" scan result as "nothing obvious was found," not as a guarantee.

## 10. Testing
Documented in full above, including the genuine failure and fix — this is real Node.js console output, not a predicted or asserted result.

## 11. Limitations
Keyword-based matching is evadable and language-specific; see README.md § Limitations.

## 12. Future Improvements
See README.md § Future Improvements.

## 13. Conclusion
All three official requirements — flag suspicious links/keywords, list red flags, explain why a message is unsafe — are implemented and verified against real sample data, including a real bug that was caught by testing rather than glossed over.
