/* ============================================================
   Phishing Awareness Analysis — rule-based indicator matching
   DecodeLabs Cyber Security Internship — Project 3

   OFFICIAL REQUIREMENTS (from DecodeLabs brief, per README):
     - Identify suspicious links or keywords
     - List red flags found in phishing messages
     - Explain why the message is unsafe

   ENHANCEMENTS:
     - URL shortener detection
     - Sensitive information request detection
     - Impersonation-style language detection
     - Per-flag individual explanations
     - URL extraction and inspection
     - Defensive recommendations
     - Sample message loading

   This is intentionally NOT machine learning or AI classification.
   It is a fixed, transparent keyword/pattern rule set.
   ============================================================ */

const messageInput = document.getElementById('message');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const riskBadge = document.getElementById('riskBadge');
const flagList = document.getElementById('flagList');
const explanationList = document.getElementById('explanationList');
const urlInspection = document.getElementById('urlInspection');
const urlList = document.getElementById('urlList');
const recommendationsSection = document.getElementById('recommendationsSection');
const recList = document.getElementById('recList');

/* Sample messages — all fictional, using only example.com */
const SAMPLES = {
  phishing1: `Subject: URGENT: Your Account Will Be Suspended

URGENT: Your account will be suspended within 24 hours.

Verify your account immediately by signing in with your password.
Failure to act now will result in permanent account closure.

Click the link below to verify:
https://example.com/account-verify

— Account Security Team`,

  phishing2: `Subject: FINAL WARNING — Payment Information Required

FINAL WARNING

Your payment information must be updated immediately or your
subscription will be suspended.

Please provide your credit card details at the link below to
avoid account suspension:
https://example.com/billing-update

This is time-sensitive — please act now.

— Billing Department`,

  legitimate: `Subject: Library Book Due Reminder

Hello,

This is a reminder that your library book is due back tomorrow.

If you need more time, you're welcome to renew it at the front
desk or through the library's usual renewal process.

Thank you,
Campus Library`
};

const INDICATORS = [
  {
    name: 'Urgent / time-pressure language',
    patterns: ['urgent', 'immediately', 'act now', 'within 24 hours', 'final warning', 'as soon as possible', 'time-sensitive', 'limited time', 'expires today', 'don\'t delay'],
    why: 'Urgency is a social engineering tactic designed to short-circuit careful judgment before the message can be verified through a trusted channel.',
    icon: '⏰'
  },
  {
    name: 'Credential or login request',
    patterns: ['password', 'verify your account', 'sign in', 'log in', 'credentials', 'confirm your identity', 'verify your identity', 'reset your password', 'update your login'],
    why: 'Legitimate services essentially never ask you to "confirm" a password by clicking a link in an unsolicited email. This is a hallmark of credential harvesting.',
    icon: '🔑'
  },
  {
    name: 'Financial request',
    patterns: ['payment', 'bank account', 'credit card', 'wire transfer', 'invoice attached', 'gift card', 'billing', 'financial details', 'routing number', 'social security'],
    why: 'Unexpected financial requests should always be verified through a separate, already-known channel — never through a link or number provided in the suspicious message itself.',
    icon: '💰'
  },
  {
    name: 'Account-threat language',
    patterns: ['account suspended', 'be suspended', 'account locked', 'account closure', 'account will be closed', 'unusual activity', 'security alert', 'unauthorized access', 'account terminated', 'account disabled'],
    why: 'Threatening account loss is a pressure tactic used to provoke a fast, unverified click — legitimate services provide account issues through their official dashboard, not alarming emails.',
    icon: '⚠️'
  },
  {
    name: 'Sensitive information request',
    patterns: ['social security', 'date of birth', 'mother\'s maiden', 'personal information', 'verify your details', 'confirm your details', 'update your information', 'tax id', 'passport number'],
    why: 'Requests for personally identifiable information (PII) via email are a strong indicator of social engineering. Legitimate organizations do not collect sensitive data this way.',
    icon: '📋'
  },
  {
    name: 'Impersonation-style language',
    patterns: ['dear customer', 'dear user', 'dear valued', 'dear account holder', 'dear sir/madam', 'we have detected', 'our records show', 'your account has been'],
    why: 'Generic greetings and impersonation of official organizations suggest the sender does not actually know the recipient — a common trait of mass phishing campaigns.',
    icon: '🎭'
  }
];

const URL_SHORTENERS = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly'];

function analyzeMessage(raw) {
  const text = raw.trim().toLowerCase();

  if (!text) {
    return {
      level: 'none', label: 'NOT ANALYZED', flags: [], explanations: [],
      urls: [], recommendations: [],
      summaryText: 'Paste a message above and click Analyze.'
    };
  }

  const found = [];
  const explanations = [];

  INDICATORS.forEach(indicator => {
    const matched = indicator.patterns.some(p => text.includes(p));
    if (matched) {
      found.push({ name: indicator.name, icon: indicator.icon });
      explanations.push({ name: indicator.name, why: indicator.why, icon: indicator.icon });
    }
  });

  /* URL detection */
  const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
  const urls = (raw.match(urlRegex) || []).map(url => {
    const issues = [];
    const lowerUrl = url.toLowerCase();
    if (URL_SHORTENERS.some(s => lowerUrl.includes(s))) {
      issues.push('URL shortener detected — may hide the real destination');
    }
    if (lowerUrl.includes('login') || lowerUrl.includes('verify') || lowerUrl.includes('account') || lowerUrl.includes('secure')) {
      issues.push('URL contains credential-related keywords');
    }
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      issues.push('URL uses an IP address instead of a domain name');
    }
    return { url, issues };
  });

  if (urls.length > 0) {
    found.push({ name: 'Contains link(s)', icon: '🔗' });
    explanations.push({
      name: 'Contains link(s)',
      why: 'Links in unsolicited messages should be inspected — or better, not clicked — before being trusted. Navigate to official websites directly instead.',
      icon: '🔗'
    });
  }

  /* Risk level */
  let level = 'none';
  let label = 'NO OBVIOUS INDICATORS';
  if (found.length >= 4) { level = 'high'; label = 'HIGH RISK'; }
  else if (found.length >= 2) { level = 'medium'; label = 'MEDIUM RISK'; }
  else if (found.length === 1) { level = 'low'; label = 'LOW / REVIEW'; }

  /* Summary */
  let summaryText;
  if (found.length > 0) {
    summaryText = found.length + ' indicator(s) detected. Review the red flags and explanations below.';
  } else {
    summaryText = 'No obvious indicators from this tool\u2019s rule set were detected. That does not prove the message is legitimate \u2014 always verify through a channel you already trust, not one the message itself provides.';
  }

  /* Recommendations */
  const recommendations = [];
  if (found.length > 0) {
    recommendations.push('Do not click any links in the suspicious message.');
    recommendations.push('Verify the sender independently through a known, trusted channel.');
    recommendations.push('Navigate to official websites by typing the URL directly — never through email links.');
    recommendations.push('Do not provide passwords, financial details, or personal information.');
    recommendations.push('Report the suspicious message to your IT security team or email provider.');
    if (urls.length > 0) {
      recommendations.push('Hover over links to inspect the actual destination URL before clicking.');
    }
  }

  return { level, label, flags: found, explanations, urls, recommendations, summaryText };
}

function renderResult(result) {
  const { level, label, flags, explanations, urls, recommendations, summaryText } = result;

  riskBadge.textContent = label;
  riskBadge.className = 'stamp' + (level !== 'none' ? ' ' + level : '');

  /* Flags */
  flagList.innerHTML = '';
  if (flags.length === 0) {
    flagList.innerHTML = '<li class="empty">No flags matched this tool\u2019s rule set.</li>';
  } else {
    flags.forEach(flag => {
      const li = document.createElement('li');
      li.innerHTML = '<span class="flag-icon">' + flag.icon + '</span> ' + flag.name;
      flagList.appendChild(li);
    });
  }

  /* Explanations */
  explanationList.innerHTML = '';
  if (explanations.length === 0) {
    explanationList.innerHTML = '<p class="empty-explanation">' + summaryText + '</p>';
  } else {
    explanations.forEach(exp => {
      const div = document.createElement('div');
      div.className = 'explanation-card';
      div.innerHTML = '<div class="exp-header"><span class="exp-icon">' + exp.icon + '</span> <strong>' + exp.name + '</strong></div><p>' + exp.why + '</p>';
      explanationList.appendChild(div);
    });
  }

  /* URLs */
  if (urls.length > 0) {
    urlInspection.style.display = 'block';
    urlList.innerHTML = '';
    urls.forEach(u => {
      const li = document.createElement('li');
      let html = '<code class="url-text">' + escapeHtml(u.url) + '</code>';
      if (u.issues.length > 0) {
        html += '<ul class="url-issues">' + u.issues.map(i => '<li>' + i + '</li>').join('') + '</ul>';
      } else {
        html += '<span class="url-note">No specific issues detected from this rule set.</span>';
      }
      li.innerHTML = html;
      urlList.appendChild(li);
    });
  } else {
    urlInspection.style.display = 'none';
  }

  /* Recommendations */
  if (recommendations.length > 0) {
    recommendationsSection.style.display = 'block';
    recList.innerHTML = recommendations.map(r => '<li>' + r + '</li>').join('');
  } else {
    recommendationsSection.style.display = 'none';
  }
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

analyzeBtn.addEventListener('click', () => {
  renderResult(analyzeMessage(messageInput.value));
});

clearBtn.addEventListener('click', () => {
  messageInput.value = '';
  renderResult({
    level: 'none', label: 'NOT ANALYZED', flags: [], explanations: [],
    urls: [], recommendations: [],
    summaryText: 'Paste a message above and click Analyze.'
  });
  messageInput.focus();
});

/* Sample loading */
document.querySelectorAll('.sample-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const key = btn.dataset.sample;
    if (SAMPLES[key]) {
      messageInput.value = SAMPLES[key];
      messageInput.focus();
    }
  });
});
