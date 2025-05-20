# 🛡️ NS WebScanner

**NS WebScanner** is a web-based vulnerability scanning tool that evaluates the security posture of websites by identifying common misconfigurations and vulnerabilities. It extends the core functionalities of **reNgine** by adding SSL/TLS analysis, security header checks, and basic AI-assisted reporting.

## 🔍 Features

- 🌐 URL validation and sanitization
- 🔒 SSL/TLS certificate inspection (validity, issuer, expiry)
- 🧾 HTTP security header analysis (CSP, HSTS, X-Frame-Options, etc.)
- 💥 Vulnerability scanning:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Open Redirects
- 🧠 AI-powered assistance (via Gemini Pro) for vulnerability explanations
- 📈 Custom scoring system based on severity and exploitability
- 📋 Real-time report with suggestions for each vulnerability

## 🧠 AI Integration

Utilizes **Gemini 1.5 Pro** to provide contextual responses and remediation advice, with rate limiting and fallback mechanisms.

## ⚙️ Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, Bootstrap
- **AI API**: Google Generative AI (Gemini)
- **Libraries**: `requests`, `urllib`, `socket`, `ssl`, `whois`



