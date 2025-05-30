# 🛡️ ReNgine - Web Security Scanner

**ReNgine** is a web-based vulnerability scanning tool that evaluates the security posture of websites by identifying common misconfigurations and vulnerabilities. It extends the core functionalities of **reNgine** by adding SSL/TLS analysis, security header checks, and basic AI-assisted reporting.

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

## 🧠 AI Integration (Partially Integrated)

Utilizes **Gemini 1.5 Pro** to provide contextual responses and remediation advice, with rate limiting and fallback mechanisms.

## ⚙️ Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, Bootstrap
- **AI API**: Google Generative AI (Gemini)
- **Libraries**: `requests`, `urllib`, `socket`, `ssl`, `whois`

## 🗂️ Project Structure

NS-webscanner/
- ├── main.py # Flask app and ai integration
- ├── scanner.py # Vulnerability scanner class
- ├── templates/
- │ └── index.html # Web UI
- ├── static/
- │ └── style.css # Styling 
- │ └──  main.js # presenting output of result in interface
- └── README.md # Project documentation


## 📝 Step-by-Step Setup Guide

Follow these steps to run ReNgine-WebScanner locally on your machine:
### 1️⃣ Clone the Repository
        vs terminal:
        git clone https://github.com/dhatrishv/ns-webscanner.git
        cd ns-webscanner
        
### 2️⃣ Download the requirements (Refer the requirements.txt)
### 3️⃣ Place the files as structure mentioned above
### 4️⃣ Run the main.py
        In Terminal:
        python main.py
        
### 5️⃣ Open in Browser
      Type http://localhost:5000




 


