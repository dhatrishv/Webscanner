WebScanner 🔍🛡️
WebScanner is a web-based security scanning tool designed to identify and report common vulnerabilities on websites. It aims to simplify the process of scanning websites for weaknesses and educating users about potential risks and how to address them.

🧰 Features
🌐 Website URL Input: Scan any public-facing website by simply entering its URL.

🚀 Start Scan: Initiate a vulnerability scan with a single click.

📊 Vulnerability Report: Detailed display of discovered vulnerabilities including severity.

💡 Security Suggestions: Actionable recommendations for each identified issue.

⚙️ Technology Stack:

Frontend: HTML, CSS, Bootstrap

Backend: Python (Flask)

Tools: requests, BeautifulSoup, whois, socket, etc.

🖥️ Project Structure
csharp
Copy
Edit
NS-webscanner/
├── app.py              # Main Flask application
├── templates/
│   └── index.html      # Web interface
├── static/
│   └── style.css       # Styling (if any)
└── README.md           # Project documentation
📋 Scanning Capabilities
Detects:

Open ports

Directory listings

CMS details

Email harvesting

JavaScript vulnerabilities (basic)

Clickjacking protection

HTTPS misconfigurations

Provides:

Vulnerability score

Remediation suggestions

🚀 How to Run
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/ns-webscanner.git
cd ns-webscanner
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Run the app:

bash
Copy
Edit
python app.py
Open your browser and visit:

arduino
Copy
Edit
http://localhost:5000
🛡️ Disclaimer
This tool is intended for educational purposes only. Use it only on websites you own or have explicit permission to scan.
