import os
import logging
import time
import google.generativeai as genai
from flask import Flask, render_template, request, jsonify
from scanner import SecurityScanner
from urllib.parse import urlparse
from tenacity import retry, stop_after_attempt, wait_exponential
import requests
import string

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-secret-key")

# Initialize Gemini client
try:
    logger.info("Initializing Gemini client")
    # Get API key from environment variable or use a default one
    api_key = os.environ.get("GEMINI_API_KEY", "AIzaSyDSkWG-S4os6NaArdb5RWXS93bubUMapZQ")
    genai.configure(api_key=api_key)
    
    generation_config = {
        "temperature": 0.7,  # Slightly increased for more natural responses
        "top_p": 1,
        "top_k": 1,
        "max_output_tokens": 2048,
    }
    
    safety_settings = [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
    ]
    
    model = genai.GenerativeModel(
        model_name="gemini-pro",
        generation_config=generation_config,
        safety_settings=safety_settings
    )
    logger.debug("Gemini client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Gemini client: {str(e)}", exc_info=True)
    raise

# Rate limiting
scan_history = {}
ask_history = {}
RATE_LIMIT_WINDOW = 60
MAX_SCANS = 3
MAX_ASK_REQUESTS = 10

# Fallback answers for common questions
FALLBACK_ANSWERS = {
    "what is xss": "Cross-Site Scripting (XSS) is a security vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. It can be prevented by properly sanitizing user input and implementing Content Security Policy (CSP) headers.",
    "what is sql injection": "SQL Injection is a code injection technique that exploits vulnerabilities in database-driven applications. It occurs when user input is not properly sanitized before being used in SQL queries. Prevention includes using parameterized queries and input validation.",
    "what is open redirect": "Open Redirect is a vulnerability that allows attackers to redirect users to malicious websites. It occurs when a website accepts a URL parameter for redirection without proper validation. Prevention includes validating and whitelisting allowed redirect URLs.",
    "what is website security": "Website security involves protecting websites from various threats like XSS, SQL Injection, CSRF, and other vulnerabilities. It includes implementing security headers, using HTTPS, keeping software updated, and following secure coding practices.",
    "how to secure my website": "To secure your website: 1) Use HTTPS, 2) Implement security headers, 3) Keep software updated, 4) Use strong authentication, 5) Validate and sanitize user input, 6) Implement rate limiting, 7) Use secure coding practices, and 8) Regular security audits.",
    "what is csrf": "Cross-Site Request Forgery (CSRF) is an attack that forces authenticated users to execute unwanted actions on a website. Prevention includes using CSRF tokens, SameSite cookies, and checking the Origin/Referer headers.",
    "what is clickjacking": "Clickjacking is an attack where users are tricked into clicking on something different from what they perceive. Prevention includes using X-Frame-Options or Content-Security-Policy headers to control frame embedding.",
    "what is security headers": "Security headers are HTTP response headers that help protect websites from various attacks. Common headers include: Content-Security-Policy, X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, and Strict-Transport-Security."
}

response_cache = {}

def is_rate_limited(ip, history, max_requests):
    now = time.time()
    if ip in history:
        history[ip] = [ts for ts in history[ip] if now - ts < RATE_LIMIT_WINDOW]
        if len(history[ip]) >= max_requests:
            return True
    return False

def calculate_score(results):
    score = 100
    if results['http_usage']['status'] == 'insecure':
        score -= 25
    if 'headers' in results:
        missing = sum(1 for h, v in results['headers'].items() if v.get('value') == 'Not set')
        score -= missing * 6
    if results.get('xss'):
        score -= len(results['xss']) * 6
    if results.get('sql_injection'):
        score -= len(results['sql_injection']) * 8
    if results.get('open_redirect'):
        score -= len(results['open_redirect']) * 5
    return max(0, min(score, 90))

@app.route('/')
def index():
    logger.info("Serving index.html")
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        target_url = request.form.get('url', '').strip()
        client_ip = request.remote_addr
        parsed_url = urlparse(target_url)

        if not parsed_url.scheme or not parsed_url.netloc:
            return jsonify({'error': 'Invalid URL format. Please include http:// or https://'}), 400

        if is_rate_limited(client_ip, scan_history, MAX_SCANS):
            return jsonify({'error': 'Scan rate limit exceeded.'}), 429

        scan_history.setdefault(client_ip, []).append(time.time())

        scanner = SecurityScanner(target_url)
        results = scanner.run_all_checks()
        results['security_score'] = calculate_score(results)

        return jsonify(results)
    except Exception as e:
        logger.error(f"Scan error: {str(e)}", exc_info=True)
        return jsonify({'error': f"Scan failed: {str(e)}"}), 500

@app.route('/scan/redirects', methods=['POST'])
def scan_redirects():
    try:
        data = request.get_json()
        target_url = data.get('url', '').strip()

        if not target_url:
            return jsonify({'error': 'URL is required'}), 400

        scanner = SecurityScanner(target_url)
        open_redirects = scanner.check_open_redirect()

        return jsonify({
            'open_redirect': open_redirects,
            'security_score': 100 - len(open_redirects) * 5
        })
    except Exception as e:
        logger.error(f"Open redirect scan failed: {str(e)}", exc_info=True)
        return jsonify({'error': f"Open redirect scan failed: {str(e)}"}), 500

@app.route("/ask", methods=["POST"])
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def ask():
    try:
        client_ip = request.remote_addr
        if is_rate_limited(client_ip, ask_history, MAX_ASK_REQUESTS):
            return jsonify({"error": "Rate limit exceeded. Please wait a minute before asking more questions."}), 429

        ask_history.setdefault(client_ip, []).append(time.time())

        # Log the raw request data
        logger.info(f"Raw request data: {request.get_data()}")
        
        question = request.json.get("question", "").lower().strip()
        if not question:
            logger.error("No question provided in request")
            return jsonify({"error": "Please provide a question"}), 400

        # Remove punctuation for flexible matching
        question_nopunct = question.translate(str.maketrans('', '', string.punctuation))
        logger.info(f"Received question: '{question}' (nopunct: '{question_nopunct}')")

        # Flexible fallback matching
        for key, answer in FALLBACK_ANSWERS.items():
            key_nopunct = key.translate(str.maketrans('', '', string.punctuation))
            if key_nopunct in question_nopunct:
                logger.info(f"Matched fallback answer for key: '{key}'")
                return jsonify({"response": answer})

        if question in response_cache:
            logger.info("Returning cached response")
            return jsonify({"response": response_cache[question]})

        try:
            # Sending the question to Gemini model
            logger.info("Attempting to get response from Gemini model")
            chat = model.start_chat(history=[])
            response = chat.send_message(
                f"You are a cybersecurity assistant helping users understand scan results and vulnerabilities. "
                f"Answer this question about website security: {question}. "
                f"Keep your response concise and focused on practical security advice."
            )
            
            if not response or not hasattr(response, 'text'):
                logger.error("Invalid response from Gemini model")
                return jsonify({"error": "Unable to generate a response. Please try again."}), 500

            answer = response.text.strip()
            response_cache[question] = answer
            logger.info("Successfully got response from Gemini model")
            return jsonify({"response": answer})

        except Exception as model_error:
            logger.error(f"Error with Gemini model: {str(model_error)}", exc_info=True)
            return jsonify({"error": "Unable to generate a response at this time. Please try again later."}), 500

    except Exception as e:
        logger.error(f"Error in /ask route: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500

if __name__ == '__main__':
    logger.info("Starting Flask app")
    app.run(host='0.0.0.0', port=5000, debug=True)
