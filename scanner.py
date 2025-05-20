import requests
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
import logging

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.logger = logging.getLogger(__name__)
        requests.packages.urllib3.disable_warnings()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })

    def check_ssl(self):
        """Check SSL certificate validity and configuration"""
        try:
            hostname = urlparse(self.target_url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'status': 'secure',
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter'],
                        'suggestion': 'SSL is correctly configured.'
                    }
        except ssl.SSLError as e:
            self.logger.error(f"SSL error: {str(e)}")
            return {
                'status': 'error',
                'message': 'SSL certificate error: ' + str(e),
                'suggestion': 'Ensure a valid SSL certificate is installed and properly configured.'
            }
        except socket.error as e:
            self.logger.error(f"Socket error while connecting: {str(e)}")
            return {
                'status': 'error',
                'message': f"Socket connection error: {str(e)}",
                'suggestion': 'Check server network connectivity.'
            }
        except Exception as e:
            self.logger.error(f"SSL check error: {str(e)}")
            return {
                'status': 'error',
                'message': f"Unexpected error: {str(e)}",
                'suggestion': 'SSL certificate validation failed.'
            }

    def check_headers(self):
        """Check for important security headers"""
        try:
            response = self.session.head(self.target_url, verify=False, timeout=5)
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': {
                    'suggestion': 'Set to enforce HTTPS (e.g., "max-age=31536000; includeSubDomains")'
                },
                'X-Content-Type-Options': {
                    'suggestion': 'Set to "nosniff" to prevent MIME type sniffing'
                },
                'X-Frame-Options': {
                    'suggestion': 'Set to "DENY" or "SAMEORIGIN" to prevent clickjacking'
                },
                'Content-Security-Policy': {
                    'suggestion': 'Implement to control resources the browser can load'
                },
                'X-XSS-Protection': {
                    'suggestion': 'Set to "1; mode=block" for XSS protection'
                }
            }

            results = {}
            for header, info in security_headers.items():
                value = headers.get(header, 'Not set')
                results[header] = {
                    'value': value,
                    'suggestion': info['suggestion'] if value == 'Not set' else 'Header is properly configured'
                }
            return results
        except requests.RequestException as e:
            self.logger.error(f"Header check error: {str(e)}")
            return {'error': 'Request failed during header check.'}
        except Exception as e:
            self.logger.error(f"Unknown error in header check: {str(e)}")
            return {'error': str(e)}

    def check_xss_vulnerabilities(self):
        """Check for potential XSS vulnerabilities"""
        try:
            response = self.session.get(self.target_url, verify=False, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')

            vulnerabilities = []

            # Check form inputs for potential XSS vectors
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea']):
                    if input_field.get('type') not in ['hidden', 'submit', 'button']:
                        vulnerabilities.append({
                            'element': str(input_field),
                            'risk': 'Potential XSS vector in form input',
                            'suggestion': 'Implement input validation and output encoding'
                        })

            # Check URL parameters for potential XSS vectors
            parsed_url = urlparse(self.target_url)
            for param in parse_qs(parsed_url.query):
                vulnerabilities.append({
                    'element': param,
                    'risk': 'Potential XSS vector in URL parameter',
                    'suggestion': 'Sanitize and encode URL parameters'
                })

            return vulnerabilities
        except Exception as e:
            self.logger.error(f"XSS check error: {str(e)}")
            return {'error': str(e)}

    def check_insecure_http(self):
        """Check if the site is using HTTP instead of HTTPS"""
        if self.target_url.startswith('http://'):
            return {
                'status': 'insecure',
                'message': 'Site is using HTTP',
                'suggestion': 'Redirect all HTTP traffic to HTTPS'
            }
        return {
            'status': 'secure',
            'message': 'Site is using HTTPS',
            'suggestion': 'No action needed'
        }

    def check_sql_injection(self):
        """Test for basic SQL injection vulnerabilities"""
        try:
            test_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "'--", "'#", "' OR 1=1--"]
            vulnerable = []

            for payload in test_payloads:
                test_url = self._add_param('test', payload) if '?' not in self.target_url else self.target_url + payload
                
                try:
                    resp = self.session.get(test_url, verify=False, timeout=5)
                    content = resp.text.lower()

                    error_keywords = [
                        "sql syntax", "mysql_fetch", "syntax error", "unterminated string",
                        "warning", "unclosed quotation mark", "odbc", "pdo", "fatal error"
                    ]

                    if any(err in content for err in error_keywords):
                        vulnerable.append({
                            'url': test_url,
                            'payload': payload,
                            'risk': 'Possible SQL Injection',
                            'suggestion': 'Use parameterized queries and input validation'
                        })
                except requests.RequestException as e:
                    self.logger.warning(f"Request failed for SQLi test: {str(e)}")
                    continue

            return vulnerable
        except Exception as e:
            self.logger.error(f"SQLi check error: {str(e)}")
            return {'error': str(e)}

    def check_open_redirect(self):
        """Enhanced open redirect detection"""
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        
        redirect_params = [
            'redirect', 'redirect_to', 'redirect_url', 'url',
            'next', 'next_page', 'destination', 'r', 'u',
            'return', 'return_url', 'go', 'target', 'link',
            'forward', 'file', 'load', 'page', 'view'
        ]
        
        test_domains = [
            'security-test.example.com',
            'redirect-validation.example.com',
            'open-redirect-check.example.org'
        ]
        
        findings = []
        
        # Test existing parameters
        for param in redirect_params:
            if param in query_params:
                for domain in test_domains:
                    test_url = f"https://{domain}/open-redirect-test"
                    modified_url = self._replace_param_value(param, test_url)
                    
                    try:
                        response = self.session.get(
                            modified_url,
                            allow_redirects=False,
                            verify=False,
                            timeout=5
                        )
                        
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get('Location', '')
                            if any(domain in location for domain in test_domains):
                                findings.append({
                                    'parameter': param,
                                    'url': modified_url,
                                    'payload': test_url,
                                    'risk': 'High',
                                    'confidence': 'high',
                                    'suggestion': f"Validate '{param}' parameter to only allow trusted URLs"
                                })
                                break
                    except requests.RequestException:
                        continue
        
        # Test adding parameters if none found
        if not findings:
            for param in redirect_params:
                if param not in query_params:
                    for domain in test_domains:
                        test_url = f"https://{domain}/open-redirect-test"
                        modified_url = self._add_param(param, test_url)
                        
                        try:
                            response = self.session.get(
                                modified_url,
                                allow_redirects=False,
                                verify=False,
                                timeout=5
                            )
                            
                            if response.status_code in (301, 302, 303, 307, 308):
                                location = response.headers.get('Location', '')
                                if any(domain in location for domain in test_domains):
                                    findings.append({
                                        'parameter': param,
                                        'url': modified_url,
                                        'payload': test_url,
                                        'risk': 'Medium',
                                        'confidence': 'medium',
                                        'suggestion': f"Server accepts '{param}' parameter. Implement redirect validation"
                                    })
                                    break
                        except requests.RequestException:
                            continue
        
        return findings

    def _replace_param_value(self, param_name, new_value):
        """Helper to replace parameter value in URL"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        params[param_name] = [new_value]
        new_query = '&'.join(f"{k}={v[0]}" for k, v in params.items())
        return urlunparse(parsed._replace(query=new_query))

    def _add_param(self, param_name, value):
        """Helper to add parameter to URL"""
        parsed = urlparse(self.target_url)
        query = f"{parsed.query}&{param_name}={value}" if parsed.query else f"{param_name}={value}"
        return urlunparse(parsed._replace(query=query))

    def run_all_checks(self):
        """Run all security checks"""
        return {
            'ssl': self.check_ssl(),
            'headers': self.check_headers(),
            'xss': self.check_xss_vulnerabilities(),
            'http_usage': self.check_insecure_http(),
            'sql_injection': self.check_sql_injection(),
            'open_redirect': self.check_open_redirect()
        }
