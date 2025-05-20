document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const resultsDiv = document.getElementById('results');
    const errorDiv = document.getElementById('error');
    const spinner = document.querySelector('.spinner-border');
    const chatBtn = document.getElementById('sendChat');
    const chatInput = document.getElementById('chatInput');
    const chatResponse = document.getElementById('chatResponse');

    // Debounce function to limit rapid requests
    function debounce(func, wait) {
        let timeout;
        return function (...args) {
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(this, args), wait);
        };
    }

    // Handle scan form submission
    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        resultsDiv.classList.add('d-none');
        errorDiv.classList.add('d-none');
        spinner.classList.remove('d-none');

        const formData = new FormData(scanForm);
        const targetUrl = formData.get('url');

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            if (data.error) throw new Error(data.error);

            if (!data.open_redirect) {
                const redirectData = await checkOpenRedirects(targetUrl);
                if (redirectData.error) throw new Error(redirectData.error);
                data.open_redirect = redirectData.open_redirect;
                if (redirectData.security_score && data.security_score) {
                    data.security_score = Math.min(data.security_score, redirectData.security_score);
                }
            }

            displayResults(data);
            resultsDiv.classList.remove('d-none');
        } catch (err) {
            errorDiv.textContent = err.message;
            errorDiv.classList.remove('d-none');
        } finally {
            spinner.classList.add('d-none');
        }
    });

    async function checkOpenRedirects(targetUrl) {
        try {
            const response = await fetch('/scan/redirects', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: targetUrl })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.error || 'Open redirect scan failed');
            return data;
        } catch (error) {
            console.error('Open redirect scan failed:', error);
            return { error: `Failed to complete open redirect scan: ${error.message}` };
        }
    }

    function displayResults(data) {
        updateText('sslResults', `
            <strong>Status:</strong> ${data.ssl.status}<br>
            <strong>Issuer:</strong> ${JSON.stringify(data.ssl.issuer)}<br>
            <strong>Expiry:</strong> ${data.ssl.expiry}<br>
            <em class="text-warning">${data.ssl.suggestion}</em>
        `);

        updateText('headerResults', Object.entries(data.headers || {}).map(([key, val]) => `
            <div><strong>${key}:</strong> ${val.value}<br><em class="text-warning">${val.suggestion}</em></div>
        `).join(''));

        updateText('xssResults', (data.xss || []).map(xss => `
            <div class="vulnerability-item"><strong>Risk:</strong> ${xss.risk}<br>
            <strong>Element:</strong> ${xss.element}<br>
            <em class="text-warning">${xss.suggestion}</em></div>
        `).join('') || '<div class="secure-item">No XSS vulnerabilities found</div>');

        updateText('httpUsageResults', `
            <strong>Status:</strong> ${data.http_usage.status}<br>
            <strong>Message:</strong> ${data.http_usage.message}<br>
            <em class="text-warning">${data.http_usage.suggestion}</em>
        `);

        if (Array.isArray(data.sql_injection)) {
            updateText('sqlInjectionResults',
                data.sql_injection.length === 0
                    ? '<div class="secure-item">No SQL Injection issues detected.</div>'
                    : data.sql_injection.map(vuln => `
                        <div class="vulnerability-item">
                            <strong>Risk:</strong> ${vuln.risk}<br>
                            <strong>Payload:</strong> <code>${escapeHtml(vuln.payload)}</code><br>
                            <strong>Tested URL:</strong> <code>${escapeHtml(vuln.url)}</code><br>
                            <em class="text-warning">${vuln.suggestion}</em>
                        </div>
                    `).join('')
            );
        } else if (data.sql_injection?.error) {
            updateText('sqlInjectionResults', `
                <div class="alert alert-warning">Error checking SQL Injection: ${data.sql_injection.error}</div>
            `);
        }

        if (Array.isArray(data.open_redirect)) {
            const statusBadge = document.getElementById('openRedirectStatus');
            const card = document.getElementById('openRedirectCard');
            if (data.open_redirect.length > 0) {
                statusBadge.textContent = 'Vulnerable';
                statusBadge.className = 'badge badge-vulnerable';  // Use custom badge class
                card.classList.add('vulnerable-card');
                updateText('openRedirectResults', `
                    <div class="alert alert-danger">
                        <strong>${data.open_redirect.length} Open Redirect Vulnerability(s) Found</strong>
                    </div>
                    ${data.open_redirect.map((vuln, index) => `
                        <div class="mb-3">
                            <h5 data-bs-toggle="collapse" data-bs-target="#openRedirectDetails${index}" class="details-toggle">
                                Parameter: ${vuln.parameter}
                            </h5>
                            <div id="openRedirectDetails${index}" class="collapse vulnerability-details">
                                <p><strong>Vulnerable URL:</strong> <code>${escapeHtml(vuln.url)}</code></p>
                                <p><strong>Test Payload:</strong> <code>${escapeHtml(vuln.payload)}</code></p>
                                <p><strong>Confidence:</strong> <span class="badge badge-warning">${vuln.confidence}</span></p>
                                <div class="alert alert-info"><strong>Recommendation:</strong> ${vuln.suggestion}</div>
                            </div>
                        </div>
                    `).join('')}
                `);
            } else {
                statusBadge.textContent = 'Secure';
                statusBadge.className = 'badge badge-secure';  // Use custom badge class
                card.classList.add('safe-card');
                updateText('openRedirectResults', `
                    <div class="alert alert-success">No Open Redirect Vulnerabilities Found</div>
                `);
            }
        }

        updateSecurityScore(data.security_score);
    }

    function updateText(id, html) {
        const el = document.getElementById(id);
        if (el) el.innerHTML = html;
    }

    function updateSecurityScore(score) {
        const bar = document.getElementById('securityScoreBar');
        const label = document.getElementById('scoreValue');

        if (bar) {
            bar.style.width = `${score}%`;
            bar.setAttribute('aria-valuenow', score);
            bar.className = `progress-bar ${
                score >= 80 ? 'bg-success' : score >= 50 ? 'bg-warning' : 'bg-danger'
            }`;
        }
        if (label) {
            label.textContent = `${score}%`;
            label.className = `badge ${
                score >= 80 ? 'bg-success' : score >= 50 ? 'bg-warning' : 'bg-danger'
            } fs-5 px-3 py-2`;
        }
    }

    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // AI Assistant for Security Help with Debounce
    if (chatBtn && chatInput && chatResponse) {
        chatBtn.addEventListener('click', debounce(async () => {
            const question = chatInput.value.trim();
            if (!question) {
                chatResponse.textContent = 'Please enter a question.';
                chatResponse.classList.remove('d-none');
                chatResponse.classList.add('alert-danger');
                return;
            }

            chatBtn.disabled = true;
            chatResponse.classList.remove('d-none', 'alert-danger', 'alert-secondary');
            chatResponse.classList.add('alert-info');
            chatResponse.textContent = 'Thinking...';

            try {
                const res = await fetch('/ask', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question })
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || 'Failed to get response from AI');
                }
                chatResponse.textContent = data.response || 'No response received from AI.';
                chatResponse.classList.remove('alert-info');
                chatResponse.classList.add('alert-secondary');
                chatInput.value = ''; // Clear input
            } catch (err) {
                chatResponse.textContent = `Error: ${err.message}`;
                chatResponse.classList.remove('alert-info');
                chatResponse.classList.add('alert-danger');
            } finally {
                chatBtn.disabled = false;
            }
        }, 2000)); // 2-second debounce
    }
});
