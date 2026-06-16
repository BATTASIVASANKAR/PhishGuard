/**
 * PhishGuard — URL Scanner Dashboard Logic
 * Handles async API scanning, UI updates, and dashboard rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('url-scan-form');
    const urlInput = document.getElementById('url-input');
    const initialView = document.getElementById('initial-view');
    const progressView = document.getElementById('progress-view');
    const dashboardView = document.getElementById('dashboard-view');
    const errorBanner = document.getElementById('error-banner');
    
    let currentScanId = null;

    if (!scanForm) return;

    scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        // Reset UI
        errorBanner.style.display = 'none';
        initialView.style.display = 'none';
        dashboardView.style.display = 'none';
        progressView.style.display = 'block';
        
        // Reset steps
        document.querySelectorAll('.scan-step').forEach(el => {
            el.className = 'scan-step';
        });

        try {
            // Start mock progress animation
            animateProgress();
            
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Scan failed to complete.');
            }

            // Render Dashboard
            currentScanId = data.scan_id;
            renderDashboard(data);
            
            // Switch views
            progressView.style.display = 'none';
            dashboardView.style.display = 'grid';

        } catch (err) {
            progressView.style.display = 'none';
            initialView.style.display = 'block';
            errorBanner.textContent = `⚠️ ${err.message}`;
            errorBanner.style.display = 'flex';
        }
    });

    // Handle PDF Download
    const downloadBtn = document.getElementById('download-pdf-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            if (currentScanId) {
                window.location.href = `/api/report/${currentScanId}`;
            }
        });
    }
});

// ── Progress Animation ──────────────────────────────────────────────────────

function animateProgress() {
    const steps = document.querySelectorAll('.scan-step');
    let currentStep = 0;

    steps[0].classList.add('active');

    const interval = setInterval(() => {
        if (currentStep < steps.length - 1) {
            steps[currentStep].classList.remove('active');
            steps[currentStep].classList.add('done');
            currentStep++;
            steps[currentStep].classList.add('active');
        } else {
            clearInterval(interval);
        }
    }, 1200); // Faux progress updating every 1.2s
}

// ── Dashboard Rendering ─────────────────────────────────────────────────────

function renderDashboard(data) {
    // 1. Verdict
    renderVerdict(data);

    // 2. SSL Card
    renderSSLCard(data.ssl);

    // 3. WHOIS Card
    renderWhoisCard(data.whois);

    // 4. VirusTotal Panel
    renderVirusTotalPanel(data.virustotal);

    // 5. DNS & Hosting
    renderDNSCard(data.dns);

    // 6. Technologies
    renderTechCard(data.technologies);

    // 7. Findings
    renderFindings(data.url_patterns);
}

// ── Components ──────────────────────────────────────────────────────────────

function renderVerdict(data) {
    const verdictContent = document.getElementById('verdict-content');
    if (!verdictContent) return;
    
    let reasons = [];
    let isHighRisk = false;
    let isSuspicious = false;
    let suspiciousCount = 0;
    
    // Evaluate VirusTotal
    let vtDetections = false;
    if (data.virustotal && data.virustotal.available && data.virustotal.malicious > 0) {
        vtDetections = true;
        isHighRisk = true;
    }
    
    // Evaluate SSL
    let invalidSsl = false;
    if (!data.ssl || !data.ssl.available || data.ssl.status !== 'valid') {
        invalidSsl = true;
        isHighRisk = true;
    }

    // Evaluate URL shortener
    let isShortener = false;
    if (data.url_patterns && data.url_patterns.findings && data.url_patterns.findings.some(f => f.toLowerCase().includes('shortener'))) {
        isShortener = true;
        isSuspicious = true;
        suspiciousCount++;
    }

    // Evaluate Domain Age
    let isNewDomain = false;
    let isOldDomain = false;
    if (data.whois && data.whois.domain_age_days !== null && data.whois.domain_age_days !== undefined) {
        if (data.whois.domain_age_days < 90) {
            isNewDomain = true;
            isSuspicious = true;
            suspiciousCount++;
        } else if (data.whois.domain_age_days >= 365) {
            isOldDomain = true;
        }
    }

    // Evaluate SPF
    let isSpfMissing = false;
    if (!data.dns || !data.dns.spf_record || data.dns.spf_record === 'Not Found' || data.dns.spf_record === 'Missing') {
        isSpfMissing = true;
        isSuspicious = true;
        suspiciousCount++;
    }

    // Evaluate DMARC
    let isDmarcMissing = false;
    if (!data.dns || !data.dns.dmarc_record || data.dns.dmarc_record === 'Not Found' || data.dns.dmarc_record === 'Missing') {
        isDmarcMissing = true;
        isSuspicious = true;
        suspiciousCount++;
    }

    // Multiple suspicious indicators for HIGH RISK
    if (suspiciousCount >= 2) {
        isHighRisk = true;
    }

    let status = 'SAFE';
    let color = 'var(--safe-color)';
    
    if (isHighRisk) {
        status = 'HIGH RISK';
        color = 'var(--danger-color)';
        
        if (vtDetections) reasons.push('<span style="color:var(--danger-color)">✖ VirusTotal flagged the URL</span>');
        if (invalidSsl) reasons.push('<span style="color:var(--danger-color)">✖ Invalid SSL certificate</span>');
        if (suspiciousCount >= 2) reasons.push('<span style="color:var(--danger-color)">✖ Multiple security warnings detected</span>');
        
    } else if (isSuspicious) {
        status = 'SUSPICIOUS';
        color = 'var(--warning-color)';
        
        if (isShortener) reasons.push('<span style="color:var(--warning-color)">⚠ URL shortener detected</span>');
        if (isNewDomain) reasons.push('<span style="color:var(--warning-color)">⚠ Domain is relatively new</span>');
        if (isSpfMissing) reasons.push('<span style="color:var(--warning-color)">⚠ SPF record missing</span>');
        if (isDmarcMissing) reasons.push('<span style="color:var(--warning-color)">⚠ DMARC record missing</span>');
        if (data.virustotal && data.virustotal.available && data.virustotal.suspicious > 0 && !vtDetections) {
             reasons.push('<span style="color:var(--warning-color)">⚠ VirusTotal flagged the URL as suspicious</span>');
        }
        
    } else {
        // SAFE
        reasons.push('<span style="color:var(--safe-color)">✔ No VirusTotal detections</span>');
        reasons.push('<span style="color:var(--safe-color)">✔ Valid SSL certificate</span>');
        reasons.push('<span style="color:var(--safe-color)">✔ HTTPS enabled</span>');
        if (isOldDomain) reasons.push('<span style="color:var(--safe-color)">✔ Domain has existed for several years</span>');
        reasons.push('<span style="color:var(--safe-color)">✔ SPF record found</span>');
        reasons.push('<span style="color:var(--safe-color)">✔ DMARC record found</span>');
    }

    verdictContent.innerHTML = `
        <div style="font-size: 1.5rem; font-weight: bold; margin-bottom: 1rem;">
            Status: <span style="color: ${color}">${status}</span>
        </div>
        <div style="font-weight: bold; margin-bottom: 0.5rem; color: var(--text-primary); font-size: 1.1rem;">Reasons:</div>
        <ul style="list-style: none; padding-left: 0; line-height: 1.8; margin: 0; font-size: 1.05rem;">
            ${reasons.map(r => `<li>${r}</li>`).join('')}
        </ul>
    `;
}

function renderThreatMeter(risk) {
    const scoreEl = document.getElementById('meter-score');
    const valueCircle = document.getElementById('meter-value');
    const badgeEl = document.getElementById('risk-badge');
    const descEl = document.getElementById('risk-description');

    // Colors mapping
    const colors = {
        'Critical': '#ef4444', // Danger Red
        'High': '#f87171',     // Light Red
        'Medium': '#f59e0b',   // Amber
        'Low': '#22c55e'       // Green
    };

    const color = colors[risk.level] || '#1e90ff';

    // Animate Number
    let start = 0;
    const end = risk.total;
    const duration = 1500;
    const stepTime = Math.abs(Math.floor(duration / (end || 1)));
    
    if (end > 0) {
        const timer = setInterval(() => {
            start += 1;
            scoreEl.textContent = start;
            if (start === end) clearInterval(timer);
        }, stepTime);
    } else {
        scoreEl.textContent = '0';
    }

    scoreEl.style.color = color;
    
    // Stroke dasharray magic (circumference is ~440 for r=70)
    const circ = 2 * Math.PI * 70;
    const offset = circ - (risk.total / 100) * circ;
    
    setTimeout(() => {
        valueCircle.style.strokeDasharray = `${circ} ${circ}`;
        valueCircle.style.strokeDashoffset = offset;
        valueCircle.style.stroke = color;
    }, 100);

    // Badge
    badgeEl.textContent = `${risk.level} RISK`;
    badgeEl.style.backgroundColor = `${color}20`; // 20% opacity
    badgeEl.style.color = color;
    badgeEl.style.border = `1px solid ${color}40`;
    
    descEl.textContent = risk.level_description;
}

function renderSSLCard(ssl) {
    const tbody = document.getElementById('ssl-table-body');
    tbody.innerHTML = '';

    // Not available or no parseable certificate
    if (!ssl.available) {
        const msg = ssl.error || 'Certificate information unavailable';
        tbody.innerHTML = `<tr><td colspan="2" class="value" style="color:var(--warning-color); font-style: italic;">${msg}</td></tr>`;
        return;
    }

    // Status colour
    let statusColor = 'var(--safe-color)';
    if (ssl.status === 'expired' || ssl.status === 'no_ssl') statusColor = 'var(--danger-color)';
    else if (ssl.status === 'self_signed' || ssl.status === 'expiring_soon' || ssl.status === 'invalid') statusColor = 'var(--warning-color)';

    // Only show fields that have real values
    const rows = [
        ['Status', `<span style="color: ${statusColor}; font-weight: bold">${ssl.status.replace(/_/g, ' ').toUpperCase()}</span>`],
    ];

    if (ssl.issuer_cn) rows.push(['Issuer CN', ssl.issuer_cn]);
    else if (ssl.issuer)  rows.push(['Issuer',    ssl.issuer]);

    if (ssl.subject_cn) rows.push(['Subject CN', ssl.subject_cn]);
    else if (ssl.subject) rows.push(['Subject',   ssl.subject]);

    if (ssl.valid_from) rows.push(['Valid From', ssl.valid_from]);
    if (ssl.valid_to)   rows.push(['Valid To',   ssl.valid_to]);

    if (ssl.days_remaining !== null && ssl.days_remaining !== undefined) {
        rows.push(['Days Remaining', `${ssl.days_remaining} days`]);
    }

    if (ssl.signature_algorithm) rows.push(['Signature Algorithm', ssl.signature_algorithm]);

    // If only the status row exists (no cert fields), show unavailable note
    if (rows.length === 1) {
        tbody.innerHTML = `<tr><td colspan="2" class="value" style="color:var(--warning-color); font-style: italic;">Certificate information unavailable</td></tr>`;
        return;
    }

    rows.forEach(([label, value]) => {
        tbody.innerHTML += `<tr><td class="label">${label}</td><td class="value">${value}</td></tr>`;
    });
}

function renderWhoisCard(whois) {
    const tbody = document.getElementById('whois-table-body');
    tbody.innerHTML = '';

    if (!whois.available) {
        tbody.innerHTML = `<tr><td colspan="2" class="value" style="color:var(--warning-color)">${whois.error || 'WHOIS data hidden/unavailable'}</td></tr>`;
        return;
    }

    const rows = [
        ['Domain', whois.domain || 'N/A'],
        ['Registrar', whois.registrar || 'N/A'],
        ['Creation Date', whois.creation_date || 'N/A'],
        ['Domain Age', whois.domain_age_days ? `${whois.domain_age_days} days` : 'N/A'],
        ['Country', whois.registrant_country || 'N/A']
    ];

    rows.forEach(([label, value]) => {
        tbody.innerHTML += `<tr><td class="label">${label}</td><td class="value">${value}</td></tr>`;
    });
}

function renderVirusTotalPanel(vt) {
    const vtContent = document.getElementById('vt-content');
    vtContent.innerHTML = '';

    // ── API not configured ───────────────────────────────────────────────────
    if (!vt.available && vt.error_code === 'NO_API_KEY') {
        vtContent.innerHTML = `
            <div style="padding:1.5rem; border:1px solid var(--accent-primary)40; border-radius:12px; background:var(--accent-primary)08;">
                <div style="font-size:1.1rem; font-weight:600; margin-bottom:.75rem;">🔑 VirusTotal API Key Required</div>
                <p style="color:var(--text-secondary); margin-bottom:1rem; line-height:1.6;">
                    VirusTotal integration requires a free API key.
                    The free tier allows <strong>500 lookups/day</strong> and <strong>4 lookups/minute</strong>.
                </p>
                <ol style="color:var(--text-secondary); line-height:2; padding-left:1.25rem; margin-bottom:1rem;">
                    <li>Go to <a href="https://www.virustotal.com/gui/join-us" target="_blank" style="color:var(--accent-primary)">virustotal.com/gui/join-us</a> and create a free account.</li>
                    <li>After logging in, visit <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" style="color:var(--accent-primary)">virustotal.com/gui/my-apikey</a>.</li>
                    <li>Copy your 64-character API key.</li>
                    <li>Open <code style="background:var(--bg-secondary);padding:2px 6px;border-radius:4px">.env</code> in the project root.</li>
                    <li>Set <code style="background:var(--bg-secondary);padding:2px 6px;border-radius:4px">VIRUSTOTAL_API_KEY=&lt;your_key&gt;</code> and save.</li>
                    <li>Restart the Flask server.</li>
                </ol>
                <div style="font-size:.8rem; color:var(--text-muted);">
                    ℹ️ All other scan sections (WHOIS, SSL, DNS) work without a VirusTotal key.
                </div>
            </div>`;
        return;
    }

    // ── Invalid / revoked key ────────────────────────────────────────────────
    if (!vt.available && vt.error_code === 'INVALID_KEY') {
        vtContent.innerHTML = `
            <div style="padding:1rem; color:var(--danger-color);">
                🚫 <strong>Invalid API Key</strong> — Your VirusTotal API key was rejected (HTTP 401/403).<br>
                <span style="color:var(--text-muted); font-size:.9rem;">
                    Please verify the key at
                    <a href="https://www.virustotal.com/gui/my-apikey" target="_blank" style="color:var(--accent-primary)">virustotal.com/gui/my-apikey</a>
                    and update <code>.env</code>.
                </span>
            </div>`;
        return;
    }

    // ── Rate limited ─────────────────────────────────────────────────────────
    if (!vt.available && vt.error_code === 'RATE_LIMITED') {
        vtContent.innerHTML = `
            <div style="padding:1rem; color:var(--warning-color);">
                ⏳ <strong>Rate Limit Reached</strong> — VirusTotal free plan allows 4 lookups/min, 500/day.<br>
                <span style="color:var(--text-muted); font-size:.9rem;">Wait a minute and scan again.</span>
            </div>`;
        return;
    }

    // ── Any other error ──────────────────────────────────────────────────────
    if (!vt.available) {
        vtContent.innerHTML = `
            <div style="padding:1rem; color:var(--text-muted);">
                ⚠️ ${vt.error || 'VirusTotal analysis is not available for this scan.'}
            </div>`;
        return;
    }

    // ── Stats bar ────────────────────────────────────────────────────────────
    const scanDateHtml = vt.scan_date
        ? `<div style="font-size:.78rem; color:var(--text-muted); text-align:right; padding:.25rem 1rem;">Last scanned: ${vt.scan_date}</div>`
        : '';

    const communityColor = vt.community_score > 0
        ? 'var(--safe-color)'
        : vt.community_score < 0 ? 'var(--danger-color)' : 'var(--text-muted)';

    const statsHtml = `
        <div class="vt-stats">
            <div class="vt-stat-item">
                <div class="vt-stat-value" style="color:${vt.malicious > 0 ? 'var(--danger-color)' : 'var(--text-primary)'}">
                    ${vt.malicious}
                </div>
                <div class="vt-stat-label">Malicious</div>
            </div>
            <div class="vt-stat-item">
                <div class="vt-stat-value" style="color:${vt.suspicious > 0 ? 'var(--warning-color)' : 'var(--text-primary)'}">
                    ${vt.suspicious}
                </div>
                <div class="vt-stat-label">Suspicious</div>
            </div>
            <div class="vt-stat-item">
                <div class="vt-stat-value" style="color:var(--safe-color)">${vt.harmless}</div>
                <div class="vt-stat-label">Harmless</div>
            </div>
            <div class="vt-stat-item">
                <div class="vt-stat-value">${vt.undetected}</div>
                <div class="vt-stat-label">Undetected</div>
            </div>
            <div class="vt-stat-item">
                <div class="vt-stat-value">${vt.total_engines}</div>
                <div class="vt-stat-label">Engines</div>
            </div>
            <div class="vt-stat-item">
                <div class="vt-stat-value" style="color:${communityColor}">
                    ${vt.community_score > 0 ? '+' : ''}${vt.community_score}
                </div>
                <div class="vt-stat-label">Community</div>
            </div>
        </div>
        ${scanDateHtml}`;

    // ── Permalink ─────────────────────────────────────────────────────────────
    const linkHtml = vt.permalink
        ? `<div style="padding:.5rem 1rem; font-size:.82rem;">
               <a href="${vt.permalink}" target="_blank" style="color:var(--accent-primary);">
                   🔗 View full VirusTotal report →
               </a>
           </div>`
        : '';

    // ── Detection engine grid ─────────────────────────────────────────────────
    let detectionsHtml = '';
    if (vt.detections && vt.detections.length > 0) {
        detectionsHtml = `<div class="vt-detections-grid">`;
        vt.detections.forEach(d => {
            const isMalicious = d.category === 'malicious';
            detectionsHtml += `
                <div class="vt-detection-item ${isMalicious ? 'malicious' : ''}">
                    <strong>${d.engine}</strong>
                    <span>${d.result}</span>
                </div>`;
        });
        detectionsHtml += `</div>`;
    } else {
        detectionsHtml = `
            <div style="text-align:center; padding:1rem; color:var(--safe-color)">
                ✓ No security engines flagged this URL.
            </div>`;
    }

    vtContent.innerHTML = statsHtml + linkHtml + detectionsHtml;
}

function renderDNSCard(dns) {
    const tbody = document.getElementById('dns-table-body');
    tbody.innerHTML = '';

    // ── Helper: colour a "Not Found" value differently ──────────────────────
    function cell(value) {
        if (!value || value === 'Not Found' || value === 'Missing') {
            return `<span style="color:var(--warning-color)">Not Found</span>`;
        }
        return value;
    }

    // ── Full failure ─────────────────────────────────────────────────────────
    if (!dns.available && (!dns.ip_addresses || !dns.ip_addresses.length)) {
        tbody.innerHTML = `
            <tr>
                <td colspan="2" class="value" style="color:var(--danger-color)">
                    ⚠ ${dns.error || 'DNS lookup failed — could not resolve domain.'}
                </td>
            </tr>`;
        return;
    }

    // ── A Records (IPv4) ─────────────────────────────────────────────────────
    const aVal = dns.ip_addresses && dns.ip_addresses.length
        ? dns.ip_addresses.join('<br>')
        : null;
    tbody.innerHTML += `<tr><td class="label">A (IPv4)</td><td class="value">${cell(aVal)}</td></tr>`;

    // ── AAAA Records (IPv6) ──────────────────────────────────────────────────
    const aaaaVal = dns.ipv6_addresses && dns.ipv6_addresses.length
        ? dns.ipv6_addresses.join('<br>')
        : null;
    tbody.innerHTML += `<tr><td class="label">AAAA (IPv6)</td><td class="value">${cell(aaaaVal)}</td></tr>`;

    // ── MX Records ───────────────────────────────────────────────────────────
    let mxVal = null;
    if (dns.mx_records && dns.mx_records.length) {
        mxVal = dns.mx_records
            .map(m => `<span style="opacity:.7">[${m.priority}]</span> ${m.host}`)
            .join('<br>');
    }
    tbody.innerHTML += `<tr><td class="label">MX (Mail)</td><td class="value">${cell(mxVal)}</td></tr>`;

    // ── NS Records ───────────────────────────────────────────────────────────
    const nsVal = dns.ns_records && dns.ns_records.length
        ? dns.ns_records.join('<br>')
        : null;
    tbody.innerHTML += `<tr><td class="label">NS (Nameservers)</td><td class="value">${cell(nsVal)}</td></tr>`;

    // ── TXT Records ──────────────────────────────────────────────────────────
    let txtVal = null;
    if (dns.txt_records && dns.txt_records.length) {
        txtVal = dns.txt_records
            .map(t => `<code style="font-size:.75rem;word-break:break-all">${t}</code>`)
            .join('<br>');
    }
    tbody.innerHTML += `<tr><td class="label">TXT Records</td><td class="value">${cell(txtVal)}</td></tr>`;

    // ── SPF / DMARC ──────────────────────────────────────────────────────────
    tbody.innerHTML += `<tr><td class="label">SPF</td><td class="value">${cell(dns.spf_record)}</td></tr>`;
    tbody.innerHTML += `<tr><td class="label">DMARC</td><td class="value">${cell(dns.dmarc_record)}</td></tr>`;

    // ── Hosting / Location ───────────────────────────────────────────────────
    const loc    = dns.server_location || {};
    const locStr = [loc.city, loc.region, loc.country].filter(Boolean).join(', ') || null;
    tbody.innerHTML += `<tr><td class="label">Hosting</td><td class="value">${cell(dns.hosting_provider)}</td></tr>`;
    tbody.innerHTML += `<tr><td class="label">Server Location</td><td class="value">${cell(locStr)}</td></tr>`;

    // ── Partial Errors Notice ────────────────────────────────────────────────
    const partial = dns.partial_errors || {};
    const errKeys = Object.keys(partial);
    if (errKeys.length) {
        const msgs = errKeys.map(k => `<strong>${k}</strong>: ${partial[k]}`).join('<br>');
        tbody.innerHTML += `
            <tr>
                <td colspan="2" style="padding-top:.5rem; font-size:.78rem; color:var(--text-muted)">
                    ⚠ Some queries had issues:<br>${msgs}
                </td>
            </tr>`;
    }
}

function renderTechCard(techData) {
    const grid = document.getElementById('tech-grid');
    grid.innerHTML = '';

    if (!techData.available || !techData.technologies || techData.technologies.length === 0) {
        grid.innerHTML = `<div style="color:var(--text-muted)">Could not detect specific technologies.</div>`;
        return;
    }

    techData.technologies.forEach(t => {
        grid.innerHTML += `
            <div class="tech-badge">
                <span class="tech-name">${t.name}</span>
                <span class="tech-category">${t.category}</span>
            </div>
        `;
    });
}

function renderFindings(patterns) {
    const container = document.getElementById('findings-container');
    container.innerHTML = '';

    if (!patterns.findings || patterns.findings.length === 0) {
        container.innerHTML = `<div style="color:var(--safe-color)">✓ No suspicious URL patterns detected.</div>`;
        return;
    }

    patterns.findings.forEach(f => {
        const isPositive = f.includes('enabled') || f.includes('detected') || f.includes('Secure');
        const icon = isPositive ? '✓' : '⚠';
        const color = isPositive ? 'var(--safe-color)' : 'var(--warning-color)';
        container.innerHTML += `
            <div style="margin-bottom: 0.5rem; color: ${color}; font-size: 0.9rem;">
                ${icon} ${f}
            </div>
        `;
    });
}

function renderRiskBreakdown(breakdown) {
    const container = document.getElementById('risk-breakdown-list');
    container.innerHTML = '';

    if (!breakdown) return;

    Object.values(breakdown).forEach(item => {
        // Calculate percentage width (cap at 100%)
        const pct = Math.min((item.score / item.max) * 100, 100);
        
        // Color based on score severity
        let color = 'var(--safe-color)';
        if (pct >= 60) color = 'var(--danger-color)';
        else if (pct >= 30) color = 'var(--warning-color)';
        else if (pct > 0) color = 'var(--accent-primary)';

        container.innerHTML += `
            <div class="risk-item">
                <div class="risk-item-header">
                    <span>${item.label}</span>
                    <span>${item.score} / ${item.max}</span>
                </div>
                <div class="risk-item-bar-container">
                    <div class="risk-item-bar" style="width: 0%; background: ${color}" data-target-width="${pct}%"></div>
                </div>
                <div class="risk-item-detail">${item.detail}</div>
            </div>
        `;
    });

    // Animate bars after rendering
    setTimeout(() => {
        document.querySelectorAll('.risk-item-bar').forEach(bar => {
            bar.style.width = bar.getAttribute('data-target-width');
        });
    }, 100);
}
