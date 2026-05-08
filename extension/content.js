// PhishGuard Content Script v3
// Gmail bridge, optional modern panel, and sensitive-reply warning.

(() => {
  if (window.__phishguardInstalled) {
    document.querySelectorAll('#phishguard-panel, .pg-shell').forEach((panel) => panel.remove());
    return;
  }
  window.__phishguardInstalled = true;

  const BACKEND_ANALYSE_URL = 'http://127.0.0.1:5001/analyse';
  const PANEL_ID = 'phishguard-panel';
  const REPLY_WARNING_ID = 'phishguard-reply-warning';

  let lastSignature = '';
  let scanTimer = null;
  let currentScanId = 0;

  const SENSITIVE_REPLY_PATTERNS = [
    { label: 'password', pattern: /\b(password|passcode|login)\b/i },
    { label: 'verification code', pattern: /\b(verification code|2fa|otp|one[-\s]?time code)\b/i },
    { label: 'banking details', pattern: /\b(bank account|routing number|sort code|iban|wire transfer)\b/i },
    { label: 'payment card', pattern: /\b(credit card|card number|cvv|cvc|expiry)\b/i },
    { label: 'identity document', pattern: /\b(passport|driver'?s licence|driver'?s license|national id|student id)\b/i },
    { label: 'gift card', pattern: /\b(gift card|steam card|apple card|google play card)\b/i },
  ];

  function escapeHTML(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function removeLegacyPanels() {
    document.querySelectorAll('#phishguard-panel, .pg-shell').forEach((panel) => panel.remove());
  }

  function getSubjectEl() {
    return document.querySelector('h2.hP') ||
      document.querySelector('[data-thread-perm-id] h2') ||
      document.querySelector('.ha h2');
  }

  function getSenderEl() {
    return document.querySelector('.gD[email]') ||
      document.querySelector('[email].gD') ||
      document.querySelector('[email]');
  }

  function getEmailContent() {
    const subjectEl = getSubjectEl();
    const subject = subjectEl ? subjectEl.innerText.trim() : '';

    const bodyEl = document.querySelector('.a3s.aiL') ||
      document.querySelector('[data-message-id] .a3s') ||
      document.querySelector('.ii.gt div');
    const body = bodyEl ? bodyEl.innerText.trim() : '';
    const bodyHtml = bodyEl ? bodyEl.innerHTML : '';

    const senderEl = getSenderEl();
    const senderEmail = senderEl ? senderEl.getAttribute('email') || '' : '';
    const senderName = senderEl
      ? senderEl.getAttribute('name') || senderEl.innerText.trim() || ''
      : '';
    const senderDomain = senderEmail.includes('@')
      ? senderEmail.split('@').pop().toLowerCase()
      : '';

    const headers = [
      `From: ${senderName} <${senderEmail}>`,
      `Subject: ${subject}`,
      `X-Sender-Domain: ${senderDomain}`,
    ].join('\n');

    return {
      subject,
      body,
      body_html: bodyHtml,
      senderEmail,
      senderName,
      senderDomain,
      headers,
      signature: `${document.location.href}|${subject}|${senderEmail}|${body.slice(0, 160)}`,
    };
  }

  function findPanelContainer() {
    return document.querySelector('[role="main"]') ||
      document.querySelector('.AO') ||
      document.querySelector('.nH.bkL') ||
      document.body;
  }

  function topbarHTML() {
    return `
      <div class="pg-panel-topbar">
        <div class="pg-panel-brand">
          <div class="pg-panel-logo">P</div>
          <div>
            <div class="pg-panel-title">PhishGuard</div>
            <div class="pg-panel-subtitle">Realtime email threat intelligence</div>
          </div>
        </div>
        <div class="pg-panel-actions">
          <button class="pg-panel-btn" type="button" data-pg-rescan title="Rescan">↻</button>
          <button class="pg-panel-btn" type="button" data-pg-close title="Close">×</button>
        </div>
      </div>
    `;
  }

  function getPanel() {
    let panel = document.getElementById(PANEL_ID);
    if (!panel) {
      panel = document.createElement('section');
      panel.id = PANEL_ID;
      const container = findPanelContainer();
      container.insertBefore(panel, container.firstChild);
    }
    return panel;
  }

  function bindPanelButtons(panel) {
    panel.querySelector('[data-pg-close]')?.addEventListener('click', () => panel.remove());
    panel.querySelector('[data-pg-rescan]')?.addEventListener('click', () => scanEmail({ force: true }));
  }

  function renderLoading(email) {
    const panel = getPanel();
    panel.innerHTML = topbarHTML() + `
      <div class="pg-panel-loading">
        <span class="pg-panel-spinner"></span>
        <span>Analysing ${escapeHTML(email.subject || 'current email')}...</span>
      </div>
    `;
    bindPanelButtons(panel);
  }

  function renderError(message) {
    const panel = getPanel();
    panel.innerHTML = topbarHTML() + `
      <div class="pg-panel-error">
        <span>⚠</span>
        <span>${escapeHTML(message)}</span>
      </div>
    `;
    bindPanelButtons(panel);
  }

  function authPill(label, value) {
    const normalized = String(value || 'UNKNOWN').toUpperCase();
    const cls = normalized === 'PASS'
      ? 'pg-auth-pass'
      : normalized === 'FAIL'
        ? 'pg-auth-fail'
        : 'pg-auth-none';
    return `<span class="pg-auth-pill ${cls}">${escapeHTML(label)}: ${escapeHTML(normalized)}</span>`;
  }

  function renderResult(data, email) {
    const risk = data?.risk || {};
    const ml = data?.ml || {};
    const hdr = data?.headers || {};
    const ip = data?.ip || {};
    const links = data?.links || {};
    const intent = data?.intent || {};
    const prompt = data?.prompt_injection || {};
    const level = String(risk.level || 'LOW').toLowerCase();
    const levelClass = level === 'high' ? 'pg-level-high' : level === 'medium' ? 'pg-level-medium' : 'pg-level-low';
    const icon = level === 'high' ? '!' : level === 'medium' ? '?' : '✓';
    const score = Math.min(Math.max(Number(risk.score || 0), 0), 100);
    const suspiciousLinks = Array.isArray(links.suspicious_links) ? links.suspicious_links.length : 0;
    const flags = Array.isArray(risk.flags) ? risk.flags : [];
    const originPrimary = ip.ip
      ? `${ip.city || 'Unknown'}, ${ip.country || 'Unknown'}`
      : (email.senderDomain || hdr.sender_domain || 'Unknown domain');
    const originSecondary = ip.ip ? `IP ${ip.ip}` : `Domain ${email.senderDomain || hdr.sender_domain || '-'}`;
    const promptRisk = prompt.risk || 'NONE';

    const flagsHTML = flags.length
      ? flags.slice(0, 5).map((flag, index) => `
          <div class="pg-flag" style="animation-delay:${0.04 + index * 0.04}s">
            <span>${level === 'high' ? '🚨' : '⚠'}</span>
            <span>${escapeHTML(flag)}</span>
          </div>
        `).join('')
      : `
          <div class="pg-flag pg-flag-ok">
            <span>✓</span>
            <span>No major red flags detected</span>
          </div>
        `;

    const panel = getPanel();
    panel.innerHTML = topbarHTML() + `
      <div class="pg-verdict-band ${levelClass}">
        <div class="pg-verdict-main">
          <div class="pg-verdict-icon">${icon}</div>
          <div>
            <div class="pg-verdict-label">${escapeHTML(risk.level || 'LOW')} risk</div>
            <div class="pg-verdict-text">${escapeHTML(risk.verdict || 'Analysis complete')}</div>
          </div>
        </div>
        <div class="pg-score-orb" style="--pg-score:${score}">
          <strong>${score}</strong>
          <span>/100</span>
        </div>
      </div>

      <div class="pg-progress">
        <div class="pg-progress-fill" data-target="${score}"></div>
      </div>

      <div class="pg-panel-grid">
        <div class="pg-panel-cell">
          <div class="pg-cell-label">Authentication</div>
          <div class="pg-auth-row">
            ${authPill('SPF', hdr.spf)}
            ${authPill('DKIM', hdr.dkim)}
            ${authPill('DMARC', hdr.dmarc)}
          </div>
          <div class="pg-cell-secondary">Gmail hides most raw auth headers unless Gmail API access is enabled.</div>
        </div>

        <div class="pg-panel-cell">
          <div class="pg-cell-label">Origin</div>
          <div class="pg-cell-primary">${escapeHTML(originPrimary)}</div>
          <div class="pg-cell-secondary">${escapeHTML(originSecondary)}</div>
          <div class="pg-cell-secondary">ISP: ${escapeHTML(ip.isp || email.senderDomain || 'Unknown')}</div>
          ${ip.is_vpn_proxy ? '<div class="pg-pill-row"><span class="pg-mini-pill pg-auth-fail">VPN / proxy</span></div>' : ''}
        </div>

        <div class="pg-panel-cell">
          <div class="pg-cell-label">AI verdict</div>
          <div class="pg-cell-primary">${escapeHTML(ml.label || 'Unknown')}</div>
          <div class="pg-cell-secondary">${escapeHTML(ml.confidence ?? 0)}% confidence</div>
          <div class="pg-ai-bar"><div class="pg-ai-fill" data-target="${Number(ml.confidence || 0)}"></div></div>
        </div>

        <div class="pg-panel-cell">
          <div class="pg-cell-label">Links</div>
          <div class="pg-cell-primary">${escapeHTML(links.total_links ?? 0)} total · ${suspiciousLinks} suspicious</div>
          <div class="pg-cell-secondary">${suspiciousLinks ? 'Review links before clicking.' : 'No suspicious link pattern found.'}</div>
        </div>
      </div>

      <div class="pg-panel-insight">
        <strong>Likely goal: ${escapeHTML(intent.goal || 'No clear malicious goal detected')}</strong>
        <span>${escapeHTML(intent.dangerous_step || 'No dangerous step identified.')}</span>
      </div>

      <div class="pg-panel-insight">
        <strong>Hidden AI-instruction check: ${escapeHTML(promptRisk)}</strong>
        <span>${escapeHTML(prompt.findings?.[0] || 'No hidden AI manipulation patterns detected.')}</span>
      </div>

      <div class="pg-panel-flags">${flagsHTML}</div>

      <div class="pg-panel-footer">
        <span>Local scan · Gmail data not stored by panel</span>
        <span>PHISHGUARD AI <span class="pg-live-dot"></span></span>
      </div>
    `;

    bindPanelButtons(panel);
    setTimeout(() => {
      panel.querySelectorAll('[data-target]').forEach((bar) => {
        bar.style.width = `${Math.min(Math.max(Number(bar.dataset.target || 0), 0), 100)}%`;
      });
    }, 80);
  }

  async function updateStats(data) {
    try {
      const current = await chrome.storage.local.get(['scanned', 'threats', 'safe']);
      const level = data?.risk?.level || 'LOW';
      await chrome.storage.local.set({
        scanned: (current.scanned || 0) + 1,
        threats: (current.threats || 0) + (level === 'HIGH' ? 1 : 0),
        safe: (current.safe || 0) + (level === 'LOW' ? 1 : 0),
      });
    } catch {
      // Storage failures should not block the panel.
    }
  }

  async function scanEmail({ force = false } = {}) {
    const email = getEmailContent();
    if (!email.subject && !email.body) return;
    if (!force && email.signature === lastSignature) return;

    lastSignature = email.signature;
    const scanId = ++currentScanId;
    renderLoading(email);

    try {
      const response = await fetch(BACKEND_ANALYSE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: email.subject,
          body: email.body,
          body_html: email.body_html,
          headers: email.headers,
          senderEmail: email.senderEmail,
          senderDomain: email.senderDomain,
        }),
      });
      if (!response.ok) throw new Error(`Backend returned ${response.status}`);

      const data = await response.json();
      if (scanId !== currentScanId) return;

      renderResult(data, email);
      updateStats(data);
    } catch (err) {
      if (scanId !== currentScanId) return;
      renderError('Flask backend offline or unavailable. Start backend/app.py and rescan.');
    }
  }

  function scheduleScan() {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(() => scanEmail(), 700);
  }

  function observeGmail() {
    const observer = new MutationObserver(() => {
      if (getSubjectEl()) scheduleScan();
    });
    observer.observe(document.body, { childList: true, subtree: true });
    scheduleScan();
  }

  function findComposeBodies() {
    return [...document.querySelectorAll('div[contenteditable="true"][aria-label="Message Body"]')];
  }

  function updateReplyWarnings() {
    for (const body of findComposeBodies()) {
      const text = body.innerText || '';
      const hits = SENSITIVE_REPLY_PATTERNS
        .filter((item) => item.pattern.test(text))
        .map((item) => item.label);
      const uniqueHits = [...new Set(hits)];
      const existing = body.parentElement?.querySelector(`#${REPLY_WARNING_ID}`);

      if (!uniqueHits.length) {
        existing?.remove();
        continue;
      }

      const warning = existing || document.createElement('div');
      warning.id = REPLY_WARNING_ID;
      warning.innerHTML = `
        <strong>PhishGuard reply warning</strong>
        This draft appears to include ${escapeHTML(uniqueHits.join(', '))}. Verify the sender outside this email before sending.
      `;
      if (!existing) body.parentElement?.insertBefore(warning, body);
    }
  }

  function observeComposeWarnings() {
    let timer = null;
    const observer = new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(updateReplyWarnings, 250);
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    document.addEventListener('input', (event) => {
      if (event.target?.closest?.('div[contenteditable="true"][aria-label="Message Body"]')) {
        updateReplyWarnings();
      }
    }, true);
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === 'PG_GET_EMAIL') {
      sendResponse({ ok: true, email: getEmailContent() });
      return true;
    }

    if (message?.type === 'PG_CLEAR_PANELS') {
      removeLegacyPanels();
      sendResponse({ ok: true });
      return true;
    }

    if (message?.type === 'PG_SCAN_AND_SHOW') {
      scanEmail({ force: true });
      sendResponse({ ok: true });
      return true;
    }

    return false;
  });

  removeLegacyPanels();
  observeGmail();
  observeComposeWarnings();
})();
