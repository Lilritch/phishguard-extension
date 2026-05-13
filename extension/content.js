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

  function getAttachments() {
    const candidates = [
      ...document.querySelectorAll('[download_url]'),
      ...document.querySelectorAll('[aria-label*="Download attachment"]'),
      ...document.querySelectorAll('[data-tooltip*="Download"]'),
      ...document.querySelectorAll('.aQH, .aZo, .aV3'),
    ];
    const seen = new Set();

    return candidates
      .map((node) => {
        const downloadUrl = node.getAttribute?.('download_url') || '';
        const parts = downloadUrl.split(':');
        const fromUrl = parts.length >= 3 ? parts[2] : '';
        const label = node.getAttribute?.('aria-label') ||
          node.getAttribute?.('data-tooltip') ||
          node.getAttribute?.('title') ||
          node.innerText ||
          '';
        const name = (fromUrl || label)
          .replace(/^Download attachment\s*/i, '')
          .replace(/\s+/g, ' ')
          .trim();

        return {
          name,
          type: parts.length >= 2 ? parts[1] : '',
        };
      })
      .filter((item) => item.name)
      .filter((item) => {
        const key = `${item.name}|${item.type}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      })
      .slice(0, 12);
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
    const attachments = getAttachments();

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
      attachments,
      headers,
      signature: `${document.location.href}|${subject}|${senderEmail}|${body.slice(0, 160)}`,
    };
  }

  function getPanelTargetRect() {
    const target = document.querySelector('.a3s.aiL') ||
      document.querySelector('.ii.gt') ||
      document.querySelector('[data-message-id] .a3s');
    return target?.getBoundingClientRect() || document.querySelector('[role="main"]')?.getBoundingClientRect();
  }

  function positionPanel(panel) {
    const rect = getPanelTargetRect();
    if (!rect) return;

    const width = Math.min(380, Math.max(300, rect.width * 0.46), window.innerWidth - 32);
    const left = Math.max(16, Math.min(rect.right - width - 12, window.innerWidth - width - 16));
    const top = Math.max(76, rect.top + 8);

    panel.style.setProperty('--pg-overlay-left', `${left}px`);
    panel.style.setProperty('--pg-overlay-top', `${top}px`);
    panel.style.setProperty('--pg-overlay-width', `${width}px`);
  }

  function positionExistingPanel() {
    const panel = document.getElementById(PANEL_ID);
    if (panel) positionPanel(panel);
  }

  function getPanel() {
    let panel = document.getElementById(PANEL_ID);
    if (!panel) {
      panel = document.createElement('section');
      panel.id = PANEL_ID;
      document.body.appendChild(panel);
    }
    positionPanel(panel);
    return panel;
  }

  function bindPanelButtons(panel) {
    panel.querySelector('[data-pg-close]')?.addEventListener('click', () => panel.remove());
    panel.querySelector('[data-pg-details]')?.addEventListener('click', (event) => {
      const details = panel.querySelector('.phishguard-details');
      const isOpen = details?.classList.toggle('open');
      event.currentTarget.textContent = isOpen ? 'Hide' : 'Details';
      event.currentTarget.setAttribute('aria-expanded', String(Boolean(isOpen)));
    });
  }

  function renderLoading(email) {
    const panel = getPanel();
    panel.innerHTML = `
      <div class="phishguard-banner">
        <div class="pg-banner-left">
          <span class="pg-dot safe"></span>
          <span class="pg-risk-label">Analysing</span>
          <span class="pg-divider">|</span>
          <span class="pg-summary">Checking ${escapeHTML(email.subject || 'current email')}</span>
        </div>
        <div class="pg-banner-actions">
          <button class="pg-close-btn" type="button" data-pg-close aria-label="Close">×</button>
        </div>
      </div>
    `;
    bindPanelButtons(panel);
  }

  function renderError(message) {
    const panel = getPanel();
    panel.innerHTML = `
      <div class="phishguard-banner">
        <div class="pg-banner-left">
          <span class="pg-dot high"></span>
          <span class="pg-risk-label">Unavailable</span>
          <span class="pg-divider">|</span>
          <span class="pg-summary">${escapeHTML(message)}</span>
        </div>
        <div class="pg-banner-actions">
          <button class="pg-close-btn" type="button" data-pg-close aria-label="Close">×</button>
        </div>
      </div>
    `;
    bindPanelButtons(panel);
  }

  function authStatus(label, value) {
    const normalized = String(value || 'UNKNOWN').toUpperCase();
    const cls = normalized === 'PASS'
      ? 'pass'
      : normalized === 'FAIL'
        ? 'fail'
        : 'unknown';
    return `
      <div class="pg-auth-row">
        <span>${escapeHTML(label)}</span>
        <span class="pg-status ${cls}">${escapeHTML(normalized)}</span>
      </div>
    `;
  }

  function riskDotClass(level) {
    if (level === 'high') return 'high';
    if (level === 'medium') return 'medium';
    return 'safe';
  }

  function riskLabel(level) {
    if (level === 'high') return 'High Risk';
    if (level === 'medium') return 'Medium Risk';
    return 'Low Risk';
  }

  function renderResult(data, email) {
    const risk = data?.risk || {};
    const ml = data?.ml || {};
    const hdr = data?.headers || {};
    const ip = data?.ip || {};
    const links = data?.links || {};
    const intent = data?.intent || {};
    const prompt = data?.prompt_injection || {};
    const tracking = data?.tracking_pixels || {};
    const attachments = data?.attachments || {};
    const aiExplanation = data?.ai_explanation || {};
    const level = String(risk.level || 'LOW').toLowerCase();
    const score = Math.min(Math.max(Number(risk.score || 0), 0), 100);
    const suspiciousLinks = Array.isArray(links.suspicious_links) ? links.suspicious_links.length : 0;
    const flags = Array.isArray(risk.flags) ? risk.flags : [];
    const originPrimary = ip.ip
      ? `${ip.city || 'Unknown'}, ${ip.country || 'Unknown'}`
      : (email.senderDomain || hdr.sender_domain || 'Unknown domain');
    const originSecondary = ip.ip ? `IP ${ip.ip}` : `Domain ${email.senderDomain || hdr.sender_domain || '-'}`;
    const promptRisk = prompt.risk || 'NONE';
    const trackingCount = Array.isArray(tracking.tracking_pixels) ? tracking.tracking_pixels.length : 0;
    const riskyAttachmentCount = Array.isArray(attachments.risky_attachments) ? attachments.risky_attachments.length : 0;
    const aiProviderLabel = aiExplanation.enabled
      ? `${aiExplanation.provider || 'AI'} · ${aiExplanation.model || 'model'}`
      : 'Local explanation';
    const aiFlags = Array.isArray(aiExplanation.red_flags) ? aiExplanation.red_flags : [];
    const summaryParts = [
      `${ml.label || 'Unknown'} · ${ml.confidence ?? 0}% confidence`,
      ip.is_vpn_proxy ? 'VPN detected' : (originSecondary || 'Origin checked'),
      `${links.total_links ?? 0} links · ${suspiciousLinks} suspicious`,
    ];
    const aiText = [
      aiExplanation.summary,
      aiFlags.length ? `Key signs: ${aiFlags.slice(0, 3).join('; ')}` : '',
      aiExplanation.recommended_action,
    ].filter(Boolean).join(' ');
    const signalText = [
      `${trackingCount} likely tracking pixel(s)`,
      `${attachments.total_attachments ?? email.attachments?.length ?? 0} attachment(s)`,
      `${riskyAttachmentCount} risky attachment(s)`,
    ].join(' · ');
    const linksText = suspiciousLinks
      ? `${links.total_links ?? 0} total · ${suspiciousLinks} suspicious - Review before clicking`
      : `${links.total_links ?? 0} total · no suspicious link pattern found`;

    const panel = getPanel();
    panel.innerHTML = `
      <div class="phishguard-banner">
        <div class="pg-banner-left">
          <span class="pg-dot ${riskDotClass(level)}"></span>
          <span class="pg-risk-label">${escapeHTML(riskLabel(level))}</span>
          <span class="pg-divider">|</span>
          <span class="pg-summary">${escapeHTML(summaryParts.join(' · '))}</span>
        </div>
        <div class="pg-banner-actions">
          <button class="pg-details-btn" type="button" data-pg-details aria-expanded="false">Details</button>
          <button class="pg-close-btn" type="button" data-pg-close aria-label="Close">×</button>
        </div>
      </div>

      <div class="phishguard-details">
        <div class="pg-details-grid">
          <div class="pg-detail-card">
            <p class="pg-col-label">Detection</p>
            <p class="pg-col-value">${escapeHTML(ml.label || 'Unknown')}</p>
            <p class="pg-col-sub">${escapeHTML(ml.confidence ?? 0)}% confidence · score ${escapeHTML(score)}/100</p>
            <div class="pg-confidence-track">
              <div class="pg-confidence-fill" style="width:${score}%"></div>
            </div>
          </div>

          <div class="pg-detail-card">
            <p class="pg-col-label">Authentication</p>
            <div class="pg-auth-list">
              ${authStatus('SPF', hdr.spf)}
              ${authStatus('DKIM', hdr.dkim)}
              ${authStatus('DMARC', hdr.dmarc)}
            </div>
          </div>

          <div class="pg-detail-card">
            <p class="pg-col-label">Origin</p>
            <p class="pg-col-value">${escapeHTML(originPrimary)}</p>
            <p class="pg-col-sub">${escapeHTML(originSecondary)} · ${escapeHTML(ip.isp || email.senderDomain || 'Unknown')}</p>
            ${ip.is_vpn_proxy ? '<span class="pg-tag">VPN / Proxy</span>' : ''}
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">Links</p>
            <p class="pg-col-sub">${escapeHTML(linksText)}</p>
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">Signals</p>
            <p class="pg-col-sub">${escapeHTML(signalText)}</p>
            <p class="pg-col-sub">${escapeHTML(intent.goal || 'No clear malicious goal detected')} · prompt check ${escapeHTML(promptRisk)}</p>
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">Analysis · ${escapeHTML(aiProviderLabel)}</p>
            <p class="pg-analysis-text">${escapeHTML(aiText || flags.slice(0, 3).join(' ') || 'No explanation returned.')}</p>
          </div>
        </div>
      </div>
    `;

    bindPanelButtons(panel);
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

  async function storeThreatHistory(email, data) {
    try {
      const key = 'phishguard_threat_history_v1';
      const current = await chrome.storage.local.get(key);
      const history = Array.isArray(current[key]) ? current[key] : [];
      const risk = data?.risk || {};
      const tracking = data?.tracking_pixels || {};
      const attachments = data?.attachments || {};
      const next = [{
        scannedAt: new Date().toISOString(),
        subject: email.subject || '(No subject)',
        senderEmail: email.senderEmail || '',
        senderDomain: email.senderDomain || '',
        level: risk.level || 'LOW',
        score: risk.score || 0,
        flags: (risk.flags || []).slice(0, 4),
        trackingPixels: (tracking.tracking_pixels || []).length,
        riskyAttachments: (attachments.risky_attachments || []).length,
      }, ...history].slice(0, 50);
      await chrome.storage.local.set({ [key]: next });
    } catch {
      // History is thesis evidence, but scanning should still work if storage fails.
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
          attachments: email.attachments,
        }),
      });
      if (!response.ok) throw new Error(`Backend returned ${response.status}`);

      const data = await response.json();
      if (scanId !== currentScanId) return;

      renderResult(data, email);
      updateStats(data);
      storeThreatHistory(email, data);
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
      if (getSubjectEl()) {
        positionExistingPanel();
        scheduleScan();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('resize', positionExistingPanel, { passive: true });
    window.addEventListener('scroll', positionExistingPanel, { passive: true, capture: true });
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
