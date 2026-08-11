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
  const THREAT_HISTORY_KEY = 'phishguard_threat_history_v1';
  const THESIS_EVIDENCE_KEY = 'phishguard_thesis_evidence_v1';
  const FEEDBACK_DATASET_KEY = 'phishguard_feedback_dataset_v1';
  const MAX_EVIDENCE_ITEMS = 150;
  const MAX_FEEDBACK_ITEMS = 500;

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

  function buildTrainingText(email) {
    return [
      `Subject: ${email.subject || ''}`,
      `From: ${email.senderEmail || ''}`,
      '',
      email.body || '',
    ].join('\n').trim();
  }

  function normaliseHref(href) {
    try {
      const url = new URL(href);
      const host = url.hostname.replace(/^www\./, '').toLowerCase();
      const redirected = url.searchParams.get('q') || url.searchParams.get('url');
      if (redirected && (host === 'google.com' || host === 'mail.google.com')) {
        return redirected;
      }
    } catch {
      return href;
    }
    return href;
  }

  async function getGmailApiHeaders(email, interactive = false) {
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'PG_GMAIL_HEADERS',
        email: {
          subject: email.subject,
          senderEmail: email.senderEmail,
          senderDomain: email.senderDomain,
        },
        interactive,
      });
      if (response?.ok && response.rawHeaders) return response;
      return response || { ok: false, reason: 'Gmail API headers unavailable.' };
    } catch (error) {
      return { ok: false, reason: error.message };
    }
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
    const visibleBody = bodyEl ? bodyEl.innerText.trim() : '';
    const bodyHtml = bodyEl ? bodyEl.innerHTML : '';
    const bodyLinks = bodyEl
      ? [...new Set([...bodyEl.querySelectorAll('a[href]')]
          .map((anchor) => normaliseHref(anchor.href))
          .filter((href) => /^https?:\/\//i.test(href)))]
      : [];
    const body = bodyLinks.length
      ? `${visibleBody}\n\nExtracted links:\n${bodyLinks.join('\n')}`
      : visibleBody;

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

  async function getSenderVerdictHistory(email) {
    try {
      const current = await chrome.storage.local.get(THREAT_HISTORY_KEY);
      const history = Array.isArray(current[THREAT_HISTORY_KEY]) ? current[THREAT_HISTORY_KEY] : [];
      const senderEmail = String(email.senderEmail || '').trim().toLowerCase();
      const senderDomain = String(email.senderDomain || '').trim().toLowerCase();

      return history
        .filter((item) => {
          const itemEmail = String(item.senderEmail || '').trim().toLowerCase();
          const itemDomain = String(item.senderDomain || '').trim().toLowerCase();
          return (senderEmail && itemEmail === senderEmail) || (senderDomain && itemDomain === senderDomain);
        })
        .slice(0, 3)
        .map((item) => ({
          level: item.level || 'LOW',
          score: item.score || 0,
          scannedAt: item.scannedAt || '',
        }));
    } catch {
      return [];
    }
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

  function setFeedbackStatus(message, tone = 'ok') {
    const panel = document.getElementById(PANEL_ID);
    const feedbackStatus = panel?.querySelector('[data-pg-feedback-status]');
    if (!feedbackStatus) return;
    feedbackStatus.className = `pg-feedback-status ${tone}`;
    feedbackStatus.textContent = message;
  }

  async function storeFeedback(email, label, source = 'gmail_panel') {
    try {
      const current = await chrome.storage.local.get(FEEDBACK_DATASET_KEY);
      const feedbackRows = Array.isArray(current[FEEDBACK_DATASET_KEY]) ? current[FEEDBACK_DATASET_KEY] : [];
      const text = buildTrainingText(email);
      if (!text) {
        setFeedbackStatus('Could not save feedback because no email text was captured.', 'error');
        return;
      }

      const nextRows = [{
        createdAt: new Date().toISOString(),
        source: `feedback:${source}`,
        text,
        label,
        senderEmail: email.senderEmail || '',
        senderDomain: email.senderDomain || '',
        subject: email.subject || '',
      }, ...feedbackRows].slice(0, MAX_FEEDBACK_ITEMS);

      await chrome.storage.local.set({ [FEEDBACK_DATASET_KEY]: nextRows });
      const kind = label === 0 ? 'hard negative / safe' : 'hard positive / phishing';
      setFeedbackStatus(`Saved ${kind} example. Feedback rows: ${nextRows.length}.`, 'ok');
    } catch (error) {
      setFeedbackStatus(`Could not save feedback: ${error.message || 'storage error'}.`, 'error');
    }
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
    const cls = valueClass(normalized);
    return `
      <div class="pg-auth-row">
        <span>${escapeHTML(label)}</span>
        <span class="pg-status ${cls}">${escapeHTML(normalized)}</span>
      </div>
    `;
  }

  function valueClass(value) {
    const normalized = String(value || '').trim().toUpperCase();
    if (normalized === 'NONE') return 'none';
    if (normalized === 'UNKNOWN') return 'unknown';
    if (normalized === 'PASS') return 'pass';
    if (normalized === 'FAIL' || normalized === 'HIGH') return 'fail';
    return '';
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
    const fusion = risk.fusion || {};
    const fusionSignals = fusion.signals || {};
    const vsr = fusion.vsr || {};
    const uncertainty = risk.uncertainty || {};
    const counterfactuals = Array.isArray(risk.counterfactuals) ? risk.counterfactuals : [];
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
    const fusionText = Object.entries(fusionSignals).length
      ? Object.entries(fusionSignals).map(([name, signal]) => {
          const weight = Math.round((signal.adaptive_weight || 0) * 100);
          const scoreValue = Math.round((signal.score || 0) * 100);
          return `${signal.label || name}: ${weight}% weight, ${scoreValue}% risk`;
        }).join(' · ')
      : 'CWAF signal evidence unavailable';
    const counterfactualText = counterfactuals.length
      ? counterfactuals.slice(0, 3).map((item) => `${item.action} (-${item.risk_reduction || 0}, new ${item.new_score || score}/100)`).join(' · ')
      : 'No counterfactual explanation returned';
    const uncertaintyText = `${uncertainty.evidence_completeness ?? 0}% evidence complete · ${uncertainty.level || 'UNKNOWN'} uncertainty`;

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
            <p class="pg-col-sub">${escapeHTML(intent.goal || 'No clear malicious goal detected')} · prompt check <span class="pg-inline-value ${valueClass(promptRisk)}">${escapeHTML(promptRisk)}</span></p>
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">CWAF fusion</p>
            <p class="pg-col-sub">${escapeHTML(fusion.algorithm || 'CWAF+VSR')} · core ${escapeHTML(fusion.core_score ?? score)}/100 · auxiliary +${escapeHTML(fusion.auxiliary_adjustment ?? 0)}</p>
            <p class="pg-col-sub">${escapeHTML(fusionText)}</p>
            <p class="pg-col-sub">${escapeHTML(vsr.reason || 'No sender-history stability change applied.')}</p>
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">Counterfactuals</p>
            <p class="pg-col-sub">${escapeHTML(counterfactualText)}</p>
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">Uncertainty</p>
            <p class="pg-col-sub">${escapeHTML(uncertaintyText)}</p>
            <p class="pg-col-sub">${escapeHTML((uncertainty.reasons || []).slice(0, 2).join(' · ') || 'No uncertainty reason returned.')}</p>
          </div>

          <div class="pg-detail-card pg-detail-wide">
            <p class="pg-col-label">Analysis · ${escapeHTML(aiProviderLabel)}</p>
            <p class="pg-analysis-text">${escapeHTML(aiText || flags.slice(0, 3).join(' ') || 'No explanation returned.')}</p>
          </div>

          <div class="pg-feedback-actions">
            <button type="button" data-pg-feedback="safe">Mark safe</button>
            <button type="button" data-pg-feedback="phishing">Mark phishing</button>
          </div>
          <div class="pg-feedback-status" data-pg-feedback-status></div>
        </div>
      </div>
    `;

    bindPanelButtons(panel);
    panel.querySelector('[data-pg-feedback="safe"]')?.addEventListener('click', () => storeFeedback(email, 0));
    panel.querySelector('[data-pg-feedback="phishing"]')?.addEventListener('click', () => storeFeedback(email, 1));
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
      const current = await chrome.storage.local.get(THREAT_HISTORY_KEY);
      const history = Array.isArray(current[THREAT_HISTORY_KEY]) ? current[THREAT_HISTORY_KEY] : [];
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
      await chrome.storage.local.set({ [THREAT_HISTORY_KEY]: next });
    } catch {
      // History is thesis evidence, but scanning should still work if storage fails.
    }
  }

  async function storeThesisEvidence(email, data) {
    try {
      const current = await chrome.storage.local.get(THESIS_EVIDENCE_KEY);
      const evidence = Array.isArray(current[THESIS_EVIDENCE_KEY]) ? current[THESIS_EVIDENCE_KEY] : [];
      const risk = data?.risk || {};
      const fusion = risk.fusion || {};
      const uncertainty = risk.uncertainty || {};
      const signals = fusion.signals || {};
      const record = {
        scannedAt: new Date().toISOString(),
        source: 'gmail_panel',
        subjectLength: String(email.subject || '').length,
        bodyLength: String(email.body || '').length,
        senderDomain: email.senderDomain || '',
        verdict: risk.level || 'LOW',
        score: risk.score || 0,
        algorithm: fusion.algorithm || 'CWAF+VSR',
        coreScore: fusion.core_score ?? null,
        auxiliaryAdjustment: fusion.auxiliary_adjustment ?? null,
        uncertaintyLevel: uncertainty.level || 'UNKNOWN',
        evidenceCompleteness: uncertainty.evidence_completeness ?? null,
        vsrApplied: Boolean(fusion.vsr?.applied),
        signalWeights: Object.fromEntries(Object.entries(signals).map(([name, signal]) => [
          name,
          {
            score: signal.score,
            confidence: signal.confidence,
            adaptiveWeight: signal.adaptive_weight,
          },
        ])),
        counterfactuals: (risk.counterfactuals || []).slice(0, 3).map((item) => ({
          action: item.action,
          riskReduction: item.risk_reduction,
          newScore: item.new_score,
        })),
      };
      await chrome.storage.local.set({
        [THESIS_EVIDENCE_KEY]: [record, ...evidence].slice(0, MAX_EVIDENCE_ITEMS),
      });
    } catch {
      // Thesis logging should never block the Gmail panel.
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
      const senderHistory = await getSenderVerdictHistory(email);
      const gmailApiHeaders = await getGmailApiHeaders(email, false);
      const headers = gmailApiHeaders?.ok
        ? `${gmailApiHeaders.rawHeaders}\nX-PhishGuard-Header-Source: gmail_api`
        : `${email.headers}\nX-PhishGuard-Header-Source: gmail_dom\nX-PhishGuard-Gmail-Api-Status: ${gmailApiHeaders?.reason || 'unavailable'}`;
      const response = await fetch(BACKEND_ANALYSE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: email.subject,
          body: email.body,
          body_html: email.body_html,
          headers,
          senderEmail: email.senderEmail,
          senderDomain: email.senderDomain,
          attachments: email.attachments,
          senderHistory,
        }),
      });
      if (!response.ok) throw new Error(`Backend returned ${response.status}`);

      const data = await response.json();
      if (scanId !== currentScanId) return;

      renderResult(data, email);
      updateStats(data);
      storeThreatHistory(email, data);
      storeThesisEvidence(email, data);
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
