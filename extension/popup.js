const BACKEND_ANALYSE_URL = 'http://127.0.0.1:5001/analyse';
const BACKEND_HEALTH_URL = 'http://127.0.0.1:5001/health';
const SENDER_MEMORY_KEY = 'phishguard_sender_memory_v1';
const THREAT_HISTORY_KEY = 'phishguard_threat_history_v1';
const THESIS_EVIDENCE_KEY = 'phishguard_thesis_evidence_v1';
const FEEDBACK_DATASET_KEY = 'phishguard_feedback_dataset_v1';
const MAX_DOMAINS_PER_SENDER = 24;
const MAX_HISTORY_ITEMS = 50;
const MAX_EVIDENCE_ITEMS = 150;
const MAX_FEEDBACK_ITEMS = 500;

const backendStatus = document.getElementById('backend-status');
const statusText = document.getElementById('status-text');
const scanButton = document.getElementById('scan-btn');
const panelButton = document.getElementById('panel-btn');
const clearButton = document.getElementById('clear-btn');
const evidenceButton = document.getElementById('evidence-btn');
const gmailButton = document.getElementById('gmail-btn');
const result = document.getElementById('result');

function escapeHTML(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function setBackendStatus(state, label) {
  backendStatus.className = `pill ${state}`;
  backendStatus.querySelector('span:last-child').textContent = label;
}

function setBusy(isBusy) {
  scanButton.disabled = isBusy;
  panelButton.disabled = isBusy;
  clearButton.disabled = isBusy;
  evidenceButton.disabled = isBusy;
}

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function setStatGauge(className, value, maxValue) {
  const node = document.querySelector(`.stat.${className}`);
  if (!node) return;
  const max = Math.max(Number(maxValue) || 1, 1);
  const percent = Math.max(0, Math.min(100, Math.round(((Number(value) || 0) / max) * 100)));
  node.style.setProperty('--gauge', percent);
}

function setSignal(id, value, color) {
  const percent = Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
  const fill = document.getElementById(`rail-${id}`);
  if (fill) {
    fill.style.setProperty('--value', `${percent}%`);
    if (color) fill.style.setProperty('--color', color);
  }
  setText(`rail-${id}-value`, `${percent}%`);
}

function formatHeaderSource(source) {
  const value = String(source || '').toLowerCase();
  if (value === 'gmail_api') return 'Gmail API';
  if (value === 'gmail_dom') return 'Gmail view';
  return '--';
}

function getDomain(value) {
  try {
    const cleanValue = String(value || '').trim();
    if (!cleanValue) return '';
    if (cleanValue.includes('@') && !cleanValue.startsWith('http')) {
      return cleanValue.split('@').pop().toLowerCase();
    }
    return new URL(cleanValue.startsWith('http') ? cleanValue : `https://${cleanValue}`).hostname
      .replace(/^www\./, '')
      .toLowerCase();
  } catch {
    return '';
  }
}

function extractUrls(text) {
  return String(text || '').match(/https?:\/\/[^\s<>"'{}|\\^`\[\]]+/g) || [];
}

function getLinkDomains(email) {
  return [...new Set(extractUrls(email?.body || '').map(getDomain).filter(Boolean))];
}

function senderKey(email) {
  return String(email?.senderEmail || '').trim().toLowerCase() || getDomain(email?.senderEmail);
}

function buildTrainingText(email) {
  return [
    `Subject: ${email.subject || ''}`,
    `From: ${email.senderEmail || ''}`,
    '',
    email.body || '',
  ].join('\n').trim();
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
    if (response?.ok && response.rawHeaders) {
      return response;
    }
    return response || { ok: false, reason: 'Gmail API headers unavailable.' };
  } catch (error) {
    return { ok: false, reason: error.message };
  }
}

async function getSenderMemory() {
  const data = await chrome.storage.local.get(SENDER_MEMORY_KEY);
  return data[SENDER_MEMORY_KEY] || {};
}

async function saveSenderMemory(memory) {
  await chrome.storage.local.set({ [SENDER_MEMORY_KEY]: memory });
}

function compareSenderMemory(memory, email) {
  const key = senderKey(email);
  const profile = key ? memory[key] : null;
  const currentDomains = getLinkDomains(email);
  const currentSenderName = String(email?.senderName || '').trim();

  if (!key || !profile) {
    return {
      status: 'new',
      title: 'New sender profile',
      notes: ['PhishGuard will learn this sender locally after this scan.'],
      currentDomains,
    };
  }

  const knownDomains = profile.linkDomains || [];
  const newDomains = currentDomains.filter((domain) => !knownDomains.includes(domain));
  const notes = [];

  if (newDomains.length) notes.push(`New link domain for this sender: ${newDomains.join(', ')}`);
  if (profile.senderName && currentSenderName && profile.senderName !== currentSenderName) {
    notes.push(`Sender display name changed from "${profile.senderName}" to "${currentSenderName}".`);
  }
  if (!currentDomains.length && knownDomains.length) {
    notes.push('This email contains no visible links, unlike earlier messages from this sender.');
  }

  return {
    status: notes.length ? 'changed' : 'familiar',
    title: notes.length ? 'Sender pattern changed' : 'Sender looks familiar',
    notes: notes.length ? notes : [`Seen ${profile.scanCount || 1} time(s) before with no unusual sender-pattern changes.`],
    currentDomains,
  };
}

async function updateSenderMemory(memory, email) {
  const key = senderKey(email);
  if (!key) return;

  const existing = memory[key] || {
    firstSeen: new Date().toISOString(),
    scanCount: 0,
    linkDomains: [],
  };

  memory[key] = {
    ...existing,
    senderEmail: email.senderEmail || existing.senderEmail || '',
    senderName: email.senderName || existing.senderName || '',
    senderDomain: email.senderDomain || getDomain(email.senderEmail) || existing.senderDomain || '',
    linkDomains: [...new Set([...existing.linkDomains, ...getLinkDomains(email)])].slice(-MAX_DOMAINS_PER_SENDER),
    scanCount: (existing.scanCount || 0) + 1,
    lastSeen: new Date().toISOString(),
  };

  await saveSenderMemory(memory);
}

async function updateScanStats(data) {
  const current = await chrome.storage.local.get(['scanned', 'threats', 'safe']);
  const level = data?.risk?.level || 'LOW';
  await chrome.storage.local.set({
    scanned: (current.scanned || 0) + 1,
    threats: (current.threats || 0) + (level === 'HIGH' ? 1 : 0),
    safe: (current.safe || 0) + (level === 'LOW' ? 1 : 0),
  });
  loadStats();
}

async function loadStats() {
  const data = await chrome.storage.local.get(['scanned', 'threats', 'safe', THREAT_HISTORY_KEY, THESIS_EVIDENCE_KEY, FEEDBACK_DATASET_KEY]);
  const scanned = data.scanned ?? 0;
  const threats = data.threats ?? 0;
  const safe = data.safe ?? 0;
  setText('stat-scanned', scanned);
  setText('stat-threats', threats);
  setText('stat-safe', safe);
  setText('rail-scanned', scanned);
  setText('rail-threats', threats);
  setText('rail-safe', safe);

  const evidenceCount = Array.isArray(data[THESIS_EVIDENCE_KEY]) ? data[THESIS_EVIDENCE_KEY].length : 0;
  const feedbackCount = Array.isArray(data[FEEDBACK_DATASET_KEY]) ? data[FEEDBACK_DATASET_KEY].length : 0;
  const totalEvidence = evidenceCount + feedbackCount;
  setText('stat-evidence', evidenceCount + feedbackCount);
  setText('rail-evidence', evidenceCount);
  setText('rail-feedback', feedbackCount);

  const gaugeMax = Math.max(scanned, threats, safe, totalEvidence, 1);
  setStatGauge('scanned', scanned, gaugeMax);
  setStatGauge('threats', threats, gaugeMax);
  setStatGauge('safe', safe, gaugeMax);
  setStatGauge('evidence', totalEvidence, gaugeMax);

  const history = Array.isArray(data[THREAT_HISTORY_KEY]) ? data[THREAT_HISTORY_KEY] : [];
  renderHistory(history);
  renderRailHistory(history);
}

async function storeThreatHistory(email, data) {
  const current = await chrome.storage.local.get(THREAT_HISTORY_KEY);
  const history = Array.isArray(current[THREAT_HISTORY_KEY]) ? current[THREAT_HISTORY_KEY] : [];
  const risk = data?.risk || {};
  const tracking = data?.tracking_pixels || {};
  const attachments = data?.attachments || {};
  const next = [{
    scannedAt: new Date().toISOString(),
    subject: email.subject || '(No subject)',
    senderEmail: email.senderEmail || '',
    senderDomain: email.senderDomain || getDomain(email.senderEmail),
    level: risk.level || 'LOW',
    score: risk.score || 0,
    flags: (risk.flags || []).slice(0, 4),
    trackingPixels: (tracking.tracking_pixels || []).length,
    riskyAttachments: (attachments.risky_attachments || []).length,
  }, ...history].slice(0, MAX_HISTORY_ITEMS);
  await chrome.storage.local.set({ [THREAT_HISTORY_KEY]: next });
  renderHistory(next);
  renderRailHistory(next);
}

async function storeThesisEvidence(email, data, memoryInsight) {
  const current = await chrome.storage.local.get(THESIS_EVIDENCE_KEY);
  const evidence = Array.isArray(current[THESIS_EVIDENCE_KEY]) ? current[THESIS_EVIDENCE_KEY] : [];
  const risk = data?.risk || {};
  const fusion = risk.fusion || {};
  const uncertainty = risk.uncertainty || {};
  const signals = fusion.signals || {};

  const record = {
    scannedAt: new Date().toISOString(),
    subjectLength: String(email.subject || '').length,
    bodyLength: String(email.body || '').length,
    senderDomain: email.senderDomain || getDomain(email.senderEmail),
    linkDomainCount: getLinkDomains(email).length,
    verdict: risk.level || 'LOW',
    score: risk.score || 0,
    algorithm: fusion.algorithm || 'CWAF+VSR',
    coreScore: fusion.core_score ?? null,
    auxiliaryAdjustment: fusion.auxiliary_adjustment ?? null,
    uncertaintyLevel: uncertainty.level || 'UNKNOWN',
    evidenceCompleteness: uncertainty.evidence_completeness ?? null,
    vsrApplied: Boolean(fusion.vsr?.applied),
    senderMemoryStatus: memoryInsight?.status || 'unknown',
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
}

async function getSenderVerdictHistory(email) {
  const current = await chrome.storage.local.get(THREAT_HISTORY_KEY);
  const history = Array.isArray(current[THREAT_HISTORY_KEY]) ? current[THREAT_HISTORY_KEY] : [];
  const key = senderKey(email);
  const domain = email.senderDomain || getDomain(email.senderEmail);

  return history
    .filter((item) => {
      const itemEmail = String(item.senderEmail || '').trim().toLowerCase();
      const itemDomain = String(item.senderDomain || '').trim().toLowerCase();
      return (key && itemEmail === key) || (domain && itemDomain === domain);
    })
    .slice(0, 3)
    .map((item) => ({
      level: item.level || 'LOW',
      score: item.score || 0,
      scannedAt: item.scannedAt || '',
    }));
}

function renderHistory(history) {
  const container = document.getElementById('history-list');
  const summary = document.getElementById('history-summary');
  if (!container || !summary) return;

  const high = history.filter((item) => item.level === 'HIGH').length;
  const medium = history.filter((item) => item.level === 'MEDIUM').length;
  const low = history.filter((item) => item.level === 'LOW').length;
  summary.textContent = `${history.length} saved scans · ${high} high · ${medium} medium · ${low} low`;

  if (!history.length) {
    container.innerHTML = '<div class="empty-history">No scan evidence saved yet.</div>';
    return;
  }

  container.innerHTML = history.slice(0, 5).map((item) => {
    const levelClass = String(item.level || 'LOW').toLowerCase();
    const scannedAt = item.scannedAt ? new Date(item.scannedAt).toLocaleString() : 'Unknown time';
    return `
      <div class="history-item ${levelClass}">
        <div>
          <strong>${escapeHTML(item.subject)}</strong>
          <span>${escapeHTML(item.senderEmail || item.senderDomain || 'Unknown sender')}</span>
          <span>${escapeHTML(scannedAt)}</span>
        </div>
        <div class="history-score">
          <b>${escapeHTML(item.score)}/100</b>
          <span>${escapeHTML(item.level)}</span>
          <small>${escapeHTML(item.trackingPixels || 0)} px · ${escapeHTML(item.riskyAttachments || 0)} att</small>
        </div>
      </div>
    `;
  }).join('');
}

function renderRailHistory(history) {
  const container = document.getElementById('rail-verdicts');
  if (!container) return;

  setText('rail-history-count', history.length);

  if (!history.length) {
    container.innerHTML = '<div class="capsule"><i></i><b>No scans yet</b><span>--</span></div>';
    return;
  }

  container.innerHTML = history.slice(0, 4).map((item) => {
    const level = String(item.level || 'LOW').toLowerCase();
    const label = item.level || 'LOW';
    const title = item.subject || item.senderDomain || 'Email scan';
    return `
      <div class="capsule ${escapeHTML(level)}">
        <i></i>
        <b>${escapeHTML(title)}</b>
        <span>${escapeHTML(label)}</span>
      </div>
    `;
  }).join('');
}

function renderRailLatestResult(data) {
  const risk = data?.risk || {};
  const hdr = data?.headers || {};
  const signals = risk?.fusion?.signals || {};
  const level = String(risk.level || 'LOW').toUpperCase();
  const levelColor = level === 'HIGH' ? '#ff4d6a' : level === 'MEDIUM' ? '#ffb020' : '#34d399';
  const passCount = [hdr.spf, hdr.dkim, hdr.dmarc]
    .filter((value) => String(value || '').toUpperCase() === 'PASS')
    .length;

  setText('rail-risk-label', `${level} ${risk.score ?? 0}/100`);
  setText('rail-header-source', formatHeaderSource(hdr.header_source));
  setText('rail-auth-pass', `${passCount}/3`);

  setSignal('nlp', (signals.nlp?.score || 0) * 100, levelColor);
  setSignal('auth', (signals.header?.confidence || 0) * 100, '#34d399');
  setSignal('ip', (signals.ip?.score || 0) * 100, '#8b6bff');
  setSignal('url', (signals.url?.score || 0) * 100, '#ffb020');
}

function buildVerificationPlan(email, data, memoryInsight) {
  const senderDomain = email?.senderDomain || getDomain(email?.senderEmail);
  const linkDomains = memoryInsight.currentDomains || [];
  const suspiciousLinks = data?.links?.suspicious_links || [];
  const steps = [];

  steps.push(senderDomain
    ? `Verify by visiting ${senderDomain} manually or using a saved bookmark.`
    : 'Verify through a known official website, not through this email.');
  if (linkDomains.length) steps.push(`Treat these domains carefully: ${linkDomains.slice(0, 3).join(', ')}.`);
  if (suspiciousLinks.length) steps.push('Avoid suspicious or shortened links in this message.');
  steps.push('Use a separate trusted channel before sending payment, password, identity, or code details.');
  return steps;
}

async function checkBackend() {
  try {
    const res = await fetch(BACKEND_HEALTH_URL, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) throw new Error('Health check failed');
    setBackendStatus('online', 'Online');
    statusText.textContent = 'Backend connected. Ready to scan Gmail.';
  } catch {
    setBackendStatus('offline', 'Offline');
    statusText.textContent = 'Backend offline. Start Flask before scanning.';
  }
}

async function getActiveGmailTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url?.startsWith('https://mail.google.com/')) {
    throw new Error('Open an individual Gmail message first.');
  }
  return tab;
}

async function ensureContentScript(tabId) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'PG_CLEAR_PANELS' });
  } catch {
    await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
  }
}

async function getEmailFromGmail(tabId) {
  await ensureContentScript(tabId);
  const response = await chrome.tabs.sendMessage(tabId, { type: 'PG_GET_EMAIL' });
  if (!response?.ok) throw new Error('Refresh Gmail and try again.');
  return response.email;
}

async function scanEmail() {
  result.innerHTML = '<div class="loading"><span class="spinner"></span>Analysing the selected Gmail message...</div>';
  statusText.textContent = 'Reading Gmail content and available headers.';
  setBusy(true);

  try {
    const tab = await getActiveGmailTab();
    const email = await getEmailFromGmail(tab.id);
    if (!email?.subject && !email?.body) throw new Error('Open an individual email first, not just the inbox list.');
    const senderHistory = await getSenderVerdictHistory(email);
    const gmailApiHeaders = await getGmailApiHeaders(email, true);
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
    if (!response.ok) throw new Error(`Backend returned ${response.status}.`);

    const data = await response.json();
    const memory = await getSenderMemory();
    const memoryInsight = compareSenderMemory(memory, email);
    await updateSenderMemory(memory, email);
    await updateScanStats(data);
    await storeThreatHistory(email, data);
    await storeThesisEvidence(email, data, memoryInsight);
    await loadStats();
    renderResult(data, email, memoryInsight);
    statusText.textContent = 'Scan complete.';
  } catch (err) {
    result.innerHTML = `
      <div class="result">
        <div class="mini">
          <span>Could not scan</span>
          <strong>${escapeHTML(err.message || 'Something went wrong.')}</strong>
        </div>
      </div>
    `;
    statusText.textContent = 'Fix the issue below, then scan again.';
  } finally {
    setBusy(false);
    checkBackend();
  }
}

async function showGmailPanel() {
  setBusy(true);
  try {
    const tab = await getActiveGmailTab();
    await ensureContentScript(tab.id);
    await chrome.tabs.sendMessage(tab.id, { type: 'PG_SCAN_AND_SHOW' });
    statusText.textContent = 'Modern Gmail panel started.';
    setTimeout(() => window.close(), 120);
  } catch (err) {
    statusText.textContent = err.message || 'Could not show Gmail panel.';
  } finally {
    setBusy(false);
  }
}

async function clearGmailPanels() {
  try {
    const tab = await getActiveGmailTab();
    await ensureContentScript(tab.id);
    await chrome.tabs.sendMessage(tab.id, { type: 'PG_CLEAR_PANELS' });
    result.innerHTML = '';
    statusText.textContent = 'Gmail panel removed.';
  } catch {
    statusText.textContent = 'Refresh Gmail once, then try Clean page again.';
  }
}

async function exportEvidence() {
  const data = await chrome.storage.local.get([THESIS_EVIDENCE_KEY, THREAT_HISTORY_KEY, FEEDBACK_DATASET_KEY]);
  const feedbackRows = Array.isArray(data[FEEDBACK_DATASET_KEY]) ? data[FEEDBACK_DATASET_KEY] : [];
  const payload = {
    exportedAt: new Date().toISOString(),
    project: 'PhishGuard-XAI',
    privacyNote: 'Email body text is not included. Records store metadata, signal weights, verdicts, uncertainty, and counterfactual summaries.',
    evidence: Array.isArray(data[THESIS_EVIDENCE_KEY]) ? data[THESIS_EVIDENCE_KEY] : [],
    threatHistory: Array.isArray(data[THREAT_HISTORY_KEY]) ? data[THREAT_HISTORY_KEY] : [],
    labelledFeedbackCount: feedbackRows.length,
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `phishguard-xai-evidence-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 500);

  if (feedbackRows.length) {
    const csvHeader = 'text,label,source,senderDomain,createdAt\n';
    const csvRows = feedbackRows.map((row) => [
      row.text,
      row.label,
      row.source,
      row.senderDomain,
      row.createdAt,
    ].map((value) => `"${String(value ?? '').replace(/"/g, '""')}"`).join(','));
    const csvBlob = new Blob([csvHeader + csvRows.join('\n')], { type: 'text/csv' });
    const csvUrl = URL.createObjectURL(csvBlob);
    const csvLink = document.createElement('a');
    csvLink.href = csvUrl;
    csvLink.download = `phishguard-feedback-training-${new Date().toISOString().slice(0, 10)}.csv`;
    csvLink.click();
    setTimeout(() => URL.revokeObjectURL(csvUrl), 500);
  }

  statusText.textContent = `Exported ${payload.evidence.length} evidence record(s) and ${feedbackRows.length} labelled feedback row(s).`;
}

function setFeedbackStatus(message, tone = 'ok') {
  const feedbackStatus = result.querySelector('[data-feedback-status]');
  if (!feedbackStatus) return;
  feedbackStatus.className = `feedback-note ${tone}`;
  feedbackStatus.textContent = message;
}

async function storeFeedback(email, label, source = 'popup') {
  try {
    const current = await chrome.storage.local.get(FEEDBACK_DATASET_KEY);
    const feedbackRows = Array.isArray(current[FEEDBACK_DATASET_KEY]) ? current[FEEDBACK_DATASET_KEY] : [];
    const text = buildTrainingText(email);
    if (!text) {
      setFeedbackStatus('Could not save feedback because no email text was captured.', 'error');
      return;
    }

    const row = {
      createdAt: new Date().toISOString(),
      source: `feedback:${source}`,
      text,
      label,
      senderEmail: email.senderEmail || '',
      senderDomain: email.senderDomain || getDomain(email.senderEmail),
      subject: email.subject || '',
    };
    const nextRows = [row, ...feedbackRows].slice(0, MAX_FEEDBACK_ITEMS);
    await chrome.storage.local.set({ [FEEDBACK_DATASET_KEY]: nextRows });
    await loadStats();

    const kind = label === 0 ? 'hard negative / safe' : 'hard positive / phishing';
    const message = `Saved ${kind} example. Feedback rows: ${nextRows.length}.`;
    setFeedbackStatus(message, 'ok');
    statusText.textContent = message;
  } catch (error) {
    const message = `Could not save feedback: ${error.message || 'storage error'}.`;
    setFeedbackStatus(message, 'error');
    statusText.textContent = message;
  }
}

function renderResult(data, email, memoryInsight) {
  const risk = data?.risk || {};
  const ml = data?.ml || {};
  const hdr = data?.headers || {};
  const links = data?.links || {};
  const ip = data?.ip || {};
  const intent = data?.intent || {};
  const promptInjection = data?.prompt_injection || {};
  const tracking = data?.tracking_pixels || {};
  const attachments = data?.attachments || {};
  const aiExplanation = data?.ai_explanation || {};
  const fusion = risk.fusion || {};
  const fusionSignals = fusion.signals || {};
  const vsr = fusion.vsr || {};
  const uncertainty = risk.uncertainty || {};
  const counterfactuals = Array.isArray(risk.counterfactuals) ? risk.counterfactuals : [];

  const level = String(risk.level || 'LOW').toLowerCase();
  const scoreClass = level === 'high' ? 'high' : level === 'medium' ? 'medium' : '';
  const flags = Array.isArray(risk.flags) ? risk.flags : [];
  const flagsHTML = flags.length
    ? flags.slice(0, 5).map((flag) => `<li>${escapeHTML(flag)}</li>`).join('')
    : '<li class="ok">No major red flags found.</li>';
  const memoryClass = memoryInsight.status === 'changed' ? 'warn' : memoryInsight.status === 'new' ? 'info' : 'ok';
  const memoryHTML = memoryInsight.notes.map((note) => `<li>${escapeHTML(note)}</li>`).join('');
  const promptFindings = promptInjection.findings || [];
  const promptHTML = promptFindings.length
    ? promptFindings.slice(0, 3).map((finding) => `<li>${escapeHTML(finding)}</li>`).join('')
    : '<li>No hidden AI-instruction patterns detected.</li>';
  const trackingCount = Array.isArray(tracking.tracking_pixels) ? tracking.tracking_pixels.length : 0;
  const riskyAttachmentCount = Array.isArray(attachments.risky_attachments) ? attachments.risky_attachments.length : 0;
  const verificationHTML = buildVerificationPlan(email, data, memoryInsight)
    .map((step) => `<li>${escapeHTML(step)}</li>`)
    .join('');
  const aiFlags = Array.isArray(aiExplanation.red_flags) ? aiExplanation.red_flags : [];
  const aiFlagsHTML = aiFlags.length
    ? aiFlags.slice(0, 4).map((flag) => `<li>${escapeHTML(flag)}</li>`).join('')
    : '<li>No AI explanation flags available.</li>';
  const aiProviderLabel = aiExplanation.enabled
    ? `${aiExplanation.provider || 'AI'} · ${aiExplanation.model || 'model'}`
    : 'Local explanation';
  const fusionRowsHTML = Object.entries(fusionSignals).length
    ? Object.entries(fusionSignals).map(([name, signal]) => {
        const score = Math.round((signal.score || 0) * 100);
        const confidence = Math.round((signal.confidence || 0) * 100);
        const weight = Math.round((signal.adaptive_weight || 0) * 100);
        return `<li>${escapeHTML(signal.label || name)}: ${escapeHTML(score)}% risk · ${escapeHTML(confidence)}% confidence · ${escapeHTML(weight)}% weight</li>`;
      }).join('')
    : '<li>CWAF signal evidence unavailable.</li>';
  const fusionClass = vsr.applied ? 'warn' : 'info';
  const uncertaintyClass = uncertainty.level === 'HIGH' ? 'warn' : uncertainty.level === 'LOW' ? 'ok' : 'info';
  const uncertaintyHTML = (uncertainty.reasons || [])
    .slice(0, 3)
    .map((reason) => `<li>${escapeHTML(reason)}</li>`)
    .join('') || '<li>Evidence completeness unavailable.</li>';
  const counterfactualHTML = counterfactuals.length
    ? counterfactuals.slice(0, 4).map((item) => `
        <li>
          <b>${escapeHTML(item.action)}</b>
          <small>-${escapeHTML(item.risk_reduction ?? 0)} risk · new score ${escapeHTML(item.new_score ?? risk.score ?? 0)}/100</small>
        </li>
      `).join('')
    : '<li>No counterfactual explanation returned.</li>';

  result.innerHTML = `
    <div class="result">
      <div class="score ${scoreClass}">
        <div>
          <div class="score-label">${escapeHTML(risk.level || 'LOW')} risk</div>
          <div class="score-verdict">${escapeHTML(risk.verdict || 'Analysis complete')}</div>
        </div>
        <div class="score-number">${escapeHTML(risk.score ?? 0)}/100</div>
      </div>

      <div class="metric-grid">
        <div class="mini">
          <span>ML verdict</span>
          <strong>${escapeHTML(ml.label || 'Unknown')} · ${escapeHTML(ml.confidence ?? 0)}%</strong>
        </div>
        <div class="mini">
          <span>Origin</span>
          <strong>${escapeHTML(ip.ip || email.senderDomain || 'No IP')} · ${escapeHTML(ip.country || 'Unknown')}</strong>
        </div>
        <div class="mini">
          <span>Auth</span>
          <strong>SPF ${escapeHTML(hdr.spf || 'UNKNOWN')} · DKIM ${escapeHTML(hdr.dkim || 'UNKNOWN')} · DMARC ${escapeHTML(hdr.dmarc || 'UNKNOWN')}</strong>
        </div>
        <div class="mini">
          <span>Links</span>
          <strong>${escapeHTML(links.total_links ?? 0)} total · ${escapeHTML((links.suspicious_links || []).length)} suspicious</strong>
        </div>
        <div class="mini">
          <span>Tracking</span>
          <strong>${escapeHTML(trackingCount)} likely pixel(s) · ${escapeHTML(tracking.risk || 'NONE')}</strong>
        </div>
        <div class="mini">
          <span>Attachments</span>
          <strong>${escapeHTML(attachments.total_attachments ?? email.attachments?.length ?? 0)} total · ${escapeHTML(riskyAttachmentCount)} risky</strong>
        </div>
      </div>

      <div class="insight ${fusionClass}">
        <span>CWAF + VSR</span>
        <strong>Core ${escapeHTML(fusion.core_score ?? risk.score ?? 0)}/100 · Auxiliary +${escapeHTML(fusion.auxiliary_adjustment ?? 0)}</strong>
        <ul>${fusionRowsHTML}</ul>
        <p>${escapeHTML(vsr.reason || 'No sender-history stability change applied.')}</p>
      </div>

      <div class="insight counterfactual">
        <span>Counterfactual risk reduction</span>
        <strong>What would make this email safer?</strong>
        <ul class="counterfactual-list">${counterfactualHTML}</ul>
      </div>

      <div class="insight ${uncertaintyClass}">
        <span>Evidence completeness</span>
        <strong>${escapeHTML(uncertainty.evidence_completeness ?? 0)}% complete · ${escapeHTML(uncertainty.level || 'UNKNOWN')} uncertainty</strong>
        <ul>${uncertaintyHTML}</ul>
      </div>

      <div class="insight ${memoryClass}">
        <span>Sender memory</span>
        <strong>${escapeHTML(memoryInsight.title)}</strong>
        <ul>${memoryHTML}</ul>
      </div>

      <div class="feedback-actions">
        <button type="button" data-feedback="safe">Mark safe</button>
        <button type="button" data-feedback="phishing">Mark phishing</button>
      </div>
      <div class="feedback-note" data-feedback-status></div>

      <div class="insight">
        <span>Likely attack goal</span>
        <strong>${escapeHTML(intent.goal || 'No clear malicious goal detected')}</strong>
        <p>${escapeHTML(intent.dangerous_step || 'No dangerous step identified.')}</p>
      </div>

      <div class="insight ${promptInjection.risk === 'HIGH' ? 'warn' : ''}">
        <span>Hidden AI-instruction check</span>
        <strong>${escapeHTML(promptInjection.risk || 'NONE')}</strong>
        <ul>${promptHTML}</ul>
      </div>

      <div class="insight ai">
        <span>AI explanation · ${escapeHTML(aiProviderLabel)}</span>
        <strong>${escapeHTML(aiExplanation.summary || 'No AI explanation returned.')}</strong>
        <ul>${aiFlagsHTML}</ul>
        <p>${escapeHTML(aiExplanation.recommended_action || 'No recommendation returned.')}</p>
      </div>

      <div class="insight">
        <span>Verify safely</span>
        <strong>Recommended next steps</strong>
        <ul>${verificationHTML}</ul>
      </div>

      <ul class="flags">${flagsHTML}</ul>
    </div>
  `;

  result.querySelector('[data-feedback="safe"]')?.addEventListener('click', () => storeFeedback(email, 0, 'popup'));
  result.querySelector('[data-feedback="phishing"]')?.addEventListener('click', () => storeFeedback(email, 1, 'popup'));
  renderRailLatestResult(data);
}

scanButton.addEventListener('click', scanEmail);
panelButton.addEventListener('click', showGmailPanel);
clearButton.addEventListener('click', clearGmailPanels);
evidenceButton.addEventListener('click', exportEvidence);
gmailButton.addEventListener('click', () => chrome.tabs.create({ url: 'https://mail.google.com' }));

checkBackend();
loadStats();
