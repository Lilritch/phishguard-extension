const BACKEND_ANALYSE_URL = 'http://127.0.0.1:5001/analyse';
const BACKEND_HEALTH_URL = 'http://127.0.0.1:5001/health';
const SENDER_MEMORY_KEY = 'phishguard_sender_memory_v1';
const MAX_DOMAINS_PER_SENDER = 24;

const backendStatus = document.getElementById('backend-status');
const statusText = document.getElementById('status-text');
const scanButton = document.getElementById('scan-btn');
const panelButton = document.getElementById('panel-btn');
const clearButton = document.getElementById('clear-btn');
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
  const data = await chrome.storage.local.get(['scanned', 'threats', 'safe']);
  document.getElementById('stat-scanned').textContent = data.scanned ?? 0;
  document.getElementById('stat-threats').textContent = data.threats ?? 0;
  document.getElementById('stat-safe').textContent = data.safe ?? 0;
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
  statusText.textContent = 'Reading Gmail content.';
  setBusy(true);

  try {
    const tab = await getActiveGmailTab();
    const email = await getEmailFromGmail(tab.id);
    if (!email?.subject && !email?.body) throw new Error('Open an individual email first, not just the inbox list.');

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
    if (!response.ok) throw new Error(`Backend returned ${response.status}.`);

    const data = await response.json();
    const memory = await getSenderMemory();
    const memoryInsight = compareSenderMemory(memory, email);
    await updateSenderMemory(memory, email);
    await updateScanStats(data);
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

function renderResult(data, email, memoryInsight) {
  const risk = data?.risk || {};
  const ml = data?.ml || {};
  const hdr = data?.headers || {};
  const links = data?.links || {};
  const ip = data?.ip || {};
  const intent = data?.intent || {};
  const promptInjection = data?.prompt_injection || {};
  const aiExplanation = data?.ai_explanation || {};

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
      </div>

      <div class="insight ${memoryClass}">
        <span>Sender memory</span>
        <strong>${escapeHTML(memoryInsight.title)}</strong>
        <ul>${memoryHTML}</ul>
      </div>

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
}

scanButton.addEventListener('click', scanEmail);
panelButton.addEventListener('click', showGmailPanel);
clearButton.addEventListener('click', clearGmailPanels);
gmailButton.addEventListener('click', () => chrome.tabs.create({ url: 'https://mail.google.com' }));

checkBackend();
loadStats();
