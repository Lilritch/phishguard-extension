const BACKEND_ANALYSE_URL = 'http://127.0.0.1:5001/analyse';
const BACKEND_HEALTH_URL = 'http://127.0.0.1:5001/health';

const backendStatus = document.getElementById('backend-status');
const statusText = document.getElementById('status-text');
const scanButton = document.getElementById('scan-btn');
const clearButton = document.getElementById('clear-btn');
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
  clearButton.disabled = isBusy;
}

async function checkBackend() {
  try {
    const res = await fetch(BACKEND_HEALTH_URL);
    if (!res.ok) throw new Error('Health check failed');
    setBackendStatus('online', 'Online');
    statusText.textContent = 'Backend connected. Ready to scan the selected Gmail message.';
  } catch {
    setBackendStatus('offline', 'Offline');
    statusText.textContent = 'Backend offline. Start Flask before scanning.';
  }
}

async function getActiveGmailTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url?.startsWith('https://mail.google.com/')) {
    throw new Error('Open a Gmail message tab first.');
  }
  return tab;
}

async function getEmailFromGmail(tabId) {
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'PG_GET_EMAIL' });
    if (!response?.ok) throw new Error('No email response from Gmail.');
    return response.email;
  } catch {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });
    const response = await chrome.tabs.sendMessage(tabId, { type: 'PG_GET_EMAIL' });
    if (!response?.ok) throw new Error('Refresh Gmail and try again.');
    return response.email;
  }
}

async function scanEmail() {
  result.innerHTML = '<div class="loading"><span class="spinner"></span>Analysing the open email...</div>';
  statusText.textContent = 'Reading the selected Gmail message.';
  setBusy(true);

  try {
    const tab = await getActiveGmailTab();
    const email = await getEmailFromGmail(tab.id);

    if (!email?.subject && !email?.body) {
      throw new Error('Open an individual email first, not just the inbox list.');
    }

    statusText.textContent = 'Sending email text to the local Flask backend.';
    const response = await fetch(BACKEND_ANALYSE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        subject: email.subject,
        body: email.body,
        headers: email.headers
      })
    });

    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}.`);
    }

    const data = await response.json();
    renderResult(data, email);
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

async function clearGmailPanels() {
  try {
    const tab = await getActiveGmailTab();
    try {
      await chrome.tabs.sendMessage(tab.id, { type: 'PG_CLEAR_PANELS' });
    } catch {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content.js']
      });
      await chrome.tabs.sendMessage(tab.id, { type: 'PG_CLEAR_PANELS' });
    }
    result.innerHTML = '';
    statusText.textContent = 'Old Gmail side panels removed.';
  } catch {
    statusText.textContent = 'Refresh Gmail once, then click Clean page again.';
  }
}

function renderResult(data, email) {
  const risk = data?.risk || {};
  const ml = data?.ml || {};
  const hdr = data?.headers || {};
  const links = data?.links || {};
  const ip = data?.ip || {};

  const level = String(risk.level || 'LOW').toLowerCase();
  const scoreClass = level === 'high' ? 'high' : level === 'medium' ? 'medium' : '';
  const flags = Array.isArray(risk.flags) ? risk.flags : [];
  const flagsHTML = flags.length
    ? flags.map((flag) => `<li>${escapeHTML(flag)}</li>`).join('')
    : '<li class="ok">No major red flags found.</li>';

  result.innerHTML = `
    <div class="result">
      <div class="score ${scoreClass}">
        <div>
          <div class="score-label">${escapeHTML(risk.level || 'LOW')} risk</div>
          <div class="score-verdict">${escapeHTML(risk.verdict || 'Analysis complete')}</div>
        </div>
        <div class="score-number">${escapeHTML(risk.score ?? 0)}/100</div>
      </div>

      <div class="meta">
        <div class="mini">
          <span>Message</span>
          <strong>${escapeHTML(email.subject || 'No subject')}</strong>
        </div>
      </div>

      <div class="metric-grid">
        <div class="mini">
          <span>AI verdict</span>
          <strong>${escapeHTML(ml.label || 'Unknown')} · ${escapeHTML(ml.confidence ?? 0)}%</strong>
        </div>
        <div class="mini">
          <span>Links</span>
          <strong>${escapeHTML(links.total_links ?? 0)} total · ${escapeHTML((links.suspicious_links || []).length)} suspicious</strong>
        </div>
        <div class="mini">
          <span>Auth</span>
          <strong>SPF ${escapeHTML(hdr.spf || 'UNKNOWN')} · DKIM ${escapeHTML(hdr.dkim || 'UNKNOWN')} · DMARC ${escapeHTML(hdr.dmarc || 'UNKNOWN')}</strong>
        </div>
        <div class="mini">
          <span>Origin</span>
          <strong>${escapeHTML(ip.ip || 'No IP')} · ${escapeHTML(ip.country || 'Unknown')}</strong>
        </div>
      </div>

      <ul class="flags">${flagsHTML}</ul>
    </div>
  `;
}

scanButton.addEventListener('click', scanEmail);
clearButton.addEventListener('click', clearGmailPanels);

checkBackend();
