// PhishGuard - Gmail content bridge
// Extracts the open email for the popup. It does not inject UI into Gmail.

function removeLegacyPanels() {
  document.querySelectorAll('#phishguard-panel, .pg-shell').forEach((panel) => {
    panel.remove();
  });
}

function getEmailContent() {
  removeLegacyPanels();

  const subjectEl = document.querySelector('h2.hP') ||
                    document.querySelector('[data-thread-perm-id]');
  const subject = subjectEl ? subjectEl.innerText.trim() : '';

  const bodyEl = document.querySelector('.a3s.aiL') ||
                 document.querySelector('[data-message-id] .ii.gt div');
  const body = bodyEl ? bodyEl.innerText.trim() : '';

  const senderEl = document.querySelector('.gD');
  const senderEmail = senderEl ? senderEl.getAttribute('email') || '' : '';
  const senderName = senderEl ? senderEl.innerText.trim() : '';

  return {
    subject,
    body,
    senderEmail,
    senderName,
    headers: `From: ${senderName} <${senderEmail}>\nSubject: ${subject}`
  };
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

  return false;
});

removeLegacyPanels();
