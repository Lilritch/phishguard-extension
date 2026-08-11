const GMAIL_API_BASE = 'https://www.googleapis.com/gmail/v1/users/me';
const OAUTH_PLACEHOLDER = 'REPLACE_WITH_GOOGLE_OAUTH_CLIENT_ID.apps.googleusercontent.com';

function isOAuthConfigured() {
  const manifest = chrome.runtime.getManifest();
  return Boolean(
    manifest.oauth2?.client_id &&
    manifest.oauth2.client_id !== OAUTH_PLACEHOLDER
  );
}

function getAuthToken(interactive = false) {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive }, (token) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(new Error(error.message));
        return;
      }
      const accessToken = typeof token === 'string' ? token : token?.token;
      if (!accessToken) {
        reject(new Error('Chrome did not return a Gmail OAuth token.'));
        return;
      }
      resolve(accessToken);
    });
  });
}

async function gmailFetch(path, token) {
  const response = await fetch(`${GMAIL_API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) {
    throw new Error(`Gmail API returned ${response.status}`);
  }
  return response.json();
}

function quoteGmailQuery(value) {
  return String(value || '').replace(/"/g, '\\"').trim();
}

function buildSearchQuery(email) {
  const parts = [];
  if (email.senderEmail) parts.push(`from:${quoteGmailQuery(email.senderEmail)}`);
  if (email.subject) parts.push(`subject:"${quoteGmailQuery(email.subject).slice(0, 80)}"`);
  parts.push('newer_than:90d');
  return parts.join(' ');
}

function headersToRaw(headers = []) {
  return headers
    .map((header) => `${header.name}: ${header.value}`)
    .join('\n');
}

async function fetchGmailHeaders(email, interactive = false) {
  if (!isOAuthConfigured()) {
    return {
      ok: false,
      configured: false,
      reason: 'Gmail API OAuth client ID is not configured in manifest.json.',
    };
  }

  const token = await getAuthToken(interactive);
  const query = encodeURIComponent(buildSearchQuery(email));
  const list = await gmailFetch(`/messages?q=${query}&maxResults=5`, token);
  const messageId = list.messages?.[0]?.id;
  if (!messageId) {
    return {
      ok: false,
      configured: true,
      reason: 'No Gmail API message matched the open email.',
    };
  }

  const metadataHeaders = [
    'From',
    'To',
    'Subject',
    'Date',
    'Message-ID',
    'Authentication-Results',
    'Received-SPF',
    'DKIM-Signature',
    'DMARC-Filter',
    'Received',
    'Reply-To',
    'Return-Path',
  ];
  const headerParams = metadataHeaders
    .map((name) => `metadataHeaders=${encodeURIComponent(name)}`)
    .join('&');
  const message = await gmailFetch(
    `/messages/${messageId}?format=metadata&${headerParams}`,
    token
  );
  const headers = message.payload?.headers || [];

  return {
    ok: true,
    configured: true,
    messageId,
    threadId: message.threadId,
    rawHeaders: headersToRaw(headers),
    headers,
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'PG_GMAIL_HEADERS') {
    fetchGmailHeaders(message.email || {}, Boolean(message.interactive))
      .then(sendResponse)
      .catch((error) => sendResponse({
        ok: false,
        configured: isOAuthConfigured(),
        reason: error.message,
      }));
    return true;
  }

  return false;
});
