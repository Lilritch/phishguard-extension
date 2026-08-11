# Gmail API And OAuth Setup

PhishGuard can now use the Gmail API to fetch real message headers. This improves institutional and SaaS email accuracy because SPF, DKIM, DMARC, Received-SPF, Return-Path, Reply-To, and Received headers are not reliably visible to a Gmail content script.

Official references:

- Chrome extension identity API: https://developer.chrome.com/docs/extensions/reference/api/identity
- Chrome extension OAuth guide: https://developer.chrome.com/docs/extensions/how-to/integrate/oauth
- Gmail `users.messages.list`: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list
- Gmail `users.messages.get`: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get
- Gmail API scopes: https://developers.google.com/workspace/gmail/api/auth/scopes

## What Was Added In The Project

The extension manifest now includes:

```json
"permissions": ["identity"],
"host_permissions": ["https://www.googleapis.com/*"],
"oauth2": {
  "client_id": "REPLACE_WITH_GOOGLE_OAUTH_CLIENT_ID.apps.googleusercontent.com",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
}
```

The background service worker now handles:

```text
PG_GMAIL_HEADERS
```

When OAuth is configured, the extension asks Gmail for metadata headers and sends them to the Flask backend with:

```text
X-PhishGuard-Header-Source: gmail_api
```

If OAuth is not configured yet, scans still work using the Gmail page evidence and the backend marks header authentication as incomplete instead of treating it as a hard failure.

## Google Cloud Setup

1. Open Google Cloud Console:

```text
https://console.cloud.google.com/
```

2. Create or select a project.

3. Enable Gmail API:

```text
APIs and services -> Library -> Gmail API -> Enable
```

4. Configure OAuth consent screen:

```text
APIs and services -> OAuth consent screen
```

Use `External` while testing, add your own Gmail account as a test user, and keep the scope to:

```text
https://www.googleapis.com/auth/gmail.readonly
```

5. Get your extension ID:

```text
chrome://extensions
```

Turn on Developer Mode, load `extension/`, then copy the extension ID shown on the card.

6. Create OAuth Client ID:

```text
APIs and services -> Credentials -> Create credentials -> OAuth client ID
```

Choose the Chrome extension application type and paste the extension ID.

7. Copy the generated client ID into:

```text
extension/manifest.json
```

Replace:

```text
REPLACE_WITH_GOOGLE_OAUTH_CLIENT_ID.apps.googleusercontent.com
```

with your real client ID.

8. Reload the extension in:

```text
chrome://extensions
```

9. Open Gmail, open one email, then click the PhishGuard popup `Scan popup` button. The first scan can show a Google consent screen. After you approve it, later Gmail panel scans can reuse the token silently.

## Why This Helps Accuracy

Without Gmail API headers, PhishGuard may see:

```text
SPF UNKNOWN
DKIM UNKNOWN
DMARC UNKNOWN
```

That should increase uncertainty, not automatically make the email risky.

With Gmail API headers, institutional emails can show:

```text
SPF PASS
DKIM PASS
DMARC PASS
```

The backend then gives the header signal high confidence and lower risk. A spoofed email can still be risky if authentication fails, Reply-To does not match, or the links go to unrelated domains.

## Thesis Note

Use this as one of your project contributions:

```text
Real-time authenticated-header retrieval through Gmail API/OAuth, combined with local explainable fusion, reduces false positives for legitimate institutional email while preserving risk flags for spoofed or mismatched messages.
```
