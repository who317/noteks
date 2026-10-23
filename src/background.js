// This extension has almost no other background logic - the main reason this
// file exists is a Chrome restriction: content scripts can't access
// chrome.storage.session unless a trusted context (like this service worker)
// explicitly grants it. Without this, content.js's encryption unlock check
// throws "Access to storage is not allowed from this context."
//
// This runs as a plain top-level statement (not wrapped in an onInstalled
// listener) so it re-applies every time Chrome wakes this service worker up -
// service workers are ephemeral and get a fresh execution each time.
chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" });

// --- Error capture (for the in-popup bug report link) ---
// Records the single most recent error from THIS context into chrome.storage.local.
// popup.js and content.js do the same in their own contexts.
const ERROR_CONTEXT = "background";

function captureError(message, source, lineno, error) {
  try {
    // Prefer the explicit location; otherwise use the first frame of the stack.
    let file = source ? source.split("/").pop() : "";
    let line = lineno || 0;
    if (!file && error && error.stack) {
      const match = /([\w.-]+\.js):(\d+):\d+/.exec(error.stack);
      if (match) {
        file = match[1];
        line = Number(match[2]);
      }
    }
    chrome.storage.local
      .set({
        tn_last_error: {
          message: message || (error && error.message) || "Unknown error",
          source: file,
          line,
          timestamp: Date.now(),
          context: ERROR_CONTEXT,
        },
      })
      .catch(() => {});
  } catch {
    // Error reporting must never throw an error of its own.
  }
}

self.addEventListener("error", (event) => {
  captureError(event.message, event.filename, event.lineno, event.error);
});

self.addEventListener("unhandledrejection", (event) => {
  const reason = event.reason;
  const message = reason && reason.message ? reason.message : String(reason);
  captureError(message, "", 0, reason instanceof Error ? reason : null);
});
// --- end error capture ---
