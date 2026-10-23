console.log("NoteKS loaded");

// --- Error capture (for the in-popup bug report link) ---
// Records the single most recent error from THIS context into chrome.storage.local.
// Because content scripts run in an isolated world, this only sees errors from
// OUR code - not X's own page scripts - so the report isn't polluted with noise.
const ERROR_CONTEXT = "content";

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

// For errors we catch ourselves (try/catch): logs to the console like before
// AND records it for the bug report. Without this, the report would say "no
// error" for every failure we handle gracefully - which is most of them.
function logError(label, err) {
  console.error(`NoteKS: ${label}:`, err);
  const detail = err && err.message ? err.message : String(err);
  captureError(`${label}: ${detail}`, "", 0, err instanceof Error ? err : null);
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

// X's DOM structure (especially data-testid values) can change over time. We
// keep all selectors here in one place - if X ever renames one, we only need
// to update this spot instead of hunting through the whole file.
const SELECTORS = {
  tweetAuthor: '[data-testid="User-Name"]', // a single tweet's author row
  profileHeader: '[data-testid="UserName"]', // the profile page header (no hyphen, different from tweets)
  repostContext: '[data-testid="socialContext"]', // the "X reposted" line
  profileLink: 'a[href^="/"]', // a link pointing to someone's profile
};

const STORAGE_KEY = "notes";
const SETTINGS_KEY = "settings";
const DEFAULT_BADGE_ICON = { type: "text", value: "★" };
const DEFAULT_THEME = "minimalism";
let notesCache = {};
let badgeIcon = DEFAULT_BADGE_ICON;

async function loadSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = result[SETTINGS_KEY] || {};
  badgeIcon = settings.badgeIcon || DEFAULT_BADGE_ICON;
  applyTheme(settings.theme || DEFAULT_THEME);
}

// ============================================================
// ENCRYPTION (Web Crypto API: AES-256-GCM) - same logic as popup.js.
// Setup/removal happens from the popup; here we just read the state and
// can unlock (when clicked from the panel).
// ============================================================
const LOCK_TIMEOUT_MS = 2 * 60 * 1000;
const SESSION_KEY_STORAGE = "tn_session_key";
const SESSION_ACTIVITY_STORAGE = "tn_session_activity";
const VERIFY_STRING = "tn-verify-ok";

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary);
}

function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

async function deriveKeyFromPassword(password, saltBytes) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 200000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function encryptString(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return bytesToBase64(combined);
}

async function decryptString(key, encoded) {
  const combined = base64ToBytes(encoded);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const dec = new TextDecoder();
  const plaintextBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return dec.decode(plaintextBuffer);
}

async function exportKeyToBase64(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bytesToBase64(new Uint8Array(raw));
}

async function importKeyFromBase64(base64) {
  const raw = base64ToBytes(base64);
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function getUnlockedKey() {
  const result = await chrome.storage.session.get([SESSION_KEY_STORAGE, SESSION_ACTIVITY_STORAGE]);
  const rawKey = result[SESSION_KEY_STORAGE];
  const lastActivity = result[SESSION_ACTIVITY_STORAGE];

  if (!rawKey || !lastActivity) return null;
  if (Date.now() - lastActivity > LOCK_TIMEOUT_MS) {
    await chrome.storage.session.remove([SESSION_KEY_STORAGE, SESSION_ACTIVITY_STORAGE]);
    return null;
  }

  await chrome.storage.session.set({ [SESSION_ACTIVITY_STORAGE]: Date.now() });
  return importKeyFromBase64(rawKey);
}

async function setUnlockedKey(key) {
  const rawBase64 = await exportKeyToBase64(key);
  await chrome.storage.session.set({
    [SESSION_KEY_STORAGE]: rawBase64,
    [SESSION_ACTIVITY_STORAGE]: Date.now(),
  });
}

async function isEncryptionEnabled() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = result[SETTINGS_KEY] || {};
  return Boolean(settings.encryption && settings.encryption.enabled);
}

// Verifies the password (throws if wrong) and both returns the key and stores it in the session.
async function unlockWithPassword(password) {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  const settings = result[SETTINGS_KEY] || {};
  const enc = settings.encryption;
  if (!enc || !enc.enabled) throw new Error("Encryption is not enabled");

  const saltBytes = base64ToBytes(enc.salt);
  const key = await deriveKeyFromPassword(password, saltBytes);

  let decrypted;
  try {
    decrypted = await decryptString(key, enc.verifier);
  } catch {
    throw new Error("Wrong password");
  }
  if (decrypted !== VERIFY_STRING) throw new Error("Wrong password");

  await setUnlockedKey(key);
  return key;
}

// Applies the chosen theme to the <html> element as data-tn-theme.
// The [data-tn-theme="..."] blocks in themes.css activate based on this attribute.
function applyTheme(theme) {
  document.documentElement.setAttribute("data-tn-theme", theme);
}

// Renders a badge's content (text/emoji or image) based on the current setting
function applyBadgeIconToElement(badge) {
  badge.innerHTML = "";
  if (badgeIcon.type === "image" && badgeIcon.value) {
    const img = document.createElement("img");
    img.src = badgeIcon.value; // a data URL we generated ourselves in the popup, safe
    img.className = "tn-badge-img";
    img.alt = "";
    badge.appendChild(img);
  } else {
    badge.textContent = badgeIcon.value || DEFAULT_BADGE_ICON.value;
  }
}

// Instantly refreshes the look of every existing badge on the page when the setting changes
function refreshAllBadgeIcons() {
  const found = document.querySelectorAll(".tn-badge");
  found.forEach(applyBadgeIconToElement);
}

// Migrates the old data shape ({note, createdAt}) to the current one ([{id, text, createdAt}, ...]).
// So earlier test notes don't get lost.
function normalizeNotesShape(rawNotes) {
  const normalized = {};
  for (const [handle, value] of Object.entries(rawNotes || {})) {
    if (Array.isArray(value)) {
      normalized[handle] = value;
    } else if (value && typeof value === "object" && "note" in value) {
      normalized[handle] = [
        { id: crypto.randomUUID(), text: value.note, createdAt: value.createdAt || Date.now() },
      ];
    }
  }
  return normalized;
}

async function loadNotes() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  notesCache = normalizeNotesShape(result[STORAGE_KEY]);
}

async function persistNotes() {
  await chrome.storage.local.set({ [STORAGE_KEY]: notesCache });
}

async function addNoteEntry(handle, text, image) {
  const encEnabled = await isEncryptionEnabled();
  let finalText = text;
  let finalImage = image || null;

  if (encEnabled) {
    const key = await getUnlockedKey();
    if (!key) throw new Error("Unlock first to add a note");
    finalText = await encryptString(key, text);
    if (finalImage) finalImage = await encryptString(key, finalImage);
  }

  if (!notesCache[handle]) notesCache[handle] = [];
  const entry = { id: crypto.randomUUID(), text: finalText, createdAt: Date.now() };
  if (finalImage) entry.image = finalImage;
  notesCache[handle].push(entry);
  await persistNotes();
}

// Updates an existing note's text and (optionally) its photo.
// newImage: undefined = leave the existing photo untouched, null = remove
// the photo, a data URL string = replace it with a new photo.
async function updateNoteEntry(handle, id, text, newImage) {
  const encEnabled = await isEncryptionEnabled();
  let key = null;
  if (encEnabled) {
    key = await getUnlockedKey();
    if (!key) throw new Error("Unlock first to edit a note");
  }

  const entry = (notesCache[handle] || []).find((e) => e.id === id);
  if (!entry) return;

  entry.text = encEnabled ? await encryptString(key, text) : text;

  if (newImage === null) {
    delete entry.image;
  } else if (newImage) {
    entry.image = encEnabled ? await encryptString(key, newImage) : newImage;
  }

  await persistNotes();
}

async function deleteNoteEntry(handle, id) {
  if (!notesCache[handle]) return;
  notesCache[handle] = notesCache[handle].filter((entry) => entry.id !== id);
  if (notesCache[handle].length === 0) delete notesCache[handle];
  await persistNotes();
}

// We use plain JS objects like notesCache with handles as keys, so if a
// "handle" value coming from the URL/DOM happens to be a special name like
// __proto__, it risks prototype pollution. This function guards every place we extract a handle.
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function sanitizeHandle(raw) {
  if (!raw) return null;
  const handle = raw.toLowerCase();
  if (DANGEROUS_KEYS.has(handle)) return null;
  return handle;
}

function getHandleFromUserNameBlock(block) {
  const link = block.querySelector(SELECTORS.profileLink);
  if (!link) return null;
  const href = link.getAttribute("href");
  return sanitizeHandle(href.split("/")[1]);
}

// If the URL looks like /username (or a profile subtab like /username/reposts),
// we're on that person's profile page. This lets us suppress the redundant
// star on their own tweets/reposts while we're already on their profile.
const RESERVED_PATHS = new Set([
  "home", "explore", "notifications", "messages", "i", "settings",
  "search", "compose", "bookmarks", "lists", "communities", "topics",
  "premium_sign_up", "jobs", "login", "logout",
]);

// Tabs under a profile (/username/<one of these>) - still counts as being on that profile
const PROFILE_SUBTABS = new Set([
  "with_replies", "media", "likes", "reposts", "highlights",
  "following", "followers", "verified_followers",
]);

function getCurrentProfileHandle() {
  const segments = window.location.pathname.split("/").filter(Boolean);
  if (segments.length === 0 || segments.length > 2) return null; // exclude things like /username/status/123
  const handle = sanitizeHandle(segments[0]);
  if (!handle) return null;
  if (RESERVED_PATHS.has(handle)) return null;
  if (segments.length === 2 && !PROFILE_SUBTABS.has(segments[1].toLowerCase())) return null;
  return handle;
}

// Opens a note photo in a new tab. Chrome blocks top-level navigation to
// data: URLs directly (anti-phishing hardening) - window.open(dataUrl) opens
// a tab but shows it blank. Converting to a blob: URL first works around this.
function dataUrlToBlob(dataUrl) {
  const [header, base64] = dataUrl.split(",");
  const mimeMatch = header.match(/data:(.*?);base64/);
  const mime = mimeMatch ? mimeMatch[1] : "image/jpeg";
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type: mime });
}

function openImageInNewTab(dataUrl) {
  const blob = dataUrlToBlob(dataUrl);
  const url = URL.createObjectURL(blob);
  window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// Renders note text with any http(s) links turned into real, clickable <a>
// elements - built manually with createElement/createTextNode, NEVER via
// innerHTML, so nothing in the note text can be interpreted as HTML. Only
// http:// and https:// links are linkified.
const URL_PATTERN = /(https?:\/\/[^\s]+)/g;

function renderNoteTextInto(container, text) {
  container.textContent = "";
  let lastIndex = 0;
  let match;

  URL_PATTERN.lastIndex = 0;
  while ((match = URL_PATTERN.exec(text)) !== null) {
    if (match.index > lastIndex) {
      container.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
    }

    const url = match[0];
    const link = document.createElement("a");
    link.href = url;
    link.textContent = url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.className = "tn-note-link";
    link.addEventListener("click", (e) => e.stopPropagation());
    container.appendChild(link);

    lastIndex = match.index + url.length;
  }

  if (lastIndex < text.length) {
    container.appendChild(document.createTextNode(text.slice(lastIndex)));
  }
}

// --- Photo attachment (same approach as popup.js's badge image upload) ---
function readFileHeaderBytes(file, byteCount = 262144) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.readAsArrayBuffer(file.slice(0, byteCount));
  });
}

// Reads real pixel dimensions straight from the PNG/JPEG header, without
// letting the browser fully decode the file - our defense against
// "decompression bomb" images (tiny file, huge claimed pixel size).
function readDimensionsFromHeader(bytes) {
  const isPng =
    bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47;
  if (isPng && bytes.length >= 24) {
    const width = ((bytes[16] << 24) | (bytes[17] << 16) | (bytes[18] << 8) | bytes[19]) >>> 0;
    const height = ((bytes[20] << 24) | (bytes[21] << 16) | (bytes[22] << 8) | bytes[23]) >>> 0;
    return { width, height };
  }

  const isJpeg = bytes[0] === 0xff && bytes[1] === 0xd8;
  if (isJpeg) {
    let offset = 2;
    while (offset + 9 < bytes.length) {
      if (bytes[offset] !== 0xff) {
        offset++;
        continue;
      }
      const marker = bytes[offset + 1];
      const isSofMarker =
        marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
      if (isSofMarker) {
        const height = (bytes[offset + 5] << 8) | bytes[offset + 6];
        const width = (bytes[offset + 7] << 8) | bytes[offset + 8];
        return { width, height };
      }
      const segmentLength = (bytes[offset + 2] << 8) | bytes[offset + 3];
      if (segmentLength < 2) break;
      offset += 2 + segmentLength;
    }
  }

  return null;
}

async function loadValidatedImage(file) {
  const MAX_FILE_SIZE = 5 * 1024 * 1024;
  const MAX_IMAGE_DIMENSION = 8000;

  if (!file.type.startsWith("image/")) {
    throw new Error("Only image files are supported");
  }
  if (file.size > MAX_FILE_SIZE) {
    throw new Error("Image is too large (over 5MB), pick a smaller file");
  }

  const headerBytes = await readFileHeaderBytes(file);
  const dimensions = readDimensionsFromHeader(headerBytes);

  if (!dimensions) {
    throw new Error("This image format isn't supported, use PNG or JPEG");
  }
  if (dimensions.width > MAX_IMAGE_DIMENSION || dimensions.height > MAX_IMAGE_DIMENSION) {
    throw new Error(`Image dimensions are too large (max ${MAX_IMAGE_DIMENSION}x${MAX_IMAGE_DIMENSION}px)`);
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      const img = new Image();
      img.onerror = () => reject(new Error("Could not read the image"));
      img.onload = () => resolve(img);
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}

// Keeps the original aspect ratio and caps the longest side - used for photos
// attached to a note. JPEG output keeps storage usage reasonable.
async function resizeNotePhoto(file, maxDimension = 480) {
  const img = await loadValidatedImage(file);
  const scale = Math.min(1, maxDimension / Math.max(img.width, img.height));
  const width = Math.round(img.width * scale);
  const height = Math.round(img.height * scale);

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(img, 0, 0, width, height);
  return canvas.toDataURL("image/jpeg", 0.82);
}

// Relative time like "3d ago" - consistent with the popup, friendlier than a bare date.
function formatDate(timestamp) {
  const diffMs = Date.now() - timestamp;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHour = Math.floor(diffMs / 3600000);
  const diffDay = Math.floor(diffMs / 86400000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHour < 24) return `${diffHour}h ago`;
  if (diffDay === 1) return "yesterday";
  if (diffDay < 7) return `${diffDay}d ago`;

  return new Date(timestamp).toLocaleDateString(undefined, { day: "2-digit", month: "2-digit", year: "numeric" });
}

function positionFloatingEl(el, anchorEl) {
  const rect = anchorEl.getBoundingClientRect();
  el.style.top = `${rect.bottom + window.scrollY + 6}px`;
  el.style.left = `${rect.left + window.scrollX}px`;
}

// --- Shadow DOM shell ---
// The tooltip and panel are added inside an isolated Shadow DOM shell rather
// than directly into X's page. This means: (1) X's CSS can't break our
// tooltip/panel, and (2) our CSS (especially our earlier !important overrides)
// never leaks into X's page. Only our CSS custom properties (--tn-...) cross
// the Shadow DOM boundary normally (standard browser behavior), so the theme
// system keeps working unchanged.
const shadowHost = document.createElement("div");
shadowHost.id = "tn-shadow-host";
document.documentElement.appendChild(shadowHost);
const shadowRoot = shadowHost.attachShadow({ mode: "open" });

const shadowStyle = document.createElement("style");
shadowStyle.textContent = `
  :host {
    all: initial; /* cut off any font/color inheritance leaking in from X's body */
  }

  /* Without this, any class that sets display (e.g. .tn-panel-form { display: flex })
     silently overrides the [hidden] attribute - the popup has the same rule
     in popup.css. This is what made the "Tap to unlock" toggle do nothing. */
  [hidden] {
    display: none !important;
  }

  /* The floating profile-header badge lives in this Shadow DOM (unlike
     tweet/repost badges, which stay in X's own light DOM and get their
     styles from content.css). Light-DOM stylesheets don't cross into a
     shadow tree, so this badge needs its own copy of the badge styles here -
     without it, the badge renders completely unstyled (invisible). */
  .tn-badge {
    position: absolute;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    color: var(--tn-highlight);
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    transition: transform 0.12s ease, color 0.12s ease;
  }

  .tn-badge:hover {
    color: var(--tn-highlight-hover);
  }

  .tn-badge-img {
    width: 16px;
    height: 16px;
    border-radius: var(--tn-radius-sm);
    object-fit: cover;
    display: block;
  }

  .tn-add-badge {
    position: absolute;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    border: 1.5px dashed var(--tn-text-muted);
    border-radius: 50%;
    color: var(--tn-text-muted);
    font-size: 12px;
    line-height: 1;
    opacity: 0.55;
    cursor: pointer;
    transition: opacity 0.12s ease, border-color 0.12s ease, color 0.12s ease;
  }

  .tn-add-badge:hover {
    opacity: 1;
    border-style: solid;
    border-color: var(--tn-highlight);
    color: var(--tn-highlight);
  }

  .tn-tooltip {
    position: absolute;
    display: none;
    max-width: 240px;
    background: var(--tn-text);
    color: var(--tn-bg);
    font-size: 12px;
    line-height: 1.4;
    padding: 8px 10px;
    border-radius: var(--tn-radius-md);
    box-shadow: var(--tn-shadow-md);
    z-index: 9999;
    pointer-events: none;
    font-family: var(--tn-font-sans);
  }

  .tn-panel {
    position: absolute;
    width: 260px;
    max-height: 360px;
    display: flex;
    flex-direction: column;
    background: var(--tn-surface);
    color: var(--tn-text);
    border: var(--tn-border-width) solid var(--tn-border);
    border-radius: var(--tn-radius-lg);
    box-shadow: var(--tn-shadow-md);
    z-index: 10000;
    font-family: var(--tn-font-sans);
    overflow: hidden;
  }

  .tn-panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: var(--tn-border-width) solid var(--tn-border);
  }

  .tn-panel-handle {
    font-family: var(--tn-font-mono);
    font-size: 13px;
    font-weight: 600;
    color: var(--tn-text);
  }

  .tn-panel-close {
    background: transparent;
    border: none;
    font-size: 16px;
    line-height: 1;
    color: var(--tn-text-muted);
    cursor: pointer;
    padding: 2px 6px;
    border-radius: var(--tn-radius-sm);
  }

  .tn-panel-close:hover {
    background: rgba(0, 0, 0, 0.06);
  }

  .tn-panel-list {
    list-style: none;
    margin: 0;
    padding: 8px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    overflow-y: auto;
    max-height: 180px;
  }

  .tn-panel-empty {
    margin: 0;
    font-size: 12px;
    color: var(--tn-text-muted);
    text-align: center;
    padding: 8px 0;
  }

  .tn-panel-locked-summary {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    width: 100%;
    background: transparent;
    border: none;
    cursor: pointer;
    padding: 4px 0;
  }

  .tn-panel-locked-summary .tn-panel-empty {
    padding: 0;
  }

  .tn-panel-unlock-hint {
    margin: 0;
    font-size: 10px;
    color: var(--tn-accent);
    text-decoration: underline;
  }

  .tn-panel-item {
    border: var(--tn-border-width) solid var(--tn-border);
    border-left: var(--tn-note-accent-width) solid var(--tn-highlight);
    border-radius: var(--tn-radius-md);
    padding: 6px 8px;
    background: var(--tn-bg);
    transition: transform 0.12s ease;
  }

  .tn-panel-item:hover {
    transform: translateX(1px);
  }

  .tn-panel-text {
    margin: 0 0 4px;
    font-size: 12px;
    line-height: 1.4;
    word-break: break-word;
    color: var(--tn-text);
  }

  .tn-note-link {
    color: var(--tn-accent);
    text-decoration: underline;
    word-break: break-all;
  }

  .tn-note-link:hover {
    color: var(--tn-accent-hover);
  }

  .tn-panel-item-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .tn-panel-date {
    font-size: 10px;
    color: var(--tn-text-muted);
  }

  .tn-panel-btn-group {
    display: flex;
    gap: 4px;
  }

  .tn-panel-edit,
  .tn-panel-delete {
    background: transparent;
    border: none;
    font-size: 11px;
    color: var(--tn-text-muted);
    cursor: pointer;
    padding: 2px 4px;
    border-radius: var(--tn-radius-sm);
  }

  .tn-panel-edit:hover {
    color: var(--tn-accent);
    background: rgba(0, 0, 0, 0.06);
  }

  .tn-panel-delete:hover {
    color: var(--tn-danger);
    background: rgba(179, 38, 30, 0.08);
  }

  .tn-panel-item textarea {
    width: 100%;
    border: var(--tn-border-width) solid var(--tn-border);
    border-radius: var(--tn-radius-sm);
    padding: 6px 8px;
    font-size: 12px;
    font-family: inherit;
    resize: vertical;
    background: var(--tn-surface);
    color: var(--tn-text);
    margin-bottom: 6px;
  }

  .tn-panel-item textarea:focus {
    outline: none;
    border-color: var(--tn-accent);
  }

  .tn-panel-edit-actions {
    display: flex;
    justify-content: flex-end;
    gap: 6px;
  }

  .tn-panel-edit-actions button {
    background: var(--tn-accent);
    color: var(--tn-accent-text);
    border: var(--tn-border-width) solid var(--tn-border);
    border-radius: var(--tn-radius-sm);
    padding: 4px 10px;
    font-size: 11px;
    font-weight: var(--tn-font-weight-bold);
    cursor: pointer;
  }

  .tn-panel-edit-actions button:hover {
    background: var(--tn-accent-hover);
  }

  .tn-panel-edit-actions .tn-panel-cancel {
    background: transparent;
    color: var(--tn-text-muted);
  }

  .tn-panel-edit-actions .tn-panel-cancel:hover {
    background: rgba(0, 0, 0, 0.06);
  }

  .tn-panel-form {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px 12px;
    border-top: var(--tn-border-width) solid var(--tn-border);
  }

  .tn-panel-form textarea,
  .tn-panel-form input[type="password"] {
    border: var(--tn-border-width) solid var(--tn-border);
    border-radius: var(--tn-radius-sm);
    padding: 6px 8px;
    font-size: 12px;
    font-family: inherit;
    background: var(--tn-surface);
    color: var(--tn-text);
  }

  .tn-panel-form textarea {
    resize: vertical;
    min-height: 40px;
  }

  .tn-panel-form textarea:focus,
  .tn-panel-form input[type="password"]:focus {
    outline: none;
    border-color: var(--tn-accent);
  }

  .tn-panel-form button {
    align-self: flex-end;
    background: var(--tn-accent);
    color: var(--tn-accent-text);
    border: var(--tn-border-width) solid var(--tn-border);
    border-radius: var(--tn-radius-sm);
    padding: 6px 12px;
    font-size: 12px;
    font-weight: var(--tn-font-weight-bold);
    cursor: pointer;
  }

  .tn-panel-form button:hover {
    background: var(--tn-accent-hover);
  }

  .tn-panel-photo {
    display: block;
    width: 100%;
    max-height: 160px;
    object-fit: cover;
    border-radius: var(--tn-radius-sm);
    margin-bottom: 4px;
    cursor: zoom-in;
  }

  .tn-panel-photo-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .tn-panel-photo-label {
    flex-shrink: 0;
    border: var(--tn-border-width) dashed var(--tn-border);
    border-radius: var(--tn-radius-sm);
    padding: 4px 8px;
    font-size: 10px;
    color: var(--tn-text-muted);
    cursor: pointer;
  }

  .tn-panel-photo-label:hover {
    border-color: var(--tn-accent);
    color: var(--tn-accent);
  }

  .tn-panel-photo-preview {
    width: 26px;
    height: 26px;
    object-fit: cover;
    border-radius: var(--tn-radius-sm);
    border: var(--tn-border-width) solid var(--tn-border);
  }

  .tn-panel-photo-remove {
    width: 16px;
    height: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: var(--tn-danger);
    color: #fff;
    border: none;
    font-size: 11px;
    line-height: 1;
    cursor: pointer;
    padding: 0;
  }

  /* The photo-remove button lives inside .tn-panel-form, whose generic
     ".tn-panel-form button" rule (purple pill) has higher specificity than
     ".tn-panel-photo-remove" alone - so it rendered as a big purple pill
     instead of the small red circle it was designed to be. */
  .tn-panel-form .tn-panel-photo-remove {
    align-self: center;
    width: 16px;
    height: 16px;
    padding: 0;
    border: none;
    border-radius: 50%;
    background: var(--tn-danger);
    color: #fff;
    font-size: 11px;
    font-weight: 400;
  }

  .tn-panel-form .tn-panel-photo-remove:hover {
    background: var(--tn-danger);
  }
`;
shadowRoot.appendChild(shadowStyle);

// --- Hover preview ---
let tooltipEl = null;
let tooltipTimer = null;

function ensureTooltipEl() {
  if (tooltipEl) return tooltipEl;
  tooltipEl = document.createElement("div");
  tooltipEl.className = "tn-tooltip";
  shadowRoot.appendChild(tooltipEl);
  return tooltipEl;
}

function showTooltip(badgeEl) {
  if (panelEl) return; // don't show the preview while the panel is open
  clearTimeout(tooltipTimer);
  tooltipTimer = setTimeout(async () => {
    const handle = badgeEl.dataset.tnHandle;
    const entries = notesCache[handle];
    if (!entries || entries.length === 0) return;

    const tooltip = ensureTooltipEl();
    const encEnabled = await isEncryptionEnabled();

    if (encEnabled) {
      // Never show the real text on hover while encrypted - click to unlock instead
      tooltip.textContent = `🔒 ${entries.length} note${entries.length === 1 ? "" : "s"}, click to view`;
    } else {
      const latest = [...entries].sort((a, b) => b.createdAt - a.createdAt)[0];
      const extra = entries.length > 1 ? ` (+${entries.length - 1} more)` : "";
      tooltip.textContent = latest.text + extra; // textContent -> safe against XSS
    }

    tooltip.style.display = "block";
    positionFloatingEl(tooltip, badgeEl);
  }, 200);
}

function hideTooltip() {
  clearTimeout(tooltipTimer);
  if (tooltipEl) tooltipEl.style.display = "none";
}

// --- Click-to-open detail panel (note history + adding new notes) ---
let panelEl = null;
let panelHandle = null;

function closePanel() {
  if (panelEl) {
    panelEl.remove();
    panelEl = null;
    panelHandle = null;
  }
  document.removeEventListener("mousedown", handleOutsideClick, true);
  document.removeEventListener("keydown", handleEscKey);
}

function handleOutsideClick(e) {
  // In Shadow DOM, events listened to from outside get "retargeted" - e.target
  // shows the shadow host, not the actual clicked element. composedPath() gives
  // the real path, so we check whether panelEl is in it - .contains() isn't reliable here.
  if (panelEl && !e.composedPath().includes(panelEl)) closePanel();
}

function handleEscKey(e) {
  if (e.key === "Escape") closePanel();
}

async function renderPanel() {
  // Pin down which panel/handle this call is for RIGHT NOW - while this
  // function is waiting on an await, the shared panelEl/panelHandle can
  // change (e.g. the user quickly clicks a different star). Without a fixed
  // reference, a "stale" call could wake up and write into the wrong (current)
  // panel - that's what caused the duplicate-note-appearing bug.
  const targetEl = panelEl;
  const targetHandle = panelHandle;
  if (!targetEl || !targetHandle) return;

  targetEl.innerHTML = "";

  const header = document.createElement("div");
  header.className = "tn-panel-header";

  const title = document.createElement("span");
  title.className = "tn-panel-handle";
  title.textContent = "@" + targetHandle;

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "tn-panel-close";
  closeBtn.textContent = "×";
  closeBtn.setAttribute("aria-label", "Close");
  closeBtn.addEventListener("click", closePanel);

  header.append(title, closeBtn);
  targetEl.appendChild(header);

  try {
    const rawEntries = [...(notesCache[targetHandle] || [])].sort((a, b) => b.createdAt - a.createdAt);
    const encEnabled = await isEncryptionEnabled();

    // After the await: is this still the "current" panel? If not, quietly bail without touching the DOM.
    if (panelEl !== targetEl) return;

    if (encEnabled) {
      const key = await getUnlockedKey();
      if (panelEl !== targetEl) return;

      if (!key) {
        renderPanelLockedState(targetEl, targetHandle, rawEntries.length);
        return;
      }
      // We decrypt COPIES for display - we never touch the original (encrypted)
      // text in notesCache, or it could accidentally get written back to disk unencrypted.
      const decryptedEntries = [];
      for (const entry of rawEntries) {
        const copy = { ...entry };
        try {
          copy.text = await decryptString(key, entry.text);
          if (entry.image) copy.image = await decryptString(key, entry.image);
        } catch {
          copy.text = "⚠️ Could not decrypt";
          copy.image = undefined;
      }
      decryptedEntries.push(copy);
    }
    if (panelEl !== targetEl) return;
    renderPanelUnlockedContent(targetEl, targetHandle, decryptedEntries);
    return;
    }

    renderPanelUnlockedContent(targetEl, targetHandle, rawEntries);
  } catch (err) {
    // Something in the block above threw and would otherwise have left the
    // panel showing just the header with nothing else - surface it clearly
    // instead of failing silently.
    logError("failed to render the panel", err);
    if (panelEl === targetEl) {
      const errorMsg = document.createElement("p");
      errorMsg.className = "tn-panel-empty";
      errorMsg.textContent = "Something went wrong showing this panel. Check the console for details.";
      targetEl.appendChild(errorMsg);
    }
  }
}

// Locked state: shows how many notes exist + an inline password field.
function renderPanelLockedState(targetEl, targetHandle, noteCount) {
  const wrap = document.createElement("div");
  wrap.className = "tn-panel-locked";

  // A single clickable summary line - tapping it reveals the password field,
  // instead of always showing the password input up front.
  const summary = document.createElement("button");
  summary.type = "button";
  summary.className = "tn-panel-locked-summary";

  const line1 = document.createElement("p");
  line1.className = "tn-panel-empty";
  line1.textContent = noteCount > 0 ? `🔒 Notes are encrypted (${noteCount})` : "🔒 Notes are encrypted";

  const line2 = document.createElement("p");
  line2.className = "tn-panel-unlock-hint";
  line2.textContent = "Tap to unlock";

  summary.append(line1, line2);
  wrap.appendChild(summary);

  const unlockForm = document.createElement("form");
  unlockForm.className = "tn-panel-form";
  unlockForm.hidden = true;

  const passwordInput = document.createElement("input");
  passwordInput.type = "password";
  passwordInput.placeholder = "Password";

  const unlockBtn = document.createElement("button");
  unlockBtn.type = "submit";
  unlockBtn.textContent = "Unlock";

  unlockForm.append(passwordInput, unlockBtn);

  summary.addEventListener("click", () => {
    unlockForm.hidden = !unlockForm.hidden;
    if (!unlockForm.hidden) passwordInput.focus();
  });

  unlockForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    try {
      await unlockWithPassword(passwordInput.value);
      if (panelEl !== targetEl) return;
      await renderPanel();
    } catch (err) {
      passwordInput.value = "";
      passwordInput.placeholder = err.message || "Wrong password";
    }
  });

  wrap.appendChild(unlockForm);
  targetEl.appendChild(wrap);
}

// Unlocked (or encryption off): the normal note list + the add-note form.
// Replaces a panel note item's contents with an edit form, in place - same
// approach as popup.js's renderNoteEditForm (no cross-render state needed,
// Save/Cancel both end in a fresh render anyway).
function renderPanelNoteEditForm(li, targetHandle, entry) {
  li.innerHTML = "";

  const textarea = document.createElement("textarea");
  textarea.value = entry.text;
  textarea.rows = 2;
  textarea.maxLength = 500;

  let editImage = entry.image || null;
  let imageChanged = false;

  const photoRow = document.createElement("div");
  photoRow.className = "tn-panel-photo-row";

  const photoLabel = document.createElement("label");
  photoLabel.className = "tn-panel-photo-label";
  photoLabel.textContent = editImage ? "📷 Change" : "📷 Photo";

  const photoInput = document.createElement("input");
  photoInput.type = "file";
  photoInput.accept = "image/png,image/jpeg";
  photoInput.hidden = true;
  photoLabel.appendChild(photoInput);

  const photoPreview = document.createElement("img");
  photoPreview.className = "tn-panel-photo-preview";
  photoPreview.hidden = !editImage;
  if (editImage) photoPreview.src = editImage;

  const photoRemoveBtn = document.createElement("button");
  photoRemoveBtn.type = "button";
  photoRemoveBtn.className = "tn-panel-photo-remove";
  photoRemoveBtn.textContent = "×";
  photoRemoveBtn.hidden = !editImage;
  photoRemoveBtn.setAttribute("aria-label", "Remove photo");

  photoRow.append(photoLabel, photoPreview, photoRemoveBtn);

  photoInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      editImage = await resizeNotePhoto(file);
      imageChanged = true;
      photoPreview.src = editImage;
      photoPreview.hidden = false;
      photoRemoveBtn.hidden = false;
      photoLabel.textContent = "📷 Change";
    } catch (err) {
      logError("failed to process note photo", err);
    }
  });

  photoRemoveBtn.addEventListener("click", () => {
    editImage = null;
    imageChanged = true;
    photoPreview.hidden = true;
    photoRemoveBtn.hidden = true;
    photoInput.value = "";
    photoLabel.textContent = "📷 Photo";
  });

  const actions = document.createElement("div");
  actions.className = "tn-panel-edit-actions";

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.textContent = "Save";

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "tn-panel-cancel";
  cancelBtn.textContent = "Cancel";

  actions.append(saveBtn, cancelBtn);

  saveBtn.addEventListener("click", async () => {
    const newText = textarea.value.trim();
    if (!newText) return;
    try {
      const imageArg = imageChanged ? editImage : undefined;
      await updateNoteEntry(targetHandle, entry.id, newText, imageArg);
      // No explicit renderPanel() call - chrome.storage.onChanged refreshes it automatically.
    } catch (err) {
      logError("failed to update note", err);
    }
  });

  cancelBtn.addEventListener("click", () => {
    renderPanel();
  });

  li.append(textarea, photoRow, actions);
}

function renderPanelUnlockedContent(targetEl, targetHandle, entries) {
  const list = document.createElement("ul");
  list.className = "tn-panel-list";

  if (entries.length === 0) {
    const empty = document.createElement("p");
    empty.className = "tn-panel-empty";
    empty.textContent = "No notes yet.";
    list.appendChild(empty);
  } else {
    entries.forEach((entry) => {
      const li = document.createElement("li");
      li.className = "tn-panel-item";

      if (entry.image) {
        const photo = document.createElement("img");
        photo.className = "tn-panel-photo";
        photo.src = entry.image; // a data URL we generated ourselves, safe
        photo.alt = "";
        photo.addEventListener("click", () => openImageInNewTab(entry.image));
        li.appendChild(photo);
      }

      const text = document.createElement("p");
      text.className = "tn-panel-text";
      renderNoteTextInto(text, entry.text);

      const footer = document.createElement("div");
      footer.className = "tn-panel-item-footer";

      const date = document.createElement("span");
      date.className = "tn-panel-date";
      date.textContent = formatDate(entry.createdAt);
      date.title = new Date(entry.createdAt).toLocaleString();

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "tn-panel-delete";
      deleteBtn.textContent = "Delete";
      deleteBtn.addEventListener("click", async () => {
        try {
          // We do NOT call renderPanel() again here - deleteNoteEntry already
          // writes to storage, which triggers chrome.storage.onChanged and
          // refreshes the panel AUTOMATICALLY. Calling it twice caused a race
          // that duplicated content.
          await deleteNoteEntry(targetHandle, entry.id);
        } catch (err) {
          logError("failed to delete note", err);
        }
      });

      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "tn-panel-edit";
      editBtn.textContent = "Edit";
      editBtn.addEventListener("click", () => renderPanelNoteEditForm(li, targetHandle, entry));

      const btnGroup = document.createElement("div");
      btnGroup.className = "tn-panel-btn-group";
      btnGroup.append(editBtn, deleteBtn);

      footer.append(date, btnGroup);
      li.append(text, footer);
      list.appendChild(li);
    });
  }

  targetEl.appendChild(list);

  // Local to this render - each time the panel redraws it gets a fresh form
  // and a fresh pending-photo slot, so this doesn't need to be module-level state.
  let pendingPhoto = null;

  const form = document.createElement("form");
  form.className = "tn-panel-form";

  const textarea = document.createElement("textarea");
  textarea.placeholder = "Add a new note...";
  textarea.rows = 2;
  textarea.maxLength = 500;

  const photoRow = document.createElement("div");
  photoRow.className = "tn-panel-photo-row";

  const photoLabel = document.createElement("label");
  photoLabel.className = "tn-panel-photo-label";
  photoLabel.textContent = "📷 Photo";

  const photoInput = document.createElement("input");
  photoInput.type = "file";
  photoInput.accept = "image/png,image/jpeg";
  photoInput.hidden = true;

  const photoPreview = document.createElement("img");
  photoPreview.className = "tn-panel-photo-preview";
  photoPreview.hidden = true;

  const photoRemoveBtn = document.createElement("button");
  photoRemoveBtn.type = "button";
  photoRemoveBtn.className = "tn-panel-photo-remove";
  photoRemoveBtn.textContent = "×";
  photoRemoveBtn.hidden = true;
  photoRemoveBtn.setAttribute("aria-label", "Remove photo");

  photoLabel.appendChild(photoInput);
  photoRow.append(photoLabel, photoPreview, photoRemoveBtn);

  photoInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      pendingPhoto = await resizeNotePhoto(file);
      photoPreview.src = pendingPhoto;
      photoPreview.hidden = false;
      photoRemoveBtn.hidden = false;
    } catch (err) {
      logError("failed to process note photo", err);
      photoInput.value = "";
    }
  });

  photoRemoveBtn.addEventListener("click", () => {
    pendingPhoto = null;
    photoPreview.hidden = true;
    photoPreview.src = "";
    photoRemoveBtn.hidden = true;
    photoInput.value = "";
  });

  const addBtn = document.createElement("button");
  addBtn.type = "submit";
  addBtn.textContent = "Add";

  form.append(textarea, photoRow, addBtn);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const text = textarea.value.trim();
    if (!text) return;
    try {
      // Same as above - no explicit renderPanel() call, chrome.storage.onChanged
      // already refreshes the panel automatically after addNoteEntry writes to storage.
      await addNoteEntry(targetHandle, text, pendingPhoto);
      textarea.value = "";
      pendingPhoto = null;
    } catch (err) {
      logError("failed to add note", err);
    }
  });

  targetEl.appendChild(form);
}


function openPanel(handle, badgeEl) {
  hideTooltip();
  closePanel();
  panelHandle = handle;
  panelEl = document.createElement("div");
  panelEl.className = "tn-panel";
  shadowRoot.appendChild(panelEl);
  positionFloatingEl(panelEl, badgeEl);
  renderPanel();

  setTimeout(() => {
    document.addEventListener("mousedown", handleOutsideClick, true);
    document.addEventListener("keydown", handleEscKey);
  }, 0);
}

// --- Badge ---
// Attaches the badge to a box - makes the box "position: relative" and pins
// the badge to its corner with absolute positioning. This was necessary
// because X uses different flex layouts on different pages for tweet/repost
// rows (the badge kept wrapping to odd spots otherwise). ONLY use for tweet and repost rows.
function attachBadge(container, handle) {
  container.classList.add("tn-badge-anchor");
  container.appendChild(createNoteBadge(handle));
}

// Same anchoring trick as attachBadge, but for the "+" (add note) badge.
function attachAddBadge(container, handle) {
  container.classList.add("tn-badge-anchor");
  container.appendChild(createAddNoteBadge(handle));
}

function createNoteBadge(handle, options = {}) {
  const badge = document.createElement("span");
  badge.className = options.inline ? "tn-badge tn-badge--inline" : "tn-badge";
  badge.dataset.tnHandle = handle;
  badge.setAttribute("role", "button");
  badge.setAttribute("aria-label", `Notes for @${handle}`);
  applyBadgeIconToElement(badge);

  badge.addEventListener("mouseenter", () => showTooltip(badge));
  badge.addEventListener("mouseleave", hideTooltip);
  badge.addEventListener("mousedown", (e) => e.stopPropagation());
  badge.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    openPanel(handle, badge);
  });

  return badge;
}

// A subtle "+" badge shown next to people who DON'T have a note yet - opens
// the same panel used for existing notes, so adding one is a single click
// right where you see the person, instead of switching to the popup and
// typing their username in by hand.
function createAddNoteBadge(handle) {
  const badge = document.createElement("span");
  badge.className = "tn-add-badge";
  badge.dataset.tnHandle = handle;
  badge.textContent = "+";
  badge.setAttribute("role", "button");
  badge.setAttribute("aria-label", `Add a note for @${handle}`);

  badge.addEventListener("mousedown", (e) => e.stopPropagation());
  badge.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    openPanel(handle, badge);
  });

  return badge;
}

// If roots is given (newly added nodes from the MutationObserver), only search
// WITHIN them (and check the roots themselves) - not the whole page. If roots
// isn't given (a storage change or the initial load, where a full scan is
// needed), scan the whole document like before.
function queryWithinRoots(roots, selector) {
  const results = new Set();
  roots.forEach((root) => {
    if (root.nodeType !== Node.ELEMENT_NODE) return;
    if (root.matches && root.matches(selector)) results.add(root);
    if (root.querySelectorAll) {
      root.querySelectorAll(selector).forEach((el) => results.add(el));
    }
  });
  return Array.from(results);
}

function applyHighlights(roots = null) {
  const userNameBlocks = roots
    ? queryWithinRoots(roots, SELECTORS.tweetAuthor)
    : document.querySelectorAll(SELECTORS.tweetAuthor);
  const profileHandle = getCurrentProfileHandle();

  userNameBlocks.forEach((block) => {
    const handle = getHandleFromUserNameBlock(block);
    if (!handle) return;

    const isOwnProfileTweet = profileHandle && handle === profileHandle;
    const existingNoteBadge = block.querySelector(".tn-badge");
    const existingAddBadge = block.querySelector(".tn-add-badge");

    if (isOwnProfileTweet) {
      // Already shown once in the profile header - don't repeat on every one of their tweets
      if (existingNoteBadge) existingNoteBadge.remove();
      if (existingAddBadge) existingAddBadge.remove();
      return;
    }

    const hasNotes = Boolean(notesCache[handle] && notesCache[handle].length > 0);

    if (hasNotes) {
      if (existingAddBadge) existingAddBadge.remove();
      if (!existingNoteBadge) attachBadge(block, handle);
    } else {
      if (existingNoteBadge) existingNoteBadge.remove();
      if (!existingAddBadge) attachAddBadge(block, handle);
    }
  });
}

// Adds a badge to the person named in the "X reposted" line.
// data-testid="socialContext" is INSIDE the <a> wrapping the whole line, so we
// attach the badge to the anchor's parent (outside it) instead of the anchor
// itself - otherwise it clashes with X's own profile hover card.
function applyRepostBadges(roots = null) {
  const profileHandle = getCurrentProfileHandle();
  const socialContextBlocks = roots
    ? queryWithinRoots(roots, SELECTORS.repostContext)
    : document.querySelectorAll(SELECTORS.repostContext);

  socialContextBlocks.forEach((block) => {
    const anchor = block.closest(SELECTORS.profileLink);
    if (!anchor) return;

    const href = anchor.getAttribute("href");
    const handle = sanitizeHandle(href.split("/")[1]);
    if (!handle) return;

    const container = anchor.parentElement;
    if (!container) return;

    const isOwnProfileRepost = profileHandle && handle === profileHandle;
    const existingNoteBadge = container.querySelector(":scope > .tn-badge");
    const existingAddBadge = container.querySelector(":scope > .tn-add-badge");

    if (isOwnProfileRepost) {
      if (existingNoteBadge) existingNoteBadge.remove();
      if (existingAddBadge) existingAddBadge.remove();
      return;
    }

    const hasNotes = Boolean(notesCache[handle] && notesCache[handle].length > 0);

    if (hasNotes) {
      if (existingAddBadge) existingAddBadge.remove();
      if (!existingNoteBadge) attachBadge(container, handle);
    } else {
      if (existingNoteBadge) existingNoteBadge.remove();
      if (!existingAddBadge) attachAddBadge(container, handle);
    }
  });
}

// Collapses rapid, repeated calls into a single one - runs `wait` ms after the last call.
function debounce(fn, wait) {
  let timeoutId = null;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), wait);
  };
}

// Accumulates here while the MutationObserver keeps firing (until the debounce
// window closes), then everything gets processed together in a SINGLE scan pass.
let pendingAddedNodes = [];

function collectAddedElements(mutationsList) {
  const nodes = [];
  for (const mutation of mutationsList) {
    mutation.addedNodes.forEach((node) => {
      if (node.nodeType === Node.ELEMENT_NODE) nodes.push(node);
    });
  }
  return nodes;
}

const runBadgeUpdates = debounce(() => {
  const roots = pendingAddedNodes;
  pendingAddedNodes = [];

  // If nothing was actually added in this window (only removals happened),
  // there's nothing to scan - X's feed constantly removes old tweets from the
  // DOM, and none of that affects our badges.
  if (roots.length === 0) return;

  applyHighlights(roots);
  applyProfileHeaderBadge();
  applyRepostBadges(roots);
}, 150);

const observer = new MutationObserver((mutationsList) => {
  pendingAddedNodes.push(...collectAddedElements(mutationsList));
  runBadgeUpdates();
});
observer.observe(document.body, { childList: true, subtree: true });

// Finds the narrow element carrying the "@handle" text instead of the wide
// headerBlock box. Matches by text content, not class names (not exact
// equality but "includes" - X sometimes wraps text with invisible
// bidirectional-control characters, so we stay tolerant).
function findHandleLineElement(headerBlock, profileHandle) {
  const target = "@" + profileHandle.toLowerCase();
  const spans = headerBlock.querySelectorAll("span");
  let best = null;

  spans.forEach((span) => {
    const text = span.textContent.toLowerCase();
    if (!text.includes(target)) return;

    // Skip screen-reader-only copies that are visually hidden (0px)
    const rect = span.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;

    if (!best || span.textContent.length < best.textContent.length) {
      best = span;
    }
  });

  if (best) return best.parentElement || best;

  console.warn("NoteKS: couldn't find the @handle line in the profile header, falling back to the wide box.");
  return headerBlock; // fall back to the old (wide) behavior if not found
}

// Adds a single badge next to the name/handle while on a profile
// (data-testid="UserName", no hyphen - different from tweets).
//
// Unlike tweet/repost badges, this one does NOT get inserted as a child
// inside X's own DOM. X's React re-renders the profile header very
// frequently (for reasons unrelated to us), which kept wiping out an
// inline badge - even a short debounce couldn't keep up, and the constant
// remove/recreate cycle made the badge un-clickable.
//
// Instead, this badge lives in our Shadow DOM (like the tooltip/panel) and
// is just POSITIONED over the real @handle text using its live coordinates.
// React can re-render the text underneath all it wants - our badge element
// itself is never touched, so it stays clickable. We only ever reposition
// it (cheap, non-destructive), never recreate it unless the profile changes.
let profileHeaderBadgeEl = null;
let profileHeaderBadgeKind = null; // "note" or "add" - tracks which variant is currently shown

function positionBadgeNextToAnchor(badgeEl, anchorEl) {
  const rect = anchorEl.getBoundingClientRect();
  badgeEl.style.position = "absolute";
  badgeEl.style.top = `${rect.top + window.scrollY + rect.height / 2}px`;
  badgeEl.style.left = `${rect.right + window.scrollX + 6}px`;
  badgeEl.style.right = "auto";
  badgeEl.style.transform = "translateY(-50%)";
}

function applyProfileHeaderBadge() {
  const profileHandle = getCurrentProfileHandle();
  const headerBlock = document.querySelector(SELECTORS.profileHeader);

  if (!profileHandle || !headerBlock) {
    if (profileHeaderBadgeEl) {
      profileHeaderBadgeEl.remove();
      profileHeaderBadgeEl = null;
      profileHeaderBadgeKind = null;
    }
    return;
  }

  const hasNotes = Boolean(notesCache[profileHandle] && notesCache[profileHandle].length > 0);
  const desiredKind = hasNotes ? "note" : "add";
  const anchorEl = findHandleLineElement(headerBlock, profileHandle);

  if (
    !profileHeaderBadgeEl ||
    profileHeaderBadgeEl.dataset.tnHandle !== profileHandle ||
    profileHeaderBadgeKind !== desiredKind
  ) {
    if (profileHeaderBadgeEl) profileHeaderBadgeEl.remove();
    profileHeaderBadgeEl =
      desiredKind === "note" ? createNoteBadge(profileHandle) : createAddNoteBadge(profileHandle);
    profileHeaderBadgeKind = desiredKind;
    shadowRoot.appendChild(profileHeaderBadgeEl);
  }

  positionBadgeNextToAnchor(profileHeaderBadgeEl, anchorEl);
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  if (changes[STORAGE_KEY]) {
    notesCache = normalizeNotesShape(changes[STORAGE_KEY].newValue);
    applyHighlights();
    applyProfileHeaderBadge();
    applyRepostBadges();
    if (panelEl && panelHandle) renderPanel();
  }

  if (changes[SETTINGS_KEY]) {
    const newSettings = changes[SETTINGS_KEY].newValue || {};
    badgeIcon = newSettings.badgeIcon || DEFAULT_BADGE_ICON;
    applyTheme(newSettings.theme || DEFAULT_THEME);
    refreshAllBadgeIcons();
  }
});

Promise.all([loadNotes(), loadSettings()]).then(() => {
  applyHighlights();
  applyProfileHeaderBadge();
  applyRepostBadges();
});
