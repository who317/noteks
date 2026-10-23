const STORAGE_KEY = "notes";
const SETTINGS_KEY = "settings";
const DEFAULT_BADGE_ICON = { type: "text", value: "★" };
const DEFAULT_THEME = "minimalism";

// --- Error capture (for the in-popup bug report link) ---
// Records the single most recent error from THIS context into chrome.storage.local.
// content.js and background.js do the same in their own contexts, so whichever
// one actually fails, the bug report link picks it up without asking the user
// to open DevTools themselves.
const ERROR_CONTEXT = "popup";

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

// We use handles as plain object keys, so if someone types a username like
// "@__proto__" this could open the door to prototype pollution.
const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function normalizeHandle(raw) {
  const handle = raw.trim().replace(/^@/, "").toLowerCase();
  if (DANGEROUS_KEYS.has(handle)) return "";
  return handle;
}

// Migrates the old data shape ({note, createdAt}) to the current one ([{id, text, createdAt}, ...]).
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

async function getSettings() {
  const result = await chrome.storage.local.get(SETTINGS_KEY);
  return result[SETTINGS_KEY] || {};
}

async function getNotes() {
  const result = await chrome.storage.local.get(STORAGE_KEY);
  return normalizeNotesShape(result[STORAGE_KEY]);
}

// ============================================================
// ENCRYPTION (Web Crypto API: AES-256-GCM + PBKDF2)
// The password is never written to disk. Only the key derived from it is
// kept, and only in chrome.storage.session (memory-only, cleared on browser close).
// ============================================================
const LOCK_TIMEOUT_MS = 2 * 60 * 1000; // auto-lock after 2 minutes of inactivity
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
    true, // extractable - so we can store it as raw bytes in session storage
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

// Returns the key if unlocked (and not expired), otherwise null. Refreshes
// the activity timestamp on use (sliding window - locks after 2 minutes idle).
async function getUnlockedKey() {
  const result = await chrome.storage.session.get([SESSION_KEY_STORAGE, SESSION_ACTIVITY_STORAGE]);
  const rawKey = result[SESSION_KEY_STORAGE];
  const lastActivity = result[SESSION_ACTIVITY_STORAGE];

  if (!rawKey || !lastActivity) return null;
  if (Date.now() - lastActivity > LOCK_TIMEOUT_MS) {
    await lockNow();
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

async function lockNow() {
  await chrome.storage.session.remove([SESSION_KEY_STORAGE, SESSION_ACTIVITY_STORAGE]);
}

async function isEncryptionEnabled() {
  const settings = await getSettings();
  return Boolean(settings.encryption && settings.encryption.enabled);
}

// Turns encryption on for the first time: encrypts all existing notes and stores a verifier.
async function enableEncryption(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassword(password, saltBytes);
  const verifier = await encryptString(key, VERIFY_STRING);

  const notes = await getNotes();
  for (const handle of Object.keys(notes)) {
    for (const entry of notes[handle]) {
      entry.text = await encryptString(key, entry.text);
      if (entry.image) entry.image = await encryptString(key, entry.image);
    }
  }

  const settings = await getSettings();
  settings.encryption = { enabled: true, salt: bytesToBase64(saltBytes), verifier };

  await chrome.storage.local.set({ [STORAGE_KEY]: notes, [SETTINGS_KEY]: settings });
  await setUnlockedKey(key);
}

// Verifies the password (AES-GCM already rejects decryption with the wrong key) and returns the key.
async function unlockWithPassword(password) {
  const settings = await getSettings();
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

// Fully removes encryption: decrypts all notes back to plain text and stores them that way.
async function disableEncryption(password) {
  const key = await unlockWithPassword(password); // verifies + returns the key

  const notes = await getNotes();
  for (const handle of Object.keys(notes)) {
    for (const entry of notes[handle]) {
      entry.text = await decryptString(key, entry.text);
      if (entry.image) entry.image = await decryptString(key, entry.image);
    }
  }

  const settings = await getSettings();
  delete settings.encryption;

  await chrome.storage.local.set({ [STORAGE_KEY]: notes, [SETTINGS_KEY]: settings });
  await lockNow();
}

// Returns notes ready for display (decrypted). If encryption is off or there's
// no key, returns notes as-is (already plain text).
async function getDecryptedNotes(notes, key) {
  if (!key) return notes;
  const result = {};
  for (const [handle, entries] of Object.entries(notes)) {
    result[handle] = [];
    for (const entry of entries) {
      let text = entry.text;
      let image = entry.image;
      try {
        text = await decryptString(key, entry.text);
        if (entry.image) image = await decryptString(key, entry.image);
      } catch {
        text = "⚠️ Could not decrypt";
        image = undefined;
      }
      result[handle].push({ ...entry, text, image });
    }
  }
  return result;
}

async function addNote(handle, text, image) {
  const encEnabled = await isEncryptionEnabled();
  let finalText = text;
  let finalImage = image || null;

  if (encEnabled) {
    const key = await getUnlockedKey();
    if (!key) throw new Error("Unlock first to add a note");
    finalText = await encryptString(key, text);
    if (finalImage) finalImage = await encryptString(key, finalImage);
  }

  const notes = await getNotes();
  if (!notes[handle]) notes[handle] = [];
  const entry = { id: crypto.randomUUID(), text: finalText, createdAt: Date.now() };
  if (finalImage) entry.image = finalImage;
  notes[handle].push(entry);
  await chrome.storage.local.set({ [STORAGE_KEY]: notes });
}

async function deleteNote(handle, id) {
  const notes = await getNotes();
  if (!notes[handle]) return;
  notes[handle] = notes[handle].filter((entry) => entry.id !== id);
  if (notes[handle].length === 0) delete notes[handle];
  await chrome.storage.local.set({ [STORAGE_KEY]: notes });
}

// Updates an existing note's text and (optionally) its photo.
// newImage: undefined = leave the existing photo untouched, null = remove
// the photo, a data URL string = replace it with a new photo.
async function updateNote(handle, id, text, newImage) {
  const encEnabled = await isEncryptionEnabled();
  let key = null;
  if (encEnabled) {
    key = await getUnlockedKey();
    if (!key) throw new Error("Unlock first to edit a note");
  }

  const notes = await getNotes();
  const entry = (notes[handle] || []).find((e) => e.id === id);
  if (!entry) return;

  entry.text = encEnabled ? await encryptString(key, text) : text;

  if (newImage === null) {
    delete entry.image;
  } else if (newImage) {
    entry.image = encEnabled ? await encryptString(key, newImage) : newImage;
  }
  // newImage === undefined -> leave entry.image exactly as it was

  await chrome.storage.local.set({ [STORAGE_KEY]: notes });
}

// ============================================================
// THEME
// ============================================================
async function saveTheme(theme) {
  const settings = await getSettings();
  settings.theme = theme;
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-tn-theme", theme);
  document.querySelectorAll(".theme-option").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.theme === theme);
  });
}

document.querySelectorAll(".theme-option").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const theme = btn.dataset.theme;
    applyTheme(theme);
    try {
      await saveTheme(theme);
    } catch (err) {
      logError("failed to save theme", err);
    }
  });
});

// Gear icon: opens/closes the settings panel (theme + badge + security)
const settingsToggle = document.getElementById("settings-toggle");
const settingsPanel = document.getElementById("settings-panel");

settingsToggle.addEventListener("click", () => {
  const willOpen = settingsPanel.hidden;
  settingsPanel.hidden = !willOpen;
  settingsToggle.setAttribute("aria-expanded", String(willOpen));
});

// ============================================================
// BADGE APPEARANCE
// ============================================================
async function saveBadgeIcon(icon) {
  const settings = await getSettings();
  settings.badgeIcon = icon;
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

function renderBadgePreview(icon) {
  const preview = document.getElementById("badge-preview");
  preview.innerHTML = "";
  if (icon && icon.type === "image" && icon.value) {
    const img = document.createElement("img");
    img.src = icon.value; // a data URL we generated ourselves, safe
    img.alt = "";
    preview.appendChild(img);
  } else {
    preview.textContent = (icon && icon.value) || DEFAULT_BADGE_ICON.value;
  }
}

function readFileHeaderBytes(file, byteCount = 262144) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.readAsArrayBuffer(file.slice(0, byteCount));
  });
}

// Reads the real pixel dimensions straight from the PNG/JPEG header, without
// letting the browser fully decode the file. This is our defense against
// "decompression bomb" images: a tiny file can claim to be a huge (e.g.
// 50000x50000) image and crash the tab when decoded at full size.
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

// Crops and downsizes the uploaded image to a small square (keeps storage lean).
// Shared validation for any uploaded image (badge icon or note photo): checks
// declared type, file size, and (via header-only dimension sniffing, without
// letting the browser decode the full image) real pixel dimensions to guard
// against "decompression bomb" files. Returns a loaded Image ready to draw.
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

// Crops to a small square - used for the badge icon.
async function resizeImageFile(file, size = 64) {
  const img = await loadValidatedImage(file);
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  const minSide = Math.min(img.width, img.height);
  const sx = (img.width - minSide) / 2;
  const sy = (img.height - minSide) / 2;
  ctx.drawImage(img, sx, sy, minSide, minSide, 0, 0, size, size);
  return canvas.toDataURL("image/png");
}

// Keeps the original aspect ratio and just caps the longest side - used for
// photos attached to a note. JPEG output (not PNG) since photos compress
// much smaller that way, keeping storage usage reasonable.
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

document.getElementById("badge-text-save").addEventListener("click", async () => {
  const input = document.getElementById("badge-text-input");
  const value = input.value.trim();
  if (!value) return;
  const icon = { type: "text", value };
  try {
    await saveBadgeIcon(icon);
    renderBadgePreview(icon);
    input.value = "";
  } catch (err) {
    logError("failed to save badge", err);
  }
});

document.getElementById("badge-image-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    const dataUrl = await resizeImageFile(file);
    const icon = { type: "image", value: dataUrl };
    await saveBadgeIcon(icon);
    renderBadgePreview(icon);
    showBackupStatus("Badge image updated.");
  } catch (err) {
    logError("failed to process image", err);
    showBackupStatus(err.message || "Could not process the image.", true);
  }
  event.target.value = "";
});

document.getElementById("badge-reset").addEventListener("click", async () => {
  try {
    await saveBadgeIcon(DEFAULT_BADGE_ICON);
    renderBadgePreview(DEFAULT_BADGE_ICON);
  } catch (err) {
    logError("failed to reset badge", err);
  }
});

getSettings().then((settings) => {
  applyTheme(settings.theme || DEFAULT_THEME);
  renderBadgePreview(settings.badgeIcon);
});

// ============================================================
// SECURITY (encryption) UI
// ============================================================
const securityStateOff = document.getElementById("security-state-off");
const securityStateSetup = document.getElementById("security-state-setup");
const securityStateLocked = document.getElementById("security-state-locked");
const securityStateUnlocked = document.getElementById("security-state-unlocked");
const securityStatus = document.getElementById("security-status");

function showSecurityStatus(message, isError = false) {
  securityStatus.textContent = message;
  securityStatus.classList.toggle("is-error", isError);
}

function showOnlySecurityState(stateEl) {
  [securityStateOff, securityStateSetup, securityStateLocked, securityStateUnlocked].forEach((el) => {
    el.hidden = el !== stateEl;
  });
}

// Redraws the settings panel + note list + note form based on the current encryption state.
async function refreshApp() {
  const encEnabled = await isEncryptionEnabled();

  if (!encEnabled) {
    showOnlySecurityState(securityStateOff);
    document.getElementById("encryption-toggle").checked = false;
    setNoteFormLocked(false);
    const notes = await getNotes();
    updateHeaderStat(notes);
    renderNotes(notes);
    return;
  }

  const key = await getUnlockedKey();

  if (key) {
    showOnlySecurityState(securityStateUnlocked);
    setNoteFormLocked(false);
    const notes = await getNotes();
    updateHeaderStat(notes);
    const decrypted = await getDecryptedNotes(notes, key);
    renderNotes(decrypted);
  } else {
    showOnlySecurityState(securityStateLocked);
    setNoteFormLocked(true);
    const notes = await getNotes();
    updateHeaderStat(notes);
    renderLockedNotes(notes);
  }
}

// Replaces the static tagline with a real stat (how many people, how many notes).
function updateHeaderStat(notes) {
  const tagline = document.getElementById("header-tagline");
  const handles = Object.keys(notes).filter((h) => notes[h] && notes[h].length > 0);

  if (handles.length === 0) {
    tagline.textContent = "Keep personal notes on people, and get reminded when you see them again.";
    return;
  }

  const totalNotes = handles.reduce((sum, h) => sum + notes[h].length, 0);
  const peopleWord = handles.length === 1 ? "person" : "people";
  const noteWord = totalNotes === 1 ? "note" : "notes";
  tagline.textContent = `You're keeping ${totalNotes} ${noteWord} on ${handles.length} ${peopleWord}.`;
}

function setNoteFormLocked(isLocked) {
  const form = document.getElementById("note-form");
  const lockedMsg = document.getElementById("note-form-locked-msg");
  form.hidden = isLocked;
  lockedMsg.hidden = !isLocked;
}

function renderLockedNotes(notes) {
  const list = document.getElementById("notes-list");
  const emptyState = document.getElementById("empty-state");
  const countBadge = document.getElementById("notes-count-badge");
  list.innerHTML = "";

  let totalCount = 0;
  Object.values(notes).forEach((entries) => (totalCount += entries.length));

  if (totalCount === 0) {
    emptyState.style.display = "flex";
    countBadge.hidden = true;
    return;
  }

  emptyState.style.display = "none";
  countBadge.hidden = false;
  countBadge.textContent = String(totalCount);

  const li = document.createElement("li");
  li.className = "note-card locked-card";
  li.textContent = `🔒 ${totalCount} note${totalCount === 1 ? "" : "s"}, unlock to view`;
  li.addEventListener("click", () => {
    settingsPanel.hidden = false;
    settingsToggle.setAttribute("aria-expanded", "true");
    document.getElementById("unlock-password").focus();
  });
  list.appendChild(li);
}

// Toggling the switch opens/closes the password setup form (only when encryption isn't active yet)
document.getElementById("encryption-toggle").addEventListener("change", (event) => {
  if (event.target.checked) {
    showOnlySecurityState(securityStateSetup);
  } else {
    // User toggled the switch off before setting a password - just close the form
    event.target.checked = false;
    showOnlySecurityState(securityStateOff);
  }
});

document.getElementById("setup-cancel-btn").addEventListener("click", () => {
  document.getElementById("setup-password").value = "";
  document.getElementById("setup-password-confirm").value = "";
  document.getElementById("encryption-toggle").checked = false;
  showOnlySecurityState(securityStateOff);
});

document.getElementById("setup-confirm-btn").addEventListener("click", async () => {
  const pw1 = document.getElementById("setup-password").value;
  const pw2 = document.getElementById("setup-password-confirm").value;

  if (pw1.length < 6) {
    showSecurityStatus("Password must be at least 6 characters.", true);
    return;
  }
  if (pw1 !== pw2) {
    showSecurityStatus("Passwords don't match.", true);
    return;
  }

  try {
    await enableEncryption(pw1);
    document.getElementById("setup-password").value = "";
    document.getElementById("setup-password-confirm").value = "";
    showSecurityStatus("Encryption enabled, your notes are now encrypted.");
    await refreshApp();
  } catch (err) {
    logError("failed to enable encryption", err);
    showSecurityStatus("Could not enable encryption.", true);
  }
});

document.getElementById("unlock-btn").addEventListener("click", async () => {
  const pw = document.getElementById("unlock-password").value;
  if (!pw) return;

  try {
    await unlockWithPassword(pw);
    document.getElementById("unlock-password").value = "";
    showSecurityStatus("Unlocked.");
    await refreshApp();
  } catch (err) {
    showSecurityStatus(err.message || "Could not unlock.", true);
  }
});

document.getElementById("unlock-password").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    document.getElementById("unlock-btn").click();
  }
});

document.getElementById("lock-now-btn").addEventListener("click", async () => {
  await lockNow();
  showSecurityStatus("Notes locked.");
  await refreshApp();
});

document.getElementById("disable-encryption-btn").addEventListener("click", async () => {
  const pw = prompt("Enter your current password to remove encryption:");
  if (!pw) return;

  try {
    await disableEncryption(pw);
    showSecurityStatus("Encryption removed, notes are now plain text.");
    await refreshApp();
  } catch (err) {
    showSecurityStatus(err.message || "Could not remove encryption.", true);
  }
});

// ============================================================
// NOTE LIST AND FORM
// ============================================================
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
// http:// and https:// links are linkified - this also means schemes like
// "javascript:" can never become a clickable link, since they don't match
// the pattern at all.
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
    link.className = "note-link";
    link.addEventListener("click", (e) => e.stopPropagation());
    container.appendChild(link);

    lastIndex = match.index + url.length;
  }

  if (lastIndex < text.length) {
    container.appendChild(document.createTextNode(text.slice(lastIndex)));
  }
}

// Relative time like "3 days ago" - friendlier than a bare date.
// The exact date/time is still available on hover (title attribute).
function formatRelativeDate(timestamp) {
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

// Groups notes by person - a flat mixed list makes it hard to track "what did
// I write about whom", so each person gets their own little file instead.
// Collapsed by default (like folders); clicking a person expands their notes.
// expandedHandles tracks which ones are open, and persists across re-renders.
const expandedHandles = new Set();

// Replaces a note card's contents with an edit form (textarea + photo
// controls + Save/Cancel), in place - no need to track "which note is being
// edited" across re-renders, since this only lives until Save/Cancel, both
// of which trigger a fresh refreshApp() anyway.
function renderNoteEditForm(card, handle, entry) {
  card.innerHTML = "";
  card.classList.add("is-editing");

  const textarea = document.createElement("textarea");
  textarea.className = "note-edit-textarea";
  textarea.value = entry.text;
  textarea.rows = 3;
  textarea.maxLength = 500;

  // Tracks the photo for THIS edit session: starts as the note's current
  // photo (if any); becomes a new data URL if the user picks a different
  // file; becomes null if they explicitly remove it.
  let editImage = entry.image || null;
  let imageChanged = false;

  const photoRow = document.createElement("div");
  photoRow.className = "note-photo-row";

  const photoLabel = document.createElement("label");
  photoLabel.className = "file-label small";
  photoLabel.textContent = editImage ? "📷 Change photo" : "📷 Add photo";

  const photoInput = document.createElement("input");
  photoInput.type = "file";
  photoInput.accept = "image/png,image/jpeg";
  photoInput.hidden = true;
  photoLabel.appendChild(photoInput);

  const photoPreview = document.createElement("div");
  photoPreview.className = "note-photo-preview";
  photoPreview.hidden = !editImage;

  const photoPreviewImg = document.createElement("img");
  if (editImage) photoPreviewImg.src = editImage;

  const photoRemoveBtn = document.createElement("button");
  photoRemoveBtn.type = "button";
  photoRemoveBtn.className = "note-photo-remove";
  photoRemoveBtn.textContent = "×";
  photoRemoveBtn.setAttribute("aria-label", "Remove photo");

  photoPreview.append(photoPreviewImg, photoRemoveBtn);
  photoRow.append(photoLabel, photoPreview);

  photoInput.addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      editImage = await resizeNotePhoto(file);
      imageChanged = true;
      photoPreviewImg.src = editImage;
      photoPreview.hidden = false;
      photoLabel.textContent = "📷 Change photo";
    } catch (err) {
      logError("failed to process note photo", err);
    }
  });

  photoRemoveBtn.addEventListener("click", () => {
    editImage = null;
    imageChanged = true;
    photoPreview.hidden = true;
    photoInput.value = "";
    photoLabel.textContent = "📷 Add photo";
  });

  const actions = document.createElement("div");
  actions.className = "note-edit-actions";

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "mini-btn";
  saveBtn.textContent = "Save";

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "mini-btn mini-btn-secondary";
  cancelBtn.textContent = "Cancel";

  actions.append(saveBtn, cancelBtn);

  saveBtn.addEventListener("click", async () => {
    const newText = textarea.value.trim();
    if (!newText) return;
    try {
      const imageArg = imageChanged ? editImage : undefined;
      await updateNote(handle, entry.id, newText, imageArg);
      await refreshApp();
    } catch (err) {
      logError("failed to update note", err);
    }
  });

  cancelBtn.addEventListener("click", () => {
    refreshApp();
  });

  card.append(textarea, photoRow, actions);
}

function renderNotes(notes) {
  const list = document.getElementById("notes-list");
  const emptyState = document.getElementById("empty-state");
  const countBadge = document.getElementById("notes-count-badge");
  list.innerHTML = "";

  const handles = Object.keys(notes).filter((h) => notes[h] && notes[h].length > 0);

  if (handles.length === 0) {
    emptyState.style.display = "flex";
    countBadge.hidden = true;
    return;
  }
  emptyState.style.display = "none";

  const totalNotes = handles.reduce((sum, h) => sum + notes[h].length, 0);
  countBadge.hidden = false;
  countBadge.textContent = String(totalNotes);

  // Most recently noted person first
  const sortedHandles = handles.sort((a, b) => {
    const latestA = Math.max(...notes[a].map((e) => e.createdAt));
    const latestB = Math.max(...notes[b].map((e) => e.createdAt));
    return latestB - latestA;
  });

  for (const handle of sortedHandles) {
    const entries = [...notes[handle]].sort((a, b) => b.createdAt - a.createdAt);
    const isExpanded = expandedHandles.has(handle);

    const group = document.createElement("li");
    group.className = "person-group";
    if (isExpanded) group.classList.add("is-expanded");

    // A button, not a div - so it's keyboard-focusable and behaves like a
    // real disclosure control, not just a div that happens to have a click handler.
    const groupHeader = document.createElement("button");
    groupHeader.type = "button";
    groupHeader.className = "person-group-header";
    groupHeader.setAttribute("aria-expanded", String(isExpanded));

    const chevron = document.createElement("span");
    chevron.className = "person-group-chevron";
    chevron.textContent = "▸";

    const handleEl = document.createElement("span");
    handleEl.className = "note-handle";
    handleEl.textContent = "@" + handle;

    const countEl = document.createElement("span");
    countEl.className = "person-group-count";
    countEl.textContent = entries.length === 1 ? "1 note" : `${entries.length} notes`;

    groupHeader.append(chevron, handleEl, countEl);
    group.appendChild(groupHeader);

    const entriesWrap = document.createElement("div");
    entriesWrap.className = "person-group-entries";
    entriesWrap.hidden = !isExpanded;

    groupHeader.addEventListener("click", () => {
      const willExpand = entriesWrap.hidden;
      entriesWrap.hidden = !willExpand;
      groupHeader.setAttribute("aria-expanded", String(willExpand));
      group.classList.toggle("is-expanded", willExpand);
      if (willExpand) {
        expandedHandles.add(handle);
      } else {
        expandedHandles.delete(handle);
      }
    });

    entries.forEach((entry) => {
      const card = document.createElement("div");
      card.className = "note-card";

      const noteEl = document.createElement("p");
      noteEl.className = "note-text";
      renderNoteTextInto(noteEl, entry.text);

      let photoEl = null;
      if (entry.image) {
        photoEl = document.createElement("img");
        photoEl.className = "note-photo";
        photoEl.src = entry.image; // a data URL we generated ourselves, safe
        photoEl.alt = "";
        photoEl.addEventListener("click", () => openImageInNewTab(entry.image));
      }

      const footer = document.createElement("div");
      footer.className = "note-card-footer";

      const dateEl = document.createElement("span");
      dateEl.className = "note-date";
      dateEl.textContent = formatRelativeDate(entry.createdAt);
      dateEl.title = new Date(entry.createdAt).toLocaleString();

      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "edit-btn";
      editBtn.textContent = "Edit";
      editBtn.setAttribute("aria-label", `Edit note for @${handle}`);
      editBtn.addEventListener("click", () => renderNoteEditForm(card, handle, entry));

      const deleteBtn = document.createElement("button");
      deleteBtn.type = "button";
      deleteBtn.className = "delete-btn";
      deleteBtn.textContent = "Delete";
      deleteBtn.setAttribute("aria-label", `Delete note for @${handle}`);
      deleteBtn.addEventListener("click", async () => {
        try {
          await deleteNote(handle, entry.id);
          await refreshApp();
        } catch (err) {
          logError("failed to delete note", err);
        }
      });

      const btnGroup = document.createElement("div");
      btnGroup.className = "note-card-btn-group";
      btnGroup.append(editBtn, deleteBtn);

      footer.append(dateEl, btnGroup);
      if (photoEl) card.appendChild(photoEl);
      card.append(noteEl, footer);
      entriesWrap.appendChild(card);
    });

    group.appendChild(entriesWrap);
    list.appendChild(group);
  }
}

// Holds the resized photo (data URL) selected for the note currently being
// written, until the form is submitted (or cleared).
let pendingNotePhoto = null;

function showNotePhotoPreview(dataUrl) {
  const preview = document.getElementById("note-photo-preview");
  const img = document.getElementById("note-photo-preview-img");
  img.src = dataUrl;
  preview.hidden = false;
}

function clearNotePhoto() {
  pendingNotePhoto = null;
  const preview = document.getElementById("note-photo-preview");
  const img = document.getElementById("note-photo-preview-img");
  const input = document.getElementById("note-photo-input");
  preview.hidden = true;
  img.src = "";
  input.value = "";
}

document.getElementById("note-photo-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const noteStatus = document.getElementById("note-status");
  try {
    const dataUrl = await resizeNotePhoto(file);
    pendingNotePhoto = dataUrl;
    showNotePhotoPreview(dataUrl);
    noteStatus.textContent = "";
    noteStatus.classList.remove("is-error");
  } catch (err) {
    logError("failed to process note photo", err);
    noteStatus.textContent = err.message || "Could not process the photo.";
    noteStatus.classList.add("is-error");
    event.target.value = "";
  }
});

document.getElementById("note-photo-remove").addEventListener("click", clearNotePhoto);

document.getElementById("note-form").addEventListener("submit", async (event) => {
  event.preventDefault();

  const handleInput = document.getElementById("handle-input");
  const noteInput = document.getElementById("note-input");
  const noteStatus = document.getElementById("note-status");

  const handle = normalizeHandle(handleInput.value);
  const text = noteInput.value.trim();

  if (!handle || !text) {
    return;
  }

  try {
    await addNote(handle, text, pendingNotePhoto);

    handleInput.value = "";
    noteInput.value = "";
    clearNotePhoto();

    noteStatus.textContent = "";
    noteStatus.classList.remove("is-error");
    await refreshApp();
  } catch (err) {
    logError("failed to save note", err);
    noteStatus.textContent = err.message || "Could not save the note.";
    noteStatus.classList.add("is-error");
  }
});

// ============================================================
// BACKUP: EXPORT/IMPORT
// ============================================================
const backupStatus = document.getElementById("backup-status");

function showBackupStatus(message, isError = false) {
  backupStatus.textContent = message;
  backupStatus.classList.toggle("is-error", isError);
}

document.getElementById("export-notes").addEventListener("click", async () => {
  try {
    const notes = await getNotes();
    const handleCount = Object.keys(notes).length;

    if (handleCount === 0) {
      showBackupStatus("There's nothing to export.");
      return;
    }

    const encEnabled = await isEncryptionEnabled();
    if (encEnabled) {
      showBackupStatus("Export is disabled while encrypted, remove encryption first.", true);
      return;
    }

    const payload = {
      exportedAt: new Date().toISOString(),
      notes,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `noteks-backup-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    showBackupStatus(`Exported notes for ${handleCount} ${handleCount === 1 ? "person" : "people"}.`);
  } catch (err) {
    logError("export failed", err);
    showBackupStatus("Export failed.", true);
  }
});

document.getElementById("import-notes-input").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;

  try {
    const encEnabled = await isEncryptionEnabled();
    if (encEnabled) {
      showBackupStatus("Import is disabled while encrypted, remove encryption first.", true);
      event.target.value = "";
      return;
    }

    const text = await file.text();
    const parsed = JSON.parse(text);
    const importedRaw = parsed && typeof parsed === "object" && parsed.notes ? parsed.notes : parsed;
    const importedNotes = normalizeNotesShape(importedRaw);

    if (Object.keys(importedNotes).length === 0) {
      showBackupStatus("No valid notes found in the file.", true);
      return;
    }

    const currentNotes = await getNotes();
    let addedCount = 0;

    for (const [handle, entries] of Object.entries(importedNotes)) {
      if (!currentNotes[handle]) currentNotes[handle] = [];
      const existingIds = new Set(currentNotes[handle].map((entry) => entry.id));

      entries.forEach((entry) => {
        if (entry && entry.id && !existingIds.has(entry.id)) {
          currentNotes[handle].push(entry);
          existingIds.add(entry.id);
          addedCount++;
        }
      });
    }

    await chrome.storage.local.set({ [STORAGE_KEY]: currentNotes });
    await refreshApp();
    showBackupStatus(
      addedCount > 0 ? `Imported ${addedCount} new note${addedCount === 1 ? "" : "s"}.` : "No new notes found (already had them all)."
    );
  } catch (err) {
    logError("import failed", err);
    showBackupStatus("Couldn't read the file, make sure it's a valid backup.", true);
  }

  event.target.value = "";
});

// ============================================================
// REPORT & FEEDBACK (Google Form, pre-filled)
// ============================================================
// Opens a Google Form with the technical fields already filled in, so users
// don't have to know (or dig up) their browser/OS, extension version, or the
// last error - they just describe what went wrong.
const BUG_REPORT_FORM_ID = "1FAIpQLSeKY-3Yi8bFB12p9hC88QEsou8tPpki4txRGGCBbw2MJlxetg";
const BUG_REPORT_ENTRIES = {
  browserOS: "entry.1404091227",
  version: "entry.1213244534",
  errorLog: "entry.25495616",
};

// e.g. "Google Chrome on Windows". Brave deliberately reports a plain Chrome
// user agent (a privacy choice), so it needs its own navigator.brave check.
async function getBrowserAndOS() {
  const ua = navigator.userAgent;

  let os = "Unknown OS";
  if (ua.includes("Windows")) os = "Windows";
  else if (ua.includes("Mac OS X")) os = "macOS";
  else if (ua.includes("Android")) os = "Android";
  else if (ua.includes("CrOS")) os = "ChromeOS";
  else if (ua.includes("Linux")) os = "Linux";

  let browser = "Chromium-based browser";
  try {
    if (navigator.brave && typeof navigator.brave.isBrave === "function" && (await navigator.brave.isBrave())) {
      browser = "Brave";
    }
  } catch {
    // ignore - fall through to the user-agent checks below
  }
  if (browser === "Chromium-based browser") {
    if (ua.includes("Edg/")) browser = "Microsoft Edge";
    else if (ua.includes("OPR/")) browser = "Opera";
    else if (ua.includes("Chrome")) browser = "Google Chrome";
  }

  return `${browser} on ${os}`;
}

// Summarizes the most recent captured error (written by the error listeners
// in popup.js, content.js and background.js) as a single line.
async function getLastErrorSummary() {
  const result = await chrome.storage.local.get("tn_last_error");
  const err = result.tn_last_error;
  if (!err) return "No dynamic error captured";

  const where = err.source ? `${err.source}:${err.line}` : err.context || "unknown location";
  // The age matters: without it, a days-old error would look like it's related
  // to whatever feedback the user is sending right now.
  const when = err.timestamp ? ` (captured ${formatRelativeDate(err.timestamp)})` : "";
  return `[JS Error]: ${err.message} at ${where}${when}`;
}

function buildBugReportUrl(browserOS, version, errorLog) {
  const base = `https://docs.google.com/forms/d/e/${BUG_REPORT_FORM_ID}/viewform`;
  const params = new URLSearchParams({
    usp: "pp_url",
    [BUG_REPORT_ENTRIES.browserOS]: browserOS,
    [BUG_REPORT_ENTRIES.version]: version,
    [BUG_REPORT_ENTRIES.errorLog]: errorLog,
  });
  return `${base}?${params.toString()}`;
}

document.getElementById("report-feedback-link").addEventListener("click", async (event) => {
  event.preventDefault();

  try {
    const [browserOS, errorLog] = await Promise.all([getBrowserAndOS(), getLastErrorSummary()]);
    const version = `v${chrome.runtime.getManifest().version}`;
    window.open(buildBugReportUrl(browserOS, version, errorLog), "_blank");
  } catch (err) {
    logError("failed to open the report form", err);
  }
});

// Draw everything based on the current state as soon as the popup opens
refreshApp();
