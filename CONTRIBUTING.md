# Contributing to NoteKS

Thanks for helping. This is a small, dependency-free browser extension, and the goal is to keep it that way.

## Run it locally

1. Clone the repository.
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and pick the folder that contains `manifest.json`.
3. After editing a file, click the reload icon on the extension card, then refresh the x.com tab. Content-script logs appear in that tab's DevTools console. Popup logs appear when you right-click the popup and choose **Inspect**.

Quick syntax check before you commit:

```
node --check src/popup.js && node --check src/content.js && node --check src/background.js
```

## Ground rules

These exist to protect people's notes, so please keep to them.

- **No network requests, analytics or remote code.** The extension must keep working without contacting any server. A new permission needs a clear reason in the pull request.
- **Never put note text, usernames or other page data into `innerHTML`.** Use `textContent` and `createElement`. Links are built manually and only `http(s)` is linkified.
- **Do not log or store note content in error reports.** The error capture stores a message and a code location, nothing else.
- **Keep the page selectors in one place.** All `data-testid` selectors live in the `SELECTORS` object in `src/content.js`.
- **The tooltip, panel and floating badge live in a Shadow DOM**, so the page's CSS cannot break them. Styles for them go in the `<style>` block in `src/content.js`, not in `content.css`. Remember that `[hidden]` needs the explicit rule in each stylesheet.
- **Keep the crypto in sync.** The encryption helpers exist in both `popup.js` and `content.js`.
- **Branding.** Do not use the logos, name or colors of the site the extension works on.

## Before you open a pull request

Please try these by hand on x.com (and mention what you tested):

- Add, edit and delete a note from the page panel and from the popup, with and without a photo.
- Turn encryption on, lock, unlock with a wrong and then the right password, and turn it off again.
- Export a backup (encryption off) and import it back.
- Switch through all five themes. Brutalism is meant to be monospace and unrounded.
- Check that nothing throws in the console.

Keep pull requests small and focused, and describe the user-visible change.

## Questions and bugs

[Open an issue](https://github.com/who317/noteks/issues). Please do not include the contents of your notes. For security problems, see [SECURITY.md](SECURITY.md).
