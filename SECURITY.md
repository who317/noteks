# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. If that option is not available, open an issue that says you have a security concern, without any technical details, and a private channel will be arranged.

Things that matter most for this project:

- Anything that makes note text, photos or the encryption key readable without the password.
- Any way for a web page (or text inside a note) to run script inside the extension.
- Any way for note content to leave the device.

## Supported versions

Only the latest release is supported.

## What encryption does and does not protect

See the "Encryption" section of the [README](README.md#encryption-what-it-covers-and-what-it-does-not). Usernames and creation times are intentionally not encrypted, so reports about that are known and not vulnerabilities.
