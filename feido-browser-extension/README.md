# FeIDo Firefox Browser Extension

Experimental Firefox WebExtension that intercepts WebAuthn requests, derives
FIDO2 credentials from locally stored EUDI PID claims, and replies directly to
the relying party. All cryptographic operations run inside the extension by
using the Web Crypto API; the historical middleware/WebSocket bridge is kept
only as a legacy fallback and is not required during normal operation.


## Installation
The extension is intended to be loaded as a temporary add-on while it is under
development. To load it into Firefox Desktop:

1. Navigate to `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on**.
3. Select `feido-browser-extension/manifest.json`.

Firefox unloads temporary extensions after a restart, so repeat the steps above
whenever the browser restarts or the source code changes.


## Initial configuration

1. Open the popup (`browser-action` icon) and set a device-secret passphrase. The
	 extension derives a 32-byte random device secret, encrypts it with
	 PBKDF2-SHA256 (200,000 iterations) and AES-GCM, and stores only the ciphertext
	 in `browser.storage.local`.
2. With an unlocked device secret and fresh claims, WebAuthn registration and
	 authentication requests issued by relying parties will be satisfied locally
	 without contacting external middleware.

If the device secret is locked or not configured, the extension prompts the user
to unlock or set it before continuing. If claims are missing or expired, the
user is redirected back to the verifier to refresh them.


## Security (overview)

This section summarizes the security properties and operational policies of the
current prototype.

### Data protection
- Device secret and credential records are encrypted at rest with AES-GCM
	(256-bit keys).
- The encryption key is derived from the user passphrase using PBKDF2-SHA256
	with a random salt and 200,000 iterations.
- PID claims (`feidoClaims`) are encrypted separately using HKDF-SHA256 derived
	keys tied to the unlocked device secret.
- The passphrase is never stored in plaintext; the device secret is only kept in
	memory after a successful unlock and can be locked on demand.

### Export / import
- Export bundles the encrypted device secret and encrypted credential records
	into a single package.
- Export and import always rely on a user-provided passphrase; the passphrase is
	not transmitted in plaintext between UI components.
- The exported file contains only ciphertext plus salt/IV metadata (no secrets in
	cleartext).

### Claim acquisition flow
- The extension reads PID claims exclusively from the verifier page’s DOM that
	the user opens explicitly.
- The content script triggers the page’s “View content” action, performs a few
	DOM extraction attempts, and, once claims are found, normalizes and encrypts
	them before storage.
- Required attributes (e.g., issuing country) are enforced before credential
	derivation; missing attributes cause a clear error code and no derivation.
- The credential expiry date supplied by the verifier is stored as metadata
	(`feidoClaimsMeta.expiryISO`) and checked before each registration or
	authentication; expired claims trigger a `FEIDO_CLAIMS_EXPIRED` error and the
	user is redirected to refresh them.
- Origin enforcement: the content script and runtime listeners only operate on
	the exact origin `https://verifier.eudiw.dev`; messages/events from other
	origins are ignored.

### WebAuthn binding
- Derived credentials and assertions are bound to the RP ID / origin of the
	requesting site.
- Responses include the relying party’s fresh challenge to prevent replay.

### Logging and privacy
- Logs redact sensitive fields (e.g., passphrase); only diagnostic messages are
	emitted.
- The extension does not automatically close the verifier tab so users can
	review the attributes that were read.

### Limitations
- Prototype code; no automatic updates; the legacy WebSocket bridge remains for
	backward compatibility but is disabled during normal flows.
- The verifier’s page security (e.g., CSP, page integrity) is outside the
	extension’s control.
- Only tested on Firefox Desktop; other browsers require the WebExtensions
	polyfill to support the `browser.*` namespace.

