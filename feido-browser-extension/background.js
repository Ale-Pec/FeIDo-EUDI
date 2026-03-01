/*
 * Copyright (C) 2024-2026 Alessandro
 * 
 * This file is part of a Master's Thesis project.
 * Based on or modified from the original FeIDo Browser Extension.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; version 2.1 of the License.
 */

// Track the tab that initiated the current credential request so responses can be routed back.
let currentRequestTabId = null;
var lastOriginTabId = null; // to return focus after verifier flow
// Notification helper state
var __feidoNotifRegistered = false;

function ensureFeidoNotificationListener(){
  if (__feidoNotifRegistered) return;
  try {
    console.log('[feido] registering notifications onClicked listener');
    browser.notifications.onClicked.addListener((notifId) => {
      console.log('[feido] notification clicked:', notifId);
      try {
        if (String(notifId).startsWith('feido_locked')) {
          // Open the popup page (as a tab) so user can unlock
          const url = browser.runtime.getURL('popup.html');
          browser.tabs.create({ url });
        }
      } catch (e) { console.warn('[feido] notification click handler error', e && e.message); }
    });
    __feidoNotifRegistered = true;
  } catch (e) { console.warn('[feido] cannot register notifications listener', e && e.message); }
}

function notifyDeviceSecretLocked(){
  try {
    ensureFeidoNotificationListener();
    const id = 'feido_locked_' + Date.now();
    const opts = {
      type: 'basic',
      title: 'FeIDo — device secret locked',
      message: 'Your FeIDo device secret is locked. Click this notification to open the extension and unlock.',
      // iconUrl optional; fall back to extension icon
      iconUrl: browser.runtime.getURL('feido_qr.png')
    };
    if (browser.notifications && typeof browser.notifications.create === 'function') {
      browser.notifications.create(id, opts).then(()=>{
        // Also open the popup as a visible fallback shortly after creation to ensure user sees UI
        try { setTimeout(()=>{ notifyDeviceSecretLockedFallback(); }, 800); } catch(e){}
      }).catch((err)=>{ console.warn('[feido] notification create failed', err && err.message); notifyDeviceSecretLockedFallback(); });
    } else {
      // notifications not available: open popup as fallback
      notifyDeviceSecretLockedFallback();
    }
  } catch (e) { console.warn('[feido] notifyDeviceSecretLocked failed', e && e.message); }
}

// Defensive fallback: if notifications API is not available (e.g. manifest missing permission or older hosts),
// open the popup page as a tab to prompt the user to unlock.
function notifyDeviceSecretLockedFallback(){
  try {
    const url = browser.runtime.getURL('popup.html');
    // Try to open as a compact popup window first
    if (browser.windows && typeof browser.windows.create === 'function') {
      browser.windows.create({ url, type: 'popup', width: 420, height: 640 }).then(()=>{
      }).catch((e)=>{
        console.warn('[feido] popup window create failed, falling back to tab:', e && e.message);
        // Fallback to tab
        try { browser.tabs.create({ url }).then(()=>{ }).catch(()=>{}); } catch(_){}
      });
    } else {
      // windows API not available: fallback to tab
      try { browser.tabs.create({ url }).then(()=>{ }).catch(()=>{}); } catch(_){}
    }
  } catch(e) { /* ignore */ }
}

// Open the popup UI so the user can configure the device secret
async function openDeviceSecretSetupUI(){
  try {
    const url = browser.runtime.getURL('popup.html');
    if (browser.windows && typeof browser.windows.create === 'function') {
      await browser.windows.create({ url, type: 'popup', width: 420, height: 640 });
    } else {
      await browser.tabs.create({ url });
    }
  } catch (e) {
    console.warn('[feido] openDeviceSecretSetupUI failed, falling back to notify:', e && e.message);
    try { notifyDeviceSecretLockedFallback(); } catch(_) {}
  }
}

// Check whether an encrypted device secret already exists in storage
async function deviceSecretExists(){
  try {
    const st = await browser.storage.local.get('feidoDeviceSecretEnc');
    const enc = st && st.feidoDeviceSecretEnc;
    return !!(enc && enc.ct && enc.ct.length);
  } catch (e) {
    console.warn('[feido] deviceSecretExists check failed:', e && e.message);
    return false;
  }
}

// listen for sendMessage requests from content script
browser.runtime.onMessage.addListener(interceptAndHandleLocally);

function createFeidoError(code, message){
  const err = new Error(message || code);
  err.code = code;
  return err;
}

function isDeviceSecretLockedError(err){
  if (!err) return false;
  if (err.code === 'FEIDO_DEVICE_SECRET_LOCKED') return true;
  const msg = (err && err.message) ? String(err.message).toLowerCase() : '';
  return msg.includes('feido_device_secret_locked');
}

function isDeviceSecretMissingError(err){
  if (!err) return false;
  if (err.code === 'FEIDO_DEVICE_SECRET_MISSING') return true;
  const msg = (err && err.message) ? String(err.message).toLowerCase() : '';
  return msg.includes('feido_device_secret_missing');
}

function isDeviceSecretUnlocked(){
  try {
    if (getDeviceSecret._unlockedKey && typeof getDeviceSecret._unlockedKey === 'object') return true;
    if (typeof getDeviceSecret._unlocked === 'object' && getDeviceSecret._unlocked instanceof Uint8Array && getDeviceSecret._unlocked.length) return true;
  } catch (_) {}
  return false;
}

function parseExpiryFromMeta(meta){
  if (!meta || typeof meta !== 'object') return { iso: null, date: null, invalid: false };
  const raw = (typeof meta.expiryISO === 'string') ? meta.expiryISO.trim() : '';
  if (!raw) return { iso: null, date: null, invalid: false };
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return { iso: raw, date: null, invalid: true };
  }
  return { iso: raw, date: parsed, invalid: false };
}

const __mergeCheckEncoder = new TextEncoder();
const MERGE_CHECK_MESSAGE = __mergeCheckEncoder.encode('feido-merge-check-v1');

function buffersEqual(a, b){
  if (a === b) return true;
  if (!a || !b) return false;
  const lenA = a.length >>> 0;
  const lenB = b.length >>> 0;
  if (lenA !== lenB) return false;
  for (let i = 0; i < lenA; i++){
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function digestDeviceSecretFromRaw(rawBytes){
  if (!rawBytes) throw new Error('missing_device_secret');
  const key = await crypto.subtle.importKey('raw', rawBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, MERGE_CHECK_MESSAGE);
  return new Uint8Array(sig);
}

async function digestDeviceSecretFromKey(secretKey){
  if (!secretKey) throw new Error('missing_device_secret_key');
  const sig = await crypto.subtle.sign('HMAC', secretKey, MERGE_CHECK_MESSAGE);
  return new Uint8Array(sig);
}

async function loadFreshClaimsOrThrow(flowName = 'registration'){
  const prefix = flowName || 'registration';
  const metaForSub = { substep: true };
  // Sub-step 1: storage get
  const store = FeidoMetrics ? await FeidoMetrics.measureAsync(`${prefix}.loadClaims.storageGet`, () => browser.storage.local.get(['feidoClaims', 'feidoClaimsMeta']), metaForSub) : await browser.storage.local.get(['feidoClaims', 'feidoClaimsMeta']);

  // Sub-step 2: parsing claims and meta
  let claims, meta;
  if (FeidoMetrics) {
    const parseToken = FeidoMetrics.start(`${prefix}.loadClaims.parseClaimsMeta`, metaForSub);
    const encClaims = (store.feidoClaims && typeof store.feidoClaims === 'object') ? store.feidoClaims : null;
    meta = (store.feidoClaimsMeta && typeof store.feidoClaimsMeta === 'object') ? store.feidoClaimsMeta : null;
    FeidoMetrics.end(parseToken);
    
    // Sub-step 2.5: decrypt claims if encrypted
    if (encClaims) {
      const decryptToken = FeidoMetrics.start(`${prefix}.loadClaims.decryptClaims`, metaForSub);
      try {
        claims = await decryptClaimsWithDeviceSecret(encClaims);
        FeidoMetrics.end(decryptToken, { outcome: 'ok' });
      } catch (e) {
        FeidoMetrics.end(decryptToken, { outcome: 'error', error: e && (e.message || String(e)) });
        throw e;
      }
    } else {
      claims = null;
    }
  } else {
    const encClaims = (store.feidoClaims && typeof store.feidoClaims === 'object') ? store.feidoClaims : null;
    meta = (store.feidoClaimsMeta && typeof store.feidoClaimsMeta === 'object') ? store.feidoClaimsMeta : null;
    
    // Decrypt claims if encrypted
    if (encClaims) {
      claims = await decryptClaimsWithDeviceSecret(encClaims);
    } else {
      claims = null;
    }
  }

  if (!claims) {
    throw createFeidoError('FEIDO_CLAIMS_MISSING', 'feido_claims_missing');
  }

  // Sub-step 3: parse expiry
  const expiry = FeidoMetrics ? await FeidoMetrics.measureAsync(`${prefix}.loadClaims.parseExpiry`, () => parseExpiryFromMeta(meta), metaForSub) : parseExpiryFromMeta(meta);

  // Sub-step 4: expiry checks
  if (FeidoMetrics) {
  const checkToken = FeidoMetrics.start(`${prefix}.loadClaims.expiryChecks`, metaForSub);
    if (expiry.invalid) {
      const err = createFeidoError('FEIDO_CLAIMS_EXPIRED', 'feido_claims_expiry_invalid');
      err.expiryISO = expiry.iso;
      FeidoMetrics.end(checkToken, { outcome: 'error', error: 'expiry_invalid' });
      throw err;
    }
    if (expiry.date && Date.now() >= expiry.date.getTime()) {
      const err = createFeidoError('FEIDO_CLAIMS_EXPIRED', 'feido_claims_expired');
      err.expiryISO = expiry.iso;
      FeidoMetrics.end(checkToken, { outcome: 'error', error: 'expiry_expired' });
      throw err;
    }
    FeidoMetrics.end(checkToken, { outcome: 'ok' });
  } else {
    if (expiry.invalid) {
      const err = createFeidoError('FEIDO_CLAIMS_EXPIRED', 'feido_claims_expiry_invalid');
      err.expiryISO = expiry.iso;
      throw err;
    }
    if (expiry.date && Date.now() >= expiry.date.getTime()) {
      const err = createFeidoError('FEIDO_CLAIMS_EXPIRED', 'feido_claims_expired');
      err.expiryISO = expiry.iso;
      throw err;
    }
  }

  return { claims, meta, expiryISO: expiry.iso, expiryDate: expiry.date };
}

// Main handler for intercepted credential messages coming from the content script
async function interceptAndHandleLocally(msg, sender){
  try {
    // Redact sensitive fields before logging
    const safeMsg = (msg && typeof msg === 'object') ? Object.assign({}, msg) : msg;
    if (safeMsg && safeMsg.passphrase) safeMsg.passphrase = '[REDACTED]';
  } catch (e) {
    // ignore
  }
  if (msg && msg.opType === 'feido.userFlow.event') {
    const payload = msg.payload ? Object.assign({}, msg.payload) : {};
    if (!payload.reqId && msg.reqId) payload.reqId = msg.reqId;
    if (!payload.flow && msg.flow) payload.flow = msg.flow;
    recordUserFlowEvent(payload);
    return { ok: true };
  }
  // Handle internal control messages originating from extension UI (popup)
  // so the popup receives a direct response even though we also have a
  // dedicated runtime.onMessage listener later. Also ignore messages that do
  // not originate from a tab (e.g. popup/background) so we don't treat them
  // as credential requests and accidentally open the WebSocket fallback.
  if (msg && msg.action) {
    console.log('[feido] intercept: handling internal action message', msg.action);
    try {
      // Handler to encrypt claims from content scripts
      if (msg.action === 'feido.encryptClaims') {
        if (!msg.claims || typeof msg.claims !== 'object') {
          return { ok: false, error: 'missing_claims' };
        }
        try {
          const encrypted = await encryptClaimsWithDeviceSecret(msg.claims);
          return { ok: true, encrypted };
        } catch (e) {
          const errMsg = (e && e.message) ? String(e.message) : String(e);
          return { ok: false, error: errMsg };
        }
      }
      if (msg.action === 'feido.setPassphrase'){
        if (!msg.passphrase) throw new Error('missing_passphrase');
        // Create device secret only if it does not already exist. Overwriting is disallowed.
        await setDeviceSecretWithPassphrase(msg.passphrase);
        return { ok: true };
      }
      // Export everything: encrypted device secret + encrypted credential records (credentials encrypted with passphrase)
      if (msg.action === 'feido.exportAll'){
        const pass = msg.passphrase;
        if (!pass) return { ok: false, error: 'missing_passphrase' };
        try {
          const st = await browser.storage.local.get(null);
          const deviceEnc = st.feidoDeviceSecretEnc || null;
          const creds = {};
          for (const k of Object.keys(st)){
            if (k && k.startsWith('feidoCreds_')) creds[k] = st[k];
          }
          const credsEnc = await encryptJsonWithPassphrase(creds, pass);
          return { ok: true, package: { deviceEnc, credsEnc } };
        } catch (e) {
          const errName = (e && e.name) ? String(e.name) : '';
          const errMsg = (e && e.message) ? String(e.message) : String(e);
          const errMsgLower = errMsg.toLowerCase();
          const isDomException = (typeof DOMException !== 'undefined' && e instanceof DOMException && e.name === 'OperationError');
          if (errName === 'OperationError' || isDomException || errMsgLower.includes('operation failed') || errMsgLower.includes('authentication tag')) {
            return { ok: false, error: 'wrong_passphrase' };
          }
          return { ok: false, error: errMsg };
        }
      }
      if (msg.action === 'feido.importAll'){
        // Expect { package: { deviceEnc, credsEnc }, passphrase }
        const pkg = msg.package;
        const pass = msg.passphrase;
        const merge = !!msg.merge;
        if (!pkg) return { ok: false, error: 'missing_package' };
        if (!pass) return { ok: false, error: 'missing_passphrase' };
        try {
          const res = await importAllPackage(pkg, pass, merge);
          return Object.assign({ ok: true }, res);
        } catch (e) {
          const code = (e && e.code) ? String(e.code) : null;
          const message = (e && e.message) ? String(e.message) : String(e);
          return { ok: false, error: code || message, message };
        }
      }
      if (msg.action === 'feido.unlock'){
        if (!msg.passphrase) throw new Error('missing_passphrase');
        await unlockDeviceSecret(msg.passphrase);
        if (msg.reqId) {
          recordUserFlowEvent({ reqId: msg.reqId, flow: msg.flow || null, event: 'deviceSecret.unlocked' });
        }
        return { ok: true };
      }
      if (msg.action === 'feido.lock'){
        lockDeviceSecret();
        return { ok: true };
      }
      if (msg.action === 'feido.ping'){
        const st = await browser.storage.local.get('feidoDeviceSecretEnc');
        const enc = st && st.feidoDeviceSecretEnc;
        const exists = !!(enc && enc.ct);
        // Consider the secret unlocked if we have the non-exportable CryptoKey cached (_unlockedKey).
        // For compatibility, also accept the legacy raw Uint8Array stored in _unlocked (should be cleared in modern flows).
        const unlocked = !!getDeviceSecret._unlockedKey || (typeof getDeviceSecret._unlocked === 'object' && getDeviceSecret._unlocked instanceof Uint8Array);
        return { ok: true, exists, unlocked };
      }
      if (msg.action === 'feido.changePassphrase'){
        // Expect { currentPassphrase, newPassphrase }
        if (!msg.newPassphrase) throw new Error('missing_new_passphrase');
        await changeDevicePassphrase(msg.currentPassphrase, msg.newPassphrase);
        return { ok: true };
      }
      if (msg.action === 'feido.metrics.get'){
        const metrics = FeidoMetrics ? FeidoMetrics.getHistory() : [];
        return { ok: true, metrics };
      }
      if (msg.action === 'feido.metrics.clear'){
        if (FeidoMetrics) FeidoMetrics.clear();
        return { ok: true };
      }

    } catch (e) {
      const errMsg = (e && e.message) ? String(e.message) : String(e);
      return { ok: false, error: errMsg };
    }
  }
  if (!sender || !sender.tab || typeof sender.tab.id !== 'number') {
    console.log('[feido] intercept: ignoring message without sender.tab');
    return;
  }
  currentRequestTabId = sender.tab.id;

  if (msg.type === 'credentials.create') {
    const metricsMeta = metricsMetaForRequest(msg, 'registration');
    if (FeidoMetrics && typeof FeidoMetrics.prepareForAttempt === 'function') {
      FeidoMetrics.prepareForAttempt('registration', metricsMeta);
    } else if (FeidoMetrics) {
      FeidoMetrics.clear(); // legacy fallback
    }
    // Remember the currently active tab so we can return focus later
    try{
      const tabs = await browser.tabs.query({active: true, currentWindow: true});
      if (Array.isArray(tabs) && tabs.length) lastOriginTabId = tabs[0].id;
    }catch(e){}
    const flowMeta = {};
    if (typeof msg.origin === 'string') flowMeta.origin = msg.origin;
    if (metricsMeta && metricsMeta.rpId) flowMeta.rpId = metricsMeta.rpId;
    recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'extension.intercepted', meta: flowMeta });
    const totalToken = FeidoMetrics ? FeidoMetrics.start('registration.total', metricsMeta) : null;
  // Ensure claims exist and are fresh (not expired)
    let claimsCtx;
    try {
  claimsCtx = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.loadClaims', () => loadFreshClaimsOrThrow('registration'), metricsMeta) : await loadFreshClaimsOrThrow('registration');
      recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'claims.loaded', meta: flowMeta });
    } catch (e) {
      recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'abort', error: e && (e.code || e.message || String(e)), meta: flowMeta });
      if (FeidoMetrics && totalToken) FeidoMetrics.end(totalToken, { outcome: 'error', error: e && (e.code || e.message || String(e)) });
      
      // If device secret is locked, prompt user to unlock instead of redirecting to verifier
      if (isDeviceSecretLockedError(e)) {
        console.warn('[feido] device secret locked: prompting user to unlock');
        try { notifyDeviceSecretLocked(); } catch(_) {}
        const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_LOCKED';
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret locked. Please unlock the extension to proceed.' } });
        return;
      }
      
      // If device secret is not configured, prompt user to set it up first
      if (isDeviceSecretMissingError(e)) {
        console.warn('[feido] device secret missing: prompting user to configure');
        await openDeviceSecretSetupUI();
        const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_MISSING';
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret not configured. Please set a passphrase first.' } });
        return;
      }
      
      if (e && e.code === 'FEIDO_CLAIMS_MISSING') {
        console.warn('[feido] feidoClaims assenti: redirect a /custom-request/create');
      } else if (e && e.code === 'FEIDO_CLAIMS_EXPIRED') {
        console.warn('[feido] feidoClaims scadute: redirect a /custom-request/create');
      } else {
        console.warn('[feido] verifica feidoClaims fallita:', e && e.message);
      }
      const secretExists = await deviceSecretExists();
      const secretUnlocked = isDeviceSecretUnlocked();

      if (secretExists && !secretUnlocked) {
        console.warn('[feido] device secret exists but locked while claims missing/expired; prompting unlock');
        try { notifyDeviceSecretLocked(); } catch(_) {}
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: 'FEIDO_DEVICE_SECRET_LOCKED', message: 'Device secret locked. Please unlock the extension to proceed.' } });
        return;
      }

      if (!secretExists) {
        console.warn('[feido] device secret not configured while claims missing/expired; prompting setup before redirect');
        await openDeviceSecretSetupUI();
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: 'FEIDO_DEVICE_SECRET_MISSING', message: 'Device secret not configured. Please set a passphrase first.' } });
        return;
      }

      await redirectToVerifier();
      return;
    }
    // Derive keys from the local VC and build the PublicKeyCredential response
    try {
      const derivation = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation', () => deriveAttestationFromVC(msg.opts.publicKey, msg.origin, msg.originalChallenge, claimsCtx), metricsMeta) : await deriveAttestationFromVC(msg.opts.publicKey, msg.origin, msg.originalChallenge, claimsCtx);
      recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'attestation.derived', meta: flowMeta });
      const proto = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.buildResponse', () => buildAttestationReturn(derivation.rawId, derivation.clientDataJSON, derivation.attestationObject), metricsMeta) : await buildAttestationReturn(derivation.rawId, derivation.clientDataJSON, derivation.attestationObject);
      const forwardPayload = { data: new Blob([proto]) };
      if (FeidoMetrics) {
        await FeidoMetrics.measureAsync('registration.forwardToContent', () => returnedForwardToOverwriteJs(forwardPayload, msg.reqId, 'credentials.create', 'registration'), metricsMeta);
      } else {
        await returnedForwardToOverwriteJs(forwardPayload, msg.reqId, 'credentials.create', 'registration');
      }
      recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'response.forwarded', meta: flowMeta });
      if (FeidoMetrics && totalToken) FeidoMetrics.end(totalToken, { outcome: 'ok' });
      recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'complete', meta: flowMeta });
      // Auto-export metrics to file after successful registration
      if (FeidoMetrics) {
        console.log('[feido-metrics] auto-exporting registration metrics');
        await FeidoMetrics.exportToFile(`feido-registration-${Date.now()}.json`);
        FeidoMetrics.clear(); // reset history so the next flow starts fresh
      }
    } catch (e) {
      recordUserFlowEvent({ reqId: msg.reqId, flow: 'registration', event: 'abort', error: e && (e.code || e.message || String(e)), meta: flowMeta });
      if (FeidoMetrics && totalToken) FeidoMetrics.end(totalToken, { outcome: 'error', error: e && (e.code || e.message || String(e)) });
      console.warn('[feido] derivazione locale non riuscita:', e && e.message);
      // If the device secret exists but is encrypted and locked, inform the page so
      // the UI can prompt the user to unlock the extension rather than redirecting
      // to the verifier.
      try {
        if (isDeviceSecretLockedError(e)) {
          try { notifyDeviceSecretLocked(); } catch(_) {}
          const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_LOCKED';
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret locked' } });
          return;
        }
        if (isDeviceSecretMissingError(e)) {
          const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_MISSING';
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret missing; please set a passphrase' } });
          return;
        }
        if (e && e.code === 'FEIDO_ISSUING_COUNTRY_MISSING') {
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: e.code, message: 'Issuing country missing; open the verifier page and reveal all attributes before proceeding' } });
          return;
        }
        if (e && e.code === 'FEIDO_CLAIMS_MISSING') {
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: e.code, message: 'Claims missing; open the verifier page to capture them before proceeding' } });
          return;
        }
        if (e && e.code === 'FEIDO_CLAIMS_EXPIRED') {
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: e.code, message: 'Claims expired; open the verifier page to refresh them before proceeding' } });
        }
      } catch (se) {
        console.warn('[feido] error sending feido.error message:', se && se.message);
      }
      await redirectToVerifier();
    }
    return;
  }

  if (msg.type === 'credentials.get') {
    const flow = 'login';
    const metricsMeta = metricsMetaForRequest(msg, flow);
    if (FeidoMetrics && typeof FeidoMetrics.prepareForAttempt === 'function') {
      FeidoMetrics.prepareForAttempt(flow, metricsMeta);
    } else if (FeidoMetrics) {
      FeidoMetrics.clear();
    }
    // Remember the currently active tab so we can return focus later
    try{
      const tabs = await browser.tabs.query({active: true, currentWindow: true});
      if (Array.isArray(tabs) && tabs.length) lastOriginTabId = tabs[0].id;
    }catch(e){}
    const flowMeta = {};
    if (typeof msg.origin === 'string') flowMeta.origin = msg.origin;
    if (metricsMeta && metricsMeta.rpId) flowMeta.rpId = metricsMeta.rpId;
    recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'extension.intercepted', meta: flowMeta });
    const totalToken = FeidoMetrics ? FeidoMetrics.start(`total.${flow}`, metricsMeta) : null;
    let claimsCtx;
    try {
  claimsCtx = FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.loadClaims`, () => loadFreshClaimsOrThrow(flow), metricsMeta) : await loadFreshClaimsOrThrow(flow);
      recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'claims.loaded', meta: flowMeta });
    } catch (e) {
      recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'abort', error: e && (e.code || e.message || String(e)), meta: flowMeta });
      if (FeidoMetrics && totalToken) FeidoMetrics.end(totalToken, { outcome: 'error', error: e && (e.code || e.message || String(e)) });
      
      // If device secret is locked, prompt user to unlock instead of redirecting to verifier
      if (isDeviceSecretLockedError(e)) {
        console.warn('[feido] device secret locked (get): prompting user to unlock');
        try { notifyDeviceSecretLocked(); } catch(_) {}
        const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_LOCKED';
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret locked. Please unlock the extension to proceed.' } });
        return;
      }
      
      // If device secret is not configured, prompt user to set it up first
      if (isDeviceSecretMissingError(e)) {
        console.warn('[feido] device secret missing (get): prompting user to configure');
        await openDeviceSecretSetupUI();
        const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_MISSING';
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret not configured. Please set a passphrase first.' } });
        return;
      }
      
      if (e && e.code === 'FEIDO_CLAIMS_MISSING') {
        console.warn('[feido] feidoClaims assenti (get): redirect a /custom-request/create');
      } else if (e && e.code === 'FEIDO_CLAIMS_EXPIRED') {
        console.warn('[feido] feidoClaims scadute (get): redirect a /custom-request/create');
      } else {
        console.warn('[feido] verifica feidoClaims fallita (get):', e && e.message);
      }
      const secretExists = await deviceSecretExists();
      const secretUnlocked = isDeviceSecretUnlocked();

      if (secretExists && !secretUnlocked) {
        console.warn('[feido] device secret exists but locked while claims missing/expired (get); prompting unlock');
        try { notifyDeviceSecretLocked(); } catch(_) {}
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: 'FEIDO_DEVICE_SECRET_LOCKED', message: 'Device secret locked. Please unlock the extension to proceed.' } });
        return;
      }

      if (!secretExists) {
        console.warn('[feido] device secret not configured while claims missing/expired (get); prompting setup before redirect');
        await openDeviceSecretSetupUI();
        sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: 'FEIDO_DEVICE_SECRET_MISSING', message: 'Device secret not configured. Please set a passphrase first.' } });
        return;
      }

      await redirectToVerifier();
      return;
    }
    try {
      const assertion = FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.buildAssertion`, () => buildAssertionFromVC(msg.opts.publicKey, msg.origin, msg.originalChallenge, claimsCtx), metricsMeta) : await buildAssertionFromVC(msg.opts.publicKey, msg.origin, msg.originalChallenge, claimsCtx);
      recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'assertion.derived', meta: flowMeta });
      const proto = FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.buildResponse`, () => buildAssertionReturn(assertion.rawId, assertion.clientDataJSON, assertion.authenticatorData, assertion.signature, assertion.userHandle), metricsMeta) : await buildAssertionReturn(assertion.rawId, assertion.clientDataJSON, assertion.authenticatorData, assertion.signature, assertion.userHandle);
      const forwardPayload = { data: new Blob([proto]) };
      if (FeidoMetrics) {
        await FeidoMetrics.measureAsync(`${flow}.forwardToContent`, () => returnedForwardToOverwriteJs(forwardPayload, msg.reqId, 'credentials.get', flow), metricsMeta);
      } else {
        returnedForwardToOverwriteJs(forwardPayload, msg.reqId, 'credentials.get', flow);
      }
      recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'response.forwarded', meta: flowMeta });
      if (FeidoMetrics && totalToken) FeidoMetrics.end(totalToken, { outcome: 'ok' });
      recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'complete', meta: flowMeta });
      // Auto-export metrics to file after successful login
      if (FeidoMetrics) {
        console.log('[feido-metrics] auto-exporting login metrics');
        await FeidoMetrics.exportToFile(`feido-login-${Date.now()}.json`);
        FeidoMetrics.clear(); // reset history so the next flow starts fresh
      }
    } catch (e) {
      recordUserFlowEvent({ reqId: msg.reqId, flow, event: 'abort', error: e && (e.code || e.message || String(e)), meta: flowMeta });
      if (FeidoMetrics && totalToken) FeidoMetrics.end(totalToken, { outcome: 'error', error: e && (e.code || e.message || String(e)) });
      console.warn('[feido] get locale non riuscito:', e && e.message);
      try {
        if (isDeviceSecretLockedError(e)) {
          try { notifyDeviceSecretLocked(); } catch(_) {}
          const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_LOCKED';
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret locked' } });
          return;
        }
        if (isDeviceSecretMissingError(e)) {
          const errCode = (e && e.code) ? e.code : 'FEIDO_DEVICE_SECRET_MISSING';
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: errCode, message: 'Device secret missing; please set a passphrase' } });
          return;
        }
        if (e && e.code === 'FEIDO_ISSUING_COUNTRY_MISSING') {
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: e.code, message: 'Issuing country missing; open the verifier page and reveal all attributes before proceeding' } });
          return;
        }
        if (e && e.code === 'FEIDO_CLAIMS_MISSING') {
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: e.code, message: 'Claims missing; open the verifier page to capture them before proceeding' } });
          return;
        }
        if (e && e.code === 'FEIDO_CLAIMS_EXPIRED') {
          sendMessage({ reqId: msg.reqId, opType: 'feido.error', payload: { error: e.code, message: 'Claims expired; open the verifier page to refresh them before proceeding' } });
        }
      } catch (se) {
        console.warn('[feido] error sending feido.error message:', se && se.message);
      }
      await redirectToVerifier();
    }
    return;
  }

  // Handle notification from content script that feidoClaims are stored
  if (msg.type === 'feidoClaimsStored'){
    try{
      // Validate sender origin: only acknowledge if coming from the expected verifier origin
      const allowedOrigin = 'https://verifier.eudiw.dev';
      let senderUrl = '';
      try { senderUrl = (sender && sender.tab && sender.tab.url) || ''; } catch(_) {}
      let originOk = false;
      if (senderUrl) {
        try {
          const u = new URL(senderUrl);
          const origin = u.origin;
          originOk = (origin === allowedOrigin);
        } catch(_) { originOk = false; }
      }
      if (!originOk){
        console.warn('[feido] feidoClaimsStored ignored: unexpected sender origin', senderUrl);
        return;
      }
      // Do not redirect or close the verifier tab automatically; keep it open so the user can review the retrieved attributes.
      // Still retain `lastOriginTabId` in case a later manual action needs to focus that tab.
    }catch(e){ console.warn('[feido] error handling feidoClaimsStored', e && e.message); }
    return;
  }

  // Fallback: use the legacy WebSocket bridge for get/login flows or when credentials.create is unsupported
  var proto = await buildCredentials(msg);
  let socket = new WebSocket("ws://localhost:11111");
  socket.onopen = function(e) {
    socket.send(proto);
  };
  socket.onmessage = function(event) {
    const flow = msg.type === 'credentials.get' ? 'login' : 'registration';
    returnedForwardToOverwriteJs(event, msg.reqId, msg.type, flow);
  };
}

// Minimal VC-based FIDO2 derivation inside the extension (fmt: none)
async function deriveAttestationFromVC(pubKeyOpts, origin, expectedChallengeStr, claimsContext){
  const metaForSub = { substep: true };
  // Expect pubKeyOpts: challenge(ArrayBuffer), rp: {id}, user: {id, displayName}
  const rpId = effectiveRpIdFrom(pubKeyOpts, origin);
  const challengeField = expectedChallengeStr || ((typeof pubKeyOpts.challenge === 'string') ? pubKeyOpts.challenge : null);
  const challenge = challengeField ? new Uint8Array(0) : toBytes(pubKeyOpts.challenge); // Normalize to Uint8Array when not a string

  // Load canonical claims from storage; require callers to provide them via feidoClaims
  const ctx = (claimsContext && claimsContext.claims) ? claimsContext : await loadFreshClaimsOrThrow('registration');
  const claims = ctx.claims;
  const payload = { vc: { credentialSubject: extractCanonicalFromClaims(claims) } };

  const subject = (payload.vc && payload.vc.credentialSubject) || {};
  const issuing = subject.issuingCountry || subject.issuing_country || '';
  if (!issuing) {
    const err = new Error('issuing_country_missing');
    err.code = 'FEIDO_ISSUING_COUNTRY_MISSING';
    throw err;
  }

  const cs = (payload.vc && payload.vc.credentialSubject) || {};
  const givenName = cs.givenName || cs.given_name || '';
  const familyName = cs.familyName || cs.family_name || '';
  const birthDate = cs.birthDate || cs.birthdate || cs.birth_date || '';
  const birthPlace = cs.birthPlace || cs.place_of_birth || '';
  const issuingCountry = cs.issuingCountry || cs.issuing_country || '';

  // Deterministic KDF (HMAC-SHA256 with fixed key) – dev only
  const enc = new TextEncoder();
  // If a digest is provided, bind KDF to it; else build canonical string from fields
  const msg = `${rpId}|${givenName}|${familyName}|${birthDate}|${birthPlace}|${issuingCountry}`;
  // Device-bound KDF: use a per-device random secret as HMAC key
  // Use non-exportable CryptoKey derived from device secret to avoid exposing raw bytes
  const hmacKey = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.getDeviceSecretKey', () => getDeviceSecretKey(), metaForSub) : await getDeviceSecretKey();
  const mac = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.hmacSign', () => crypto.subtle.sign('HMAC', hmacKey, enc.encode(`${msg}`)), metaForSub) : await crypto.subtle.sign('HMAC', hmacKey, enc.encode(`${msg}`));
  let d = new Uint8Array(mac).slice(0,32);
  // Clamp into [1, n-1] for P-256 using BigInt to satisfy WebCrypto key import requirements
  const N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  let di = bytesToBigInt(d);
  di = (di % (N - 1n)) + 1n; // ensure 1..n-1
  d = bigIntToBytes(di, 32);  // private key bytes

  const { xBytes, yBytes } = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.p256PublicFromPrivate', () => p256PublicFromPrivate(d), metaForSub) : p256PublicFromPrivate(d);

  // Deterministic credId derived from VC + rpId + user (first 16 bytes)
  const credId = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.deriveCredentialId', () => deriveCredentialId(rpId, payload, pubKeyOpts), metaForSub) : await deriveCredentialId(rpId, payload, pubKeyOpts);

  // Persist mapping for login (store userHandle if provided)
  const userHandle = toBytes(pubKeyOpts.user && pubKeyOpts.user.id);
  await (FeidoMetrics ? FeidoMetrics.measureAsync('registration.deriveAttestation.saveCredentialRecord', () => saveCredentialRecord(rpId, credId, { signCount: 0, userHandle }), metaForSub) : saveCredentialRecord(rpId, credId, { signCount: 0, userHandle }));

  // Build clientDataJSON
  const clientData = {
    type: 'webauthn.create',
    challenge: challengeField || b64url(challenge),
    origin: origin,
    crossOrigin: false
  };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));

  // Build minimal COSE key
  const cosePub = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.cborEncodeCoseKey', () => cborEncodeCoseKey(xBytes, yBytes), metaForSub) : cborEncodeCoseKey(xBytes, yBytes);

  const rpIdHash = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.sha256RpId', async () => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(rpId))), metaForSub) : new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(rpId)));
  const flags = new Uint8Array([0x41]);
  const signCount = new Uint8Array([0,0,0,0]);
  const aaguid = hexToBytes('010102030405060708090a0b0c0d0e0f');
  const credIdLen = new Uint8Array([ (credId.length >> 8) & 0xff, credId.length & 0xff ]);
  const authData = concatBytes(rpIdHash, flags, signCount, aaguid, credIdLen, credId, cosePub);

  const attObj = FeidoMetrics ? await FeidoMetrics.measureAsync('registration.deriveAttestation.cborEncodeAttObj', () => cborEncodeAttObj('none', new Uint8Array(0), authData), metaForSub) : cborEncodeAttObj('none', new Uint8Array(0), authData);
  return { clientDataJSON, attestationObject: attObj, rawId: credId };
}

// Build assertion (credentials.get) using same VC-derived key
async function buildAssertionFromVC(pubKeyOpts, origin, expectedChallengeStr, claimsContext){
  const metaForSub = { substep: true };
  const rpId = effectiveRpIdFrom(pubKeyOpts, origin);
  const challengeField = expectedChallengeStr || ((typeof pubKeyOpts.challenge === 'string') ? pubKeyOpts.challenge : null);
  const challenge = challengeField ? new Uint8Array(0) : toBytes(pubKeyOpts.challenge);

  // Load canonical claims from storage; require callers to provide them via feidoClaims
  const ctx = (claimsContext && claimsContext.claims) ? claimsContext : await loadFreshClaimsOrThrow('login');
  const claims = ctx.claims;
  const payload = { vc: { credentialSubject: extractCanonicalFromClaims(claims) } };
  const subj = (payload.vc && payload.vc.credentialSubject) || {};
  if (!subj.issuingCountry && !subj.issuing_country) {
    const err = new Error('issuing_country_missing');
    err.code = 'FEIDO_ISSUING_COUNTRY_MISSING';
    throw err;
  }
  const cs = (payload.vc && payload.vc.credentialSubject) || {};
  const givenName = cs.givenName || cs.given_name || '';
  const familyName = cs.familyName || cs.family_name || '';
  const birthDate = cs.birthDate || cs.birthdate || cs.birth_date || '';
  const birthPlace = cs.birthPlace || cs.place_of_birth || '';
  const issuingCountry = cs.issuingCountry || cs.issuing_country || '';

  // Derive private key as in registration
  const enc = new TextEncoder();
  const msg = `${rpId}|${givenName}|${familyName}|${birthDate}|${birthPlace}|${issuingCountry}`;
  const hmacKey = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.getDeviceSecretKey', () => getDeviceSecretKey(), metaForSub) : await getDeviceSecretKey();
  const mac = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.hmacSign', () => crypto.subtle.sign('HMAC', hmacKey, enc.encode(`${msg}`)), metaForSub) : await crypto.subtle.sign('HMAC', hmacKey, enc.encode(`${msg}`));
  let d = new Uint8Array(mac).slice(0,32);
  const N = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
  let di = bytesToBigInt(d);
  di = (di % (N - 1n)) + 1n;
  d = bigIntToBytes(di, 32);

  const selectCredential = async () => {
    if (Array.isArray(pubKeyOpts.allowCredentials) && pubKeyOpts.allowCredentials.length > 0) {
      const directCred = toBytes(pubKeyOpts.allowCredentials[0].id);
      try { console.log('[feido] get: using allowCredentials id'); } catch {}
      return { credId: directCred, recordRpId: rpId };
    }
    let recordRpId = rpId;
    let credId;
    try {
      let recs = await getCredentialRecords(rpId);
      let keys = Object.keys(recs || {});
      if (!keys.length) {
        const alt = toggleWww(rpId);
        if (alt !== rpId) {
          const recsAlt = await getCredentialRecords(alt);
          const keysAlt = Object.keys(recsAlt || {});
          if (keysAlt.length) {
            recs = recsAlt;
            keys = keysAlt;
            recordRpId = alt;
          }
        }
      }
      if (keys.length > 0) {
        const pick = keys[0];
        credId = hexToBytes(pick);
        try { console.log('[feido] get: using stored credential for rpId', recordRpId, pick); } catch {}
      } else {
        credId = await deriveCredentialId(rpId, payload, pubKeyOpts);
        try { console.log('[feido] get: derived credId (no stored records)'); } catch {}
      }
    } catch (e) {
      credId = await deriveCredentialId(rpId, payload, pubKeyOpts);
      try { console.log('[feido] get: derived credId (error loading records)'); } catch {}
    }
    return { credId, recordRpId };
  };

  const selection = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.resolveCredentialId', selectCredential, metaForSub) : await selectCredential();
  let { credId, recordRpId } = selection;

  const rec = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.loadCredentialRecord', () => getCredentialRecord(recordRpId, credId), metaForSub) : await getCredentialRecord(recordRpId, credId);
  let signCount = (rec && rec.signCount) || 0;
  signCount = (signCount + 1) >>> 0;
  if (FeidoMetrics) {
    await FeidoMetrics.measureAsync('login.buildAssertion.saveCredentialRecord', () => saveCredentialRecord(recordRpId, credId, { signCount, userHandle: rec && rec.userHandle }), metaForSub);
  } else {
    await saveCredentialRecord(recordRpId, credId, { signCount, userHandle: rec && rec.userHandle });
  }

  const clientData = { type: 'webauthn.get', challenge: challengeField || b64url(challenge), origin, crossOrigin: false };
  const clientDataJSON = new TextEncoder().encode(JSON.stringify(clientData));
  const clientDataHash = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.hashClientData', async () => new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON)), metaForSub) : new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataJSON));

  const rpIdHash = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.sha256RpId', async () => new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))), metaForSub) : new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
  const flags = new Uint8Array([0x01]);
  const signCountBE = u32be(signCount);
  const authenticatorData = concatBytes(rpIdHash, flags, signCountBE);

  const toSign = concatBytes(authenticatorData, clientDataHash);
  const pubPoint = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.p256PublicFromPrivate', () => p256PublicFromPrivate(d), metaForSub) : p256PublicFromPrivate(d);
  const { xBytes, yBytes } = pubPoint;
  const jwk = { kty: 'EC', crv: 'P-256', d: b64url(d), x: b64url(xBytes), y: b64url(yBytes), alg: 'ES256', ext: true };

  let privKey;
  try {
    privKey = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.importSigningKey', () => crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']), metaForSub) : await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  } catch (e) {
    console.error('[feido] importKey(JWK) failed:', e && e.name, e && e.message);
    throw e;
  }
  let signature;
  try {
    const dataToSign = (toSign instanceof Uint8Array) ? toSign : new Uint8Array(toSign);
    const sigBuf = FeidoMetrics ? await FeidoMetrics.measureAsync('login.buildAssertion.ecdsaSign', () => crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, dataToSign), metaForSub) : await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privKey, dataToSign);
    signature = new Uint8Array(sigBuf);
  } catch (e) {
    console.error('[feido] subtle.sign failed:', e && e.name, e && e.message);
    throw e;
  }
  if (signature.length === 64 || (signature.length > 0 && signature[0] !== 0x30)) {
    signature = ecdsaRawToDer(signature);
  }

  const userHandle = (rec && rec.userHandle) ? new Uint8Array(rec.userHandle) : new Uint8Array();
  return { clientDataJSON, authenticatorData, signature, rawId: credId, userHandle };
}

async function deriveCredentialId(rpId, payload, pubKeyOpts){
  const cs = (payload.vc && payload.vc.credentialSubject) || {};
  const enc = new TextEncoder();
  // Include a stable user component to avoid overwriting previous registrations for the same VC
  let userPart = '';
  try {
    if (pubKeyOpts && pubKeyOpts.user) {
      if (typeof pubKeyOpts.user.name === 'string' && pubKeyOpts.user.name) userPart = pubKeyOpts.user.name;
      else if (pubKeyOpts.user.id) userPart = b64url(toBytes(pubKeyOpts.user.id));
    }
  } catch {}
  // If payload carries a digest, bind credId to it to avoid collisions across claim variants
  const issuingCountry = cs.issuingCountry || cs.issuing_country || '';
  const material = `${rpId}|${cs.givenName||cs.given_name||''}|${cs.familyName||cs.family_name||''}|${cs.birthDate||cs.birthdate||cs.birth_date||''}|${cs.birthPlace||cs.place_of_birth||''}|${issuingCountry}|${userPart}`;
  // Device-bound credId v2 (use the same device secret to avoid collisions across devices)
  const hmacKey = await getDeviceSecretKey();
  const mac = await crypto.subtle.sign('HMAC', hmacKey, enc.encode(`${material}`));
  return new Uint8Array(mac).slice(0,16);
}

// Multiple-credential storage per rpId, keyed by credId hex
async function getCredentialRecords(rpId){
  const key = `feidoCreds_${rpId}`;
  const st = await browser.storage.local.get(key);
  return st[key] || {};
}
async function getCredentialRecord(rpId, credId){
  const all = await getCredentialRecords(rpId);
  const rec = all[toHex(credId)];
  return rec ? { signCount: rec.signCount>>>0, userHandle: rec.userHandle ? new Uint8Array(rec.userHandle) : new Uint8Array() } : null;
}
async function saveCredentialRecord(rpId, credId, rec){
  const key = `feidoCreds_${rpId}`;
  const all = await getCredentialRecords(rpId);
  all[toHex(credId)] = { signCount: rec.signCount>>>0, userHandle: rec.userHandle ? Array.from(rec.userHandle) : [] };
  await browser.storage.local.set({ [key]: all });
}

// --- Device secret management (32-byte random, persisted locally) ---
async function getDeviceSecret(){
  // In-memory unlocked secret (cleared on lock or extension unload)
  if (typeof getDeviceSecret._unlocked === 'object' && getDeviceSecret._unlocked instanceof Uint8Array) {
    return getDeviceSecret._unlocked;
  }

  const encKeyName = 'feidoDeviceSecretEnc';
  const st = await browser.storage.local.get([encKeyName]);
  const enc = st[encKeyName];
  // If encrypted secret exists but not unlocked, throw a specific error so caller can prompt the user
  if (enc && enc.ct) {
    const err = new Error('feido_device_secret_locked');
    err.code = 'FEIDO_DEVICE_SECRET_LOCKED';
    throw err;
  }

  // No encrypted secret present: require operator to set one via setDeviceSecretWithPassphrase
  const err = new Error('feido_device_secret_missing');
  err.code = 'FEIDO_DEVICE_SECRET_MISSING';
  throw err;
}

// Return a cached non-exportable CryptoKey representing the device secret.
// This imports the raw unlocked secret into a non-exportable HMAC key and
// zeroes the raw buffer as soon as possible to reduce exposure in JS memory.
async function getDeviceSecretKey(){
  // Return cached CryptoKey if present
  if (getDeviceSecret._unlockedKey && typeof getDeviceSecret._unlockedKey === 'object') return getDeviceSecret._unlockedKey;

  // If raw unlocked secret is available, import it and zero the raw buffer
  if (typeof getDeviceSecret._unlocked === 'object' && getDeviceSecret._unlocked instanceof Uint8Array){
    try{
      const raw = getDeviceSecret._unlocked;
      const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      // zero out raw buffer and drop reference
      try{ raw.fill(0); }catch(e){}
      getDeviceSecret._unlocked = null;
      getDeviceSecret._unlockedKey = key;
      return key;
    }catch(e){
      // ensure raw cleared on error
      try{ if (getDeviceSecret._unlocked instanceof Uint8Array) getDeviceSecret._unlocked.fill(0); }catch(_){ }
      getDeviceSecret._unlocked = null;
      throw e;
    }
  }

  // If no unlocked secret, signal locked
  const err = new Error('feido_device_secret_locked');
  err.code = 'FEIDO_DEVICE_SECRET_LOCKED';
  throw err;
}

// Allow other parts of the extension to set/unlock the device secret with a passphrase
async function deriveKeyFromPassphrase(passphrase, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Helpers to encrypt/decrypt arbitrary JSON with passphrase (used for exporting creds)
async function encryptJsonWithPassphrase(obj, passphrase){
  const txt = JSON.stringify(obj);
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassphrase(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(txt));
  return { salt: Array.from(salt), iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}
async function decryptJsonWithPassphrase(encObj, passphrase){
  const salt = new Uint8Array(encObj.salt);
  const iv = new Uint8Array(encObj.iv);
  const ct = new Uint8Array(encObj.ct);
  const key = await deriveKeyFromPassphrase(passphrase, salt);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(plain));
}

// Helper to get device secret raw bytes for encryption/decryption
// Works even when the secret is stored as a non-exportable CryptoKey
async function getDeviceSecretRawBytes(){
  // Check if we have the CryptoKey version
  if (getDeviceSecret._unlockedKey && typeof getDeviceSecret._unlockedKey === 'object') {
    // We have the HMAC key. Use it to sign a known message to get deterministic bytes
    const sig = await crypto.subtle.sign('HMAC', getDeviceSecret._unlockedKey, new Uint8Array(32));
    return new Uint8Array(sig);
  }
  
  // Check if we have raw bytes
  if (typeof getDeviceSecret._unlocked === 'object' && getDeviceSecret._unlocked instanceof Uint8Array) {
    return getDeviceSecret._unlocked;
  }
  
  // Check storage for encrypted secret
  const encKeyName = 'feidoDeviceSecretEnc';
  const st = await browser.storage.local.get([encKeyName]);
  const enc = st[encKeyName];
  
  if (enc && enc.ct) {
    const err = new Error('feido_device_secret_locked');
    err.code = 'FEIDO_DEVICE_SECRET_LOCKED';
    throw err;
  }
  
  const err = new Error('feido_device_secret_missing');
  err.code = 'FEIDO_DEVICE_SECRET_MISSING';
  throw err;
}

// Encrypt/decrypt claims using device secret as encryption key
async function encryptClaimsWithDeviceSecret(claimsObj){
  if (!claimsObj || typeof claimsObj !== 'object') {
    throw new Error('invalid_claims_object');
  }
  
  const deviceSecretBytes = await getDeviceSecretRawBytes();
  if (!deviceSecretBytes) {
    throw new Error('device_secret_not_available');
  }
  
  const txt = JSON.stringify(claimsObj);
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  // Derive encryption key from device secret using HKDF
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    deviceSecretBytes,
    { name: 'HKDF' },
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const encKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: enc.encode('feido-claims-encryption-v1')
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    encKey,
    enc.encode(txt)
  );
  
  return {
    version: 1,
    iv: Array.from(iv),
    ct: Array.from(new Uint8Array(ct))
  };
}

async function decryptClaimsWithDeviceSecret(encObj){
  if (!encObj || typeof encObj !== 'object') {
    throw new Error('invalid_encrypted_claims');
  }
  
  // Check if claims are already in plaintext (backward compatibility)
  if (!encObj.version && !encObj.iv && !encObj.ct) {
    // This is plaintext claims object, return as-is
    return encObj;
  }
  
  const deviceSecretBytes = await getDeviceSecretRawBytes();
  if (!deviceSecretBytes) {
    throw new Error('device_secret_not_available');
  }
  
  const iv = new Uint8Array(encObj.iv);
  const ct = new Uint8Array(encObj.ct);
  const enc = new TextEncoder();
  
  // Derive decryption key from device secret using HKDF
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    deviceSecretBytes,
    { name: 'HKDF' },
    false,
    ['deriveBits', 'deriveKey']
  );
  
  const decKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: enc.encode('feido-claims-encryption-v1')
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    decKey,
    ct
  );
  
  return JSON.parse(new TextDecoder().decode(plain));
}

function validateDeviceEncShape(encObj){
  if (!encObj) return true;
  return Array.isArray(encObj.salt) && Array.isArray(encObj.iv) && Array.isArray(encObj.ct);
}

function sanitizeRemoteCredentials(raw){
  const cleaned = {};
  if (!raw || typeof raw !== 'object') return cleaned;
  for (const k of Object.keys(raw)){
    if (!k.startsWith('feidoCreds_')) continue;
    const v = raw[k];
    if (!v || typeof v !== 'object') continue;
    cleaned[k] = v;
  }
  return cleaned;
}

function arrayishEqual(a, b){
  if (!a || !b) return false;
  const arrA = Array.isArray(a) ? a : Array.from(a);
  const arrB = Array.isArray(b) ? b : Array.from(b);
  const lenA = arrA.length >>> 0;
  if (lenA !== (arrB.length >>> 0)) return false;
  for (let i = 0; i < lenA; i++){
    if ((arrA[i] >>> 0) !== (arrB[i] >>> 0)) return false;
  }
  return true;
}

function encryptedDeviceBlobsEqual(a, b){
  if (!a || !b) return false;
  return arrayishEqual(a.salt, b.salt) && arrayishEqual(a.iv, b.iv) && arrayishEqual(a.ct, b.ct);
}

async function importAllPackage(pkg, passphrase, mergeRequested){
  if (!pkg) {
    const err = new Error('missing_package');
    err.code = 'missing_package';
    throw err;
  }
  if (!passphrase) {
    const err = new Error('missing_passphrase');
    err.code = 'missing_passphrase';
    throw err;
  }
  if (pkg.deviceEnc && !validateDeviceEncShape(pkg.deviceEnc)) {
    const err = new Error('invalid_device_enc');
    err.code = 'invalid_device_enc';
    throw err;
  }

  const state = await browser.storage.local.get(null);
  const existingDeviceEnc = state.feidoDeviceSecretEnc || null;
  const result = { mode: mergeRequested ? 'merge' : 'replace', stats: {} };

  const zeroOut = (buf)=>{ try { if (buf && typeof buf.fill === 'function') buf.fill(0); } catch(_){} };

  let backupSecret = null;
  try {
    let remoteCreds = {};
    if (pkg.credsEnc) {
      let credsObj;
      try {
        credsObj = await decryptJsonWithPassphrase(pkg.credsEnc, passphrase);
      } catch (e) {
        const err = new Error('wrong_passphrase');
        err.code = 'wrong_passphrase';
        throw err;
      }
      remoteCreds = sanitizeRemoteCredentials(credsObj);
    }

    if (mergeRequested) {
      let deviceSecretHandled = 'unchanged';
      let backupSecretDecrypted = false;
      if (existingDeviceEnc && existingDeviceEnc.ct) {
        if (!pkg.deviceEnc) {
          const err = new Error('merge_missing_device_secret');
          err.code = 'merge_missing_device_secret';
          throw err;
        }
        try {
          backupSecret = await decryptDeviceSecret(pkg.deviceEnc, passphrase);
          backupSecretDecrypted = true;
        } catch (e) {
          if (encryptedDeviceBlobsEqual(existingDeviceEnc, pkg.deviceEnc)) {
            backupSecret = null;
            backupSecretDecrypted = false;
          } else {
            const err = new Error('merge_device_secret_decrypt_failed');
            err.code = 'merge_device_secret_decrypt_failed';
            throw err;
          }
        }
        let secretsMatch = false;
        let localSecret = null;
        if (backupSecretDecrypted) {
          try {
            localSecret = await decryptDeviceSecret(existingDeviceEnc, passphrase);
          } catch (_) {
            localSecret = null;
          }
          if (localSecret) {
            secretsMatch = buffersEqual(localSecret, backupSecret);
            zeroOut(localSecret);
          }
        }
        if (!secretsMatch) {
          if (!backupSecretDecrypted && encryptedDeviceBlobsEqual(existingDeviceEnc, pkg.deviceEnc)) {
            secretsMatch = true;
          } else {
            try {
              const localKey = await getDeviceSecretKey();
              const localDigest = await digestDeviceSecretFromKey(localKey);
              const backupDigest = backupSecretDecrypted ? await digestDeviceSecretFromRaw(backupSecret) : null;
              if (backupDigest && buffersEqual(localDigest, backupDigest)) {
                secretsMatch = true;
              }
            } catch (e) {
              if (isDeviceSecretLockedError(e)) {
                const err = new Error('merge_requires_unlock');
                err.code = 'merge_requires_unlock';
                throw err;
              }
              throw e;
            }
          }
        }
        if (!secretsMatch) {
          const err = new Error('merge_device_secret_mismatch');
          err.code = 'merge_device_secret_mismatch';
          throw err;
        }
      } else {
        if (!pkg.deviceEnc) {
          const err = new Error('merge_missing_device_secret');
          err.code = 'merge_missing_device_secret';
          throw err;
        }
        deviceSecretHandled = 'imported';
      }

      const toStore = {};
      let added = 0;
      let updated = 0;
      let totalRemote = 0;
      for (const key of Object.keys(remoteCreds)){
        const incoming = remoteCreds[key] || {};
        const existing = state[key] || {};
        const merged = Object.assign({}, existing);
        let changed = false;
        for (const credId of Object.keys(incoming)){
          const incomingRec = incoming[credId];
          if (!incomingRec) continue;
          totalRemote++;
          const currentRec = existing[credId];
          if (!currentRec) {
            merged[credId] = incomingRec;
            added++;
            changed = true;
            continue;
          }
          const currentCount = (currentRec.signCount >>> 0) || 0;
          const incomingCount = (incomingRec.signCount >>> 0) || 0;
          const userHandleUpdate = (!currentRec.userHandle || currentRec.userHandle.length === 0) && Array.isArray(incomingRec.userHandle) && incomingRec.userHandle.length > 0;
          if (incomingCount > currentCount || userHandleUpdate) {
            merged[credId] = Object.assign({}, currentRec, incomingRec, { signCount: incomingCount });
            updated++;
            changed = true;
          }
        }
        if (changed) {
          toStore[key] = merged;
          state[key] = merged;
        }
      }

      const storageOps = [];
      if (!existingDeviceEnc || !existingDeviceEnc.ct) {
        storageOps.push(browser.storage.local.set({ feidoDeviceSecretEnc: pkg.deviceEnc }));
        getDeviceSecret._unlocked = null;
        if (getDeviceSecret._unlockedKey) getDeviceSecret._unlockedKey = null;
        if (getDeviceSecret._lockTimer) {
          try { clearTimeout(getDeviceSecret._lockTimer); } catch(_){}
          getDeviceSecret._lockTimer = null;
        }
      }
      if (Object.keys(toStore).length > 0) {
        storageOps.push(browser.storage.local.set(toStore));
      }
      if (storageOps.length > 0) await Promise.all(storageOps);

  result.stats = { added, updated, totalRemote, deviceSecretHandled };
      return result;
    }

    // Replace mode
    const storageOps = [];
    if (pkg.deviceEnc) {
      storageOps.push(browser.storage.local.set({ feidoDeviceSecretEnc: pkg.deviceEnc }));
    }
    if (Object.keys(remoteCreds).length > 0) {
      storageOps.push(browser.storage.local.set(remoteCreds));
    }
    if (storageOps.length > 0) await Promise.all(storageOps);
    if (pkg.deviceEnc) {
      getDeviceSecret._unlocked = null;
      if (getDeviceSecret._unlockedKey) getDeviceSecret._unlockedKey = null;
      if (getDeviceSecret._lockTimer) {
        try { clearTimeout(getDeviceSecret._lockTimer); } catch(_){}
        getDeviceSecret._lockTimer = null;
      }
    }
    let importedCount = 0;
    let totalKeys = 0;
    for (const key of Object.keys(remoteCreds)){
      importedCount += Object.keys(remoteCreds[key] || {}).length;
      totalKeys++;
    }
    result.stats = { importedCount, totalKeys };
    return result;
  } finally {
    zeroOut(backupSecret);
  }
}

async function encryptDeviceSecret(deviceSecretUint8, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKeyFromPassphrase(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, deviceSecretUint8);
  return { salt: Array.from(salt), iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function decryptDeviceSecret(encryptedObj, passphrase) {
  const salt = new Uint8Array(encryptedObj.salt);
  const iv = new Uint8Array(encryptedObj.iv);
  const ct = new Uint8Array(encryptedObj.ct);
  const key = await deriveKeyFromPassphrase(passphrase, salt);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(plain);
}

async function setDeviceSecretWithPassphrase(passphrase){
  // Only allow generating the device secret if none exists. Overwriting the
  // persisted device secret is disallowed to prevent accidental credential loss.
  const st = await browser.storage.local.get('feidoDeviceSecretEnc');
  const existing = st && st.feidoDeviceSecretEnc;
  if (existing && existing.ct) {
    const err = new Error('device_secret_already_exists');
    err.code = 'FEIDO_DEVICE_SECRET_EXISTS';
    throw err;
  }
  // Generate a fresh device secret and store it encrypted with the provided passphrase.
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  const encObj = await encryptDeviceSecret(secret, passphrase);
  // store encrypted only
  await browser.storage.local.set({ feidoDeviceSecretEnc: encObj });
  // Import as non-exportable CryptoKey and zero raw buffer to minimize exposure
  try{
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    try{ secret.fill(0); }catch(e){}
    getDeviceSecret._unlockedKey = key;
    // set auto-lock timer
    try{ if (getDeviceSecret._lockTimer) clearTimeout(getDeviceSecret._lockTimer); getDeviceSecret._lockTimer = setTimeout(()=>{ try{ lockDeviceSecret(); }catch(e){} }, 5*60*1000); }catch(e){}
  }catch(e){
    // if import fails, keep raw unlocked as fallback (unlikely)
    getDeviceSecret._unlocked = secret;
  }
}

// Change passphrase securely: decrypt with currentPassphrase (or use unlocked secret),
// then re-encrypt the same secret with newPassphrase atomically.
async function changeDevicePassphrase(currentPassphrase, newPassphrase){
  // Ensure encrypted blob exists
  const st = await browser.storage.local.get('feidoDeviceSecretEnc');
  const enc = st && st.feidoDeviceSecretEnc;
  if (!enc || !enc.ct) {
    const err = new Error('no_encrypted_device_secret');
    err.code = 'FEIDO_DEVICE_SECRET_MISSING';
    throw err;
  }
  // For security, require the current passphrase to re-encrypt. Do not rely on raw unlocked secret.
  if (!currentPassphrase) {
    const err = new Error('missing_current_passphrase');
    err.code = 'MISSING_CURRENT_PASSPHRASE';
    throw err;
  }
  let secret;
  try {
    secret = await decryptDeviceSecret(enc, currentPassphrase);
  } catch (e) {
    const err = new Error('invalid_current_passphrase');
    err.code = 'INVALID_CURRENT_PASSPHRASE';
    throw err;
  }
  // Re-encrypt with new passphrase and atomically store
  const newEnc = await encryptDeviceSecret(secret, newPassphrase);
  await browser.storage.local.set({ feidoDeviceSecretEnc: newEnc });
  // Import as non-exportable key and zero raw buffer
  try{
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    try{ secret.fill(0); }catch(e){}
    getDeviceSecret._unlockedKey = key;
    try{ if (getDeviceSecret._lockTimer) clearTimeout(getDeviceSecret._lockTimer); getDeviceSecret._lockTimer = setTimeout(()=>{ try{ lockDeviceSecret(); }catch(e){} }, 5*60*1000); }catch(e){}
  }catch(e){
    // fallback: keep raw in memory
    getDeviceSecret._unlocked = secret;
  }
}

async function unlockDeviceSecret(passphrase){
  const st = await browser.storage.local.get('feidoDeviceSecretEnc');
  const enc = st && st.feidoDeviceSecretEnc;
  if (!enc || !enc.ct) throw new Error('no_encrypted_device_secret');
  const secret = await decryptDeviceSecret(enc, passphrase);
  if (!secret || !(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('invalid_decrypted_secret');
  // Immediately import as non-exportable CryptoKey and zero raw buffer to avoid exposure
  try{
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    try{ secret.fill(0); }catch(e){}
    getDeviceSecret._unlockedKey = key;
    // set auto-lock timer (5 minutes)
    try{ if (getDeviceSecret._lockTimer) clearTimeout(getDeviceSecret._lockTimer); getDeviceSecret._lockTimer = setTimeout(()=>{ try{ lockDeviceSecret(); }catch(e){} }, 5*60*1000); }catch(e){}
    return true;
  }catch(e){
    // fallback to keeping raw for compatibility
    getDeviceSecret._unlocked = secret;
    return true;
  }
}

function lockDeviceSecret(){
  try { if (getDeviceSecret._unlocked instanceof Uint8Array) { try{ getDeviceSecret._unlocked.fill(0); }catch(e){} } }catch(e){}
  getDeviceSecret._unlocked = null;
  try { getDeviceSecret._unlockedKey = null; }catch(e){}
  try { if (getDeviceSecret._lockTimer) { clearTimeout(getDeviceSecret._lockTimer); getDeviceSecret._lockTimer = null; } }catch(e){}
}

// Expose runtime messages for passphrase management
// Legacy runtime listener removed: all actions are handled in interceptAndHandleLocally to avoid
// duplicate responses and ensure merge-aware import logic runs consistently.

// Utils (minimal CBOR + helpers)
function b64url(u8){ return btoa(String.fromCharCode(...u8)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_'); }
function b64uToBytes(s){ s=s.replace(/-/g,'+').replace(/_/g,'/'); const pad = s.length%4? '='.repeat(4-(s.length%4)) : ''; const b = atob(s+pad); return Uint8Array.from(b, c=>c.charCodeAt(0)); }
function hexToBytes(hex){ return Uint8Array.from(hex.match(/.{1,2}/g).map(b=>parseInt(b,16))); }
function concatBytes(...arrs){ let len=arrs.reduce((a,b)=>a+b.length,0); let out=new Uint8Array(len); let o=0; for(const a of arrs){ out.set(a,o); o+=a.length;} return out; }
function bytesToBigInt(u8){ let n=0n; for (const b of u8){ n = (n<<8n) + BigInt(b); } return n; }
function bigIntToBytes(n, len){ const out = new Uint8Array(len); for (let i=len-1; i>=0; i--){ out[i] = Number(n & 0xFFn); n >>= 8n; } return out; }
function toBytes(x){
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (Array.isArray(x)) return new Uint8Array(x);
  if (x && typeof x === 'object') {
    // object with numeric keys {0:..,1:..}
    const keys = Object.keys(x).filter(k=>!isNaN(Number(k))).sort((a,b)=>Number(a)-Number(b));
    const arr = keys.map(k=>Number(x[k]) & 0xff);
    return new Uint8Array(arr);
  }
  return new Uint8Array();
}
function u32be(n){ return new Uint8Array([ (n>>>24)&0xff, (n>>>16)&0xff, (n>>>8)&0xff, n&0xff ]); }
function toHex(u8){ return Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join(''); }

// Convert raw 64-byte ECDSA signature (r||s) to DER format
function ecdsaRawToDer(sig){
  const toInt = (arr)=>{
    // strip leading zeros
    let i = 0; while (i < arr.length && arr[i] === 0) i++;
    let v = arr.slice(i);
    // if high bit set, prepend 0x00
    if (v.length === 0) v = new Uint8Array([0]);
    else if (v[0] & 0x80) v = concatBytes(new Uint8Array([0]), v);
    return v;
  };
  let r, s;
  if (sig.length === 64) {
    r = toInt(sig.slice(0,32));
    s = toInt(sig.slice(32));
  } else {
    // Unexpected length; return as-is
    return sig;
  }
  const der = [];
  der.push(0x30);
  const len = 2 + r.length + 2 + s.length;
  der.push(len);
  der.push(0x02, r.length, ...r);
  der.push(0x02, s.length, ...s);
  return new Uint8Array(der);
}

// Minimal P-256 math (BigInt) just to compute Q = d*G
const P256 = {
  p: BigInt('0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'),
  a: -3n,
  b: BigInt('0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'),
  Gx: BigInt('0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'),
  Gy: BigInt('0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5')
};
function mod(a,m){ const r = a % m; return r >= 0n ? r : r + m; }
function modAdd(a,b,m){ return mod(a+b,m); }
function modSub(a,b,m){ return mod(a-b,m); }
function modMul(a,b,m){ return mod(a*b,m); }
function modPow(a,e,m){ let r=1n; let x=mod(a,m); let k=e; while(k>0n){ if(k&1n) r=modMul(r,x,m); x=modMul(x,x,m); k>>=1n; } return r; }
function modInv(a,m){ // a^(p-2) mod p since p is prime
  return modPow(mod(a,m), P256.p - 2n, P256.p);
}
function pointDouble(P){ if(!P) return null; const [x1,y1]=P; if(y1===0n) return null; const p=P256.p; const a=BigInt(P256.a);
  const s = modMul(modAdd(modMul(3n, modMul(x1,x1,p), p), a, p), modInv(modMul(2n,y1,p), p), p);
  const x3 = modSub(modMul(s,s,p), modMul(2n,x1,p), p);
  const y3 = modSub(modMul(s, modSub(x1,x3,p), p), y1, p);
  return [x3,y3];
}
function pointAdd(P,Q){ if(!P) return Q; if(!Q) return P; const [x1,y1]=P; const [x2,y2]=Q; const p=P256.p;
  if (x1===x2){ if(y1===mod(-y2,p)) return null; else return pointDouble(P); }
  const s = modMul(modSub(y2,y1,p), modInv(modSub(x2,x1,p), p), p);
  const x3 = modSub(modMul(s,s,p), modAdd(x1,x2,p), p);
  const y3 = modSub(modMul(s, modSub(x1,x3,p), p), y1, p);
  return [x3,y3];
}
function scalarMult(k){ let N = k; let Q = null; let P = [P256.Gx, P256.Gy];
  while (N > 0n){ if (N & 1n) Q = pointAdd(Q,P); P = pointDouble(P); N >>= 1n; }
  return Q;
}
function p256PublicFromPrivate(dBytes){ const d = bytesToBigInt(dBytes); const Q = scalarMult(d); const [x,y]=Q; return { xBytes: bigIntToBytes(x,32), yBytes: bigIntToBytes(y,32) };
}

// CBOR encoders for the limited structures we need
function cborHead(mt, ai){ return new Uint8Array([ (mt<<5) | ai ]); }
function cborUint(n){
  if (n < 24) return cborHead(0, n);
  if (n < 256) return concatBytes(cborHead(0, 24), new Uint8Array([n]));
  return concatBytes(cborHead(0, 25), new Uint8Array([ (n>>8)&0xff, n&0xff ]));
}
function cborNegInt(n){ // n is positive magnitude of -1 - value
  if (n < 24) return cborHead(1, n);
  if (n < 256) return concatBytes(cborHead(1, 24), new Uint8Array([n]));
  return concatBytes(cborHead(1, 25), new Uint8Array([ (n>>8)&0xff, n&0xff ]));
}
function cborBytes(u8){
  const len = u8.length;
  if (len < 24) return concatBytes(cborHead(2, len), u8);
  if (len < 256) return concatBytes(cborHead(2, 24), new Uint8Array([len]), u8);
  return concatBytes(cborHead(2, 25), new Uint8Array([ (len>>8)&0xff, len&0xff ]), u8);
}
function cborText(str){
  const enc = new TextEncoder();
  const u8 = enc.encode(str);
  const len = u8.length;
  if (len < 24) return concatBytes(cborHead(3, len), u8);
  if (len < 256) return concatBytes(cborHead(3, 24), new Uint8Array([len]), u8);
  return concatBytes(cborHead(3, 25), new Uint8Array([ (len>>8)&0xff, len&0xff ]), u8);
}
function cborMap(entries){ // entries: array of [keyEnc, valEnc]
  const len = entries.length;
  let head;
  if (len < 24) head = cborHead(5, len);
  else if (len < 256) head = concatBytes(cborHead(5, 24), new Uint8Array([len]));
  else head = concatBytes(cborHead(5, 25), new Uint8Array([ (len>>8)&0xff, len&0xff ]));
  let out = head;
  for (const [k,v] of entries) out = concatBytes(out, k, v);
  return out;
}

function cborEncodeCoseKey(x,y){
  // {1:2,3:-7,-1:1,-2:x,-3:y}
  const entries = [
    [ cborUint(1), cborUint(2) ],
    [ cborUint(3), cborNegInt(6) ], // -7 => 6 as magnitude
    [ cborNegInt(0), cborUint(1) ], // -1 => 0 magnitude
    [ cborNegInt(1), cborBytes(x) ], // -2 => 1 magnitude
    [ cborNegInt(2), cborBytes(y) ], // -3 => 2 magnitude
  ];
  return cborMap(entries);
}

function cborEncodeAttObj(fmt, attStmtEmptyMap, authData){
  // {"authData": bstr, "fmt": text, "attStmt": {}}
  const entries = [
    [ cborText('authData'), cborBytes(authData) ],
    [ cborText('fmt'), cborText(fmt) ],
    [ cborText('attStmt'), cborMap([]) ],
  ];
  return cborMap(entries);
}

// --- RP ID helpers ---
function effectiveRpIdFrom(pubKeyOpts, origin){
  try{
    if (pubKeyOpts && typeof pubKeyOpts.rpId === 'string' && pubKeyOpts.rpId) return pubKeyOpts.rpId;
    if (pubKeyOpts && pubKeyOpts.rp && typeof pubKeyOpts.rp.id === 'string' && pubKeyOpts.rp.id) return pubKeyOpts.rp.id;
  }catch{}
  try{ return new URL(origin).hostname; }catch{}
  return '';
}
function toggleWww(rpId){
  if (!rpId) return rpId;
  if (rpId.startsWith('www.')) return rpId.slice(4);
  return 'www.' + rpId;
}

// --- Helpers to support PID/VC canonicalization ---
function extractCanonicalFromClaims(claims){
  // Accepts PID (SD-JWT or mDoc mapped) or VC-like claim object; returns normalized fields
  const get = (obj, keys, def='')=>{
    for (const k of keys){ if (obj && obj[k] != null) return obj[k]; }
    return def;
  };
  // Handle nested place_of_birth structures
  let place = get(claims, ['birthPlace','place_of_birth','placeOfBirth'], '');
  if (place && typeof place === 'object') {
    const locality = get(place, ['locality','city','town','municipality'], '');
    const country = get(place, ['country','country_code','countryCode'], '');
    place = `${String(locality).trim().toLowerCase()},${String(country).trim().toLowerCase()}`;
  }
  const given = String(get(claims, ['givenName','given_name','first_name','firstName'], '')).trim().toLowerCase();
  const family = String(get(claims, ['familyName','family_name','last_name','lastName'], '')).trim().toLowerCase();
  // Normalize date to YYYY-MM-DD when possible
  let bd = String(get(claims, ['birthDate','birthdate','birth_date','dateOfBirth'], '')).trim();
  const m = bd.match(/^(\d{4})[-\/]?(\d{2})[-\/]?(\d{2})/);
  if (m) bd = `${m[1]}-${m[2]}-${m[3]}`;
  const issuing = String(get(claims, [
    'issuingCountry',
    'issuing_country',
    'issuerCountry',
    'issuingCountryCode',
    'country_of_issue',
    'eu.europa.ec.eudi.pid.1:issuing_country'
  ], '')).trim().toLowerCase();
  return {
    givenName: given,
    familyName: family,
    birthDate: bd,
    birthPlace: String(place||'').trim().toLowerCase(),
    issuingCountry: issuing
  };
}

// parse to object and forward return to overwrite.js
async function returnedForwardToOverwriteJs(msg, reqId, opType, flow = 'registration'){
  console.log("Received WebSocket message:" + JSON.stringify(msg));
  
  const metaForSub = { substep: true };
  let publicKeyCredential = FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.forwardToContent.parseReturn`, () => parseReturn(msg, flow), metaForSub) : await parseReturn(msg, flow);

  const sendPayload = { reqId, opType, payload: publicKeyCredential };
  FeidoMetrics ? await FeidoMetrics.measureAsync(`${flow}.forwardToContent.sendMessage`, () => sendMessage(sendPayload), metaForSub) : sendMessage(sendPayload);
}

// send return message to content script
async function sendMessage(msg){
  console.log("Sending message to content script: " + JSON.stringify(msg));
  if (typeof currentRequestTabId !== 'number') {
    console.warn('[feido] sendMessage: no currentRequestTabId set');
    return;
  }
  let promisedSending = browser.tabs.sendMessage(currentRequestTabId, msg);
  promisedSending.then(sentMessage, sendMessageError)
}

function sentMessage(msg){
  console.log("Sent message to content script.");
}

function sendMessageError(err){
  console.log("Error during sendMessage communication to content script: " + err);
}

// Open or focus the verifier custom-request page so the user can populate feidoClaims
async function redirectToVerifier(){
  const url = 'https://verifier.eudiw.dev/custom-request/create';
  try{
    // Try to find an existing tab with that URL
    const tabs = await browser.tabs.query({ url: url });
    if (Array.isArray(tabs) && tabs.length > 0){
      await browser.tabs.update(tabs[0].id, { active: true });
      await browser.windows.update(tabs[0].windowId, { focused: true });
      return;
    }
  }catch(e){ /* ignore */ }
  try{ await browser.tabs.create({ url }); } catch(e){ console.warn('[feido] cannot open verifier page:', e && e.message); }
}

// Process combined import candidate fallback (deviceEnc + credsEnc/raw)
browser.storage.onChanged.addListener(async (changes, area) => {
  try {
    if (area !== 'local') return;
    if (!changes || !changes.feidoAllImportCandidate) return;
    const newVal = changes.feidoAllImportCandidate.newValue;
    if (!newVal || !newVal.package) return;
    console.log('[feido] storage.onChanged: found feidoAllImportCandidate, attempting import');
    const pkg = newVal.package;
    // If package contains deviceEnc, validate and store
    if (pkg.deviceEnc) {
      const enc = pkg.deviceEnc;
      if (!enc.salt || !enc.iv || !enc.ct) { console.warn('[feido] feidoAllImportCandidate.deviceEnc invalid'); await browser.storage.local.remove('feidoAllImportCandidate'); return; }
      await browser.storage.local.set({ feidoDeviceSecretEnc: enc });
      getDeviceSecret._unlocked = null;
      console.log('[feido] storage.onChanged: deviceEnc saved to feidoDeviceSecretEnc');
    }
    // If package contains credsEnc (encrypted creds blob), try to leave as-is so user can decrypt via UI
    if (pkg.credsEnc) {
      // store as a marker; background doesn't decrypt without passphrase
      await browser.storage.local.set({ feidoCredsEncryptedCandidate: pkg.credsEnc });
      console.log('[feido] storage.onChanged: stored encrypted credentials candidate');
    }
    // Legacy raw creds handling removed: only encrypted credsEnc (passphrase-protected) are accepted
    // Clear candidate key
    try { await browser.storage.local.remove('feidoAllImportCandidate'); } catch (e){}
  } catch (e) { console.warn('[feido] error processing feidoAllImportCandidate', e && e.message); }
});
