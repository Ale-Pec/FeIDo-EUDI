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

// code to overwrite navigator.credentials.get and .create
var code = `
  // Preserve native WebAuthn methods before overwriting
  const __nativeCreds = navigator.credentials;
  const __origGet = __nativeCreds.get.bind(__nativeCreds);
  const __origCreate = __nativeCreds.create.bind(__nativeCreds);
  const __expectedChallengeById = Object.create(null);
  // --- FeIDo page API + Online Verifier auto-capture ---
  (function(){
    // Canonicalize PID-like claims to the 4 fields used by FeIDo KDF
    const canonicalize = (claims)=>{
      const get = (o, ks, def='')=>{ for (const k of ks){ if (o && o[k] != null) return o[k]; } return def; };
      let place = get(claims, ['birthPlace','place_of_birth','placeOfBirth'], '');
      if (place && typeof place === 'object') {
          const locality = get(place, ['locality','city','town','municipality'], '');
          const country = get(place, ['country','country_code','countryCode'], '');
          place = (String(locality).trim().toLowerCase()) + ',' + (String(country).trim().toLowerCase());
      }
      const given = String(get(claims, ['givenName','given_name','first_name','firstName'], '')).trim().toLowerCase();
      const family = String(get(claims, ['familyName','family_name','last_name','lastName'], '')).trim().toLowerCase();
      let bd = String(get(claims, ['birthDate','birthdate','birth_date','dateOfBirth'], '')).trim();
    const m = bd.match(/^(\d{4})[-\/]?(\d{2})[-\/]?(\d{2})/);
    if (m) bd = m[1] + '-' + m[2] + '-' + m[3];
      return { givenName: given, familyName: family, birthDate: bd, birthPlace: String(place||'').trim().toLowerCase() };
    };

    // Expose a tiny API on window for RPs or helper scripts
    const ensureFeIDo = ()=>{
      if (!window.FeIDo) window.FeIDo = {};
      if (!window.FeIDo.setClaims) {
        window.FeIDo.setClaims = (obj)=>{
          try { window.postMessage({ channel:'feido', op:'setClaims', claims: canonicalize(obj) }, location.origin); }
          catch (e) { console.warn('[feido] setClaims error:', e); }
        };
      }
      if (!window.FeIDo.clear) {
        window.FeIDo.clear = ()=>{
          try { window.postMessage({ channel:'feido', op:'clear' }, location.origin); }
          catch (e) { console.warn('[feido] clear error:', e); }
        };
      }
    };
    ensureFeIDo();

    // Auto-capture on Verifier/RP pages: hook fetch and XHR
    const hostLc = location.hostname.toLowerCase();
    const pathLc = decodeURIComponent(location.pathname).toLowerCase();
    const isEudiOnlineVerifier = hostLc.includes('eu-digital-identity-wallet.github.io') && pathLc.includes('online verifier');
    const isEudiTesterRP = hostLc === 'tester.relyingparty.eudiw.dev' || hostLc.endsWith('.relyingparty.eudiw.dev');
    if (isEudiOnlineVerifier || isEudiTesterRP) {
      console.info('[feido] Verifier/RP detected — installing auto-capture hooks');
      const tryExtractClaims = (data)=>{
        if (!data || typeof data !== 'object') return false;
        // Heuristics: check common paths where claims may appear
        const candidates = [];
        const pushIfObj = (o)=>{ if (o && typeof o === 'object') candidates.push(o); };
        pushIfObj(data.claims);
        pushIfObj(data.disclosedClaims);
        pushIfObj(data.verifiedClaims);
        pushIfObj(data.credentialSubject);
        pushIfObj(data.vc && data.vc.credentialSubject);
        // SD-JWT might embed in disclosures/payload
        if (Array.isArray(data.disclosures)) {
          for (const d of data.disclosures) pushIfObj(d);
        }
        // Fallback: scan shallow keys
        candidates.push(data);
        for (const obj of candidates) {
          if (!obj) continue;
          const cn = canonicalize(obj);
          if (cn.givenName || cn.familyName || cn.birthDate || cn.birthPlace) {
            try { window.FeIDo.setClaims(cn); console.info('[feido] Claims captured from verifier and stored'); } catch {}
            return true;
          }
        }
        return false;
      };
      // fetch hook
      const __origFetch = window.fetch;
      window.fetch = async (...args)=>{
        const res = await __origFetch.apply(window, args);
        try {
          const clone = res.clone();
          const ct = (clone.headers && clone.headers.get && clone.headers.get('content-type')) || '';
          if (ct && ct.includes('application/json')) {
            const json = await clone.json();
            tryExtractClaims(json);
          }
        } catch {}
        return res;
      };
      // XHR hook
      const __OrigXHR = window.XMLHttpRequest;
      function XHRWrap(){ const xhr = new __OrigXHR(); return xhr; }
      XHRWrap.prototype = __OrigXHR.prototype;
      const open = __OrigXHR.prototype.open;
      const send = __OrigXHR.prototype.send;
      XHRWrap.prototype.open = function(){ return open.apply(this, arguments); };
      XHRWrap.prototype.send = function(){
        this.addEventListener('load', function(){
          try {
            const ct = this.getResponseHeader('content-type') || '';
            if (ct.includes('application/json') && this.responseText) {
              const data = JSON.parse(this.responseText);
              tryExtractClaims(data);
            }
          } catch {}
        });
        return send.apply(this, arguments);
      };
      window.XMLHttpRequest = XHRWrap;
    }
  })();

  const __u8 = (o)=>{
    if (o instanceof Uint8Array) return o;
    if (o instanceof ArrayBuffer) return new Uint8Array(o);
    if (Array.isArray(o)) return new Uint8Array(o);
    if (o && typeof o === 'object') {
      const keys = Object.keys(o).filter(k=>!isNaN(k)).sort((a,b)=>Number(a)-Number(b));
      if (keys.length) return new Uint8Array(keys.map(k=>Number(o[k]) & 0xff));
    }
    return new Uint8Array();
  };
  const __b64FromU8 = (u8)=>{
    let s = '';
    for (let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  };
  const __b64ToB64url = (s)=> s.replace(/[+]/g,'-').replace(/[\/]/g,'_').replace(/=+$/,'');
  const __b64u = (u8)=> __b64ToB64url(__b64FromU8(u8));
  const __arrBuf = (u8)=>{ const c=new Uint8Array(u8.length); c.set(u8); return c.buffer; };
  const __encodeTxt = (str)=> new TextEncoder().encode(str);
  const __decodeTxt = (buf)=> new TextDecoder().decode(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf);
  
  // intercept webauthn credentials.get and forward to FeIDo extension
  navigator.credentials.get = async function(opts) {
    console.log("Intercepted navigator.credentials.get().");
    // Rimuovi il campo signal se presente
    if (opts && opts.signal) {
      delete opts.signal;
      console.warn("Removed AbortSignal from opts to avoid cloning errors. (FeIDo)");
    }
    // Conditional UI: se non abbiamo allowCredentials lasciamo passare alla funzione nativa per non rompere UX
    if (opts && opts.mediation === 'conditional' && (!opts.publicKey || !opts.publicKey.allowCredentials || opts.publicKey.allowCredentials.length === 0)) {
      try {
        return await __origGet(opts);
      } catch (e) {
        // Riemetti l'eccezione nativa (es. NotAllowedError) così la lib gestisce correttamente
        throw e;
      }
    }
    // Normalizza campi binari e challenge in stringa base64url
    const __toU8 = (o)=>{
      if (o instanceof Uint8Array) return o;
      if (o instanceof ArrayBuffer) return new Uint8Array(o);
      if (Array.isArray(o)) return new Uint8Array(o);
      if (o && typeof o === 'object') {
        const keys = Object.keys(o).filter(k=>!isNaN(k)).sort((a,b)=>Number(a)-Number(b));
        if (keys.length) return new Uint8Array(keys.map(k=>Number(o[k]) & 0xff));
      }
      return new Uint8Array();
    };
    const __b64FromU8 = (u8)=>{
      let s = '';
      for (let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
      return btoa(s);
    };
    const __b64ToB64url = (s)=>{
      let out = '';
      for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === '+') out += '-';
        else if (c === '/') out += '_';
        else if (c === '=') { /* drop padding */ }
        else out += c;
      }
      return out;
    };
    const __b64u = (u8)=> __b64ToB64url(__b64FromU8(u8));
    const pkSrc = opts && opts.publicKey ? opts.publicKey : {};
    const norm = { ...opts, publicKey: { ...pkSrc } };
    if (norm && norm.publicKey) {
      const pk = norm.publicKey;
      // Do not coerce challenge here; let background handle binary vs string
      if (pk.allowCredentials && Array.isArray(pk.allowCredentials)) {
        pk.allowCredentials = pk.allowCredentials.map(ac => ({
          ...ac,
          id: Array.from(__toU8(ac.id))
        }));
      }
    }
    const __rid = Date.now().toString(36) + Math.random().toString(36).slice(2);
    // Stash original challenge if present
    try {
      const pk = norm && norm.publicKey;
      if (pk && pk.challenge) {
        const ch = typeof pk.challenge === 'string' ? pk.challenge : __b64u(__u8(pk.challenge));
        __expectedChallengeById[__rid] = ch;
      }
    } catch {}
  console.log('[feido] get expected challenge for', __rid, __expectedChallengeById[__rid]);
  window.postMessage([norm, "fromWebsite", "credentials.get", __rid, __expectedChallengeById[__rid]], location.origin);
  // listen for postMessage from content script and in Promise 
  return new Promise(resolve => {
      const toU8 = (o)=>{
        if (o instanceof Uint8Array) return o;
        if (o instanceof ArrayBuffer) return new Uint8Array(o);
        if (Array.isArray(o)) return new Uint8Array(o);
        if (o && typeof o === 'object') {
          const keys = Object.keys(o).filter(k=>!isNaN(k)).sort((a,b)=>Number(a)-Number(b));
          if (keys.length) return new Uint8Array(keys.map(k=>Number(o[k]) & 0xff));
        }
        return new Uint8Array();
      };
      const __handler = function(event) {
          if (event.source == window && event.data && event.data[1] == "fromContentScript") {
            const envelope = event.data[0];
            if (!envelope || envelope.reqId !== __rid || envelope.opType !== 'credentials.get') return;
            console.log("Received message from content script." + JSON.stringify(event.data));
            const data = envelope.payload;
            // Rebuild a PublicKeyCredential-like object in page context
            const cred = { type: data.type || 'public-key' };
            {
              const u = toU8(data.rawId);
              const c = new Uint8Array(u.length); c.set(u);
              cred.rawId = c.buffer;
            }
            cred.getClientExtensionResults = () => ({ });
            const __b64FromU8 = (u8)=>{
              // Build in chunks to avoid call stack limits
              let s = '';
              const chunk = 0x8000;
              for (let i=0;i<u8.length;i+=chunk) {
                const sub = u8.subarray(i, i+chunk);
                s += String.fromCharCode.apply(null, Array.from(sub));
              }
              return btoa(s);
            };
            const __b64ToB64url = (s)=>{
              let out = '';
              for (let i = 0; i < s.length; i++) {
                const c = s[i];
                if (c === '+') out += '-';
                else if (c === '/') out += '_';
                else if (c === '=') { /* drop padding */ }
                else out += c;
              }
              return out;
            };
            const b64u = (u8)=> __b64ToB64url(__b64FromU8(u8));
            cred.toJSON = ()=>{
              const out = { id: cred.id, type: cred.type, rawId: b64u(new Uint8Array(cred.rawId)), response: {} };
              if (cred.response) {
                for (const k of ['clientDataJSON','attestationObject','authenticatorData','signature','userHandle']){
                  if (cred.response[k]) out.response[k] = b64u(new Uint8Array(cred.response[k]));
                }
              }
              out.clientExtensionResults = cred.getClientExtensionResults();
              return out;
            };
            // Ensure id is the base64url of rawId
            cred.id = b64u(new Uint8Array(cred.rawId));
              if (data.response) {
                // Flat attestation shape
                if (data.response.clientDataJSON && data.response.attestationObject) {
                  const cd = toU8(data.response.clientDataJSON);
                  const ao = toU8(data.response.attestationObject);
                  const cd2 = new Uint8Array(cd.length); cd2.set(cd);
                  const ao2 = new Uint8Array(ao.length); ao2.set(ao);
                  cred.response = { clientDataJSON: cd2.buffer, attestationObject: ao2.buffer };
                }
                // Nested attestation
                else if (data.response.authenticatorAttestationResponse) {
                  const r = data.response.authenticatorAttestationResponse;
                  {
                    const cd = toU8(r.clientDataJSON);
                    const ao = toU8(r.attestationObject);
                    const cd2 = new Uint8Array(cd.length); cd2.set(cd);
                    const ao2 = new Uint8Array(ao.length); ao2.set(ao);
                    cred.response = { clientDataJSON: cd2.buffer, attestationObject: ao2.buffer };
                  }
                }
                // Flat assertion shape
                else if (data.response.clientDataJSON && data.response.authenticatorData && data.response.signature) {
                  const cd = toU8(data.response.clientDataJSON);
                  const ad = toU8(data.response.authenticatorData);
                  const sg = toU8(data.response.signature);
                  const uh = toU8(data.response.userHandle);
                  const cd2 = new Uint8Array(cd.length); cd2.set(cd);
                  const ad2 = new Uint8Array(ad.length); ad2.set(ad);
                  const sg2 = new Uint8Array(sg.length); sg2.set(sg);
                  const uh2 = new Uint8Array(uh.length); uh2.set(uh);
                  cred.response = { clientDataJSON: cd2.buffer, authenticatorData: ad2.buffer, signature: sg2.buffer, userHandle: uh2.buffer };
                }
                // Nested assertion
                else if (data.response.authenticatorAssertionResponse) {
                  const r = data.response.authenticatorAssertionResponse;
                  {
                    const cd = toU8(r.clientDataJSON);
                    const ad = toU8(r.authenticatorData);
                    const sg = toU8(r.signature);
                    const uh = toU8(r.userHandle);
                    const cd2 = new Uint8Array(cd.length); cd2.set(cd);
                    const ad2 = new Uint8Array(ad.length); ad2.set(ad);
                    const sg2 = new Uint8Array(sg.length); sg2.set(sg);
                    const uh2 = new Uint8Array(uh.length); uh2.set(uh);
                    cred.response = { clientDataJSON: cd2.buffer, authenticatorData: ad2.buffer, signature: sg2.buffer, userHandle: uh2.buffer };
                  }
                } else {
                  cred.response = {};
                }
                // Enforce expected challenge after response has been assembled
                if (cred.response && cred.response.clientDataJSON) {
                  try {
                    const exp = __expectedChallengeById[__rid];
                    if (exp) {
                      const json = JSON.parse(__decodeTxt(cred.response.clientDataJSON));
                      if (!json.challenge || json.challenge !== exp) {
                        json.challenge = exp;
                        cred.response.clientDataJSON = __arrBuf(__encodeTxt(JSON.stringify(json)));
                        console.log('[feido] get clientDataJSON rewritten with expected challenge');
                      }
                    }
                  } catch {}
                }
              } else {
                cred.response = {};
              }
            window.removeEventListener("message", __handler);
            resolve(cred);
          }};
      window.addEventListener("message", __handler);
        });
  };

  // intercept webauthn credentials.create and forward to FeIDo extension
  navigator.credentials.create = async function(opts) {
    console.log("Intercepted navigator.credentials.create().");
    // Rimuovi il campo signal se presente
    if (opts && opts.signal) {
      delete opts.signal;
      console.warn("Removed AbortSignal from opts to avoid cloning errors. (FeIDo)");
    }
    // Normalizza campi binari e challenge in stringa base64url
    const __toU8 = (o)=>{
      if (o instanceof Uint8Array) return o;
      if (o instanceof ArrayBuffer) return new Uint8Array(o);
      if (Array.isArray(o)) return new Uint8Array(o);
      if (o && typeof o === 'object') {
        const keys = Object.keys(o).filter(k=>!isNaN(k)).sort((a,b)=>Number(a)-Number(b));
        if (keys.length) return new Uint8Array(keys.map(k=>Number(o[k]) & 0xff));
      }
      return new Uint8Array();
    };
    const __b64FromU8 = (u8)=>{
      let s = '';
      for (let i=0;i<u8.length;i++) s += String.fromCharCode(u8[i]);
      return btoa(s);
    };
    const __b64ToB64url = (s)=>{
      let out = '';
      for (let i = 0; i < s.length; i++) {
        const c = s[i];
        if (c === '+') out += '-';
        else if (c === '/') out += '_';
        else if (c === '=') { /* drop padding */ }
        else out += c;
      }
      return out;
    };
    const __b64u = (u8)=> __b64ToB64url(__b64FromU8(u8));
    const pkSrc = opts && opts.publicKey ? opts.publicKey : {};
    const norm = { ...opts, publicKey: { ...pkSrc } };
    if (norm && norm.publicKey) {
      const pk = norm.publicKey;
      // Do not coerce challenge or user.id here; let background handle
      if (pk.excludeCredentials && Array.isArray(pk.excludeCredentials)) {
        pk.excludeCredentials = pk.excludeCredentials.map(ec => ({
          ...ec,
          id: Array.from(__toU8(ec.id))
        }));
      }
    }
    const __rid = Date.now().toString(36) + Math.random().toString(36).slice(2);
    // Stash original challenge if present
    try {
      const pk = norm && norm.publicKey;
      if (pk && pk.challenge) {
        const ch = typeof pk.challenge === 'string' ? pk.challenge : __b64u(__u8(pk.challenge));
        __expectedChallengeById[__rid] = ch;
      }
    } catch {}
  console.log('[feido] create expected challenge for', __rid, __expectedChallengeById[__rid]);
  window.postMessage([norm, "fromWebsite", "credentials.create", __rid, __expectedChallengeById[__rid]], location.origin);
  // listen for postMessage from content script and in Promise 
  return new Promise(resolve => {
      const toU8 = (o)=>{
        if (o instanceof Uint8Array) return o;
        if (o instanceof ArrayBuffer) return new Uint8Array(o);
        if (Array.isArray(o)) return new Uint8Array(o);
        if (o && typeof o === 'object') {
          const keys = Object.keys(o).filter(k=>!isNaN(k)).sort((a,b)=>Number(a)-Number(b));
          if (keys.length) return new Uint8Array(keys.map(k=>Number(o[k]) & 0xff));
        }
        return new Uint8Array();
      };
      const __handler = function(event) {
          if (event.source == window && event.data && event.data[1] == "fromContentScript") {
            const envelope = event.data[0];
            if (!envelope || envelope.reqId !== __rid || envelope.opType !== 'credentials.create') return;
            console.log("Received message from content script." + JSON.stringify(event.data));
            const data = envelope.payload;
            const cred = { type: data.type || 'public-key' };
            {
              const u = toU8(data.rawId);
              const c = new Uint8Array(u.length); c.set(u);
              cred.rawId = c.buffer;
            }
            cred.getClientExtensionResults = () => ({ });
            const __b64FromU8 = (u8)=>{
              let s = '';
              const chunk = 0x8000;
              for (let i=0;i<u8.length;i+=chunk) {
                const sub = u8.subarray(i, i+chunk);
                s += String.fromCharCode.apply(null, Array.from(sub));
              }
              return btoa(s);
            };
            const __b64ToB64url = (s)=>{
              let out = '';
              for (let i = 0; i < s.length; i++) {
                const c = s[i];
                if (c === '+') out += '-';
                else if (c === '/') out += '_';
                else if (c === '=') { /* drop padding */ }
                else out += c;
              }
              return out;
            };
            const b64u = (u8)=> __b64ToB64url(__b64FromU8(u8));
            cred.toJSON = ()=>{
              const out = { id: cred.id, type: cred.type, rawId: b64u(new Uint8Array(cred.rawId)), response: {} };
              if (cred.response) {
                for (const k of ['clientDataJSON','attestationObject','authenticatorData','signature','userHandle']){
                  if (cred.response[k]) out.response[k] = b64u(new Uint8Array(cred.response[k]));
                }
              }
              out.clientExtensionResults = cred.getClientExtensionResults();
              return out;
            };
            // Ensure id is the base64url of rawId
            cred.id = b64u(new Uint8Array(cred.rawId));
            if (data.response && data.response.clientDataJSON && data.response.attestationObject) {
              const cd = toU8(data.response.clientDataJSON);
              const ao = toU8(data.response.attestationObject);
              const cd2 = new Uint8Array(cd.length); cd2.set(cd);
              const ao2 = new Uint8Array(ao.length); ao2.set(ao);
              cred.response = { clientDataJSON: cd2.buffer, attestationObject: ao2.buffer };
            } else if (data.response && data.response.authenticatorAttestationResponse) {
              const r = data.response.authenticatorAttestationResponse;
              const cd = toU8(r.clientDataJSON);
              const ao = toU8(r.attestationObject);
              const cd2 = new Uint8Array(cd.length); cd2.set(cd);
              const ao2 = new Uint8Array(ao.length); ao2.set(ao);
              cred.response = { clientDataJSON: cd2.buffer, attestationObject: ao2.buffer };
            } else if (data.response && data.response.authenticatorAssertionResponse) {
              const r = data.response.authenticatorAssertionResponse;
              const cd = toU8(r.clientDataJSON);
              const ad = toU8(r.authenticatorData);
              const sg = toU8(r.signature);
              const uh = toU8(r.userHandle);
              const cd2 = new Uint8Array(cd.length); cd2.set(cd);
              const ad2 = new Uint8Array(ad.length); ad2.set(ad);
              const sg2 = new Uint8Array(sg.length); sg2.set(sg);
              const uh2 = new Uint8Array(uh.length); uh2.set(uh);
              cred.response = { clientDataJSON: cd2.buffer, authenticatorData: ad2.buffer, signature: sg2.buffer, userHandle: uh2.buffer };
            } else {
              cred.response = {};
            }
            // Enforce expected challenge after response has been assembled
            if (cred.response && cred.response.clientDataJSON) {
              try {
                const exp = __expectedChallengeById[__rid];
                if (exp) {
                  const json = JSON.parse(__decodeTxt(cred.response.clientDataJSON));
                  if (!json.challenge || json.challenge !== exp) {
                    json.challenge = exp;
                    cred.response.clientDataJSON = __arrBuf(__encodeTxt(JSON.stringify(json)));
                    console.log('[feido] create clientDataJSON rewritten with expected challenge');
                  }
                }
              } catch {}
            }
            window.removeEventListener("message", __handler);
            resolve(cred);
          }};
      window.addEventListener("message", __handler);
        });
  };
`;

// inject code into website
var script = document.createElement('script');
script.textContent = code;
(document.head || document.documentElement).appendChild(script);
script.remove();

// listen for postMessage from website and forward to background script
window.addEventListener("message", function (event) {
  if (event.source == window && event.data && event.data[1] == "fromWebsite") {
    console.log("Forwarding navigator." + event.data[2] + " to background script.");
  const toPlain = (v)=>{
      if (v == null) return v;
      if (v instanceof ArrayBuffer) return Array.from(new Uint8Array(v));
      if (ArrayBuffer.isView(v)) return Array.from(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
      if (Array.isArray(v)) return v.map(toPlain);
      if (typeof v === 'object') {
        const out = {};
        for (const k of Object.keys(v)) out[k] = toPlain(v[k]);
        return out;
      }
      return v;
    };
  const safeOpts = toPlain(event.data[0]);
  const reqId = event.data[3];
  // Prefer original challenge passed explicitly from injected page
  let originalChallenge = event.data[4];
  if (!originalChallenge) {
    // Fallback: try to reconstruct
    try {
      const pk = event.data[0] && event.data[0].publicKey;
      if (pk && pk.challenge) {
        if (typeof pk.challenge === 'string') originalChallenge = pk.challenge;
        else {
          const u8 = (pk.challenge instanceof ArrayBuffer) ? new Uint8Array(pk.challenge)
            : (Array.isArray(pk.challenge) ? new Uint8Array(pk.challenge) : (ArrayBuffer.isView(pk.challenge) ? new Uint8Array(pk.challenge.buffer, pk.challenge.byteOffset, pk.challenge.byteLength) : new Uint8Array()));
          const b64 = btoa(String.fromCharCode.apply(null, Array.from(u8)));
          originalChallenge = b64.replace(/=+$/,'').replace(/\+/g,'-').replace(/\//g,'_');
        }
      }
    } catch {}
  }
  browser.runtime.sendMessage({ "opts": safeOpts, "type": event.data[2], "origin": location.origin, "reqId": reqId, "originalChallenge": originalChallenge })
  }
  // Handle FeIDo page API messages (setClaims/setDigest/clear)
  if (event.source === window && event.data && event.data.channel === 'feido') {
    const op = event.data.op;
    if (op === 'setClaims') {
      const claims = event.data.claims || {};
      let expiryIso = null;
      if (event.data && typeof event.data.expiryISO === 'string') {
        const trimmed = event.data.expiryISO.trim();
        if (trimmed) {
          const parsed = new Date(trimmed);
          if (!Number.isNaN(parsed.getTime())) {
            expiryIso = parsed.toISOString();
          }
        }
      } else if (event.data && event.data.meta && typeof event.data.meta.expiryISO === 'string') {
        const trimmed = event.data.meta.expiryISO.trim();
        if (trimmed) {
          const parsed = new Date(trimmed);
          if (!Number.isNaN(parsed.getTime())) {
            expiryIso = parsed.toISOString();
          }
        }
      }
      
      // Encrypt claims before storing
      browser.runtime.sendMessage({
        action: 'feido.encryptClaims',
        claims: claims
      }).then((encryptResponse) => {
        if (!encryptResponse || !encryptResponse.ok) {
          console.error('[feido][overwrite] encryption failed:', encryptResponse && encryptResponse.error);
          window.postMessage({ channel:'feido', ack:false, op, error: 'encryption_failed' }, location.origin);
          return;
        }
        
        const storePayload = { feidoClaims: encryptResponse.encrypted };
        storePayload.feidoClaimsMeta = expiryIso ? { expiryISO: expiryIso } : null;
        browser.storage.local.set(storePayload).then(()=>{
          window.postMessage({ channel:'feido', ack:true, op }, location.origin);
        });
      }).catch((err) => {
        console.error('[feido][overwrite] encryption error:', err);
        window.postMessage({ channel:'feido', ack:false, op, error: 'encryption_error' }, location.origin);
      });
    } else if (op === 'clear') {
        browser.storage.local.set({ feidoClaims: null, feidoClaimsMeta: null }).then(()=>{
        window.postMessage({ channel:'feido', ack:true, op }, location.origin);
      });
    }
  }
});

// listen for sendMessage from background script and forward to injected code
browser.runtime.onMessage.addListener(function (event) {
  console.log("Recevied sendMessage from background script: " + event);
  // Log challenge type before forwarding to the page
  let msg = event.publicKey ? event.publicKey : event;
  console.log("Tipo challenge inviato alla pagina:", typeof msg.challenge, msg.challenge && msg.challenge.constructor && msg.challenge.constructor.name);
  window.postMessage([event, "fromContentScript"], location.origin);
});

