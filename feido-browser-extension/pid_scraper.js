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

// pid_scraper.js (minimal)
(function () {
  // Enforce strict origin check: only run on the expected HTTPS origin
  const ALLOWED_ORIGIN = 'https://verifier.eudiw.dev';
  if (location.origin !== ALLOWED_ORIGIN) return;
  console.log('[feido][pid_scraper] injected (origin OK)', location.origin);

  // PID field names as per EU standards
  const ISSUING_FIELD = 'issuing_country';
  const EXPIRY_FIELD = 'expiry_date';
  const GIVEN_FIELD = 'given_name';
  const FAMILY_FIELD = 'family_name';
  const BIRTHDATE_FIELD = 'birth_date';
  const BIRTHPLACE_FIELD = 'place_of_birth';

  // Utility to normalize strings: trim, lowercase, handle nulls
  const normalizeLower = (v) => {
    if (v == null) return '';
    const s = String(v).trim();
    return s ? s.toLowerCase() : '';
  };

  const normalizeExpiryISO = (value) => {
    if (value == null) return null;
    const raw = String(value).trim();
    if (!raw) return null;
    // Allow the value to appear embedded within longer strings; extract the ISO-like segment if present
    const maybeIso = raw.match(/\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?/);
    const candidate = maybeIso ? maybeIso[0] : raw;
    const parsed = new Date(candidate);
    if (Number.isNaN(parsed.getTime())) return null;
    return parsed.toISOString();
  };

  // Normalize and validate extracted claims, then store in browser storage if complete
  async function save(raw) {
    if (!raw || typeof raw !== 'object') return false;
    const claims = {
      givenName: String(raw.givenName || '').trim(),
      familyName: String(raw.familyName || '').trim(),
      birthDate: String(raw.birthDate || '').trim(),
      birthPlace: normalizeLower(raw.birthPlace || ''),
      issuingCountry: normalizeLower(raw.issuingCountry || '')
    };
    const expiryISO = normalizeExpiryISO(raw.expiryDate || raw.expiryISO || raw.expiry || raw.expirationDate || raw.expiration || raw.validUntil);
    if (claims.givenName && claims.familyName && claims.birthDate && claims.birthPlace && claims.issuingCountry) {
      // Encrypt claims before storing
      try {
        const encryptResponse = await browser.runtime.sendMessage({
          action: 'feido.encryptClaims',
          claims: claims
        });
        
        if (!encryptResponse || !encryptResponse.ok) {
          console.error('[feido][pid_scraper] encryption failed:', encryptResponse && encryptResponse.error);
          return false;
        }
        
        const toStore = { feidoClaims: encryptResponse.encrypted };
        if (expiryISO) {
          toStore.feidoClaimsMeta = { expiryISO };
        } else {
          toStore.feidoClaimsMeta = null;
        }
        await browser.storage.local.set(toStore);
        console.log('[feido][pid_scraper] stored encrypted claims');
        try { browser.runtime.sendMessage({ type: 'feidoClaimsStored' }); } catch (e) { }
        return true;
      } catch (e) {
        console.error('[feido][pid_scraper] encryption error:', e);
        return false;
      }
    }
    console.log('[feido][pid_scraper] incomplete, not stored', claims);
    return false;
  }

  // forwarder: inject into page to catch console.log presentation objects
  (function () {
    try {
      const s = document.createElement('script');
      s.textContent = `(()=>{const o=console.log.bind(console); console.log=function(...a){ try{ const ORG='${'https://verifier.eudiw.dev'}'; if (location.origin!==ORG) return o(...a); for(const x of a){ if(x&&typeof x==='object'&&(x.transactionId||x.presentationQuery||x.walletResponse)){ window.postMessage({source:'feido',type:'FEIDO_PRESENTATION_OBJ',obj:x},ORG); } } }catch(e){}; return o(...a); }})();`;
      (document.head || document.documentElement).appendChild(s); s.remove();
    } catch (e) { }
  })();

  // insert custom request on /custom-request/
  (function () {
    if (!location.pathname.includes('/custom-request')) return;
    const payload = JSON.stringify({
      type: 'vp_token',
      dcql_query: {
        credentials: [{
          id: 'query_0',
          format: 'mso_mdoc',
          meta: { doctype_value: 'eu.europa.ec.eudi.pid.1' },
          claims: [FAMILY_FIELD, GIVEN_FIELD, BIRTHDATE_FIELD, BIRTHPLACE_FIELD, ISSUING_FIELD, EXPIRY_FIELD].map(field => ({
            path: ['eu.europa.ec.eudi.pid.1', field],
            intent_to_retain: false
          }))
        }]
      },
      nonce: crypto.randomUUID(),
      request_uri_method: 'post'
    }, null, 2);

    let tries = 0; const maxTries = 60; const intervalMs = 300;
    const id = setInterval(() => {
      tries++;
      const cmContent = document.querySelector('.cm-content[contenteditable="true"]');

      // Stop if already filled
      const existing = (cmContent && (cmContent.innerText || '').trim());
      if (existing && existing.length > 2) { clearInterval(id); return; }

      let done = false;

      // Simulated paste into contentEditable so the app validates properly
      if (cmContent) {
        try {
          cmContent.focus();
          try { document.execCommand('selectAll'); } catch (e) { }
          let ok = false;
          try { ok = document.execCommand('insertText', false, payload); } catch (e) { ok = false; }
          if (!ok) {
            cmContent.innerText = payload;
            cmContent.dispatchEvent(new InputEvent('beforeinput', { bubbles: true, inputType: 'insertFromPaste', data: payload }));
            cmContent.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertFromPaste', data: payload }));
          }
          done = true;
        } catch (e) { }
      }

      if (done) {
        // Release focus to avoid keeping buttons disabled
        try { if (document.activeElement && typeof document.activeElement.blur === 'function') document.activeElement.blur(); } catch (e) { }
        clearInterval(id);
        console.log('[feido][pid_scraper] inserted custom request');
      } else if (tries >= maxTries) {
        clearInterval(id);
      }
    }, intervalMs);
  })();

  // DOM extraction
  function extractFromDOM() {
    try {
      const txt = (document.body && document.body.innerText) || '';
      return extractFromText(txt);
    } catch (e) { return {}; }
  }

  // run regex extraction against arbitrary text (supports label+value concatenated)
  function extractFromText(text) {
    if (!text || typeof text !== 'string') return {};
    const out = {};
    // given_name and family_name can appear concatenated to the value
    const gv = text.match(/eu\.europa\.ec\.eudi\.pid\.1:given_name\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ' -]{1,80})/i);
    if (gv) out.givenName = (gv[1] || '').trim();

    const fm = text.match(/eu\.europa\.ec\.eudi\.pid\.1:family_name\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ' -]{1,80})/i);
    if (fm) out.familyName = (fm[1] || '').trim();

    // birth_date: look near the label; often "value YYYY-MM-DD" or within ~100 chars
    let bd = null;
    const bdIdx = text.search(/eu\.europa\.ec\.eudi\.pid\.1:birth_date/i);
    if (bdIdx >= 0) {
      const snip = text.slice(bdIdx, bdIdx + 200);
      const m = snip.match(/\b(\d{4}-\d{2}-\d{2})\b/) || snip.match(/value\s*(\d{4}-\d{2}-\d{2})/i);
      if (m) bd = m[1];
    }
    if (bd) out.birthDate = bd;

    // place_of_birth: gather locality/region/country following the label
    const pobIdx = text.search(/eu\.europa\.ec\.eudi\.pid\.1:place_of_birth/i);
    if (pobIdx >= 0) {
      const snip = text.slice(pobIdx, pobIdx + 400);
      const localityMatch = snip.match(/\blocality\b\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ' -]{1,80})/i);
      const regionMatch = snip.match(/\bregion\b\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ' -]{1,80})/i);
      const countryMatch = snip.match(/\bcountry\b\s*[:\-]?\s*([A-Za-zÀ-ÖØ-öø-ÿ' -]{1,80})/i);
      const parts = [];
      if (localityMatch && localityMatch[1]) parts.push(localityMatch[1].trim().toLowerCase());
      if (regionMatch && regionMatch[1]) parts.push(regionMatch[1].trim().toLowerCase());
      if (countryMatch && countryMatch[1]) parts.push(countryMatch[1].trim().toLowerCase());
      if (parts.length) out.birthPlace = parts.join(',');
    }
    // issuing_country
    const ic = text.match(/(?:eu\.europa\.ec\.eudi\.pid\.1:issuing_country|issuing[_\s-]?country)[\s:]*([A-Za-z0-9]{2,16})/i);
    if (ic) out.issuingCountry = ic[1].trim();
    // expiry_date (optional)
    const edIdx = text.search(/eu\.europa\.ec\.eudi\.pid\.1:expiry_date|expiry[_\s-]?date/i);
    if (edIdx >= 0) {
      const snip = text.slice(edIdx, edIdx + 200);
      const m = snip.match(/\b(\d{4}-\d{2}-\d{2})(?:[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?/);
      if (m) out.expiryDate = m[0];
    }
    return out;
  }

  // Handle forwarded presentation objects: click 'View Content' button to reveal data, then extract claims from DOM
  window.addEventListener('message', (ev) => {
    try {
      const d = ev.data || {};
      // Accept only messages coming from the allowed page origin
      if (ev.origin !== ALLOWED_ORIGIN) return;
      if (!d || d.source !== 'feido' || d.type !== 'FEIDO_PRESENTATION_OBJ') return;
      console.log('[feido][pid_scraper] presentation forwarded');
      // click View Content to reveal attributes
      const btn = Array.from(document.querySelectorAll('button,a')).find(el => /(view content|view|mostra contenuto|visualizza|open content)/i.test((el.innerText || el.textContent || '').toLowerCase()));
      if (btn) { try { btn.click(); } catch (e) { } }

      let attempts = 0;
      const maxAttempts = 5;
      const delayMs = 2000;

      const runDomExtraction = async () => {
        attempts++;
        const dom = extractFromDOM();
        if (dom && Object.keys(dom).length) {
          console.log(`[feido][pid_scraper] DOM extraction attempt ${attempts}`, dom);
          const stored = await save(dom);
          if (stored) {
            console.log('[feido][pid_scraper] stored claims from DOM extraction');
            return;
          }
          console.log('[feido][pid_scraper] DOM extraction missing required fields');
        } else {
          console.log('[feido][pid_scraper] DOM extraction yielded empty result');
        }
        if (attempts < maxAttempts) {
          setTimeout(runDomExtraction, delayMs);
        } else {
          console.warn('[feido][pid_scraper] DOM extraction exhausted retries without storing claims');
        }
      };

      setTimeout(runDomExtraction, 500);
    } catch (e) { console.warn('[feido][pid_scraper] handler err', e); }
  });

})();
