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

window.addEventListener('load', function(){
  const f = document.getElementById('file');
  const closeBtn = document.getElementById('close');
  const importControls = document.getElementById('importControls');
  const importPassInline = document.getElementById('importPassInline');
  const importOkInline = document.getElementById('importOkInline');
  const importCancelInline = document.getElementById('importCancelInline');
  const importError = document.getElementById('importError');
  const importPassToggle = document.getElementById('importPassToggle');
  const importSuccess = document.getElementById('importSuccess');
  const fileNameEl = document.getElementById('fileName');
  const defaultFileLabel = 'No file selected.';
  const mergeOptionWrap = document.getElementById('mergeOptionWrap');
  const mergeOption = document.getElementById('mergeOption');
  if (fileNameEl) fileNameEl.textContent = defaultFileLabel;
  let mergeAvailable = false;

  async function refreshImportContext(){
    try {
      const ping = await browser.runtime.sendMessage({ action: 'feido.ping' });
      mergeAvailable = !!(ping && ping.exists);
    } catch (_) {
      mergeAvailable = false;
    }
    if (mergeOptionWrap) {
      mergeOptionWrap.classList.toggle('visible', mergeAvailable);
    }
    if (mergeOption) {
      mergeOption.checked = mergeAvailable ? true : false;
      mergeOption.disabled = !mergeAvailable;
    }
  }
  refreshImportContext();
  const logMessage = (...args)=>{ try { console.log('[feido][import]', ...args); } catch(_){} };
  let passVisibility = false;
  function updatePassVisibility(forceState){
    if (typeof forceState === 'boolean') passVisibility = forceState;
    if (importPassInline) importPassInline.type = passVisibility ? 'text' : 'password';
    if (importPassToggle) {
      importPassToggle.setAttribute('aria-pressed', String(passVisibility));
      importPassToggle.setAttribute('aria-label', passVisibility ? 'Hide passphrase' : 'Show passphrase');
    }
  }
  if (importPassToggle) {
    importPassToggle.addEventListener('click', ()=>{
      passVisibility = !passVisibility;
      updatePassVisibility();
      if (importPassInline) {
        importPassInline.focus({ preventScroll: true });
        try {
          const len = importPassInline.value.length;
          importPassInline.setSelectionRange(len, len);
        } catch(_) {}
      }
    });
  }
  function setInlineError(message){
    if (!importError) return;
    if (message){
      importError.textContent = message;
      importError.classList.add('visible');
      importError.setAttribute('aria-hidden', 'false');
    } else {
      importError.textContent = '';
      importError.classList.remove('visible');
      importError.setAttribute('aria-hidden', 'true');
    }
  }
  function setSuccessMessage(message){
    if (!importSuccess) return;
    if (message){
      importSuccess.textContent = message;
      importSuccess.classList.add('visible');
      importSuccess.setAttribute('aria-hidden', 'false');
    } else {
      importSuccess.textContent = '';
      importSuccess.classList.remove('visible');
      importSuccess.setAttribute('aria-hidden', 'true');
    }
  }
  function hidePassphrasePrompt(){
    if (!importControls) return;
    importControls.style.display = 'none';
    setInlineError('');
    if (importPassInline) importPassInline.value = '';
    if (importOkInline) importOkInline.disabled = true;
    updatePassVisibility(false);
  }
  async function promptForPassphrase(errorMessage){
    if (!importControls || !importPassInline || !importOkInline || !importCancelInline) return null;
    if (errorMessage) setSuccessMessage('');
    setInlineError(errorMessage);
    importControls.style.display = 'block';
    importPassInline.value = '';
    updatePassVisibility(false);
    importPassInline.focus();
    const updateState = ()=>{
      if (importOkInline) importOkInline.disabled = !importPassInline.value;
    };
    updateState();
    importPassInline.addEventListener('input', updateState);
    return new Promise((resolve) => {
      function cleanup(){
        importOkInline.removeEventListener('click', onOk);
        importCancelInline.removeEventListener('click', onCancel);
        importPassInline.removeEventListener('keydown', onKey);
        importPassInline.removeEventListener('input', updateState);
      }
      function onOk(){ cleanup(); resolve(importPassInline.value); }
      function onCancel(){ cleanup(); resolve(null); }
      function onKey(ev){
        if (ev.key === 'Enter') {
          if (importPassInline.value) onOk();
        } else if (ev.key === 'Escape') {
          onCancel();
        }
      }
      importOkInline.addEventListener('click', onOk);
      importCancelInline.addEventListener('click', onCancel);
      importPassInline.addEventListener('keydown', onKey);
    });
  }
  hidePassphrasePrompt();
  f.addEventListener('change', async (ev)=>{
    const file = ev.target.files && ev.target.files[0];
    if(!file){ if (fileNameEl) fileNameEl.textContent = defaultFileLabel; return; }
  if (fileNameEl) fileNameEl.textContent = file.name;
  setSuccessMessage('');
  logMessage('Selected file', file.name);
    try{
        const txt = await file.text();
        const obj = JSON.parse(txt);
        // mode selection via query param
        const params = new URLSearchParams(location.search);
        const mode = params.get('mode') || 'auto';
        if (mode === 'all' || (obj && obj.deviceEnc && obj.credsEnc)){
          logMessage('Detected combined package (deviceEnc + credsEnc)');
          let errorMessage = null;
          let passphraseAttempt = null;
          while (true){
            passphraseAttempt = await promptForPassphrase(errorMessage);
            if (passphraseAttempt === null){
              hidePassphrasePrompt();
              logMessage('Import cancelled (no passphrase)');
              return;
            }
            const mergeChoice = mergeAvailable && mergeOption && mergeOption.checked;
            try{
              const payload = { action: 'feido.importAll', package: obj, passphrase: passphraseAttempt, merge: mergeChoice };
              logMessage('Sending import request', { merge: mergeChoice });
              const res = await browser.runtime.sendMessage(payload);
              logMessage('Background responded', res);
              const errorCode = (res && res.error) ? String(res.error) : '';
              const errorDetail = (res && res.message) ? String(res.message) : errorCode;
              if (res && res.ok){
                hidePassphrasePrompt();
                refreshImportContext();
                const stats = (res && res.stats) || {};
                if (res.mode === 'merge'){
                  const added = stats.added || 0;
                  const updated = stats.updated || 0;
                  const totalRemote = stats.totalRemote || 0;
                  const secretHandled = stats.deviceSecretHandled || 'unchanged';
                  const secretNote = secretHandled === 'imported' ? ' Device secret imported.' : '';
                  setSuccessMessage(`Merge completed successfully. Added ${added} and updated ${updated} credential(s). Close this tab and unlock if needed.${secretNote}`);
                  logMessage('Merge stats', { added, updated, totalRemote, deviceSecretHandled: secretHandled });
                } else {
                  const importedCount = stats.importedCount || 0;
                  const totalKeys = stats.totalKeys || 0;
                  setSuccessMessage(`Import completed successfully. Imported ${importedCount} credential(s). Close this tab and unlock if needed.`);
                  logMessage('Import stats', { importedCount, totalKeys });
                }
                break;
              }
              if (errorCode === 'wrong_passphrase' || /operation/i.test(errorDetail) || /authentication tag/i.test(errorDetail)){
                errorMessage = 'Incorrect passphrase. Please try again.';
                logMessage('Incorrect passphrase response');
                setSuccessMessage('');
                continue;
              }
              if (errorCode === 'merge_device_secret_mismatch'){
                errorMessage = 'Merge failed: backup belongs to a different device secret. Disable merge to replace everything.';
                logMessage('Merge failed: device secret mismatch');
                if (mergeOption) mergeOption.checked = false;
                setSuccessMessage('');
                continue;
              }
              if (errorCode === 'merge_device_secret_decrypt_failed'){
                errorMessage = 'Merge failed: the passphrase does not unlock the backup\'s device secret. Enter the original device passphrase or disable merge to replace everything.';
                logMessage('Merge halted: passphrase cannot decrypt backup device secret');
                setSuccessMessage('');
                continue;
              }
              if (errorCode === 'merge_requires_unlock'){
                errorMessage = 'Unlock the extension in the popup before merging, or disable merge to overwrite.';
                logMessage('Merge halted: extension locked');
                setSuccessMessage('');
                continue;
              }
              if (errorCode === 'merge_missing_device_secret'){
                errorMessage = 'Backup is missing the device secret required for merge. Disable merge to continue.';
                logMessage('Merge unavailable: backup missing device secret');
                if (mergeOption) mergeOption.checked = false;
                setSuccessMessage('');
                continue;
              }
              hidePassphrasePrompt();
              logMessage('Full import failed', errorDetail);
              setSuccessMessage('');
              break;
            }catch(e){
              hidePassphrasePrompt();
              logMessage('runtime sendMessage failed', e && e.message || e);
              logMessage('Falling back to storage write for full package');
              try {
                await browser.storage.local.set({ feidoAllImportCandidate: { package: obj, passphraseHint: !!passphraseAttempt } });
                logMessage('Stored feidoAllImportCandidate for background processing');
              } catch(storageErr){
                logMessage('Failed to store fallback import candidate', storageErr && storageErr.message || storageErr);
              }
              setSuccessMessage('');
              break;
            }
          }
          return;
        } else {
          // auto-detect previous modes
          const looksLikeEncSecret = obj && obj.salt && obj.iv && obj.ct;
          const looksLikeCredRecords = obj && Object.keys(obj).some(k => String(k).startsWith('feidoCreds_'));
          if (looksLikeEncSecret) {
            logMessage('Detected encrypted device secret file; sending to background');
            try{
              // Prefer combined importAll flow: wrap deviceEnc in package and ask user to import via UI
              const pkg = { deviceEnc: obj, credsEnc: null };
              const res = await browser.runtime.sendMessage({ action: 'feido.importAll', package: pkg, passphrase: null });
              logMessage('Background responded', res);
              if (res && res.ok){
                setSuccessMessage('Device secret import complete. Close this tab and unlock the extension with your passphrase.');
              } else {
                logMessage('Device secret import failed', res && res.error);
                setSuccessMessage('');
              }
            }catch(e){
              logMessage('runtime sendMessage failed', e && e.message || e);
              logMessage('Falling back to storage write for device secret');
              await browser.storage.local.set({ feidoAllImportCandidate: { package: { deviceEnc: obj, credsEnc: null } } });
              logMessage('Stored feidoAllImportCandidate for device secret import');
              setSuccessMessage('');
            }
          } else if (looksLikeCredRecords) {
            logMessage('Detected credential-records file; import not supported');
            try{
              // Wrap credentials into combined package with null deviceEnc and ask user for passphrase to encrypt them locally on import
              const pkg = { deviceEnc: null, credsEnc: null };
                // Raw credentials import is no longer supported. Inform the user.
                throw new Error('raw_creds_import_not_supported');
            }catch(e){ logMessage('Credential records import failed', e && e.message || e); setSuccessMessage(''); }
          } else {
            logMessage('Invalid file: not recognized as encrypted device secret or credential records');
            return;
          }
        }
    }catch(e){ logMessage('Error reading file', e && e.message || e); }
  });
  closeBtn.addEventListener('click', ()=>window.close());
});
