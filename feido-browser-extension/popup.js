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

window.addEventListener('load', function () {
  const passEl = document.getElementById('passphrase')
  const currentEl = document.getElementById('currentPassphrase')
  const newEl = document.getElementById('newPassphrase')
  const changeSection = document.getElementById('changeSection')
  const toggleChange = document.getElementById('toggleChange')
  const setBtn = document.getElementById('set')
  const changeBtn = document.getElementById('change')
  const unlockBtn = document.getElementById('unlock')
  const lockBtn = document.getElementById('lock')
  // Buttons provided directly in popup.html
  const statusBadge = document.getElementById('statusBadge')
  const log = document.getElementById('log')
  const backupLog = document.getElementById('backupLog')
  const exportAllBtn = document.getElementById('exportAll')
  const importAllBtn = document.getElementById('importAll')
  const passphraseUnlockEl = document.getElementById('passphraseUnlock')
  const exportPassEl = document.getElementById('exportPass')
  const exportPassConfirmEl = document.getElementById('exportPassConfirm')
  const strengthFill = document.getElementById('strengthFill')
  const exportDoBtn = document.getElementById('exportDo')
  const reqIconLen = document.getElementById('reqIconLen')
  const reqIconLower = document.getElementById('reqIconLower')
  const reqIconUpper = document.getElementById('reqIconUpper')
  const reqIconDigit = document.getElementById('reqIconDigit')
  const reqIconSymbol = document.getElementById('reqIconSymbol')
  const reqIconConfirm = document.getElementById('reqIconConfirm')
  // main view set-password controls
  const setPassConfirmEl = document.getElementById('setPassConfirm')
  const setStrengthFill = document.getElementById('setStrengthFill')
  const setReqIconLen = document.getElementById('setReqIconLen')
  const setReqIconLower = document.getElementById('setReqIconLower')
  const setReqIconUpper = document.getElementById('setReqIconUpper')
  const setReqIconDigit = document.getElementById('setReqIconDigit')
  const setReqIconSymbol = document.getElementById('setReqIconSymbol')
  const setReqIconConfirm = document.getElementById('setReqIconConfirm')
  const setHint = document.getElementById('setHint')
  const deviceState = { exists: false, unlocked: false }
  if (exportAllBtn) {
    exportAllBtn.disabled = true
    exportAllBtn.setAttribute('aria-disabled', 'true')
  }

  // Disable persistent popup logs in UI; keep function as no-op so callers remain safe
  function writeLog(s) {
    // no-op: previously used to prepend messages to visible log in popup
    // Kept for compatibility with callers, but intentionally does nothing now.
    return
  }

  // Map internal/error messages to user-friendly text
  function friendlyError(err) {
    if (!err) return 'Unknown error';
    const s = String(err);
  if (s.includes('missing_passphrase')) return 'Missing passphrase. Please enter a passphrase.';
  if (s.includes('no_encrypted_device_secret') || s.includes('FEIDO_DEVICE_SECRET_MISSING')) return 'No device secret found. Use "Set device secret" to initialize.';
  if (s.includes('invalid_decrypted_secret')) return 'Decryption failed: data corrupted or incorrect passphrase.';
  if (s.includes('invalid_current_passphrase') || s.includes('invalid_current_passphrase')) return 'Current passphrase is invalid.';
  if (s.includes('missing_current_passphrase')) return 'Please enter the current passphrase.';
  if (s.includes('device_secret_already_exists') || s.includes('FEIDO_DEVICE_SECRET_EXISTS')) return 'A device secret already exists. Overwriting is not allowed.';
  if (s.includes('missing_package')) return 'Import package missing or invalid.';
    // Generic crypto/subtle errors often have vague DOMException messages
    if (s.includes('The operation failed for an operation-specific') || s.includes('OperationError') || s.includes('DOMException')) {
      return 'Incorrect passphrase or decryption error. Check your passphrase and try again.';
    }
    // Fallback: return the original message
    return s;
  }

  // Show a short status message next to the status badge.
  // type: 'error' | 'success' | 'info'
  function showStatus(message, type = 'info', timeout = 4000) {
    const el = document.getElementById('statusAlert');
    if (!el) return;
    el.textContent = message;
    el.style.display = 'block';
    el.style.opacity = '1';
    el.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
    if (type === 'error') {
      el.style.background = 'rgba(220,53,69,0.08)';
      el.style.color = '#d32f2f';
      el.style.border = '1px solid rgba(220,53,69,0.12)';
    } else if (type === 'success') {
      el.style.background = 'rgba(40,167,69,0.06)';
      el.style.color = '#155724';
      el.style.border = '1px solid rgba(40,167,69,0.12)';
    } else {
      el.style.background = 'rgba(0,0,0,0.03)';
      el.style.color = '#111';
      el.style.border = '1px solid rgba(0,0,0,0.06)';
    }
    // Auto-clear after timeout
    if (timeout > 0) {
      clearTimeout(showStatus._t);
      showStatus._t = setTimeout(() => clearStatus(), timeout);
    }
  }

  function clearStatus() {
    const el = document.getElementById('statusAlert');
    if (!el) return;
    el.style.opacity = '0';
    setTimeout(() => {
      el.style.display = 'none';
      el.textContent = '';
    }, 220);
  }

  // Disable backup inline visible status; keep API for compatibility
  function writeBackup(s){ /* no-op */ }

  async function call(action, payload = {}) {
    return browser.runtime.sendMessage(Object.assign({ action }, payload))
  }

  setBtn.addEventListener('click', async () => {
    const pass = passEl.value || ''
    try {
      const res = await call('feido.setPassphrase', { passphrase: pass })
  if (res && res.ok) { writeLog('set: ok'); showStatus('Device secret set', 'success'); }
  else if (res && res.error) { writeLog('set: error: ' + friendlyError(res.error)); showStatus(friendlyError(res.error), 'error'); }
  else { writeLog('set: unexpected response: ' + JSON.stringify(res)); showStatus('Unexpected response while setting device secret', 'error'); }
      passEl.value = ''
      updateStatus()
  } catch (e) { const msg = friendlyError(e && e.message || e); writeLog('set: exception: ' + msg); showStatus(msg, 'error'); }
  })

  changeBtn.addEventListener('click', async () => {
    const current = currentEl.value || null
    const neu = newEl.value
    if (!neu) { alert('Enter a new passphrase'); return }
    try {
      const res = await call('feido.changePassphrase', { currentPassphrase: current, newPassphrase: neu })
  if (res && res.ok) { writeLog('change: ok'); showStatus('Passphrase changed', 'success'); }
  else if (res && res.error) { writeLog('change: error: ' + friendlyError(res.error)); showStatus(friendlyError(res.error), 'error'); }
  else { writeLog('change: unexpected response: ' + JSON.stringify(res)); showStatus('Unexpected response while changing passphrase', 'error'); }
      currentEl.value = ''
      newEl.value = ''
      updateStatus()
  } catch (e) { const msg = friendlyError(e && e.message || e); writeLog('change: exception: ' + msg); showStatus(msg, 'error'); }
  })

  unlockBtn.addEventListener('click', async () => {
    // Prefer the dedicated unlock input if present (manageArea), otherwise use passEl
    const pass = (passphraseUnlockEl && passphraseUnlockEl.value) ? passphraseUnlockEl.value : (passEl.value || '')
    try {
      const res = await call('feido.unlock', { passphrase: pass })
  if (res && res.ok) { writeLog('unlock: ok'); showStatus('Unlocked', 'success'); }
  else if (res && res.error) { writeLog('unlock: error: ' + friendlyError(res.error)); showStatus(friendlyError(res.error), 'error'); }
  else { writeLog('unlock: unexpected response: ' + JSON.stringify(res)); showStatus('Unexpected response while unlocking', 'error'); }
      // clear both possible inputs
      if (passphraseUnlockEl) passphraseUnlockEl.value = ''
      passEl.value = ''
      updateStatus()
  } catch (e) { const msg = friendlyError(e && e.message || e); writeLog('unlock: exception: ' + msg); showStatus(msg, 'error'); }
  })

  lockBtn.addEventListener('click', async () => {
    try {
      const res = await call('feido.lock')
  if (res && res.ok) { writeLog('lock: ok'); showStatus('Locked', 'success'); }
  else { writeLog('lock: unexpected response: ' + JSON.stringify(res)); showStatus('Unexpected response while locking', 'error'); }
      updateStatus()
  } catch (e) { const msg = friendlyError(e && e.message || e); writeLog('lock: exception: ' + msg); showStatus(msg, 'error'); }
  })

  async function updateStatus() {
    try {
      const res = await call('feido.ping')
      if (res && res.ok) {
        deviceState.exists = !!res.exists
        deviceState.unlocked = !!res.unlocked
        const setArea = document.getElementById('setArea')
        const manageArea = document.getElementById('manageArea')
        if (!res.exists) {
          statusBadge.textContent = 'no secret stored'
          // show only set area + backup
          if (setArea) setArea.style.display = 'block'
          if (manageArea) manageArea.style.display = 'none'
          // make Set primary look
          setPrimaryButton(setBtn)
        } else {
          statusBadge.textContent = (res.unlocked ? 'unlocked' : 'locked')
          // show manage area (unlock/lock/change) and hide set area
          if (setArea) setArea.style.display = 'none'
          if (manageArea) manageArea.style.display = 'block'
          if (res.unlocked) {
            // If unlocked, primary action is to Lock
            setPrimaryButton(lockBtn)
          } else {
            // If exists but locked, primary action is to Unlock
            setPrimaryButton(unlockBtn)
          }
        }
        updateExportAvailability()
      } else if (res && res.error) {
        statusBadge.textContent = 'error'
        deviceState.exists = false
        deviceState.unlocked = false
        updateExportAvailability()
      } else {
        statusBadge.textContent = 'unknown'
        deviceState.exists = false
        deviceState.unlocked = false
        updateExportAvailability()
      }
    } catch (e) {
      statusBadge.textContent = 'unknown'
      deviceState.exists = false
      deviceState.unlocked = false
      updateExportAvailability()
    }
  }

  // Set the primary (blue) button among set/unlock/lock
  function setPrimaryButton(primaryBtn){
    const candidates = [setBtn, unlockBtn, lockBtn];
    candidates.forEach(b => {
      if (!b) return;
      // Keep base 'btn' class; ghost modifier makes it secondary
      if (b === primaryBtn) b.classList.remove('ghost');
      else b.classList.add('ghost');
    })
  }

  function updateExportAvailability(){
    if (!exportAllBtn) return
    const canExport = deviceState.exists && deviceState.unlocked
    exportAllBtn.disabled = !canExport
    exportAllBtn.setAttribute('aria-disabled', String(!canExport))
    if (!canExport) {
      const message = deviceState.exists ? 'Unlock the device secret to create an encrypted backup.' : 'Set a device secret before creating an encrypted backup.'
      exportAllBtn.title = message
      if (backupLog) backupLog.textContent = message
    } else {
      exportAllBtn.title = ''
      if (backupLog) backupLog.textContent = 'Encrypted backups are available while the device secret stays unlocked.'
    }
  }

  toggleChange.addEventListener('click', () => {
    const visible = changeSection.style.display !== 'none'
    changeSection.style.display = visible ? 'none' : 'block'
    toggleChange.textContent = visible ? 'Change passphrase' : 'Hide change'
  })

  // Create encrypted backup (deviceEnc + credsEnc) - ask passphrase to encrypt creds
  // Export flow: controlled by exportDoBtn (requires strong passphrase)
  // Views
  const mainView = document.getElementById('mainView')
  const exportView = document.getElementById('exportView')
  const exportBack = document.getElementById('exportBack')
  const backupCard = document.getElementById('backupCard')
  const exportControls = document.getElementById('exportControls')

  function showExportView(){
    if (!deviceState.unlocked) {
      showStatus('Unlock the device secret before exporting a backup.', 'info', 5000)
      return
    }
    mainView.classList.add('dimmed')
    mainView.classList.remove('active')
    mainView.classList.add('inactive')
    exportView.classList.remove('inactive')
    exportView.classList.add('active')
    if (backupCard) { backupCard.classList.add('inactive'); backupCard.classList.remove('active'); }
    exportPassEl.focus()
  writeLog('exportAll: opened export screen')
  showStatus('Export: enter passphrase to encrypt export', 'info', 5000)
  }
  function showMainView(){
    exportView.classList.remove('active')
    exportView.classList.add('inactive')
    mainView.classList.remove('inactive')
    mainView.classList.add('active')
    mainView.classList.remove('dimmed')
    if (backupCard) { backupCard.classList.remove('inactive'); backupCard.classList.add('active'); }
  writeLog('Returned to main screen')
  showStatus('Returned', 'info', 1500)
  }

  // ensure mainView starts active
  if (mainView && !mainView.classList.contains('active')) mainView.classList.add('active')

  exportAllBtn.addEventListener('click', () => {
    if (exportAllBtn.disabled || !deviceState.unlocked) {
      showStatus('Unlock the device secret before creating an encrypted backup.', 'info', 4000)
      return
    }
    showExportView()
  })
  exportBack.addEventListener('click', () => { showMainView() })

  function scorePassword(p){
    if (!p) return 0
    let score = 0
    if (p.length >= 8) score += 1
    if (p.length >= 12) score += 1
    if (/[a-z]/.test(p)) score += 1
    if (/[A-Z]/.test(p)) score += 1
    if (/[0-9]/.test(p)) score += 1
    if (/[^A-Za-z0-9]/.test(p)) score += 1
    return score
  }

  // Reuse same handlers for main view passphrase validation
  function updateSetStrength(v){
    const s = scorePassword(v)
    const pct = Math.min(100, Math.max(0, (s / 6) * 100))
    if (setStrengthFill) setStrengthFill.style.width = pct + '%'
    if (s <= 2) setStrengthFill.style.background = 'linear-gradient(90deg,#fb7185,#f97316)'
    else if (s <=4) setStrengthFill.style.background = 'linear-gradient(90deg,#f97316,#f59e0b)'
    else setStrengthFill.style.background = 'linear-gradient(90deg,#10b981,#06b6d4)'
  }

  function checkSetRequirements(){
    const v = passEl.value || ''
    const conf = (setPassConfirmEl && setPassConfirmEl.value) || ''
    const hasLower = /[a-z]/.test(v)
    const hasUpper = /[A-Z]/.test(v)
    const hasDigit = /[0-9]/.test(v)
    const hasSymbol = /[^A-Za-z0-9]/.test(v)
    const minLen = v.length >= 12
    const ok = minLen && hasLower && hasUpper && hasDigit && hasSymbol
    updateReqIcon(setReqIconLen, minLen)
    updateReqIcon(setReqIconLower, hasLower)
    updateReqIcon(setReqIconUpper, hasUpper)
    updateReqIcon(setReqIconDigit, hasDigit)
    updateReqIcon(setReqIconSymbol, hasSymbol)
    const confMatch = (conf === v && v.length>0)
    updateReqIcon(setReqIconConfirm, confMatch)
    if (setHint) {
      if (!ok) setHint.style.color = '#b91c1c'
      else setHint.style.color = '#065f46'
      if (conf && conf !== v) { setHint.textContent = 'Password confirmation does not match.'; setHint.style.color = '#b91c1c' }
      else setHint.textContent = 'Password requirements: at least 12 characters and must include lowercase, uppercase, digits, and symbols.'
    }
    // Enable set button only when all rules satisfy
    setBtn.disabled = !(ok && confMatch)
  }

  // Attach listeners for main view
  if (passEl) passEl.addEventListener('input', (ev) => { updateSetStrength(passEl.value || ''); checkSetRequirements() })
  if (setPassConfirmEl) setPassConfirmEl.addEventListener('input', checkSetRequirements)

  exportPassEl.addEventListener('input', (ev) => {
    const v = exportPassEl.value || ''
    const s = scorePassword(v)
    // Map score to width and color
    const pct = Math.min(100, Math.max(0, (s / 6) * 100))
    strengthFill.style.width = pct + '%'
    // color stop based on strength
    if (s <= 2) strengthFill.style.background = 'linear-gradient(90deg,#fb7185,#f97316)'
    else if (s <=4) strengthFill.style.background = 'linear-gradient(90deg,#f97316,#f59e0b)'
    else strengthFill.style.background = 'linear-gradient(90deg,#10b981,#06b6d4)'
  // Require minimum length + all 4 categories (lower, upper, digit, symbol)
  const hasLower = /[a-z]/.test(v)
  const hasUpper = /[A-Z]/.test(v)
  const hasDigit = /[0-9]/.test(v)
  const hasSymbol = /[^A-Za-z0-9]/.test(v)
  const minLen = v.length >= 12
  const ok = minLen && hasLower && hasUpper && hasDigit && hasSymbol
  // update requirement icons
  updateReqIcon(reqIconLen, minLen)
  updateReqIcon(reqIconLower, hasLower)
  updateReqIcon(reqIconUpper, hasUpper)
  updateReqIcon(reqIconDigit, hasDigit)
  updateReqIcon(reqIconSymbol, hasSymbol)
  // confirmation will be checked separately
  const conf = exportPassConfirmEl.value || ''
  const confMatch = (conf === v)
  updateReqIcon(reqIconConfirm, confMatch)
  exportDoBtn.disabled = !(ok && confMatch)
    const exportHint = document.getElementById('exportHint')
    if (!ok) { exportHint.style.color = '#b91c1c' } else { exportHint.style.color = '#065f46' }
    // Also check confirmation match
    if (conf && conf !== v) {
      exportHint.textContent = 'Password confirmation does not match.'
      exportHint.style.color = '#b91c1c'
      exportDoBtn.disabled = true
    } else {
      exportHint.textContent = 'Password requirements: at least 12 characters and must include lowercase, uppercase, digits, and symbols.'
      if (ok) exportHint.style.color = '#065f46'
    }
  })

  exportPassConfirmEl.addEventListener('input', () => {
    const v = exportPassEl.value || ''
    const conf = exportPassConfirmEl.value || ''
    const exportHint = document.getElementById('exportHint')
    if (conf && conf !== v) {
      exportHint.textContent = 'Password confirmation does not match.'
      exportHint.style.color = '#b91c1c'
      updateReqIcon(reqIconConfirm, false)
      exportDoBtn.disabled = true
    } else {
      exportHint.textContent = 'Password requirements: at least 12 characters and must include lowercase, uppercase, digits, and symbols.'
      // Re-run the strength check to decide if button should be enabled
      const s = scorePassword(v)
      const hasLower = /[a-z]/.test(v)
      const hasUpper = /[A-Z]/.test(v)
      const hasDigit = /[0-9]/.test(v)
      const hasSymbol = /[^A-Za-z0-9]/.test(v)
      const minLen = v.length >= 12
      const ok = minLen && hasLower && hasUpper && hasDigit && hasSymbol
      // update icons
      updateReqIcon(reqIconLen, minLen)
      updateReqIcon(reqIconLower, hasLower)
      updateReqIcon(reqIconUpper, hasUpper)
      updateReqIcon(reqIconDigit, hasDigit)
      updateReqIcon(reqIconSymbol, hasSymbol)
      const confMatch = (conf === v)
      updateReqIcon(reqIconConfirm, confMatch)
      exportDoBtn.disabled = !(ok && confMatch)
      if (ok && confMatch) exportHint.style.color = '#065f46'
    }
  })

  function updateReqIcon(el, ok){
    if (!el) return
    if (ok){
      el.style.background = '#10b981'
      el.style.color = '#fff'
      el.textContent = '✓'
    } else {
      el.style.background = '#efefef'
      el.style.color = '#777'
      el.textContent = '•'
    }
  }

  exportDoBtn.addEventListener('click', async () => {
    try {
      if (!deviceState.unlocked) {
        showStatus('Unlock the device secret before exporting a backup.', 'error')
        return
      }
      const pass = exportPassEl.value || ''
  if (!pass) { writeLog('exportAll: no passphrase provided'); showStatus('Please provide an export passphrase', 'error'); return }
      // If button is disabled (shouldn't be clickable), show hint
      if (exportDoBtn.disabled) {
        const exportHint = document.getElementById('exportHint')
        exportHint.textContent = 'Password too weak. Requirements: at least 12 characters and at least 3 of: lowercase, uppercase, digits, symbols.'
        exportHint.style.color = '#b91c1c'
        return
      }
      // Read deviceEnc and credentials
      const st = await browser.storage.local.get(null)
      const deviceEnc = st.feidoDeviceSecretEnc || null
      const creds = {}
      for (const k of Object.keys(st)){
        if (k && k.startsWith('feidoCreds_')) creds[k] = st[k]
      }
      async function deriveKeyFromPassphraseLocal(passphrase, salt){
        const enc = new TextEncoder()
        const baseKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), { name: 'PBKDF2' }, false, ['deriveKey'])
        return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
      }
      async function encryptJsonWithPassphraseLocal(obj, passphrase){
        const txt = JSON.stringify(obj)
        const enc = new TextEncoder()
        const salt = crypto.getRandomValues(new Uint8Array(16))
        const iv = crypto.getRandomValues(new Uint8Array(12))
        const key = await deriveKeyFromPassphraseLocal(passphrase, salt)
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(txt))
        return { salt: Array.from(salt), iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) }
      }
      const credsEnc = await encryptJsonWithPassphraseLocal(creds, pass)
      // produce file
  const packageObj = { deviceEnc, credsEnc }
  const dataStr = JSON.stringify(packageObj, null, 2)
  const url = URL.createObjectURL(new Blob([dataStr], { type: 'application/json' }))
  const today = new Date()
  const formattedDate = today.toISOString().slice(0, 10)
  const filename = `feido_backup_${formattedDate}.json`
  const a = document.createElement('a')
  a.href = url
  a.download = filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
  writeLog('exportAll: downloaded (encrypted locally)')
  showStatus('Export saved (encrypted locally)', 'success')
  writeBackup('Last full export: just now')
    // clear passphrase field and reset view to main
  exportPassEl.value = ''
  strengthFill.style.width = '0%'
  exportDoBtn.disabled = true
  setTimeout(()=>{ showMainView() }, 150)
  } catch (e) { const msg = friendlyError(e && e.message || e); writeLog('exportAll: exception: ' + msg); showStatus(msg, 'error'); }
  })

  // Restore encrypted backup -> open import page with mode=all
  importAllBtn.addEventListener('click', async () => {
    try {
      const url = browser.runtime.getURL('import.html') + '?mode=all';
      await browser.tabs.create({ url });
      writeLog('importAll: opened import page')
    } catch (e) { writeLog('importAll: failed to open import page: ' + (e && e.message || e)) }
  })

  // importBackup and inline file picker removed from UI. Use Restore encrypted backup to open import page.

  updateStatus()
})
