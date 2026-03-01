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

// Lightweight metrics collector to profile FeIDo flows while keeping data local to the current session.
const __feidoGlobalScope = (typeof globalThis !== 'undefined') ? globalThis : (typeof self !== 'undefined' ? self : this);

function createFeidoMetrics() {
  const nowFn = (typeof performance !== 'undefined' && performance && typeof performance.now === 'function') ? () => performance.now() : () => Date.now();
  const MAX_HISTORY = 1000;
  let counter = 0;
  const history = [];

  function pushHistory(entry) {
    history.push(entry);
    if (history.length > MAX_HISTORY) history.shift();
    try {
      console.log(`[feido-metrics] ${entry.label}: ${entry.durationMs.toFixed(3)} ms`, entry);
    } catch (_) {
      /* ignore logging issues */
    }
  }

  function normalizeTimestamp(ts, fallback) {
    if (typeof ts === 'number' && Number.isFinite(ts)) return ts;
    return fallback;
  }

  function start(label, meta) {
    counter += 1;
    return {
      id: counter,
      label,
      meta: meta ? Object.assign({}, meta) : {},
      startedAt: Date.now(),
      _startHighRes: nowFn()
    };
  }

  function end(token, extra) {
    if (!token) return null;
    const endHighRes = nowFn();
    const startHighRes = typeof token._startHighRes === 'number' ? token._startHighRes : endHighRes;
    const durationMsRaw = Math.max(0, endHighRes - startHighRes);
    const entry = {
      id: token.id,
      label: token.label,
      durationMs: Number(durationMsRaw.toFixed(3)),
      startedAt: normalizeTimestamp(token.startedAt, Date.now()),
      endedAt: Date.now(),
      outcome: (extra && extra.outcome) ? String(extra.outcome) : 'ok',
      meta: Object.assign({}, token.meta, extra && extra.meta ? extra.meta : {}),
      error: extra && extra.error ? String(extra.error) : null
    };
    pushHistory(entry);
    return entry;
  }

  async function measureAsync(label, fn, meta) {
    const token = start(label, meta);
    try {
      const res = await fn();
      end(token, { outcome: 'ok' });
      return res;
    } catch (err) {
      const code = err && (err.code || err.name);
      const message = err && (err.message || String(err));
      end(token, { outcome: 'error', error: code ? `${code}: ${message}` : message });
      throw err;
    }
  }

  function measureSync(label, fn, meta) {
    const token = start(label, meta);
    try {
      const res = fn();
      end(token, { outcome: 'ok' });
      return res;
    } catch (err) {
      const code = err && (err.code || err.name);
      const message = err && (err.message || String(err));
      end(token, { outcome: 'error', error: code ? `${code}: ${message}` : message });
      throw err;
    }
  }

  function record(entry) {
    if (!entry || typeof entry.label !== 'string') return null;
    counter += 1;
    const startedAt = normalizeTimestamp(entry.startedAt, Date.now());
    let endedAt = normalizeTimestamp(entry.endedAt, startedAt);
    let duration = typeof entry.durationMs === 'number' && Number.isFinite(entry.durationMs) ? entry.durationMs : (endedAt - startedAt);
    if (!Number.isFinite(duration) || duration < 0) duration = 0;
    if (endedAt < startedAt) endedAt = startedAt + duration;
    const result = {
      id: counter,
      label: entry.label,
      durationMs: Number(duration.toFixed(3)),
      startedAt,
      endedAt,
      outcome: entry.outcome ? String(entry.outcome) : 'ok',
      meta: entry.meta ? Object.assign({}, entry.meta) : {},
      error: entry.error ? String(entry.error) : null
    };
    pushHistory(result);
    return result;
  }

  function getHistory() {
    return history.slice();
  }

  function clear() {
    history.length = 0;
  }

  async function exportToFile(filename) {
    try {
      console.log('[feido-metrics] exporting metrics history', history.length);
      const data = JSON.stringify(history, null, 2);
      const blob = new Blob([data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const downloadId = await browser.downloads.download({
        url,
        filename: filename || `feido-metrics-${Date.now()}.json`,
        saveAs: false
      });
      console.log('[feido-metrics] download started', downloadId);
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch (err) {
      console.warn('[feido-metrics] export failed', err && err.message);
    }
  }

  return { start, end, measureAsync, measureSync, record, getHistory, clear, exportToFile };
}

if (!__feidoGlobalScope.FeidoMetrics) {
  __feidoGlobalScope.FeidoMetrics = createFeidoMetrics();
}
const FeidoMetrics = __feidoGlobalScope.FeidoMetrics;

if (browser.downloads && browser.downloads.onChanged) {
  browser.downloads.onChanged.addListener((delta) => {
    if (delta.state && delta.state.current === 'complete') {
      console.log('[feido-metrics] download completed', delta.id);
    } else if (delta.state && delta.state.current === 'interrupted') {
      console.warn('[feido-metrics] download interrupted', delta.id, delta.error && delta.error.current);
    }
  });
}

const __feidoUserFlows = new Map();
const __feidoUserFlowRecovery = new Map();

function recordUserFlowEvent(payload) {
  if (!payload || !payload.event) return;
  try {
    const now = typeof payload.timestamp === 'number' && Number.isFinite(payload.timestamp) ? payload.timestamp : Date.now();
    const reqId = payload.reqId || `feido-userflow-${now}`;
    const eventName = String(payload.event);
    const isDeviceSecretEvent = eventName === 'deviceSecret.unlocked' || eventName === 'deviceSecret.set' || eventName === 'deviceSecret.imported';

    if (eventName === 'reset') {
      __feidoUserFlows.delete(reqId);
      return;
    }

    let session = __feidoUserFlows.get(reqId);
    const shouldMaterializeSession = !session && !isDeviceSecretEvent;
    if (shouldMaterializeSession) {
      session = createFlowSession(reqId, payload.flow || null, now, payload.meta);
      __feidoUserFlows.set(reqId, session);
    } else if (session && payload.meta) {
      session.baseMeta = Object.assign({}, session.baseMeta, payload.meta);
    }

    const metaForKey = session ? collectSessionMeta(session) : looseMetaSnapshot(payload.flow || null, payload.meta, reqId);
    const flowName = metaForKey.flow || payload.flow || null;

    if (eventName === 'extension.intercepted') {
      processRecoveryPendings(flowName, metaForKey, reqId, now, 'extension.intercepted');
    }
    if (isDeviceSecretEvent) {
      processRecoveryPendings(flowName, metaForKey, reqId, now, eventName);
    }

    if (session) {
      if (payload.meta) session.baseMeta = Object.assign({}, session.baseMeta, payload.meta);
      session.events.push({ name: eventName, ts: now });
      if (typeof session.startedAt !== 'number' || now < session.startedAt) session.startedAt = now;
      session.lastEventAt = now;
    }

    if (session && (eventName === 'complete' || eventName === 'abort')) {
      const errorMsg = payload && payload.error ? String(payload.error) : null;
      emitFlowMetrics(session, eventName === 'complete' ? 'ok' : 'error', now, errorMsg);
      if (eventName === 'abort') {
        queueRecoveryPending(flowName, collectSessionMeta(session), reqId, now, errorMsg);
      } else {
        clearRecoveryPendings(flowName, collectSessionMeta(session));
      }
      __feidoUserFlows.delete(reqId);
    }
  } catch (err) {
    console.warn('[feido-metrics] recordUserFlowEvent failed', err && err.message);
  }
}

function createFlowSession(reqId, flowName, ts, meta) {
  return {
    reqId,
    flowName: flowName || null,
    baseMeta: meta ? Object.assign({}, meta) : {},
    events: [],
    startedAt: ts,
    lastEventAt: ts
  };
}

function collectSessionMeta(session) {
  const meta = Object.assign({}, session.baseMeta || {});
  if (session.flowName && !meta.flow) meta.flow = session.flowName;
  meta.reqId = session.reqId;
  return meta;
}

function looseMetaSnapshot(flowName, meta, reqId) {
  const result = meta ? Object.assign({}, meta) : {};
  if (flowName && !result.flow) result.flow = flowName;
  if (reqId && typeof result.reqId === 'undefined') result.reqId = reqId;
  return result;
}

function emitFlowMetrics(session, outcome, now, errorMsg) {
  if (!FeidoMetrics || typeof FeidoMetrics.record !== 'function') return;
  const events = session.events.slice().sort((a, b) => a.ts - b.ts);
  const meta = collectSessionMeta(session);
  const firstTs = typeof session.startedAt === 'number' ? session.startedAt : (events[0] ? events[0].ts : now);
  const lastTs = events.length ? events[events.length - 1].ts : now;
  const totalDuration = Math.max(0, lastTs - firstTs);

  FeidoMetrics.record({
    label: 'user.e2e.total',
    durationMs: totalDuration,
    startedAt: firstTs,
    endedAt: lastTs,
    outcome,
    meta,
    error: outcome === 'ok' ? null : errorMsg
  });

  let prevTs = firstTs;
  for (let i = 0; i < events.length; i += 1) {
    const evt = events[i];
    if (i === 0) {
      prevTs = evt.ts;
      continue;
    }
    const duration = Math.max(0, evt.ts - prevTs);
    FeidoMetrics.record({
      label: `user.e2e.step.${evt.name}`,
      durationMs: duration,
      startedAt: prevTs,
      endedAt: evt.ts,
      outcome: 'ok',
      meta: Object.assign({}, meta, { step: evt.name })
    });
    prevTs = evt.ts;
  }
}

function queueRecoveryPending(flowName, meta, abortReqId, endedAt, errorMsg) {
  const key = buildUserFlowRecoveryKey(flowName, meta);
  if (!key) return;
  const entryMeta = Object.assign({}, meta || {});
  entryMeta.abortReqId = abortReqId;
  if (errorMsg) entryMeta.error = errorMsg;
  const pending = { endedAt, meta: entryMeta };
  const list = __feidoUserFlowRecovery.get(key) || [];
  list.push(pending);
  __feidoUserFlowRecovery.set(key, list);
}

function clearRecoveryPendings(flowName, meta) {
  const key = buildUserFlowRecoveryKey(flowName, meta);
  if (key) __feidoUserFlowRecovery.delete(key);
}

function processRecoveryPendings(flowName, meta, resumedReqId, now, trigger) {
  if (!FeidoMetrics || typeof FeidoMetrics.record !== 'function') return;
  const desiredParts = extractKeyParts(flowName, meta);
  let key = buildUserFlowRecoveryKey(flowName, meta);
  let pendings = key ? __feidoUserFlowRecovery.get(key) : undefined;

  if (!pendings || !pendings.length) {
    for (const [candidateKey, candidateList] of __feidoUserFlowRecovery.entries()) {
      if (!Array.isArray(candidateList) || !candidateList.length) continue;
      const sampleParts = extractKeyParts(candidateList[candidateList.length - 1].meta && candidateList[candidateList.length - 1].meta.flow, candidateList[candidateList.length - 1].meta);
      if (sampleParts.flow === desiredParts.flow && sampleParts.rpId === desiredParts.rpId && sampleParts.origin === desiredParts.origin) {
        key = candidateKey;
        pendings = candidateList;
        break;
      }
    }
  }

  if ((!pendings || !pendings.length) && __feidoUserFlowRecovery.size === 1) {
    for (const [candidateKey, candidateList] of __feidoUserFlowRecovery.entries()) {
      if (!Array.isArray(candidateList) || !candidateList.length) continue;
      key = candidateKey;
      pendings = candidateList;
      break;
    }
  }

  if (!pendings || !pendings.length) return;
  pendings.sort((a, b) => (a.endedAt || 0) - (b.endedAt || 0));

  for (let i = 0; i < pendings.length; i += 1) {
    const pending = pendings[i];
    const startedAt = typeof pending.endedAt === 'number' ? pending.endedAt : now;
    const duration = Math.max(0, now - startedAt);
    const metaSnapshot = Object.assign({}, pending.meta || {});
    metaSnapshot.reqId = resumedReqId;
    if (flowName && !metaSnapshot.flow) metaSnapshot.flow = flowName;
    metaSnapshot.recoveryTrigger = trigger;
    metaSnapshot.recoverySequence = i + 1;

    FeidoMetrics.record({
      label: 'user.e2e.step.recovery',
      durationMs: duration,
      startedAt,
      endedAt: now,
      outcome: 'ok',
      meta: metaSnapshot
    });
  }

  if (key) __feidoUserFlowRecovery.delete(key);
}

function buildUserFlowRecoveryKey(flowName, meta) {
  const parts = extractKeyParts(flowName, meta);
  return `${parts.flow}::${parts.rpId}::${parts.origin}`;
}

function extractKeyParts(flowName, meta) {
  const flow = flowName || (meta && meta.flow) || '';
  const rpId = meta && typeof meta.rpId === 'string' ? meta.rpId : '';
  const origin = meta && typeof meta.origin === 'string' ? meta.origin : '';
  return { flow, rpId, origin };
}

function hasPendingRecoveries(flowName, meta) {
  if (!__feidoUserFlowRecovery.size) return false;
  const target = extractKeyParts(flowName, meta);
  for (const list of __feidoUserFlowRecovery.values()) {
    if (!Array.isArray(list) || !list.length) continue;
    const sample = list[list.length - 1];
    const sampleMeta = sample && sample.meta ? sample.meta : {};
    const sampleParts = extractKeyParts(sampleMeta.flow, sampleMeta);
    if (sampleParts.flow === target.flow && sampleParts.rpId === target.rpId && sampleParts.origin === target.origin) {
      return true;
    }
  }
  return false;
}

if (FeidoMetrics && typeof FeidoMetrics.prepareForAttempt !== 'function') {
  FeidoMetrics.prepareForAttempt = function prepareForAttempt(flowName, meta) {
    try {
      if (!hasPendingRecoveries(flowName, meta)) {
        FeidoMetrics.clear();
      }
    } catch (err) {
      console.warn('[feido-metrics] prepareForAttempt failed', err && err.message);
      FeidoMetrics.clear();
    }
  };
}

function metricsExtractRpId(msg) {
  try {
    const pubKey = msg && msg.opts && msg.opts.publicKey;
    if (pubKey) {
      if (typeof pubKey.rpId === 'string' && pubKey.rpId) return pubKey.rpId;
      if (pubKey.rp && typeof pubKey.rp.id === 'string' && pubKey.rp.id) return pubKey.rp.id;
    }
  } catch (_) {
    /* ignore */
  }
  try {
    if (msg && typeof msg.origin === 'string' && msg.origin) return new URL(msg.origin).hostname;
  } catch (_) {
    /* ignore */
  }
  return '';
}

function metricsMetaForRequest(msg, flow) {
  const meta = { flow };
  if (msg && typeof msg.reqId !== 'undefined' && msg.reqId !== null) meta.reqId = msg.reqId;
  if (msg && typeof msg.origin === 'string') meta.origin = msg.origin;
  meta.rpId = metricsExtractRpId(msg);
  try {
    const pubKey = msg && msg.opts && msg.opts.publicKey;
    if (pubKey) {
      if (Array.isArray(pubKey.allowCredentials)) meta.allowCredentials = pubKey.allowCredentials.length;
      if (pubKey.user && pubKey.user.id) meta.hasUserId = true;
    }
  } catch (_) {
    /* ignore */
  }
  return meta;
}
