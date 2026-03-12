'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');

const bind = process.env.ANCHOR_BIND || '0.0.0.0';
const parsedPort = Number(process.env.ANCHOR_PORT || 8787);
const port = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort < 65536 ? parsedPort : 8787;
const anchorName = process.env.ANCHOR_NAME || 'DefendMesh Anchor';
const publicUrl = process.env.ANCHOR_PUBLIC_URL || 'https://defend.ordl.org';
const publicUrlBase = publicUrl.replace(/\/+$/, '');
const nodeTokensFile = process.env.ANCHOR_NODE_TOKENS_FILE || './node-tokens.json';
const githubRepo = (process.env.ANCHOR_GITHUB_REPO || 'https://github.com/Open-Research-Development-Laboratories/ordl-infra.git').trim();
const githubRef = (process.env.ANCHOR_GITHUB_REF || 'main').trim();

const nodeBearerToken = process.env.ANCHOR_NODE_TOKEN || '';
const cfServiceId = process.env.ANCHOR_CF_SERVICE_TOKEN_ID || '';
const cfServiceSecret = process.env.ANCHOR_CF_SERVICE_TOKEN_SECRET || '';

const adminDevToken = process.env.ANCHOR_ADMIN_DEV_TOKEN || '';
const openEnroll = String(process.env.ANCHOR_OPEN_ENROLL || 'false').trim().toLowerCase() !== 'false';
const adminEmailTokenTtlSec = Math.max(60, Number(process.env.ANCHOR_ADMIN_EMAIL_TOKEN_TTL_SEC || 600) || 600);
const adminSessionIdleSec = Math.max(60, Number(process.env.ANCHOR_ADMIN_SESSION_IDLE_SEC || 1800) || 1800);
const adminSessionMaxSec = Math.max(adminSessionIdleSec, Number(process.env.ANCHOR_ADMIN_SESSION_MAX_SEC || 28800) || 28800);
const adminTokenDispatchWebhook = String(process.env.ANCHOR_ADMIN_TOKEN_DISPATCH_WEBHOOK || '').trim();
const adminTokenFallbackEnabled = String(process.env.ANCHOR_ADMIN_TOKEN_FALLBACK || 'false').trim().toLowerCase() === 'true';
const smtpHost = String(process.env.ANCHOR_SMTP_HOST || '').trim();
const smtpPort = Math.max(1, Math.min(65535, Number(process.env.ANCHOR_SMTP_PORT || 587) || 587));
const smtpSecure = String(process.env.ANCHOR_SMTP_SECURE || 'false').trim().toLowerCase() === 'true';
const smtpUser = String(process.env.ANCHOR_SMTP_USER || '').trim();
const smtpPass = String(process.env.ANCHOR_SMTP_PASS || '');
const smtpFrom = String(process.env.ANCHOR_SMTP_FROM || '').trim();
const smtpReplyTo = String(process.env.ANCHOR_SMTP_REPLY_TO || '').trim();
const smtpHeloName = String(process.env.ANCHOR_SMTP_HELO || 'defend.ordl.org').trim();
const smtpTlsRejectUnauthorized = String(process.env.ANCHOR_SMTP_TLS_REJECT_UNAUTHORIZED || 'true').trim().toLowerCase() !== 'false';
const threatAlertEmails = (process.env.ANCHOR_THREAT_ALERT_EMAILS || '')
  .split(',')
  .map((v) => v.trim())
  .filter(Boolean);
const threatAlertMinSeverity = String(process.env.ANCHOR_THREAT_ALERT_MIN_SEVERITY || 'high').trim().toLowerCase();
const threatAlertCooldownSec = Math.max(30, Number(process.env.ANCHOR_THREAT_ALERT_COOLDOWN_SEC || 300) || 300);
const autoPlaybooksEnabled = String(process.env.ANCHOR_AUTO_PLAYBOOKS || 'true').trim().toLowerCase() !== 'false';
const autoAuditIntervalSec = Math.max(15, Number(process.env.ANCHOR_AUTO_AUDIT_SEC || 300) || 300);
const autoMonitorIntervalSec = Math.max(10, Number(process.env.ANCHOR_AUTO_MONITOR_SEC || 120) || 120);
const autoRemediateMinSeverity = String(process.env.ANCHOR_AUTO_REMEDIATE_MIN_SEVERITY || 'high').trim().toLowerCase();
const autoRemediateCooldownSec = Math.max(30, Number(process.env.ANCHOR_AUTO_REMEDIATE_COOLDOWN_SEC || 600) || 600);
const aiTriageEnabled = String(process.env.ANCHOR_AI_TRIAGE_ENABLED || 'true').trim().toLowerCase() !== 'false';
const aiTriageBaseUrl = String(process.env.ANCHOR_AI_BASE_URL || process.env.OPENAI_BASE_URL || 'https://api.openai.com/v1').trim();
const aiTriageApiKey = String(process.env.ANCHOR_AI_API_KEY || process.env.OPENAI_API_KEY || '').trim();
const aiTriageModel = String(process.env.ANCHOR_AI_MODEL || '').trim();
const aiTriageTimeoutMs = Math.max(1000, Number(process.env.ANCHOR_AI_TIMEOUT_MS || 8000) || 8000);
const aiTriageMaxContextChars = Math.max(1500, Number(process.env.ANCHOR_AI_MAX_CONTEXT_CHARS || 12000) || 12000);
const aiTriageMinSeverity = String(process.env.ANCHOR_AI_MIN_SEVERITY || 'info').trim().toLowerCase();
const aiTriageFullContext = String(process.env.ANCHOR_AI_FULL_CONTEXT || 'false').trim().toLowerCase() === 'true';
const missionStatement = String(
  process.env.ANCHOR_MISSION_STATEMENT ||
  'Mission: Strengthen lawful defensive cyber readiness to protect U.S. citizens, support the military and lawful civilian chain of command (including the Commander in Chief), and reduce harm to civilians at home and abroad during cyber crises.'
).trim();
const allowedEmails = (process.env.ANCHOR_ALLOWED_EMAILS || '')
  .split(',')
  .map((v) => v.trim().toLowerCase())
  .filter(Boolean);
const allowedSuffixes = (process.env.ANCHOR_ALLOWED_EMAIL_SUFFIXES || '.gov')
  .split(',')
  .map((v) => v.trim().toLowerCase())
  .filter(Boolean);

const nodes = new Map();
const logsByNode = new Map();
const queuesByNode = new Map();
const resultsByNode = new Map();
const patches = new Map();
const profilesByNode = new Map();
const triageByNode = new Map();
const nodeTokensByNode = new Map();
const nodeIdsByToken = new Map();
const taskMetaById = new Map();
const adminChallengesByEmail = new Map();
const adminSessionsByToken = new Map();
const threatAlertLastSentByKey = new Map();
const autoDispatchStateByNode = new Map();

const PLAYBOOKS = new Set([
  'endpoint_audit',
  'endpoint_remediate',
  'monitor_start',
  'monitor_stop',
  'monitor_oneshot',
  'stage_patch'
]);

function saveNodeTokens() {
  if (!nodeTokensFile) return;
  const dir = nodeTokensFile.includes('/') ? nodeTokensFile.slice(0, nodeTokensFile.lastIndexOf('/')) : '.';
  if (dir) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const arr = Array.from(nodeTokensByNode.values()).map((v) => ({
    node_id: v.node_id,
    token: v.token,
    created_at: v.created_at,
    created_by: v.created_by,
    note: v.note || ''
  }));
  const tmpFile = `${nodeTokensFile}.tmp`;
  fs.writeFileSync(tmpFile, `${JSON.stringify(arr, null, 2)}\n`, 'utf8');
  fs.renameSync(tmpFile, nodeTokensFile);
}

function setNodeToken(nodeId, token, createdBy, note = '') {
  if (!nodeId || !token) return;
  const existing = nodeTokensByNode.get(nodeId);
  if (existing && existing.token) {
    nodeIdsByToken.delete(existing.token);
  }
  const record = {
    node_id: nodeId,
    token,
    created_at: new Date().toISOString(),
    created_by: createdBy || 'unknown',
    note: note || ''
  };
  nodeTokensByNode.set(nodeId, record);
  nodeIdsByToken.set(token, nodeId);
  saveNodeTokens();
}

function loadNodeTokens() {
  if (!nodeTokensFile) return;
  try {
    if (!fs.existsSync(nodeTokensFile)) return;
    const raw = fs.readFileSync(nodeTokensFile, 'utf8');
    if (!raw.trim()) return;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return;
    for (const item of parsed) {
      const nodeId = String(item && item.node_id || '').trim();
      const token = String(item && item.token || '').trim();
      if (!nodeId || !token) continue;
      const record = {
        node_id: nodeId,
        token,
        created_at: String(item.created_at || new Date().toISOString()),
        created_by: String(item.created_by || 'unknown'),
        note: String(item.note || '')
      };
      nodeTokensByNode.set(nodeId, record);
      nodeIdsByToken.set(token, nodeId);
    }
  } catch (_) {
    // Ignore malformed token file and continue with empty registry.
  }
}

function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store'
  });
  res.end(payload);
}

function sendHtml(res, statusCode, html) {
  res.writeHead(statusCode, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'Cache-Control': 'no-store'
  });
  res.end(html);
}

function sendText(res, statusCode, text, filename) {
  const headers = {
    'Content-Type': 'application/octet-stream',
    'Content-Length': Buffer.byteLength(text),
    'Cache-Control': 'no-store'
  };
  if (filename) {
    headers['Content-Disposition'] = `attachment; filename="${filename}"`;
  }
  res.writeHead(statusCode, headers);
  res.end(text);
}

function sendRedirect(res, location, cookieHeader) {
  const headers = { Location: location, 'Cache-Control': 'no-store' };
  if (cookieHeader) headers['Set-Cookie'] = cookieHeader;
  res.writeHead(302, headers);
  res.end();
}

function badRequest(res, message) {
  sendJson(res, 400, { error: message });
}

function unauthorized(res) {
  sendJson(res, 401, { error: 'unauthorized' });
}

function forbidden(res) {
  sendJson(res, 403, { error: 'forbidden' });
}

function notFound(res) {
  sendJson(res, 404, { error: 'not_found' });
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';

    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 5 * 1024 * 1024) {
        reject(new Error('payload too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      if (!raw) {
        reject(new Error('empty body'));
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (_) {
        reject(new Error('invalid json'));
      }
    });

    req.on('error', reject);
  });
}

function parseFormBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';

    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 64 * 1024) {
        reject(new Error('payload too large'));
        req.destroy();
      }
    });

    req.on('end', () => {
      const params = new URLSearchParams(raw || '');
      const out = {};
      for (const [k, v] of params.entries()) {
        out[k] = v;
      }
      resolve(out);
    });

    req.on('error', reject);
  });
}

function parseCookies(req) {
  const out = {};
  const raw = String(req.headers.cookie || '');
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const kv = part.trim();
    if (!kv) continue;
    const idx = kv.indexOf('=');
    if (idx < 1) continue;
    const key = kv.slice(0, idx).trim();
    const value = kv.slice(idx + 1).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(value);
  }
  return out;
}

function normalizeTrend(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'up') return 'up';
  if (v === 'down') return 'down';
  if (v === 'flat' || v === 'steady') return 'steady';
  return 'unknown';
}

function normalizeBool(value) {
  if (typeof value === 'boolean') return value;
  const v = String(value || '').trim().toLowerCase();
  return v === 'true' || v === 'yes' || v === '1';
}

function severityRank(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'critical') return 4;
  if (v === 'high') return 3;
  if (v === 'medium') return 2;
  if (v === 'low') return 1;
  return 0;
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function escHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatEstMinus5(value) {
  const ms = typeof value === 'number' ? value : Date.parse(String(value || ''));
  if (!Number.isFinite(ms)) return String(value || '-');
  const shifted = new Date(ms - 5 * 60 * 60 * 1000).toISOString();
  return `${shifted.slice(0, 19).replace('T', ' ')} EST-05:00`;
}

function getQueue(nodeId) {
  if (!queuesByNode.has(nodeId)) {
    queuesByNode.set(nodeId, []);
  }
  return queuesByNode.get(nodeId);
}

function pushBounded(map, key, value, maxLen) {
  if (!map.has(key)) {
    map.set(key, []);
  }
  const arr = map.get(key);
  arr.push(value);
  while (arr.length > maxLen) arr.shift();
}

function latestFromBoundedMap(map, key) {
  const arr = map.get(key);
  if (!Array.isArray(arr) || arr.length < 1) return null;
  return arr[arr.length - 1];
}

function normalizeSeverity(value, fallback = 'info') {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low' || v === 'info') return v;
  return fallback;
}

function queueHasPlaybook(queue, playbook) {
  return Array.isArray(queue) && queue.some((item) => String(item && item.playbook || '').trim() === playbook);
}

function enqueueTask(nodeId, playbook, args, createdBy, dispatchId, createdAt) {
  const task = {
    task_id: makeTaskId(),
    dispatch_id: dispatchId || `dispatch_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
    node_id: nodeId,
    playbook,
    args: args && typeof args === 'object' ? args : {},
    created_at: createdAt || new Date().toISOString(),
    created_by: createdBy || 'system'
  };
  const queue = getQueue(nodeId);
  queue.push(task);
  taskMetaById.set(task.task_id, {
    task_id: task.task_id,
    node_id: nodeId,
    playbook,
    dispatch_id: task.dispatch_id,
    created_at: task.created_at,
    created_by: task.created_by
  });
  if (taskMetaById.size > 50000) {
    const oldestKey = taskMetaById.keys().next();
    if (oldestKey && !oldestKey.done) taskMetaById.delete(oldestKey.value);
  }
  return task;
}

function maybeEnqueueAutoPlaybooks(nodeId, severityRaw) {
  if (!autoPlaybooksEnabled || !nodeId) return [];

  const nowMs = Date.now();
  const nowIso = new Date(nowMs).toISOString();
  const state = autoDispatchStateByNode.get(nodeId) || {
    last_audit_ms: 0,
    last_monitor_ms: 0,
    last_remediate_ms: 0
  };
  const queue = getQueue(nodeId);
  const out = [];

  if (nowMs - state.last_audit_ms >= autoAuditIntervalSec * 1000 && !queueHasPlaybook(queue, 'endpoint_audit')) {
    const task = enqueueTask(nodeId, 'endpoint_audit', { mode: 'auto', reason: 'continuous_audit' }, 'system:auto', `auto_${nowMs}_audit`, nowIso);
    out.push(task);
    state.last_audit_ms = nowMs;
  }

  if (nowMs - state.last_monitor_ms >= autoMonitorIntervalSec * 1000 && !queueHasPlaybook(queue, 'monitor_oneshot')) {
    const task = enqueueTask(
      nodeId,
      'monitor_oneshot',
      { mode: 'auto', interval_sec: 2, loop_count: 5 },
      'system:auto',
      `auto_${nowMs}_monitor`,
      nowIso
    );
    out.push(task);
    state.last_monitor_ms = nowMs;
  }

  if (
    severityRank(severityRaw) >= severityRank(autoRemediateMinSeverity) &&
    nowMs - state.last_remediate_ms >= autoRemediateCooldownSec * 1000 &&
    !queueHasPlaybook(queue, 'endpoint_remediate')
  ) {
    const task = enqueueTask(
      nodeId,
      'endpoint_remediate',
      { mode: 'auto', reason: `severity_${normalizeSeverity(severityRaw, 'high')}` },
      'system:auto',
      `auto_${nowMs}_remediate`,
      nowIso
    );
    out.push(task);
    state.last_remediate_ms = nowMs;
  }

  autoDispatchStateByNode.set(nodeId, state);
  return out;
}

function nodeAuthOk(req) {
  const auth = req.headers.authorization || '';
  const bearerToken = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length).trim() : '';
  const staticBearerOk = nodeBearerToken ? bearerToken === nodeBearerToken : false;
  const dynamicBearerOk = bearerToken ? nodeIdsByToken.has(bearerToken) : false;
  const bearerOk = staticBearerOk || dynamicBearerOk;

  const serviceConfigured = !!(cfServiceId && cfServiceSecret);
  const serviceOk = serviceConfigured
    ? req.headers['cf-access-client-id'] === cfServiceId && req.headers['cf-access-client-secret'] === cfServiceSecret
    : false;

  if (nodeBearerToken || serviceConfigured || nodeIdsByToken.size > 0) {
    return bearerOk || serviceOk;
  }
  return true;
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function adminEmailAllowed(emailRaw) {
  const email = normalizeEmail(emailRaw);
  if (!email) return false;
  if (allowedEmails.includes(email)) return true;
  return allowedSuffixes.some((s) => email.endsWith(s));
}

function gcAdminAuthState(nowMs) {
  for (const [email, challenge] of adminChallengesByEmail.entries()) {
    if (!challenge || challenge.expires_ms <= nowMs) {
      adminChallengesByEmail.delete(email);
    }
  }
  for (const [token, session] of adminSessionsByToken.entries()) {
    if (!session) {
      adminSessionsByToken.delete(token);
      continue;
    }
    const idleExpired = nowMs - session.last_active_ms > adminSessionIdleSec * 1000;
    const hardExpired = nowMs > session.max_expires_ms;
    if (idleExpired || hardExpired) {
      adminSessionsByToken.delete(token);
    }
  }
}

function issueAdminChallenge(emailRaw) {
  const email = normalizeEmail(emailRaw);
  const nowMs = Date.now();
  gcAdminAuthState(nowMs);
  const token = crypto.randomBytes(4).toString('hex').toUpperCase();
  const expiresMs = nowMs + adminEmailTokenTtlSec * 1000;
  adminChallengesByEmail.set(email, {
    email,
    token,
    created_ms: nowMs,
    expires_ms: expiresMs
  });
  return { email, token, expires_ms: expiresMs };
}

function verifyAdminChallenge(emailRaw, tokenRaw) {
  const email = normalizeEmail(emailRaw);
  const token = String(tokenRaw || '').trim().toUpperCase();
  if (!email || !token) return false;
  const nowMs = Date.now();
  gcAdminAuthState(nowMs);
  const challenge = adminChallengesByEmail.get(email);
  if (!challenge) return false;
  if (challenge.token !== token) return false;
  if (challenge.expires_ms <= nowMs) return false;
  adminChallengesByEmail.delete(email);
  return true;
}

function createAdminSession(emailRaw) {
  const email = normalizeEmail(emailRaw);
  const nowMs = Date.now();
  gcAdminAuthState(nowMs);
  const token = crypto.randomBytes(24).toString('hex');
  const session = {
    email,
    created_ms: nowMs,
    last_active_ms: nowMs,
    max_expires_ms: nowMs + adminSessionMaxSec * 1000
  };
  adminSessionsByToken.set(token, session);
  return { token, session };
}

function smtpConfigured() {
  return !!(smtpHost && smtpFrom);
}

function createSmtpLineReader(socket) {
  let buffer = '';
  let endedError = null;
  const queue = [];
  let waiter = null;

  function pushLine(line) {
    if (waiter) {
      const w = waiter;
      waiter = null;
      w.resolve(line);
      return;
    }
    queue.push(line);
  }

  socket.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    for (;;) {
      const idx = buffer.indexOf('\n');
      if (idx < 0) break;
      const line = buffer.slice(0, idx).replace(/\r$/, '');
      buffer = buffer.slice(idx + 1);
      if (line) pushLine(line);
    }
  });
  socket.on('end', () => {
    endedError = new Error('smtp connection closed');
    if (waiter) {
      const w = waiter;
      waiter = null;
      w.reject(endedError);
    }
  });
  socket.on('error', (err) => {
    endedError = err;
    if (waiter) {
      const w = waiter;
      waiter = null;
      w.reject(err);
    }
  });

  async function nextLine(timeoutMs = 15000) {
    if (queue.length > 0) return queue.shift();
    if (endedError) throw endedError;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        if (waiter) waiter = null;
        reject(new Error('smtp timeout waiting for response'));
      }, timeoutMs);
      waiter = {
        resolve: (line) => {
          clearTimeout(timeout);
          resolve(line);
        },
        reject: (err) => {
          clearTimeout(timeout);
          reject(err);
        }
      };
    });
  }

  async function readResponse() {
    const lines = [];
    for (;;) {
      const line = await nextLine();
      lines.push(line);
      if (/^\d{3}\s/.test(line)) break;
      if (!/^\d{3}-/.test(line)) break;
    }
    const last = lines[lines.length - 1] || '';
    const codeMatch = last.match(/^(\d{3})[ -]/);
    const code = codeMatch ? Number(codeMatch[1]) : 0;
    return { code, lines };
  }

  return { readResponse };
}

function smtpOpenSocket(secure, existingSocket) {
  return new Promise((resolve, reject) => {
    const options = secure
      ? {
          host: smtpHost,
          port: smtpPort,
          servername: smtpHost,
          rejectUnauthorized: smtpTlsRejectUnauthorized
        }
      : { host: smtpHost, port: smtpPort };

    const socket = existingSocket
      ? tls.connect({
          socket: existingSocket,
          servername: smtpHost,
          rejectUnauthorized: smtpTlsRejectUnauthorized
        })
      : (secure ? tls.connect(options) : net.connect(options));

    const onError = (err) => reject(err);
    socket.once('error', onError);
    socket.setTimeout(20000, () => socket.destroy(new Error('smtp socket timeout')));
    socket.once(secure || existingSocket ? 'secureConnect' : 'connect', () => {
      socket.off('error', onError);
      resolve(socket);
    });
  });
}

async function smtpSendCmd(socket, reader, command, expectedCodes) {
  socket.write(`${command}\r\n`);
  const resp = await reader.readResponse();
  if (!expectedCodes.includes(resp.code)) {
    throw new Error(`smtp command failed: ${command} -> ${resp.code} ${resp.lines.join(' | ')}`);
  }
  return resp;
}

async function smtpSendTextEmail(email, subject, bodyText) {
  let socket = null;
  try {
    socket = await smtpOpenSocket(smtpSecure, null);
    let reader = createSmtpLineReader(socket);

    const greeting = await reader.readResponse();
    if (greeting.code !== 220) {
      throw new Error(`smtp greeting failed: ${greeting.code} ${greeting.lines.join(' | ')}`);
    }

    let ehloResp = await smtpSendCmd(socket, reader, `EHLO ${smtpHeloName || 'localhost'}`, [250]);
    const supportsStartTls = ehloResp.lines.some((line) => /STARTTLS/i.test(line));

    if (!smtpSecure && supportsStartTls) {
      await smtpSendCmd(socket, reader, 'STARTTLS', [220]);
      socket = await smtpOpenSocket(true, socket);
      reader = createSmtpLineReader(socket);
      ehloResp = await smtpSendCmd(socket, reader, `EHLO ${smtpHeloName || 'localhost'}`, [250]);
      void ehloResp;
    }

    if (smtpUser || smtpPass) {
      await smtpSendCmd(socket, reader, 'AUTH LOGIN', [334]);
      await smtpSendCmd(socket, reader, Buffer.from(smtpUser, 'utf8').toString('base64'), [334]);
      await smtpSendCmd(socket, reader, Buffer.from(smtpPass, 'utf8').toString('base64'), [235]);
    }

    await smtpSendCmd(socket, reader, `MAIL FROM:<${smtpFrom}>`, [250]);
    await smtpSendCmd(socket, reader, `RCPT TO:<${email}>`, [250, 251]);
    await smtpSendCmd(socket, reader, 'DATA', [354]);
    const safeSubject = String(subject || '')
      .replace(/\r|\n/g, ' ')
      .slice(0, 220);

    const safeBody = bodyText
      .replace(/\r?\n/g, '\r\n')
      .split('\r\n')
      .map((line) => (line.startsWith('.') ? `.${line}` : line))
      .join('\r\n');

    const headers = [
      `From: ${smtpFrom}`,
      `To: ${email}`,
      `Subject: ${safeSubject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      smtpReplyTo ? `Reply-To: ${smtpReplyTo}` : ''
    ]
      .filter(Boolean)
      .join('\r\n');

    socket.write(`${headers}\r\n\r\n${safeBody}\r\n.\r\n`);
    const dataResp = await reader.readResponse();
    if (dataResp.code !== 250) {
      throw new Error(`smtp data failed: ${dataResp.code} ${dataResp.lines.join(' | ')}`);
    }

    try {
      await smtpSendCmd(socket, reader, 'QUIT', [221, 250]);
    } catch (_) {
      // Ignore quit failures; email was already accepted if DATA returned 250.
    }
    socket.end();
    return { ok: true, mode: 'smtp', to: email };
  } catch (err) {
    if (socket) {
      try {
        socket.destroy();
      } catch (_) {
        // Ignore socket teardown issues.
      }
    }
    return { ok: false, mode: 'smtp', to: email, error: String(err && err.message || err || 'smtp_failed') };
  }
}

async function smtpSendAdminTokenEmail(email, token, expiresAtIso) {
  const subject = `DefendMesh Admin Access Token (${anchorName})`;
  const bodyText =
    `Your DefendMesh admin access token is: ${token}\n` +
    `Expires at: ${expiresAtIso}\n` +
    `Anchor: ${publicUrlBase}\n\n` +
    `If you did not request this, ignore this message.`;
  return smtpSendTextEmail(email, subject, bodyText);
}

async function dispatchAdminToken(email, token, expiresAtIso) {
  if (smtpConfigured()) {
    const smtpResult = await smtpSendAdminTokenEmail(email, token, expiresAtIso);
    if (smtpResult.ok) return smtpResult;
    if (!adminTokenDispatchWebhook) return smtpResult;
  }

  if (adminTokenDispatchWebhook) {
    try {
      const resp = await fetch(adminTokenDispatchWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          token,
          expires_at: expiresAtIso,
          anchor: publicUrlBase,
          event: 'admin_access_token'
        })
      });
      return { ok: resp.ok, mode: 'webhook', status: resp.status };
    } catch (err) {
      return { ok: false, mode: 'webhook', error: String(err && err.message || err || 'webhook_failed') };
    }
  }

  return { ok: false, mode: 'none', error: 'email_dispatch_not_configured' };
}

function shouldSendThreatAlert(nodeId, severity) {
  if (!nodeId) return false;
  if (threatAlertEmails.length === 0) return false;
  if (!smtpConfigured()) return false;
  if (severityRank(severity) < severityRank(threatAlertMinSeverity)) return false;
  const key = `${nodeId}:${String(severity || '').toLowerCase()}`;
  const nowMs = Date.now();
  const lastMs = Number(threatAlertLastSentByKey.get(key) || 0);
  if (lastMs > 0 && nowMs - lastMs < threatAlertCooldownSec * 1000) {
    return false;
  }
  threatAlertLastSentByKey.set(key, nowMs);
  return true;
}

async function dispatchThreatAlertEmail(item) {
  if (!item || typeof item !== 'object') return { ok: false, reason: 'invalid_item' };
  if (!shouldSendThreatAlert(item.node_id, item.severity)) {
    return { ok: false, reason: 'not_eligible' };
  }

  const subject = `[DefendMesh][${String(item.severity || 'info').toUpperCase()}] ${item.node_id}`;
  const indicators = Array.isArray(item.indicators) ? item.indicators.slice(0, 30) : [];
  const counts = item.counts && typeof item.counts === 'object' ? item.counts : {};
  const body =
    `Threat alert generated by DefendMesh.\n` +
    `Node: ${item.node_id}\n` +
    `Severity: ${item.severity}\n` +
    `Source: ${item.source || 'endpoint'}\n` +
    `At: ${item.at}\n` +
    `Summary: ${item.summary || '-'}\n` +
    `Indicators: ${indicators.join(', ') || '-'}\n` +
    `Counts: ${JSON.stringify(counts)}\n` +
    `Anchor: ${publicUrlBase}/admin\n`;

  const results = [];
  for (const email of threatAlertEmails) {
    // eslint-disable-next-line no-await-in-loop
    const sent = await smtpSendTextEmail(email, subject, body);
    results.push(sent);
  }
  const sentCount = results.filter((r) => r && r.ok).length;
  return { ok: sentCount > 0, sent: sentCount, total: results.length, results };
}

function aiTriageConfigured() {
  return aiTriageEnabled && !!aiTriageModel && !!aiTriageBaseUrl;
}

function extractAiJsonObject(text) {
  let raw = String(text || '').trim();
  if (!raw) return null;
  if (raw.startsWith('```')) {
    raw = raw.replace(/^```[a-zA-Z]*\s*/, '').replace(/\s*```$/, '').trim();
  }
  try {
    const direct = JSON.parse(raw);
    return direct && typeof direct === 'object' ? direct : null;
  } catch (_) {
    // Try bracket extraction fallback.
  }
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start >= 0 && end > start) {
    try {
      const obj = JSON.parse(raw.slice(start, end + 1));
      return obj && typeof obj === 'object' ? obj : null;
    } catch (_) {
      return null;
    }
  }
  return null;
}

function compactStringList(value, maxItems = 8, maxLen = 120) {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => String(v || '').trim())
    .filter(Boolean)
    .slice(0, maxItems)
    .map((v) => v.slice(0, maxLen));
}

function aiContextForNode(item) {
  const nodeId = String(item && item.node_id || '').trim();
  const node = nodes.get(nodeId) || null;
  const profile = profilesByNode.get(nodeId) || null;
  const recentLogs = (logsByNode.get(nodeId) || []).slice(-12);
  const recentResults = (resultsByNode.get(nodeId) || []).slice(-10);
  const recentTriage = (triageByNode.get(nodeId) || []).slice(-10, -1);

  const compactLogs = recentLogs.map((v) => ({
    at: String(v.at || ''),
    level: String(v.level || ''),
    message: String(v.message || '').slice(0, 180)
  }));
  const compactResults = recentResults.map((v) => ({
    at: String(v.at || ''),
    task_id: String(v.task_id || ''),
    status: String(v.status || ''),
    output: String(v.output || '').slice(0, 200)
  }));
  const compactTriage = recentTriage.map((v) => ({
    at: String(v.at || ''),
    severity: normalizeSeverity(v.severity, 'info'),
    summary: String(v.summary || '').slice(0, 200),
    source: String(v.source || '').slice(0, 64)
  }));

  const context = {
    node: {
      node_id: nodeId,
      platform: String(node && node.platform || 'unknown'),
      connections_present: !!(node && node.connections_present),
      current_count: isFiniteNumber(node && node.current_count) ? node.current_count : 0,
      active_sockets: isFiniteNumber(node && node.current_count) ? node.current_count : 0,
      trend: String(node && node.trend || 'unknown'),
      latency_ms: isFiniteNumber(node && node.latency_ms) ? node.latency_ms : 0
    },
    triage_event: {
      at: String(item.at || ''),
      source: String(item.source || 'endpoint'),
      severity: normalizeSeverity(item.severity, 'info'),
      summary: String(item.summary || '').slice(0, 1200),
      indicators: compactStringList(item.indicators, 32, 120),
      counts: item.counts && typeof item.counts === 'object' ? item.counts : {}
    },
    recent_triage: compactTriage
  };

  if (profile) {
    context.host_profile = {
      client_host: String(profile.client_host || '').slice(0, 128),
      client_user: String(profile.client_user || '').slice(0, 128),
      client_os: String(profile.client_os || '').slice(0, 128),
      client_build: String(profile.client_build || '').slice(0, 128),
      client_arch: String(profile.client_arch || '').slice(0, 64),
      client_kernel: String(profile.client_kernel || '').slice(0, 128)
    };
  }

  if (aiTriageFullContext) {
    context.recent_logs = compactLogs;
    context.recent_results = compactResults;
  } else {
    context.recent_logs = compactLogs.slice(-5);
    context.recent_results = compactResults.slice(-5);
  }

  return context;
}

async function aiTriageAssist(item) {
  if (!item || typeof item !== 'object') return { ok: false, error: 'invalid_item' };
  if (!aiTriageConfigured()) return { ok: false, error: 'not_configured' };
  if (severityRank(item.severity) < severityRank(aiTriageMinSeverity)) return { ok: false, error: 'below_min_severity' };

  const endpoint = `${aiTriageBaseUrl.replace(/\/+$/, '')}/chat/completions`;
  const context = aiContextForNode(item);
  let contextText = JSON.stringify(context);
  if (contextText.length > aiTriageMaxContextChars) {
    contextText = contextText.slice(0, aiTriageMaxContextChars);
  }

  const headers = { 'Content-Type': 'application/json' };
  if (aiTriageApiKey) {
    headers.Authorization = `Bearer ${aiTriageApiKey}`;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), aiTriageTimeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers,
      signal: controller.signal,
      body: JSON.stringify({
        model: aiTriageModel,
        temperature: 0,
        max_tokens: 400,
        messages: [
          {
            role: 'system',
            content: 'You are a defensive cyber triage assistant. Provide only defensive mitigation guidance. Return strict JSON with keys: severity, summary, confidence, mitigation_steps, tags.'
          },
          {
            role: 'user',
            content: contextText
          }
        ]
      })
    });
    if (!response.ok) {
      return { ok: false, error: `http_${response.status}` };
    }
    const data = await response.json();
    const message = data && data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message : null;
    let content = message ? message.content : '';
    if (Array.isArray(content)) {
      content = content
        .map((part) => (typeof part === 'string' ? part : String(part && part.text || '')))
        .join('\n');
    }
    const parsed = extractAiJsonObject(content);
    if (!parsed) return { ok: false, error: 'invalid_ai_json' };

    const ai = {
      model: aiTriageModel,
      assessed_at: new Date().toISOString(),
      severity: normalizeSeverity(parsed.severity, normalizeSeverity(item.severity, 'info')),
      summary: String(parsed.summary || '').slice(0, 1200),
      confidence: Math.max(0, Math.min(1, Number(parsed.confidence || 0) || 0)),
      mitigation_steps: compactStringList(parsed.mitigation_steps, 12, 180),
      tags: compactStringList(parsed.tags, 12, 64)
    };
    return { ok: true, ai };
  } catch (err) {
    return { ok: false, error: String(err && err.message || err || 'ai_triage_failed') };
  } finally {
    clearTimeout(timeout);
  }
}

function adminAuth(req) {
  const nowMs = Date.now();
  gcAdminAuthState(nowMs);

  const auth = req.headers.authorization || '';
  if (adminDevToken && auth === `Bearer ${adminDevToken}`) {
    return { ok: true, email: 'dev-token' };
  }

  const cookies = parseCookies(req);
  if (adminDevToken && cookies.defend_admin_token === adminDevToken) {
    return { ok: true, email: 'dev-cookie' };
  }

  const sessionToken = String(cookies.defend_admin_session || '').trim();
  if (sessionToken) {
    const session = adminSessionsByToken.get(sessionToken);
    if (session && adminEmailAllowed(session.email)) {
      session.last_active_ms = nowMs;
      return { ok: true, email: session.email };
    }
  }

  const email = normalizeEmail(req.headers['cf-access-authenticated-user-email']);
  if (!email) {
    return { ok: false, reason: 'missing cf-access email header' };
  }
  if (!adminEmailAllowed(email)) {
    return { ok: false, reason: 'email domain not allowed' };
  }
  return { ok: true, email };
}

function asNodeSnapshot(nowMs) {
  const out = [];
  for (const node of nodes.values()) {
    const profile = profilesByNode.get(node.node_id) || {};
    const triage = latestFromBoundedMap(triageByNode, node.node_id);
    const firstSeenMs = Number.isFinite(node._firstSeenMs) ? node._firstSeenMs : node._updatedMs;
    const ageSec = Math.max(0, Math.floor((nowMs - firstSeenMs) / 1000));
    out.push({
      node_id: node.node_id,
      platform: node.platform,
      connections_present: node.connections_present,
      current_count: node.current_count,
      active_sockets: node.current_count,
      trend: node.trend,
      updated_at: node.updated_at,
      age_sec: ageSec,
      queued_tasks: getQueue(node.node_id).length,
      client_host: profile.client_host || '',
      client_user: profile.client_user || '',
      client_os: profile.client_os || '',
      client_build: profile.client_build || '',
      client_arch: profile.client_arch || '',
      client_kernel: profile.client_kernel || '',
      latency_ms: isFiniteNumber(node.latency_ms) ? node.latency_ms : 0,
      latest_severity: triage ? String(triage.severity || 'none') : 'none',
      latest_incident_at: triage ? String(triage.at || '') : ''
    });
  }
  out.sort((a, b) => a.node_id.localeCompare(b.node_id));
  return out;
}

function spoofHostname(value) {
  const source = String(value || 'node');
  const digest = crypto.createHash('sha256').update(source).digest('hex').slice(0, 8);
  return `node-${digest}`;
}

function githubBaseUrl() {
  return githubRepo.replace(/\.git$/, '');
}

function githubRawBasePath() {
  const base = githubBaseUrl();
  if (base.startsWith('https://github.com/')) {
    const tail = base.slice('https://github.com/'.length).replace(/\/+$/, '');
    return `https://raw.githubusercontent.com/${tail}/${githubRef}/defend-america-against-cyberwarfare`;
  }
  return '';
}

function downloadAssetMap() {
  const rawBase = githubRawBasePath();
  if (!rawBase) return {};
  return {
    'deploy-all.sh': `${rawBase}/scripts/deploy/deploy-all.sh`,
    'linux-connection-monitor.sh': `${rawBase}/scripts/linux/connection-monitor.sh`,
    'windows-connection-monitor.ps1': `${rawBase}/scripts/windows/connection-monitor.ps1`,
    'linux-remove.sh': `${rawBase}/scripts/remove/linux-remove.sh`,
    'macos-remove.sh': `${rawBase}/scripts/remove/macos-remove.sh`,
    'windows-remove.ps1': `${rawBase}/scripts/remove/windows-remove.ps1`
  };
}

function downloadLocalAssetMap() {
  const repoBase = `${__dirname}/..`;
  return {
    'deploy-all.sh': `${repoBase}/scripts/deploy/deploy-all.sh`,
    'linux-connection-monitor.sh': `${repoBase}/scripts/linux/connection-monitor.sh`,
    'windows-connection-monitor.ps1': `${repoBase}/scripts/windows/connection-monitor.ps1`,
    'linux-remove.sh': `${repoBase}/scripts/remove/linux-remove.sh`,
    'macos-remove.sh': `${repoBase}/scripts/remove/macos-remove.sh`,
    'windows-remove.ps1': `${repoBase}/scripts/remove/windows-remove.ps1`
  };
}

function fetchRemoteText(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        timeout: 10000,
        headers: { 'User-Agent': 'defendmesh-anchor/1.0' }
      },
      (upstream) => {
        if (upstream.statusCode !== 200) {
          upstream.resume();
          reject(new Error(`upstream status ${upstream.statusCode || 0}`));
          return;
        }

        const chunks = [];
        let size = 0;
        upstream.on('data', (chunk) => {
          size += chunk.length;
          if (size > 2 * 1024 * 1024) {
            req.destroy(new Error('upstream payload too large'));
            return;
          }
          chunks.push(chunk);
        });
        upstream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      }
    );
    req.on('timeout', () => req.destroy(new Error('upstream timeout')));
    req.on('error', reject);
  });
}

function downloadLinuxScript() {
  const rawBase = githubRawBasePath();
  const monitorUrl = `${rawBase}/scripts/linux/connection-monitor.sh`;
  return `#!/usr/bin/env bash
set -euo pipefail
ANCHOR_URL="\${DEFEND_ANCHOR_URL:-${publicUrlBase}}"
NODE_ID="\${DEFEND_NODE_ID:-$(hostname 2>/dev/null || echo node-linux)}"
OUTPUT_DIR="\${DEFEND_OUTPUT_DIR:-\${HOME:-/tmp}/.defendmesh/output/live-dashboard}"
WORK_DIR="\${TMPDIR:-/tmp}/defendmesh-bootstrap"
MONITOR="$WORK_DIR/connection-monitor.sh"
PID_FILE="$OUTPUT_DIR/monitor.pid"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "${monitorUrl}" -o "$MONITOR"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$MONITOR" "${monitorUrl}"
else
  echo "need curl or wget" >&2
  exit 1
fi
chmod +x "$MONITOR"
ANCHOR_TOKEN="\${DEFEND_ANCHOR_TOKEN:-}"
if [ -z "$ANCHOR_TOKEN" ]; then
  ENROLL_URL="\${ANCHOR_URL%/}/api/v1/node/enroll"
  ENROLL_PAYLOAD="{\\"node_id\\":\\"$NODE_ID\\",\\"platform\\":\\"linux\\"}"
  if command -v curl >/dev/null 2>&1; then
    ENROLL_RESP="$(curl -fsS -m 10 -X POST -H 'Content-Type: application/json' -d "$ENROLL_PAYLOAD" "$ENROLL_URL" 2>/dev/null || true)"
  elif command -v wget >/dev/null 2>&1; then
    ENROLL_RESP="$(wget -qO- --timeout=10 --header='Content-Type: application/json' --post-data="$ENROLL_PAYLOAD" "$ENROLL_URL" 2>/dev/null || true)"
  fi
  if [ -n "\${ENROLL_RESP:-}" ]; then
    ANCHOR_TOKEN="$(printf '%s' "$ENROLL_RESP" | sed -n 's/.*"token":"\\([^"]*\\)".*/\\1/p' | head -n 1)"
  fi
fi
MON_ARGS=(--anchor-url "$ANCHOR_URL" --node-id "$NODE_ID" --output-dir "$OUTPUT_DIR")
if [ -n "$ANCHOR_TOKEN" ]; then
  MON_ARGS+=(--anchor-token "$ANCHOR_TOKEN")
fi
if [ -f "$PID_FILE" ]; then
  RUN_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$RUN_PID" ] && kill -0 "$RUN_PID" 2>/dev/null; then
    echo "monitor already running pid=$RUN_PID node=$NODE_ID; skipping duplicate launch"
    exit 0
  fi
fi
nohup "$MONITOR" "\${MON_ARGS[@]}" > "$OUTPUT_DIR/monitor-stdout.log" 2>&1 &
PID="$!"
printf '%s\n' "$PID" > "$PID_FILE"
echo "started monitor pid=$PID node=$NODE_ID anchor=$ANCHOR_URL output=$OUTPUT_DIR"
if [ -n "$ANCHOR_TOKEN" ]; then
  echo "anchor token auto-provisioned"
else
  echo "warning: no anchor token; heartbeat may be rejected by anchor policy"
fi
`;
}

function downloadMacosScript() {
  return downloadLinuxScript().replace('node-linux', 'node-macos');
}

function downloadWindowsScript() {
  const rawBase = githubRawBasePath();
  const monitorUrl = `${rawBase}/scripts/windows/connection-monitor.ps1`;
  return `$ErrorActionPreference = 'Stop'
$AnchorUrl = if ($env:DEFEND_ANCHOR_URL) { $env:DEFEND_ANCHOR_URL } else { '${publicUrlBase}' }
$NodeId = if ($env:DEFEND_NODE_ID) { $env:DEFEND_NODE_ID } else { $env:COMPUTERNAME }
$OutputDir = if ($env:DEFEND_OUTPUT_DIR) { $env:DEFEND_OUTPUT_DIR } else { Join-Path $env:USERPROFILE '.defendmesh\\output\\live-dashboard' }
$AnchorToken = $env:DEFEND_ANCHOR_TOKEN
$TmpRoot = Join-Path $env:TEMP 'defendmesh-bootstrap'
$MonitorPath = Join-Path $TmpRoot 'connection-monitor.ps1'
$PidFile = Join-Path $OutputDir 'monitor.pid'
New-Item -ItemType Directory -Path $TmpRoot -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Invoke-WebRequest -UseBasicParsing -Uri '${monitorUrl}' -OutFile $MonitorPath
if ([string]::IsNullOrWhiteSpace($AnchorToken)) {
  try {
    $EnrollBody = @{ node_id = $NodeId; platform = 'windows' } | ConvertTo-Json -Compress
    $Enroll = Invoke-RestMethod -Method Post -ContentType 'application/json' -Uri (($AnchorUrl.TrimEnd('/')) + '/api/v1/node/enroll') -Body $EnrollBody
    if ($Enroll -and $Enroll.token) { $AnchorToken = [string]$Enroll.token }
  } catch {}
}
$args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$MonitorPath,'-AnchorUrl',$AnchorUrl,'-NodeId',$NodeId,'-OutputDir',$OutputDir)
if (-not [string]::IsNullOrWhiteSpace($AnchorToken)) { $args += @('-AnchorToken',$AnchorToken) }
if (Test-Path -LiteralPath $PidFile) {
  try {
    $existingPid = [int](Get-Content -LiteralPath $PidFile -ErrorAction Stop | Select-Object -First 1)
    if (Get-Process -Id $existingPid -ErrorAction SilentlyContinue) {
      Write-Output ('monitor already running pid=' + $existingPid + ' node=' + $NodeId + '; skipping duplicate launch')
      exit 0
    }
  } catch {}
}
$existingProc = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
  $_.CommandLine -like '*connection-monitor.ps1*' -and $_.CommandLine -like ('*-NodeId*' + $NodeId + '*')
} | Select-Object -First 1
if ($existingProc) {
  Write-Output ('monitor already running pid=' + $existingProc.ProcessId + ' node=' + $NodeId + '; skipping duplicate launch')
  exit 0
}
$proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $args -WindowStyle Hidden -PassThru
[string]$proc.Id | Set-Content -LiteralPath $PidFile -Encoding ASCII
Write-Output ('started monitor pid=' + $proc.Id + ' node=' + $NodeId + ' anchor=' + $AnchorUrl + ' output=' + $OutputDir)
`;
}

function downloadRemoveLinuxScript() {
  return `#!/usr/bin/env bash
set -euo pipefail
HOME_BASE="\${HOME:-/tmp}"
DEFAULT_ROOT="\${DEFEND_ROOT_DIR:-$HOME_BASE/.defendmesh}"
WORK_DIR="\${DEFEND_WORK_DIR:-\${TMPDIR:-/tmp}/defendmesh-bootstrap}"
echo "[1/4] Stopping DefendMesh monitor/agent processes..."
pkill -f 'connection-monitor.sh' 2>/dev/null || true
pkill -f 'node-agent.sh' 2>/dev/null || true
echo "[2/4] Removing bootstrap workspace..."
rm -rf "$WORK_DIR" 2>/dev/null || true
echo "[3/4] Removing DefendMesh output directories..."
rm -rf "$DEFAULT_ROOT" 2>/dev/null || true
rm -rf "./output/live-dashboard" "./output/node-agent" "./output/oneclick-live-dashboard" "./output/oneclick-node-agent" 2>/dev/null || true
echo "[4/4] Removal complete."
`;
}

function downloadRemoveMacosScript() {
  return downloadRemoveLinuxScript();
}

function downloadRemoveWindowsScript() {
  return `$ErrorActionPreference = 'SilentlyContinue'
$root = if ($env:DEFEND_ROOT_DIR) { $env:DEFEND_ROOT_DIR } else { Join-Path $env:USERPROFILE '.defendmesh' }
$work = if ($env:DEFEND_WORK_DIR) { $env:DEFEND_WORK_DIR } else { Join-Path $env:TEMP 'defendmesh-bootstrap' }
Write-Output '[1/4] Stopping DefendMesh monitor/agent processes...'
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -and (
    $_.CommandLine -like '*connection-monitor.ps1*' -or
    $_.CommandLine -like '*node-agent.ps1*'
  )
} | ForEach-Object {
  try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {}
}
Write-Output '[2/4] Removing bootstrap workspace...'
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Output '[3/4] Removing DefendMesh output directories...'
Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\\output\\live-dashboard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\\output\\node-agent' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\\output\\oneclick-live-dashboard' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath '.\\output\\oneclick-node-agent' -Recurse -Force -ErrorAction SilentlyContinue
Write-Output '[4/4] Removal complete.'
`;
}

function renderNodes(nodes, authorized) {
  return nodes.map((n) => ({
    ...n,
    display_node_id: authorized ? (n.node_id || '-') : spoofHostname(n.node_id || 'node'),
    display_host: authorized ? (n.client_host || n.node_id || '-') : spoofHostname(n.client_host || n.node_id),
    display_user: authorized ? (n.client_user || '-') : '-'
  }));
}

function dashboardHtml(authorized) {
  const now = Date.now();
  const list = renderNodes(asNodeSnapshot(now), authorized);
  const gitBase = githubBaseUrl();
  const linuxDl = `${publicUrlBase}/download/linux`;
  const macDl = `${publicUrlBase}/download/macos`;
  const winDl = `${publicUrlBase}/download/windows`;
  const linuxRmDl = `${publicUrlBase}/download/remove/linux`;
  const macRmDl = `${publicUrlBase}/download/remove/macos`;
  const winRmDl = `${publicUrlBase}/download/remove/windows`;
  const winMonitor = `${publicUrlBase}/download/asset/windows-connection-monitor.ps1`;
  const linMonitor = `${publicUrlBase}/download/asset/linux-connection-monitor.sh`;
  const linRemoveAsset = `${publicUrlBase}/download/asset/linux-remove.sh`;
  const macRemoveAsset = `${publicUrlBase}/download/asset/macos-remove.sh`;
  const winRemoveAsset = `${publicUrlBase}/download/asset/windows-remove.ps1`;
  const deployAll = `${publicUrlBase}/download/asset/deploy-all.sh`;
  const cmdLinux = `curl -fsSL ${linuxDl} | bash`;
  const cmdMac = `curl -fsSL ${macDl} | bash`;
  const cmdWin = `powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing ${winDl} -OutFile $env:TEMP\\defendmesh.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\defendmesh.ps1"`;
  const rmCmdLinux = `curl -fsSL ${linuxRmDl} | bash`;
  const rmCmdMac = `curl -fsSL ${macRmDl} | bash`;
  const rmCmdWin = `powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing ${winRmDl} -OutFile $env:TEMP\\defendmesh-remove.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\defendmesh-remove.ps1"`;
  const refreshMeta = authorized ? '' : '<meta http-equiv="refresh" content="5">';
  const playbookOptions = Array.from(PLAYBOOKS)
    .sort((a, b) => a.localeCompare(b))
    .map((p) => `<option value="${escHtml(p)}">${escHtml(p)}</option>`)
    .join('');
  const nodeChoices = list.length
    ? list
        .map((n) => `<label class="node-choice"><input type="checkbox" name="op-node" value="${escHtml(n.node_id)}"> ${escHtml(n.node_id)} <span class="meta-mini">(${escHtml(n.platform)})</span></label>`)
        .join('')
    : '<div class="meta-mini">No nodes currently reported.</div>';
  const adminOpsPanel = authorized
    ? `<div class="ops">
<h2 style="margin:14px 0 8px 0;font-size:15px;text-transform:uppercase;letter-spacing:.05em;">Admin Operations</h2>
<div class="meta">Approved playbooks and signed patch staging only. Arbitrary shell/python execution is intentionally disabled.</div>
<div class="ops-grid">
<div class="panel2">
<h3>Dispatch Playbook</h3>
<label class="field-label" for="op-playbook">Playbook</label>
<select id="op-playbook" class="op-input">${playbookOptions}</select>
<label class="field-label" for="op-target">Target Mode</label>
<select id="op-target" class="op-input">
<option value="one">one</option>
<option value="many">many</option>
<option value="all">all</option>
</select>
<label class="field-label" for="op-limit">Limit (optional for all/many)</label>
<input id="op-limit" class="op-input" type="number" min="1" placeholder="e.g. 2">
<label class="field-label">Node Selection</label>
<div class="node-list" id="op-node-list">${nodeChoices}</div>
<label class="field-label" for="op-args">Args JSON (object)</label>
<textarea id="op-args" class="op-input op-textarea" placeholder='{"interval_sec":2}'></textarea>
<button class="copy-btn" type="button" id="op-send-task">send task</button>
<pre id="op-task-result">idle</pre>
</div>
<div class="panel2">
<h3>Patch Upload</h3>
<label class="field-label" for="op-patch-filename">Filename</label>
<input id="op-patch-filename" class="op-input" type="text" placeholder="harden.sh">
<label class="field-label" for="op-patch-content">Patch / Script Content</label>
<textarea id="op-patch-content" class="op-input op-textarea" placeholder="#!/usr/bin/env bash"></textarea>
<div style="display:flex;gap:8px;flex-wrap:wrap;">
<button class="copy-btn" type="button" id="op-upload-patch">upload patch</button>
<button class="copy-btn" type="button" id="op-upload-dispatch">upload + dispatch stage_patch</button>
</div>
<pre id="op-patch-result">idle</pre>
</div>
</div>
</div>`
    : '';
  const rows = list.length
    ? list
        .map((node) => `<tr>
<td>${escHtml(node.display_node_id)}</td>
<td>${escHtml(node.display_host)}</td>
<td>${escHtml(node.display_user)}</td>
<td>${escHtml(node.client_os || '-')}</td>
<td>${escHtml(node.platform)}</td>
<td>${node.connections_present ? 'yes' : 'no'}</td>
<td>${node.current_count}</td>
<td>${escHtml(node.trend)}</td>
<td>${node.latency_ms}ms</td>
<td>${escHtml(node.latest_severity || 'none')}</td>
<td>${escHtml(formatEstMinus5(node.updated_at))}</td>
<td>${node.age_sec}s</td>
<td>${node.queued_tasks}</td>
</tr>`)
        .join('')
    : '<tr><td colspan="13">No nodes reported yet.</td></tr>';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(anchorName)}</title>
${refreshMeta}
<style>
body { font-family: "JetBrains Mono", "SF Mono", Consolas, monospace; margin: 0; background: #0a0a0a; color: #fff; }
.wrap { max-width: 1440px; margin: 24px auto; padding: 0 16px; }
.panel { border: 1px solid #2a2a2a; background: #111; border-radius: 0; padding: 14px; }
h1 { margin: 0 0 6px 0; font-size: 20px; letter-spacing: .04em; text-transform: uppercase; }
.meta { color: #ccc; font-size: 12px; margin-bottom: 10px; }
a { color: #fff; text-decoration: underline; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #2a2a2a; padding: 7px 8px; text-align: left; font-size: 12px; white-space: nowrap; }
th { background: #0a0a0a; color: #fff; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; }
td { color: #ccc; }
tbody tr:hover td { background: #1a1a1a; color: #fff; }
pre { border: 1px solid #2a2a2a; background: #0a0a0a; color: #ddd; padding: 8px; font-size: 12px; overflow-x: auto; }
.downloads { margin-top: 14px; border-top: 1px solid #2a2a2a; padding-top: 12px; }
.downloads-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 10px; }
.downloads-grid .panel2 { border: 1px solid #2a2a2a; padding: 10px; background: #141414; border-radius: 6px; }
.downloads-grid h3 { margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #fff; }
.os-line { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.os-tag { display: inline-block; min-width: 70px; text-align: center; border: 1px solid #3a3a3a; background: #0f0f0f; color: #ddd; padding: 3px 6px; font-size: 10px; text-transform: uppercase; letter-spacing: .07em; }
.os-win { border-color: #2563eb; color: #93c5fd; }
.os-lin { border-color: #16a34a; color: #86efac; }
.os-mac { border-color: #d97706; color: #fdba74; }
.cmd-row { display: flex; align-items: center; gap: 8px; border: 1px solid #2a2a2a; background: #0c0c0c; padding: 8px; margin-bottom: 8px; }
.cmd-row code { display: block; white-space: nowrap; overflow-x: auto; color: #e8e8e8; font-size: 11px; flex: 1 1 auto; }
.copy-btn { border: 1px solid #3a3a3a; background: #1e1e1e; color: #fff; padding: 6px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; cursor: pointer; }
.copy-btn:hover { background: #2a2a2a; }
.mission { margin: 8px 0 10px 0; padding: 8px 10px; border: 1px solid #2a2a2a; background: #0d1117; color: #d1fae5; font-size: 12px; }
.ops { margin-top: 14px; border-top: 1px solid #2a2a2a; padding-top: 12px; }
.ops-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 10px; }
.field-label { display: block; margin: 8px 0 4px 0; color: #bbb; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.op-input { width: 100%; background: #0b0b0b; color: #fff; border: 1px solid #2a2a2a; padding: 8px; box-sizing: border-box; }
.op-textarea { min-height: 110px; resize: vertical; font-family: "JetBrains Mono", "SF Mono", Consolas, monospace; font-size: 12px; }
.node-list { max-height: 150px; overflow-y: auto; border: 1px solid #2a2a2a; background: #0b0b0b; padding: 6px; }
.node-choice { display: block; margin: 4px 0; font-size: 12px; color: #ddd; }
.meta-mini { color: #888; font-size: 11px; }
</style>
</head>
<body>
<div class="wrap">
<div class="panel">
<h1>${escHtml(anchorName)}</h1>
<div class="meta">route=${escHtml(publicUrl)} | auth_view=${authorized ? 'authorized_real' : 'public_spoofed'} | nodes=${list.length} | est=${escHtml(formatEstMinus5(now))}</div>
<div class="mission">${escHtml(missionStatement)}</div>
${authorized ? '<div class="meta"><a href="/admin/logout">logout</a></div>' : ''}
<table>
<thead>
<tr>
<th>node_id</th>
<th>host</th>
<th>user</th>
<th>client_os</th>
<th>platform</th>
<th>connections</th>
<th>active_sockets</th>
<th>trend</th>
<th>latency</th>
<th>severity</th>
<th>updated_at</th>
<th>age</th>
<th>queued_tasks</th>
</tr>
</thead>
<tbody>${rows}</tbody>
</table>
${adminOpsPanel}
<div class="downloads">
<h2 style="margin:14px 0 8px 0;font-size:15px;text-transform:uppercase;letter-spacing:.05em;">Connect Node</h2>
<div class="meta">Download from this anchor or pull direct from GitHub.</div>
<div class="downloads-grid">
<div class="panel2">
<h3>Direct Downloads</h3>
<div class="os-line"><span class="os-tag os-win">Windows</span><a download href="${escHtml(winDl)}">bootstrap (.ps1)</a></div>
<div class="os-line"><span class="os-tag os-lin">Linux</span><a download href="${escHtml(linuxDl)}">bootstrap (.sh)</a></div>
<div class="os-line"><span class="os-tag os-mac">macOS</span><a download href="${escHtml(macDl)}">bootstrap (.sh)</a></div>
</div>
<div class="panel2">
<h3>One-line Run</h3>
<div class="cmd-row"><span class="os-tag os-lin">Linux</span><code>${escHtml(cmdLinux)}</code><button class="copy-btn" type="button" data-copy-text="${escHtml(cmdLinux)}">copy</button></div>
<div class="cmd-row"><span class="os-tag os-mac">macOS</span><code>${escHtml(cmdMac)}</code><button class="copy-btn" type="button" data-copy-text="${escHtml(cmdMac)}">copy</button></div>
<div class="cmd-row"><span class="os-tag os-win">Windows</span><code>${escHtml(cmdWin)}</code><button class="copy-btn" type="button" data-copy-text="${escHtml(cmdWin)}">copy</button></div>
<h3 style="margin-top:10px;">One-line Remove</h3>
<div class="cmd-row"><span class="os-tag os-lin">Linux</span><code>${escHtml(rmCmdLinux)}</code><button class="copy-btn" type="button" data-copy-text="${escHtml(rmCmdLinux)}">copy</button></div>
<div class="cmd-row"><span class="os-tag os-mac">macOS</span><code>${escHtml(rmCmdMac)}</code><button class="copy-btn" type="button" data-copy-text="${escHtml(rmCmdMac)}">copy</button></div>
<div class="cmd-row"><span class="os-tag os-win">Windows</span><code>${escHtml(rmCmdWin)}</code><button class="copy-btn" type="button" data-copy-text="${escHtml(rmCmdWin)}">copy</button></div>
</div>
<div class="panel2">
<h3>GitHub Source</h3>
<div><a href="${escHtml(gitBase)}">${escHtml(gitBase)}</a></div>
<div><a href="${escHtml(`${publicUrlBase}/admin`)}">Admin View</a> (authorized only)</div>
<pre>git clone ${escHtml(githubRepo)} && cd ordl-infra/defend-america-against-cyberwarfare</pre>
<div><a download href="${escHtml(deployAll)}">deploy-all.sh</a></div>
<div><a download href="${escHtml(linMonitor)}">linux connection-monitor.sh</a></div>
<div><a download href="${escHtml(winMonitor)}">windows connection-monitor.ps1</a></div>
<div><a download href="${escHtml(linRemoveAsset)}">linux-remove.sh</a></div>
<div><a download href="${escHtml(macRemoveAsset)}">macos-remove.sh</a></div>
<div><a download href="${escHtml(winRemoveAsset)}">windows-remove.ps1</a></div>
</div>
</div>
</div>
</div>
</div>
<script>
(() => {
  async function copyText(value) {
    if (!value) return false;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', 'readonly');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  }
  document.addEventListener('click', async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const button = target.closest('button[data-copy-text]');
    if (!button) return;
    const text = button.getAttribute('data-copy-text') || '';
    const original = button.textContent || 'copy';
    try {
      const ok = await copyText(text);
      button.textContent = ok ? 'copied' : 'failed';
    } catch (_) {
      button.textContent = 'failed';
    }
    setTimeout(() => { button.textContent = original; }, 1500);
  });

  function selectedNodeIds() {
    return Array.from(document.querySelectorAll('input[name="op-node"]:checked')).map((el) => el.value);
  }

  const adminStateKey = 'defendmesh_admin_ops_state_v1';

  function hasAdminOps() {
    return !!document.getElementById('op-playbook');
  }

  function collectAdminOpsState() {
    return {
      playbook: (document.getElementById('op-playbook') && document.getElementById('op-playbook').value) || '',
      target: (document.getElementById('op-target') && document.getElementById('op-target').value) || '',
      limit: (document.getElementById('op-limit') && document.getElementById('op-limit').value) || '',
      args: (document.getElementById('op-args') && document.getElementById('op-args').value) || '',
      patch_filename: (document.getElementById('op-patch-filename') && document.getElementById('op-patch-filename').value) || '',
      patch_content: (document.getElementById('op-patch-content') && document.getElementById('op-patch-content').value) || '',
      selected_nodes: selectedNodeIds()
    };
  }

  function applyAdminOpsState(state) {
    if (!state || typeof state !== 'object') return;
    const setValue = (id, value) => {
      const el = document.getElementById(id);
      if (el && typeof value === 'string') el.value = value;
    };
    setValue('op-playbook', String(state.playbook || ''));
    setValue('op-target', String(state.target || ''));
    setValue('op-limit', String(state.limit || ''));
    setValue('op-args', String(state.args || ''));
    setValue('op-patch-filename', String(state.patch_filename || ''));
    setValue('op-patch-content', String(state.patch_content || ''));
    const selected = Array.isArray(state.selected_nodes) ? new Set(state.selected_nodes.map((v) => String(v))) : new Set();
    for (const cb of document.querySelectorAll('input[name="op-node"]')) {
      cb.checked = selected.has(String(cb.value || ''));
    }
  }

  function saveAdminOpsState() {
    if (!hasAdminOps()) return;
    try {
      localStorage.setItem(adminStateKey, JSON.stringify(collectAdminOpsState()));
    } catch (_) {
      // Ignore storage failures.
    }
  }

  function loadAdminOpsState() {
    if (!hasAdminOps()) return;
    try {
      const raw = localStorage.getItem(adminStateKey);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      applyAdminOpsState(parsed);
    } catch (_) {
      // Ignore storage failures.
    }
  }

  function parseArgsJson() {
    const el = document.getElementById('op-args');
    const text = (el && el.value || '').trim();
    if (!text) return {};
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('args JSON must be an object');
    }
    return parsed;
  }

  function targetPayload() {
    const mode = (document.getElementById('op-target') && document.getElementById('op-target').value) || 'one';
    const ids = selectedNodeIds();
    const limitRaw = (document.getElementById('op-limit') && document.getElementById('op-limit').value || '').trim();
    const limit = Number(limitRaw);
    const payload = {};
    if (mode === 'all') {
      payload.target = 'all';
      if (Number.isInteger(limit) && limit > 0) payload.limit = limit;
      return payload;
    }
    if (mode === 'one') {
      if (ids.length < 1) throw new Error('select one node');
      payload.node_id = ids[0];
      return payload;
    }
    if (ids.length < 1) throw new Error('select one or more nodes');
    payload.node_ids = ids;
    if (Number.isInteger(limit) && limit > 0) payload.limit = limit;
    return payload;
  }

  function setOut(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value);
  }

  async function postJson(path, payload) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const txt = await res.text();
    let data = null;
    try {
      data = JSON.parse(txt);
    } catch (_) {
      data = { raw: txt };
    }
    if (!res.ok) {
      throw new Error((data && data.error) ? data.error : ('http_' + res.status));
    }
    return data;
  }

  function toBase64(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  }

  loadAdminOpsState();
  if (hasAdminOps()) {
    const saveIds = ['op-playbook', 'op-target', 'op-limit', 'op-args', 'op-patch-filename', 'op-patch-content'];
    for (const id of saveIds) {
      const el = document.getElementById(id);
      if (!el) continue;
      el.addEventListener('change', saveAdminOpsState);
      el.addEventListener('input', saveAdminOpsState);
    }
    for (const cb of document.querySelectorAll('input[name="op-node"]')) {
      cb.addEventListener('change', saveAdminOpsState);
    }
  }

  const taskBtn = document.getElementById('op-send-task');
  if (taskBtn) {
    taskBtn.addEventListener('click', async () => {
      try {
        const playbook = (document.getElementById('op-playbook') && document.getElementById('op-playbook').value) || '';
        if (!playbook) throw new Error('select playbook');
        const payload = {
          playbook,
          args: parseArgsJson(),
          ...targetPayload()
        };
        const out = await postJson('/api/v1/admin/task', payload);
        setOut('op-task-result', JSON.stringify(out, null, 2));
      } catch (err) {
        setOut('op-task-result', 'error: ' + (err && err.message || err));
      }
    });
  }

  async function uploadPatchOnly() {
    const name = (document.getElementById('op-patch-filename') && document.getElementById('op-patch-filename').value || '').trim();
    const content = (document.getElementById('op-patch-content') && document.getElementById('op-patch-content').value || '');
    if (!name) throw new Error('filename required');
    if (!content) throw new Error('content required');
    return postJson('/api/v1/admin/patch', { filename: name, content_b64: toBase64(content) });
  }

  const uploadBtn = document.getElementById('op-upload-patch');
  if (uploadBtn) {
    uploadBtn.addEventListener('click', async () => {
      try {
        const out = await uploadPatchOnly();
        setOut('op-patch-result', JSON.stringify(out, null, 2));
      } catch (err) {
        setOut('op-patch-result', 'error: ' + (err && err.message || err));
      }
    });
  }

  const uploadDispatchBtn = document.getElementById('op-upload-dispatch');
  if (uploadDispatchBtn) {
    uploadDispatchBtn.addEventListener('click', async () => {
      try {
        const patch = await uploadPatchOnly();
        const taskPayload = {
          playbook: 'stage_patch',
          args: { patch_id: patch.patch_id },
          ...targetPayload()
        };
        const task = await postJson('/api/v1/admin/task', taskPayload);
        setOut('op-patch-result', JSON.stringify({ patch, dispatch: task }, null, 2));
      } catch (err) {
        setOut('op-patch-result', 'error: ' + (err && err.message || err));
      }
    });
  }
})();
</script>
</body>
</html>`;
}

function adminLoginHtml(message = '') {
  const note = message ? `<p style="color:#fca5a5;font-family:monospace;border:1px solid #3a1d1d;background:#1a0f0f;padding:8px">${escHtml(message)}</p>` : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Login</title>
<style>
body{font-family:"JetBrains Mono","SF Mono",Consolas,monospace;background:#0a0a0a;color:#fff;margin:0}
.wrap{max-width:640px;margin:64px auto;padding:0 16px}
.panel{border:1px solid #2a2a2a;background:#111;padding:16px}
.section{border:1px solid #2a2a2a;background:#0d0d0d;padding:12px;margin-top:10px}
label{display:block;margin-bottom:8px;color:#ccc;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
input{width:100%;padding:10px;border:1px solid #2a2a2a;background:#0a0a0a;color:#fff;box-sizing:border-box}
button{margin-top:10px;padding:10px 14px;border:1px solid #3a3a3a;background:#1e1e1e;color:#fff;cursor:pointer;text-transform:uppercase;font-size:12px}
a{color:#fff}
</style>
</head>
<body>
<div class="wrap">
<div class="panel">
<h1 style="margin:0 0 10px 0;font-size:18px;text-transform:uppercase;">Admin Access</h1>
<p style="color:#d1fae5;border:1px solid #2a2a2a;background:#0d1117;padding:8px">${escHtml(missionStatement)}</p>
<p style="color:#ccc">Allowed email only: explicit whitelist or approved suffix (for example <code>.gov</code>).</p>
<p style="color:#ccc">Token TTL: ${adminEmailTokenTtlSec}s. Session idle timeout: ${adminSessionIdleSec}s.</p>
${note}
<div class="section">
<h2 style="margin:0 0 8px 0;font-size:14px;text-transform:uppercase;">1) Request Access Token</h2>
<form method="post" action="/admin/request-access">
<label for="request_email">Email</label>
<input id="request_email" name="email" type="email" autocomplete="email" required />
<button type="submit">Send Token</button>
</form>
</div>
<div class="section">
<h2 style="margin:0 0 8px 0;font-size:14px;text-transform:uppercase;">2) Verify Access Token</h2>
<form method="post" action="/admin/verify-access">
<label for="verify_email">Email</label>
<input id="verify_email" name="email" type="email" autocomplete="email" required />
<label for="verify_token" style="margin-top:10px">Access Token</label>
<input id="verify_token" name="token" type="text" autocomplete="one-time-code" required />
<button type="submit">Sign In</button>
</form>
</div>
<div class="section">
<h2 style="margin:0 0 8px 0;font-size:14px;text-transform:uppercase;">Fallback Dev Token</h2>
<form method="post" action="/admin/login">
<label for="dev_token">Admin Dev Token</label>
<input id="dev_token" name="token" type="password" autocomplete="off" />
<button type="submit">Sign In (Dev)</button>
</form>
</div>
<p style="margin-top:12px;font-size:12px;color:#aaa"><a href="/">Back to public dashboard</a></p>
</div>
</div>
</body>
</html>`;
}

function makeTaskId() {
  return `task_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function makePatchId() {
  return `patch_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

function handleHeartbeat(body, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  const platform = String(body.platform || '').trim().toLowerCase();
  const updatedAt = String(body.updated_at || '');
  if (!nodeId) return badRequest(res, 'node_id required');
  if (!platform) return badRequest(res, 'platform required');
  const reportedCount = isFiniteNumber(body.current_count)
    ? body.current_count
    : (isFiniteNumber(body.active_sockets) ? body.active_sockets : NaN);
  if (!isFiniteNumber(reportedCount)) return badRequest(res, 'current_count or active_sockets must be number');
  if (!updatedAt || Number.isNaN(Date.parse(updatedAt))) return badRequest(res, 'updated_at must be ISO date');

  const existing = nodes.get(nodeId);
  const entry = {
    node_id: nodeId,
    platform,
    connections_present: normalizeBool(body.connections_present),
    current_count: reportedCount,
    trend: normalizeTrend(body.trend),
    updated_at: updatedAt,
    _updatedMs: Date.parse(updatedAt),
    _firstSeenMs: existing && Number.isFinite(existing._firstSeenMs) ? existing._firstSeenMs : Date.parse(updatedAt),
    latency_ms: isFiniteNumber(body.latency_ms)
      ? Math.max(0, Math.floor(body.latency_ms))
      : Math.max(0, Date.now() - Date.parse(updatedAt))
  };
  nodes.set(nodeId, entry);
  const latestTriage = latestFromBoundedMap(triageByNode, nodeId);
  const autoTasks = maybeEnqueueAutoPlaybooks(nodeId, latestTriage ? latestTriage.severity : 'info');
  sendJson(res, 200, { ok: true, node_id: nodeId, auto_tasks_queued: autoTasks.length });
}

function handleNodeLog(body, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  const message = String(body.message || '').trim();
  const level = String(body.level || 'info').trim().toLowerCase();
  if (!nodeId) return badRequest(res, 'node_id required');
  if (!message) return badRequest(res, 'message required');

  const item = {
    at: new Date().toISOString(),
    node_id: nodeId,
    level,
    message
  };
  pushBounded(logsByNode, nodeId, item, 300);
  sendJson(res, 200, { ok: true });
}

function handleNodeTasks(req, res, url) {
  const nodeId = String(url.searchParams.get('node_id') || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  const queue = getQueue(nodeId);
  const tasks = queue.splice(0, queue.length);
  sendJson(res, 200, { ok: true, node_id: nodeId, tasks });
}

function handleNodeStatus(req, res, url) {
  const nodeId = String(url.searchParams.get('node_id') || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  const node = nodes.get(nodeId) || null;
  const profile = profilesByNode.get(nodeId) || null;
  const triage = latestFromBoundedMap(triageByNode, nodeId);
  const queued = getQueue(nodeId).length;

  if (!node) {
    sendJson(res, 200, {
      ok: true,
      node_id: nodeId,
      registered: false,
      queued_tasks: queued
    });
    return;
  }

  const nowMs = Date.now();
  const firstSeenMs = Number.isFinite(node._firstSeenMs) ? node._firstSeenMs : node._updatedMs;
  sendJson(res, 200, {
    ok: true,
    node_id: nodeId,
    registered: true,
    platform: node.platform,
    updated_at: node.updated_at,
    age_sec: Math.max(0, Math.floor((nowMs - firstSeenMs) / 1000)),
    latency_ms: isFiniteNumber(node.latency_ms) ? node.latency_ms : 0,
    current_count: node.current_count,
    active_sockets: node.current_count,
    connections_present: node.connections_present,
    trend: node.trend,
    queued_tasks: queued,
    profile: profile || {},
    latest_severity: triage ? String(triage.severity || 'none') : 'none',
    token_registered: nodeTokensByNode.has(nodeId)
  });
}

function handleTaskResult(body, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  const taskId = String(body.task_id || '').trim();
  const status = String(body.status || '').trim().toLowerCase();
  if (!nodeId || !taskId || !status) return badRequest(res, 'node_id, task_id, status required');

  const item = {
    at: new Date().toISOString(),
    node_id: nodeId,
    task_id: taskId,
    status,
    output: String(body.output || '')
  };
  pushBounded(resultsByNode, nodeId, item, 200);
  const taskMeta = taskMetaById.get(taskId) || null;
  if (taskMeta) taskMetaById.delete(taskId);

  const resultSeverity = status === 'error' ? 'high' : 'low';
  const triageItem = {
    at: item.at,
    node_id: nodeId,
    source: taskMeta ? `task:${taskMeta.playbook}` : 'task:unknown',
    severity: resultSeverity,
    summary: `Task result ${status}${taskMeta ? ` (${taskMeta.playbook})` : ''}`,
    indicators: [],
    counts: {}
  };
  pushBounded(triageByNode, nodeId, triageItem, 100);

  sendJson(res, 200, { ok: true, node_id: nodeId, severity: triageItem.severity });

  void (async () => {
    try {
      const aiResult = await aiTriageAssist(triageItem);
      if (aiResult && aiResult.ok && aiResult.ai) {
        triageItem.ai = aiResult.ai;
        triageItem.severity = normalizeSeverity(aiResult.ai.severity, triageItem.severity);
        if (aiResult.ai.summary) {
          triageItem.summary = aiResult.ai.summary;
        }
      }
      maybeEnqueueAutoPlaybooks(nodeId, triageItem.severity);
      await dispatchThreatAlertEmail(triageItem);
    } catch (_) {
      // Keep node result flow resilient even if enrichment/alerts fail.
    }
  })();
}

function handleNodeProfile(body, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  const profile = body.profile && typeof body.profile === 'object' ? body.profile : {};
  const record = {
    node_id: nodeId,
    client_host: String(profile.client_host || '').trim(),
    client_user: String(profile.client_user || '').trim(),
    client_os: String(profile.client_os || '').trim(),
    client_build: String(profile.client_build || '').trim(),
    client_arch: String(profile.client_arch || '').trim(),
    client_kernel: String(profile.client_kernel || '').trim(),
    updated_at: String(body.updated_at || new Date().toISOString())
  };
  profilesByNode.set(nodeId, record);
  sendJson(res, 200, { ok: true, node_id: nodeId });
}

function handleNodeEnroll(body, res) {
  if (!openEnroll) {
    forbidden(res);
    return;
  }
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  const existing = nodeTokensByNode.get(nodeId);
  if (existing && existing.token) {
    sendJson(res, 200, { ok: true, node_id: nodeId, existing: true, token_issued: false });
    return;
  }

  const token = crypto.randomBytes(24).toString('hex');
  const platform = String(body.platform || 'unknown').trim().toLowerCase().slice(0, 32);
  setNodeToken(nodeId, token, 'self-enroll', `bootstrap:${platform || 'unknown'}`);
  sendJson(res, 200, { ok: true, node_id: nodeId, token, existing: false, token_issued: true });
}

function handleNodeTriage(body, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  const severityRaw = String(body.severity || 'info').trim().toLowerCase();
  const severity = normalizeSeverity(severityRaw, 'info');
  const indicators = Array.isArray(body.indicators) ? body.indicators.slice(0, 200) : [];
  const counts = body.counts && typeof body.counts === 'object' ? body.counts : {};
  const summary = String(body.summary || '').slice(0, 2000);
  const source = String(body.source || 'endpoint').slice(0, 64);
  const at = new Date().toISOString();

  const item = {
    at,
    node_id: nodeId,
    source,
    severity,
    summary,
    indicators,
    counts
  };
  pushBounded(triageByNode, nodeId, item, 100);
  const autoTasks = maybeEnqueueAutoPlaybooks(nodeId, item.severity);
  sendJson(res, 200, { ok: true, node_id: nodeId, severity: item.severity, auto_tasks_queued: autoTasks.length });

  void (async () => {
    try {
      const aiResult = await aiTriageAssist(item);
      if (aiResult && aiResult.ok && aiResult.ai) {
        item.ai = aiResult.ai;
        item.severity = normalizeSeverity(aiResult.ai.severity, item.severity);
        if (aiResult.ai.summary) {
          item.summary = aiResult.ai.summary;
        }
      }
      maybeEnqueueAutoPlaybooks(nodeId, item.severity);
      await dispatchThreatAlertEmail(item);
    } catch (_) {
      // Keep triage ingestion available even if async enrichment fails.
    }
  })();
}

function knownNodeIds() {
  const ids = new Set();
  for (const k of nodes.keys()) ids.add(String(k));
  for (const k of profilesByNode.keys()) ids.add(String(k));
  for (const k of nodeTokensByNode.keys()) ids.add(String(k));
  for (const k of queuesByNode.keys()) ids.add(String(k));
  return Array.from(ids).filter(Boolean).sort((a, b) => a.localeCompare(b));
}

function resolveTaskTargets(body) {
  const targetMode = String(body.target || '').trim().toLowerCase();
  const nodeId = String(body.node_id || '').trim();
  const nodeIds = Array.isArray(body.node_ids) ? body.node_ids : [];
  const platformFilter = String(body.platform || '').trim().toLowerCase();
  const parsedLimit = Number(body.limit || 0);
  const limit = Number.isInteger(parsedLimit) && parsedLimit > 0 ? parsedLimit : 0;

  let targets = [];
  if (targetMode === 'all') {
    targets = knownNodeIds();
  } else if (nodeIds.length > 0) {
    targets = nodeIds.map((v) => String(v || '').trim()).filter(Boolean);
  } else if (nodeId) {
    targets = [nodeId];
  } else {
    return { ok: false, error: 'target required: use node_id, node_ids, or target=all' };
  }

  // Deduplicate while preserving first-seen order.
  const seen = new Set();
  targets = targets.filter((id) => {
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  if (platformFilter) {
    targets = targets.filter((id) => {
      const entry = nodes.get(id);
      const p = String(entry && entry.platform || '').trim().toLowerCase();
      return p === platformFilter;
    });
  }

  if (limit > 0) {
    targets = targets.slice(0, limit);
  }

  if (targets.length === 0) {
    return { ok: false, error: 'no matching target nodes' };
  }

  if (targets.length > 500) {
    return { ok: false, error: 'target count exceeds max (500)' };
  }

  return { ok: true, targets };
}

function handleAdminTask(body, adminEmail, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const playbook = String(body.playbook || '').trim();
  if (!playbook) return badRequest(res, 'playbook required');
  if (!PLAYBOOKS.has(playbook)) return badRequest(res, 'unsupported playbook');

  const resolved = resolveTaskTargets(body);
  if (!resolved.ok) return badRequest(res, resolved.error);

  const dispatchId = `dispatch_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const args = body.args && typeof body.args === 'object' ? body.args : {};
  const createdAt = new Date().toISOString();
  const tasks = [];
  for (const nodeId of resolved.targets) {
    const task = enqueueTask(nodeId, playbook, args, adminEmail, dispatchId, createdAt);
    tasks.push({ task_id: task.task_id, node_id: task.node_id });
  }

  sendJson(res, 200, {
    ok: true,
    dispatch_id: dispatchId,
    playbook,
    count: tasks.length,
    targets: resolved.targets,
    tasks
  });
}

function handleAdminPatch(body, adminEmail, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const filename = String(body.filename || '').trim();
  const contentB64 = String(body.content_b64 || '').trim();
  if (!filename || !contentB64) return badRequest(res, 'filename and content_b64 required');

  let raw;
  try {
    raw = Buffer.from(contentB64, 'base64');
  } catch {
    return badRequest(res, 'invalid base64');
  }

  const patchId = String(body.patch_id || '').trim() || makePatchId();
  const sha256 = crypto.createHash('sha256').update(raw).digest('hex');

  patches.set(patchId, {
    patch_id: patchId,
    filename,
    content_b64: contentB64,
    sha256,
    uploaded_at: new Date().toISOString(),
    uploaded_by: adminEmail,
    bytes: raw.length
  });

  sendJson(res, 200, {
    ok: true,
    patch_id: patchId,
    filename,
    sha256,
    bytes: raw.length
  });
}

function handleAdminNodeToken(body, adminEmail, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  let token = String(body.token || '').trim();
  if (!token) {
    token = crypto.randomBytes(24).toString('hex');
  }

  const note = String(body.note || 'auto-provisioned').trim();
  setNodeToken(nodeId, token, adminEmail, note);
  sendJson(res, 200, { ok: true, node_id: nodeId, token, note });
}

function handleAdminNodeTokens(res) {
  const tokens = Array.from(nodeTokensByNode.values())
    .map((v) => ({
      node_id: v.node_id,
      created_at: v.created_at,
      created_by: v.created_by,
      note: v.note || '',
      token_masked: `${v.token.slice(0, 8)}...${v.token.slice(-4)}`
    }))
    .sort((a, b) => a.node_id.localeCompare(b.node_id));
  sendJson(res, 200, { ok: true, count: tokens.length, tokens });
}

loadNodeTokens();

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, {
      ok: true,
      name: anchorName,
      time: new Date().toISOString()
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/') {
    sendHtml(res, 200, dashboardHtml(false));
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin') {
    const devToken = String(url.searchParams.get('dev_token') || '').trim();
    if (adminDevToken && devToken && devToken === adminDevToken) {
      sendRedirect(res, '/admin', `defend_admin_token=${encodeURIComponent(adminDevToken)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800`);
      return;
    }
    const auth = adminAuth(req);
    if (!auth.ok) {
      if ((auth.reason || '').includes('domain')) {
        sendHtml(res, 403, '<!doctype html><html><body><h1>403 Forbidden</h1><p>Admin view requires approved email domain/allowlist.</p></body></html>');
        return;
      }
      sendHtml(res, 401, adminLoginHtml());
      return;
    }
    sendHtml(res, 200, dashboardHtml(true));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/admin/request-access') {
    let form;
    try {
      form = await parseFormBody(req);
    } catch (err) {
      badRequest(res, err.message || 'invalid request body');
      return;
    }
    const email = normalizeEmail(form.email || '');
    if (!adminEmailAllowed(email)) {
      sendHtml(res, 403, adminLoginHtml('Email is not allowed for admin access.'));
      return;
    }

    const challenge = issueAdminChallenge(email);
    const expiresAtIso = new Date(challenge.expires_ms).toISOString();
    const dispatch = await dispatchAdminToken(email, challenge.token, expiresAtIso);
    if (dispatch.ok) {
      sendHtml(res, 200, adminLoginHtml(`Access token sent to ${email}. Expires at ${expiresAtIso}.`));
      return;
    }
    if (adminTokenFallbackEnabled) {
      sendHtml(
        res,
        200,
        adminLoginHtml(
          `Dispatch failed (${dispatch.mode || 'unknown'}). Temporary token for ${email}: ${challenge.token} (expires ${expiresAtIso}).`
        )
      );
      return;
    }
    adminChallengesByEmail.delete(email);
    sendHtml(res, 503, adminLoginHtml('Email dispatch failed. Token was not issued. Contact operator now.'));
    return;
  }

  if (req.method === 'POST' && url.pathname === '/admin/verify-access') {
    let form;
    try {
      form = await parseFormBody(req);
    } catch (err) {
      badRequest(res, err.message || 'invalid request body');
      return;
    }
    const email = normalizeEmail(form.email || '');
    const token = String(form.token || '').trim();
    if (!adminEmailAllowed(email)) {
      sendHtml(res, 403, adminLoginHtml('Email is not allowed for admin access.'));
      return;
    }
    if (!verifyAdminChallenge(email, token)) {
      sendHtml(res, 401, adminLoginHtml('Invalid or expired access token.'));
      return;
    }
    const session = createAdminSession(email);
    sendRedirect(
      res,
      '/admin',
      `defend_admin_session=${encodeURIComponent(session.token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${adminSessionMaxSec}`
    );
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin/logout') {
    sendRedirect(
      res,
      '/admin',
      'defend_admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'
    );
    return;
  }

  if (req.method === 'POST' && url.pathname === '/admin/login') {
    let form;
    try {
      form = await parseFormBody(req);
    } catch (err) {
      badRequest(res, err.message || 'invalid request body');
      return;
    }
    const token = String(form.token || '').trim();
    if (!adminDevToken || !token || token !== adminDevToken) {
      sendHtml(res, 401, adminLoginHtml('Invalid admin token.'));
      return;
    }
    sendRedirect(res, '/admin', `defend_admin_token=${encodeURIComponent(adminDevToken)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800`);
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/linux') {
    sendText(res, 200, downloadLinuxScript(), 'defendmesh-connect-linux.sh');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/macos') {
    sendText(res, 200, downloadMacosScript(), 'defendmesh-connect-macos.sh');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/windows') {
    sendText(res, 200, downloadWindowsScript(), 'defendmesh-connect-windows.ps1');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/remove/linux') {
    sendText(res, 200, downloadRemoveLinuxScript(), 'defendmesh-remove-linux.sh');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/remove/macos') {
    sendText(res, 200, downloadRemoveMacosScript(), 'defendmesh-remove-macos.sh');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/download/remove/windows') {
    sendText(res, 200, downloadRemoveWindowsScript(), 'defendmesh-remove-windows.ps1');
    return;
  }

  if (req.method === 'GET' && url.pathname.startsWith('/download/asset/')) {
    const name = decodeURIComponent(url.pathname.replace('/download/asset/', '')).trim();
    if (name === 'linux-remove.sh') {
      sendText(res, 200, downloadRemoveLinuxScript(), name);
      return;
    }
    if (name === 'macos-remove.sh') {
      sendText(res, 200, downloadRemoveMacosScript(), name);
      return;
    }
    if (name === 'windows-remove.ps1') {
      sendText(res, 200, downloadRemoveWindowsScript(), name);
      return;
    }
    const assetMap = downloadAssetMap();
    const localMap = downloadLocalAssetMap();
    const sourceUrl = assetMap[name];
    const localPath = localMap[name];
    if (localPath && fs.existsSync(localPath)) {
      try {
        const content = fs.readFileSync(localPath, 'utf8');
        sendText(res, 200, content, name);
        return;
      } catch (_) {
        // Fall through to remote fetch attempt.
      }
    }
    if (!sourceUrl) {
      notFound(res);
      return;
    }
    try {
      const content = await fetchRemoteText(sourceUrl);
      sendText(res, 200, content, name);
    } catch (_) {
      if (localPath && fs.existsSync(localPath)) {
        try {
          const content = fs.readFileSync(localPath, 'utf8');
          sendText(res, 200, content, name);
          return;
        } catch (_) {
          // Continue to 502.
        }
      }
      sendJson(res, 502, { error: 'download_unavailable' });
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/v1/nodes') {
    const view = renderNodes(asNodeSnapshot(Date.now()), false).map((n) => ({
      ...n,
      node_id: n.display_node_id,
      client_host: n.display_host,
      client_user: n.display_user,
      spoofed: true
    }));
    sendJson(res, 200, view);
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/v1/node/enroll') {
    let body;
    try {
      body = await parseJsonBody(req);
    } catch (err) {
      badRequest(res, err.message || 'invalid request body');
      return;
    }
    handleNodeEnroll(body, res);
    return;
  }

  if (url.pathname.startsWith('/api/v1/node/') || req.method === 'POST' && url.pathname === '/api/v1/heartbeat') {
    if (!nodeAuthOk(req)) {
      unauthorized(res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/heartbeat') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleHeartbeat(body, res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/node/log') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleNodeLog(body, res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/node/tasks') {
      handleNodeTasks(req, res, url);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/node/status') {
      handleNodeStatus(req, res, url);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/node/task-result') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleTaskResult(body, res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/node/triage') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleNodeTriage(body, res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/node/profile') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleNodeProfile(body, res);
      return;
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/v1/node/patch/')) {
      const patchId = decodeURIComponent(url.pathname.replace('/api/v1/node/patch/', '')).trim();
      if (!patchId) return badRequest(res, 'patch id required');
      const patch = patches.get(patchId);
      if (!patch) return notFound(res);
      sendJson(res, 200, patch);
      return;
    }
  }

  if (url.pathname.startsWith('/api/v1/admin/')) {
    const auth = adminAuth(req);
    if (!auth.ok) {
      if ((auth.reason || '').includes('domain')) {
        forbidden(res);
        return;
      }
      unauthorized(res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/admin/nodes') {
      sendJson(res, 200, { ok: true, nodes: asNodeSnapshot(Date.now()) });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/admin/node-tokens') {
      handleAdminNodeTokens(res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/node-token') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleAdminNodeToken(body, auth.email, res);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/admin/logs') {
      const nodeId = String(url.searchParams.get('node_id') || '').trim();
      if (!nodeId) return badRequest(res, 'node_id required');
      sendJson(res, 200, { ok: true, node_id: nodeId, logs: logsByNode.get(nodeId) || [] });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/admin/results') {
      const nodeId = String(url.searchParams.get('node_id') || '').trim();
      if (!nodeId) return badRequest(res, 'node_id required');
      sendJson(res, 200, { ok: true, node_id: nodeId, results: resultsByNode.get(nodeId) || [] });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/v1/admin/profile') {
      const nodeId = String(url.searchParams.get('node_id') || '').trim();
      if (!nodeId) return badRequest(res, 'node_id required');
      sendJson(res, 200, { ok: true, node_id: nodeId, profile: profilesByNode.get(nodeId) || null });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/task') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleAdminTask(body, auth.email, res);
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/v1/admin/patch') {
      let body;
      try {
        body = await parseJsonBody(req);
      } catch (err) {
        badRequest(res, err.message || 'invalid request body');
        return;
      }
      handleAdminPatch(body, auth.email, res);
      return;
    }
  }

  notFound(res);
});

server.listen(port, bind, () => {
  process.stdout.write(`anchor listening on http://${bind}:${port}\n`);
});
