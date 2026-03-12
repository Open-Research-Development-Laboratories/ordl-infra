'use strict';

const crypto = require('node:crypto');
const http = require('node:http');

const bind = process.env.ANCHOR_BIND || '0.0.0.0';
const parsedPort = Number(process.env.ANCHOR_PORT || 8787);
const port = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort < 65536 ? parsedPort : 8787;
const anchorName = process.env.ANCHOR_NAME || 'DefendMesh Anchor';
const publicUrl = process.env.ANCHOR_PUBLIC_URL || 'https://defend.ordl.org';

const nodeBearerToken = process.env.ANCHOR_NODE_TOKEN || '';
const cfServiceId = process.env.ANCHOR_CF_SERVICE_TOKEN_ID || '';
const cfServiceSecret = process.env.ANCHOR_CF_SERVICE_TOKEN_SECRET || '';

const adminDevToken = process.env.ANCHOR_ADMIN_DEV_TOKEN || '';
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

const PLAYBOOKS = new Set([
  'endpoint_audit',
  'endpoint_remediate',
  'monitor_start',
  'monitor_stop',
  'monitor_oneshot',
  'stage_patch'
]);

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

function nodeAuthOk(req) {
  const auth = req.headers.authorization || '';
  const bearerOk = nodeBearerToken ? auth === `Bearer ${nodeBearerToken}` : true;

  const serviceConfigured = !!(cfServiceId && cfServiceSecret);
  const serviceOk = serviceConfigured
    ? req.headers['cf-access-client-id'] === cfServiceId && req.headers['cf-access-client-secret'] === cfServiceSecret
    : false;

  if (nodeBearerToken || serviceConfigured) {
    return bearerOk || serviceOk;
  }
  return true;
}

function adminAuth(req) {
  const auth = req.headers.authorization || '';
  if (adminDevToken && auth === `Bearer ${adminDevToken}`) {
    return { ok: true, email: 'dev-token' };
  }

  const emailRaw = req.headers['cf-access-authenticated-user-email'];
  const email = String(emailRaw || '').trim().toLowerCase();
  if (!email) {
    return { ok: false, reason: 'missing cf-access email header' };
  }

  if (allowedEmails.includes(email)) {
    return { ok: true, email };
  }

  const suffixMatch = allowedSuffixes.some((s) => email.endsWith(s));
  if (!suffixMatch) {
    return { ok: false, reason: 'email domain not allowed' };
  }
  return { ok: true, email };
}

function asNodeSnapshot(nowMs) {
  const out = [];
  for (const node of nodes.values()) {
    const ageSec = Math.max(0, Math.floor((nowMs - node._updatedMs) / 1000));
    out.push({
      node_id: node.node_id,
      platform: node.platform,
      connections_present: node.connections_present,
      current_count: node.current_count,
      trend: node.trend,
      updated_at: node.updated_at,
      age_sec: ageSec,
      queued_tasks: getQueue(node.node_id).length
    });
  }
  out.sort((a, b) => a.node_id.localeCompare(b.node_id));
  return out;
}

function dashboardHtml() {
  const now = Date.now();
  const list = asNodeSnapshot(now);
  const rows = list.length
    ? list
        .map((node) => `<tr>
<td>${escHtml(node.node_id)}</td>
<td>${escHtml(node.platform)}</td>
<td>${node.connections_present ? 'yes' : 'no'}</td>
<td>${node.current_count}</td>
<td>${escHtml(node.trend)}</td>
<td>${escHtml(node.updated_at)}</td>
<td>${node.age_sec}s</td>
<td>${node.queued_tasks}</td>
</tr>`)
        .join('')
    : '<tr><td colspan="8">No nodes reported yet.</td></tr>';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escHtml(anchorName)}</title>
<meta http-equiv="refresh" content="5">
<style>
:root { color-scheme: light dark; }
body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; margin: 24px; }
h1 { margin: 0 0 8px 0; }
small { color: #666; }
table { border-collapse: collapse; width: 100%; margin-top: 16px; }
th, td { border: 1px solid #8885; padding: 8px; text-align: left; font-size: 14px; }
th { background: #8882; }
code { background: #8882; padding: 2px 4px; border-radius: 4px; }
</style>
</head>
<body>
<h1>${escHtml(anchorName)}</h1>
<small>Auto-refresh 5s. Nodes: ${list.length}. UTC: ${new Date(now).toISOString()}</small>
<p>Connection Route: <a href="${escHtml(publicUrl)}">${escHtml(publicUrl)}</a></p>
<p>Backend/Admin Access: approved identity email required (example domains: ${escHtml(allowedSuffixes.join(', '))})</p>
<table>
<thead>
<tr>
<th>node_id</th>
<th>platform</th>
<th>connections</th>
<th>current_count</th>
<th>trend</th>
<th>updated_at</th>
<th>age</th>
<th>queued_tasks</th>
</tr>
</thead>
<tbody>${rows}</tbody>
</table>
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
  if (!isFiniteNumber(body.current_count)) return badRequest(res, 'current_count must be number');
  if (!updatedAt || Number.isNaN(Date.parse(updatedAt))) return badRequest(res, 'updated_at must be ISO date');

  const entry = {
    node_id: nodeId,
    platform,
    connections_present: normalizeBool(body.connections_present),
    current_count: body.current_count,
    trend: normalizeTrend(body.trend),
    updated_at: updatedAt,
    _updatedMs: Date.parse(updatedAt)
  };
  nodes.set(nodeId, entry);
  sendJson(res, 200, { ok: true, node_id: nodeId });
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
  sendJson(res, 200, { ok: true });
}

function handleAdminTask(body, adminEmail, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  const playbook = String(body.playbook || '').trim();
  if (!nodeId || !playbook) return badRequest(res, 'node_id and playbook required');
  if (!PLAYBOOKS.has(playbook)) return badRequest(res, 'unsupported playbook');

  const task = {
    task_id: makeTaskId(),
    node_id: nodeId,
    playbook,
    args: body.args && typeof body.args === 'object' ? body.args : {},
    created_at: new Date().toISOString(),
    created_by: adminEmail
  };

  getQueue(nodeId).push(task);
  sendJson(res, 200, { ok: true, task });
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
    sendHtml(res, 200, dashboardHtml());
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/v1/nodes') {
    sendJson(res, 200, asNodeSnapshot(Date.now()));
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
