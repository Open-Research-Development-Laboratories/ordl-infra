'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');

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
const openEnroll = String(process.env.ANCHOR_OPEN_ENROLL || 'true').trim().toLowerCase() !== 'false';
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
    const profile = profilesByNode.get(node.node_id) || {};
    const triage = triageByNode.get(node.node_id) || null;
    const ageSec = Math.max(0, Math.floor((nowMs - node._updatedMs) / 1000));
    out.push({
      node_id: node.node_id,
      platform: node.platform,
      connections_present: node.connections_present,
      current_count: node.current_count,
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
    'windows-connection-monitor.ps1': `${rawBase}/scripts/windows/connection-monitor.ps1`
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
nohup "$MONITOR" "\${MON_ARGS[@]}" > "$OUTPUT_DIR/monitor-stdout.log" 2>&1 &
PID="$!"
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
Start-Process -FilePath 'powershell.exe' -ArgumentList $args -WindowStyle Hidden
Write-Output ('started monitor node=' + $NodeId + ' anchor=' + $AnchorUrl + ' output=' + $OutputDir)
`;
}

function renderNodes(nodes, authorized) {
  return nodes.map((n) => ({
    ...n,
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
  const winMonitor = `${publicUrlBase}/download/asset/windows-connection-monitor.ps1`;
  const linMonitor = `${publicUrlBase}/download/asset/linux-connection-monitor.sh`;
  const deployAll = `${publicUrlBase}/download/asset/deploy-all.sh`;
  const rows = list.length
    ? list
        .map((node) => `<tr>
<td>${escHtml(node.node_id)}</td>
<td>${escHtml(node.display_host)}</td>
<td>${escHtml(node.display_user)}</td>
<td>${escHtml(node.client_os || '-')}</td>
<td>${escHtml(node.platform)}</td>
<td>${node.connections_present ? 'yes' : 'no'}</td>
<td>${node.current_count}</td>
<td>${escHtml(node.trend)}</td>
<td>${node.latency_ms}ms</td>
<td>${escHtml(node.latest_severity || 'none')}</td>
<td>${escHtml(node.updated_at)}</td>
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
<meta http-equiv="refresh" content="5">
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
.downloads-grid .panel2 { border: 1px solid #2a2a2a; padding: 10px; }
.downloads-grid h3 { margin: 0 0 8px 0; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: #fff; }
</style>
</head>
<body>
<div class="wrap">
<div class="panel">
<h1>${escHtml(anchorName)}</h1>
<div class="meta">route=${escHtml(publicUrl)} | auth_view=${authorized ? 'authorized_real' : 'public_spoofed'} | nodes=${list.length} | utc=${new Date(now).toISOString()}</div>
<table>
<thead>
<tr>
<th>node_id</th>
<th>host</th>
<th>user</th>
<th>client_os</th>
<th>platform</th>
<th>connections</th>
<th>current_count</th>
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
<div class="downloads">
<h2 style="margin:14px 0 8px 0;font-size:15px;text-transform:uppercase;letter-spacing:.05em;">Connect Node</h2>
<div class="meta">Download from this anchor or pull direct from GitHub.</div>
<div class="downloads-grid">
<div class="panel2">
<h3>Direct Downloads</h3>
<div><a href="${escHtml(winDl)}">Windows bootstrap (.ps1)</a></div>
<div><a href="${escHtml(linuxDl)}">Linux bootstrap (.sh)</a></div>
<div><a href="${escHtml(macDl)}">macOS bootstrap (.sh)</a></div>
</div>
<div class="panel2">
<h3>One-line Run</h3>
<pre>Linux: curl -fsSL ${escHtml(linuxDl)} | bash
macOS: curl -fsSL ${escHtml(macDl)} | bash
Windows: powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing ${escHtml(winDl)} -OutFile $env:TEMP\\defendmesh.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\defendmesh.ps1"</pre>
</div>
<div class="panel2">
<h3>GitHub Source</h3>
<div><a href="${escHtml(gitBase)}">${escHtml(gitBase)}</a></div>
<pre>git clone ${escHtml(githubRepo)} && cd ordl-infra/defend-america-against-cyberwarfare</pre>
<div><a href="${escHtml(deployAll)}">deploy-all.sh</a></div>
<div><a href="${escHtml(linMonitor)}">linux connection-monitor.sh</a></div>
<div><a href="${escHtml(winMonitor)}">windows connection-monitor.ps1</a></div>
</div>
</div>
</div>
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
  if (!isFiniteNumber(body.current_count)) return badRequest(res, 'current_count must be number');
  if (!updatedAt || Number.isNaN(Date.parse(updatedAt))) return badRequest(res, 'updated_at must be ISO date');

  const entry = {
    node_id: nodeId,
    platform,
    connections_present: normalizeBool(body.connections_present),
    current_count: body.current_count,
    trend: normalizeTrend(body.trend),
    updated_at: updatedAt,
    _updatedMs: Date.parse(updatedAt),
    latency_ms: isFiniteNumber(body.latency_ms)
      ? Math.max(0, Math.floor(body.latency_ms))
      : Math.max(0, Date.now() - Date.parse(updatedAt))
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
    sendJson(res, 200, { ok: true, node_id: nodeId, token: existing.token, existing: true });
    return;
  }

  const token = crypto.randomBytes(24).toString('hex');
  const platform = String(body.platform || 'unknown').trim().toLowerCase().slice(0, 32);
  setNodeToken(nodeId, token, 'self-enroll', `bootstrap:${platform || 'unknown'}`);
  sendJson(res, 200, { ok: true, node_id: nodeId, token, existing: false });
}

function handleNodeTriage(body, res) {
  if (!body || typeof body !== 'object') return badRequest(res, 'body must be JSON object');
  const nodeId = String(body.node_id || '').trim();
  if (!nodeId) return badRequest(res, 'node_id required');

  const severityRaw = String(body.severity || 'info').trim().toLowerCase();
  const severity = ['info', 'low', 'medium', 'high', 'critical'].includes(severityRaw) ? severityRaw : 'info';
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
  sendJson(res, 200, { ok: true, node_id: nodeId, severity });
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
    const auth = adminAuth(req);
    sendHtml(res, 200, dashboardHtml(auth.ok));
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

  if (req.method === 'GET' && url.pathname.startsWith('/download/asset/')) {
    const name = decodeURIComponent(url.pathname.replace('/download/asset/', '')).trim();
    const assetMap = downloadAssetMap();
    const sourceUrl = assetMap[name];
    if (!sourceUrl) {
      notFound(res);
      return;
    }
    try {
      const content = await fetchRemoteText(sourceUrl);
      sendText(res, 200, content, name);
    } catch (_) {
      sendJson(res, 502, { error: 'download_unavailable' });
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/v1/nodes') {
    const auth = adminAuth(req);
    const view = renderNodes(asNodeSnapshot(Date.now()), auth.ok).map((n) => ({
      ...n,
      client_host: n.display_host,
      client_user: n.display_user,
      spoofed: !auth.ok
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
