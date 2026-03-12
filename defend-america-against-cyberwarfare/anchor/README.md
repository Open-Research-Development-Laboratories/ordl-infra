# DefendMesh Anchor

DefendMesh Anchor is the control-plane for distributed defensive nodes.

- Zero Trust operator access (email-based via Cloudflare Access headers).
- Node heartbeat ingestion.
- Node log ingestion.
- Node profile + triage ingestion.
- Automatic defensive baseline tasking (audit/monitor) with severity-gated auto-remediation.
- Optional AI-assisted defensive triage (OpenAI-compatible API).
- Playbook queue for remote defensive actions.
- Patch bundle upload + node fetch endpoint.

## Run

```bash
cd /development/ordl-infra/defend-america-against-cyberwarfare/anchor
npm start
```

## Environment

Core:
- `ANCHOR_BIND` (default `0.0.0.0`)
- `ANCHOR_PORT` (default `8787`)
- `ANCHOR_NAME` (default `DefendMesh Anchor`)
- `ANCHOR_PUBLIC_URL` (default `https://defend.ordl.org`, shown on dashboard)
- `ANCHOR_NODE_TOKENS_FILE` (default `./node-tokens.json`, persisted per-node tokens)

Node auth (choose one or both):
- `ANCHOR_NODE_TOKEN` (bearer token expected from nodes)
- `ANCHOR_CF_SERVICE_TOKEN_ID` + `ANCHOR_CF_SERVICE_TOKEN_SECRET` (Cloudflare Access service token headers)

Zero Trust operator auth:
- `ANCHOR_ALLOWED_EMAIL_SUFFIXES` (default `.gov`, comma-separated, e.g. `.gov,.mil,ordl.org`)
- `ANCHOR_ALLOWED_EMAILS` (optional explicit allowlist, comma-separated)
- `ANCHOR_ADMIN_DEV_TOKEN` (optional fallback bearer token for non-Access lab/dev only)

Email + alerting:
- `ANCHOR_SMTP_HOST`, `ANCHOR_SMTP_PORT`, `ANCHOR_SMTP_SECURE`, `ANCHOR_SMTP_USER`, `ANCHOR_SMTP_PASS`, `ANCHOR_SMTP_FROM`
- `ANCHOR_SMTP_REPLY_TO`, `ANCHOR_SMTP_HELO`, `ANCHOR_SMTP_TLS_REJECT_UNAUTHORIZED`
- `ANCHOR_THREAT_ALERT_EMAILS` (comma-separated recipients)
- `ANCHOR_THREAT_ALERT_MIN_SEVERITY` (default `high`)
- `ANCHOR_THREAT_ALERT_COOLDOWN_SEC` (default `300`)

Auto defensive playbooks:
- `ANCHOR_AUTO_PLAYBOOKS` (default `true`)
- `ANCHOR_AUTO_AUDIT_SEC` (default `300`)
- `ANCHOR_AUTO_MONITOR_SEC` (default `120`)
- `ANCHOR_AUTO_REMEDIATE_MIN_SEVERITY` (default `high`)
- `ANCHOR_AUTO_REMEDIATE_COOLDOWN_SEC` (default `600`)

AI triage (OpenAI-compatible):
- `ANCHOR_AI_TRIAGE_ENABLED` (default `true`)
- `ANCHOR_AI_BASE_URL` (default `https://api.openai.com/v1`)
- `ANCHOR_AI_MODEL` (required to enable calls)
- `ANCHOR_AI_API_KEY` (optional for local/self-hosted providers, otherwise required)
- `ANCHOR_AI_TIMEOUT_MS` (default `8000`)
- `ANCHOR_AI_MAX_CONTEXT_CHARS` (default `12000`)
- `ANCHOR_AI_MIN_SEVERITY` (default `info`)
- `ANCHOR_AI_FULL_CONTEXT` (default `false`)

## Cloudflare Zero Trust (defend.ordl.org)

Recommended:
1. Put anchor behind Cloudflare Tunnel on `defend.ordl.org`.
2. Create a Cloudflare Access app for `defend.ordl.org`.
3. Require email identity login with allowed domains (`.gov`, `.mil`, your org domain).
4. Restrict node endpoints to service tokens for machine-to-machine auth.

## Endpoints

Public/health:
- `GET /health`
- `GET /` (auto-refresh dashboard)
- `GET /api/v1/nodes`
- `GET /download/linux`
- `GET /download/macos`
- `GET /download/windows`
- `GET /download/remove/linux`
- `GET /download/remove/macos`
- `GET /download/remove/windows`

Node endpoints (node auth required if configured):
- `POST /api/v1/heartbeat`
- `POST /api/v1/node/log`
- `GET /api/v1/node/tasks?node_id=<id>`
- `GET /api/v1/node/status?node_id=<id>`
- `POST /api/v1/node/task-result`
- `POST /api/v1/node/triage`
- `POST /api/v1/node/profile`
- `GET /api/v1/node/patch/<patch_id>`

Admin endpoints (Zero Trust email required):
- `GET /api/v1/admin/nodes`
- `GET /api/v1/admin/node-tokens`
- `POST /api/v1/admin/node-token` (mint/set token for node)
- `GET /api/v1/admin/logs?node_id=<id>`
- `GET /api/v1/admin/results?node_id=<id>`
- `POST /api/v1/admin/task`
- `POST /api/v1/admin/patch`

## Supported Playbooks

- `endpoint_audit`
- `endpoint_remediate`
- `monitor_start`
- `monitor_stop`
- `monitor_oneshot`
- `stage_patch`

Note:
- Arbitrary shell/python remote execution is intentionally disabled.
- Use approved playbooks and signed patch staging only.

## Security Notes

- Keep operator auth on Zero Trust email identity, not static IP allowlists.
- Use service tokens for node auth.
- Keep `ANCHOR_ADMIN_DEV_TOKEN` unset in production.
