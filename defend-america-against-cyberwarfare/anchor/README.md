# DefendMesh Anchor

DefendMesh Anchor is the control-plane for distributed defensive nodes.

- Zero Trust operator access (email-based via Cloudflare Access headers).
- Node heartbeat ingestion.
- Node log ingestion.
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

Node auth (choose one or both):
- `ANCHOR_NODE_TOKEN` (bearer token expected from nodes)
- `ANCHOR_CF_SERVICE_TOKEN_ID` + `ANCHOR_CF_SERVICE_TOKEN_SECRET` (Cloudflare Access service token headers)

Zero Trust operator auth:
- `ANCHOR_ALLOWED_EMAIL_SUFFIXES` (default `.gov`, comma-separated, e.g. `.gov,.mil,ordl.org`)
- `ANCHOR_ALLOWED_EMAILS` (optional explicit allowlist, comma-separated)
- `ANCHOR_ADMIN_DEV_TOKEN` (optional fallback bearer token for non-Access lab/dev only)

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

Node endpoints (node auth required if configured):
- `POST /api/v1/heartbeat`
- `POST /api/v1/node/log`
- `GET /api/v1/node/tasks?node_id=<id>`
- `POST /api/v1/node/task-result`
- `GET /api/v1/node/patch/<patch_id>`

Admin endpoints (Zero Trust email required):
- `GET /api/v1/admin/nodes`
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

## Security Notes

- Keep operator auth on Zero Trust email identity, not static IP allowlists.
- Use service tokens for node auth.
- Keep `ANCHOR_ADMIN_DEV_TOKEN` unset in production.
