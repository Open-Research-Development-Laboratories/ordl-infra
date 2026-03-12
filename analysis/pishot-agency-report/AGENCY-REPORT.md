# Preliminary Cybersecurity Vulnerability Report

Date: March 12, 2026

## Subject

Publicly accessible source code appears to implement unauthenticated remote control and file retrieval functions for networked Raspberry Pi camera devices.

## Intended Recipients

- CISA / DHS
- FBI Cyber / CyWatch
- NSA Cybersecurity

## Reporting Posture

This is a **preliminary vulnerability disclosure report**, not a confirmed intrusion report.

Based on the reviewed evidence, the issue is:

- A publicly available codebase with insecure-by-default remote control behavior
- Potentially dangerous if deployed on reachable networks
- Not, on current evidence, proof of active malware, threat actor operations, or a nation-state campaign

## Reporting Entity

- Reporter name: `[fill in]`
- Organization: `[fill in]`
- Email: `[fill in]`
- Phone: `[fill in]`
- Time zone: America/New_York

## Affected Public Repository

- Repository: `https://github.com/revalo/pishot`
- Commit reviewed: `ec10a72e20b8e573bab0712164e60552690d6d47`
- Commit date: May 14, 2019
- Project description: Raspberry Pi high-speed strobe camera system with remote control over a local network

## Executive Summary

The reviewed repository contains a Flask-based slave server that listens on all network interfaces and exposes remote-control endpoints for reboot, image capture, shutter open/close, and file download without request authentication. The project also uses a shared `secret`, but the reviewed code shows that the value is used to derive a Dweepy discovery-channel name rather than to authenticate requests to the exposed HTTP endpoints.

If deployed on a reachable network, the implementation could allow unauthorized parties with network access to:

- Reboot devices
- Trigger captures
- Open or close shutters
- Download generated recording files

At this time, I have **not** identified evidence of:

- active exploitation in the wild,
- command-and-control infrastructure,
- threat-actor attribution,
- malware payload delivery, or
- victim telemetry.

## Technical Findings

### 1. Unauthenticated control endpoints are exposed

The Flask slave server exposes the following routes without any visible authentication or authorization checks:

- `/ping`
- `/reboot`
- `/capture`
- `/open`
- `/close`
- `/download`

Evidence:

- `/tmp/pishot-ec10/server.py:94`
- `/tmp/pishot-ec10/server.py:98`
- `/tmp/pishot-ec10/server.py:103`
- `/tmp/pishot-ec10/server.py:113`
- `/tmp/pishot-ec10/server.py:120`
- `/tmp/pishot-ec10/server.py:127`

### 2. The server binds to all interfaces

The server starts with:

- `app.run(host="0.0.0.0", port=5000)`

Evidence:

- `/tmp/pishot-ec10/server.py:160`

### 3. A reboot action directly invokes a system reboot

The `/reboot` route calls:

- `os.system('reboot now')`

Evidence:

- `/tmp/pishot-ec10/server.py:98-101`

### 4. The shared secret is not used as endpoint authentication

The helper function:

- hashes the provided `secret`,
- uses it to derive a Dweepy “thing” name,
- but the exposed Flask routes themselves do not verify a token, signature, session, or credential on incoming requests.

Evidence:

- `/tmp/pishot-ec10/utils.py:16-23`
- `/tmp/pishot-ec10/server.py:63-91`
- `/tmp/pishot-ec10/master.py:27-63`

### 5. Device control traffic uses plain HTTP

The master controller talks to slave devices over unauthenticated HTTP:

- `http://<ip>:5000`

Evidence:

- `/tmp/pishot-ec10/master.py:24-25`
- `/tmp/pishot-ec10/master.py:126-203`
- `/tmp/pishot-ec10/master.py:208-250`

### 6. External identifier generation dependency

The slave server requests a UUID from an external site and stores it locally:

- `https://www.uuidgenerator.net/api/version4`

Evidence:

- `/tmp/pishot-ec10/server.py:53-59`

## Risk Assessment

### Likely impact if deployed insecurely

- Unauthorized remote reboot of edge devices
- Unauthorized triggering or interruption of capture operations
- Unauthorized retrieval of generated media files
- Exposure of a remotely controllable device fleet if the service is reachable from untrusted networks

### Constraints and caveats

- The repository README describes the intended use as a Raspberry Pi camera project on a local network or direct GPIO chain, not a production enterprise service.
- The available evidence does not establish that any device is currently exposed to the public internet.
- The available evidence does not establish malicious intent by the repository author.

## Recommended Actions

### For agencies

- Treat this as a **secure-by-default / insecure deployment risk disclosure**, not a confirmed nation-state or criminal incident.
- If appropriate, notify the maintainer or coordinate responsible disclosure.
- If related deployments are found in critical infrastructure or public-facing networks, assess internet exposure, unauthorized access, and downstream operational impact.

### For maintainers or deployers

- Add request authentication to all control endpoints.
- Bind by default to localhost or a private management interface.
- Require TLS or an authenticated reverse proxy for any remote access.
- Remove or tightly restrict the reboot endpoint.
- Replace unauthenticated device discovery/control with authenticated enrollment.
- Avoid external UUID generation for device identity.

## Why This May Merit Federal Awareness

While this repository alone is not evidence of a federal cyber incident, it does present a pattern that can become operationally significant if:

- copied into sensitive environments,
- deployed on public or semi-public networks,
- used in educational, lab, municipal, healthcare, or industrial settings without compensating controls.

The concern is the combination of:

- public code,
- unauthenticated remote control,
- direct system action,
- and low-friction replication onto inexpensive hardware.

## Evidence Appendix

Primary repository context:

- `/tmp/pishot-ec10/README.md:81-102`
- `/tmp/pishot-ec10/README.md:83-100`

Primary control-surface evidence:

- `/tmp/pishot-ec10/server.py:94-129`
- `/tmp/pishot-ec10/server.py:160`
- `/tmp/pishot-ec10/master.py:24-25`
- `/tmp/pishot-ec10/master.py:126-250`
- `/tmp/pishot-ec10/utils.py:16-23`

## Current Official Reporting Channels

As checked on March 12, 2026:

- CISA / DHS:
  - Web: `https://www.cisa.gov/report`
  - Email: `Contact@cisa.dhs.gov`
  - Phone: `1-844-729-2472`
- FBI:
  - IC3: `https://www.ic3.gov`
  - CyWatch email: `CyWatch@fbi.gov`
  - CyWatch phone: `1-855-292-3937`
- NSA:
  - Cybersecurity contact form: `https://www.nsa.gov/Cybersecurity/Contact-Us/`
  - General cybersecurity inquiries: `Cybersecurity_Requests@nsa.gov`

## Source Notes

Official reporting-channel references checked on March 12, 2026:

- CISA reporting guidance and contact pages
- FBI incident-reporting references to IC3 and CyWatch
- NSA Cybersecurity Contact Us page
