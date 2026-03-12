# Security Policy

## Scope

This repository is intended for defensive security monitoring and containment only.

## Prohibited Use

The following uses are not allowed:

- Offensive cyber operations.
- Retaliation or "hack back" activity.
- Unauthorized access, disruption, or destruction of systems or data.
- Deployment on systems without explicit authorization.
- Arbitrary remote shell/python command execution outside approved defensive playbooks.

## Safe Deployment Guidance

- Default to audit mode first.
- Validate IOC quality before remediation.
- Restrict control-file and token access to administrators.
- Keep secrets out of source control.
- Review outputs before sharing externally.
- If enabling AI triage, minimize sensitive payloads and keep `ANCHOR_AI_FULL_CONTEXT=false` unless explicitly required by policy.

## Reporting Vulnerabilities

If you find a security issue in this project:

1. Do not publish exploit details publicly before remediation.
2. Open a private report through your organization's internal security channel.
3. Include reproducible steps, affected files, and impact.
4. Coordinate disclosure timing with maintainers.

## Legal and Policy

Users are responsible for complying with applicable laws, regulations, and platform policies.
