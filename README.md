<p align="center">
  <img src="orbit/static/logo.png" alt="Threat Lens ORBIT logo" width="260">
</p>

# ORBIT

ORBIT is a production-ready public client for authorized exposure assessment. It checks internet-facing assets for common posture signals, produces JSON and Markdown reports, and can optionally request a defensive breach-impact brief through the hosted Threat Lens gateway.

The public repository contains the scanner, CLI, local dashboard, report generator, redaction logic, gateway client, logo, docs, and tests. It does not contain the OpenAI-backed gateway server, provider credentials, premium tokens, or private deployment state.

## What ORBIT Checks

- DNS resolution and non-public address leakage.
- TLS certificate verification, expiry, and protocol posture.
- HTTP security headers, redirects, cookies, CORS, and version-banner signals.
- Controlled exposure probes for `.env`, `.git/config`, `.DS_Store`, and server-status pages.
- Selected TCP service posture for commonly risky public services.
- Risk scoring, prioritized findings, evidence, remediation guidance, JSON, and Markdown.

ORBIT does not exploit findings, brute force credentials, bypass authentication, crawl at high volume, or run payloads. Use it only against assets you own or are explicitly authorized to assess.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install orbit-security
```

For local development from this repository:

```bash
python -m pip install -e ".[dev,server]"
```

## CLI Usage

Run an authorized scan:

```bash
orbit scan https://example.com --authorized
```

Print Markdown:

```bash
orbit scan https://example.com --authorized --markdown
```

Use the optional AI breach-impact brief:

```bash
export ORBIT_AI_GATEWAY_URL="https://165.245.244.247.sslip.io/v1/analyze"
export ORBIT_API_TOKEN="your-orbit-token"
orbit scan https://example.com --authorized --ai
```

The token is an ORBIT gateway token, not an OpenAI API key. OpenAI credentials remain server-side in the private gateway.

## Local Dashboard

Install dashboard dependencies:

```bash
python -m pip install "orbit-security[server]"
```

Start the dashboard:

```bash
orbit serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`.

The dashboard uses the same scanner and `/api/scan` report contract as the CLI. AI fields are optional and disabled unless you request an AI brief.

The scan API is local-only by default. If you bind the dashboard to a non-loopback interface, ORBIT prints a warning and rejects scan requests from non-loopback clients unless `ORBIT_DASHBOARD_ALLOW_REMOTE=1` is set. Browser-origin checks are also enforced on scan requests.

## AI Gateway Boundary

```text
public ORBIT client -> hosted Threat Lens gateway -> AI provider
```

The public client redacts reports before sending them to the gateway. The gateway owns provider credentials, model selection, daily limits, premium-token checks, usage storage, and fallback behavior. The current public default remains:

```text
https://165.245.244.247.sslip.io/v1/analyze
```

Custom AI gateway URLs must use HTTPS. HTTP is accepted only for loopback development gateways when `ORBIT_ALLOW_INSECURE_AI_GATEWAY=1` is set.

Do not put OpenAI keys, premium tokens, gateway databases, or private backend code in this public repository. Keep private gateway implementation and deployment material outside the repo or inside ignored local-only paths such as `private_saas/`.

## Development

```bash
python -m pip install -e ".[dev,server]"
python -m pytest
orbit doctor
python -m build
python -m twine check dist/*
```

## Documentation

- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [AI gateway and public/private split](docs/AI_GATEWAY.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Publishing checklist](docs/PUBLISHING.md)

## Security

Report vulnerabilities privately to [threatlens@outlook.com](mailto:threatlens@outlook.com). Do not include real secrets, customer data, or unauthorized scan output in public issues.
