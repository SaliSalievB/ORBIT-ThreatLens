<p align="center">
  <img src="orbit/static/logo.png" alt="Threat Lens ORBIT logo" width="260">
</p>

# ORBIT

ORBIT is an authorized reconnaissance and breach-impact reporting tool for security teams. It checks internet-facing assets for common exposure patterns, produces JSON and Markdown reports, and can request AI breach-impact summaries through a hosted Threat Lens gateway.

The public repository is safe to publish as open source: it contains the scanner, local dashboard, report generator, and gateway client. The OpenAI-backed SaaS gateway lives in the local-only `private_saas/` folder, which is explicitly ignored by git because it can hold `OPENAI_API_KEY` and deployment secrets.

Payment and AI limit removal are handled manually for now by contacting [threatlens@outlook.com](mailto:threatlens@outlook.com).

## What ORBIT Does

- DNS resolution and private/internal address leakage checks.
- TLS certificate validation, expiry checks, and protocol posture signals.
- HTTP security header, redirect, cookie, CORS, and version-banner checks.
- Controlled exposure probes for `.env`, `.git/config`, `.DS_Store`, and server-status pages.
- Curated TCP posture checks for risky public services such as databases, SMB, RDP, Redis, Elasticsearch, and VNC.
- Risk scoring, evidence, remediation guidance, JSON output, and Markdown reports.
- Optional AI breach-impact summaries through the hosted gateway.

ORBIT does not exploit findings, brute force credentials, bypass authentication, or run payloads. Use it only against assets you own or are explicitly authorized to assess.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[all]"
```

CLI-only install:

```bash
python -m pip install -e .
```

## CLI Usage

Run a scan:

```bash
orbit scan https://example.com --authorized
```

Print Markdown:

```bash
orbit scan https://example.com --authorized --markdown
```

Use hosted AI analysis:

```bash
export ORBIT_AI_GATEWAY_URL="https://orbit.threatlens.ai/v1/analyze"
export ORBIT_API_TOKEN="your-orbit-token"
orbit scan https://example.com --authorized --ai
```

Start the local dashboard:

```bash
orbit serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`.

## SaaS Split

```text
public ORBIT client -> hosted Threat Lens gateway -> OpenAI Responses API
```

The client sends a redacted report to the gateway. The gateway enforces daily freemium limits, applies simple premium-token bypasses, calls OpenAI with server-side credentials, and returns a defensive breach-impact summary.

Current private gateway defaults:

- model: `gpt-5.5`
- API: OpenAI Responses API
- free daily limit: `5`
- paid/unlimited access: simple premium bearer tokens
- payment contact: `threatlens@outlook.com`

OpenAI’s current [GPT-5.5 guidance](https://developers.openai.com/api/docs/guides/latest-model) recommends `gpt-5.5` as the latest model and the [Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses) for GPT-5 reasoning workloads.

The private SaaS implementation is intentionally outside git:

```text
private_saas/   # gitignored, local-only, contains OpenAI-backed gateway
```

## Documentation

- [Usage](docs/USAGE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [AI gateway and SaaS split](docs/AI_GATEWAY.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Publishing checklist](docs/PUBLISHING.md)

## Development

```bash
python -m pip install -e ".[dev]"
pytest
```

Check optional dependencies and client environment:

```bash
orbit doctor
```

## Publication State

This repository is ready to publish as the open-source ORBIT client and scanner. The private SaaS gateway exists locally under `private_saas/` and is blocked from git by design.
