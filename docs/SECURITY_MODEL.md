# Security Model

## Intended Use

ORBIT is for authorized exposure assessment, asset review, and breach-impact reporting. It is not an exploitation framework.

Allowed use:

- assets you own,
- assets covered by a signed assessment scope,
- internal lab systems,
- bug bounty targets where this traffic is allowed by program rules.

Do not use ORBIT to scan third-party assets without authorization.

## Scanner Safety

ORBIT checks are intentionally constrained:

- no credential guessing,
- no exploit payloads,
- no authentication bypass attempts,
- no destructive requests,
- no high-volume crawling,
- no vulnerability exploitation.

The HTTP exposure probes request a small fixed list of paths and only store short metadata/evidence, not raw secret files.

## AI Safety Boundary

The AI prompt asks for defensive breach-impact analysis and remediation planning. It explicitly avoids exploitation steps, payloads, credential abuse guidance, or compromise instructions.

The OpenAI key belongs in the private SaaS gateway only. Do not place `OPENAI_API_KEY` in:

- browser JavaScript,
- mobile or desktop client bundles,
- distributed CLI defaults,
- public CI logs,
- example config with real values.

## Private SaaS Boundary

The OpenAI-backed gateway lives under `private_saas/`, which is ignored by git. Keep server secrets, premium tokens, deployment files, and local usage databases there.

## Freemium Abuse Controls

The private gateway enforces a daily request count using SQLite. It supports:

- IP-based anonymous limits,
- bearer-token limits,
- premium bearer tokens that bypass limits,
- a clear upgrade contact: [threatlens@outlook.com](mailto:threatlens@outlook.com).

Production deployments should add TLS termination, persistent storage backups, structured logs, abuse monitoring, and a proper billing/token management system.

## Reporting Security Issues

Report security issues privately to [threatlens@outlook.com](mailto:threatlens@outlook.com).
