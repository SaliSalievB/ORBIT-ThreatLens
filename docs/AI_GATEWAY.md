# AI Gateway And Public/Private Split

ORBIT uses AI only through a hosted gateway. The public client never receives provider credentials.

```text
ORBIT client -> Threat Lens gateway -> AI provider
```

## Public Client Responsibilities

The public repository contains:

- scanner modules,
- CLI and local dashboard,
- JSON and Markdown report generation,
- client-side report redaction,
- gateway client code.

The public client may send a redacted report to the gateway when the user enables AI. It must not contain OpenAI keys, premium tokens, private deployment files, or usage databases.

## Private Gateway Responsibilities

The private gateway owns:

- provider credential storage,
- provider/model configuration,
- freemium or premium access decisions,
- usage counting and persistence,
- gateway-side report redaction,
- defensive breach-impact summary generation,
- deterministic fallback summaries when the provider is unavailable.

Keep private gateway code and deployment state outside the public package or in ignored local-only paths such as `private_saas/`.

## Client Configuration

```bash
export ORBIT_AI_GATEWAY_URL="https://165.245.244.247.sslip.io/v1/analyze"
export ORBIT_API_TOKEN="user-token"
orbit scan https://example.com --authorized --ai
```

`ORBIT_API_TOKEN` is an ORBIT gateway token. It is not an OpenAI API key.

The public client accepts HTTPS gateway URLs by default. It rejects missing hosts, unsupported schemes, embedded username/password values, and public HTTP gateway URLs before opening a network connection. HTTP is available only for loopback development gateways when `ORBIT_ALLOW_INSECURE_AI_GATEWAY=1` is set.

The current hosted gateway is:

```text
https://165.245.244.247.sslip.io
```

Keep that public default until branded DNS is live, TLS is verified, and monitoring confirms the branded endpoint is stable.

## API Contract

Health:

```http
GET /health
```

Usage:

```http
GET /v1/usage
Authorization: Bearer optional-token
```

Analyze:

```http
POST /v1/analyze
Authorization: Bearer optional-token
Content-Type: application/json

{"report": {"target": "...", "findings": []}}
```

The gateway returns a defensive breach-impact summary and optional usage metadata. It must not return exploit steps, payloads, credential abuse guidance, or bypass instructions.

## Data Handling

The public client redacts likely secrets before sending reports. The private gateway should redact again before calling the provider. Raw response bodies and credential-bearing fields are not needed for breach-impact summaries.
