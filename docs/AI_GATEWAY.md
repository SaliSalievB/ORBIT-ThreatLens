# AI Gateway And SaaS Split

ORBIT uses AI through a hosted gateway so the public client never receives OpenAI credentials.

```text
ORBIT client -> Threat Lens gateway -> OpenAI Responses API
```

## Public Repository

The publishable repository contains:

- scanner modules,
- CLI,
- local dashboard,
- report generation,
- redaction logic,
- gateway client.

It does not contain the OpenAI-backed server module.

## Private SaaS Folder

The private implementation lives locally in:

```text
private_saas/
```

That folder is ignored by git:

```gitignore
private_saas/
```

Keep it ignored. It can contain `OPENAI_API_KEY`, gateway deployment configuration, usage databases, and premium-token lists.

## Private Gateway Defaults

| Setting | Default |
| --- | --- |
| OpenAI model | `gpt-5.5` |
| OpenAI API | Responses API |
| Free daily limit | `5` |
| Premium access | comma-separated bearer tokens |
| Upgrade contact | `threatlens@outlook.com` |

OpenAI’s current [GPT-5.5 guidance](https://developers.openai.com/api/docs/guides/latest-model) identifies `gpt-5.5` as the latest model and recommends the [Responses API](https://developers.openai.com/api/docs/guides/migrate-to-responses) for GPT-5 reasoning workloads.

## Client Configuration

```bash
export ORBIT_AI_GATEWAY_URL="https://orbit.threatlens.ai/v1/analyze"
export ORBIT_API_TOKEN="user-token"
orbit scan https://example.com --authorized --ai
```

The token is an ORBIT gateway token, not an OpenAI key.

## Private Gateway Configuration

The ignored `private_saas/.env.example` contains the private server variables:

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | OpenAI credential used only by the private gateway |
| `ORBIT_AI_MODEL` | OpenAI model, default `gpt-5.5` |
| `ORBIT_AI_REASONING_EFFORT` | Responses API reasoning effort |
| `ORBIT_AI_VERBOSITY` | Responses API output verbosity |
| `ORBIT_FREE_DAILY_LIMIT` | Daily request limit for free identities |
| `ORBIT_PREMIUM_TOKENS` | Comma-separated premium tokens that bypass limits |
| `ORBIT_GATEWAY_DB` | SQLite usage database path |
| `ORBIT_CONTACT_EMAIL` | Contact shown in limit responses |

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

## Data Handling

The public client redacts likely secrets before sending reports. The private gateway redacts again before calling OpenAI. Raw response bodies and credential-bearing fields are not needed for breach-impact summaries.
