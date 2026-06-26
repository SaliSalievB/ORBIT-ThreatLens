# ORBIT Usage

## Basic Scan

```bash
orbit scan https://example.com --authorized
```

ORBIT writes two files to `reports/`:

- `*.json`: machine-readable scan report.
- `*.md`: human-readable remediation report.

Use `--json` or `--markdown` to also print the report to stdout.

## Scan Depth And Timeout

Standard depth checks a curated set of common external services and web exposure paths:

```bash
orbit scan https://example.com --authorized --depth standard
```

Aggressive depth adds a small number of extra common service ports:

```bash
orbit scan https://example.com --authorized --depth aggressive
```

The default network timeout is `4.0` seconds:

```bash
orbit scan https://example.com --authorized --timeout 4.0
```

Aggressive depth is still non-exploitative. It only attempts TCP connections to selected ports.

## AI Analysis

Configure the optional ORBIT AI gateway URL and token:

```bash
export ORBIT_AI_GATEWAY_URL="https://165.245.244.247.sslip.io/v1/analyze"
export ORBIT_API_TOKEN="your-token"
orbit scan https://example.com --authorized --ai
```

The client sends a redacted report to the gateway. It does not send or store an OpenAI API key. Provider credentials and model configuration are gateway-owned server settings.

## Dashboard

Install server dependencies:

```bash
python -m pip install "orbit-security[server]"
```

Run:

```bash
orbit serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`.

The dashboard requires authorization confirmation before scanning. AI gateway fields stay hidden unless you request an AI breach-impact brief.

The dashboard scan API accepts loopback clients only by default. If you run `orbit serve --host 0.0.0.0`, ORBIT will warn and still reject non-loopback scan requests unless `ORBIT_DASHBOARD_ALLOW_REMOTE=1` is set. Scan requests with a mismatched browser `Origin` header are rejected.

Custom AI gateway URLs must use HTTPS. For local gateway development only, HTTP loopback URLs are allowed when `ORBIT_ALLOW_INSECURE_AI_GATEWAY=1` is set.

## Authorization Gate

ORBIT requires explicit authorization confirmation:

```bash
orbit scan https://asset.example --authorized
```

For controlled internal automation, set:

```bash
export ORBIT_ASSUME_AUTHORIZED=1
```

Do not use this on third-party assets without written authorization.
