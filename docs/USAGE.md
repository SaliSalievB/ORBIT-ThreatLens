# ORBIT Usage

## Basic Scan

```bash
orbit scan https://example.com --authorized
```

ORBIT writes two files to `reports/`:

- `*.json`: machine-readable scan report.
- `*.md`: human-readable remediation report.

Use `--json` or `--markdown` to also print the report to stdout.

## Scan Depth

Standard depth checks a curated set of common external services and web exposure paths:

```bash
orbit scan https://example.com --authorized --depth standard
```

Aggressive depth adds a small number of extra common service ports:

```bash
orbit scan https://example.com --authorized --depth aggressive
```

Aggressive depth is still non-exploitative. It only attempts TCP connections to selected ports.

## AI Analysis

Configure the ORBIT AI gateway URL and token:

```bash
export ORBIT_AI_GATEWAY_URL="https://your-gateway.example/v1/analyze"
export ORBIT_API_TOKEN="your-token"
orbit scan https://example.com --authorized --ai
```

The client sends a redacted report to the gateway. It does not send or store an OpenAI API key.

The OpenAI-backed server is not part of the public package. It lives in the local-only `private_saas/` folder and is ignored by git.

## Dashboard

Install server dependencies:

```bash
python -m pip install -e ".[server]"
```

Run:

```bash
orbit serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765`.

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
