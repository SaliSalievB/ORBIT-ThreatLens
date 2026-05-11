# Contributing

ORBIT accepts contributions that make authorized security assessment clearer, safer, and more useful.

## Development Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,server]"
pytest
```

## Scanner Contributions

Scanner modules should:

- require no credentials unless the user explicitly configures them,
- avoid exploitation and destructive requests,
- produce evidence without storing secrets or large response bodies,
- return actionable remediation guidance,
- include focused tests.

## SaaS Contributions

Do not move OpenAI credentials into the CLI, dashboard, browser code, or publishable package. AI provider secrets belong only in the ignored `private_saas/` gateway.
