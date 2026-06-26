# Publishing Checklist

Use this checklist for production public-client releases.

## Repository Hygiene

- Confirm `private_saas/`, `.env`, reports, local databases, caches, virtualenvs, and `.codex-audit/` are ignored.
- Run a read-only secret scan before tagging:

  ```bash
  ! git grep -I -n -E '(sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_]{30,}|xox[baprs]-[A-Za-z0-9-]{20,})'
  ```

- Confirm no real tokens, secrets, customer reports, or private gateway files are staged.

## Validation

```bash
python -m pip install -e ".[dev,server]"
python -m pytest
orbit doctor
python -m build
python -m twine check dist/*
```

Wheel smoke test:

```bash
python -m venv /tmp/orbit-wheel-smoke
/tmp/orbit-wheel-smoke/bin/python -m pip install dist/*.whl
/tmp/orbit-wheel-smoke/bin/orbit --version
/tmp/orbit-wheel-smoke/bin/orbit doctor
```

Dashboard smoke test:

```bash
orbit serve --host 127.0.0.1 --port 8765
```

Open `http://127.0.0.1:8765/`, run an authorized local or lab scan, verify exports, and confirm AI fields remain optional.

## Release

- Update version metadata and changelog/release notes.
- Commit the release changes.
- Tag the release, for example `v1.0.0`.
- Push the tag to trigger the release workflow.
- Confirm GitHub release artifacts contain source and wheel distributions.
- Confirm PyPI Trusted Publishing completed successfully.

## Gateway Default

Keep the public default gateway at `https://165.245.244.247.sslip.io/v1/analyze` until branded DNS is live, TLS is valid, and monitoring confirms the branded endpoint is stable.
