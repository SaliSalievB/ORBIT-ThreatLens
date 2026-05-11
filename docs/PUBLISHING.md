# Publishing Checklist

Use this checklist before making ORBIT public.

## Repository

- Keep `private_saas/` ignored.
- Confirm `.env`, reports, local databases, caches, and virtualenvs are ignored.
- Run `pytest`.
- Run `orbit doctor`.
- Confirm README links and logo render.
- Confirm no real tokens, secrets, or customer reports are present.

## SaaS Gateway

- Deploy `private_saas/` to a private server or platform.
- Set `OPENAI_API_KEY` only on the private server.
- Put the gateway behind HTTPS.
- Set `ORBIT_FREE_DAILY_LIMIT`.
- Set `ORBIT_PREMIUM_TOKENS` for paid users.
- Configure logs and abuse monitoring.
- Back up the usage database or move usage tracking to managed storage.

## Release

- Tag a version.
- Publish source and wheel artifacts if distributing through PyPI.
- Add screenshots after the hosted gateway URL is final.
- Keep payment instructions simple: contact `threatlens@outlook.com`.
