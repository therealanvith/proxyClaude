# KeyProxy

A secure multi-key OpenRouter proxy with smart model routing, key rotation, user authentication, and an admin dashboard.

## Features

- **Multi-Key Rotation**: Automatically rotates through `API_KEY_*` environment variables when upstream keys fail or hit rate limits.
- **Smart / Worker Routing**: Routes requests to a smart model (`SMART_MODEL`) or worker model (`WORKER_MODEL`) based on prompt content, message history, and image presence.
- **User Authentication**: Bearer token-based auth (`PROXY_USER_*`) with admin-managed users via `users.json`.
- **Admin Dashboard**: Web UI for managing users (requires `ADMIN_EMAILS` + Google OAuth config).
- **Health Check**: `/healthz` endpoint for monitoring.
- **Dark / Light Theme**: Toggle on admin and user pages.

## Setup

1. Copy `.env.example` to `.env` and fill in your values:
   - `API_KEY_1` — your OpenRouter API key
   - `PROXY_USER_*` — bearer tokens for proxy users
   - `SMART_MODEL`, `WORKER_MODEL`, `HELPER_MODEL`
   - Optional OAuth settings (`OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_REDIRECT_URI`, `ADMIN_EMAILS`)
2. Run: `python proxy.py` (or use `proxy.bat` on Windows)

## Deploy

Configured for Render (`render.yaml`) with Python environment and environment variables.
