# FileShare (variant: one-off transfer)
Run: `pip install -r requirements.txt && python app.py` → http://localhost:5000  (Docker: `docker build -t fs . && docker run -p 5000:5000 -v fsdata:/data fs`)
Test: register → login → upload → Share (1h/24h/7d) → open link in private window → Download → Revoke/Delete → reopen link (clear message).

1. **Scope**: owners (login) upload/share/revoke/delete; recipients need no account, download only. Out of scope: previews, folders, email, virus scanning.
2. **Rules**: 10 MB/file, 50 MB/user, allowlist (pdf png jpg gif txt csv zip docx mp3 mp4), expiry 1h/24h/7d.
3. **Flow**: Flask + SQLite. Upload → validate → save under random name → share creates token → `/s/<token>` page → POST download.
4. **Storage**: files + SQLite in `DATA_DIR` (mount a volume); survive restarts.
5. **Links**: 256-bit `secrets.token_urlsafe(32)`; every request checks token, revoked, expiry server-side.
6. **E2E**: all flows implemented, 404/410 messages for invalid/revoked/expired/deleted.
7. **Malicious files**: extension allowlist + magic-byte check, random stored names (no path traversal), always served as `attachment` + `octet-stream`, `nosniff`, strict CSP; never executed or served inline.
8. **Server limits**: `MAX_CONTENT_LENGTH`, post-save size and quota check, expiry checked on each request.
9. **Abuse**: owner-scoped queries (404 otherwise), CSRF tokens, hashed passwords, HttpOnly/SameSite cookies, rate limits on login and downloads.
10. **Deploy**: Dockerfile included (Render/Railway/Fly: set `SECRET_KEY`, mount volume at `/data`).
