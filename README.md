# PM Chat

A Persian-first FastAPI chat starter with a dark green responsive interface.

## Features in this starter
- Username registration/login, Argon2 password hashing, JWT sessions, and rate limits.
- Google OAuth sign-in (requires Google credentials; setup below).
- Public text chat, user search, private text chat.
- 24-hour stories with text, image, or video.
- Image/video uploads (up to 8 MB) and browser microphone recording for voice messages.
- Display name and menu-language preference (14 choices), plus change-password flow.
- Render deployment blueprint.

## Google sign-in setup (required before the button works)

1. Open [Google Cloud Console](https://console.cloud.google.com/) and create/select a project.
2. Go to **Google Auth Platform** (or **APIs & Services → OAuth consent screen**) and configure the app name, support email, and audience. While in Testing mode, add your own Google account under **Test users**. For public use, complete Google's verification requirements if applicable.
3. Go to **Clients / Credentials → Create OAuth client ID** and choose **Web application**.
4. Add the deployed site origin under **Authorized JavaScript origins**, e.g. `https://YOUR-SERVICE.onrender.com`.
5. Add this exact callback under **Authorized redirect URIs**: `https://YOUR-SERVICE.onrender.com/auth/google/callback`. Replace `YOUR-SERVICE` with the actual Render service hostname. The URL must match exactly.
6. Copy the client ID and client secret. In Render → your service → **Environment**, add:
   - `GOOGLE_CLIENT_ID` = your Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET` = your Google OAuth client secret
   - `GOOGLE_REDIRECT_URI` = `https://YOUR-SERVICE.onrender.com/auth/google/callback`
7. Save changes and redeploy/restart the service. Test the Google button using an account permitted by your consent-screen audience.

**Keep `GOOGLE_CLIENT_SECRET` private.** Never put it in frontend code or commit it to GitHub. Do not share it in chat. If it is exposed, rotate it in Google Cloud Console.

## Run locally

Python 3.11+ recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
$env:JWT_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:GOOGLE_CLIENT_ID = "your-client-id"
$env:GOOGLE_CLIENT_SECRET = "your-client-secret"
$env:GOOGLE_REDIRECT_URI = "http://127.0.0.1:8000/auth/google/callback"
uvicorn main:app --reload
```

For local Google testing, add `http://127.0.0.1:8000` as an authorized origin and `http://127.0.0.1:8000/auth/google/callback` as an authorized redirect URI in Google Cloud. Open http://127.0.0.1:8000 .

## Deploy to Render

1. Upload this project folder to a GitHub repository.
2. In Render, create a new Blueprint or Web Service from that repository.
3. Keep `JWT_SECRET_KEY` generated and private. Set the three Google variables described above.
4. For durable data, attach a Render persistent disk and set `DATABASE_PATH` and `UPLOAD_DIR` to paths on that disk. Without persistent storage, SQLite data and uploaded files may be lost on redeploy/restart. For multi-instance production, use managed PostgreSQL and object storage instead.
5. Use HTTPS for microphone permissions and secure browser APIs.

## Limitations
- Email-based password recovery is not enabled until an email provider and verified sending domain are configured.
- The language selector stores the preferred menu language, but the entire interface is not translated into all 14 languages yet.
- This is a functional starter, not a fully audited production messenger. Before public launch, add moderation/reporting, backups, durable database/object storage, and security review. Uploads are limited to 8 MB.
