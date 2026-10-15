# PM Chat

The menu language can be selected on the first screen and changed later from the header. Included menu languages: Persian, English, Turkish, Azerbaijani, Arabic, Russian, French, Spanish, German, Chinese, Hindi, Portuguese, Japanese, and Italian. Chat messages are not automatically translated.

## Deploy to Render
Upload `main.py`, `requirements.txt`, `render.yaml`, and `README.md` to a GitHub repository. In Render choose **New +** → **Blueprint**, connect GitHub, select the repository, then review and apply.

## Important
SQLite is used by default. On hosting with an ephemeral filesystem, accounts/messages can be lost after restarts or redeploys. Configure persistent storage or managed PostgreSQL for reliable persistence. Do not publish real secrets. This is a basic starter app and needs moderation and stronger production controls before broad public use.
