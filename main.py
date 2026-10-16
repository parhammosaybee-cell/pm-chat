import os
import sqlite3
import base64
import mimetypes
import json
import uuid
import secrets
import urllib.parse
import httpx
from pathlib import Path
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

# Set JWT_SECRET_KEY in your terminal before starting the app.
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        'Set JWT_SECRET_KEY first. PowerShell: '
        '$env:JWT_SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"'
    )

DATABASE = os.environ.get("DATABASE_PATH", "chat.db")
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "uploads"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = 8 * 1024 * 1024
TOKEN_MINUTES = 60 * 12
hasher = PasswordHasher()
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PM Chat")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
bearer = HTTPBearer(auto_error=False)


def db():
    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT") if "display_name" not in [r[1] for r in conn.execute("PRAGMA table_info(users)")] else None
        conn.execute("ALTER TABLE users ADD COLUMN language TEXT NOT NULL DEFAULT 'fa'") if "language" not in [r[1] for r in conn.execute("PRAGMA table_info(users)")] else None
        conn.execute("ALTER TABLE messages ADD COLUMN media_url TEXT") if "media_url" not in [r[1] for r in conn.execute("PRAGMA table_info(messages)")] else None
        conn.execute("ALTER TABLE messages ADD COLUMN media_type TEXT") if "media_type" not in [r[1] for r in conn.execute("PRAGMA table_info(messages)")] else None
        conn.execute("""CREATE TABLE IF NOT EXISTS direct_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL,
            body TEXT NOT NULL, media_url TEXT, media_type TEXT, created_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS stories (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, body TEXT NOT NULL DEFAULT '',
            media_url TEXT, media_type TEXT, created_at TEXT NOT NULL, expires_at TEXT NOT NULL)""")


init_db()


class RegisterData(BaseModel):
    username: str = Field(min_length=3, max_length=24, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=12, max_length=128)


class LoginData(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=1, max_length=128)


class MessageData(BaseModel):
    body: str = Field(default="", max_length=1000)
    media_url: str | None = Field(default=None, max_length=300)
    media_type: str | None = Field(default=None, max_length=40)


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials is None:
        raise HTTPException(401, "اول وارد حساب شو")
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=["HS256"],
            options={"require": ["sub", "exp", "iat"]},
        )
        uid = int(payload["sub"])
    except (jwt.InvalidTokenError, ValueError, KeyError):
        raise HTTPException(401, "توکن نامعتبر یا منقضی شده است")
    with db() as conn:
        user = conn.execute(
            "SELECT id, username FROM users WHERE id = ?", (uid,)
        ).fetchone()
    if user is None:
        raise HTTPException(401, "حساب پیدا نشد")
    return {"id": user["id"], "username": user["username"]}


@app.get("/", response_class=HTMLResponse)
def home():
    return HTML


def google_configured():
    return bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))


@app.get("/auth/google")
def google_login(request: Request):
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id or not os.environ.get("GOOGLE_CLIENT_SECRET"):
        raise HTTPException(503, "ورود گوگل هنوز تنظیم نشده؛ GOOGLE_CLIENT_ID و GOOGLE_CLIENT_SECRET را در Render وارد کن.")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", str(request.base_url).rstrip("/") + "/auth/google/callback")
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    response = RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params), status_code=302)
    response.set_cookie("pm_google_oauth_state", state, httponly=True, secure=request.url.scheme == "https", samesite="lax", max_age=600)
    return response


@app.get("/auth/google/callback")
def google_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    if error:
        return RedirectResponse("/?google_error=" + urllib.parse.quote("ورود گوگل لغو شد"), status_code=303)
    state_cookie = request.cookies.get("pm_google_oauth_state")
    if not state or not state_cookie or not secrets.compare_digest(state, state_cookie) or not code:
        raise HTTPException(400, "درخواست ورود گوگل معتبر نیست؛ دوباره تلاش کن.")
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", str(request.base_url).rstrip("/") + "/auth/google/callback")
    if not client_id or not client_secret:
        raise HTTPException(503, "ورود گوگل هنوز تنظیم نشده است.")
    try:
        with httpx.Client(timeout=12.0) as client:
            token_response = client.post("https://oauth2.googleapis.com/token", data={
                "code": code, "client_id": client_id, "client_secret": client_secret,
                "redirect_uri": redirect_uri, "grant_type": "authorization_code",
            })
            token_response.raise_for_status()
            access_token = token_response.json()["access_token"]
            profile_response = client.get("https://openidconnect.googleapis.com/v1/userinfo", headers={"Authorization": "Bearer " + access_token})
            profile_response.raise_for_status()
            profile = profile_response.json()
    except (httpx.HTTPError, KeyError, ValueError):
        raise HTTPException(401, "تأیید حساب گوگل ناموفق بود؛ دوباره تلاش کن.")
    email = str(profile.get("email", "")).strip().lower()
    if not email or profile.get("email_verified") is not True:
        raise HTTPException(403, "گوگل ایمیل تأییدشده‌ای برای این حساب برنگرداند.")
    base = email.split("@", 1)[0].lower()
    base = "".join(ch for ch in base if ch.isalnum() or ch == "_")[:18] or "googleuser"
    with db() as conn:
        # Keep the Google identity mapped by its verified email in a dedicated table.
        conn.execute("CREATE TABLE IF NOT EXISTS google_identities (email TEXT PRIMARY KEY, user_id INTEGER NOT NULL UNIQUE)")
        row = conn.execute("SELECT users.id, users.username FROM google_identities JOIN users ON users.id=google_identities.user_id WHERE google_identities.email=?", (email,)).fetchone()
        if row is None:
            username = base
            suffix = 1
            while conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                username = (base[:16] + str(suffix))[:24]
                suffix += 1
            password_hash = hasher.hash(secrets.token_urlsafe(48))
            now_text = datetime.now(timezone.utc).isoformat()
            cur = conn.execute("INSERT INTO users(username,password_hash,created_at,display_name) VALUES(?,?,?,?)", (username, password_hash, now_text, str(profile.get("name", username))[:40]))
            uid = cur.lastrowid
            conn.execute("INSERT INTO google_identities(email,user_id) VALUES(?,?)", (email, uid))
        else:
            uid, username = row["id"], row["username"]
    now = datetime.now(timezone.utc)
    app_token = jwt.encode({"sub": str(uid), "iat": now, "exp": now + timedelta(minutes=TOKEN_MINUTES)}, SECRET_KEY, algorithm="HS256")
    # Deliver the short-lived app token in a no-store page, never in the URL/query string.
    page = """<!doctype html><html lang="fa"><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>ورود به PM Chat</title><body style="background:#080b0a;color:#eafff1;font-family:Tahoma;text-align:center;padding:40px">ورود موفق بود؛ در حال انتقال...<script>localStorage.setItem('sabz_token', TOKEN);localStorage.setItem('sabz_user', USER);location.replace('/');</script></body></html>"""
    page = page.replace("TOKEN", json.dumps(app_token)).replace("USER", json.dumps(username))
    response = HTMLResponse(page, headers={"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"})
    response.delete_cookie("pm_google_oauth_state")
    return response


@app.post("/api/register", status_code=201)
@limiter.limit("5/minute")
def register(request: Request, data: RegisterData):
    username = data.username.strip()
    password_hash = hasher.hash(data.password)
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                (username, password_hash, datetime.now(timezone.utc).isoformat()),
            )
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "این نام کاربری قبلاً گرفته شده است")
    return {"id": uid, "username": username, "message": "حساب ساخته شد؛ حالا وارد شو"}


@app.post("/api/login")
@limiter.limit("5/minute")
def login(request: Request, data: LoginData):
    with db() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (data.username.strip(),),
        ).fetchone()
    if user is None:
        raise HTTPException(401, "نام کاربری یا رمز اشتباه است")
    try:
        hasher.verify(user["password_hash"], data.password)
    except (VerifyMismatchError, VerificationError):
        raise HTTPException(401, "نام کاربری یا رمز اشتباه است")
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(user["id"]), "iat": now, "exp": now + timedelta(minutes=TOKEN_MINUTES)},
        SECRET_KEY,
        algorithm="HS256",
    )
    return {"access_token": token, "token_type": "bearer", "username": user["username"]}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


@app.get("/api/messages")
def list_messages(after: int = 0, user=Depends(current_user)):
    with db() as conn:
        rows = conn.execute("""
            SELECT messages.id, messages.body, messages.media_url, messages.media_type, messages.created_at, users.username
            FROM messages JOIN users ON users.id = messages.user_id
            WHERE messages.id > ?
            ORDER BY messages.id ASC LIMIT 100
        """, (max(after, 0),)).fetchall()
    return [dict(row) for row in rows]


@app.post("/api/messages", status_code=201)
@limiter.limit("20/minute")
def send_message(request: Request, data: MessageData, user=Depends(current_user)):
    body = data.body.strip()
    if not body and not data.media_url:
        raise HTTPException(400, "پیام خالی است")
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO messages(user_id,body,created_at,media_url,media_type) VALUES(?,?,?,?,?)",
            (user["id"], body, now, data.media_url, data.media_type),
        )
        message_id = cur.lastrowid
    return {
        "id": message_id, "username": user["username"],
        "body": body, "media_url": data.media_url, "media_type": data.media_type, "created_at": now
    }



class UploadData(BaseModel):
    filename: str = Field(min_length=1, max_length=120)
    data_url: str = Field(min_length=20, max_length=12_000_000)

class DirectMessageData(BaseModel):
    body: str = Field(default="", max_length=1000)
    media_url: str | None = Field(default=None, max_length=300)
    media_type: str | None = Field(default=None, max_length=40)

class StoryData(BaseModel):
    body: str = Field(default="", max_length=500)
    media_url: str | None = Field(default=None, max_length=300)
    media_type: str | None = Field(default=None, max_length=40)

class SettingsData(BaseModel):
    display_name: str = Field(min_length=1, max_length=40)
    language: str = Field(default="fa", pattern=r"^(fa|en|nl|de|fr|es|it|pt|tr|ar|ru|zh|ja|hi)$")

class ChangePasswordData(BaseModel):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)

@app.get("/api/users")
def search_users(q: str = "", user=Depends(current_user)):
    q = q.strip()[:40]
    with db() as conn:
        rows = conn.execute("SELECT id, username, COALESCE(display_name, username) AS display_name FROM users WHERE id != ? AND username LIKE ? ORDER BY username LIMIT 30", (user["id"], f"%{q}%")).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/direct/{other_id}")
def list_direct(other_id: int, after: int = 0, user=Depends(current_user)):
    with db() as conn:
        exists = conn.execute("SELECT id FROM users WHERE id=?", (other_id,)).fetchone()
        if not exists: raise HTTPException(404, "کاربر پیدا نشد")
        rows = conn.execute("""SELECT d.id,d.sender_id,d.recipient_id,d.body,d.media_url,d.media_type,d.created_at,
          u.username FROM direct_messages d JOIN users u ON u.id=d.sender_id
          WHERE d.id>? AND ((d.sender_id=? AND d.recipient_id=?) OR (d.sender_id=? AND d.recipient_id=?))
          ORDER BY d.id ASC LIMIT 100""", (max(after,0),user["id"],other_id,other_id,user["id"])).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/direct/{other_id}", status_code=201)
@limiter.limit("30/minute")
def send_direct(other_id: int, request: Request, data: DirectMessageData, user=Depends(current_user)):
    body=data.body.strip()
    if not body and not data.media_url: raise HTTPException(400,"پیام خالی است")
    with db() as conn:
        if not conn.execute("SELECT id FROM users WHERE id=?",(other_id,)).fetchone(): raise HTTPException(404,"کاربر پیدا نشد")
        now=datetime.now(timezone.utc).isoformat()
        cur=conn.execute("INSERT INTO direct_messages(sender_id,recipient_id,body,media_url,media_type,created_at) VALUES(?,?,?,?,?,?)",(user["id"],other_id,body,data.media_url,data.media_type,now))
        mid=cur.lastrowid
        row=conn.execute("SELECT d.id,d.sender_id,d.recipient_id,d.body,d.media_url,d.media_type,d.created_at,u.username FROM direct_messages d JOIN users u ON u.id=d.sender_id WHERE d.id=?",(mid,)).fetchone()
    return dict(row)

@app.post("/api/upload")
@limiter.limit("10/minute")
def upload_file(request: Request, data: UploadData, user=Depends(current_user)):
    try:
        header, encoded = data.data_url.split(',',1)
        mime=header.split(';')[0].replace('data:','')
        if mime not in ('image/jpeg','image/png','image/gif','image/webp','video/mp4','video/webm','audio/webm','audio/ogg','audio/mp4'):
            raise HTTPException(415,"این نوع فایل پشتیبانی نمی‌شود")
        raw=base64.b64decode(encoded, validate=True)
    except HTTPException: raise
    except Exception: raise HTTPException(400,"فایل نامعتبر است")
    if len(raw)>MAX_UPLOAD_BYTES: raise HTTPException(413,"حداکثر حجم فایل ۸ مگابایت است")
    ext=mimetypes.guess_extension(mime) or '.bin'
    name=f"{uuid.uuid4().hex}{ext}"
    (UPLOAD_DIR/name).write_bytes(raw)
    return {"url":f"/uploads/{name}","media_type":mime,"filename":data.filename}

from fastapi.staticfiles import StaticFiles
app.mount("/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")

@app.get("/api/stories")
def get_stories(user=Depends(current_user)):
    now=datetime.now(timezone.utc).isoformat()
    with db() as conn:
        conn.execute("DELETE FROM stories WHERE expires_at <= ?",(now,))
        rows=conn.execute("""SELECT s.id,s.user_id,s.body,s.media_url,s.media_type,s.created_at,s.expires_at,u.username
        FROM stories s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC LIMIT 100""").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/stories",status_code=201)
@limiter.limit("10/minute")
def create_story(request: Request, data: StoryData, user=Depends(current_user)):
    body=data.body.strip()
    if not body and not data.media_url: raise HTTPException(400,"استوری خالی است")
    now=datetime.now(timezone.utc); expires=now+timedelta(hours=24)
    with db() as conn:
        cur=conn.execute("INSERT INTO stories(user_id,body,media_url,media_type,created_at,expires_at) VALUES(?,?,?,?,?,?)",(user["id"],body,data.media_url,data.media_type,now.isoformat(),expires.isoformat()))
        row=conn.execute("SELECT s.id,s.user_id,s.body,s.media_url,s.media_type,s.created_at,s.expires_at,u.username FROM stories s JOIN users u ON u.id=s.user_id WHERE s.id=?",(cur.lastrowid,)).fetchone()
    return dict(row)

@app.get("/api/settings")
def get_settings(user=Depends(current_user)):
    with db() as conn:
        row=conn.execute("SELECT COALESCE(display_name,username) display_name,language FROM users WHERE id=?",(user["id"],)).fetchone()
    return dict(row)

@app.put("/api/settings")
def update_settings(data: SettingsData, user=Depends(current_user)):
    with db() as conn: conn.execute("UPDATE users SET display_name=?,language=? WHERE id=?",(data.display_name.strip(),data.language,user["id"]))
    return {"display_name":data.display_name.strip(),"language":data.language}

@app.post("/api/change-password")
@limiter.limit("5/minute")
def change_password(request: Request, data: ChangePasswordData, user=Depends(current_user)):
    with db() as conn: row=conn.execute("SELECT password_hash FROM users WHERE id=?",(user["id"],)).fetchone()
    try: hasher.verify(row["password_hash"],data.old_password)
    except (VerifyMismatchError,VerificationError): raise HTTPException(400,"رمز فعلی اشتباه است")
    with db() as conn: conn.execute("UPDATE users SET password_hash=? WHERE id=?",(hasher.hash(data.new_password),user["id"]))
    return {"message":"رمز عبور تغییر کرد؛ برای امنیت دوباره وارد شو"}

HTML = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PM Chat</title>
<style>
:root{color-scheme:dark;--bg:#080b0a;--panel:#111715;--panel2:#18211d;--green:#25e58b;--muted:#9aaba3;--line:#26352d}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#14271d 0,#080b0a 55%);color:#f2fff7;font-family:Tahoma,Arial,sans-serif;min-height:100vh;display:grid;place-items:center;padding:18px}
.app{width:min(100%,1000px);height:min(800px,94vh);min-height:550px;background:#0c100e;border:1px solid var(--line);border-radius:22px;overflow:hidden;display:grid;grid-template-columns:280px 1fr;box-shadow:0 25px 80px #0009}
.sidebar{background:#0e1411;border-left:1px solid var(--line);padding:22px;display:flex;flex-direction:column;gap:18px}
.brand{display:flex;align-items:center;gap:10px;font-size:22px;font-weight:bold}.logo{background:var(--green);color:#07140d;width:40px;height:40px;border-radius:13px;display:grid;place-items:center;font-weight:900}
.small{color:var(--muted);font-size:12px;line-height:1.8}.pill{border:1px solid #24563d;background:#10291d;color:var(--green);padding:10px 12px;border-radius:12px;font-size:13px}
.chat{display:flex;flex-direction:column;min-width:0}.top{padding:20px 24px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:12px}.top h2{font-size:17px;margin:0 0 6px}.status{font-size:12px;color:var(--green)}
.messages{flex:1;overflow:auto;padding:22px;display:flex;flex-direction:column;gap:14px}.empty{margin:auto;text-align:center;color:var(--muted);line-height:2}.bubble{max-width:min(80%,560px);align-self:flex-start;background:var(--panel2);border:1px solid var(--line);padding:12px 15px;border-radius:16px 4px 16px 16px;overflow-wrap:anywhere}.bubble.mine{align-self:flex-end;background:#123a27;border-color:#206b46;border-radius:4px 16px 16px 16px}.meta{font-size:11px;color:var(--green);margin-bottom:7px}.body{white-space:pre-wrap;line-height:1.8}.time{font-size:10px;color:#91a59a;margin-top:6px}
.composer{padding:18px 22px;border-top:1px solid var(--line);display:flex;gap:10px}.composer input{flex:1;min-width:0}
input{background:#101713;border:1px solid #2a3b31;color:#fff;border-radius:12px;padding:13px;font:inherit;outline:none;width:100%}input:focus{border-color:var(--green)}button{border:0;border-radius:12px;padding:12px 16px;background:var(--green);color:#06150d;font-weight:bold;font:inherit;cursor:pointer}button:disabled{opacity:.5;cursor:wait}.secondary{background:#202a24;color:#dfffee;border:1px solid #33473a}.auth{width:min(100%,420px);background:var(--panel);padding:28px;border:1px solid var(--line);border-radius:22px;box-shadow:0 25px 80px #0009}.auth h1{margin:12px 0 5px}.auth p{color:var(--muted);font-size:13px;line-height:1.8}.form{display:flex;flex-direction:column;gap:12px;margin-top:22px}.form button{margin-top:4px}.switch{display:flex;gap:10px;margin-top:12px}.switch button{flex:1}.error{color:#ff9c9c;font-size:13px;min-height:20px;line-height:1.7}.hidden{display:none!important}
@media(max-width:650px){.app{grid-template-columns:1fr;height:94vh;min-height:0}.sidebar{display:none}.top{padding:16px}.messages{padding:14px}.composer{padding:12px}.bubble{max-width:90%}}
</style></head>
<body>
<section class="auth" id="auth">
 <div class="brand"><div class="logo">PM</div><div>PM Chat<div class="small">گفت‌وگوی خودت، فضای خودت</div></div></div>
 <h1 id="authTitle">ورود به حساب</h1><p>برای ورود، نام کاربری و رمز عبورت را وارد کن. اگر حساب نداری، ثبت‌نام کن.</p>
 <form class="form" id="authForm">
  <input id="username" placeholder="نام کاربری (انگلیسی و عدد)" minlength="3" maxlength="24" required autocomplete="username">
  <input id="password" type="password" placeholder="رمز عبور (حداقل ۱۲ کاراکتر برای ثبت‌نام)" required autocomplete="current-password">
  <button id="authSubmit" type="submit">ورود</button>
 </form>
 <button class="secondary" id="googleLogin" type="button" style="width:100%;margin-top:12px" onclick="location.href='/auth/google'">ورود با Google</button>
 <div class="switch"><button class="secondary" id="showLogin" type="button">ورود</button><button class="secondary" id="showRegister" type="button">ساخت حساب</button></div>
 <div class="error" id="authError"></div>
 <p class="small">نسخه شروع PM Chat؛ پیش از استفاده عمومی باید روی سرور امن با HTTPS نصب شود.</p>
</section>
<section class="app hidden" id="app">
 <aside class="sidebar"><div class="brand"><div class="logo">PM</div><div>PM Chat<div class="small">پیام‌رسان شخصی</div></div></div>
 <div class="pill">● سرویس چت فعال است</div><div><div class="small">واردشده به‌عنوان</div><strong id="sideUser"></strong></div>
 <button class="secondary" id="tabPublic">چت عمومی</button><button class="secondary" id="tabPeople">پیدا کردن کاربران</button><button class="secondary" id="tabStories">استوری‌ها (۲۴ ساعت)</button><button class="secondary" id="tabSettings">تنظیمات</button>
 <div class="small">پیام خصوصی، جست‌وجوی کاربران، استوری و تنظیمات حساب</div>
 <div style="margin-top:auto"><button class="secondary" id="logout" style="width:100%">خروج از حساب</button></div></aside>
 <main class="chat"><header class="top"><div><h2 id="panelTitle">گفت‌وگوی عمومی</h2><div class="status">● آماده ارسال پیام</div></div><div class="small" id="who"></div></header>
 <section id="peoplePanel" class="hidden" style="padding:18px;overflow:auto"><input id="userSearch" placeholder="جست‌وجوی نام کاربری..."><div id="userResults" style="display:grid;gap:10px;margin-top:12px"></div></section>
 <section id="storiesPanel" class="hidden" style="padding:18px;overflow:auto"><form id="storyForm" class="form" style="margin:0"><input id="storyText" maxlength="500" placeholder="استوری متنی بنویس..."><input id="storyFile" type="file" accept="image/*,video/mp4,video/webm"><button>انتشار استوری ۲۴ ساعته</button></form><div id="storyResults" style="display:grid;gap:12px;margin-top:18px"></div></section>
 <section id="settingsPanel" class="hidden" style="padding:18px;overflow:auto"><form id="settingsForm" class="form" style="margin:0;max-width:500px"><label>نام نمایشی</label><input id="displayName" maxlength="40" required><label>زبان منو</label><select id="language" style="padding:12px;background:#101713;color:white;border:1px solid #2a3b31;border-radius:12px"><option value="fa">فارسی</option><option value="en">English</option><option value="nl">Nederlands</option><option value="de">Deutsch</option><option value="fr">Français</option><option value="es">Español</option><option value="it">Italiano</option><option value="pt">Português</option><option value="tr">Türkçe</option><option value="ar">العربية</option><option value="ru">Русский</option><option value="zh">中文</option><option value="ja">日本語</option><option value="hi">हिन्दी</option></select><button>ذخیره تنظیمات</button></form><hr style="border-color:#26352d;margin:24px 0"><form id="passwordForm" class="form" style="margin:0;max-width:500px"><h3>تغییر رمز عبور</h3><input id="oldPassword" type="password" placeholder="رمز فعلی" required><input id="newPassword" type="password" minlength="12" placeholder="رمز جدید، حداقل ۱۲ کاراکتر" required><button>تغییر رمز</button></form><div class="error" id="settingsNotice"></div><p class="small">ورود گوگل و بازیابی رمز از طریق ایمیل به تنظیم OAuth و سرویس ایمیل نیاز دارند و در این نسخه فعال نشده‌اند.</p></section>
 <div class="messages" id="messages"><div class="empty" id="empty">🌱<br>هنوز پیامی نیست<br>اولین پیام را بفرست!</div></div>
 <form class="composer" id="sendForm"><input id="message" maxlength="1000" placeholder="پیامت را بنویس..." autocomplete="off" required><button id="sendBtn">ارسال</button><button id="attachBtn" class="secondary" type="button" title="ارسال عکس یا ویدئو">📎</button><input id="mediaFile" type="file" accept="image/*,video/mp4,video/webm" class="hidden"><button id="voiceBtn" class="secondary" type="button">🎙️</button></form>
 <div class="small" style="padding:0 22px 10px" id="notice"></div></main>
</section>
<script>
let token=localStorage.getItem('sabz_token')||'', username=localStorage.getItem('sabz_user')||'', registering=false,lastId=0,polling=false,mode='public',directUser=null,recorder=null,recorded=[];
const $=id=>document.getElementById(id);
const authParams=new URLSearchParams(location.search);
if(authParams.has('google_error')){$('authError').textContent=authParams.get('google_error')||'ورود گوگل ناموفق بود';history.replaceState({},document.title,location.pathname)}
function authMode(reg){registering=reg;$('authTitle').textContent=reg?'ساخت حساب جدید':'ورود به حساب';$('authSubmit').textContent=reg?'ثبت‌نام':'ورود';$('password').autocomplete=reg?'new-password':'current-password';$('authError').textContent='';}
$('showLogin').onclick=()=>authMode(false);$('showRegister').onclick=()=>authMode(true);
async function api(url,opts={}){opts.headers={...(opts.headers||{}),...(token?{Authorization:'Bearer '+token}:{})};if(opts.body&&!(opts.body instanceof FormData))opts.headers['Content-Type']='application/json';let r=await fetch(url,opts),d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.detail||'خطا در ارتباط با سرور');return d;}
$('authForm').onsubmit=async e=>{e.preventDefault();$('authError').textContent='';$('authSubmit').disabled=true;try{let u=$('username').value.trim(),p=$('password').value;if(registering){await api('/api/register',{method:'POST',body:JSON.stringify({username:u,password:p})});authMode(false);$('authError').textContent='حساب ساخته شد؛ حالا وارد شو.';$('username').value=u;$('password').value='';}else{let d=await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});token=d.access_token;username=d.username;localStorage.setItem('sabz_token',token);localStorage.setItem('sabz_user',username);showChat();}}catch(err){$('authError').textContent=err.message;}finally{$('authSubmit').disabled=false;}};
function showChat(){ $('auth').classList.add('hidden');$('app').classList.remove('hidden');$('sideUser').textContent=username;$('who').textContent='@'+username;switchMode('public');loadMessages(true);loadStories();loadSettings();}
function showAuth(){ $('app').classList.add('hidden');$('auth').classList.remove('hidden');}
function switchMode(m){mode=m;['peoplePanel','storiesPanel','settingsPanel'].forEach(id=>$(id).classList.add('hidden'));$('messages').classList.toggle('hidden',m==='people'||m==='stories'||m==='settings');$('sendForm').classList.toggle('hidden',m==='people'||m==='stories'||m==='settings');if(m==='people')$('peoplePanel').classList.remove('hidden');if(m==='stories')$('storiesPanel').classList.remove('hidden');if(m==='settings')$('settingsPanel').classList.remove('hidden');$('panelTitle').textContent=m==='public'?'گفت‌وگوی عمومی':m==='direct'?'چت خصوصی با @'+(directUser?.username||''):m==='people'?'پیدا کردن کاربران':m==='stories'?'استوری‌ها':'تنظیمات';if(m==='public')loadMessages(true);if(m==='direct')loadDirect(true);}
$('tabPublic').onclick=()=>switchMode('public');$('tabPeople').onclick=()=>{switchMode('people');searchUsers()};$('tabStories').onclick=()=>{switchMode('stories');loadStories()};$('tabSettings').onclick=()=>switchMode('settings');
function addMessage(m,direct=false){$('empty').classList.add('hidden');const wrap=document.createElement('div');wrap.className='bubble'+(direct?m.sender_id===currentId?' mine':'':m.username===username?' mine':'');const meta=document.createElement('div');meta.className='meta';meta.textContent='@'+m.username;const body=document.createElement('div');body.className='body';body.textContent=m.body||'';wrap.append(meta,body);if(m.media_url){let el=document.createElement(m.media_type?.startsWith('video')?'video':m.media_type?.startsWith('audio')?'audio':'img');el.src=m.media_url;el.controls=true;el.style.maxWidth='100%';el.style.maxHeight='260px';wrap.append(el)}const time=document.createElement('div');time.className='time';try{time.textContent=new Date(m.created_at).toLocaleString()}catch{}wrap.append(time);$('messages').appendChild(wrap);$('messages').scrollTop=$('messages').scrollHeight;lastId=Math.max(lastId,m.id);}
let currentId=0;
async function loadMessages(initial=false){if(polling||!token||mode!=='public')return;polling=true;try{let me=await api('/api/me');currentId=me.id;let list=await api('/api/messages?after='+(initial?0:lastId));if(initial){$('messages').querySelectorAll('.bubble').forEach(n=>n.remove());lastId=0;}list.forEach(m=>addMessage(m));$('notice').textContent='';}catch(err){if(err.message.includes('توکن')||err.message.includes('وارد'))logout();else $('notice').textContent='ارتباط قطع شد؛ دوباره تلاش می‌کنیم.';}finally{polling=false;}}
async function loadDirect(initial=false){if(!directUser)return;try{let list=await api('/api/direct/'+directUser.id+'?after='+(initial?0:lastId));if(initial){$('messages').querySelectorAll('.bubble').forEach(n=>n.remove());lastId=0;}list.forEach(m=>addMessage(m,true));}catch(e){$('notice').textContent=e.message}}
$('sendForm').onsubmit=async e=>{e.preventDefault();let body=$('message').value.trim();if(!body)return;$('sendBtn').disabled=true;try{let m;if(mode==='direct'){m=await api('/api/direct/'+directUser.id,{method:'POST',body:JSON.stringify({body})});addMessage(m,true)}else{m=await api('/api/messages',{method:'POST',body:JSON.stringify({body})});addMessage(m)}$('message').value='';}catch(err){$('notice').textContent=err.message;}finally{$('sendBtn').disabled=false;$('message').focus();}};
async function searchUsers(){try{let q=$('userSearch').value||'',users=await api('/api/users?q='+encodeURIComponent(q));$('userResults').replaceChildren();users.forEach(u=>{let b=document.createElement('button');b.className='secondary';b.textContent=(u.display_name||u.username)+' (@'+u.username+') — شروع چت خصوصی';b.onclick=()=>{directUser=u;lastId=0;switchMode('direct')};$('userResults').append(b)});if(!users.length)$('userResults').textContent='کاربری پیدا نشد.'}catch(e){$('userResults').textContent=e.message}}
$('userSearch').oninput=searchUsers;
async function upload(file){if(!file)return null;if(file.size>8*1024*1024)throw Error('حداکثر حجم فایل ۸ مگابایت است');let data=await new Promise((resolve,reject)=>{let r=new FileReader();r.onload=()=>resolve(r.result);r.onerror=reject;r.readAsDataURL(file)});return api('/api/upload',{method:'POST',body:JSON.stringify({filename:file.name,data_url:data})})}
$('attachBtn').onclick=()=>$('mediaFile').click();$('mediaFile').onchange=async()=>{let f=$('mediaFile').files[0];if(!f)return;try{let up=await upload(f),payload={body:'',media_url:up.url,media_type:up.media_type};let m=mode==='direct'?await api('/api/direct/'+directUser.id,{method:'POST',body:JSON.stringify(payload)}):await api('/api/messages',{method:'POST',body:JSON.stringify({body:'[رسانه] '+up.url})});if(mode==='direct')addMessage(m,true);else addMessage(m);$('notice').textContent='فایل ارسال شد.'}catch(e){$('notice').textContent=e.message}$('mediaFile').value=''};
$('voiceBtn').onclick=async()=>{try{if(!recorder){let stream=await navigator.mediaDevices.getUserMedia({audio:true});recorder=new MediaRecorder(stream);recorded=[];recorder.ondataavailable=e=>{if(e.data.size)recorded.push(e.data)};recorder.onstop=async()=>{try{let file=new File(recorded,'voice.webm',{type:recorder.mimeType||'audio/webm'}),up=await upload(file),payload={body:'پیام صوتی',media_url:up.url,media_type:up.media_type};let m=mode==='direct'?await api('/api/direct/'+directUser.id,{method:'POST',body:JSON.stringify(payload)}):await api('/api/messages',{method:'POST',body:JSON.stringify({body:'پیام صوتی: '+up.url})});if(mode==='direct')addMessage(m,true);else addMessage(m);stream.getTracks().forEach(t=>t.stop());recorder=null;$('voiceBtn').textContent='🎙️';}catch(e){$('notice').textContent=e.message;recorder=null;$('voiceBtn').textContent='🎙️'}};recorder.start();$('voiceBtn').textContent='⏹ توقف و ارسال';}else{recorder.stop()}}catch(e){$('notice').textContent='ضبط صدا ممکن است به HTTPS و اجازه میکروفون نیاز داشته باشد: '+e.message}};
async function loadStories(){try{let stories=await api('/api/stories');$('storyResults').replaceChildren();stories.forEach(s=>{let card=document.createElement('div');card.className='bubble';let title=document.createElement('div');title.className='meta';title.textContent='@'+s.username+' · '+new Date(s.created_at).toLocaleString();card.append(title);if(s.body){let p=document.createElement('p');p.textContent=s.body;card.append(p)}if(s.media_url){let el=document.createElement(s.media_type?.startsWith('video')?'video':'img');el.src=s.media_url;el.controls=true;el.style.maxWidth='100%';el.style.maxHeight='300px';card.append(el)}$('storyResults').append(card)});if(!stories.length)$('storyResults').textContent='هنوز استوری‌ای نیست.'}catch(e){$('storyResults').textContent=e.message}}
$('storyForm').onsubmit=async e=>{e.preventDefault();try{let file=$('storyFile').files[0],up=file?await upload(file):null;await api('/api/stories',{method:'POST',body:JSON.stringify({body:$('storyText').value,media_url:up?.url||null,media_type:up?.media_type||null})});$('storyText').value='';$('storyFile').value='';loadStories()}catch(e){alert(e.message)}};
async function loadSettings(){try{let s=await api('/api/settings');$('displayName').value=s.display_name;$('language').value=s.language}catch(e){}}
$('settingsForm').onsubmit=async e=>{e.preventDefault();try{await api('/api/settings',{method:'PUT',body:JSON.stringify({display_name:$('displayName').value,language:$('language').value})});$('settingsNotice').textContent='تنظیمات ذخیره شد. انتخاب زبان ذخیره می‌شود؛ ترجمه همه متن‌های رابط هنوز کامل نیست.'}catch(e){$('settingsNotice').textContent=e.message}};
$('passwordForm').onsubmit=async e=>{e.preventDefault();try{let r=await api('/api/change-password',{method:'POST',body:JSON.stringify({old_password:$('oldPassword').value,new_password:$('newPassword').value})});$('settingsNotice').textContent=r.message;logout()}catch(e){$('settingsNotice').textContent=e.message}};
function logout(){token='';username='';lastId=0;localStorage.removeItem('sabz_token');localStorage.removeItem('sabz_user');showAuth()}$('logout').onclick=logout;
if(token&&username)showChat();else showAuth();setInterval(()=>{if(token&&!$('app').classList.contains('hidden')){if(mode==='public')loadMessages(false);if(mode==='direct')loadDirect(false)}},2500);
</script></body></html>
"""
