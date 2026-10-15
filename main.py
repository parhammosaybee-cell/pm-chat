import os
import time
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

APP_NAME = "PM Chat"
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")
if not SECRET_KEY:
    SECRET_KEY = "local-only-change-this-before-deploying"
DB_PATH = os.environ.get("DB_PATH", "chat.db")
TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7
hasher = PasswordHasher()
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title=APP_NAME)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, lambda request, exc: __import__("slowapi")._rate_limit_exceeded_handler(request, exc))
app.add_middleware(SlowAPIMiddleware)

def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(db()) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        conn.commit()

@app.on_event("startup")
def startup():
    init_db()

class AuthInput(BaseModel):
    username: str = Field(min_length=3, max_length=24, pattern=r"^[A-Za-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)

class MessageInput(BaseModel):
    body: str = Field(min_length=1, max_length=1000)

def make_token(username: str) -> str:
    return jwt.encode({"sub": username, "exp": int(time.time()) + TOKEN_TTL_SECONDS}, SECRET_KEY, algorithm="HS256")

def current_user(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="لطفاً وارد حساب شو.")
    try:
        payload = jwt.decode(authorization[7:], SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise ValueError()
        return username
    except Exception:
        raise HTTPException(status_code=401, detail="نشست تمام شده؛ دوباره وارد شو.")

@app.post("/api/register")
@limiter.limit("5/minute")
def register(request: Request, data: AuthInput):
    username = data.username.strip()
    try:
        password_hash = hasher.hash(data.password)
        with closing(db()) as conn:
            conn.execute("INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
                         (username, password_hash, datetime.now(timezone.utc).isoformat()))
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="این نام کاربری قبلاً گرفته شده است.")
    return {"token": make_token(username), "username": username}

@app.post("/api/login")
@limiter.limit("10/minute")
def login(request: Request, data: AuthInput):
    with closing(db()) as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username=?", (data.username.strip(),)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز اشتباه است.")
    try:
        hasher.verify(row["password_hash"], data.password)
    except VerifyMismatchError:
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز اشتباه است.")
    return {"token": make_token(data.username.strip()), "username": data.username.strip()}

@app.get("/api/messages")
def get_messages(username: str = Depends(current_user), after: int = 0):
    with closing(db()) as conn:
        rows = conn.execute("SELECT id, username, body, created_at FROM messages WHERE id > ? ORDER BY id ASC LIMIT 100",
                            (max(0, after),)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/messages")
@limiter.limit("30/minute")
def send_message(request: Request, data: MessageInput, username: str = Depends(current_user)):
    body = data.body.strip()
    if not body:
        raise HTTPException(status_code=400, detail="پیام خالی است.")
    with closing(db()) as conn:
        cur = conn.execute("INSERT INTO messages(username,body,created_at) VALUES(?,?,?)",
                           (username, body, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        row = conn.execute("SELECT id,username,body,created_at FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)

@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(PAGE)

PAGE = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PM Chat</title>
<style>
:root{color-scheme:dark;--bg:#080b09;--panel:#101713;--green:#20d66b;--muted:#9ba9a0}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#123522 0,#080b09 42%);font-family:Tahoma,Arial,sans-serif;color:#f3fff6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:18px}
.wrap{width:min(760px,100%);background:#0d130f;border:1px solid #244331;border-radius:22px;overflow:hidden;box-shadow:0 20px 70px #0009}
header{padding:22px;background:#101a13;border-bottom:1px solid #244331;display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{font-size:25px;font-weight:900;color:var(--green);letter-spacing:.4px}.logo{width:42px;height:42px;border-radius:13px;background:#20d66b;color:#06140b;display:grid;place-items:center;font-weight:1000;font-size:19px;box-shadow:0 0 24px #20d66b40}.headleft{display:flex;align-items:center;gap:12px}.sub{font-size:12px;color:var(--muted);margin-top:6px}
main{padding:20px}.tabs{display:flex;gap:8px;margin-bottom:16px}.tabs button{flex:1}
button{border:0;border-radius:10px;padding:12px 15px;background:var(--green);color:#041008;font-weight:bold;cursor:pointer;font-family:inherit}
button.secondary{background:#1b2a20;color:#eaffef;border:1px solid #31523c}
input,textarea{width:100%;background:#080d09;border:1px solid #294331;border-radius:10px;color:#fff;padding:13px;margin:6px 0 12px;font:inherit}
label{font-size:13px;color:#c8d8cd}.hidden{display:none!important}.notice{font-size:13px;color:#b7f7ca;min-height:20px;margin:8px 0}
#messages{height:340px;overflow:auto;background:#080d09;border:1px solid #233b2b;border-radius:14px;padding:12px;margin:12px 0}
.msg{padding:10px 12px;background:#14241a;border:1px solid #1c3826;border-radius:12px;margin:8px 0;overflow-wrap:anywhere}.msg strong{color:var(--green)}.msg small{display:block;color:#93a59a;font-size:10px;margin-top:5px}
.send{display:flex;gap:8px;align-items:center}.send input{margin:0}.send button{min-width:90px}
.pill{border:1px solid #285437;border-radius:999px;padding:6px 10px;color:#9ff0b8;font-size:11px;white-space:nowrap}
@media(max-width:500px){header{padding:16px}.brand{font-size:21px}main{padding:14px}#messages{height:48vh}}
</style></head>
<body><div class="wrap">
<header><div class="headleft"><div class="logo">PM</div><div><div class="brand">PM Chat</div><div class="sub" id="tagline">گفت‌وگو با تم مشکی و سبز</div></div></div><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><label id="settingsLabel" for="langHeader" class="hidden">زبان منو</label><select id="langHeader" class="hidden" onchange="setLanguage(this.value)" style="max-width:145px;background:#080d09;color:#fff;padding:9px;border:1px solid #294331;border-radius:9px"><option value="fa">فارسی</option><option value="en">English</option><option value="tr">Türkçe</option><option value="az">Azərbaycanca</option><option value="ar">العربية</option><option value="ru">Русский</option><option value="fr">Français</option><option value="es">Español</option><option value="de">Deutsch</option><option value="zh">中文</option><option value="hi">हिन्दी</option><option value="pt">Português</option><option value="ja">日本語</option><option value="it">Italiano</option></select><span class="pill" id="onlinePill">آنلاین</span><button id="logout" class="secondary hidden" onclick="logout()">خروج</button></div></header>
<main>
<section id="auth">
<div style="margin-bottom:14px"><label id="firstLangLabel" for="langFirst">زبان منو</label><select id="langFirst" onchange="setLanguage(this.value)" style="width:100%;background:#080d09;color:#fff;padding:12px;border:1px solid #294331;border-radius:10px;margin-top:6px"><option value="fa">فارسی</option><option value="en">English</option><option value="tr">Türkçe</option><option value="az">Azərbaycanca</option><option value="ar">العربية</option><option value="ru">Русский</option><option value="fr">Français</option><option value="es">Español</option><option value="de">Deutsch</option><option value="zh">中文</option><option value="hi">हिन्दी</option><option value="pt">Português</option><option value="ja">日本語</option><option value="it">Italiano</option></select></div>
<div class="tabs"><button id="loginTab" onclick="setMode('login')">ورود</button><button id="regTab" class="secondary" onclick="setMode('register')">ساخت حساب</button></div>
<label id="usernameLabel">نام کاربری (حداقل ۳ حرف انگلیسی یا عدد)</label><input id="username" autocomplete="username" placeholder="مثلاً parham_123">
<label id="passwordLabel">رمز عبور (حداقل ۸ کاراکتر)</label><input id="password" type="password" autocomplete="current-password" placeholder="رمز عبور">
<button id="continueBtn" style="width:100%" onclick="authenticate()">ادامه</button><div id="authNotice" class="notice"></div>
</section>
<section id="chat" class="hidden">
<div id="welcome" class="sub"></div><div id="messages"></div>
<div class="send"><input id="message" maxlength="1000" placeholder="پیامت را بنویس..." onkeydown="if(event.key==='Enter')sendMessage()"><button id="sendBtn" onclick="sendMessage()">ارسال</button></div>
<div id="chatNotice" class="notice"></div>
</section>
</main></div>
<script>
let mode='login', token=localStorage.getItem('pc_token')||'', username=localStorage.getItem('pc_user')||'', lastId=0, poller=null;
let lang=localStorage.getItem('pc_lang')||'fa';
const $=id=>document.getElementById(id);
const T={
fa:['گفت‌وگو با تم مشکی و سبز','زبان منو','آنلاین','خروج','ورود','ساخت حساب','نام کاربری (حداقل ۳ حرف انگلیسی یا عدد)','رمز عبور (حداقل ۸ کاراکتر)','مثلاً parham_123','رمز عبور','ادامه','خوش آمدی، {u}؛ پیام‌های اتاق عمومی را می‌بینی.','پیامت را بنویس...','ارسال','در حال بررسی...'],
en:['Chat in black and green','Menu language','Online','Log out','Log in','Create account','Username (3–24 letters, numbers or _)','Password (at least 8 characters)','e.g. parham_123','Password','Continue','Welcome, {u}! You can see messages in the public room.','Write a message...','Send','Checking...'],
tr:['Siyah ve yeşil sohbet','Menü dili','Çevrimiçi','Çıkış','Giriş yap','Hesap oluştur','Kullanıcı adı (3–24 karakter)','Şifre (en az 8 karakter)','örn. parham_123','Şifre','Devam','Hoş geldin, {u}! Genel odadaki mesajları görebilirsin.','Mesajını yaz...','Gönder','Kontrol ediliyor...'],
az:['Qara və yaşıl çat','Menyu dili','Onlayn','Çıxış','Daxil ol','Hesab yarat','İstifadəçi adı (3–24 simvol)','Şifrə (ən azı 8 simvol)','məs. parham_123','Şifrə','Davam et','Xoş gəldin, {u}! Ümumi otaqdakı mesajları görə bilərsən.','Mesajını yaz...','Göndər','Yoxlanılır...'],
ar:['دردشة بالأسود والأخضر','لغة القوائم','متصل','تسجيل الخروج','تسجيل الدخول','إنشاء حساب','اسم المستخدم (3–24 حرفًا أو رقمًا)','كلمة المرور (8 أحرف على الأقل)','مثال: parham_123','كلمة المرور','متابعة','مرحبًا {u}! يمكنك رؤية رسائل الغرفة العامة.','اكتب رسالتك...','إرسال','جارٍ التحقق...'],
ru:['Чат в чёрно-зелёном стиле','Язык меню','В сети','Выйти','Войти','Создать аккаунт','Имя пользователя (3–24 символа)','Пароль (не менее 8 символов)','например, parham_123','Пароль','Продолжить','Добро пожаловать, {u}! Здесь видны сообщения общей комнаты.','Напишите сообщение...','Отправить','Проверка...'],
fr:['Discussion en noir et vert','Langue du menu','En ligne','Déconnexion','Connexion','Créer un compte','Nom d’utilisateur (3 à 24 caractères)','Mot de passe (8 caractères minimum)','ex. parham_123','Mot de passe','Continuer','Bienvenue, {u} ! Voici les messages du salon public.','Écrivez un message...','Envoyer','Vérification...'],
es:['Chat en negro y verde','Idioma del menú','En línea','Cerrar sesión','Iniciar sesión','Crear cuenta','Usuario (3–24 caracteres)','Contraseña (mínimo 8 caracteres)','p. ej., parham_123','Contraseña','Continuar','¡Bienvenido, {u}! Puedes ver los mensajes de la sala pública.','Escribe un mensaje...','Enviar','Comprobando...'],
de:['Chat in Schwarz und Grün','Menüsprache','Online','Abmelden','Anmelden','Konto erstellen','Benutzername (3–24 Zeichen)','Passwort (mindestens 8 Zeichen)','z. B. parham_123','Passwort','Weiter','Willkommen, {u}! Du siehst die Nachrichten im öffentlichen Raum.','Nachricht schreiben...','Senden','Wird geprüft...'],
zh:['黑绿主题聊天','菜单语言','在线','退出登录','登录','创建账户','用户名（3–24 个字符）','密码（至少 8 个字符）','例如 parham_123','密码','继续','欢迎，{u}！你可以查看公共聊天室的消息。','输入消息...','发送','正在检查...'],
hi:['काले और हरे रंग की चैट','मेनू की भाषा','ऑनलाइन','लॉग आउट','लॉग इन','खाता बनाएँ','उपयोगकर्ता नाम (3–24 अक्षर)','पासवर्ड (कम से कम 8 अक्षर)','जैसे parham_123','पासवर्ड','जारी रखें','स्वागत है, {u}! आप सार्वजनिक चैट के संदेश देख सकते हैं।','संदेश लिखें...','भेजें','जाँच हो रही है...'],
pt:['Chat em preto e verde','Idioma do menu','Online','Sair','Entrar','Criar conta','Nome de usuário (3–24 caracteres)','Senha (mínimo de 8 caracteres)','ex.: parham_123','Senha','Continuar','Bem-vindo, {u}! Você pode ver as mensagens da sala pública.','Escreva uma mensagem...','Enviar','Verificando...'],
ja:['黒と緑のチャット','メニュー言語','オンライン','ログアウト','ログイン','アカウント作成','ユーザー名（3～24文字）','パスワード（8文字以上）','例：parham_123','パスワード','続行','{u} さん、ようこそ。公開ルームのメッセージを表示できます。','メッセージを入力...','送信','確認中...'],
it:['Chat in nero e verde','Lingua del menu','Online','Esci','Accedi','Crea account','Nome utente (3–24 caratteri)','Password (almeno 8 caratteri)','es. parham_123','Password','Continua','Benvenuto, {u}! Puoi vedere i messaggi della stanza pubblica.','Scrivi un messaggio...','Invia','Verifica in corso...']
};
function setLanguage(next){
 lang=T[next]?next:'fa';localStorage.setItem('pc_lang',lang);
 $('langFirst').value=lang;$('langHeader').value=lang;
 const a=T[lang];document.documentElement.lang=lang==='zh'?'zh-CN':lang;
 document.documentElement.dir=['fa','ar'].includes(lang)?'rtl':'ltr';
 $('tagline').textContent=a[0];$('settingsLabel').textContent=a[1];$('firstLangLabel').textContent=a[1];
 $('onlinePill').textContent=a[2];$('logout').textContent=a[3];$('loginTab').textContent=a[4];$('regTab').textContent=a[5];
 $('usernameLabel').textContent=a[6];$('passwordLabel').textContent=a[7];$('username').placeholder=a[8];$('password').placeholder=a[9];
 $('continueBtn').textContent=a[10];$('message').placeholder=a[12];$('sendBtn').textContent=a[13];
 if(token&&username)$('welcome').textContent=a[11].replace('{u}',username);
 setMode(mode);
}
function setMode(m){mode=m;$('loginTab').className=m==='login'?'':'secondary';$('regTab').className=m==='register'?'':'secondary';$('authNotice').textContent='';}
function showChat(){ $('auth').classList.add('hidden');$('chat').classList.remove('hidden');$('logout').classList.remove('hidden');$('langHeader').classList.remove('hidden');$('settingsLabel').classList.remove('hidden');$('welcome').textContent=T[lang][11].replace('{u}',username);loadMessages();if(poller)clearInterval(poller);poller=setInterval(loadMessages,2500);}
function logout(){token='';username='';lastId=0;localStorage.removeItem('pc_token');localStorage.removeItem('pc_user');if(poller)clearInterval(poller);$('chat').classList.add('hidden');$('logout').classList.add('hidden');$('langHeader').classList.add('hidden');$('settingsLabel').classList.add('hidden');$('auth').classList.remove('hidden');$('messages').innerHTML='';}
async function authenticate(){let u=$('username').value.trim(),p=$('password').value;$('authNotice').textContent=T[lang][14];try{let r=await fetch('/api/'+(mode==='register'?'register':'login'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});let d=await r.json();if(!r.ok)throw Error(d.detail||'Error');token=d.token;username=d.username;localStorage.setItem('pc_token',token);localStorage.setItem('pc_user',username);$('authNotice').textContent='';showChat();}catch(e){$('authNotice').textContent=e.message;}}
async function loadMessages(){if(!token)return;try{let r=await fetch('/api/messages?after='+lastId,{headers:{Authorization:'Bearer '+token}});if(r.status===401){logout();return}if(!r.ok)return;let arr=await r.json();for(let m of arr){lastId=Math.max(lastId,m.id);let div=document.createElement('div');div.className='msg';let strong=document.createElement('strong');strong.textContent=m.username+' : ';let body=document.createElement('span');body.textContent=m.body;let small=document.createElement('small');small.textContent=new Date(m.created_at).toLocaleString();div.append(strong,body,small);$('messages').append(div)}if(arr.length)$('messages').scrollTop=$('messages').scrollHeight;}catch(e){}}
async function sendMessage(){let box=$('message'),body=box.value.trim();if(!body)return;try{let r=await fetch('/api/messages',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify({body})});let d=await r.json();if(!r.ok)throw Error(d.detail||'Send failed');box.value='';await loadMessages();$('chatNotice').textContent='';}catch(e){$('chatNotice').textContent=e.message;}}
setLanguage(lang);if(token&&username)showChat();
</script>
</body></html>"""
