"""KeyProxy v9-deploy: secure multi-key OpenRouter proxy."""
import os, re, time, json, hmac, html, base64, secrets, logging, threading, http.client
from logging.handlers import RotatingFileHandler
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- env loading
def _load_env_file(path):
    """Load KEY=VALUE lines; never overrides variables already set (Render env wins)."""
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, _, v = ln.partition("=")
            k, v = k.strip(), v.strip()
            if k and v not in ("", "None", "null") and not os.environ.get(k):
                os.environ[k] = v


_load_env_file(os.path.join(BASE_DIR, ".env"))


def _csv(name):
    return {e.strip().lower() for e in os.environ.get(name, "").split(",") if e.strip()}


# --------------------------------------------------------------------- config
API_KEYS = []
_n = 1
while True:
    _k = os.environ.get(f"API_KEY_{_n}")
    if _k is None:
        break
    _k = _k.strip()
    if _k and _k not in API_KEYS:
        API_KEYS.append(_k)
    _n += 1

ENV_USERS = {}
for _k, _v in os.environ.items():
    if _k.startswith("PROXY_USER_"):
        _u, _v = _k[len("PROXY_USER_"):], _v.strip()
        if _u and _v and _v not in ("None", "null"):
            ENV_USERS[_u] = _v

OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "")
OAUTH_REDIRECT_URI = os.environ.get("OAUTH_REDIRECT_URI", "")
ADMIN_EMAILS = _csv("ADMIN_EMAILS")
ALLOWED_EMAILS = _csv("ALLOWED_EMAILS")
COOKIE_SECURE = OAUTH_REDIRECT_URI.startswith("https://")

SMART_MODEL = os.environ.get("SMART_MODEL", "apodex/apodex-1.1-mini:free")
WORKER_MODEL = os.environ.get("WORKER_MODEL", "thinkingmachines/inkling:free")
HELPER_MODEL = os.environ.get("HELPER_MODEL", WORKER_MODEL)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "4000"))
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)
os.makedirs(DATA_DIR, exist_ok=True)

VERSION = "v9-deploy"
UPSTREAM_HOST = "openrouter.ai"
UPSTREAM_PREFIX = "/api"

MAX_BODY = 10 * 1024 * 1024
MAX_FORM = 64 * 1024
SESSION_TTL = 8 * 3600
SMART_COOLDOWN = 60
WORKER_FAIL_LIMIT = 3

USER_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{24,128}$")

HARD_LEN = 400
HARD_WORDS = ("plan", "design", "architect", "refactor", "debug", "why", "fix",
              "implement", "migrate", "optimize", "investigate", "build",
              "analyze", "analyse", "research", "strategy", "compare")
HARD_RE = re.compile(r"\b(" + "|".join(HARD_WORDS) + r")\b")

IMMEDIATE = {401, 402}
COUNTED = {403, 429}
KEY_STATUSES = IMMEDIATE | COUNTED
FAIL_LIMIT = 3
DAILY_MARKERS = (b"free-models-per-day", b"per-day", b"per_day")
SKIP_REQ = {"host", "authorization", "x-api-key", "content-length",
            "connection", "accept-encoding", "transfer-encoding", "keep-alive"}
SKIP_RESP = {"transfer-encoding", "connection", "content-length", "keep-alive"}

# -------------------------------------------------------------------- logging
_logger = logging.getLogger("proxy")
_logger.setLevel(logging.INFO)
_fmt = logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S")
try:
    _fh = RotatingFileHandler(os.path.join(DATA_DIR, "proxy.log"),
                              maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    _fh.setFormatter(_fmt)
    _logger.addHandler(_fh)
except Exception:
    pass
_sh = logging.StreamHandler()
_sh.setFormatter(_fmt)
_logger.addHandler(_sh)


def log(msg):
    try:
        _logger.info(msg)
    except Exception:
        pass


def mask(key):
    return ("..." + key[-4:]) if key else "..."


# ----------------------------------------------------------------- user store
class UserStore:
    """Admin-managed users in users.json; env users (PROXY_USER_*) are immutable and win."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                d = json.load(f)
            self.data = {u: t for u, t in d.items()
                         if isinstance(u, str) and isinstance(t, str) and USER_RE.match(u)}
        except FileNotFoundError:
            pass
        except Exception as e:
            log("users.json load failed: %r" % (e,))

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        os.replace(tmp, self.path)

    def all(self):
        with self.lock:
            return {**self.data, **ENV_USERS}

    def tokens(self):
        return list(self.all().values())

    def stored(self):
        with self.lock:
            return dict(self.data)

    def add(self, user, token):
        with self.lock:
            if user in ENV_USERS:
                raise ValueError("user is defined in env and can't be changed here")
            self.data[user] = token
            self._save()

    def remove(self, user):
        with self.lock:
            if user in ENV_USERS or user not in self.data:
                return False
            del self.data[user]
            self._save()
            return True


USERS = UserStore(os.path.join(DATA_DIR, "users.json"))

# ------------------------------------------------------------------- sessions
_sessions = {}
_sessions_lock = threading.Lock()


def create_session(email):
    now = time.time()
    sid = secrets.token_urlsafe(32)
    with _sessions_lock:
        for k in [k for k, v in _sessions.items() if v["exp"] < now]:
            del _sessions[k]
        _sessions[sid] = {"email": email,
                          "role": "admin" if email in ADMIN_EMAILS else "user",
                          "csrf": secrets.token_urlsafe(24),
                          "exp": now + SESSION_TTL}
    return sid


def get_session(sid):
    if not sid:
        return None
    with _sessions_lock:
        s = _sessions.get(sid)
        if s and s["exp"] < time.time():
            del _sessions[sid]
            return None
        return s


def get_cookie(headers, name):
    for part in headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return None


def cookie_header(name, value, max_age):
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={max_age}"]
    if COOKIE_SECURE:
        parts.append("Secure")
    return "; ".join(parts)


# ---------------------------------------------------------------- Google OAuth
def oauth_configured():
    return bool(OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET and OAUTH_REDIRECT_URI)


def make_google_auth_url(state):
    params = {"client_id": OAUTH_CLIENT_ID, "redirect_uri": OAUTH_REDIRECT_URI,
              "response_type": "code", "scope": "openid email",
              "state": state, "prompt": "select_account"}
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)


def _b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def exchange_code(code):
    """Exchange auth code at Google's token endpoint (server-to-server TLS, with client secret)
    and return the verified lowercase email, or None. The ID token comes straight from Google over
    TLS, so per OIDC Core 3.1.3.7 signature checking is optional; iss/aud/exp/email_verified are checked."""
    body = urlencode({"code": code, "client_id": OAUTH_CLIENT_ID,
                      "client_secret": OAUTH_CLIENT_SECRET,
                      "redirect_uri": OAUTH_REDIRECT_URI,
                      "grant_type": "authorization_code"}).encode()
    conn = None
    try:
        conn = http.client.HTTPSConnection("oauth2.googleapis.com", timeout=15)
        conn.request("POST", "/token", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        r = conn.getresponse()
        data = r.read()
        if r.status != 200:
            log("oauth token exchange failed: HTTP %d" % r.status)
            return None
        idt = json.loads(data).get("id_token", "")
        parts = idt.split(".")
        if len(parts) < 2:
            log("oauth id_token malformed (not enough segments)")
            return None
        claims = json.loads(_b64url(parts[1]))
        if claims.get("iss") not in ("https://accounts.google.com", "accounts.google.com"):
            return None
        aud = claims.get("aud")
        if aud != OAUTH_CLIENT_ID and not (isinstance(aud, list) and OAUTH_CLIENT_ID in aud):
            return None
        if float(claims.get("exp", 0)) < time.time():
            return None
        if claims.get("email_verified") not in (True, "true"):
            return None
        email = str(claims.get("email", "")).strip().lower()
        return email or None
    except Exception as e:
        log("oauth error: %r" % (e,))
        return None
    finally:
        if conn:
            conn.close()


# ------------------------------------------------------------------ HTML pages
CSS_TEMPLATE = """
<style>:root{--bg:#f5f3eb;--fg:#181810;--card:#ebe8d6;--accent:#888899;--accent-deep:#777788;--border:#d4d0c5;--surface:#f0ede4;--surface-alt:#ebe8d6;--text-muted:#777766;}
[data-theme="dark"]{--bg:#0b0c15;--fg:#e8e6f0;--card:#16161d;--accent:#888899;--accent-deep:#777788;--border:#2a2a30;--surface:#12121a;--surface-alt:#16161d;--text-muted:#888899;}
*{box-sizing:border-box;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:0;}
body{background:var(--bg);color:var(--fg);min-height:100vh;padding:40px 20px;line-height:1.55;transition:background .25s ease,color .25s ease;}
.container{max-width:780px;margin:0 auto;}
h1{font-size:32px;font-weight:700;margin-bottom:24px;color:var(--fg);letter-spacing:-0.5px;}
h2{font-size:18px;margin:28px 0 14px;font-weight:600;}
.card{background:var(--card);border:1px solid var(--border);border-radius:0;padding:24px;box-shadow:0 4px 16px rgba(0,0,0,.12);margin-bottom:20px;transition:background .25s ease,border-color .25s ease,box-shadow .25s ease;}
[data-theme="dark"] .card{box-shadow:0 4px 24px rgba(0,0,0,.35);}
.table-glass{width:100%;border-collapse:collapse;font-size:14px;}
.table-glass th,.table-glass td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--border);transition:border-color .25s ease;}
.table-glass th{font-weight:600;opacity:.8;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--text-muted);}
.btn{display:inline-flex;align-items:center;gap:6px;background:linear-gradient(135deg,#888899,#777788);color:#f0f0f5;padding:10px 22px;border:none;border-radius:0;cursor:pointer;font-weight:700;font-size:14px;text-decoration:none;box-shadow:0 2px 10px rgba(136,137,152,.35);transition:transform .12s ease,box-shadow .2s ease,background .2s ease;}
.btn:hover{transform:translateY(-2px);box-shadow:0 6px 18px rgba(136,137,152,.45);}
.btn:active{transform:translateY(0);box-shadow:0 2px 6px rgba(136,137,152,.3);}
.btn-secondary{background:transparent;border:2px solid #888899;color:#888899;box-shadow:none;padding:8px 20px;border-radius:0;transition:background .2s ease,border-color .2s ease;}
.btn-secondary:hover{background:rgba(136,137,152,.08);box-shadow:0 2px 8px rgba(136,137,152,.15);}
input[type="text"]{background:var(--surface);border:1.5px solid var(--border);color:var(--fg);padding:10px 12px;border-radius:0;font-size:14px;width:220px;margin-right:6px;transition:background .2s ease,border-color .2s ease,color .2s ease;outline:none;}
input[type="text"]:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(136,137,152,.25);}
input[name="token"]{width:260px;}
.login-card{position:relative;max-width:440px;margin:120px auto;background:var(--card);border:1px solid var(--border);border-radius:0;padding:48px 40px;box-shadow:0 10px 40px rgba(0,0,0,.12);text-align:center;transition:background .25s ease,border-color .25s ease,box-shadow .25s ease;}
.login-card h1{margin-bottom:6px;font-size:42px;font-weight:800;color:var(--fg);letter-spacing:-2px;}
.login-card .key{color:#e8a84c;}
.login-card .proxy{color:#d6a241;}
.login-card .subtitle{color:var(--text-muted);font-size:15px;margin-bottom:28px;}
.login-card .btn{display:inline-flex;align-items:center;gap:8px;background:linear-gradient(135deg,#888899,#777788);color:#f0f0f5;padding:14px 32px;border:none;border-radius:0;cursor:pointer;font-weight:800;font-size:16px;text-decoration:none;box-shadow:0 4px 16px rgba(136,137,152,.3);transition:transform .1s ease,box-shadow .2s ease,background .2s ease;}
.login-card .btn:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(136,137,152,.45);}
.login-card .btn:active{transform:translateY(0);box-shadow:0 2px 8px rgba(136,137,152,.3);}
.theme-btn{position:fixed;top:18px;right:18px;background:var(--card);border:1.5px solid var(--border);color:var(--fg);padding:8px 16px;border-radius:0;cursor:pointer;font-size:13px;font-weight:700;display:inline-flex;align-items:center;gap:6px;box-shadow:0 2px 8px rgba(0,0,0,.08);transition:background .2s ease,border-color .2s ease,transform .12s ease;}
.theme-btn:hover{transform:translateY(-1px);box-shadow:0 4px 10px rgba(0,0,0,.14);}
.theme-btn .icon{font-size:16px;line-height:1;}
.tag{display:inline-block;padding:3px 10px;border-radius:0;font-size:11px;font-weight:800;background:var(--accent);color:#0d0d0d;letter-spacing:.2px;transition:background .2s ease;}
.tag.admin{background:#888899;color:#fff;}
footer{text-align:center;padding:28px;font-size:12px;opacity:.55;color:var(--text-muted);transition:color .25s ease;}
</style>
"""

def _page(title, body):
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>%s</title>%s</head><body data-theme='light'><div class='container'>%s</div><footer></footer><script>document.body.setAttribute('data-theme',localStorage.getItem('theme')||'light');function toggleTheme(){const d=document.body.getAttribute('data-theme');const n=d==='light'?'dark':'light';document.body.setAttribute('data-theme',n);localStorage.setItem('theme',n);}</script></body></html>"
            % (html.escape(title), CSS_TEMPLATE, body))


def build_login_page():
    if not oauth_configured():
        body = "<div class='login-card'><h1>KEYPROXY</h1><p class='notice'>OAuth not configured.</p></div>"
        return _page("Sign In", body)
    theme_btn = '<button class="theme-btn" onclick="toggleTheme()" title="Toggle theme">&#9728; / &#9789;</button>'
    body = ("<div class='login-card'><h1><span class='key'>KEY</span><span class='proxy'>PROXY</span></h1>"
            "<p class='subtitle'>Secure multi-key OpenRouter proxy</p>"
            "<a href='/auth/google' class='btn'><span style='display:inline-flex;align-items:center;justify-content:center;width:20px;height:20px;margin-right:6px;vertical-align:middle;'><svg width='20' height='20' viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'><path d='M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.72h3.57c2.08-1.92 3.28-4.75 3.28-8.05z' fill='#4285f4'/><path d='M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.72c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z' fill='#34a853'/><path d='M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.66-2.84z' fill='#fbbc05'/><path d='M12 5.38c1.62 0 3.06.56 4.2 1.64l3.12-3.12C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l2.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z' fill='#ea4335'/></svg></span> SIGN IN WITH GOOGLE</a>"
            "</div>" + theme_btn)
    return _page("KEYPROXY — Sign In", body)


def build_admin_page(session, notice=""):
    csrf = html.escape(session["csrf"])
    user_cards = []
    for user, token in sorted(USERS.all().items()):
        u = html.escape(user)
        if user in ENV_USERS:
            tag = '<span class="tag admin">env-admin</span>'
        else:
            tag = '<span class="tag">user</span>'
        # User card with username, admin tag, and remove option
        masked_text = html.escape(mask(token))
        full_text = html.escape(token)
        token_display = '<span style="font-family:monospace;font-size:12px;color:var(--text-muted);">%s</span> <span style="cursor:pointer;font-size:11px;color:var(--accent);vertical-align:middle;" title="Show" onclick="this.previousElementSibling.style.display=\'none\';this.nextElementSibling.style.display=\'inline\';this.style.display=\'none\';">&#9678;</span> <span style="display:none;font-family:monospace;font-size:12px;color:var(--fg);">%s</span> <span style="cursor:pointer;font-size:11px;color:var(--accent);vertical-align:middle;" title="Copy" onclick="navigator.clipboard.writeText(this.previousElementSibling.innerText);">&#128462;</span>' % (masked_text, full_text)
        user_cards.append(
            '<div class="card" style="margin-bottom:14px;padding:18px 20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;background:var(--card);border:1px solid var(--border);border-radius:0;">'
            '<div style="min-width:0;flex:1;">'
            '<div style="font-weight:700;font-size:16px;margin-bottom:4px;color:var(--fg);">%s %s</div>'
            '<div style="margin-top:2px;">%s</div>'
            '</div>'
            '<div style="margin-left:auto;display:flex;align-items:center;gap:8px;">'
            '<form method="POST" action="/admin/users/remove" style="display:inline;">'
            '<input type="hidden" name="csrf" value="%s">'
            '<input type="hidden" name="user" value="%s">'
            '<button style="background:#777777;color:#fff;border:none;padding:5px 10px;border-radius:0;font-size:10px;font-weight:700;cursor:pointer;">&#10005;</button>'
            '</form>'
            '</div></div>' % (u, tag, token_display, csrf, u)
        )
    user_cards_html = "\n".join(user_cards)
    note = '<p style="margin-bottom:16px;color:#e8a84c;font-size:14px;"><b>%s</b></p>' % html.escape(notice) if notice else ""
    theme_btn = '<button class="theme-btn" onclick="toggleTheme()" title="Toggle theme">&#9728; / &#9789;</button>'
    signout = '<form method="POST" action="/auth/logout" style="display:inline;margin-left:8px;"><button class="btn btn-secondary">Sign out</button></form>'
    body_header = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;flex-wrap:wrap;gap:10px;"><h1 style="margin:0;font-size:28px;color:var(--fg);font-weight:800;letter-spacing:-0.5px;">Proxy Admin</h1><div>%s %s</div></div>' % (theme_btn, signout)
    # ADD USER form: username input + ADD USER button
    add_form = (
        '<form method="POST" action="/admin/users/add" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">'
        '<input type="hidden" name="csrf" value="%s">'
        '<input name="user" placeholder="e.g. staging-worker" required style="background:var(--bg);border:1.5px solid var(--border);color:var(--fg);padding:9px 12px;border-radius:0;font-size:14px;width:220px;">'
        '<button type="submit" style="background:#777777;color:#fff;border:none;padding:10px 22px;border-radius:0;font-weight:700;font-size:14px;cursor:pointer;">ADD USER</button>'
        '</form>'
    ) % csrf
    body = (
        body_header +
        '<p style="font-size:13px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:16px;">PROXY USERS</p>' +
        note +
        user_cards_html +
        '<h2 style="margin-top:32px;margin-bottom:12px;font-weight:700;font-size:18px;color:var(--fg);">Add User</h2>'
        '<div class="card" style="padding:20px;background:var(--surface);border:1px solid var(--border);border-radius:0;">'
        '%s'
        '<p style="font-size:12px;color:var(--text-muted);margin-top:12px;margin-bottom:0;">User: A-Z, a-z, 0-9, _, - (max 64). Token: 24-128 chars.</p>'
        '</div>'
        % add_form
    )
    return _page("Proxy Admin", body)


def build_user_page(email):
    name = email.split("@")[0]
    token = USERS.all().get(name)
    theme_btn = '<button class="theme-btn" onclick="toggleTheme()" title="Toggle theme"><span class="icon">&#9728; / &#9789;</span></button>'
    signout = '<form method="POST" action="/auth/logout" style="display:inline;margin-left:8px;"><button class="btn btn-secondary">Sign out</button></form>'
    header = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:8px;"><h1 style="margin:0;font-size:26px;color:var(--fg);">My Status</h1><div>%s %s</div></div>' % (theme_btn, signout)
    body = header + "<div class='card'><table class='table-glass'><tbody><tr><th>User</th><td>%s</td></tr><tr><th>Token (masked)</th><td>%s</td></tr></tbody></table></div>" % (html.escape(email), html.escape(mask(token)) if token else "none")
    return _page("My Status", body)


# --------------------------------------------------------------- model routing
def _block_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _block_types(content):
    if isinstance(content, list):
        return [str(b.get("type")) for b in content if isinstance(b, dict)]
    return ["text"] if isinstance(content, str) else []


def _has_tool_block(msg):
    return isinstance(msg, dict) and any("tool" in t for t in _block_types(msg.get("content")))


def _is_human_turn(msg):
    return isinstance(msg, dict) and msg.get("role") == "user" and not _has_tool_block(msg)


def _has_image_block(msg):
    content = msg.get("content") if isinstance(msg, dict) else None
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "image_url" for b in content)
    return False


def _msg_has_image(msgs):
    if not isinstance(msgs, list):
        return False
    return any(_has_image_block(m) for m in msgs if isinstance(m, dict))


SMART_L = SMART_MODEL.lower()
WORKER_L = WORKER_MODEL.lower()


def is_smart(model):
    return bool(model) and str(model).lower() == SMART_L and SMART_L != WORKER_L


def is_worker(model):
    return bool(model) and str(model).lower() == WORKER_L


class RouteState:
    """Shared routing state (locked). Smart-model cooldown is time-based; worker failures are real failures."""

    def __init__(self):
        self.lock = threading.Lock()
        self.worker_fails = 0
        self.smart_fails = 0
        self.smart_until = 0.0

    def smart_available(self):
        with self.lock:
            return time.time() >= self.smart_until

    def limit_smart(self):
        with self.lock:
            self.smart_until = time.time() + SMART_COOLDOWN

    def worker_result(self, ok):
        with self.lock:
            self.worker_fails = 0 if ok else self.worker_fails + 1

    def smart_result(self, ok):
        with self.lock:
            self.smart_fails = 0 if ok else self.smart_fails + 1

    def escalate(self):
        with self.lock:
            if self.smart_fails >= 2 and time.time() >= self.smart_until:
                self.smart_fails = 0
                return True
            return False


ROUTE = RouteState()


def pick_model(obj):
    msgs = obj.get("messages") if isinstance(obj.get("messages"), list) else []
    has_tools = bool(obj.get("tools"))
    if "haiku" in str(obj.get("model") or "").lower():
        return WORKER_MODEL, "background (haiku)"
    if not has_tools:
        return HELPER_MODEL, "helper (no tools)"
    if ROUTE.escalate():
        return WORKER_MODEL, "smart failed %dx -> switch to worker" % WORKER_FAIL_LIMIT
    if not msgs:
        return WORKER_MODEL, "no messages"
    if _msg_has_image(msgs):
        return WORKER_MODEL, "image in prompt -> worker"
    last_human = -1
    for i in range(len(msgs) - 1, -1, -1):
        if _is_human_turn(msgs[i]):
            last_human = i
            break
    if last_human < 0:
        return WORKER_MODEL, "no human turn"
    if any(_has_tool_block(m) for m in msgs[last_human + 1:]):
        return WORKER_MODEL, "execution (tools used since prompt)"
    text = _block_text(msgs[last_human].get("content")).lower()
    human_turns = sum(1 for m in msgs if _is_human_turn(m))
    reason = None
    if human_turns <= 1:
        reason = "task start (first prompt)"
    elif len(text) > HARD_LEN:
        reason = "task start (long prompt)"
    elif HARD_RE.search(text):
        reason = "task start (hard keyword)"
    if reason is None:
        return WORKER_MODEL, "task start (simple follow-up)"
    if not ROUTE.smart_available():
        return WORKER_MODEL, reason + ", smart cooling down"
    return SMART_MODEL, reason


def route_model(path, body):
    """Returns (body, model_used). model_used is None if the request wasn't a model request."""
    if not body:
        return body, None
    try:
        obj = json.loads(body)
    except Exception:
        return body, None
    if not isinstance(obj, dict):
        return body, None
    clean = path.split("?")[0].rstrip("/")
    if "model" in obj or clean.endswith(("/messages", "/chat/completions", "/completions")):
        orig = obj.get("model")
        model, reason = pick_model(obj)
        obj["model"] = model
        msgs = obj.get("messages")
        last = msgs[-1] if isinstance(msgs, list) and msgs and isinstance(msgs[-1], dict) else {}
        log("route: %r -> %s [%s] msgs=%d tools=%d last=%s%s" % (
            orig, model, reason,
            len(msgs) if isinstance(msgs, list) else 0,
            len(obj.get("tools") or []),
            last.get("role"), _block_types(last.get("content"))))
        return json.dumps(obj).encode("utf-8"), model
    return body, None


def set_body_model(body, model):
    try:
        obj = json.loads(body)
        obj["model"] = model
        return json.dumps(obj).encode("utf-8")
    except Exception:
        return body


# ------------------------------------------------------------------- key state
class KeyState:
    def __init__(self, keys):
        self.keys = list(keys)
        self.fails = 0
        self.lock = threading.Lock()

    def current(self):
        with self.lock:
            return self.keys[0] if self.keys else None

    def count(self):
        with self.lock:
            return len(self.keys)

    def ok(self, key):
        with self.lock:
            if self.keys and self.keys[0] == key:
                self.fails = 0

    def fail(self, key, status, immediate=False, reason=""):
        with self.lock:
            if len(self.keys) < 2:
                return False
            if self.keys[0] != key:
                return True
            self.fails += 1
            if immediate or status in IMMEDIATE or self.fails >= FAIL_LIMIT:
                old = self.keys.pop(0)
                self.keys.append(old)
                self.fails = 0
                msg = "key %s hit HTTP %d%s -> now using %s (%d keys)" % (
                    mask(old), status, (" (" + reason + ")") if reason else "",
                    mask(self.keys[0]), len(self.keys))
                log("ROTATE " + msg)
                return True
            return False


STATE = None

SEC_HEADERS = (("Cache-Control", "no-store"),
               ("X-Content-Type-Options", "nosniff"),
               ("X-Frame-Options", "DENY"),
               ("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"))

ROUTES = {
    ("GET", "/healthz"): "h_health",
    ("HEAD", "/healthz"): "h_health",
    ("GET", "/admin/users"): "h_admin",
    ("POST", "/admin/users/add"): "h_admin_add",
    ("POST", "/admin/users/remove"): "h_admin_remove",
    ("GET", "/user/status"): "h_status",
    ("GET", "/login"): "h_login",
    ("GET", "/auth/google"): "h_auth_google",
    ("GET", "/auth/callback"): "h_auth_callback",
    ("POST", "/auth/logout"): "h_auth_logout",
}
LOCAL_PATHS = {p for _, p in ROUTES}


def client_token(headers):
    auth = headers.get("Authorization", "")
    if auth[:7].lower() == "bearer ":
        return auth[7:].strip()
    return (headers.get("x-api-key") or "").strip()


def token_ok(tok):
    if not tok:
        return False
    tb = tok.encode("utf-8", "replace")
    ok = False
    for t in USERS.tokens():  # no early exit: constant-ish time over all tokens
        if hmac.compare_digest(t.encode("utf-8", "replace"), tb):
            ok = True
    return ok


class Handler(BaseHTTPRequestHandler):
    server_version = "keyproxy/%s" % VERSION

    def log_message(self, *a):
        pass

    def log_error(self, *a):
        pass

    # ---- helpers
    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        return xff.split(",")[0].strip() if xff else self.client_address[0]

    def _send(self, status, data, ctype, extra=()):
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in SEC_HEADERS:
                self.send_header(k, v)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
        except Exception:
            pass

    def send_json(self, status, message):
        body = json.dumps({"type": "error", "error": {"type": "api_error", "message": message}}).encode()
        self._send(status, body, "application/json")

    def send_html(self, status, page, extra=()):
        self._send(status, page.encode("utf-8"), "text/html; charset=utf-8", extra)

    def redirect(self, location, status=302, cookies=()):
        try:
            self.send_response(status)
            self.send_header("Location", location)
            for c in cookies:
                self.send_header("Set-Cookie", c)
            for k, v in SEC_HEADERS:
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        except Exception:
            pass

    def send_buffered(self, status, headers, data):
        try:
            self.send_response(status)
            for k, v in headers:
                if k.lower() not in SKIP_RESP:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    def current_session(self):
        return get_session(get_cookie(self.headers, "proxy_session"))

    def read_form(self):
        try:
            n = max(0, int(self.headers.get("Content-Length") or 0))
        except ValueError:
            n = 0
        if n > MAX_FORM:
            return None
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def _admin_post(self):
        """Returns (session, form) for a valid admin POST with CSRF token, else sends an error and returns (None, None)."""
        s = self.current_session()
        if not s or s["role"] != "admin":
            self.send_html(403, _page("Forbidden", "<h1>403 Forbidden</h1>"))
            return None, None
        form = self.read_form()
        if form is None:
            self.send_json(413, "Form too large")
            return None, None
        if not hmac.compare_digest(form.get("csrf", "").encode(), s["csrf"].encode()):
            self.send_html(403, _page("Forbidden", "<h1>403 Bad CSRF token</h1>"))
            return None, None
        return s, form

    # ---- local routes
    def h_health(self):
        self._send(200, b"ok", "text/plain")

    def h_admin(self):
        s = self.current_session()
        if not s:
            return self.redirect("/login")
        if s["role"] != "admin":
            return self.send_html(403, _page("Forbidden", "<h1>403 Forbidden</h1><p>Admin access required.</p>"))
        self.send_html(200, build_admin_page(s))

    def h_status(self):
        s = self.current_session()
        if not s:
            return self.redirect("/login")
        self.send_html(200, build_user_page(s["email"]))

    def h_auth_google(self):
        if not oauth_configured():
            return self.send_html(500, _page("Error", "OAuth not configured "
                                  "(OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET / OAUTH_REDIRECT_URI)"))
        state = secrets.token_urlsafe(24)
        self.redirect(make_google_auth_url(state), cookies=[cookie_header("oauth_state", state, 600)])

    def h_auth_callback(self):
        if not oauth_configured():
            return self.send_html(500, _page("Error", "OAuth not configured"))
        qs = parse_qs(urlparse(self.path).query)
        code = qs.get("code", [""])[0]
        state = qs.get("state", [""])[0]
        expected = get_cookie(self.headers, "oauth_state") or ""
        if not code or not expected or not hmac.compare_digest(state.encode(), expected.encode()):
            return self.send_html(400, _page("Error", "<h1>400 Bad OAuth state</h1>"))
        email = exchange_code(code)
        if not email:
            return self.send_html(401, _page("Error", "<h1>401 Login failed</h1>"))
        if email not in ADMIN_EMAILS and email not in ALLOWED_EMAILS:
            log("login denied for %s from %s" % (email, self.client_ip()))
            return self.send_html(403, _page("Forbidden", "<h1>403 Not authorized</h1>"),
                                  extra=[("Set-Cookie", cookie_header("oauth_state", "", 0))])
        sid = create_session(email)
        log("login ok: %s (%s)" % (email, "admin" if email in ADMIN_EMAILS else "user"))
        self.redirect("/admin/users" if email in ADMIN_EMAILS else "/user/status",
                      cookies=[cookie_header("proxy_session", sid, SESSION_TTL),
                               cookie_header("oauth_state", "", 0)])

    def h_admin_add(self):
        s, form = self._admin_post()
        if not s:
            return
        user = form.get("user", "").strip()
        token = form.get("token", "").strip()
        if not USER_RE.match(user):
            return self.send_html(400, build_admin_page(s, "Invalid username."))
        generated = False
        if not token:
            token, generated = secrets.token_urlsafe(32), True
        if not TOKEN_RE.match(token):
            return self.send_html(400, build_admin_page(s, "Invalid token format."))
        try:
            USERS.add(user, token)
        except ValueError as e:
            return self.send_html(400, build_admin_page(s, str(e)))
        except Exception as e:
            log("users.json save failed: %r" % (e,))
            return self.send_html(500, build_admin_page(s, "Failed to save user."))
        log("admin %s added user %s" % (s["email"], user))
        msg = "Added %s." % user + (" Token (shown once): %s" % token if generated else "")
        self.send_html(200, build_admin_page(s, msg))

    def h_admin_remove(self):
        s, form = self._admin_post()
        if not s:
            return
        user = form.get("user", "").strip()
        ok = USERS.remove(user) if USER_RE.match(user) else False
        log("admin %s removed user %s -> %s" % (s["email"], user, ok))
        self.redirect("/admin/users", status=303)

    def h_login(self):
        s = self.current_session()
        if s:
            return self.redirect("/admin/users" if s["role"] == "admin" else "/user/status")
        self.send_html(200, build_login_page())

    def h_auth_logout(self):
        self.redirect("/login", cookies=[cookie_header("proxy_session", "", 0), cookie_header("oauth_state", "", 0)])

    # ---- proxy
    def handle_any(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        name = ROUTES.get((self.command, path))
        if name:
            return getattr(self, name)()
        if path in LOCAL_PATHS:
            return self.send_json(405, "Method not allowed")

        self.close_connection = True

        # Fail closed: no users configured -> nobody gets in.
        if not USERS.all():
            log("503 no proxy users configured; rejecting %s" % self.client_ip())
            return self.send_json(503, "Proxy has no users configured")
        if not token_ok(client_token(self.headers)):
            log("401 unauthorized from %s" % self.client_ip())
            return self.send_json(401, "Unauthorized: invalid or missing token")

        if self.command == "GET" and path.endswith("/models"):
            return self.handle_models()

        try:
            n = max(0, int(self.headers.get("Content-Length") or 0))
        except ValueError:
            n = 0
        if n > MAX_BODY:
            return self.send_json(413, "Request body too large")
        body = self.rfile.read(n) if n else b""
        body, model_used = route_model(self.path, body)
        fwd = {k: v for k, v in self.headers.items() if k.lower() not in SKIP_REQ}
        fwd["Accept-Encoding"] = "identity"

        attempts = 0
        while True:
            key = STATE.current()
            if key is None:
                log("503 no keys in env (API_KEY_*)")
                return self.send_json(503, "No OpenRouter keys found in env (API_KEY_*)")
            fwd["Authorization"] = "Bearer " + key
            conn = None
            try:
                conn = http.client.HTTPSConnection(UPSTREAM_HOST, timeout=300)
                conn.request(self.command, UPSTREAM_PREFIX + self.path, body=body or None, headers=fwd)
                resp = conn.getresponse()
            except Exception as e:
                log("upstream error: %r" % (e,))
                if conn:
                    conn.close()
                if is_worker(model_used):
                    ROUTE.worker_result(False)
                if is_smart(model_used):
                    ROUTE.smart_result(False)
                return self.send_json(502, "Upstream connection error: %r" % (e,))

            st = resp.status

            # Smart model rate-limited: rotate key immediately and retry on smart.
            if st == 429 and is_smart(model_used):
                resp.read()
                conn.close()
                ROUTE.smart_result(False)
                log("smart model %s hit 429 -> rotating key, retrying smart" % (model_used,))
                # Force key rotation (mimic fail behavior for rotation without counting fails)
                with STATE.lock:
                    if STATE.keys:
                        old = STATE.keys.pop(0)
                        STATE.keys.append(old)
                        STATE.fails = 0
                if ROUTE.escalate():
                    model_used = WORKER_MODEL
                    body = set_body_model(body, WORKER_MODEL)
                    log('smart model rate-limited -> falling back to worker')
                else:
                    model_used = SMART_MODEL  # retry same smart model with new key
                    body = set_body_model(body, SMART_MODEL)
                continue

            if st in KEY_STATUSES:
                data = resp.read()
                headers = resp.getheaders()
                conn.close()
                low = data.lower()
                daily = st == 429 and any(m in low for m in DAILY_MARKERS)
                log("%s %s -> %d (key %s) body: %s" % (
                    self.command, self.path, st, mask(key),
                    data[:300].decode("utf-8", "replace").replace("\n", " ")))
                if STATE.fail(key, st, immediate=daily, reason="daily quota" if daily else ""):
                    attempts += 1
                    if attempts >= STATE.count():
                        log("503 all keys failed this request, will retry on next")
                        return self.send_json(503, "All OpenRouter keys exhausted (will retry)")
                    continue
                return self.send_buffered(st, headers, data)

            if st < 400:
                STATE.ok(key)
            if is_worker(model_used):
                ROUTE.worker_result(st < 400)
            if is_smart(model_used):
                ROUTE.smart_result(st < 400)
            log("%s %s -> %d (key %s)" % (self.command, self.path, st, mask(key)))
            try:
                self.send_response(st)
                for k, v in resp.getheaders():
                    if k.lower() not in SKIP_RESP:
                        self.send_header(k, v)
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = resp.read1(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                pass
            finally:
                conn.close()
            return

    def handle_models(self):
        ids = [SMART_MODEL] if SMART_MODEL == WORKER_MODEL else [SMART_MODEL, WORKER_MODEL]
        body = json.dumps({
            "object": "list",
            "data": [{"id": m, "object": "model", "type": "model",
                      "display_name": m, "owned_by": "openrouter"} for m in ids],
            "has_more": False, "first_id": ids[0], "last_id": ids[-1],
        }).encode("utf-8")
        log("GET %s -> 200 (local models list)" % self.path)
        self._send(200, body, "application/json")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = handle_any


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global STATE
    STATE = KeyState(API_KEYS)
    if not API_KEYS:
        log("WARNING: no API_KEY_* set; proxied requests will 503")
    if not USERS.all():
        log("WARNING: no proxy users (PROXY_USER_* or users.json); all proxied requests will be rejected until one is added")
    if not oauth_configured():
        log("WARNING: OAuth not fully configured; admin/user dashboards unavailable")
    elif not ADMIN_EMAILS:
        log("WARNING: ADMIN_EMAILS empty; nobody can access the admin page")
    try:
        server = Server((HOST, PORT), Handler)
    except OSError as e:
        log("could not bind %s:%d: %r" % (HOST, PORT, e))
        return
    log("keyproxy %s listening on http://%s:%d | %d keys | smart %s | worker %s | helper %s" % (
        VERSION, HOST, PORT, len(API_KEYS), SMART_MODEL, WORKER_MODEL, HELPER_MODEL))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        log("stopped")


if __name__ == "__main__":
    main()
