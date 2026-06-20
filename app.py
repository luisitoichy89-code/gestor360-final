from flask import Flask, request, session, redirect, url_for, g, jsonify, send_from_directory, make_response
from supabase import create_client
import sqlite3, secrets, os, datetime, math, hashlib, threading, time, shutil, uuid, re, logging
from logging.handlers import RotatingFileHandler

# Carga variables desde .env si existe (python-dotenv opcional)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Las credenciales de Supabase NUNCA deben escribirse en el código.
# Defínelas como variables de entorno o en un archivo .env (no subir a git):
#   SUPABASE_URL=https://xxxx.supabase.co
#   SUPABASE_KEY=xxxxxxxxxxxxxxxx
SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
else:
    supabase = None
    print('⚠️  SUPABASE_URL / SUPABASE_KEY no configuradas. Sync con Supabase deshabilitado.')

DB_PATH     = os.path.join(os.path.dirname(__file__), 'local.db')
BACKUP_PATH = os.path.join(os.path.dirname(__file__), 'local_backup.db')
SECLOG_PATH = os.path.join(os.path.dirname(__file__), 'security.log')
LOGIN_ATTEMPTS  = {}   # ip -> [timestamps]
PIN_ATTEMPTS    = {}
FAILED_LOGINS   = {}   # username -> count de intentos fallidos consecutivos
LOCKED_ACCOUNTS = {}   # username -> datetime hasta el que está bloqueada
MAX_FAILED_LOGIN = 10
LOCK_MINUTES      = 30

# --- Logger de seguridad (archivo rotativo, además de tabla seguridad_logs) ---
sec_logger = logging.getLogger('security')
sec_logger.setLevel(logging.INFO)
if not sec_logger.handlers:
    _h = RotatingFileHandler(SECLOG_PATH, maxBytes=1_000_000, backupCount=3, encoding='utf-8')
    _h.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    sec_logger.addHandler(_h)

def log_security(evento, detalle='', ip=''):
    try:
        sec_logger.info(evento + ' | ' + detalle + ' | IP:' + ip)
        db = sqlite3.connect(DB_PATH)
        db.execute("INSERT INTO seguridad_logs (evento,detalle,ip,created_at) VALUES (?,?,?,?)",
                   (evento, detalle, ip, datetime.datetime.now().isoformat()))
        db.commit(); db.close()
    except Exception:
        pass

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
CREATE TABLE IF NOT EXISTS locales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL, activo BOOLEAN DEFAULT 1, created_at TEXT);
CREATE TABLE IF NOT EXISTS usuarios ( 
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, password TEXT DEFAULT '',
    nombre TEXT, rol TEXT, pin TEXT DEFAULT '',
    almacen_id TEXT, activo BOOLEAN DEFAULT 1);
CREATE TABLE IF NOT EXISTS productos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT, precio REAL, stock INTEGER, almacen_id TEXT);
CREATE TABLE IF NOT EXISTS ventas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    producto_id INTEGER, producto_nombre TEXT,
    cantidad REAL, precio_unit REAL, total REAL,
    metodo TEXT, efectivo REAL, transferencia REAL,
    usuario_id INTEGER,  almacen_id TEXT,
    cliente_ci TEXT, cliente_tel TEXT, cliente_nombre TEXT,
    created_at TEXT);
CREATE TABLE IF NOT EXISTS trazas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario TEXT,  accion TEXT, detalle TEXT,    almacen_id TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS tarjetas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    banco TEXT, numero TEXT, almacen_id TEXT); 
CREATE TABLE IF NOT EXISTS licencias (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE, almacen_id TEXT,
    expiracion TEXT, activo BOOLEAN DEFAULT 1, created_at TEXT);
CREATE TABLE IF NOT EXISTS seguridad_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evento TEXT, detalle TEXT, ip TEXT, created_at TEXT);
""")
    db.commit()
    if db.execute("SELECT COUNT(*) FROM locales").fetchone()[0] == 0:
        db.execute("INSERT INTO locales (id,nombre,created_at) VALUES (1,'Local Principal',datetime('now'))")
        db.commit()
    if db.execute("SELECT COUNT(*) FROM usuarios WHERE rol='superadmin'").fetchone()[0] == 0:
        db.execute("INSERT INTO usuarios (username,password,nombre,rol,pin,almacen_id) VALUES (?,?,?,?,?,?)",
                   ('admin', hashlib.sha256('admin123'.encode()).hexdigest(), 'SUPER ADMIN', 'superadmin', '123456', '1'))
        db.commit()
    db.close()

@app.teardown_appcontext
def close_db(e):
    db = g.pop('db', None)
    if db: db.close()

def get_almacen():
    if 'almacen_activo' in session: return session['almacen_activo']
    u = session.get('user')
    return str(u.get('almacen_id','1')).split(',')[0].strip() if u else '1'

def get_almacenes_usuario():
    u = session.get('user')
    if not u: return ['1']
    return [x.strip() for x in str(u.get('almacen_id','1')).split(',') if x.strip()]

def add_trace(usuario, accion, detalle, almacen_id):
    try:
        db = sqlite3.connect(DB_PATH)
        db.execute("INSERT INTO trazas (usuario,accion,detalle,almacen_id,created_at) VALUES (?,?,?,?,?)",
                   (usuario, accion, detalle, almacen_id, datetime.datetime.now().isoformat()))
        db.commit(); db.close()
    except: pass

def auto_backup():
    while True:
        time.sleep(3600)
        try: shutil.copy2(DB_PATH, BACKUP_PATH)
        except: pass

threading.Thread(target=auto_backup, daemon=True).start()

def check_rate_limit(ip):
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 300]
    LOGIN_ATTEMPTS[ip] = attempts
    if len(attempts) >= 5:
        log_security('RATE_LIMIT', 'IP bloqueada temporalmente (5 intentos/5min)', ip)
        return False
    LOGIN_ATTEMPTS[ip] = attempts + [now]; return True

def is_account_locked(username):
    until = LOCKED_ACCOUNTS.get(username)
    if not until: return False
    if datetime.datetime.now() >= until:
        LOCKED_ACCOUNTS.pop(username, None)
        FAILED_LOGINS[username] = 0
        return False
    return True

def register_failed_login(username, ip):
    FAILED_LOGINS[username] = FAILED_LOGINS.get(username, 0) + 1
    log_security('LOGIN_FALLIDO', 'usuario=' + username + ' intento#' + str(FAILED_LOGINS[username]), ip)
    if FAILED_LOGINS[username] >= MAX_FAILED_LOGIN:
        LOCKED_ACCOUNTS[username] = datetime.datetime.now() + datetime.timedelta(minutes=LOCK_MINUTES)
        log_security('CUENTA_BLOQUEADA', 'usuario=' + username + ' por ' + str(LOCK_MINUTES) + ' min', ip)

def register_success_login(username):
    FAILED_LOGINS[username] = 0
    LOCKED_ACCOUNTS.pop(username, None)

# --- Sanitización de entradas ---
_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

def clean_text(value, max_len=200):
    """Limpia texto de control chars y limita longitud. Las consultas SQL siempre
    usan parámetros (?) — esto es una capa extra contra payloads malformados/control chars."""
    if value is None: return ''
    s = str(value).strip()
    s = _CONTROL_CHARS.sub('', s)
    return s[:max_len]

def clean_username(value, max_len=50):
    s = clean_text(value, max_len)
    return re.sub(r'[^A-Za-z0-9_.\-]', '', s)

def clean_device_id(value, max_len=64):
    s = clean_text(value, max_len)
    return re.sub(r'[^A-Za-z0-9\-]', '', s)

def clean_numeric_list(value, max_len=200):
    """Para campos tipo 'almacen_id' = '1,2,3'."""
    s = clean_text(value, max_len)
    return ','.join(p.strip() for p in s.split(',') if p.strip().isdigit())

@app.after_request
def set_security_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    resp.headers['Access-Control-Allow-Origin'] = request.host_url.rstrip('/')
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

STYLE = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:linear-gradient(135deg,#0d1b3e 0%,#1a237e 50%,#283593 100%);
color:#fff;font-family:'Segoe UI',sans-serif;min-height:100vh;font-size:17px;overflow-x:hidden}
.sb-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.68);z-index:499;backdrop-filter:blur(2px)}
.sb-overlay.on{display:block}
.sidebar{position:fixed;top:0;left:-310px;width:310px;height:100%;
background:#1a1f2e;z-index:500;
transition:left .28s cubic-bezier(.4,0,.2,1);
overflow-y:auto;overflow-x:hidden;
border-right:1px solid #3a4258;
box-shadow:4px 0 28px rgba(0,0,0,0.55)}
.sidebar.on{left:0}
.sb-head{padding:26px 18px 14px;background:#151a27;border-bottom:1px solid #3a4258}
.sb-logo{font-size:20px;font-weight:800;color:#4dd0c4;letter-spacing:-.3px}
.sb-user{font-size:13px;color:#8f96aa;margin-top:3px;font-weight:500}
.sb-section{padding:14px 18px 4px;font-size:10px;font-weight:800;
color:#4dd0c4;text-transform:uppercase;letter-spacing:2px}
.sb-item{display:flex;align-items:center;gap:13px;padding:13px 18px;
color:#b0b8cc;font-size:14px;font-weight:600;cursor:pointer;
border-left:3px solid transparent;transition:all .15s}
.sb-item:active,.sb-item:hover{background:#2d3444;border-left-color:#4dd0c4;color:#e8eaf0}
.sb-item .sbi{font-size:18px;width:24px;text-align:center;flex-shrink:0}
.sb-sep{height:1px;background:#3a4258;margin:6px 0}
.topbar{display:flex;align-items:center;gap:10px;
margin:12px 14px 16px;padding:11px 13px;
background:#2d3444;border-radius:12px;border:1px solid #3a4258}
.hbg{background:none;border:none;box-shadow:none;width:34px;height:34px;
padding:5px;margin:0;display:flex;flex-direction:column;justify-content:center;
gap:5px;cursor:pointer;flex-shrink:0;border-radius:8px;transition:.2s}
.hbg:active{background:#363d52}
.hbg span{display:block;width:100%;height:2.5px;background:#e8eaf0;border-radius:2px}
.tb-title{flex:1;font-weight:700;font-size:15px;color:#e8eaf0;
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tb-back{background:#363d52;border:1px solid #3a4258;box-shadow:none;
width:auto;padding:7px 13px;font-size:13px;margin:0;border-radius:9px;
color:#b0b8cc;cursor:pointer;white-space:nowrap;flex-shrink:0;font-family:inherit}
.tb-back:active{background:#404860}
.badge{background:#2d3444;border:1px solid #4dd0c4;color:#4dd0c4;
padding:2px 8px;border-radius:20px;font-size:11px;margin-left:4px;font-weight:700}
.box{background:#2d3444;border-radius:18px;
padding:32px 24px 22px;max-width:420px;width:90%;
border:1px solid #3a4258;box-shadow:0 8px 32px rgba(0,0,0,0.4);margin:auto}
h1{text-align:center;margin-bottom:20px;font-size:26px;font-weight:800;color:#4dd0c4}
h2{margin:14px 14px 7px;font-size:19px;font-weight:700;color:#e8eaf0}
h3{margin:12px 14px 7px;font-size:16px;font-weight:700;color:#b0b8cc}
input,select{width:100%;padding:12px 14px;margin:6px 0;border-radius:10px;
border:1.5px solid #3a4258;background:#363d52;
color:#e8eaf0;font-size:16px;
outline:none;transition:all .2s;-webkit-appearance:none;font-family:inherit}
input:focus,select:focus{border-color:#4dd0c4;box-shadow:0 0 0 3px rgba(77,208,196,0.14);background:#404860}
input::placeholder{color:#5a6278}
select option{background:#2d3444;color:#e8eaf0}
button{display:block;width:100%;padding:14px 18px;border:none;border-radius:10px;
font-size:15px;font-weight:700;cursor:pointer;margin-top:8px;
background:#2d3444;color:#e8eaf0;border:1.5px solid #3a4258;
box-shadow:0 3px 10px rgba(0,0,0,0.3);
transition:all .18s;position:relative;overflow:hidden;font-family:inherit}
button::after{content:'';position:absolute;inset:0;background:rgba(255,255,255,0);transition:.15s}
button:active{transform:scale(.96)}
button:active::after{background:rgba(255,255,255,0.08)}
button[type=submit],button.primary,.btn-primary{
background:#4dd0c4;color:#1a1f2e;border-color:#4dd0c4;
box-shadow:0 4px 14px rgba(77,208,196,0.3);font-weight:800}
button[type=submit]:active,button.primary:active{background:#3ab8ad}
button.dark{background:#363d52;border-color:#3a4258;color:#b0b8cc;box-shadow:none}
button.dark:active{background:#404860}
button.danger{background:#3d2020;border-color:#e05c5c;color:#e05c5c;box-shadow:none}
button.danger:active{background:#4d2828}
button.success-btn{background:#1e3530;border-color:#4dd0a0;color:#4dd0a0;box-shadow:none}
button.success-btn:active{background:#263d38}
button.ghost{background:transparent;border:1.5px solid #3a4258;color:#8f96aa;box-shadow:none}
button.del{background:none;border:none;box-shadow:none;color:#e05c5c;
font-weight:800;font-size:18px;width:auto;padding:3px 7px;margin:0}
.btn-sm{padding:8px 13px;font-size:13px;border-radius:9px;width:auto;margin:0;display:inline-block}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;padding:0 14px 14px}
.card{background:#2d3444;border-radius:14px;padding:18px 10px;
text-align:center;cursor:pointer;border:1px solid #3a4258;
transition:all .18s;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2.5px;
background:#4dd0c4;border-radius:14px 14px 0 0;opacity:.7}
.card:active{transform:scale(.95);border-color:#4dd0c4;background:#363d52}
.card .icon{font-size:30px;margin-bottom:7px}
.card .title{font-size:12px;font-weight:700;color:#b0b8cc;line-height:1.3}
.form-group{margin:0 14px 10px}
.form-group label{font-size:11px;font-weight:700;color:#8f96aa;display:block;
margin-bottom:4px;text-transform:uppercase;letter-spacing:.8px}
.product-item{background:#2d3444;border:1px solid #3a4258;
border-radius:12px;padding:13px 14px;margin:6px 14px;
display:flex;justify-content:space-between;align-items:center;transition:all .16s}
.product-item:active{background:#363d52;border-color:#4dd0c4}
.product-item .name{font-weight:700;font-size:15px;color:#e8eaf0}
.product-item .info{color:#8f96aa;font-size:13px;margin-top:3px}
.cart-item{background:#2d3444;border:1px solid #3a4258;
border-radius:10px;padding:11px 13px;margin:5px 14px;
display:flex;justify-content:space-between;align-items:center;
font-size:15px;color:#e8eaf0}
.modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;
background:rgba(15,18,28,0.97);backdrop-filter:blur(8px);
z-index:100;overflow-y:auto;padding:14px;animation:fadeIn .2s ease}
.modal.active{display:block}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.confirm-box{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);
background:#252b3b;border:1px solid #3a4258;border-radius:16px;
padding:24px 20px;z-index:600;text-align:center;
min-width:270px;max-width:86vw;
box-shadow:0 12px 40px rgba(0,0,0,0.6);display:none}
.confirm-box .cf-title{font-size:16px;font-weight:800;color:#e8eaf0;margin-bottom:6px}
.confirm-box .cf-detail{font-size:13px;color:#8f96aa;margin-bottom:16px;line-height:1.5}
.cf-btns{display:flex;gap:9px}
.cf-btns button{flex:1;margin:0}
.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:599}
.overlay.active{display:block}
.toast{position:fixed;bottom:22px;left:14px;right:14px;
background:#2d3444;border:1px solid #3a4258;
color:#e8eaf0;padding:13px 16px;border-radius:12px;text-align:center;
z-index:700;font-weight:700;font-size:15px;opacity:0;
transition:opacity .2s;box-shadow:0 6px 20px rgba(0,0,0,0.4);pointer-events:none}
.toast.show{opacity:1}
.toast.tok{background:#1e3530;border-color:#4dd0a0;color:#4dd0a0}
.toast.terr{background:#3d2020;border-color:#e05c5c;color:#e05c5c}
.toast.twarn{background:#3d2e10;border-color:#f0a030;color:#f0a030}
.error{background:#3d2020;border:1px solid #e05c5c;color:#e05c5c;
margin-top:10px;padding:13px;border-radius:10px;text-align:center;
font-size:14px;font-weight:700;animation:shake .4s}
@keyframes shake{0%,100%{transform:translateX(0)}30%{transform:translateX(-6px)}70%{transform:translateX(6px)}}
.stat-row{display:grid;grid-template-columns:1fr 1fr;gap:9px;padding:0 14px 12px}
.stat-card{background:#2d3444;border:1px solid #3a4258;border-radius:12px;padding:13px;text-align:center}
.stat-val{font-size:19px;font-weight:800;color:#4dd0c4}
.stat-lbl{font-size:11px;color:#8f96aa;margin-top:3px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}
.inv-header{background:#252b3b;border:1px solid #3a4258;border-radius:12px;padding:14px;margin:7px 14px 3px}
.lic-card{background:#2d3444;border:1px solid #3a4258;border-radius:12px;padding:13px 14px;margin:6px 14px}
.lic-id{font-family:monospace;font-size:13px;color:#4dd0c4;word-break:break-all;
background:#1e2430;border-radius:7px;padding:7px 9px;margin:5px 0}
.lic-meta{font-size:12px;color:#8f96aa;margin-top:4px}
.s-ok{color:#4dd0a0;font-weight:700}.s-err{color:#e05c5c;font-weight:700}
.device-box{background:#252b3b;border:2px dashed #3a4258;border-radius:13px;padding:18px;margin:14px 0;text-align:center}
.device-id-txt{font-family:monospace;font-size:16px;font-weight:800;color:#4dd0c4;
letter-spacing:1px;word-break:break-all;
background:#1e2430;border-radius:8px;padding:10px;margin:10px 0}
.pin-display{display:flex;justify-content:center;gap:11px;margin:14px 0}
.pin-dot{width:14px;height:14px;border-radius:50%;border:2px solid #3a4258;transition:all .17s}
.pin-dot.filled{background:#4dd0c4;border-color:#4dd0c4;box-shadow:0 0 8px rgba(77,208,196,0.5)}
.chat-bubble{max-width:80%;padding:9px 13px;border-radius:13px;margin:3px 0;font-size:14px;line-height:1.4;word-break:break-word}
.chat-bubble.me{background:#4dd0c4;color:#1a1f2e;margin-left:auto;border-radius:13px 13px 3px 13px;font-weight:600}
.chat-bubble.other{background:#2d3444;border:1px solid #3a4258;border-radius:13px 13px 13px 3px}
.bill-row{display:flex;justify-content:space-between;align-items:center;
background:#2d3444;border:1px solid #3a4258;
border-radius:10px;padding:10px 14px;margin:5px 14px}
.bill-denom{font-size:16px;font-weight:800;min-width:68px;color:#b0b8cc}
.bill-input{width:76px;font-size:17px;text-align:center;padding:7px;margin:0}
.bill-sub{min-width:86px;text-align:right;font-weight:700;color:#4dd0c4;font-size:14px}
.bill-total{color:#4dd0c4;font-size:26px;font-weight:800}
.page-btn{background:#2d3444;border:1px solid #3a4258;
padding:8px 14px;border-radius:8px;margin:2px;cursor:pointer;
font-weight:700;font-size:13px;color:#8f96aa;width:auto;box-shadow:none;font-family:inherit}
.page-btn.active{background:#4dd0c4;color:#1a1f2e;border-color:#4dd0c4}
.prod-actions{background:#252b3b;border:1px solid #3a4258;border-radius:12px;margin:0 14px 12px;padding:15px}
.actions-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}
.action-box{border-radius:10px;padding:12px}
.footer-login{text-align:center;padding:16px 0 4px;margin-top:16px;
border-top:1px solid #3a4258;font-size:11px;color:#5a6278;line-height:1.9}
.footer-login a{color:#4dd0c4;text-decoration:none}
.footer{background:#151a27;color:#5a6278;text-align:center;
padding:14px;margin-top:28px;font-size:12px;border-top:1px solid #3a4258}
.footer a{color:#4dd0c4;text-decoration:none}
@media(max-height:640px){.card{padding:12px 8px}.card .icon{font-size:26px;margin-bottom:5px}}
body{display:flex;flex-direction:column;min-height:100vh;-webkit-user-select:none;user-select:none;touch-action:manipulation;-webkit-tap-highlight-color:transparent;overscroll-behavior:none}
body::-webkit-scrollbar{display:none}
body{-ms-overflow-style:none;scrollbar-width:none}
input,textarea,select{-webkit-user-select:text;user-select:text;-webkit-touch-callout:default}
.footer-login{margin-top:auto}
.suggest-wrap{margin:0 14px 6px}
.top5-wrap{background:rgba(77,208,196,0.06);border:1px solid rgba(77,208,196,0.18);border-radius:13px;padding:12px;margin:0 14px 10px}
.top5-title{font-size:11px;font-weight:800;color:#4dd0c4;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.top5-grid{display:flex;gap:7px;overflow-x:auto;padding-bottom:4px;scrollbar-width:none}
.top5-grid::-webkit-scrollbar{display:none}
.top5-chip{flex-shrink:0;background:#363d52;border:1px solid #4dd0c4;border-radius:11px;padding:9px 13px;cursor:pointer;transition:all .15s;min-width:100px;max-width:150px}
.top5-chip:active{transform:scale(.95);background:#404860}
.top5-chip .tc-name{font-size:12px;font-weight:700;color:#e8eaf0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.top5-chip .tc-meta{font-size:10px;color:#8f96aa;margin-top:2px}
.top5-chip .tc-rank{font-size:9px;color:#4dd0c4;font-weight:800;margin-top:3px}
"""
TOAST_JS = """
<div class="toast" id="__toast"></div>
<script>
function toast(m,type){
var t=document.getElementById('__toast');
t.textContent=m;t.className='toast'+(type?' '+type:'');
t.classList.add('show');setTimeout(function(){t.classList.remove('show')},2800)}
function confirmar(titulo,detalle,cb){
if(typeof detalle==='function'){cb=detalle;detalle=''}
document.getElementById('cfTitle').textContent=titulo;
var cd=document.getElementById('cfDetail');
cd.textContent=detalle;cd.style.display=detalle?'block':'none';document.getElementById('cfOverlay').classList.add('active');
document.getElementById('cfBox').style.display='block';
document.getElementById('cfOk').onclick=function(){closeCf();cb(true)};
document.getElementById('cfCancel').onclick=function(){closeCf();cb(false)}}
function closeCf(){
document.getElementById('cfOverlay').classList.remove('active');
document.getElementById('cfBox').style.display='none'}
function toggleSB(){
document.getElementById('sbOverlay').classList.toggle('on');
document.getElementById('sidebar').classList.toggle('on')}
function closeSB(){
document.getElementById('sbOverlay').classList.remove('on');
document.getElementById('sidebar').classList.remove('on')}
(function(){
function _tryAndroidId(){
try{if(window.Android&&typeof window.Android.getDeviceId==='function')return window.Android.getDeviceId()}catch(e){}
try{if(window.AndroidInterface&&typeof window.AndroidInterface.getDeviceId==='function')return window.AndroidInterface.getDeviceId()}catch(e){}
return null}
var _aid=_tryAndroidId();
if(_aid){window._G360_DID=_aid;document.cookie='device_id='+_aid+';path=/;max-age=315360000'}
else{var _dc=document.cookie.split(';').map(function(c){return c.trim()}).find(function(c){return c.startsWith('device_id=')});window._G360_DID=_dc?_dc.split('=')[1]:null}
var _of=window.fetch;
window.fetch=function(url,opts){
opts=opts||{};opts.headers=opts.headers||{};
if(window._G360_DID){
if(opts.headers instanceof Headers)opts.headers.set('X-Device-ID',window._G360_DID);
else opts.headers['X-Device-ID']=window._G360_DID}
return _of.call(this,url,opts)}})();
</script>"""

CONFIRM_HTML = """
<div class="overlay" id="cfOverlay"></div>
<div class="confirm-box" id="cfBox">
<div class="cf-title" id="cfTitle"></div>
<div class="cf-detail" id="cfDetail" style="display:none"></div>
<div class="cf-btns">
<button class="dark" onclick="closeCf()">Cancelar</button>
<button id="cfOk">Confirmar</button>
</div>
</div>"""

FOOTER_HTML = '<div class="footer">© 2026 <strong>Gestor360°</strong> | Luisito | <a href="mailto:luisi26@nauta.cu">luisi26@nauta.cu</a></div>'

def sidebar_html(rol, nombre, almacen):
    ops = [
        ('🛒','Ingresar Ventas','/ventas'),
        ('📦','Ingresar Productos','/productos'),
        ('📊','Inventario del Día','/inventario'),
        ('💰','Contador Efectivo','/contador'),
        ('📋','Stock Real','/stock_real'),
        ('⚠️','Registrar Merma','/merma'),
        ('💬','Chat Interno','/chat'),
    ]
    adm = [
        ('📦','Panel de Stock','/stock_modal'),
        ('💳','Gestionar Tarjetas','/tarjetas'),
        ('📅','Búsqueda por Fechas','/busqueda'),
        ('📋','Registro de Trazas','/trazas'),
    ]
    sup = [
        ('🏠','Dashboard','/dashboard'),
        ('👥','Usuarios','/usuarios'),
        ('🏪','Gestión de Locales','/locales'),
        ('🔑','Licencias','/licencias'),
        ('💳','Tarjetas','/tarjetas'),
        ('📋','Trazas del Sistema','/trazas'),
        ('🔄','Sincronizar BD','/sync'),
    ]
    h = ('<div class="sb-overlay" id="sbOverlay" onclick="closeSB()"></div>'
         '<div class="sidebar" id="sidebar">'
         '<div class="sb-head">'
         '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">'
         '<div style="width:44px;height:44px;border-radius:13px;'
         'background:linear-gradient(135deg,#3D5AFE,#00E5FF);'
         'display:flex;align-items:center;justify-content:center;font-size:22px;flex-shrink:0">🏪</div>'
         '<div><div class="sb-logo">Gestor360°</div>'
         '<div class="sb-user">' + nombre + '</div></div>'
         '</div>'
         '<div style="display:flex;align-items:center;gap:8px;'
         'background:rgba(0,229,255,0.08);border:1px solid rgba(0,229,255,0.18);'
         'border-radius:10px;padding:8px 12px">'
         '<div style="width:8px;height:8px;border-radius:50%;background:#00E5FF;'
         'box-shadow:0 0 6px #00E5FF;animation:sbPulse 2s infinite;flex-shrink:0"></div>'
         '<span style="font-size:12px;color:#00E5FF;font-weight:600">Conectado · Local ' + almacen + '</span>'
         '</div></div>')

    def sb_item(ico, lbl, url):
        return ('<div class="sb-item" onclick="closeSB();location.href=\'' + url + '\'">'
                '<span class="sbi">' + ico + '</span><span>' + lbl + '</span></div>')

    if rol == 'superadmin':
        h += '<div class="sb-section">⚙️ Sistema</div>'
        for ico, lbl, url in sup:
            h += sb_item(ico, lbl, url)
    else:
        h += '<div class="sb-section">📱 Operaciones</div>'
        for ico, lbl, url in ops:
            h += sb_item(ico, lbl, url)
        if rol == 'admin':
            h += '<div class="sb-sep"></div><div class="sb-section">🔧 Administración</div>'
            for ico, lbl, url in adm:
                h += sb_item(ico, lbl, url)

    h += ('<div class="sb-sep"></div>'
          '<div class="sb-section">🔒 Sesión</div>'
          '<div class="sb-item sb-danger" onclick="closeSB();confirmar(\'¿Cerrar sesión?\',\'\','
          'function(ok){if(ok)location.href=\'/logout\'})">'
          '<span class="sbi">🚪</span><span>Cerrar Sesión</span></div>'
          '</div>'
          '<style>'
          '@keyframes sbPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.8)}}'
          '.sb-danger:hover,.sb-danger:active{background:rgba(239,83,80,0.15)!important;'
          'border-left-color:#EF5350!important;color:#EF5350!important}'
          '</style>')
    return h

def page_full(title, body, include_confirm=True, rol='seller', nombre='', almacen='1'):
    sb = sidebar_html(rol, nombre, almacen)
    c  = TOAST_JS + CONFIRM_HTML if include_confirm else ''
    return ("<!DOCTYPE html><html lang='es'><head>"
            "<title>Gestor360° — " + title + "</title>"
            "<meta name='viewport' content='width=device-width,initial-scale=1,maximum-scale=1'>"
            "<meta name='theme-color' content='#0d1b3e'>"
            "<style>" + STYLE + "</style></head>"
            "<body>" + sb + body + c + "</body></html>")

def page_auth(title, body):
    u = session.get('user', {})
    return page_full(title, body,
                     rol=u.get('rol','seller'),
                     nombre=str(u.get('nombre') or u.get('username','')),
                     almacen=get_almacen())

def page_plain(title, body):
    noscroll='<style>html,body{height:100dvh!important;overflow:hidden!important}</style>'
    return page_full(title, body+noscroll, include_confirm=False, rol='', nombre='', almacen='')

def topbar(title, back_url='/dashboard'):
    a = get_almacen()
    return ('<div class="topbar">'
            '<button class="hbg" onclick="toggleSB()"><span></span><span></span><span></span></button>'
            '<span class="tb-title">' + title + '<span class="badge">' + a + '</span></span>'
            '<button class="tb-back" onclick="location.href=\'' + back_url + '\'">← Volver</button>'
            '</div>')
@app.route('/logo_gestor360.svg')
def logo():
    return send_from_directory('.', 'logo_gestor360.svg')

@app.route('/inicio')
def inicio():
    dev_id = request.cookies.get('device_id')
    if not dev_id:
        dev_id = 'G360-' + uuid.uuid4().hex[:12].upper()
    db_raw = sqlite3.connect(DB_PATH); db_raw.row_factory = sqlite3.Row
    lic = db_raw.execute("SELECT * FROM licencias WHERE device_id=? AND activo=1", (dev_id,)).fetchone()
    db_raw.close()
    if lic:
        exp = lic['expiracion']
        if not exp or datetime.datetime.strptime(exp,'%Y-%m-%d') >= datetime.datetime.now():
            resp = make_response(redirect(url_for('login')))
            resp.set_cookie('device_id', dev_id, max_age=60*60*24*365*10)
            return resp
        status = '<div style="color:#EF5350;font-weight:800;margin-top:10px">⛔ Licencia expirada el ' + exp + '</div>'
        hint   = ''
    else:
        status = '<div style="color:#FF9800;font-weight:700;margin-top:10px">⏳ Licencia pendiente de activación</div>'
        hint   = '<p style="color:#9FA8DA;font-size:13px;margin-top:8px;text-align:center">Comparte tu ID con el administrador para activar tu acceso.</p>'
    body = ('<div style="display:flex;align-items:center;justify-content:center;flex:1;padding:20px;overflow:hidden">'
            '<div class="box">'
            '<img src="/logo_gestor360.svg" style="width:160px;display:block;margin:0 auto 18px" alt="Gestor360">'
            '<h1>Activación</h1>'
            '<div class="device-box">'
            '<div style="font-size:11px;color:#9FA8DA;font-weight:700;text-transform:uppercase;letter-spacing:1px">ID de este dispositivo</div>'
            '<div class="device-id-txt" id="devId">' + dev_id + '</div>'
            '<button onclick="copyId()" class="dark" style="width:auto;padding:8px 16px;font-size:13px;margin:4px auto 0;display:block">📋 Copiar ID</button>'
            '</div>' + status + hint +
            '<div class="footer-login">© 2026 Gestor360° | <a href="/privacidad">Privacidad</a></div>'
            '</div></div>'
            '<script>function copyId(){'
            'var t=document.getElementById("devId").textContent.trim();'
            'if(navigator.clipboard){navigator.clipboard.writeText(t)}'
            'else{var a=document.createElement("textarea");a.value=t;document.body.appendChild(a);a.select();document.execCommand("copy");document.body.removeChild(a)}'
            'alert("Copiado: "+t)}</script>')
    r = make_response(page_plain("Activación", body))
    r.set_cookie('device_id', dev_id, max_age=60*60*24*365*10)
    return r

@app.route('/', methods=['GET','POST'])
def login():
    dev_id = request.cookies.get('device_id')
    if not dev_id:
        return redirect(url_for('inicio'))
    db_raw = sqlite3.connect(DB_PATH); db_raw.row_factory = sqlite3.Row
    lic = db_raw.execute("SELECT * FROM licencias WHERE device_id=? AND activo=1",(dev_id,)).fetchone()
    db_raw.close()
    if not lic: return redirect(url_for('inicio'))
    if lic['expiracion'] and datetime.datetime.strptime(lic['expiracion'],'%Y-%m-%d') < datetime.datetime.now():
        return redirect(url_for('inicio'))
    error = ''
    if request.method == 'POST':
        ip = request.remote_addr
        u = clean_username(request.form.get('username',''))
        p = request.form.get('password','').strip()
        if is_account_locked(u):
            error = '<div class="error">⛔ Cuenta bloqueada por intentos fallidos. Intenta en ' + str(LOCK_MINUTES) + ' minutos.</div>'
            log_security('LOGIN_CUENTA_BLOQUEADA', 'usuario=' + u, ip)
        elif not check_rate_limit(ip):
            error = '<div class="error">⛔ Demasiados intentos. Espera 5 minutos.</div>'
        else:
            db = get_db()
            user = db.execute("SELECT * FROM usuarios WHERE username=? AND activo=1",(u,)).fetchone()
            if user:
                if not user['password']:
                    session['temp_user'] = dict(user)
                    return redirect(url_for('create_password'))
                if user['password'] == hashlib.sha256(p.encode()).hexdigest():
                    session.clear()
                    session['user'] = dict(user)
                    register_success_login(u)
                    add_trace(u,'LOGIN','Inicio exitoso',str(user['almacen_id'] or '1'))
                    log_security('LOGIN_OK', 'usuario=' + u, ip)
                    return redirect(url_for('dashboard'))
                register_failed_login(u, ip)
                error = '<div class="error">❌ Contraseña incorrecta</div>'
            else:
                register_failed_login(u, ip)
                error = '<div class="error">❌ Usuario no encontrado</div>'
    footer_l = ('<div class="footer-login">© 2026 <strong>Gestor360°</strong> | Luisito<br>'
                '<a href="mailto:luisi26@nauta.cu">luisi26@nauta.cu</a><br>'
                '<a href="/privacidad">Privacidad</a> | <a href="/seguridad">Seguridad</a> | '
                '<a href="/terminos">Términos</a> | <a href="/licencia_terminos">Licencia</a></div>')
    body = ('<div style="display:flex;align-items:center;justify-content:center;flex:1;padding:20px;overflow:hidden">'
            '<div class="box">'
            '<img src="/logo_gestor360.svg" style="width:170px;display:block;margin:0 auto 20px" alt="Gestor360">'
            '<form method="post" autocomplete="off">'
            '<div class="form-group"><label>Usuario</label>'
            '<input type="text" name="username" placeholder="Tu usuario" required autocomplete="username"></div>'
            '<div class="form-group"><label>Contraseña</label>'
            '<input type="password" name="password" placeholder="••••••••" required autocomplete="current-password"></div>'
            '<button type="submit">Ingresar al Sistema</button>'
            '</form>' + error + footer_l + '</div></div>')
    return page_plain("Acceso", body)

@app.route('/create_password', methods=['GET','POST'])
def create_password():
    if 'temp_user' not in session: return redirect(url_for('login'))
    error = ''
    if request.method == 'POST':
        p1 = request.form['pass1'].strip(); p2 = request.form['pass2'].strip()
        if not p1 or not p2: error='<div class="error">Completa ambos campos</div>'
        elif p1 != p2: error='<div class="error">Las contraseñas no coinciden</div>'
        elif len(p1) <6: error='<div class="error">Mínimo 6 caracteres</div>'
        else:
            db = get_db()
            db.execute("UPDATE usuarios SET password=? WHERE id=?",
                       (hashlib.sha256(p1.encode()).hexdigest(), session['temp_user']['id']))
            db.commit()
            session['user'] = dict(session.pop('temp_user'))
            add_trace(session['user']['username'],'PASS CREADA','Primer acceso',str(session['user'].get('almacen_id','1')))
            return redirect(url_for('dashboard'))
    body = ('<div style="display:flex;align-items:center;justify-content:center;flex:1;padding:20px;overflow:hidden">'
            '<div class="box"><h1>Crear Contraseña</h1>'
            '<p style="text-align:center;color:#9FA8DA;margin-bottom:14px;font-size:14px">Primer acceso — elige tu contraseña</p>'
            '<form method="post"><div class="form-group"><label>Nueva Contraseña</label>'
            '<input type="password" name="pass1" placeholder="Mínimo 6 caracteres" required></div>'
            '<div class="form-group"><label>Repetir</label>'
            '<input type="password" name="pass2" placeholder="Repite la contraseña" required></div>'
            '<button type="submit">Guardar y Entrar</button></form>' + error + '</div></div>')
    return page_plain("Crear Contraseña", body)

@app.route('/pin', methods=['GET','POST'])
def pin_verification():
    if 'user' not in session: return redirect(url_for('login'))
    u = session['user']
    if u.get('rol') != 'admin': return redirect(request.args.get('next','/dashboard'))
    error = ''
    if request.method == 'POST':
        ip = request.remote_addr; pin = clean_text(request.form.get('pin',''), 6)
        att = PIN_ATTEMPTS.get(ip,0)
        if att >= 5:
            error='<div class="error">⛔ Demasiados intentos</div>'
            log_security('PIN_RATE_LIMIT', 'usuario=' + str(u.get('username')), ip)
        elif pin == u.get('pin',''):
            PIN_ATTEMPTS[ip]=0; session['pin_verified']=True
            session['pin_time']=datetime.datetime.now().isoformat()
            log_security('PIN_OK', 'usuario=' + str(u.get('username')), ip)
            return redirect(request.args.get('next','/menu'))
        else:
            PIN_ATTEMPTS[ip]=att+1
            log_security('PIN_FALLIDO', 'usuario=' + str(u.get('username')) + ' intento#' + str(PIN_ATTEMPTS[ip]), ip)
            error='<div class="error">PIN incorrecto (' + str(5-PIN_ATTEMPTS[ip]) + ' intentos restantes)</div>'
    body = ('<div style="display:flex;align-items:center;justify-content:center;flex:1;padding:20px;overflow:hidden">'
            '<div class="box"><h1>🔐 PIN de Seguridad</h1>'
            '<div class="pin-display">'
            + ''.join(['<div class="pin-dot" id="pd' + str(i) + '"></div>' for i in range(6)])
            + '</div><form method="post" id="pf">'
            '<input type="password" name="pin" id="pi" placeholder="······" maxlength="6" '
            'inputmode="numeric" style="text-align:center;font-size:28px;letter-spacing:10px" required>'
            '<button type="submit">Verificar</button></form>' + error +
            '</div></div>'
            '<script>var pi=document.getElementById("pi");'
            'pi.addEventListener("input",function(){var v=this.value;'
            'for(var i=0;i<6;i++)document.getElementById("pd"+i).className="pin-dot "+(i<v.length?"filled":"")});'
            'pi.focus()</script>')
    return page_auth("PIN", body)

def pin_required(next_url):
    if 'user' not in session: return False
    u = session['user']
    if u.get('rol') != 'admin': return True
    if not session.get('pin_verified'): return False
    pt = datetime.datetime.fromisoformat(session.get('pin_time','2000-01-01T00:00:00'))
    if (datetime.datetime.now()-pt).seconds > 300:
        session.pop('pin_verified',None); return False
    return True

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    u = session['user']; a = get_almacen()
    nombre = str(u.get('nombre') or u.get('username')); rol = str(u.get('rol'))
    top = ('<div class="topbar">'
           '<button class="hbg" onclick="toggleSB()"><span></span><span></span><span></span></button>'
           '<span class="tb-title">' + nombre + ' <span class="badge">' + rol.upper() + '</span></span>'
           '<div style="display:flex;gap:6px">')
    if rol == 'admin':
        alms = get_almacenes_usuario()
        if len(alms) > 1:
            sel = '<select onchange="location.href=this.value" style="width:auto;padding:6px 10px;font-size:13px;margin:0">'
            for al in alms:
                sel += '<option value="/cambiar_local/' + al + '"' + (' selected' if al==a else '') + '>Local ' + al + '</option>'
            top += sel + '</select>'
    top += '</div></div>'

    if rol == 'superadmin':
        body = top + '<h2>Panel Principal</h2>'
        body += '<div style="padding:0 14px 10px"><p style="color:#9FA8DA;font-size:14px">Usa el menú ☰ para navegar.</p></div>'
        body += '<div class="grid">'
        for ico, lbl, url in [('👥','Usuarios','/usuarios'),('🏪','Locales','/locales'),
                              ('🔑','Licencias','/licencias'),('📋','Trazas','/trazas'),
                              ('🛡️','Seguridad','/seguridad_logs'),('🔄','Sincronizar','/sync')]:
            body += '<div class="card" onclick="location.href=\'' + url + '\'"><div class="icon">' + ico + '</div><div class="title">' + lbl + '</div></div>'
        body += '</div>'
    else:
        db = get_db(); hoy = datetime.date.today().isoformat()
        r = db.execute("SELECT SUM(total) t,SUM(efectivo) e,SUM(transferencia) tr,COUNT(*) c FROM ventas WHERE almacen_id=? AND created_at LIKE ?",(a,hoy+'%')).fetchone()
        body = top
        body += ('<div class="stat-row">'
                 '<div class="stat-card"><div class="stat-val">'+str(round(r['t'] or 0,2))+'</div><div class="stat-lbl">💰 Total CUP</div></div>'
                 '<div class="stat-card"><div class="stat-val">'+str(r['c'] or 0)+'</div><div class="stat-lbl">🛒 Ventas</div></div>'
                 '<div class="stat-card"><div class="stat-val">'+str(round(r['e'] or 0,2))+'</div><div class="stat-lbl">💵 Efectivo</div></div>'
                 '<div class="stat-card"><div class="stat-val">'+str(round(r['tr'] or 0,2))+'</div><div class="stat-lbl">📲 Transfer.</div></div>'
                 '</div>')
        body += ('<div style="padding:0 14px 6px"><p style="color:#9FA8DA;font-size:13px;margin-bottom:10px">Accesos rápidos</p></div>'
                 '<div class="grid">'
                 '<div class="card" onclick="location.href=\'/ventas\'"><div class="icon">🛒</div><div class="title">Ingresar Ventas</div></div>'
                 '<div class="card" onclick="location.href=\'/inventario\'"><div class="icon">📊</div><div class="title">Inventario del Día</div></div>'
                 '</div>'
                 '<div style="padding:0 14px 6px">'
                 '<p style="color:#7986CB;font-size:12px;text-align:center">Toca ☰ para ver todas las opciones</p>'
                 '</div>')
    noscroll='<style>html,body{height:100dvh!important;overflow:hidden!important}</style>'
    return page_auth("Dashboard", body + '<script>toast("Bienvenido, ' + nombre + '","tok")</script>' + noscroll)

@app.route('/cambiar_local/<local>')
def cambiar_local(local):
    if local in get_almacenes_usuario(): session['almacen_activo'] = local
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    u = session.get('user')
    if u: add_trace(u['username'],'LOGOUT','',str(u.get('almacen_id','1')))
    session.clear(); return redirect(url_for('login'))

@app.route('/menu')
def menu():
    return redirect(url_for('dashboard'))

@app.route('/locales')
def locales():
    if session.get('user',{}).get('rol') != 'superadmin': return redirect(url_for('dashboard'))
    db = get_db(); q = request.args.get('q','')
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = 10
    locs_all = db.execute("SELECT * FROM locales WHERE nombre LIKE ? OR CAST(id AS TEXT) LIKE ? ORDER BY id DESC",
                      ('%'+q+'%','%'+q+'%')).fetchall() if q else db.execute("SELECT * FROM locales ORDER BY id DESC").fetchall()
    total = len(locs_all)
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    locs = locs_all[(page-1)*per_page : page*per_page]
    h = topbar("Gestión de Locales", "/dashboard")
    h += '<div class="form-group" style="display:flex;gap:8px"><input type="text" id="sLocal" placeholder="🔍 Buscar..." value="'+q+'" style="flex:1;margin:0" oninput="location.href=\'/locales?q=\'+this.value"></div>'
    h += '<h3>Nuevo Local</h3>'
    h += '<div class="form-group"><label>Nombre</label><input type="text" id="lNom" placeholder="Ej: Tienda Centro"></div>'
    h += '<div style="padding:0 14px"><button onclick="confirmar(\'¿Crear local?\',\'\',function(ok){if(ok)crearLocal()})">🏪 Crear Local</button></div>'
    h += '<h3>Locales (' + str(total) + ')</h3>'
    h += '<p style="text-align:center;color:#9FA8DA;font-size:12px;margin:8px">Pág ' + str(page) + '/' + str(total_pages) + '</p>'
    for l in locs:
        adms = db.execute("SELECT username FROM usuarios WHERE rol='admin' AND almacen_id LIKE ? AND activo=1",('%'+str(l['id'])+'%',)).fetchall()
        sells = db.execute("SELECT COUNT(*) c FROM usuarios WHERE rol='seller' AND almacen_id LIKE ? AND activo=1",('%'+str(l['id'])+'%',)).fetchone()
        lic = db.execute("SELECT * FROM licencias WHERE almacen_id=? AND activo=1 ORDER BY id DESC LIMIT 1",(str(l['id']),)).fetchone()
        est = '🟢 Activo' if l['activo'] else '🔴 Inactivo'
        lic_inf = ('🔑 Vence: '+lic['expiracion']) if lic and lic['expiracion'] else ('🔑 Sin fecha' if lic else '⚠️ Sin licencia')
        h += ('<div class="lic-card">'
              '<div style="display:flex;justify-content:space-between;align-items:flex-start">'
              '<div><div style="font-weight:700;font-size:15px;color:#E8EAF6">🏪 '+str(l['nombre'])+'</div>'
              '<div class="lic-meta">ID: '+str(l['id'])+' | '+est+' | '+lic_inf+'</div>'
              '<div class="lic-meta">👤 Admin: '+(', '.join([a['username'] for a in adms]) or 'Ninguno')+'</div>'
              '<div class="lic-meta">🧑 Vendedores: '+str(sells['c'])+'</div></div>'
              '<div style="display:flex;flex-direction:column;gap:6px">'
              '<button class="btn-sm dark" onclick="editLocal('+str(l['id'])+',\''+str(l['nombre'])+'\','+str(l['activo'])+')">✏️</button>'
              '<button class="del" onclick="confirmar(\'¿Eliminar local '+str(l['nombre'])+'?\',\'Esta acción no se puede deshacer.\',function(ok){if(ok)location.href=\'/del_local/'+str(l['id'])+'\'})">✕</button>'
              '</div></div></div>')
    if total_pages > 1:
        h += '<div style="text-align:center;margin:10px;display:flex;flex-wrap:wrap;justify-content:center">'
        for p in range(1, total_pages+1):
            h += '<button class="page-btn '+('active' if p==page else '')+'" onclick="location.href=\'/locales?page='+str(p)+'&q='+q+'\'">'+str(p)+'</button>'
        h += '</div>'
    h += ('<div class="modal" id="mEditLocal">'
          '<div class="topbar"><span class="tb-title">Editar Local</span>'
          '<button class="tb-back" onclick="document.getElementById(\'mEditLocal\').classList.remove(\'active\')">✕</button></div>'
          '<div class="form-group"><label>Nombre</label><input type="text" id="elNom"></div>'
          '<div class="form-group"><label>Estado</label><select id="elAct"><option value="1">Activo</option><option value="0">Inactivo</option></select></div>'
          '<input type="hidden" id="elId">'
          '<div style="padding:0 14px"><button onclick="confirmar(\'¿Guardar cambios?\',\'\',function(ok){if(ok)guardarLocal()})">💾 Guardar</button></div>'
          '</div>')
    h += ('<script>'
          'function crearLocal(){var n=document.getElementById("lNom").value.trim();'
          'if(!n){toast("Nombre obligatorio","terr");return}'
          'fetch("/api/crear_local",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nombre:n})})'
          '.then(r=>r.json()).then(d=>{if(d.ok){toast("Local creado","tok");location.reload()}else toast(d.error,"terr")})}'
          'function editLocal(id,n,a){document.getElementById("elId").value=id;document.getElementById("elNom").value=n;document.getElementById("elAct").value=a;document.getElementById("mEditLocal").classList.add("active")}'
          'function guardarLocal(){var id=document.getElementById("elId").value,n=document.getElementById("elNom").value.trim(),a=document.getElementById("elAct").value;'
          'if(!n){toast("Nombre obligatorio","terr");return}'
          'fetch("/api/editar_local",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:id,nombre:n,activo:a})})'
          '.then(r=>r.json()).then(d=>{if(d.ok){toast("Local actualizado","tok");location.reload()}else toast(d.error,"terr")})}'
          '</script>')
    return page_auth("Locales", h)

@app.route('/api/crear_local', methods=['POST'])
def api_crear_local():
    if session.get('user',{}).get('rol')!='superadmin': return jsonify({'ok':False})
    d=request.json or {}; db=get_db()
    nombre = clean_text(d.get('nombre',''), 100)
    if not nombre: return jsonify({'ok':False,'error':'Nombre obligatorio'})
    db.execute("INSERT INTO locales (nombre,activo,created_at) VALUES (?,1,datetime('now'))",(nombre,))
    db.commit()
    log_security('CREAR_LOCAL', nombre, request.remote_addr)
    return jsonify({'ok':True})

@app.route('/api/editar_local', methods=['POST'])
def api_editar_local():
    if session.get('user',{}).get('rol')!='superadmin': return jsonify({'ok':False})
    d=request.json or {}; db=get_db()
    nombre = clean_text(d.get('nombre',''), 100)
    try: activo = int(d.get('activo', 1))
    except (TypeError, ValueError): activo = 1
    try: lid = int(d.get('id'))
    except (TypeError, ValueError): return jsonify({'ok':False,'error':'ID inválido'})
    if not nombre: return jsonify({'ok':False,'error':'Nombre obligatorio'})
    db.execute("UPDATE locales SET nombre=?,activo=? WHERE id=?",(nombre,activo,lid))
    db.commit()
    log_security('EDITAR_LOCAL', 'id='+str(lid), request.remote_addr)
    return jsonify({'ok':True})

@app.route('/del_local/<int:lid>')
def del_local(lid):
    if session.get('user',{}).get('rol')!='superadmin': return redirect(url_for('dashboard'))
    get_db().execute("DELETE FROM locales WHERE id=?",(lid,)); get_db().commit()
    return redirect(url_for('locales'))

@app.route('/licencias')
def licencias():
    if session.get('user',{}).get('rol')!='superadmin': return redirect(url_for('dashboard'))
    db=get_db()
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = 10
    lics_all=db.execute("SELECT l.*,lo.nombre as lnombre FROM licencias l LEFT JOIN locales lo ON lo.id=CAST(l.almacen_id AS INTEGER) ORDER BY l.id DESC").fetchall()
    locs=db.execute("SELECT * FROM locales WHERE activo=1 ORDER BY id").fetchall()
    total=len(lics_all)
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    lics = lics_all[(page-1)*per_page : page*per_page]
    activas=sum(1 for l in lics_all if l['activo'] and (not l['expiracion'] or datetime.datetime.strptime(l['expiracion'],'%Y-%m-%d') >=datetime.datetime.now()))
    h=topbar("Licencias", "/dashboard")
    h+=('<div class="stat-row">'
         '<div class="stat-card"><div class="stat-val">'+str(total)+'</div><div class="stat-lbl">Total</div></div>'
         '<div class="stat-card"><div class="stat-val">'+str(activas)+'</div><div class="stat-lbl">🟢 Activas</div></div>'
         '</div>')
    loc_opts=''.join(['<option value="'+str(l['id'])+'">'+str(l['nombre'])+' (ID:'+str(l['id'])+')</option>' for l in locs])
    h+=('<h3>Activar nueva licencia</h3>'
         '<div class="form-group"><label>Device ID del dispositivo</label>'
         '<input type="text" id="lDev" placeholder="G360-XXXXXXXXXXXX" style="font-family:monospace"></div>'
         '<div class="form-group"><label>Local</label><select id="lAlm">'+loc_opts+'</select></div>'
         '<div class="form-group"><label>Días de vigencia</label><input type="number" id="lDias" value="30" min="1"></div>'
         '<div style="padding:0 14px"><button onclick="confirmar(\'¿Activar licencia?\',\'\',function(ok){if(ok)addLic()})">🔑 Activar Licencia</button></div>')
    h+='<h3>Dispositivos registrados (' + str(total) + ')</h3>'
    h+='<p style="text-align:center;color:#9FA8DA;font-size:12px;margin:8px">Pág ' + str(page) + '/' + str(total_pages) + '</p>'
    for l in lics:
        exp=l['expiracion'] or '—'
        venc=l['expiracion'] and datetime.datetime.strptime(l['expiracion'],'%Y-%m-%d') <datetime.datetime.now()
        if venc: ecls='s-err'; est='⛔ Expirada'
        elif not l['activo']: ecls='s-err'; est='🔴 Inactiva'
        else: ecls='s-ok'; est='🟢 Activa'
        lnm=str(l['lnombre'] or 'Local '+str(l['almacen_id']))
        dr=''
        if l['expiracion'] and not venc:
            d_=(datetime.datetime.strptime(l['expiracion'],'%Y-%m-%d')-datetime.datetime.now()).days
            dr=' ('+str(d_)+' días)'
        h+=('<div class="lic-card">'
             '<div style="display:flex;justify-content:space-between;align-items:flex-start">'
             '<div style="flex:1;min-width:0"><div class="lic-id">'+str(l['device_id'])+'</div>'
             '<div class="lic-meta">🏪 '+lnm+' | 📅 '+exp+dr+'</div>'
             '<div class="lic-meta '+ecls+'">'+est+'</div></div>'
             '<div style="display:flex;flex-direction:column;gap:6px;margin-left:10px">'
             '<button class="btn-sm dark" onclick="renovar(\''+str(l['device_id'])+'\',\''+str(l['almacen_id'])+'\')">🔄</button>'
             '<button class="del" onclick="confirmar(\'¿Eliminar licencia?\',\''+str(l['device_id'])[:18]+'...\',function(ok){if(ok)location.href=\'/del_licencia/'+str(l['id'])+'\'})">✕</button>'
             '</div></div></div>')
    if total_pages > 1:
        h += '<div style="text-align:center;margin:10px;display:flex;flex-wrap:wrap;justify-content:center">'
        for p in range(1, total_pages+1):
            h += '<button class="page-btn '+('active' if p==page else '')+'" onclick="location.href=\'/licencias?page='+str(p)+'\'">'+str(p)+'</button>'
        h += '</div>'
    h+=('<script>'
         'function addLic(){var d=document.getElementById("lDev").value.trim(),a=document.getElementById("lAlm").value,di=document.getElementById("lDias").value;'
         'if(!d){toast("Ingresa el Device ID","terr");return}'
         'fetch("/api/add_licencia",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({device_id:d,almacen_id:a,dias:di})})'
         '.then(r=>r.json()).then(d=>{if(d.ok){toast("✅ Licencia activada","tok");location.reload()}else toast(d.error,"terr")})}'
         'function renovar(dev,alm){var dias=prompt("¿Cuántos días renovar?","30");'
         'if(!dias||isNaN(parseInt(dias)))return;'
         'fetch("/api/add_licencia",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({device_id:dev,almacen_id:alm,dias:dias})})'
         '.then(r=>r.json()).then(d=>{if(d.ok){toast("Renovada","tok");location.reload()}else toast(d.error,"terr")})}'
         '</script>')
    return page_auth("Licencias", h)

@app.route('/del_licencia/<int:lid>')
def del_licencia(lid):
    if session.get('user',{}).get('rol')!='superadmin': return redirect(url_for('dashboard'))
    get_db().execute("DELETE FROM licencias WHERE id=?",(lid,)); get_db().commit()
    return redirect(url_for('licencias'))

@app.route('/api/add_licencia', methods=['POST'])
def api_add_licencia():
    if session.get('user',{}).get('rol')!='superadmin': return jsonify({'ok':False,'error':'Sin permisos'})
    d=request.json or {}; db=get_db()
    device_id = clean_device_id(d.get('device_id',''))
    almacen_id = clean_text(d.get('almacen_id',''), 20)
    if not device_id or not almacen_id.isdigit():
        return jsonify({'ok':False,'error':'Datos inválidos'})
    try: dias = int(d.get('dias') or 0)
    except (TypeError, ValueError): dias = 0
    exp=(datetime.datetime.now()+datetime.timedelta(days=dias)).strftime('%Y-%m-%d') if dias>0 else ''
    db.execute("INSERT OR REPLACE INTO licencias (device_id,almacen_id,expiracion,activo,created_at) VALUES (?,?,?,1,datetime('now'))",
               (device_id,almacen_id,exp))
    db.commit()
    log_security('LICENCIA_ACTIVADA', 'device='+device_id+' almacen='+almacen_id, request.remote_addr)
    return jsonify({'ok':True})

@app.route('/usuarios')
def usuarios():
    if session.get('user',{}).get('rol')!='superadmin': return redirect(url_for('dashboard'))
    db=get_db(); q=request.args.get('q','')
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = 10
    users_all=db.execute("SELECT * FROM usuarios WHERE (username LIKE ? OR nombre LIKE ? OR almacen_id LIKE ?) AND rol!='superadmin' ORDER BY rol,username",('%'+q+'%','%'+q+'%','%'+q+'%')).fetchall() if q else db.execute("SELECT * FROM usuarios WHERE rol!='superadmin' ORDER BY rol,username").fetchall()
    locs=db.execute("SELECT * FROM locales WHERE activo=1 ORDER BY id").fetchall()
    total = len(users_all)
    total_pages = max(1, math.ceil(total / per_page))
    page = min(page, total_pages)
    users = users_all[(page-1)*per_page : page*per_page]

    h=topbar("Usuarios", "/dashboard")
    h+='<div class="form-group"><input type="text" placeholder="🔍 Buscar..." value="'+q+'" oninput="location.href=\'/usuarios?q=\'+this.value"></div>'

    h+=('<h3>➕ Crear Usuario</h3>'
         '<div class="form-group"><label>Usuario</label><input type="text" id="nU" placeholder="nombre_usuario"></div>'
         '<div class="form-group"><label>Nombre</label><input type="text" id="nN" placeholder="Nombre Apellidos"></div>'
         '<div class="form-group"><label>Rol</label><select id="nR"><option value="seller">Vendedor</option><option value="admin">Admin (Jefe)</option></select></div>'
         '<div class="form-group"><label>Locales Asignados (IDs separados por coma)</label>'
         '<input type="text" id="nA" placeholder="Ej: 1,2,3" inputmode="numeric"></div>'
         '<div class="form-group"><label>PIN (6 dígitos)</label><input type="password" id="nP" maxlength="6" inputmode="numeric" placeholder="······"></div>'
         '<div style="padding:0 14px"><button onclick="confirmar(\'¿Crear usuario?\',\'\',function(ok){if(ok)crearU()})">➕ Crear Usuario</button></div>')

    admins=[u for u in users if u['rol']=='admin']
    sellers=[u for u in users if u['rol']=='seller']
    
    def render_u(u):
        act='🟢' if u['activo'] else '🔴'
        alm_ids = str(u['almacen_id'] or '1').split(',')
        alm_names = []
        for aid in alm_ids:
            loc_match = next((l['nombre'] for l in locs if str(l['id']) == aid.strip()), 'Local '+aid.strip())
            alm_names.append(loc_match)
        alm_display = ', '.join(alm_names) if alm_names else 'Ninguno'
        
        return('<div class="product-item"><div style="flex:1;min-width:0">'
                '<span class="name">'+act+' '+str(u['username'])+'</span>'
                '<div class="info">'+(str(u['nombre']) if u['nombre'] else '—')+'<br>🏪 '+alm_display+' · PIN: '+('✓' if u['pin'] else '—')+'</div></div>'
                '<div style="display:flex;gap:5px">'
                '<button class="btn-sm dark" onclick="editU('+str(u['id'])+',\''+str(u['username'])+'\',\''+str(u['nombre'] or '')+'\',\''+str(u['almacen_id'])+'\',\''+str(u['rol'])+'\','+str(u['activo'])+')">✏️</button>'
                '<button class="del" onclick="confirmar(\'¿Eliminar '+str(u['username'])+'?\',\'Esta acción no se puede deshacer.\',function(ok){if(ok)location.href=\'/del_usuario/'+str(u['id'])+'\'})">✕</button>'
                '</div></div>')

    h += '<h3>Usuarios (' + str(total) + ')</h3>'
    h += '<p style="text-align:center;color:#9FA8DA;font-size:12px;margin:8px">Pág ' + str(page) + '/' + str(total_pages) + '</p>'
    if admins:
        h += '<p style="padding:0 14px;color:#9FA8DA;font-size:12px;font-weight:700">👤 Administradores / Jefes</p>'
        for u in admins: h += render_u(u)
    if sellers:
        h += '<p style="padding:0 14px;color:#9FA8DA;font-size:12px;font-weight:700">🧑 Vendedores</p>'
        for u in sellers: h += render_u(u)
    if not users:
        h += '<p style="text-align:center;color:#9FA8DA;padding:24px">Sin usuarios</p>'

    if total_pages > 1:
        h += '<div style="text-align:center;margin:10px;display:flex;flex-wrap:wrap;justify-content:center">'
        for p in range(1, total_pages+1):
            h += '<button class="page-btn '+('active' if p==page else '')+'" onclick="location.href=\'/usuarios?page='+str(p)+'&q='+q+'\'">'+str(p)+'</button>'
        h += '</div>'

    h+=('<div class="modal" id="mEditU">'
         '<div class="topbar"><span class="tb-title">Editar Usuario</span>'
         '<button class="tb-back" onclick="document.getElementById(\'mEditU\').classList.remove(\'active\')">✕</button></div>'
         '<div class="form-group"><label>Username</label><input type="text" id="euU" readonly style="opacity:.6"></div>'
         '<div class="form-group"><label>Nombre</label><input type="text" id="euN"></div>'
         '<div class="form-group"><label>Locales Asignados (IDs separados por coma)</label>'
         '<input type="text" id="euA" placeholder="Ej: 1,2,3" inputmode="numeric"></div>'
         '<div class="form-group"><label>Rol</label><select id="euR"><option value="seller">Vendedor</option><option value="admin">Admin</option></select></div>'
         '<div class="form-group"><label>Estado</label><select id="euAct"><option value="1">Activo</option><option value="0">Inactivo</option></select></div>'
         '<div class="form-group"><label>Nueva contraseña (vacío = no cambiar)</label><input type="password" id="euP" placeholder="Mínimo 6 caracteres"></div>'
         '<div class="form-group"><label>Nuevo PIN (vacío = no cambiar)</label><input type="password" id="euPin" maxlength="6" inputmode="numeric" placeholder="······"></div>'
         '<input type="hidden" id="euId">'
         '<div style="padding:0 14px"><button onclick="confirmar(\'¿Guardar cambios?\',\'\',function(ok){if(ok)guardarU()})">💾 Guardar</button></div>'
         '</div>')
         
    h+=('<script>'
         'async function crearU(){var u=document.getElementById("nU").value.trim(),n=document.getElementById("nN").value.trim(),'
         'r=document.getElementById("nR").value,p=document.getElementById("nP").value;'
         'var a_str=document.getElementById("nA").value.trim();'
         'if(!u||!a_str){toast("Usuario y al menos un local son obligatorios","terr");return}'
         'var res=await fetch("/api/crear_usuario",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:u,nombre:n,rol:r,almacen_id:a_str,pin:p})});'
         'var d=await res.json();if(d.ok){toast("Usuario creado","tok");location.reload()}else toast(d.error,"terr")}'
         
         'function editU(id,u,n,alm_str,r,act){'
         'document.getElementById("euId").value=id;document.getElementById("euU").value=u;'
         'document.getElementById("euN").value=n;document.getElementById("euR").value=r;'
         'document.getElementById("euAct").value=act;document.getElementById("euP").value="";document.getElementById("euPin").value="";'
         'document.getElementById("euA").value=alm_str;'
         'document.getElementById("mEditU").classList.add("active")}'
         
         'async function guardarU(){var id=document.getElementById("euId").value,n=document.getElementById("euN").value.trim(),'
         'r=document.getElementById("euR").value,act=document.getElementById("euAct").value,'
         'p=document.getElementById("euP").value,pi=document.getElementById("euPin").value;'
         'var a_str=document.getElementById("euA").value.trim();'
         'if(p&&p.length<6){toast("Contraseña mínimo 6 caracteres","terr");return}'
         'var res=await fetch("/api/editar_usuario",{method:"POST",headers:{"Content-Type":"application/json"},'
         'body:JSON.stringify({id:id,nombre:n,almacen_id:a_str,rol:r,activo:act,password:p,pin:pi})});'
         'var d=await res.json();if(d.ok){toast("Actualizado","tok");location.reload()}else toast(d.error,"terr")}'
         '</script>')
    return page_auth("Usuarios", h)

@app.route('/del_usuario/<int:uid>')
def del_usuario(uid):
    if session.get('user',{}).get('rol')!='superadmin': return redirect(url_for('dashboard'))
    get_db().execute("DELETE FROM usuarios WHERE id=? AND rol!='superadmin'",(uid,)); get_db().commit()
    return redirect(url_for('usuarios'))

@app.route('/api/crear_usuario', methods=['POST'])
def crear_usuario():
    if session.get('user',{}).get('rol') != 'superadmin':
        return jsonify({'ok':False,'error':'Sin permisos'})
    d = request.json or {}; db = get_db()
    username = clean_username(d.get('username',''))
    nombre = clean_text(d.get('nombre') or username, 100)
    rol = d.get('rol') if d.get('rol') in ('admin','seller') else 'seller'
    pin = clean_text(d.get('pin',''), 6)
    if pin and not pin.isdigit(): pin = ''
    almacen_id = clean_numeric_list(d.get('almacen_id',''))
    if not username or not almacen_id:
        return jsonify({'ok':False,'error':'Usuario y al menos un local son obligatorios'})
    try:
        db.execute(
            "INSERT INTO usuarios (username,password,nombre,rol,pin,almacen_id,activo) VALUES (?,?,?,?,?,?,1)",
            (username, '', nombre, rol, pin, almacen_id))
        db.commit()
        add_trace(session['user']['username'], 'CREAR USUARIO',
                  username + ' · ' + rol,
                  str(session['user'].get('almacen_id','1')))
        log_security('CREAR_USUARIO', 'username='+username+' rol='+rol, request.remote_addr)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': 'No se pudo crear el usuario'})

@app.route('/api/editar_usuario', methods=['POST'])
def api_editar_usuario():
    if session.get('user',{}).get('rol')!='superadmin': return jsonify({'ok':False})
    d=request.json or {}; db=get_db()
    try: uid = int(d.get('id'))
    except (TypeError, ValueError): return jsonify({'ok':False,'error':'ID inválido'})
    nombre = clean_text(d.get('nombre',''), 100)
    almacen_id = clean_numeric_list(d.get('almacen_id','')) or '1'
    rol = d.get('rol') if d.get('rol') in ('admin','seller') else 'seller'
    try: activo = int(d.get('activo', 1))
    except (TypeError, ValueError): activo = 1
    upd="nombre=?,almacen_id=?,rol=?,activo=?"; params=[nombre,almacen_id,rol,activo]
    password = d.get('password','')
    if password and len(password)>=6: upd+=",password=?"; params.append(hashlib.sha256(password.encode()).hexdigest())
    pin = clean_text(d.get('pin',''), 6)
    if pin and pin.isdigit(): upd+=",pin=?"; params.append(pin)
    params.append(uid)
    db.execute("UPDATE usuarios SET "+upd+" WHERE id=? AND rol!='superadmin'",params)
    db.commit()
    log_security('EDITAR_USUARIO', 'id='+str(uid), request.remote_addr)
    return jsonify({'ok':True})
@app.route('/productos')
def productos():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen()
    body=topbar("Productos","/dashboard")+"""
<div class="form-group"><input type="text" id="sProd" oninput="buscar()" placeholder="🔍 Buscar producto..."></div>
<div id="sResult"></div>
<div id="fProd" style="display:none;margin:0 14px">
<div style="background:rgba(61,90,254,0.09);border:1px solid rgba(61,90,254,0.28);border-radius:13px;padding:15px;margin-bottom:12px">
<div style="font-size:14px;font-weight:800;color:#00E5FF;margin-bottom:11px" id="fTitle">Nuevo Producto</div>
<div class="form-group" style="margin:0 0 9px"><label>Nombre</label>
<input type="text" id="pN" oninput="this.value=this.value.toUpperCase()" placeholder="NOMBRE DEL PRODUCTO"></div>
<div class="form-group" style="margin:0 0 9px"><label>Precio (CUP)</label>
<input type="number" id="pP" step="0.01" min="0" placeholder="0.00"></div>
<div class="form-group" style="margin:0 0 11px"><label>Entrantes</label>
<input type="number" id="pS" value="1" min="1"></div>
<input type="hidden" id="pId">
<div style="display:flex;gap:8px">
<button style="flex:1;margin:0" onclick="confirmar('¿Guardar producto?','',function(ok){if(ok)guardar()})">💾 Guardar</button>
<button style="flex:1;margin:0" class="dark" onclick="cancelar()">Cancelar</button>
</div>
</div>
</div>
<h3>Historial reciente</h3><div id="hist"></div>
<script>
var EX=null,ALM='"""+a+"""';
function buscar(){var q=document.getElementById('sProd').value.trim().toUpperCase();if(!q){document.getElementById('sResult').innerHTML='';return}
fetch('/api/buscar_productos?q='+encodeURIComponent(q)+'&almacen='+ALM).then(r=>r.json()).then(data=>{
var h='';if(!data.length)h='<div class="product-item" onclick="nuevo(\\''+q+'\\')"><span class="name">➕ Crear: '+q+'</span><span style="color:#00E5FF">Nuevo ›</span></div>';
else data.forEach(p=>{h+='<div class="product-item" onclick="sel('+p.id+',\\''+p.nombre+'\\','+p.precio+','+p.stock+')">'
+'<div><span class="name">'+p.nombre+'</span><div class="info">Stock: '+p.stock+' | '+p.precio+' CUP</div></div>'
+'<span style="color:#9FA8DA">›</span></div>'});
document.getElementById('sResult').innerHTML=h})}
function nuevo(n){document.getElementById('fTitle').textContent='Nuevo Producto';document.getElementById('pN').value=n;document.getElementById('pP').value='';document.getElementById('pS').value='1';document.getElementById('pId').value='';document.getElementById('fProd').style.display='block';EX=null;document.getElementById('sResult').innerHTML=''}
function sel(id,n,p,s){document.getElementById('fTitle').textContent='Actualizar: '+n;document.getElementById('pN').value=n;document.getElementById('pP').value=p;document.getElementById('pS').value='1';document.getElementById('pId').value=id;document.getElementById('fProd').style.display='block';EX={id:id,stock:s};document.getElementById('sResult').innerHTML=''}
function cancelar(){document.getElementById('fProd').style.display='none';document.getElementById('sProd').value='';document.getElementById('sResult').innerHTML='';EX=null}
function guardar(){var n=document.getElementById('pN').value.trim(),p=parseFloat(document.getElementById('pP').value),s=parseInt(document.getElementById('pS').value);
if(!n||!p||!s){toast('Completa todos los campos','terr');return}
fetch('/api/guardar_producto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:EX?EX.id:null,nombre:n,precio:p,stock:s,almacen:ALM})}).then(r=>r.json()).then(d=>{if(d.ok){cancelar();hist();toast('Producto guardado','tok')}else toast(d.error,'terr')})}
function hist(){fetch('/api/historial_productos?almacen='+ALM).then(r=>r.json()).then(data=>{var h='';data.slice(0,10).forEach(p=>{h+='<div class="product-item"><span class="name">'+p.nombre+'</span><div style="text-align:right"><span style="color:#00E5FF;font-weight:700">'+p.precio+' CUP</span><div class="info">'+p.stock+' uds</div></div></div>'});document.getElementById('hist').innerHTML=h||'<p style="text-align:center;color:#9FA8DA;padding:14px">Sin productos aún</p>'})}
hist();
</script>"""
    return page_auth("Productos", body)

@app.route('/api/buscar_productos')
def api_buscar_productos():
    q=request.args.get('q','').upper(); a=request.args.get('almacen','1'); db=get_db()
    p=db.execute("SELECT * FROM productos WHERE nombre LIKE ? AND almacen_id=? ORDER BY nombre LIMIT 20",('%'+q+'%',a)).fetchall() if q else db.execute("SELECT * FROM productos WHERE almacen_id=? ORDER BY nombre LIMIT 20",(a,)).fetchall()
    return jsonify([dict(x) for x in p])

@app.route('/api/guardar_producto', methods=['POST'])
def api_guardar_producto():
    d=request.json; db=get_db()
    if d.get('id'): db.execute("UPDATE productos SET stock=stock+?,precio=? WHERE id=?",(d['stock'],d['precio'],d['id']))
    else: db.execute("INSERT INTO productos (nombre,precio,stock,almacen_id) VALUES (?,?,?,?)",(d['nombre'],d['precio'],d['stock'],d.get('almacen','1')))
    db.commit()
    u=session.get('user')
    if u: add_trace(u['username'],'PRODUCTO',d.get('nombre','')+' +'+str(d.get('stock','')),str(u.get('almacen_id','1')))
    return jsonify({'ok':True})

@app.route('/api/historial_productos')
def api_historial_productos():
    a=request.args.get('almacen','1'); db=get_db()
    p=db.execute("SELECT nombre,precio,stock FROM productos WHERE almacen_id=? ORDER BY rowid DESC LIMIT 30",(a,)).fetchall()
    return jsonify([dict(x) for x in p])

@app.route('/api/verificar_licencia')
def api_verificar_licencia():
    if 'user' not in session: return jsonify({'ok':False})
    dev_id = request.args.get('device_id','').strip()
    if not dev_id: return jsonify({'ok':False,'error':'ID vacío'})
    db = get_db()
    lic = db.execute("SELECT l.*,lo.nombre as lnombre FROM licencias l LEFT JOIN locales lo ON lo.id=CAST(l.almacen_id AS INTEGER) WHERE l.device_id=?",(dev_id,)).fetchone()
    if not lic: return jsonify({'ok':True,'found':False,'msg':'Sin licencia registrada para este ID'})
    exp = lic['expiracion']
    vencida = exp and datetime.datetime.strptime(exp,'%Y-%m-%d') < datetime.datetime.now()
    dr = ''
    if exp and not vencida:
        dr = str((datetime.datetime.strptime(exp,'%Y-%m-%d')-datetime.datetime.now()).days) + ' días restantes'
    return jsonify({'ok':True,'found':True,
                    'device_id':lic['device_id'],'local':str(lic['lnombre'] or 'Local '+str(lic['almacen_id'])),
                    'expiracion':exp or 'Sin fecha','activo':bool(lic['activo']),
                    'vencida':vencida,'dias_restantes':dr})

@app.route('/stock_modal')
def stock_modal():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen(); rol=session['user'].get('rol','seller')
    is_super = 'true' if rol == 'superadmin' else 'false'
    body=topbar("Panel Inteligente","/dashboard")+"""
<div style="display:flex;gap:0;margin:0 14px 14px;background:rgba(255,255,255,0.05);border-radius:12px;padding:3px;border:1px solid rgba(255,255,255,0.08)">
<div class="ptab active" id="tab0" onclick="showTab(0)">📦 Stock</div>
"""+( '<div class="ptab" id="tab1" onclick="showTab(1)">🔑 Licencias</div>' if rol=='superadmin' else '')+"""
</div>
<style>
.ptab{flex:1;text-align:center;padding:9px 6px;font-size:13px;font-weight:700;
color:#9FA8DA;border-radius:9px;cursor:pointer;transition:.18s}
.ptab.active{background:linear-gradient(135deg,#3D5AFE,#1A237E);color:#fff;
box-shadow:0 3px 10px rgba(61,90,254,0.3)}
.panel{display:none}.panel.on{display:block}
</style>
<div class="panel on" id="panel0">
<div class="form-group"><input type="text" id="gSearch" oninput="gBuscar()" placeholder="🔍 Buscar producto para gestionar..."></div>
<div id="gResult"></div>
<div id="gActions" style="display:none">
<div style="background:rgba(0,229,255,0.06);border:1px solid rgba(0,229,255,0.18);border-radius:14px;margin:0 14px 12px;padding:16px">
<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
<div>
<div style="font-size:16px;font-weight:800;color:#E8EAF6" id="gTitle">—</div>
<div style="font-size:24px;font-weight:800;color:#00E5FF;margin-top:3px" id="gStock">0 uds</div>
</div>
<button class="dark btn-sm" onclick="gCancelar()">✕</button>
</div>
<div style="background:rgba(239,83,80,0.08);border:1px solid rgba(239,83,80,0.2);border-radius:11px;padding:12px;margin-bottom:9px">
<div style="font-size:11px;font-weight:800;color:#EF5350;text-transform:uppercase;letter-spacing:.7px;margin-bottom:7px">⚠️ Registrar Merma</div>
<div style="display:flex;gap:7px">
<input type="number" id="gMermaQ" placeholder="Cantidad" min="1" style="flex:1;margin:0">
<button class="danger btn-sm" style="flex-shrink:0;padding:9px 14px" onclick="gMerma()">Registrar</button>
</div>
</div>
<div style="background:rgba(0,191,165,0.07);border:1px solid rgba(0,191,165,0.2);border-radius:11px;padding:12px;margin-bottom:9px">
<div style="font-size:11px;font-weight:800;color:#00BFA5;text-transform:uppercase;letter-spacing:.7px;margin-bottom:7px">📦 Modificar Total de Stock</div>
<div style="display:flex;gap:7px">
<input type="number" id="gStockQ" placeholder="Total unidades" min="0" style="flex:1;margin:0">
<button class="success-btn btn-sm" style="flex-shrink:0;padding:9px 14px" onclick="gStock()">Establecer</button>
</div>
</div>
<div style="background:rgba(61,90,254,0.07);border:1px solid rgba(61,90,254,0.2);border-radius:11px;padding:12px;margin-bottom:9px">
<div style="font-size:11px;font-weight:800;color:#3D5AFE;text-transform:uppercase;letter-spacing:.7px;margin-bottom:7px">✏️ Cambiar Nombre</div>
<div style="display:flex;gap:7px">
<input type="text" id="gNombre" placeholder="Nuevo nombre" style="flex:1;margin:0" oninput="this.value=this.value.toUpperCase()">
<button class="btn-sm" style="flex-shrink:0;padding:9px 14px" onclick="gNombre()">Renombrar</button>
</div>
</div>
<div style="background:rgba(255,152,0,0.07);border:1px solid rgba(255,152,0,0.2);border-radius:11px;padding:12px">
<div style="font-size:11px;font-weight:800;color:#FF9800;text-transform:uppercase;letter-spacing:.7px;margin-bottom:7px">💰 Cambiar Precio</div>
<div style="display:flex;gap:7px">
<input type="number" id="gPrecio" placeholder="Nuevo precio CUP" step="0.01" min="0" style="flex:1;margin:0">
<button class="btn-sm" style="flex-shrink:0;padding:9px 14px;background:rgba(255,152,0,0.2);border:1px solid rgba(255,152,0,0.35);color:#FF9800;box-shadow:none" onclick="gPrecio()">Cambiar</button>
</div>
</div>
</div>
</div>
<h3>Todos los productos</h3><div id="gLista"></div>
</div>
<div class="panel" id="panel1">
<div style="padding:0 14px 14px">
<div style="background:rgba(61,90,254,0.08);border:1px solid rgba(61,90,254,0.2);border-radius:13px;padding:15px;margin-bottom:14px">
<div style="font-size:13px;font-weight:700;color:#7986CB;margin-bottom:10px">🔍 Verificar licencia por Device ID</div>
<input type="text" id="licDevId" placeholder="G360-XXXXXXXXXXXX" style="font-family:monospace;margin-bottom:8px">
<button onclick="verificarLic()">Verificar</button>
</div>
<div id="licResult" style="display:none"></div>
</div>
</div>
<script>
var SP=null,ALM='"""+a+"""';
function showTab(n){
document.querySelectorAll('.ptab').forEach(function(t,i){t.classList.toggle('active',i===n)});
document.querySelectorAll('.panel').forEach(function(p,i){p.classList.toggle('on',i===n)})}
function gBuscar(){var q=document.getElementById('gSearch').value.trim().toUpperCase();if(!q){document.getElementById('gResult').innerHTML='';return}
fetch('/api/buscar_productos?q='+encodeURIComponent(q)+'&almacen='+ALM).then(r=>r.json()).then(data=>{
var h='';if(!data.length)h='<p style="text-align:center;color:#9FA8DA;padding:14px">Sin resultados</p>';
else data.forEach(p=>{h+='<div class="product-item" onclick="gSel('+p.id+',\\''+p.nombre+'\\','+p.precio+','+p.stock+')">'
+'<div><span class="name">'+p.nombre+'</span><div class="info">'+p.stock+' uds | '+p.precio+' CUP</div></div>'
+'<span style="color:#00E5FF;font-weight:700">Gestionar ›</span></div>'});
document.getElementById('gResult').innerHTML=h})}
function gSel(id,n,p,s){
SP={id:id,nombre:n,precio:p,stock:s};
document.getElementById('gTitle').textContent=n;
document.getElementById('gStock').textContent=s+' unidades';
document.getElementById('gMermaQ').value='';
document.getElementById('gStockQ').value=s;
document.getElementById('gNombre').value=n;
document.getElementById('gPrecio').value=p;
document.getElementById('gActions').style.display='block';
document.getElementById('gResult').innerHTML='';
document.getElementById('gSearch').value='';
document.getElementById('gActions').scrollIntoView({behavior:'smooth'})}
function gCancelar(){document.getElementById('gActions').style.display='none';SP=null}
function gMerma(){if(!SP)return;var q=parseInt(document.getElementById('gMermaQ').value);
if(!q||q<=0){toast('Cantidad inválida','terr');return}
if(q>SP.stock){toast('Stock insuficiente ('+SP.stock+' uds)','terr');return}
confirmar('¿Merma de '+q+' uds de '+SP.nombre+'?','Esta acción reduce el stock permanentemente.',function(ok){if(!ok)return;
fetch('/api/merma',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:SP.id,cantidad:q})})
.then(r=>r.json()).then(d=>{if(d.ok){SP.stock-=q;document.getElementById('gStock').textContent=SP.stock+' unidades';document.getElementById('gMermaQ').value='';toast('Merma registrada','tok');gLista()}else toast(d.error,'terr')})})}
function gStock(){if(!SP)return;var q=parseInt(document.getElementById('gStockQ').value);
if(isNaN(q)||q<0){toast('Cantidad inválida','terr');return}
confirmar('¿Establecer stock de '+SP.nombre+' en '+q+' uds?','',function(ok){if(!ok)return;
fetch('/api/update_stock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:SP.id,stock:q})})
.then(r=>r.json()).then(d=>{if(d.ok){SP.stock=q;document.getElementById('gStock').textContent=q+' unidades';toast('Stock actualizado','tok');gLista()}else toast(d.error,'terr')})})}
function gNombre(){if(!SP)return;var n=document.getElementById('gNombre').value.trim();
if(!n){toast('Escribe el nuevo nombre','terr');return}
confirmar('¿Renombrar a "'+n+'"?','',function(ok){if(!ok)return;
fetch('/api/renombrar_producto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:SP.id,nombre:n})})
.then(r=>r.json()).then(d=>{if(d.ok){SP.nombre=n;document.getElementById('gTitle').textContent=n;toast('Nombre actualizado','tok');gLista()}else toast(d.error,'terr')})})}
function gPrecio(){if(!SP)return;var p=parseFloat(document.getElementById('gPrecio').value);
if(!p||p<=0){toast('Precio inválido','terr');return}
confirmar('¿Cambiar precio de '+SP.nombre+' a '+p+' CUP?','',function(ok){if(!ok)return;
fetch('/api/update_precio',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:SP.id,precio:p})})
.then(r=>r.json()).then(d=>{if(d.ok){SP.precio=p;toast('Precio actualizado','tok');gLista()}else toast(d.error,'terr')})})}
function gLista(){fetch('/api/buscar_productos?q=&almacen='+ALM).then(r=>r.json()).then(data=>{
var h='';data.forEach(function(p){var al=p.stock<=0?'🔴':p.stock<=5?'🟡':'🟢';
h+='<div class="product-item" onclick="gSel('+p.id+',\\''+p.nombre+'\\','+p.precio+','+p.stock+')">'
+'<div><span class="name">'+al+' '+p.nombre+'</span><div class="info">'+p.stock+' uds | '+p.precio+' CUP</div></div>'
+'<span style="color:#9FA8DA">›</span></div>'});
document.getElementById('gLista').innerHTML=h||'<p style="text-align:center;color:#9FA8DA;padding:16px">Sin productos</p>'})}
function verificarLic(){var id=document.getElementById('licDevId').value.trim();
if(!id){toast('Ingresa un Device ID','terr');return}
var el=document.getElementById('licResult');
el.innerHTML='<p style="text-align:center;color:#9FA8DA;padding:12px">Verificando...</p>';
el.style.display='block';
fetch('/api/verificar_licencia?device_id='+encodeURIComponent(id)).then(r=>r.json()).then(d=>{
if(!d.ok){el.innerHTML='<div class="error">Error al verificar</div>';return}
if(!d.found){
el.innerHTML='<div style="background:rgba(255,152,0,0.1);border:1px solid rgba(255,152,0,0.3);border-radius:12px;padding:14px;text-align:center">'
+'<div style="font-size:28px;margin-bottom:6px">⚠️</div>'
+'<div style="font-weight:800;color:#FF9800">Sin licencia registrada</div>'
+'<div style="color:#9FA8DA;font-size:13px;margin-top:4px">Este dispositivo no tiene acceso activado.</div></div>';return}
var color=d.vencida?'#EF5350':d.activo?'#00BFA5':'#EF5350';
var icon=d.vencida?'⛔':d.activo?'✅':'🔴';
var estado=d.vencida?'Licencia Expirada':d.activo?'Licencia Activa':'Licencia Inactiva';
el.innerHTML='<div style="background:rgba(0,0,0,0.2);border:1px solid '+color+'44;border-radius:12px;padding:16px">'
+'<div style="text-align:center;font-size:32px;margin-bottom:8px">'+icon+'</div>'
+'<div style="font-weight:800;color:'+color+';font-size:16px;text-align:center;margin-bottom:12px">'+estado+'</div>'
+'<div class="product-item" style="flex-direction:column;gap:6px;align-items:flex-start">'
+'<div><span style="color:#9FA8DA;font-size:12px">Device ID</span><div style="font-family:monospace;font-size:13px;color:#00E5FF;word-break:break-all">'+d.device_id+'</div></div>'
+'<div style="display:flex;gap:16px;width:100%">'
+'<div><span style="color:#9FA8DA;font-size:12px">Local</span><div style="font-weight:700">'+d.local+'</div></div>'
+'<div><span style="color:#9FA8DA;font-size:12px">Vence</span><div style="font-weight:700">'+d.expiracion+'</div></div>'
+(d.dias_restantes?'<div><span style="color:#9FA8DA;font-size:12px">Tiempo</span><div style="font-weight:700;color:#00BFA5">'+d.dias_restantes+'</div></div>':'')
+'</div></div></div>'})}
gLista();
</script>"""
    return page_auth("Panel Inteligente", body)

@app.route('/api/renombrar_producto', methods=['POST'])
def api_renombrar_producto():
    if 'user' not in session: return jsonify({'ok':False})
    d=request.json; db=get_db()
    db.execute("UPDATE productos SET nombre=? WHERE id=?",(d['nombre'],d['id']))
    db.commit()
    u=session.get('user')
    if u: add_trace(u['username'],'RENOMBRAR','ID:'+str(d['id'])+' → '+d['nombre'],str(u.get('almacen_id','1')))
    return jsonify({'ok':True})

@app.route('/api/update_precio', methods=['POST'])
def api_update_precio():
    if 'user' not in session: return jsonify({'ok':False})
    d=request.json; db=get_db()
    db.execute("UPDATE productos SET precio=? WHERE id=?",(d['precio'],d['id']))
    db.commit()
    u=session.get('user')
    if u: add_trace(u['username'],'PRECIO','ID:'+str(d['id'])+' → '+str(d['precio'])+'CUP',str(u.get('almacen_id','1')))
    return jsonify({'ok':True})

@app.route('/api/update_stock', methods=['POST'])
def api_update_stock():
    d=request.json; db=get_db()
    db.execute("UPDATE productos SET stock=? WHERE id=?",(d['stock'],d['id']))
    db.commit(); return jsonify({'ok':True})

@app.route('/api/merma', methods=['POST'])
def api_merma():
    d=request.json; db=get_db()
    db.execute("UPDATE productos SET stock=MAX(0,stock-?) WHERE id=?",(d['cantidad'],d['id']))
    db.commit()
    u=session.get('user')
    if u: add_trace(u['username'],'MERMA','ID:'+str(d['id'])+' -'+str(d['cantidad']),str(u.get('almacen_id','1')))
    return jsonify({'ok':True})

@app.route('/api/top5_ventas')
def api_top5_ventas():
    if 'user' not in session: return jsonify([])
    a = request.args.get('almacen', '1')
    db = get_db()
    rows = db.execute(
        "SELECT producto_nombre, SUM(cantidad) as total FROM ventas "
        "WHERE almacen_id=? GROUP BY producto_nombre ORDER BY total DESC LIMIT 5",
        (a,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/ventas')
def ventas():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen(); uid=str(session['user'].get('id',0))
    body=topbar("Ventas","/dashboard")+"""
<div class="top5-wrap" id="top5Wrap" style="display:none">
<div class="top5-title">🏆 Top 5 más vendidos</div>
<div class="top5-grid" id="top5Grid"></div>
</div>
<div class="form-group"><input type="text" id="vSearch" oninput="vBuscar()" placeholder="🔍 Buscar producto..."></div>
<div id="vSuggest" style="display:none;margin:0 14px 4px"></div>
<div id="vList"></div>
<div id="vSel" style="display:none;margin:0 14px">
<div style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.09);border-radius:13px;padding:15px;margin-bottom:11px">
<div style="font-size:17px;font-weight:800;color:#E8EAF6" id="vSelN"></div>
<div style="font-size:21px;font-weight:800;color:#00E5FF;margin:3px 0" id="vSelP"></div>
<div style="font-size:12px;color:#9FA8DA;margin-bottom:11px" id="vSelS"></div>
<div style="display:flex;gap:8px;align-items:center">
<button style="width:44px;height:44px;padding:0;margin:0;font-size:22px;border-radius:10px;flex-shrink:0" onclick="vQty(-1)">−</button>
<input type="number" id="vQty" value="1" min="1" style="text-align:center;font-size:19px;font-weight:800;flex:1;margin:0">
<button style="width:44px;height:44px;padding:0;margin:0;font-size:22px;border-radius:10px;flex-shrink:0" onclick="vQty(1)">+</button>
</div>
<button style="margin-top:10px" onclick="confirmar('¿Agregar al carrito?','',function(ok){if(ok)vAdd()})">🛒 Agregar</button>
</div>
</div>
<div id="vCart"></div>
<div id="vTotalBox" style="display:none;margin:0 14px">
<div class="inv-header" style="margin:0 0 9px">
<div style="font-size:12px;color:#9FA8DA">Total de la venta</div>
<div style="font-size:24px;font-weight:800;color:#00E5FF"><span id="vTotal"></span> CUP</div>
</div>
<button class="success-btn" onclick="confirmar('¿Confirmar EFECTIVO?','',function(ok){if(ok)vSale('cash')})">💵 Efectivo</button>
<button onclick="vOpenTf()">📲 Transferencia</button>
<button class="dark" onclick="vOpenMix()">💱 Mixto</button>
</div>
<div class="modal" id="vMixModal">
<div class="topbar"><span class="tb-title">Pago Mixto</span><button class="tb-back" onclick="vCloseMix()">✕</button></div>
<div class="inv-header"><div style="font-size:12px;color:#9FA8DA">Total</div><div style="font-size:22px;font-weight:800;color:#00E5FF"><span id="mxT"></span> CUP</div></div>
<div class="form-group"><label>Monto en Efectivo</label><input type="number" id="mxEf" placeholder="0" min="0" step="1" style="font-size:18px;text-align:center"></div>
<div class="form-group"><label>Restante (Transferencia)</label><input type="text" id="mxRest" readonly style="font-size:18px;text-align:center;font-weight:800;color:#00E5FF;background:rgba(0,229,255,0.05)"></div>
<button onclick="vConfirmMix()">Continuar →</button>
</div>
<div class="modal" id="vTfModal">
<div class="topbar"><span class="tb-title">Transferencia</span><button class="tb-back" onclick="vCloseTf()">✕</button></div>
<div class="form-group"><label>Tarjeta destino</label><select id="tfBanco"><option value="">Seleccionar...</option></select></div>
<div class="inv-header"><div style="font-size:12px;color:#9FA8DA">Total a transferir</div><div style="font-size:20px;font-weight:800;color:#00E5FF"><span id="tfT"></span> CUP</div></div>
<div class="form-group"><label>CI del Cliente</label><input type="tel" id="tfCI" maxlength="11" inputmode="numeric" placeholder="00000000000"></div>
<div class="form-group"><label>Teléfono</label><input type="tel" id="tfPh" maxlength="10" inputmode="numeric" placeholder="0000000000"></div>
<div class="form-group"><label>Nombre del Cliente</label><input type="text" id="tfNm" oninput="this.value=this.value.toUpperCase()" placeholder="NOMBRE APELLIDOS"></div>
<button onclick="confirmar('¿Confirmar '+(window._isMixed?'PAGO MIXTO':'TRANSFERENCIA')+'?','',function(ok){if(ok)vSale(window._isMixed?'mixed':'transfer')})">✔ Confirmar</button>
</div>
<script>
var ALM='"""+a+"""',UID='"""+uid+"""';
var CART_KEY='g360_cart_'+ALM;
var SEL=null,PCash=0;
var cart=(function(){try{var s=localStorage.getItem(CART_KEY);return s?JSON.parse(s)||[]:[]}catch(e){return []}})();
function saveCart(){try{localStorage.setItem(CART_KEY,JSON.stringify(cart))}catch(e){}}
function loadTop5(){
fetch('/api/top5_ventas?almacen='+ALM).then(function(r){return r.json()}).then(function(data){
if(!data||!data.length){document.getElementById('top5Wrap').style.display='none';return}
var medals=['🥇','🥈','🥉','4️⃣','5️⃣'],h='';
data.forEach(function(p,i){
var safe=p.producto_nombre.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
h+='<div class="top5-chip" data-n="'+safe+'">'+
'<div class="tc-rank">'+medals[i]+' #'+(i+1)+'</div>'+
'<div class="tc-name">'+p.producto_nombre+'</div>'+
'<div class="tc-meta">'+parseFloat(p.total).toFixed(0)+' vendidos</div></div>';});
var grid=document.getElementById('top5Grid');
grid.innerHTML=h;
grid.querySelectorAll('.top5-chip').forEach(function(c){
c.addEventListener('click',function(){vBuscarDir(this.getAttribute('data-n'))})});
document.getElementById('top5Wrap').style.display='block';
}).catch(function(){})}
function vBuscarDir(nombre){document.getElementById('vSearch').value=nombre;vBuscar()}
var _searchTimer=null;
function vBuscar(){
var q=document.getElementById('vSearch').value.trim();var sugEl=document.getElementById('vSuggest');
var listEl=document.getElementById('vList');
clearTimeout(_searchTimer);
if(!q){sugEl.style.display='none';sugEl.innerHTML='';listEl.innerHTML='';return}
_searchTimer=setTimeout(function(){
var qu=q.toUpperCase();
fetch('/api/buscar_productos?q='+encodeURIComponent(qu)+'&almacen='+ALM)
.then(r=>r.json()).then(data=>{
if(!data.length){sugEl.style.display='none';listEl.innerHTML='<p style="text-align:center;color:#9FA8DA;padding:14px;font-size:13px">Sin resultados para "'+q+'"</p>';return}
var starts=[],contains=[];
data.forEach(p=>{
var nm=p.nombre.toUpperCase();
if(nm.indexOf(qu)===0)starts.push(p);
else contains.push(p);
});
var ordered=starts.concat(contains).slice(0,6);
var sH='';
ordered.slice(0,3).forEach(p=>{
sH+='<div class="suggest-item" data-id="'+p.id+'" data-n="'+p.nombre.replace(/"/g,'&quot;')+'" data-p="'+p.precio+'" data-s="'+p.stock+'">'
+'<div><div style="font-weight:700;font-size:14px;color:#e8eaf0">'+p.nombre+'</div>'
+'<div style="color:#8f96aa;font-size:12px;margin-top:2px">Stock: '+p.stock+' uds</div></div>'
+'<div style="color:#00E5FF;font-weight:800;font-size:14px">'+p.precio+' CUP</div></div>';
});
sugEl.innerHTML=sH;
sugEl.querySelectorAll('.suggest-item').forEach(function(el){
el.addEventListener('click',function(){
vQuickAdd(this.dataset.id,this.dataset.n,parseFloat(this.dataset.p),parseInt(this.dataset.s))})});
sugEl.style.display='block';
var h='';
ordered.forEach(p=>{
h+='<div class="product-item" data-id="'+p.id+'" data-n="'+p.nombre.replace(/"/g,'&quot;')+'" data-p="'+p.precio+'" data-s="'+p.stock+'">'
+'<div><span class="name">'+p.nombre+'</span><div class="info">Stock: '+p.stock+' uds</div></div>'
+'<span style="color:#00E5FF;font-weight:800">'+p.precio+' CUP</span></div>';
});
listEl.innerHTML=h;
listEl.querySelectorAll('.product-item').forEach(function(el){
el.addEventListener('click',function(){
vSel(this.dataset.id,this.dataset.n,parseFloat(this.dataset.p),parseInt(this.dataset.s))})});
});
},150);
}
function vQuickAdd(id,nombre,precio,stock){
if(stock<=0){toast('Sin stock disponible','terr');return}
var ex=cart.find(c=>c.id==id);
if(ex){
if(ex.qty+1>stock){toast('Stock insuficiente','terr');return}
ex.qty+=1;
}else{
cart.push({id:id,nombre:nombre,precio:precio,qty:1,stock:stock});
}
if(typeof saveCart === 'function') saveCart();
vRender();
document.getElementById('vSearch').value='';
document.getElementById('vSuggest').style.display='none';
document.getElementById('vList').innerHTML='';
toast('✅ '+nombre+' agregado','tok');
}
function vSel(id,n,p,s){SEL={id:id,nombre:n,precio:p,stock:s};
document.getElementById('vSelN').textContent=n;document.getElementById('vSelP').textContent=p+' CUP';
document.getElementById('vQty').value=1;document.getElementById('vQty').max=s;
document.getElementById('vSelS').textContent='Disponible: '+s+' uds';
document.getElementById('vSel').style.display='block';
document.getElementById('vList').innerHTML='';document.getElementById('vSearch').value=''}
function vQty(d){var i=document.getElementById('vQty'),v=parseInt(i.value)+d;if(v<1)v=1;if(v>SEL.stock)v=SEL.stock;i.value=v}
function vAdd(){if(!SEL)return;var q=parseInt(document.getElementById('vQty').value);
var ex=cart.find(c=>c.id==SEL.id);
if(ex){if(ex.qty+q>SEL.stock){toast('Sin suficiente stock','terr');return}ex.qty+=q}
else cart.push({id:SEL.id,nombre:SEL.nombre,precio:SEL.precio,qty:q,stock:SEL.stock});
saveCart();vRender();SEL=null;document.getElementById('vSel').style.display='none';toast('Agregado','tok')}
function vRender(){var el=document.getElementById('vCart'),te=document.getElementById('vTotalBox'),t=0,h='';
cart.forEach((c,i)=>{var s=c.precio*c.qty;t+=s;
h+='<div class="cart-item"><div><strong>'+c.nombre+'</strong><div style="color:#9FA8DA;font-size:13px">'+c.qty+' × '+c.precio+' CUP</div></div>'
+'<div style="text-align:right"><strong style="color:#00E5FF">'+s.toFixed(2)+'</strong><br>'
+'<button class="del" onclick="vRem('+i+')">✕</button></div></div>'});
el.innerHTML=h;if(cart.length){te.style.display='block';document.getElementById('vTotal').textContent=t.toFixed(2)}else te.style.display='none'}
function vRem(i){confirmar('¿Quitar '+cart[i].nombre+'?','',function(ok){if(ok){cart.splice(i,1);saveCart();vRender()}})}
function vOpenTf(){if(!cart.length)return;var t=cart.reduce((s,c)=>s+c.precio*c.qty,0);var restante=PCash>0?Math.max(0,t-PCash):t;document.getElementById('tfT').textContent=restante.toFixed(2);window._isMixed=PCash>0;
var sel=document.getElementById('tfBanco');sel.innerHTML='<option value="">Cargando tarjetas...</option>';
fetch('/api/get_tarjetas?almacen='+ALM).then(r=>r.json()).then(data=>{
sel.innerHTML='<option value="">Seleccionar tarjeta...</option>';
if(!data||!Array.isArray(data)||data.length===0){sel.innerHTML='<option value="">⚠️ No hay tarjetas para este local</option>';return}
data.forEach(tj=>{var numStr=String(tj.numero||'');var last4=numStr.length>=4?numStr.slice(-4):numStr;
sel.innerHTML+='<option value="'+tj.banco+' - '+numStr+'">'+tj.banco+' ····'+last4+'</option>'})})
.catch(err=>{console.error('Error al cargar tarjetas:',err);sel.innerHTML='<option value="">Error de conexión</option>'});
document.getElementById('vTfModal').classList.add('active')}
function vCloseTf(){document.getElementById('vTfModal').classList.remove('active')}
function vOpenMix(){if(!cart.length)return;var t=cart.reduce((s,c)=>s+c.precio*c.qty,0);
document.getElementById('mxT').textContent=t.toFixed(2);document.getElementById('mxEf').value='';document.getElementById('mxRest').value='';
document.getElementById('vMixModal').classList.add('active');
document.getElementById('mxEf').oninput=function(){var ef=parseFloat(this.value)||0;document.getElementById('mxRest').value=Math.max(0,t-ef).toFixed(2)}}
function vCloseMix(){document.getElementById('vMixModal').classList.remove('active')}
function vConfirmMix(){var t=cart.reduce((s,c)=>s+c.precio*c.qty,0);var ef=parseFloat(document.getElementById('mxEf').value)||0;
if(ef<0||ef>t){toast('Monto inválido','terr');return}vCloseMix();PCash=ef;vOpenTf()}
function vSale(method){if(!cart.length)return;
var total=cart.reduce((s,c)=>s+c.precio*c.qty,0),cliente=null,ef=0,tr=0;
if(method=='transfer'||method=='mixed'){
var ci=document.getElementById('tfCI').value.trim(),ph=document.getElementById('tfPh').value.trim(),
nm=document.getElementById('tfNm').value.trim(),banco=document.getElementById('tfBanco').value.trim();
if(!ci||!ph||!nm||!banco){toast('Completa todos los datos del cliente','terr');return}
cliente={ci:ci,phone:ph,name:nm,banco:banco}}
if(method=='cash')ef=total;else if(method=='transfer')tr=total;else{ef=PCash;tr=total-ef;PCash=0}
fetch('/api/guardar_venta',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({cart:cart,total:total,method:method,cliente:cliente,almacen:ALM,usuario_id:UID,cashAmount:ef,transferAmount:tr})})
.then(r=>r.json()).then(d=>{if(d.ok){cart=[];try{localStorage.removeItem(CART_KEY)}catch(e){}vRender();vCloseTf();vCloseMix();toast('✅ Venta: '+total.toFixed(2)+' CUP','tok');loadTop5()}else toast(d.error,'terr')})}
vRender();loadTop5();
</script>"""
    return page_auth("Ventas", body)

@app.route('/api/guardar_venta', methods=['POST'])
def api_guardar_venta():
    d=request.json; db=get_db(); ahora=datetime.datetime.now().isoformat()
    total_ef = d.get('cashAmount', d['total'] if d['method']=='cash' else 0)
    total_tr = d.get('transferAmount', d['total'] if d['method']=='transfer' else 0)
    grand_total = d['total'] if d['total'] else 1
    for item in d['cart']:
        item_total = item['qty'] * item['precio']
        ratio = item_total / grand_total
        ef = round(total_ef * ratio, 2)
        tr = round(total_tr * ratio, 2)
        db.execute("INSERT INTO ventas (producto_id,producto_nombre,cantidad,precio_unit,total,metodo,efectivo,transferencia,usuario_id,almacen_id,cliente_ci,cliente_tel,cliente_nombre,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (item['id'],item['nombre'],item['qty'],item['precio'],item_total,
                    d['method'],ef,tr,d.get('usuario_id',0),d['almacen'],
                    d['cliente']['ci'] if d.get('cliente') else '',
                    d['cliente']['phone'] if d.get('cliente') else '',
                    d['cliente']['name'] if d.get('cliente') else '',ahora))
        db.execute("UPDATE productos SET stock=MAX(0,stock-?) WHERE id=?",(item['qty'],item['id']))
        db.commit()
    u=session.get('user')
    if u: add_trace(u['username'],'VENTA',str(len(d['cart']))+' prod - '+str(d['total'])+' CUP',str(u.get('almacen_id','1')))
    return jsonify({'ok':True})

@app.route('/tarjetas')
def tarjetas():
    if 'user' not in session or session['user'].get('rol') not in ('admin','superadmin'): return redirect(url_for('dashboard'))
    a=get_almacen(); db=get_db()
    tarjs=db.execute("SELECT * FROM tarjetas WHERE almacen_id=? ORDER BY banco",(a,)).fetchall()
    h=topbar("Tarjetas", "/dashboard")+'<h3>💳 Tarjetas registradas</h3>'
    for t in tarjs:
        nm='···· ···· ···· '+str(t['numero'])[-4:] if len(str(t['numero']))>=4 else str(t['numero'])
        h+=('<div class="product-item"><div><span class="name">'+str(t['banco'])+'</span>'
             '<div class="info">'+nm+'</div></div>'
             '<button class="del" onclick="confirmar(\'¿Eliminar tarjeta?\',\''+nm+'\',function(ok){if(ok)location.href=\'/del_tarjeta/'+str(t['id'])+'\'})">✕</button></div>')
    h+=('<h3>Agregar Tarjeta</h3>'
         '<div class="form-group"><label>Banco / Entidad</label><input type="text" id="tB" oninput="this.value=this.value.toUpperCase()" placeholder="BANDEC, BPA, TRANSFERMÓVIL..."></div>'
         '<div class="form-group"><label>Número (16 dígitos)</label><input type="text" id="tN" placeholder="0000-0000-0000-0000" maxlength="19" inputmode="numeric" oninput="fmtC(this)"></div>'
         '<div style="padding:0 14px"><button onclick="confirmar(\'¿Agregar tarjeta?\',\'\',function(ok){if(ok)addT()})">💳 Agregar</button></div>'
         '<script>function fmtC(i){var v=i.value.replace(/[^0-9]/g,"").slice(0,16),r="";for(var j=0;j<v.length;j++){if(j>0&&j%4==0)r+="-";r+=v[j]}i.value=r}'
         'function addT(){var b=document.getElementById("tB").value.trim(),n=document.getElementById("tN").value.replace(/-/g,"");'
         'if(!b||n.length<16){toast("Completa los campos correctamente","terr");return}'
         'fetch("/api/add_tarjeta",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({banco:b,numero:n,almacen:"'+a+'"})})'
         '.then(r=>r.json()).then(d=>{if(d.ok){toast("Tarjeta agregada","tok");location.reload()}else toast(d.error,"terr")})}</script>')
    return page_auth("Tarjetas", h)

@app.route('/del_tarjeta/<int:tid>')
def del_tarjeta(tid):
    get_db().execute("DELETE FROM tarjetas WHERE id=?",(tid,)); get_db().commit()
    return redirect(url_for('tarjetas'))

@app.route('/api/add_tarjeta', methods=['POST'])
def api_add_tarjeta():
    d=request.json; db=get_db()
    db.execute("INSERT INTO tarjetas (banco,numero,almacen_id) VALUES (?,?,?)",(d['banco'],d['numero'],d.get('almacen','1')))
    db.commit(); return jsonify({'ok':True})

@app.route('/api/get_tarjetas')
def api_get_tarjetas():
    a=request.args.get('almacen','1'); db=get_db()
    return jsonify([dict(t) for t in db.execute("SELECT * FROM tarjetas WHERE almacen_id=?",(a,)).fetchall()])

@app.route('/inventario')
def inventario():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen(); db=get_db(); hoy=datetime.date.today().isoformat()
    vs=db.execute("SELECT * FROM ventas WHERE almacen_id=? AND created_at LIKE ? ORDER BY created_at DESC",(a,hoy+'%')).fetchall()
    tot=sum(v['total'] or 0 for v in vs); ef=sum(v['efectivo'] or 0 for v in vs); tr=sum(v['transferencia'] or 0 for v in vs)
    h=topbar("Inventario del Día", "/dashboard")
    h+=('<div class="stat-row">'
         '<div class="stat-card"><div class="stat-val">'+str(round(tot,2))+'</div><div class="stat-lbl">💰 Total CUP</div></div>'
         '<div class="stat-card"><div class="stat-val">'+str(len(vs))+'</div><div class="stat-lbl">🛒 Ventas</div></div>'
         '<div class="stat-card"><div class="stat-val">'+str(round(ef,2))+'</div><div class="stat-lbl">💵 Efectivo</div></div>'
         '<div class="stat-card"><div class="stat-val">'+str(round(tr,2))+'</div><div class="stat-lbl">📲 Transfer.</div></div>'
         '</div>')
    if not vs:
        h+='<p style="text-align:center;color:#9FA8DA;padding:28px">Sin ventas registradas hoy</p>'
    for v in vs:
        try: hs=datetime.datetime.fromisoformat(v['created_at']).strftime('%H:%M')
        except: hs=''
        ico='💵' if v['metodo']=='cash' else '📲' if v['metodo']=='transfer' else '💱'
        h+=('<div class="product-item"><div><span class="name">'+str(v['producto_nombre'])+' ×'+str(v['cantidad'])+'</span>'
             '<div class="info">'+hs+' '+ico+'</div></div>'
             '<span style="color:#00E5FF;font-weight:700">'+str(round(v['total'] or 0,2))+'</span></div>')
    return page_auth("Inventario", h)

@app.route('/stock_real')
def stock_real():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen(); db=get_db()
    ps=db.execute("SELECT * FROM productos WHERE almacen_id=? ORDER BY stock ASC",(a,)).fetchall()
    h=topbar("Stock Real", "/dashboard")+'<h3>Inventario Actual</h3>'
    for i,p in enumerate(ps):
        al='🔴 AGOTADO' if p['stock']<=0 else '🟡 Bajo' if p['stock']<=5 else '🟢'
        h+=('<div class="product-item"><div><span class="name">'+str(i+1)+'. '+str(p['nombre'])+'</span>'
             '<div class="info">'+al+' '+str(p['stock'])+' uds | '+str(p['precio'])+' CUP</div></div></div>')
    return page_auth("Stock Real", h)

@app.route('/merma')
def merma():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen(); db=get_db()
    ps=db.execute("SELECT * FROM productos WHERE almacen_id=? ORDER BY nombre",(a,)).fetchall()
    h=topbar("Registrar Merma", "/dashboard")+'<h3>Selecciona producto y cantidad</h3>'
    for p in ps:
        h+=('<div class="product-item"><div><span class="name">'+str(p['nombre'])+'</span>'
             '<div class="info">Stock: '+str(p['stock'])+' uds</div></div>'
             '<div style="display:flex;gap:6px;align-items:center">'
             '<input type="number" id="m_'+str(p['id'])+'" placeholder="0" min="1" max="'+str(p['stock'])+'" style="width:70px;font-size:15px;margin:0">'
             '<button class="danger btn-sm" onclick="confirmar(\'¿Merma de '+str(p['nombre'])+'?\',\'\',function(ok){if(ok)sM('+str(p['id'])+')})">✔</button>'
             '</div></div>')
    h+=('<script>function sM(id){var q=parseInt(document.getElementById("m_"+id).value);'
         'if(!q||q<=0){toast("Cantidad inválida","terr");return}'
         'fetch("/api/merma",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:id,cantidad:q})})'
         '.then(r=>r.json()).then(d=>{if(d.ok){toast("Merma registrada","tok");location.reload()}else toast(d.error,"terr")})}'
         '</script>')
    return page_auth("Merma", h)

@app.route('/busqueda')
def busqueda():
    if 'user' not in session: return redirect(url_for('login'))
    a=get_almacen()
    body=topbar("Búsqueda por Fechas","/dashboard")+"""
<div style="display:flex;gap:10px;padding:0 14px 10px">
<div style="flex:1"><label style="font-size:11px;font-weight:700;color:#8f96aa;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.8px">Desde</label><input type="date" id="bD" style="margin:0"></div>
<div style="flex:1"><label style="font-size:11px;font-weight:700;color:#8f96aa;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.8px">Hasta</label><input type="date" id="bH" style="margin:0"></div>
</div>
<div style="padding:0 14px"><button onclick="bBuscar()">🔍 Buscar</button></div>
<div id="bRes"></div>
<script>
function bBuscar(){var d=document.getElementById('bD').value,h=document.getElementById('bH').value;
if(!d||!h){toast('Selecciona las fechas','terr');return}
fetch('/api/busqueda?desde='+d+'&hasta='+h+'&almacen='+'"""+a+"""').then(r=>r.json()).then(data=>{
if(!data.length){document.getElementById('bRes').innerHTML='<p style="text-align:center;color:#9FA8DA;padding:18px">Sin resultados</p>';return}
var tot=0,ef=0,tr=0,h='<h3>'+data.length+' ventas</h3>';
data.forEach(v=>{tot+=v.total||0;ef+=v.efectivo||0;tr+=v.transferencia||0;
var ico=v.metodo=='cash'?'💵':v.metodo=='transfer'?'📲':'💱';
h+='<div class="product-item"><div><span class="name">'+v.producto_nombre+' ×'+v.cantidad+'</span>'
+'<div class="info">'+ico+' | '+(v.created_at||'').substring(0,16).replace('T',' ')+'</div></div>'
+'<span style="color:#00E5FF;font-weight:700">'+parseFloat(v.total||0).toFixed(2)+'</span></div>'});
h+='<div class="inv-header" style="margin-top:8px"><strong>Total: '+tot.toFixed(2)+' CUP</strong><br>'
+'<span style="color:#9FA8DA;font-size:13px">Efectivo: '+ef.toFixed(2)+' | Transfer.: '+tr.toFixed(2)+'</span></div>';
document.getElementById('bRes').innerHTML=h})}
</script>"""
    return page_auth("Búsqueda", body)

@app.route('/api/busqueda')
def api_busqueda():
    desde=request.args.get('desde',''); hasta=request.args.get('hasta',''); a=request.args.get('almacen','1'); db=get_db()
    vs=db.execute("SELECT * FROM ventas WHERE almacen_id=? AND created_at BETWEEN ? AND ? ORDER BY created_at DESC",(a,desde+'T00:00:00',hasta+'T23:59:59')).fetchall()
    return jsonify([dict(v) for v in vs])

@app.route('/seguridad_logs')
def seguridad_logs():
    if session.get('user',{}).get('rol') != 'superadmin': return redirect(url_for('dashboard'))
    db = get_db()
    page = max(1, int(request.args.get('page', 1) or 1))
    per_page = 15
    evento_f = clean_text(request.args.get('evento',''), 40)
    w = "WHERE 1=1"; params = []
    if evento_f:
        w += " AND evento LIKE ?"; params.append('%'+evento_f+'%')
    count = db.execute("SELECT COUNT(*) FROM seguridad_logs "+w, params).fetchone()[0]
    total_pages = max(1, math.ceil(count/per_page))
    page = min(page, total_pages)
    offset = (page-1)*per_page
    logs = db.execute("SELECT * FROM seguridad_logs "+w+" ORDER BY id DESC LIMIT ? OFFSET ?", params+[per_page, offset]).fetchall()

    h = topbar("Seguridad", "/dashboard")
    h += '<div class="stat-row">'
    h += '<div class="stat-card"><div class="stat-val">'+str(count)+'</div><div class="stat-lbl">Eventos</div></div>'
    h += '<div class="stat-card"><div class="stat-val">'+str(len(LOCKED_ACCOUNTS))+'</div><div class="stat-lbl">🔒 Cuentas bloq.</div></div>'
    h += '<div class="stat-card"><div class="stat-val">'+str(len(LOGIN_ATTEMPTS))+'</div><div class="stat-lbl">🌐 IPs vigiladas</div></div>'
    h += '</div>'
    if LOCKED_ACCOUNTS:
        h += '<h3>Cuentas bloqueadas</h3>'
        for uname, until in LOCKED_ACCOUNTS.items():
            h += ('<div class="product-item"><div><span class="name">🔒 '+str(uname)+'</span>'
                  '<div class="info">Hasta: '+until.strftime('%d/%m %H:%M')+'</div></div></div>')
    h += '<div class="form-group"><input type="text" id="sEv" placeholder="🔍 Filtrar por evento (LOGIN_FALLIDO, CUENTA_BLOQUEADA...)" value="'+evento_f+'" oninput="location.href=\'/seguridad_logs?evento=\'+this.value"></div>'
    h += '<h3>Registro de eventos ('+str(count)+')</h3>'
    h += '<p style="text-align:center;color:#9FA8DA;font-size:12px;margin:8px">Pág '+str(page)+'/'+str(total_pages)+'</p>'
    for lg in logs:
        try: fs = datetime.datetime.fromisoformat(lg['created_at']).strftime('%d/%m %H:%M')
        except Exception: fs = str(lg['created_at'])[:16]
        h += ('<div class="product-item"><div><span class="name">⚠️ '+str(lg['evento'])+'</span>'
              '<div class="info">'+str(lg['detalle'])+'</div>'
              '<div class="info" style="font-size:11px">🌐 '+str(lg['ip'])+' · '+fs+'</div></div></div>')
    if total_pages > 1:
        h += '<div style="text-align:center;margin:10px;display:flex;flex-wrap:wrap;justify-content:center">'
        for p in range(1, total_pages+1):
            h += '<button class="page-btn '+('active' if p==page else '')+'" onclick="location.href=\'/seguridad_logs?page='+str(p)+'&evento='+evento_f+'\'">'+str(p)+'</button>'
        h += '</div>'
    return page_auth("Seguridad", h)

@app.route('/trazas')
def trazas():
    if 'user' not in session: return redirect(url_for('login'))
    u=session['user']; a=get_almacen(); is_s=u.get('rol')=='superadmin'
    pn=max(1,int(request.args.get('page',1))); pp=15; db=get_db()
    fecha=request.args.get('fecha',''); fid=request.args.get('fid',a if not is_s else '')
    w="WHERE 1=1"; params=[]
    if fecha: w+=" AND created_at BETWEEN ? AND ?"; params.extend([fecha+'T00:00:00',fecha+'T23:59:59'])
    if fid: w+=" AND almacen_id=?"; params.append(fid)
    elif not is_s: w+=" AND almacen_id=?"; params.append(a)
    count=db.execute("SELECT COUNT(*) FROM trazas "+w,params).fetchone()[0]
    tp=max(1,math.ceil(count/pp)); offset=(pn-1)*pp
    traces=db.execute("SELECT * FROM trazas "+w+" ORDER BY created_at DESC LIMIT ? OFFSET ?",params+[pp,offset]).fetchall()
    back="/dashboard"
    h=topbar("Trazas",back)
    h+='<div class="form-group"><label>Fecha</label><input type="date" id="tF" value="'+fecha+'"></div>'
    if is_s: h+='<div class="form-group"><label>ID Local (vacío = todos)</label><input type="text" id="tFid" value="'+fid+'" placeholder="vacío = todos"></div>'
    h+='<div style="padding:0 14px;display:flex;gap:8px"><button onclick="tFilt()">🔍 Filtrar</button>'
    if is_s: h+='<button class="danger" onclick="confirmar(\'¿Eliminar trazas visibles?\',\'\',function(ok){if(ok)tLimp()})">🗑</button>'
    h+='</div>'
    fid_js='document.getElementById("tFid")?document.getElementById("tFid").value:""'
    h+='<p style="text-align:center;color:#9FA8DA;font-size:12px;margin:8px">'+str(count)+' reg. | Pág '+str(pn)+'/'+str(tp)+'</p>'
    for t in traces:
        try: fs=datetime.datetime.fromisoformat(t['created_at']).strftime('%d/%m %H:%M')
        except: fs=str(t['created_at'])[:16]
        h+=('<div class="product-item"><div><span class="name">👤 '+str(t['usuario'])+'</span>'
             '<div class="info">'+str(t['accion'])+' — '+str(t['detalle'])+'</div>'
             '<div class="info" style="font-size:11px">🏪'+str(t['almacen_id'])+' · '+fs+'</div></div></div>')
    if tp>1:
        h+='<div style="text-align:center;margin:10px;display:flex;flex-wrap:wrap;justify-content:center">'
        for p in range(1,tp+1):
            h+='<button class="page-btn '+('active' if p==pn else '')+'" onclick="tPage('+str(p)+')">'+str(p)+'</button>'
        h+='</div>'
    h+=('<script>'
         'function tFilt(){var f=document.getElementById("tF").value,fid='+fid_js+';location.href="/trazas?fecha="+f+"&fid="+fid}'
         'function tPage(p){var f=document.getElementById("tF").value,fid='+fid_js+';location.href="/trazas?page="+p+"&fecha="+f+"&fid="+fid}'
         'function tLimp(){var f=document.getElementById("tF").value,fid='+fid_js+';'
         'fetch("/api/clear_trazas?fecha="+f+"&fid="+fid).then(r=>r.json()).then(d=>{if(d.ok){toast("Trazas eliminadas","tok");location.reload()}else toast(d.error,"terr")})}'
         '</script>')
    return page_auth("Trazas", h)

@app.route('/api/clear_trazas')
def api_clear_trazas():
    if session.get('user',{}).get('rol')!='superadmin': return jsonify({'ok':False})
    fecha=request.args.get('fecha',''); fid=request.args.get('fid',''); db=get_db()
    w="WHERE 1=1"; params=[]
    if fecha: w+=" AND created_at BETWEEN ? AND ?"; params.extend([fecha+'T00:00:00',fecha+'T23:59:59'])
    if fid: w+=" AND almacen_id=?"; params.append(fid)
    db.execute("DELETE FROM trazas "+w,params); db.commit()
    return jsonify({'ok':True})

@app.route('/chat')
def chat():
    if 'user' not in session: return redirect(url_for('login'))
    u=session['user']; a=get_almacen()
    uname=str(u.get('nombre') or u.get('username'))
    inicial = uname[:1].upper() if uname else '?'
    body=topbar("Chat Interno","/dashboard")+"""
<style>
#msgs{padding:14px 12px 90px;display:flex;flex-direction:column;gap:2px;min-height:50vh}
.chat-row{display:flex;gap:8px;align-items:flex-end;margin:4px 0}
.chat-row.me{flex-direction:row-reverse}
.chat-av{width:28px;height:28px;border-radius:50%;background:#3a4258;color:#4dd0c4;
display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;flex-shrink:0}
.chat-row.me .chat-av{background:#4dd0c4;color:#0d1b3e}
.chat-col{display:flex;flex-direction:column;max-width:78%}
.chat-row.me .chat-col{align-items:flex-end}
.chat-name{font-size:11px;color:#8f96aa;margin:0 4px 2px;font-weight:600}
.chat-bubble{padding:9px 13px;border-radius:16px;font-size:14.5px;line-height:1.42;
word-break:break-word;box-shadow:0 1px 2px rgba(0,0,0,.18)}
.chat-bubble.me{background:linear-gradient(135deg,#4dd0c4,#3bb8ac);color:#0d1b3e;
border-radius:16px 16px 4px 16px;font-weight:600}
.chat-bubble.other{background:#252b3d;border:1px solid #353c52;color:#e8eaf0;
border-radius:16px 16px 16px 4px}
.chat-time{font-size:10px;color:#6b7388;margin:2px 5px 0}
.chat-inputbar{position:fixed;left:0;right:0;bottom:0;display:flex;gap:8px;align-items:center;
padding:10px 12px calc(10px + env(safe-area-inset-bottom));
background:#1a1f2e;border-top:1px solid #3a4258;z-index:100}
#cInp{flex:1;margin:0;background:#252b3d;border:1px solid #3a4258;border-radius:22px;
padding:12px 18px;font-size:15px;color:#e8eaf0}
#cInp:focus{border-color:#4dd0c4;outline:none}
#cSendBtn{width:44px;height:44px;min-width:44px;border-radius:50%;margin:0;padding:0;
display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;
background:#4dd0c4;color:#0d1b3e;border:none;box-shadow:0 2px 8px rgba(77,208,196,.35)}
#cSendBtn:active{transform:scale(.93)}
.chat-empty{text-align:center;color:#6b7388;font-size:13px;padding:30px}
</style>
<div id="msgs"></div>
<div class="chat-inputbar">
<input type="text" id="cInp" placeholder="Escribe un mensaje..." autocomplete="off">
<button id="cSendBtn" onclick="cSend()">➤</button>
</div>
<script>
var KEY='chat_"""+a+"""',UN='"""+uname+"""',INI='"""+inicial+"""';
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function load(){var ms=JSON.parse(localStorage.getItem(KEY)||'[]'),el=document.getElementById('msgs');
if(!ms.length){el.innerHTML='<div class="chat-empty">💬 Aún no hay mensajes<br>Escribe el primero</div>';return}
var nearBottom=window.innerHeight+window.scrollY>=document.body.scrollHeight-150;
el.innerHTML='';ms.slice(-50).forEach(function(m){var me=m.user===UN;var ini=(m.user||'?').slice(0,1).toUpperCase();
el.innerHTML+='<div class="chat-row '+(me?'me':'other')+'">'
+'<div class="chat-av">'+(me?INI:ini)+'</div>'
+'<div class="chat-col">'
+(me?'':'<div class="chat-name">'+esc(m.user)+'</div>')
+'<div class="chat-bubble '+(me?'me':'other')+'">'+esc(m.text)+'</div>'
+'<div class="chat-time">'+m.time+'</div>'
+'</div></div>'});
if(nearBottom||ms.length<=1)window.scrollTo(0,document.body.scrollHeight)}
function cSend(){var inp=document.getElementById('cInp'),t=inp.value.trim();if(!t)return;
var ms=JSON.parse(localStorage.getItem(KEY)||'[]');
ms.push({user:UN,text:t,time:new Date().toLocaleTimeString('es-CU',{hour:'2-digit',minute:'2-digit'})});
if(ms.length>100)ms=ms.slice(-100);localStorage.setItem(KEY,JSON.stringify(ms));inp.value='';load();
window.scrollTo(0,document.body.scrollHeight)}
document.getElementById('cInp').addEventListener('keydown',function(e){if(e.key==='Enter')cSend()});
load();setInterval(load,3000);
</script>"""
    return page_auth("Chat", body)

@app.route('/contador')
def contador():
    if 'user' not in session: return redirect(url_for('login'))
    body=topbar("Contador de Efectivo","/dashboard")+"""
<div style="padding:0 14px 11px">
<div class="inv-header" style="text-align:center">
<div style="font-size:11px;color:#9FA8DA;text-transform:uppercase;letter-spacing:1px">Total contado</div>
<div class="bill-total"><span id="cT">0.00</span> CUP</div>
</div>
</div>
<div id="bills"></div>
<div style="padding:0 14px"><button class="dark" onclick="confirmar('¿Limpiar todo?','',function(ok){if(ok)cLimp()})">🗑 Limpiar</button></div>
<script>
var BILLS=[5000,2000,1000,500,200,100,50,20,10,5,1],cnts={};
BILLS.forEach(function(b){cnts[b]=0});
function render(){var h='',t=0;
[{l:'💵 Billetes',b:[5000,2000,1000,500,200,100,50,20,10]},{l:'🪙 Monedas',b:[5,1]}].forEach(function(s){
h+='<p style="margin:9px 14px 3px;font-size:11px;font-weight:700;color:#9FA8DA;text-transform:uppercase;letter-spacing:1px">'+s.l+'</p>';
s.b.forEach(function(b){t+=cnts[b]*b;
h+='<div class="bill-row"><span class="bill-denom">'+b+' CUP</span>'
+'<input type="number" class="bill-input" id="b_'+b+'" value="'+(cnts[b]||'')+'" min="0" placeholder="0" inputmode="numeric" oninput="upd('+b+',this.value)">'
+'<span class="bill-sub" id="s_'+b+'">'+(cnts[b]*b>0?(cnts[b]*b).toFixed(2):'—')+'</span></div>'})});
document.getElementById('bills').innerHTML=h;document.getElementById('cT').textContent=t.toFixed(2)}
function upd(b,v){cnts[b]=parseInt(v)||0;var s=document.getElementById('s_'+b);
if(s)s.textContent=cnts[b]>0?(cnts[b]*b).toFixed(2):'—';
var t=0;BILLS.forEach(function(x){t+=cnts[x]*x});document.getElementById('cT').textContent=t.toFixed(2)}
function cLimp(){BILLS.forEach(function(b){cnts[b]=0});render()}
render();
</script>"""
    return page_auth("Contador", body)

@app.route('/sync')
def sync():
    if session.get('user',{}).get('rol')!='superadmin': return redirect(url_for('dashboard'))
    try:
        db=sqlite3.connect(DB_PATH)
        res=supabase.table("usuarios").select("*").execute()
        if res.data:
            for u in res.data:
                db.execute("INSERT OR REPLACE INTO usuarios (id,username,password,nombre,rol,pin,almacen_id) VALUES (?,?,?,?,?,?,?)",
                           (u['id'],u['username'],u['password'],u.get('nombre'),u['rol'],u.get('pin'),u.get('almacen_id')))
                db.commit()
        res2=supabase.table("productos").select("*").execute()
        if res2.data:
            for p in res2.data:
                db.execute("INSERT OR REPLACE INTO productos VALUES (?,?,?,?,?)",
                           (p['id'],p['nombre'],p['precio'],p['stock'],p.get('almacen_id','1')))
                db.commit()
        db.close()
        add_trace(session['user']['username'],'SYNC','Exitosa','0')
        msg='<div class="inv-header"><h3>✅ Sincronización exitosa</h3></div>'
    except Exception as e:
        msg='<div class="error">Error: '+str(e)[:100]+'</div>'
    return page_auth("Sync", topbar("Sync", "/dashboard")+msg+'<div style="padding:0 14px"><button onclick="location.href=\'/dashboard\'">← Dashboard</button></div>')

def pol(titulo, contenido):
    body=('<div class="topbar"><button class="hbg" style="visibility:hidden"><span></span><span></span><span></span></button>'
           '<span class="tb-title">'+titulo+'</span><button class="tb-back" onclick="history.back()">← Volver</button></div>'
           '<div style="padding:16px;max-width:800px;margin:0 auto;color:#C5CAE9;line-height:1.8">'+contenido+'</div>')
    return page_plain(titulo, body)

@app.route('/privacidad')
def privacidad():
    return pol("Privacidad","<h2>Política de Privacidad</h2><p>Actualización: 14/06/2026</p><br><h3>1. Datos</h3><p>Solo datos necesarios para gestión comercial.</p><br><h3>2. Almacenamiento</h3><p>SQLite local + Supabase con SHA256.</p><br><h3>3. Contacto</h3><p>luisi26@nauta.cu</p>")

@app.route('/seguridad')
def seguridad():
    return pol("Seguridad","<h2>Política de Seguridad</h2><p>Actualización: 19/06/2026</p><br><h3>1. Protección</h3><p>SHA256, rate limiting 5 intentos/5min por IP, bloqueo de cuenta tras 10 intentos fallidos (30 min), backup cada hora, cabeceras HTTP de seguridad.</p><br><h3>2. Roles</h3><p>Superadmin / Admin (PIN 5 min) / Vendedor.</p><br><h3>3. Auditoría</h3><p>Registro de eventos de seguridad (logins fallidos, bloqueos, IPs) visible para Superadmin.</p><br><h3>4. Contacto</h3><p>luisi26@nauta.cu</p>")

@app.route('/terminos')
def terminos():
    return pol("Términos","<h2>Términos de Uso</h2><p>Actualización: 14/06/2026</p><br><h3>1. Aceptación</h3><p>El uso implica aceptación total.</p><br><h3>2. Responsabilidad</h3><p>El usuario resguarda sus credenciales.</p><br><h3>3. Contacto</h3><p>luisi26@nauta.cu</p>")

@app.route('/licencia_terminos')
def licencia_terminos():
    return pol("Licencia","<h2>Acuerdo de Licencia</h2><p>Actualización: 14/06/2026</p><br><h3>1. Modelo</h3><p>Licencia por dispositivo. No transferible.</p><br><h3>2. Vigencia</h3><p>Definida por el Superadmin en días.</p><br><h3>3. Contacto</h3><p>luisi26@nauta.cu</p>")

with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=False, use_reloader=False)
