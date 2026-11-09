import os
import sys
import json
import uuid
import base64
import smtplib
import threading
import urllib.request
import urllib.error
import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, session as flask_session
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# Ensure UTF-8 console output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def safe_log(msg):
    """Thread-safe console logger across environments"""
    try:
        print(msg, flush=True)
    except Exception:
        try:
            print(str(msg).encode('ascii', errors='replace').decode('ascii'), flush=True)
        except Exception:
            pass

# --- Initialize Flask Application ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishing-sim-secret-key-2026-admin-lock")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')

# Base64-encoded fallback credentials
_FALLBACK_DB = base64.b64decode("cG9zdGdyZXNxbDovL2F2bmFkbWluOkFWTlNfR3hNek5DUjJSMy1LTDlsVU1fa0BwaGlzaGluZ2RhdGFiYXNlLWRhbmdtaW5oY2hpMjAwNDE5MDYtbWVkY2FyZS5rLmFpdmVuY2xvdWQuY29tOjEzNjQ4L2RlZmF1bHRkYj9zc2xtb2RlPXJlcXVpcmU=").decode('utf-8')
_FALLBACK_PW = base64.b64decode("Y2VmdmprdnBpeWFqb3NpcQ==").decode('utf-8')

def load_config():
    default_config = {
        "database_url": _FALLBACK_DB,
        "admin_password": os.environ.get("ADMIN_PASSWORD", "admin123"),
        "server": {
            "host": "0.0.0.0",
            "port": 5000,
            "base_url": ""
        },
        "campaign": {
            "tracking_path": "/v",
            "use_internal_awareness": True,
            "external_landing_page_url": "https://sites.google.com/view/chopda-enterprise-test/home",
            "email_subject": "Thông báo quan trọng: Xác nhận tài khoản và quyền lợi nhân viên",
            "sender_display_name": "Cổng Thông Tin Nhân Sự",
            "sender_email": "security-alert@internal-portal.com"
        },
        "smtp": {
            "enabled": True,
            "server": "smtp.gmail.com",
            "port": 465,
            "username": "dangminhchi20041906@gmail.com",
            "password": _FALLBACK_PW,
            "webhook_url": ""
        }
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                for k, v in loaded.items():
                    if isinstance(v, dict) and k in default_config and isinstance(default_config[k], dict):
                        default_config[k].update(v)
                    else:
                        default_config[k] = v
        except Exception as e:
            safe_log(f"[!] Failed to read config.json ({e}), using defaults.")

    if default_config['campaign'].get('tracking_path') == '/verify/portal-auth':
        default_config['campaign']['tracking_path'] = '/v'

    # Prioritize cloud environment variables (Render)
    if os.environ.get('DATABASE_URL'):
        default_config['database_url'] = os.environ.get('DATABASE_URL')
    if os.environ.get('BASE_URL'):
        default_config['server']['base_url'] = os.environ.get('BASE_URL')
    if os.environ.get('SMTP_USERNAME'):
        default_config['smtp']['username'] = os.environ.get('SMTP_USERNAME')
    if os.environ.get('SMTP_PASSWORD'):
        default_config['smtp']['password'] = os.environ.get('SMTP_PASSWORD')
    if os.environ.get('SMTP_ENABLED'):
        default_config['smtp']['enabled'] = os.environ.get('SMTP_ENABLED').lower() in ('true', '1', 'yes')
    if os.environ.get('EMAIL_WEBHOOK_URL'):
        default_config['smtp']['webhook_url'] = os.environ.get('EMAIL_WEBHOOK_URL')
    if os.environ.get('ADMIN_PASSWORD'):
        default_config['admin_password'] = os.environ.get('ADMIN_PASSWORD')

    return default_config

config = load_config()

# --- Database Models (Aiven PostgreSQL via SQLAlchemy) ---
Base = declarative_base()

class User(Base):
    """Target recipients table"""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), default='Employee')
    department = Column(String(255), default='Unassigned')
    token = Column(String(64), unique=True, nullable=False, index=True)
    clicked = Column(Boolean, default=False)
    ip_address = Column(String(100), default='N/A')
    user_agent = Column(Text, default='N/A')
    clicked_at = Column(String(100), default='N/A')
    last_sent_at = Column(String(100), default='Not sent')

class ClickLog(Base):
    """Click activity log table"""
    __tablename__ = 'click_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(255), nullable=False)
    user_name = Column(String(255), default='Employee')
    department = Column(String(255), default='Unassigned')
    token = Column(String(64), nullable=False)
    ip_address = Column(String(100), default='N/A')
    user_agent = Column(Text, default='N/A')
    clicked_at = Column(String(100), default='N/A')

class AppSetting(Base):
    """Persistent application settings table"""
    __tablename__ = 'app_settings'
    key = Column(String(100), primary_key=True)
    value = Column(Text, default='')

engine = None
Session = None
last_db_error = ""

# Background bulk email job state
_send_lock = threading.Lock()
campaign_send_state = {
    "running": False,
    "sent": 0,
    "failed": 0,
    "total": 0,
    "last_error": "",
    "finished_at": ""
}

UNSENT_MARKERS = ('Chưa gửi', 'Not sent', '', None)

def is_unsent_value(val):
    return (val or '').strip() in ('Chưa gửi', 'Not sent', '')

def format_sent_display(val):
    if is_unsent_value(val):
        return 'Not sent'
    return val

def format_dept_display(val):
    cleaned = (val or '').strip()
    if not cleaned or cleaned == 'Chưa phân loại':
        return 'Unassigned'
    return cleaned

def ensure_pg_driver():
    """Ensure psycopg2 or psycopg driver is installed"""
    for mod_name in ("psycopg2", "psycopg"):
        try:
            __import__(mod_name)
            return mod_name
        except ImportError:
            pass
    try:
        import subprocess
        safe_log("[AUTO-INSTALL] Installing PostgreSQL driver...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "psycopg2-binary", "psycopg[binary]"])
        for mod_name in ("psycopg2", "psycopg"):
            try:
                __import__(mod_name)
                return mod_name
            except ImportError:
                pass
    except Exception as e:
        safe_log(f"[AUTO-INSTALL INFO] {e}")
    return "psycopg2"

def clean_db_url(url_str, driver="psycopg2"):
    """Sanitize DATABASE_URL and bind active PostgreSQL driver"""
    if not url_str:
        return ""
    s = str(url_str).strip().strip('"').strip("'")
    idx = s.find("postgres")
    if idx > 0:
        s = s[idx:]
    if "://" in s:
        _, rest = s.split("://", 1)
        s = f"postgresql+{driver}://{rest}"
    return s

def init_database():
    global engine, Session, last_db_error
    active_driver = ensure_pg_driver()
    candidates = []
    for raw in [os.environ.get('DATABASE_URL', ''), config.get("database_url", ""), _FALLBACK_DB]:
        cleaned = clean_db_url(raw, driver=active_driver)
        if cleaned and cleaned not in candidates:
            candidates.append(cleaned)

    for db_url in candidates:
        try:
            test_engine = create_engine(
                db_url,
                pool_pre_ping=True,
                pool_recycle=180,
                connect_args={'connect_timeout': 10}
            )
            with test_engine.connect() as conn:
                pass

            engine = test_engine
            Session = scoped_session(sessionmaker(bind=engine))

            try:
                Base.metadata.create_all(engine)
            except Exception as table_err:
                safe_log(f"[DB INFO] Tables already exist: {table_err}")

            last_db_error = ""
            safe_log("[DB OK] Connected to Aiven PostgreSQL (users & click_logs ready).")
            return True
        except Exception as e:
            last_db_error = str(e)
            safe_log(f"[DB RETRY] Connection failed ({e}), trying fallback URL...")

    engine = None
    Session = None
    return False

def get_db_session():
    """Retrieve a database session, reconnecting automatically if needed"""
    global Session
    if Session is None:
        init_database()
    if Session is not None:
        return Session()
    return None

init_database()

def get_vn_now_str():
    """Return current timestamp in UTC+7 (YYYY-MM-DD HH:MM:SS)"""
    vn_tz = datetime.timezone(datetime.timedelta(hours=7))
    return datetime.datetime.now(vn_tz).strftime("%Y-%m-%d %H:%M:%S")

def generate_unique_token(session, reserved_tokens=None):
    """Generate a guaranteed-unique 8-character hex tracking token"""
    if reserved_tokens is None:
        reserved_tokens = set()
    while True:
        candidate = uuid.uuid4().hex[:8]
        if candidate in reserved_tokens:
            continue
        exists = session.query(User.id).filter_by(token=candidate).first()
        if not exists:
            reserved_tokens.add(candidate)
            return candidate

# --- Admin Authentication & Settings Helpers ---
def get_admin_password():
    """Retrieve admin password from DB or fallback config"""
    session = get_db_session()
    if session:
        try:
            row = session.query(AppSetting).filter_by(key='admin_password').first()
            if row and row.value and row.value.strip():
                return row.value.strip()
        except Exception:
            session.rollback()
    return config.get("admin_password", "admin123")

def admin_required(f):
    """Restrict access to authenticated administrators"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not flask_session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def get_active_base_url():
    """Resolve active public base URL (Render or Local)"""
    configured_url = config.get("server", {}).get("base_url", "").strip().rstrip("/")
    try:
        if request and request.host_url:
            current_host = request.host_url.rstrip("/")
            if "127.0.0.1" not in current_host and "localhost" not in current_host:
                if current_host.startswith("http://") and ".onrender.com" in current_host:
                    current_host = current_host.replace("http://", "https://", 1)
                return current_host
            if not configured_url:
                return current_host
    except Exception:
        pass
    return configured_url or "http://127.0.0.1:5000"

def get_saved_setting(key, default_val=""):
    """Read a persistent key from app_settings"""
    session = get_db_session()
    if session:
        try:
            row = session.query(AppSetting).filter_by(key=key).first()
            if row and row.value and row.value.strip():
                return row.value.strip()
        except Exception:
            session.rollback()
    return default_val

def upsert_setting(session, key, val):
    """Insert or update a setting in app_settings within an active transaction"""
    row = session.query(AppSetting).filter_by(key=key).first()
    if row:
        row.value = val
    else:
        session.add(AppSetting(key=key, value=val))

def get_saved_webhook_url():
    return get_saved_setting('webhook_url', config.get("smtp", {}).get("webhook_url", "").strip())

def get_saved_smtp_username():
    return get_saved_setting('smtp_username', config.get("smtp", {}).get("username", "").strip())

def get_saved_smtp_password():
    return get_saved_setting('smtp_password', config.get("smtp", {}).get("password", "").strip())

def get_saved_sender_name():
    camp_conf = config.get("campaign", {})
    return get_saved_setting("sender_name", camp_conf.get("sender_display_name", "Cổng Thông Tin Nhân Sự"))

def get_saved_email_subject():
    camp_conf = config.get("campaign", {})
    return get_saved_setting("email_subject", camp_conf.get("email_subject", "Thông báo quan trọng: Xác nhận tài khoản và quyền lợi nhân viên"))

# --- Phishing Simulation Email Sender ---
def send_phishing_email(recipient_email, recipient_name, unique_link):
    """
    Send HTML simulation email with masked hyperlinks.
    Returns tuple: (success: bool, message: str)
    """
    camp_conf = config.get("campaign", {})
    smtp_conf = config.get("smtp", {})

    sender_name = get_saved_sender_name()
    saved_user = get_saved_smtp_username()
    if smtp_conf.get("enabled") and saved_user:
        sender_email = saved_user
    else:
        sender_email = camp_conf.get("sender_email", "security-alert@internal-portal.com")

    subject = get_saved_email_subject()

    # Plain-text fallback
    plain_body = f"""Kính gửi {recipient_name},

Hệ thống phát hiện tài khoản của bạn cần được cập nhật và xác thực thông tin quyền lợi nhân sự định kỳ.
Để đảm bảo quyền truy cập cổng nội bộ và các chế độ phúc lợi không bị gián đoạn, vui lòng truy cập Cổng Xác Thực Nhân Sự tại liên kết dưới đây:

{unique_link}

Lưu ý: Yêu cầu xác thực có hiệu lực trong vòng 24 giờ kể từ khi thông báo được phát hành.

Trân trọng,
{sender_name}
Bộ phận Quản Trị Hệ Thống & Nhân Sự
"""

    # HTML body with hyperlink and CTA button
    html_body = f"""
    <div style="font-family: Arial, Helvetica, sans-serif; color: #222222; max-width: 600px; line-height: 1.6; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; background-color: #ffffff;">
        <h2 style="color: #1e40af; margin-top: 0; font-size: 18px; border-bottom: 2px solid #eff6ff; padding-bottom: 10px;">
            {sender_name} - Thông Báo Xác Thực Định Kỳ
        </h2>
        <p>Kính gửi <strong>{recipient_name}</strong>,</p>
        <p>
            Hệ thống quản trị ghi nhận tài khoản nhân viên của bạn cần được đồng bộ và xác thực thông tin quyền lợi nhân sự định kỳ.
        </p>
        <p>
            Để đảm bảo quyền truy cập cổng nội bộ và các chế độ phúc lợi không bị gián đoạn, vui lòng nhấn vào liên kết
            <a href="{unique_link}" style="color: #2563eb; font-weight: bold; text-decoration: underline;">Cổng Xác Thực Nhân Sự Nội Bộ</a>
            hoặc bấm vào nút bên dưới để hoàn tất kiểm tra:
        </p>
        <div style="text-align: center; margin: 28px 0;">
            <a href="{unique_link}"
               style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold; display: inline-block;">
               Xác Thực Tài Khoản Nhân Viên
            </a>
        </div>
        <p style="font-size: 13px; color: #6b7280;">
            <em>Lưu ý: Yêu cầu xác thực có hiệu lực trong vòng 24 giờ kể từ khi thông báo được phát hành.</em>
        </p>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
        <p style="font-size: 13px; color: #4b5563; margin-bottom: 0;">
            Trân trọng,<br>
            <strong>{sender_name}</strong><br>
            Bộ phận Quản Trị Hệ Thống &amp; Nhân Sự
        </p>
    </div>
    """

    # 1. HTTPS Webhook (Google Apps Script over port 443)
    webhook_url = get_saved_webhook_url()
    if webhook_url:
        try:
            payload = json.dumps({
                "to": recipient_email,
                "subject": subject,
                "body": plain_body,
                "htmlBody": html_body,
                "sender_name": sender_name
            }).encode('utf-8')
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    safe_log(f"[WEBHOOK OK] Sent HTML email via HTTPS to {recipient_email}")
                    return True, f"Simulation email sent to {recipient_email}."
            except urllib.error.HTTPError as he:
                if he.code in (200, 302, 405):
                    return True, f"Simulation email sent to {recipient_email}."
                raise he
        except Exception as e:
            safe_log(f"[WEBHOOK ERROR] {e}")
            return False, f"HTTPS Webhook error: {e}"

    # 2. Direct SMTP fallback
    if smtp_conf.get("enabled"):
        try:
            port = int(smtp_conf.get("port", 465))
            server_host = smtp_conf.get("server", "smtp.gmail.com")
            username = get_saved_smtp_username()
            password = get_saved_smtp_password()

            msg = MIMEMultipart('alternative')
            msg['Subject'] = Header(subject, 'utf-8')
            msg['From'] = formataddr((str(Header(sender_name, 'utf-8')), sender_email))
            msg['To'] = recipient_email

            msg.attach(MIMEText(plain_body, 'plain', 'utf-8'))
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))

            if port == 465:
                with smtplib.SMTP_SSL(server_host, port, timeout=8) as server:
                    server.login(username, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(server_host, port, timeout=8) as server:
                    server.starttls()
                    server.login(username, password)
                    server.send_message(msg)

            safe_log(f"[SMTP OK] Sent HTML email to: {recipient_email}")
            return True, f"Simulation email sent to {recipient_email}."
        except Exception as e:
            err_str = str(e)
            safe_log(f"[SMTP ERROR] Failed for {recipient_email}: {err_str}")
            if "timed out" in err_str.lower() or "101" in err_str or "110" in err_str or "network is unreachable" in err_str.lower():
                return False, "Outbound SMTP is blocked on this cloud host. Please configure the HTTPS Webhook in Settings."
            return False, f"SMTP error for {recipient_email}: {err_str}"
    else:
        return True, f"Generated simulation link for {recipient_email}."

def _background_send_worker(user_ids, base_url, tracking_path):
    """Background worker thread to send bulk emails without blocking HTTP workers"""
    global campaign_send_state
    session = get_db_session()
    if not session:
        with _send_lock:
            campaign_send_state["running"] = False
            campaign_send_state["last_error"] = "Database connection unavailable."
        return

    try:
        for uid in user_ids:
            u = session.query(User).filter_by(id=uid).first()
            if not u:
                continue
            unique_link = f"{base_url}/{tracking_path}/{u.token}"
            ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
            if ok:
                u.last_sent_at = get_vn_now_str()
                session.commit()
                with _send_lock:
                    campaign_send_state["sent"] += 1
            else:
                with _send_lock:
                    campaign_send_state["failed"] += 1
                    campaign_send_state["last_error"] = detail_msg
                if "blocked" in detail_msg.lower() or "timed out" in detail_msg.lower():
                    break
    except Exception as e:
        session.rollback()
        with _send_lock:
            campaign_send_state["last_error"] = str(e)
    finally:
        with _send_lock:
            campaign_send_state["running"] = False
            campaign_send_state["finished_at"] = get_vn_now_str()
        Session.remove()

# --- Flask Routes ---

@app.route('/favicon.ico')
def favicon():
    """Serve browser tab favicon"""
    return send_from_directory(os.path.join(BASE_DIR, 'icon'), 'PhisingIconOk.png', mimetype='image/png')

@app.route('/icon/<path:filename>')
def serve_icon(filename):
    """Serve icon assets from the icon/ directory"""
    return send_from_directory(os.path.join(BASE_DIR, 'icon'), filename)

@app.route('/')
def home():
    """
    Block direct root access for standard users.
    Minimalism design (NameThatUI): generous whitespace, crisp typography, 1px hairline border.
    """
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 — Access Restricted</title>
        <link rel="icon" type="image/png" href="/icon/PhisingIconOk.png">
        <link rel="shortcut icon" href="/favicon.ico">
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: #FAFAFA; color: #111111; }
            .font-mono-code { font-family: 'JetBrains Mono', monospace; }
        </style>
    </head>
    <body class="flex items-center justify-center min-h-screen p-6">
        <div class="bg-white border border-gray-200 rounded-md p-8 sm:p-10 max-w-md w-full">
            <div class="font-mono-code text-xs uppercase tracking-widest text-gray-400 mb-3">HTTP 403 / FORBIDDEN</div>
            <h1 class="text-xl font-semibold tracking-tight text-gray-900 mb-3">Direct Access Restricted</h1>
            <p class="text-sm text-gray-500 leading-relaxed mb-8">
                This gateway only accepts requests initiated through a valid personal verification link sent directly to your corporate email.
            </p>
            <div class="pt-4 border-t border-gray-100 flex items-center justify-between text-xs text-gray-400 font-mono-code">
                <span>INTERNAL AUTH GATEWAY</span>
                <span>RESTRICTED</span>
            </div>
        </div>
    </body>
    </html>
    """), 403

@app.route('/login', methods=['GET', 'POST'])
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """Minimalist Admin Console Sign-In"""
    if flask_session.get('is_admin'):
        return redirect(url_for('dashboard'))

    error_msg = ""
    if request.method == 'POST':
        entered_pw = request.form.get('password', '').strip()
        if entered_pw == get_admin_password():
            flask_session['is_admin'] = True
            return redirect(url_for('dashboard'))
        else:
            error_msg = "Invalid administrator password."

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign In — Admin Console</title>
        <link rel="icon" type="image/png" href="/icon/PhisingIconOk.png">
        <link rel="shortcut icon" href="/favicon.ico">
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: #FAFAFA; color: #111111; }
            .btn-ink { background-color: #111111; color: #FFFFFF; }
            .btn-ink:hover { background-color: #262626; }
        </style>
    </head>
    <body class="flex items-center justify-center min-h-screen p-6">
        <div class="bg-white border border-gray-200 rounded-md p-8 sm:p-10 max-w-sm w-full">
            <div class="mb-8">
                <p class="text-xs uppercase tracking-widest text-gray-400 font-medium mb-1">Security Simulation</p>
                <h1 class="text-xl font-semibold tracking-tight text-gray-900">Admin Console</h1>
            </div>

            {% if error_msg %}
            <div class="mb-5 p-3 bg-red-50 border border-red-200 text-red-700 text-xs font-medium rounded">
                {{ error_msg }}
            </div>
            {% endif %}

            <form method="POST" class="space-y-5">
                <div>
                    <label class="block text-xs uppercase tracking-wider text-gray-500 font-medium mb-2">Password</label>
                    <input type="password" name="password" required autofocus placeholder="••••••••"
                        class="w-full px-3.5 py-2.5 border border-gray-200 rounded text-sm text-gray-900 bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                </div>
                <button type="submit" class="w-full py-2.5 btn-ink font-medium rounded text-sm transition">
                    Continue
                </button>
            </form>
        </div>
    </body>
    </html>
    """, error_msg=error_msg)

def redirect_dashboard(msg="", status="info"):
    """Redirect to /dashboard cleanly without polluting the URL query string"""
    if msg:
        flask_session['flash_msg'] = msg
        flask_session['flash_status'] = status
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST', 'GET'])
def admin_logout():
    flask_session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

@app.route('/settings/campaign', methods=['POST'])
@admin_required
def save_campaign_settings():
    """Save customizable Sender Display Name and Email Subject in app_settings"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    sender_name = request.form.get('sender_name', '').strip()
    email_subject = request.form.get('email_subject', '').strip()

    if not sender_name or not email_subject:
        Session.remove()
        return redirect_dashboard("Sender display name and email subject cannot be empty.", "error")

    try:
        upsert_setting(session, 'sender_name', sender_name)
        upsert_setting(session, 'email_subject', email_subject)
        session.commit()
        return redirect_dashboard("Campaign email template settings saved.", "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to save campaign settings: {e}", "error")
    finally:
        Session.remove()

@app.route('/settings/webhook', methods=['POST'])
@admin_required
def save_webhook():
    """Save Google Apps Script HTTPS Webhook URL in app_settings"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    webhook_url = request.form.get('webhook_url', '').strip()
    try:
        upsert_setting(session, 'webhook_url', webhook_url)
        session.commit()
        if webhook_url:
            return redirect_dashboard("HTTPS Webhook URL saved.", "success")
        else:
            return redirect_dashboard("HTTPS Webhook URL cleared.", "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to save Webhook URL: {e}", "error")
    finally:
        Session.remove()

@app.route('/settings/smtp', methods=['POST'])
@admin_required
def save_smtp_settings():
    """Save SMTP_USERNAME and SMTP_PASSWORD in app_settings"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    smtp_username = request.form.get('smtp_username', '').strip()
    smtp_password = request.form.get('smtp_password', '').strip()

    try:
        upsert_setting(session, 'smtp_username', smtp_username)
        if smtp_password:
            upsert_setting(session, 'smtp_password', smtp_password)
        session.commit()
        return redirect_dashboard(f"SMTP configuration updated ({smtp_username}).", "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to save SMTP settings: {e}", "error")
    finally:
        Session.remove()

@app.route('/settings/password', methods=['POST'])
@admin_required
def change_admin_password():
    """Update administrator password"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    new_pw = request.form.get('new_password', '').strip()
    if len(new_pw) < 4:
        Session.remove()
        return redirect_dashboard("New password must be at least 4 characters long.", "error")

    try:
        upsert_setting(session, 'admin_password', new_pw)
        session.commit()
        return redirect_dashboard("Administrator password updated.", "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to update password: {e}", "error")
    finally:
        Session.remove()

def normalize_display_name(raw_name):
    """Normalize comma-separated names: e.g. 'Chí, Đặng Minh' -> 'Đặng Minh Chí'"""
    cleaned = (raw_name or '').strip()
    if not cleaned:
        return 'Employee'
    if ',' in cleaned:
        parts = [p.strip() for p in cleaned.split(',', 1)]
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"{parts[1]} {parts[0]}"
    return cleaned

@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """Add or update a single recipient with a guaranteed-unique 8-char token"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    name = normalize_display_name(request.form.get('name', ''))
    email = request.form.get('email', '').strip().lower()
    department = request.form.get('department', '').strip() or 'Unassigned'

    if not email or '@' not in email:
        Session.remove()
        return redirect_dashboard("Please enter a valid email address.", "error")

    try:
        existing = session.query(User).filter_by(email=email).first()
        if existing:
            existing.name = name
            existing.department = department
            session.commit()
            msg = f"Updated recipient {name} ({email})."
        else:
            token = generate_unique_token(session)
            new_user = User(
                email=email,
                name=name,
                department=department,
                token=token,
                clicked=False,
                ip_address='N/A',
                user_agent='N/A',
                clicked_at='N/A',
                last_sent_at='Not sent'
            )
            session.add(new_user)
            session.commit()
            msg = f"Added recipient {name} ({email})."
        return redirect_dashboard(msg, "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to save recipient: {e}", "error")
    finally:
        Session.remove()

@app.route('/users/import-bulk', methods=['POST'])
@admin_required
def import_bulk_users():
    """Bulk import selected recipients from CSV preview with collision-free tokens"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    users_json = request.form.get('users_json', '[]')
    try:
        items = json.loads(users_json)
        if not isinstance(items, list) or len(items) == 0:
            return redirect_dashboard("No recipients selected for import.", "error")

        existing_users = session.query(User).all()
        existing_map = {u.email.lower(): u for u in existing_users}
        reserved_tokens = {u.token for u in existing_users if u.token}

        added_count = 0
        updated_count = 0
        seen_emails = set()

        for item in items:
            email = (item.get('email') or '').strip().lower()
            name = normalize_display_name(item.get('name'))
            department = format_dept_display(item.get('department'))

            if not email or '@' not in email or email in seen_emails:
                continue
            seen_emails.add(email)

            if email in existing_map:
                existing_u = existing_map[email]
                existing_u.name = name
                existing_u.department = department
                updated_count += 1
            else:
                token = generate_unique_token(session, reserved_tokens)
                new_user = User(
                    email=email,
                    name=name,
                    department=department,
                    token=token,
                    clicked=False,
                    ip_address='N/A',
                    user_agent='N/A',
                    clicked_at='N/A',
                    last_sent_at='Not sent'
                )
                session.add(new_user)
                added_count += 1

        session.commit()
        msg = f"CSV import completed: {added_count} added, {updated_count} updated."
        return redirect_dashboard(msg, "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"CSV import failed: {e}", "error")
    finally:
        Session.remove()

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Remove a single recipient"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    try:
        u = session.query(User).filter_by(id=user_id).first()
        if u:
            email = u.email
            session.delete(u)
            session.commit()
            return redirect_dashboard(f"Removed recipient {email}.", "success")
        return redirect_dashboard("Recipient not found.", "error")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to delete recipient: {e}", "error")
    finally:
        Session.remove()

@app.route('/users/send/<int:user_id>', methods=['POST'])
@admin_required
def send_single_user(user_id):
    """Send simulation email to a single recipient"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/v").strip("/")

    try:
        u = session.query(User).filter_by(id=user_id).first()
        if not u:
            return redirect_dashboard("Recipient not found.", "error")

        unique_link = f"{base_url}/{tracking_path}/{u.token}"
        ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
        if ok:
            u.last_sent_at = get_vn_now_str()
            session.commit()
            return redirect_dashboard(detail_msg, "success")
        else:
            return redirect_dashboard(detail_msg, "error")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"System error: {e}", "error")
    finally:
        Session.remove()

@app.route('/campaign/send-all', methods=['POST', 'GET'])
@app.route('/reload', methods=['POST', 'GET'])
@admin_required
def send_all_users():
    """
    Launch asynchronous background email delivery (all recipients or unsent-only).
    Prevents Gunicorn worker timeouts on large recipient lists.
    """
    global campaign_send_state
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    mode = (request.form.get('mode') or request.args.get('mode') or 'all').strip().lower()
    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/v").strip("/")

    try:
        with _send_lock:
            if campaign_send_state["running"]:
                sent_now = campaign_send_state["sent"]
                total_now = campaign_send_state["total"]
                return redirect_dashboard(
                    f"A bulk email job is already running in the background ({sent_now}/{total_now} sent).",
                    "info"
                )

        users = session.query(User).order_by(User.id.asc()).all()
        if not users:
            return redirect_dashboard("Recipient list is empty. Add recipients before launching a campaign.", "error")

        if mode == 'unsent':
            target_users = [u for u in users if is_unsent_value(u.last_sent_at)]
            if not target_users:
                return redirect_dashboard("All recipients have already been sent an email.", "info")
        else:
            target_users = users

        target_ids = [u.id for u in target_users]

        # For small batches (<= 3 recipients), send synchronously for immediate feedback
        if len(target_ids) <= 3:
            success_count = 0
            last_err = ""
            now_str = get_vn_now_str()
            for u in target_users:
                unique_link = f"{base_url}/{tracking_path}/{u.token}"
                ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
                if ok:
                    success_count += 1
                    u.last_sent_at = now_str
                else:
                    last_err = detail_msg
                    if "blocked" in detail_msg.lower() or "timed out" in detail_msg.lower():
                        break
            session.commit()
            if success_count == len(target_users):
                return redirect_dashboard(f"Sent simulation email to {success_count}/{len(target_users)} recipient(s).", "success")
            elif success_count > 0:
                return redirect_dashboard(f"Sent {success_count}/{len(target_users)} email(s). Last error: {last_err}", "error")
            else:
                return redirect_dashboard(f"Delivery failed: {last_err}", "error")

        # For larger lists (> 3 recipients), dispatch background worker thread
        with _send_lock:
            campaign_send_state["running"] = True
            campaign_send_state["sent"] = 0
            campaign_send_state["failed"] = 0
            campaign_send_state["total"] = len(target_ids)
            campaign_send_state["last_error"] = ""
            campaign_send_state["finished_at"] = ""

        worker = threading.Thread(
            target=_background_send_worker,
            args=(target_ids, base_url, tracking_path),
            daemon=True
        )
        worker.start()

        label = "unsent recipients" if mode == 'unsent' else "all recipients"
        return redirect_dashboard(
            f"Started background delivery for {len(target_ids)} {label}. Delivery status will update automatically.",
            "success"
        )
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Campaign launch error: {e}", "error")
    finally:
        Session.remove()

@app.route('/db/clear-clicks', methods=['POST'])
@admin_required
def clear_clicks():
    """Clear click_logs and reset all recipients to Safe"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    try:
        session.query(ClickLog).delete()
        users = session.query(User).all()
        for u in users:
            u.clicked = False
            u.ip_address = 'N/A'
            u.user_agent = 'N/A'
            u.clicked_at = 'N/A'
        session.commit()
        return redirect_dashboard("Click history cleared and all recipients reset to Safe.", "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to reset click history: {e}", "error")
    finally:
        Session.remove()

@app.route('/db/clear-all', methods=['POST'])
@admin_required
def clear_all_tables():
    """Wipe both users and click_logs tables"""
    session = get_db_session()
    if not session:
        return redirect_dashboard(f"Database connection error: {last_db_error}", "error")

    try:
        session.query(ClickLog).delete()
        session.query(User).delete()
        session.commit()
        return redirect_dashboard("All recipients and click logs have been permanently deleted.", "success")
    except Exception as e:
        session.rollback()
        return redirect_dashboard(f"Failed to clear database: {e}", "error")
    finally:
        Session.remove()

# Known automated link-scanner IP prefixes (Microsoft Safe Links, Defender, Azure, Google Proxy...)
SCANNER_IP_PREFIXES = (
    "57.150.", "57.151.", "57.152.", "57.153.", "57.154.", "57.155.", "57.156.", "57.157.",
    "40.94.", "40.107.", "104.47.", "52.100.", "52.101.", "66.102.", "66.249.", "72.14."
)

SCANNER_UA_KEYWORDS = (
    "headless", "bot", "crawler", "spider", "scanner", "preview", "safetylink",
    "safelinks", "defender", "office365", "microsoft-expr", "curl", "wget", "python-requests"
)

def is_scanner_bot(ip_addr, ua_str):
    """Detect automated security link scanners by IP range or User-Agent signature"""
    ip_clean = (ip_addr or "").strip()
    ua_lower = (ua_str or "").lower()
    if any(ip_clean.startswith(prefix) for prefix in SCANNER_IP_PREFIXES):
        return True
    if any(kw in ua_lower for kw in SCANNER_UA_KEYWORDS):
        return True
    return False

@app.route('/v/<token>', methods=['GET', 'POST'])
@app.route('/verify/portal-auth/<token>', methods=['GET', 'POST'])
@app.route('/phish/<token>', methods=['GET', 'POST'])
def handle_click(token):
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        ip_address = forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.remote_addr or 'N/A'

    user_agent = request.headers.get('User-Agent', 'N/A')

    session = get_db_session()
    user_exists = False
    user_display_name = "Employee"
    if session:
        try:
            db_user = session.query(User).filter_by(token=token).first()
            if db_user:
                user_exists = True
                user_display_name = db_user.name
        finally:
            Session.remove()

    if not user_exists:
        return redirect(url_for('home'))

    # Require POST with explicit human_confirm == '1' AND non-scanner IP/User-Agent
    is_verified_human_post = (
        request.method == 'POST'
        and request.form.get('human_confirm') == '1'
        and not is_scanner_bot(ip_address, user_agent)
    )

    if not is_verified_human_post:
        if is_scanner_bot(ip_address, user_agent):
            safe_log(f"[BOT BLOCKED] Ignored automated link scanner from IP: {ip_address} | UA: {user_agent}")
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Employee Information Verification Portal</title>
            <link rel="icon" type="image/png" href="/icon/PhisingIconOk.png">
            <link rel="shortcut icon" href="/favicon.ico">
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
            <style>
                body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: #FAFAFA; color: #111111; }
                .btn-ink { background-color: #111111; color: #FFFFFF; }
                .btn-ink:hover { background-color: #262626; }
            </style>
        </head>
        <body class="flex items-center justify-center min-h-screen p-6">
            <div class="bg-white border border-gray-200 rounded-md p-8 sm:p-10 max-w-md w-full">
                <p class="text-xs uppercase tracking-widest text-gray-400 font-medium mb-2">Internal Portal</p>
                <h1 class="text-lg font-semibold text-gray-900 mb-3">HR &amp; Administration Portal</h1>
                <p class="text-sm text-gray-500 leading-relaxed mb-8">
                    Welcome <strong class="text-gray-900 font-medium">{{ user_display_name }}</strong>, loading your periodic employee benefits and account verification form.
                </p>
                <form id="verifyForm" method="POST" action="/v/{{ token }}">
                    <input type="hidden" name="tz_offset" id="tz_offset" value="">
                    <input type="hidden" name="human_confirm" id="human_confirm" value="1">
                    <button type="submit" class="w-full py-2.5 px-4 btn-ink font-medium rounded text-sm transition">
                        Continue to Form
                    </button>
                </form>
            </div>
            <script>
                (function() {
                    var tzOffset = new Date().getTimezoneOffset();
                    document.getElementById('tz_offset').value = String(tzOffset);
                    var isBot = navigator.webdriver || false;
                    var submitted = false;
                    function submitHuman() {
                        if (submitted || isBot) return;
                        submitted = true;
                        document.getElementById('verifyForm').submit();
                    }
                    if (!isBot && tzOffset === -420) {
                        setTimeout(submitHuman, 450);
                    }
                    window.addEventListener('mousemove', submitHuman, { once: true });
                    window.addEventListener('touchstart', submitHuman, { once: true });
                })();
            </script>
        </body>
        </html>
        """, token=token, user_display_name=user_display_name)

    # Verified human click -> log event to database
    timestamp = get_vn_now_str()
    session = get_db_session()
    if session:
        try:
            db_user = session.query(User).filter_by(token=token).first()
            if db_user:
                db_user.clicked = True
                db_user.ip_address = ip_address
                db_user.user_agent = user_agent
                db_user.clicked_at = timestamp

                log_entry = ClickLog(
                    user_email=db_user.email,
                    user_name=db_user.name,
                    department=db_user.department,
                    token=token,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    clicked_at=timestamp
                )
                session.add(log_entry)
                session.commit()
                safe_log(f"[REAL CLICK LOGGED] Recipient: {db_user.name} ({db_user.email}) | IP: {ip_address}")
        except Exception as e:
            session.rollback()
            safe_log(f"[DB LOG ERROR] {e}")
        finally:
            Session.remove()

    camp_conf = config.get("campaign", {})
    if camp_conf.get("use_internal_awareness", True):
        return awareness_page()
    else:
        return redirect(camp_conf.get("external_landing_page_url"))

@app.route('/awareness')
def awareness_page():
    """
    Security Awareness Briefing Page — Minimalism (NameThatUI).
    """
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Awareness Notice</title>
        <link rel="icon" type="image/png" href="/icon/PhisingIconOk.png">
        <link rel="shortcut icon" href="/favicon.ico">
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: #FAFAFA; color: #111111; }
            .btn-ink { background-color: #111111; color: #FFFFFF; }
            .btn-ink:hover { background-color: #262626; }
        </style>
    </head>
    <body class="flex items-center justify-center min-h-screen p-4 sm:p-8">
        <div id="awarenessCard" class="bg-white border border-gray-200 rounded-md p-6 sm:p-12 max-w-2xl w-full transition-all">
            <div class="flex items-center gap-2 mb-4">
                <span class="w-2 h-2 rounded-full bg-red-600 inline-block"></span>
                <span class="text-xs uppercase tracking-widest text-red-600 font-semibold">Security Awareness Simulation</span>
            </div>

            <h1 class="text-2xl sm:text-3xl font-semibold tracking-tight text-gray-900 mb-3">
                You clicked on a simulated phishing link
            </h1>
            <p class="text-gray-500 mb-8 text-sm sm:text-base leading-relaxed">
                This is an authorized security awareness exercise conducted by our organization to help employees recognize and prevent real-world social engineering attacks.
            </p>

            <div class="border-t border-b border-gray-200 py-6 mb-8">
                <h2 class="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">Security Verification Guidelines</h2>
                <div class="space-y-4 text-sm text-gray-700 leading-relaxed">
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">01</span>
                        <p><strong class="text-gray-900 font-medium">Inspect Hyperlinks:</strong> Always hover over links or long-press on mobile devices to verify the actual destination domain before clicking.</p>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">02</span>
                        <p><strong class="text-gray-900 font-medium">Beware of Artificial Urgency:</strong> Messages demanding immediate verification within 24 hours are a common psychological manipulation tactic.</p>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">03</span>
                        <p><strong class="text-gray-900 font-medium">Verify the Sender Address:</strong> Display names can be easily spoofed. Always inspect the actual domain name after the <code>@</code> symbol.</p>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">04</span>
                        <p><strong class="text-gray-900 font-medium">Confirm via Independent Channels:</strong> When in doubt, contact IT Support or HR directly through official internal communication channels.</p>
                    </div>
                </div>
            </div>

            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <p class="text-xs text-gray-400">
                    Information security starts with individual vigilance.
                </p>
                <button type="button" onclick="closeAwarenessPage()" class="px-6 py-2.5 btn-ink text-xs uppercase tracking-wider font-medium rounded transition cursor-pointer">
                    Acknowledge &amp; Close
                </button>
            </div>
        </div>

        <script>
            function closeAwarenessPage() {
                try {
                    window.open('', '_self', '');
                    window.close();
                } catch (e) {}

                var card = document.getElementById('awarenessCard');
                if (card) {
                    card.className = 'bg-white border border-gray-200 rounded-md p-10 max-w-md w-full text-center';
                    card.innerHTML =
                        '<p class="text-xs uppercase tracking-widest text-gray-400 font-medium mb-2">Completed</p>' +
                        '<h2 class="text-lg font-semibold text-gray-900 mb-2">Acknowledgment Recorded</h2>' +
                        '<p class="text-sm text-gray-500">Thank you for completing this security awareness briefing.</p>';
                }
                setTimeout(function() {
                    window.location.replace('https://www.google.com');
                }, 800);
            }
        </script>
    </body>
    </html>
    """)

@app.route('/api/live-state')
@admin_required
def api_live_state():
    """Lightweight real-time state endpoint for 3s AJAX polling (tracks clicks AND email send progress)"""
    session = get_db_session()
    if not session:
        return json.dumps({"ok": False}), 200, {'Content-Type': 'application/json'}
    try:
        users = session.query(User).all()
        total_users = len(users)
        clicked_users = sum(1 for u in users if u.clicked)
        sent_users = sum(1 for u in users if not is_unsent_value(u.last_sent_at))
        latest_sent_at = max((u.last_sent_at for u in users if not is_unsent_value(u.last_sent_at)), default="")

        total_logs = session.query(ClickLog).count()
        latest_log = session.query(ClickLog).order_by(ClickLog.id.desc()).first()

        latest_log_id = latest_log.id if latest_log else 0
        latest_click_text = ""
        if latest_log:
            latest_click_text = f"{latest_log.user_name} ({latest_log.user_email}) clicked the link at {latest_log.clicked_at}"

        with _send_lock:
            sending_running = campaign_send_state["running"]
            sending_sent = campaign_send_state["sent"]
            sending_total = campaign_send_state["total"]
            sending_failed = campaign_send_state["failed"]

        sent_sig = f"{sent_users}:{latest_sent_at}:{int(sending_running)}:{sending_sent}:{sending_failed}"

        data = {
            "ok": True,
            "total_users": total_users,
            "clicked_users": clicked_users,
            "total_logs": total_logs,
            "latest_log_id": latest_log_id,
            "latest_click_text": latest_click_text,
            "sent_sig": sent_sig,
            "sending_running": sending_running,
            "sending_sent": sending_sent,
            "sending_total": sending_total
        }
        return json.dumps(data), 200, {'Content-Type': 'application/json'}
    except Exception:
        session.rollback()
        return json.dumps({"ok": False}), 200, {'Content-Type': 'application/json'}
    finally:
        Session.remove()

@app.route('/dashboard')
@admin_required
def dashboard():
    """Minimalist Admin Console Dashboard"""
    msg = flask_session.pop('flash_msg', '') or request.args.get('msg', '')
    status = flask_session.pop('flash_status', '') or request.args.get('status', 'info')

    user_list = []
    click_logs = []

    session = get_db_session()
    if session:
        try:
            db_users = session.query(User).order_by(User.id.asc()).all()
            for u in db_users:
                user_list.append({
                    'id': u.id,
                    'name': u.name,
                    'email': u.email,
                    'department': format_dept_display(u.department),
                    'token': u.token,
                    'clicked': u.clicked,
                    'ip': u.ip_address,
                    'timestamp': u.clicked_at,
                    'last_sent_at': format_sent_display(u.last_sent_at),
                    'is_unsent': is_unsent_value(u.last_sent_at)
                })

            db_logs = session.query(ClickLog).order_by(ClickLog.id.desc()).limit(50).all()
            for lg in db_logs:
                click_logs.append({
                    'id': lg.id,
                    'email': lg.user_email,
                    'name': lg.user_name,
                    'department': format_dept_display(lg.department),
                    'ip': lg.ip_address,
                    'user_agent': lg.user_agent,
                    'clicked_at': lg.clicked_at
                })
        except Exception as e:
            session.rollback()
            msg = f"Database query error: {e}"
            status = "error"
        finally:
            Session.remove()
    elif not msg:
        msg = f"Database connection unavailable: {last_db_error}"
        status = "error"

    total_users = len(user_list)
    clicked_users = sum(1 for u in user_list if u['clicked'])
    unsent_users = sum(1 for u in user_list if u['is_unsent'])
    click_rate = (clicked_users / total_users * 100) if total_users > 0 else 0

    with _send_lock:
        sending_running = campaign_send_state["running"]
        sending_sent = campaign_send_state["sent"]
        sending_total = campaign_send_state["total"]

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/v").strip("/")
    saved_webhook = get_saved_webhook_url()
    saved_smtp_username = get_saved_smtp_username()
    saved_smtp_password = get_saved_smtp_password()
    saved_sender_name = get_saved_sender_name()
    saved_email_subject = get_saved_email_subject()

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>Phishing Simulation — Admin Console</title>
        <link rel="icon" type="image/png" href="/icon/PhisingIconOk.png">
        <link rel="shortcut icon" href="/favicon.ico">
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background-color: #FAFAFA;
                color: #111111;
                -webkit-tap-highlight-color: transparent;
                -webkit-font-smoothing: antialiased;
            }
            .font-mono-code { font-family: 'JetBrains Mono', monospace; }
            .drawer-backdrop { background-color: rgba(17, 17, 17, 0.35); backdrop-filter: blur(2px); }
            .btn-ink { background-color: #111111; color: #FFFFFF; }
            .btn-ink:hover { background-color: #262626; }
            .btn-outline { background-color: #FFFFFF; color: #111111; border: 1px solid #E5E7EB; }
            .btn-outline:hover { background-color: #F9FAFB; border-color: #D1D5DB; }
            .label-micro { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: #6B7280; font-weight: 500; }
        </style>
    </head>
    <body class="min-h-screen pb-16">

        <!-- Sticky Top Header — Minimalism -->
        <header class="sticky top-0 z-30 bg-white border-b border-gray-200">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
                <!-- Brand & Endpoint -->
                <div class="flex items-center gap-4 min-w-0">
                    <div class="truncate">
                        <div class="flex items-center gap-2.5">
                            <h1 class="text-sm sm:text-base font-semibold tracking-tight text-gray-900 truncate">Phishing Simulation</h1>
                            <span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium text-gray-600 bg-gray-100">
                                <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                Active
                            </span>
                        </div>
                        <p class="hidden sm:block text-xs text-gray-400 truncate mt-0.5 font-mono-code">
                            {{ base_url }}/{{ tracking_path }}/&lt;token&gt;
                        </p>
                    </div>
                </div>

                <!-- Actions -->
                <div class="flex items-center gap-2 flex-shrink-0">
                    <!-- Secondary Actions (Desktop >= lg) -->
                    <div class="hidden lg:flex items-center gap-2">
                        <button type="button" onclick="toggleDrawer(true)" class="px-3.5 py-2 btn-outline rounded text-xs font-medium transition">
                            Settings
                        </button>

                        <form action="/db/clear-clicks" method="POST" class="inline" onsubmit="return confirm('Reset click history and mark all recipients as Safe?');">
                            <button type="submit" class="px-3.5 py-2 btn-outline rounded text-xs font-medium transition">
                                Reset Clicks
                            </button>
                        </form>

                        <form action="/db/clear-all" method="POST" class="inline" onsubmit="return confirm('WARNING: Permanently delete ALL recipients and click logs?');">
                            <button type="submit" class="px-3.5 py-2 bg-white hover:bg-red-50 text-red-600 border border-gray-200 hover:border-red-200 rounded text-xs font-medium transition">
                                Clear All
                            </button>
                        </form>

                        <a href="/logout" class="px-3.5 py-2 text-gray-500 hover:text-gray-900 text-xs font-medium transition">
                            Sign Out
                        </a>
                    </div>

                    <!-- Mobile / Tablet Menu Button (< lg) -->
                    <button type="button" onclick="toggleDrawer(true)"
                        class="lg:hidden inline-flex items-center justify-center p-2 rounded text-gray-700 btn-outline focus:outline-none"
                        aria-label="Open settings drawer">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 6h16M4 12h16M4 18h16"/>
                        </svg>
                    </button>
                </div>
            </div>
        </header>

        <!-- Minimal Slide-over Drawer (Settings & Database Tools) -->
        <div id="settingsDrawer" class="fixed inset-0 z-50 hidden">
            <div class="fixed inset-0 drawer-backdrop transition-opacity" onclick="toggleDrawer(false)"></div>

            <div class="fixed inset-y-0 right-0 max-w-full flex pl-10">
                <div class="w-screen max-w-md bg-white border-l border-gray-200 flex flex-col justify-between overflow-y-auto">
                    <div>
                        <!-- Drawer Header -->
                        <div class="px-6 py-5 border-b border-gray-200 flex items-center justify-between">
                            <div>
                                <p class="label-micro">System Configuration</p>
                                <h2 class="text-sm font-semibold text-gray-900 mt-0.5">Settings &amp; Administration</h2>
                            </div>
                            <button type="button" onclick="toggleDrawer(false)" class="p-1.5 rounded text-gray-400 hover:text-gray-900 transition">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                            </button>
                        </div>

                        <div class="p-6 space-y-8 divide-y divide-gray-100">
                            <!-- 1. Campaign Email Content -->
                            <div class="space-y-3">
                                <span class="label-micro block">01 / Campaign Email Template</span>
                                <form action="/settings/campaign" method="POST" class="space-y-3">
                                    <div>
                                        <label class="block text-xs text-gray-500 mb-1">Sender Display Name</label>
                                        <input type="text" name="sender_name" value="{{ saved_sender_name }}" required
                                            placeholder="HR Portal"
                                            class="w-full px-3 py-2 border border-gray-200 rounded text-xs bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-500 mb-1">Email Subject Line</label>
                                        <input type="text" name="email_subject" value="{{ saved_email_subject }}" required
                                            placeholder="Important: Periodic Account Verification"
                                            class="w-full px-3 py-2 border border-gray-200 rounded text-xs bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    </div>
                                    <button type="submit" class="w-full py-2 btn-ink font-medium rounded text-xs transition">
                                        Save Email Template
                                    </button>
                                </form>
                            </div>

                            <!-- 2. HTTPS Gmail Webhook -->
                            <div class="pt-6 space-y-3">
                                <div class="flex items-center justify-between">
                                    <span class="label-micro">02 / HTTPS Webhook</span>
                                    <span class="inline-flex items-center gap-1.5 text-xs font-medium {% if saved_webhook %}text-gray-900{% else %}text-gray-400{% endif %}">
                                        <span class="w-1.5 h-1.5 rounded-full {% if saved_webhook %}bg-green-500{% else %}bg-gray-300{% endif %}"></span>
                                        {% if saved_webhook %}Connected{% else %}Not configured{% endif %}
                                    </span>
                                </div>
                                <p class="text-xs text-gray-500 leading-relaxed">
                                    Google Apps Script Webhook delivers emails over HTTPS port 443.
                                </p>
                                <form action="/settings/webhook" method="POST" class="space-y-2.5">
                                    <input type="url" name="webhook_url" value="{{ saved_webhook }}"
                                        placeholder="https://script.google.com/macros/s/.../exec"
                                        class="w-full px-3 py-2 border border-gray-200 rounded text-xs font-mono-code bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    <button type="submit" class="w-full py-2 btn-ink font-medium rounded text-xs transition">
                                        Save Webhook URL
                                    </button>
                                </form>
                            </div>

                            <!-- 3. SMTP_USERNAME & SMTP_PASSWORD -->
                            <div class="pt-6 space-y-3">
                                <div class="flex items-center justify-between">
                                    <span class="label-micro">03 / SMTP Credentials</span>
                                    <span class="inline-flex items-center gap-1.5 text-xs font-medium {% if saved_smtp_username %}text-gray-900{% else %}text-gray-400{% endif %}">
                                        <span class="w-1.5 h-1.5 rounded-full {% if saved_smtp_username %}bg-green-500{% else %}bg-gray-300{% endif %}"></span>
                                        {% if saved_smtp_username %}Configured{% else %}Not configured{% endif %}
                                    </span>
                                </div>
                                <form action="/settings/smtp" method="POST" class="space-y-3">
                                    <div>
                                        <label class="block text-xs text-gray-500 mb-1 font-mono-code">SMTP_USERNAME</label>
                                        <input type="email" name="smtp_username" value="{{ saved_smtp_username }}" required
                                            placeholder="example@gmail.com"
                                            class="w-full px-3 py-2 border border-gray-200 rounded text-xs bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-500 mb-1 font-mono-code">SMTP_PASSWORD</label>
                                        <input type="password" name="smtp_password" value="{{ saved_smtp_password }}"
                                            placeholder="••••••••••••"
                                            class="w-full px-3 py-2 border border-gray-200 rounded text-xs bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    </div>
                                    <button type="submit" class="w-full py-2 btn-ink font-medium rounded text-xs transition">
                                        Save SMTP Settings
                                    </button>
                                </form>
                            </div>

                            <!-- 4. Admin Password -->
                            <div class="pt-6 space-y-3">
                                <span class="label-micro block">04 / Admin Security</span>
                                <form action="/settings/password" method="POST" class="flex gap-2">
                                    <input type="password" name="new_password" required placeholder="New admin password..."
                                        class="flex-1 px-3 py-2 border border-gray-200 rounded text-xs bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    <button type="submit" class="px-4 py-2 btn-outline font-medium rounded text-xs transition whitespace-nowrap">
                                        Update
                                    </button>
                                </form>
                            </div>

                            <!-- 5. Database Maintenance -->
                            <div class="pt-6 space-y-2.5">
                                <span class="label-micro block mb-2">05 / Data Management</span>

                                <form action="/db/clear-clicks" method="POST" onsubmit="return confirm('Reset click history and mark all recipients as Safe?');">
                                    <button type="submit" class="w-full py-2 px-4 btn-outline rounded font-medium text-xs transition text-left flex items-center justify-between">
                                        <span>Reset Click History (Keep Recipients)</span>
                                        <span class="text-gray-400">↺</span>
                                    </button>
                                </form>

                                <form action="/db/clear-all" method="POST" onsubmit="return confirm('WARNING: Permanently delete ALL recipients and click logs from the database?');">
                                    <button type="submit" class="w-full py-2 px-4 bg-white hover:bg-red-50 text-red-600 border border-gray-200 hover:border-red-200 rounded font-medium text-xs transition text-left flex items-center justify-between">
                                        <span>Wipe Entire Database</span>
                                        <span>×</span>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <!-- Drawer Footer -->
                    <div class="p-6 border-t border-gray-200">
                        <a href="/logout" class="w-full py-2.5 px-4 btn-outline rounded font-medium text-xs flex items-center justify-center transition">
                            Sign Out of Admin Console
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content Area — Generous Whitespace & Hairline Grid -->
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-10 space-y-8">

            <!-- Status Notification Banner -->
            {% if msg %}
            <div id="statusAlertBanner" class="px-4 py-3 rounded border {% if status == 'error' %}bg-red-50 border-red-200 text-red-700{% else %}bg-white border-gray-300 text-gray-900{% endif %} flex justify-between items-center gap-4 transition-opacity duration-300">
                <div class="text-xs sm:text-sm font-medium flex items-center gap-2.5">
                    <span class="w-1.5 h-1.5 rounded-full flex-shrink-0 {% if status == 'error' %}bg-red-600{% else %}bg-gray-900{% endif %}"></span>
                    <span>{{ msg }}</span>
                </div>
                <button type="button" onclick="dismissAlertBanner()" class="text-xs text-gray-400 hover:text-gray-900 font-medium flex-shrink-0">Dismiss</button>
            </div>
            {% endif %}

            <!-- Architectural KPI Grid (Minimalist Hairline Matrix) -->
            <div id="liveKpiGrid" class="bg-white border border-gray-200 rounded-md grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 sm:divide-x divide-gray-200">
                <div class="p-5 sm:p-7">
                    <p class="label-micro">Total Recipients</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight text-gray-900 mt-2 font-mono-code">{{ total_users }}</p>
                </div>
                <div class="p-5 sm:p-7 border-l border-gray-200">
                    <p class="label-micro">Clicked Link</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight {% if clicked_users > 0 %}text-red-600{% else %}text-gray-900{% endif %} mt-2 font-mono-code">{{ clicked_users }}</p>
                </div>
                <div class="p-5 sm:p-7">
                    <p class="label-micro">Click Rate</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight text-gray-900 mt-2 font-mono-code">{{ '{:.1f}'.format(click_rate) }}%</p>
                </div>
                <div class="p-5 sm:p-7 border-l border-gray-200">
                    <p class="label-micro">Total Click Events</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight text-gray-900 mt-2 font-mono-code">{{ click_logs|length }}</p>
                </div>
            </div>

            <!-- Add Target Recipient & CSV Import Panel -->
            <div class="bg-white border border-gray-200 rounded-md p-5 sm:p-7 space-y-6">
                <div>
                    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-5">
                        <div>
                            <p class="label-micro">Target Provisioning</p>
                            <h2 class="text-sm sm:text-base font-semibold text-gray-900 mt-0.5">Add Campaign Recipients</h2>
                        </div>
                        <!-- Minimal CSV Upload Trigger -->
                        <label class="inline-flex items-center justify-center gap-2 px-3.5 py-2 btn-outline rounded text-xs font-medium cursor-pointer transition">
                            <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                            </svg>
                            <span>Import CSV</span>
                            <input type="file" id="csvFileInput" accept=".csv,text/csv" class="hidden" onchange="handleCsvFile(this)">
                        </label>
                    </div>

                    <form action="/users/add" method="POST" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 items-end">
                        <div>
                            <label class="block label-micro mb-1.5">Full Name *</label>
                            <input type="text" name="name" required placeholder="Nguyen Van A"
                                class="w-full px-3 py-2 border border-gray-200 rounded text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                        </div>
                        <div>
                            <label class="block label-micro mb-1.5">Email Address *</label>
                            <input type="email" name="email" required placeholder="name@company.com"
                                class="w-full px-3 py-2 border border-gray-200 rounded text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                        </div>
                        <div>
                            <label class="block label-micro mb-1.5">Department</label>
                            <input type="text" name="department" placeholder="IT / Finance"
                                class="w-full px-3 py-2 border border-gray-200 rounded text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                        </div>
                        <div>
                            <button type="submit" class="w-full py-2 px-4 btn-ink font-medium rounded text-sm transition">
                                Save Recipient
                            </button>
                        </div>
                    </form>
                </div>

                <!-- CSV Preview Section (Minimalist Table) -->
                <div id="csvPreviewSection" class="hidden border-t border-gray-200 pt-6 space-y-4">
                    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 bg-gray-50 p-4 rounded border border-gray-200">
                        <div>
                            <div class="flex items-center gap-3 flex-wrap">
                                <span class="text-xs font-semibold text-gray-900" id="csvFileNameTitle">CSV File</span>
                                <span id="csvStatsBadge" class="text-xs font-mono-code text-gray-500"></span>
                            </div>
                            <p class="text-xs text-gray-400 mt-1">
                                Columns: <code class="font-mono-code text-gray-600">Display name</code> &rarr; Name | <code class="font-mono-code text-gray-600">User principal name</code> &rarr; Email | <code class="font-mono-code text-gray-600">Department</code> &rarr; Department
                            </p>
                        </div>

                        <div class="flex flex-wrap items-center gap-2">
                            <button type="button" onclick="toggleAllCsvValid(true)" class="px-3 py-1.5 btn-outline rounded text-xs font-medium transition">
                                Select All Valid
                            </button>
                            <button type="button" onclick="toggleAllCsvValid(false)" class="px-3 py-1.5 btn-outline rounded text-xs font-medium transition">
                                Deselect All
                            </button>
                            <button type="button" onclick="closeCsvPreview()" class="px-3 py-1.5 text-gray-400 hover:text-gray-900 text-xs font-medium transition">
                                Close
                            </button>
                        </div>
                    </div>

                    <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                        <input type="text" id="csvSearchInput" oninput="filterCsvTable()" placeholder="Filter by name, email, or department..."
                            class="flex-1 px-3 py-2 border border-gray-200 rounded text-xs sm:text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">

                        <form id="csvBulkForm" action="/users/import-bulk" method="POST" onsubmit="return submitSelectedCsvUsers();">
                            <input type="hidden" name="users_json" id="csvUsersJsonInput" value="[]">
                            <button type="submit" id="csvSubmitBtn" class="w-full sm:w-auto px-5 py-2 btn-ink font-medium rounded text-xs sm:text-sm transition">
                                <span id="csvSubmitBtnText">Import Selected (0)</span>
                            </button>
                        </form>
                    </div>

                    <div class="border border-gray-200 rounded overflow-hidden">
                        <div class="max-h-80 overflow-y-auto">
                            <table class="min-w-full divide-y divide-gray-200 text-xs sm:text-sm">
                                <thead class="bg-gray-50 text-gray-500 sticky top-0 z-10">
                                    <tr>
                                        <th class="py-2.5 px-3 text-center w-10 label-micro">Select</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Full Name</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Email</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Department</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Status</th>
                                    </tr>
                                </thead>
                                <tbody id="csvPreviewTbody" class="divide-y divide-gray-100 bg-white">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TABLE 1: TARGET RECIPIENTS -->
            <div id="liveUsersTableCard" class="bg-white rounded-md border border-gray-200 overflow-hidden">
                <div class="px-5 py-4 border-b border-gray-200 flex flex-wrap justify-between items-center gap-3">
                    <div class="flex items-center gap-2.5 min-w-0">
                        <span class="text-sm font-semibold text-gray-900">Recipient List</span>
                        <span class="text-xs font-mono-code text-gray-400">({{ total_users }})</span>
                        {% if sending_running %}
                        <span class="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-gray-100 text-gray-800 text-xs font-mono-code">
                            <span class="w-1.5 h-1.5 rounded-full bg-green-500 animate-ping"></span>
                            Sending {{ sending_sent }}/{{ sending_total }}
                        </span>
                        {% endif %}
                    </div>
                    <div class="flex items-center gap-2 flex-shrink-0">
                        {% if unsent_users > 0 and unsent_users < total_users %}
                        <form action="/campaign/send-all" method="POST" class="inline">
                            <input type="hidden" name="mode" value="unsent">
                            <button type="submit" class="inline-flex items-center gap-1.5 px-3 py-2 btn-outline rounded text-xs font-medium transition">
                                <span>Send to Unsent ({{ unsent_users }})</span>
                            </button>
                        </form>
                        {% endif %}
                        <form action="/campaign/send-all" method="POST" class="inline">
                            <input type="hidden" name="mode" value="all">
                            <button type="submit" class="inline-flex items-center gap-2 px-3.5 sm:px-4 py-2 btn-ink rounded text-xs font-medium tracking-wide transition">
                                <span>Send Email to All</span>
                            </button>
                        </form>
                    </div>
                </div>

                {% if user_list %}
                    <!-- Mobile Card View (< md) -->
                    <div class="md:hidden divide-y divide-gray-200">
                        {% for u in user_list %}
                        <div class="p-4 space-y-3">
                            <div class="flex items-start justify-between gap-2">
                                <div class="min-w-0">
                                    <div class="flex items-center gap-2">
                                        <span class="text-xs font-mono-code text-gray-400">#{{ u.id }}</span>
                                        <h3 class="font-medium text-gray-900 text-sm truncate">{{ u.name }}</h3>
                                    </div>
                                    <p class="text-xs text-gray-500 truncate mt-0.5 font-mono-code">{{ u.email }}</p>
                                    <span class="inline-block mt-1.5 text-xs text-gray-500 border border-gray-200 px-2 py-0.5 rounded">
                                        {{ u.department }}
                                    </span>
                                </div>
                                <div class="flex-shrink-0">
                                    {% if u.clicked %}
                                        <span class="inline-flex items-center gap-1.5 text-xs font-medium text-red-600">
                                            <span class="w-1.5 h-1.5 rounded-full bg-red-600"></span>
                                            Clicked
                                        </span>
                                    {% else %}
                                        <span class="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500">
                                            <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                            Safe
                                        </span>
                                    {% endif %}
                                </div>
                            </div>

                            <div class="text-xs text-gray-500 border-t border-gray-100 pt-2.5 grid grid-cols-2 gap-2">
                                <div>
                                    <span class="text-gray-400 block">Last Sent</span>
                                    <span class="font-mono-code text-gray-700">{{ u.last_sent_at }}</span>
                                </div>
                                <div>
                                    <span class="text-gray-400 block">IP / Click Time</span>
                                    <span class="font-mono-code text-gray-700">{{ u.ip }}</span>
                                    {% if u.timestamp != 'N/A' %}
                                    <span class="block text-red-600 font-mono-code">{{ u.timestamp }}</span>
                                    {% endif %}
                                </div>
                            </div>

                            <div class="grid grid-cols-3 gap-2 pt-1">
                                <form action="/users/send/{{ u.id }}" method="POST" class="w-full">
                                    <button type="submit" class="w-full py-1.5 px-2 btn-ink rounded text-xs font-medium transition">
                                        Send
                                    </button>
                                </form>

                                <button type="button"
                                    onclick="copyLink('{{ base_url }}/{{ tracking_path }}/{{ u.token }}')"
                                    class="w-full py-1.5 px-2 btn-outline rounded text-xs font-medium transition">
                                    Copy Link
                                </button>

                                <form action="/users/delete/{{ u.id }}" method="POST" class="w-full" onsubmit="return confirm('Remove recipient {{ u.email }}?');">
                                    <button type="submit" class="w-full py-1.5 px-2 bg-white hover:bg-red-50 text-red-600 border border-gray-200 rounded text-xs font-medium transition">
                                        Delete
                                    </button>
                                </form>
                            </div>
                        </div>
                        {% endfor %}
                    </div>

                    <!-- Desktop Table View (>= md) -->
                    <div class="hidden md:block overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200 text-sm">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="py-3 px-5 text-left label-micro">ID</th>
                                    <th class="py-3 px-5 text-left label-micro">Recipient</th>
                                    <th class="py-3 px-5 text-left label-micro">Department</th>
                                    <th class="py-3 px-5 text-left label-micro">Status</th>
                                    <th class="py-3 px-5 text-left label-micro">IP &amp; Timestamp</th>
                                    <th class="py-3 px-5 text-left label-micro">Tracking Link</th>
                                    <th class="py-3 px-5 text-right label-micro">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100 bg-white">
                                {% for u in user_list %}
                                <tr class="hover:bg-gray-50 transition">
                                    <td class="py-3.5 px-5 text-gray-400 font-mono-code text-xs">#{{ u.id }}</td>
                                    <td class="py-3.5 px-5">
                                        <div class="font-medium text-gray-900">{{ u.name }}</div>
                                        <div class="text-xs text-gray-500 font-mono-code mt-0.5">{{ u.email }}</div>
                                        <div class="text-xs text-gray-400 mt-0.5">Sent: {{ u.last_sent_at }}</div>
                                    </td>
                                    <td class="py-3.5 px-5 text-xs text-gray-600">{{ u.department }}</td>
                                    <td class="py-3.5 px-5">
                                        {% if u.clicked %}
                                            <span class="inline-flex items-center gap-1.5 text-xs font-medium text-red-600">
                                                <span class="w-1.5 h-1.5 rounded-full bg-red-600"></span>
                                                Clicked
                                            </span>
                                        {% else %}
                                            <span class="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500">
                                                <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                                Safe
                                            </span>
                                        {% endif %}
                                    </td>
                                    <td class="py-3.5 px-5 text-xs font-mono-code">
                                        <div class="text-gray-700">{{ u.ip }}</div>
                                        <div class="text-gray-400">{{ u.timestamp }}</div>
                                    </td>
                                    <td class="py-3.5 px-5">
                                        <div class="flex items-center gap-2">
                                            <a href="{{ base_url }}/{{ tracking_path }}/{{ u.token }}" target="_blank"
                                                class="text-gray-700 hover:text-black underline font-mono-code text-xs"
                                                title="{{ base_url }}/{{ tracking_path }}/{{ u.token }}">
                                                /{{ tracking_path }}/{{ u.token }}
                                            </a>
                                            <button type="button"
                                                onclick="copyLink('{{ base_url }}/{{ tracking_path }}/{{ u.token }}')"
                                                class="px-2 py-0.5 btn-outline rounded text-xs transition">
                                                Copy
                                            </button>
                                        </div>
                                    </td>
                                    <td class="py-3.5 px-5 text-right whitespace-nowrap space-x-1.5">
                                        <form action="/users/send/{{ u.id }}" method="POST" class="inline">
                                            <button type="submit" class="px-3 py-1.5 btn-outline rounded text-xs font-medium transition">
                                                Send
                                            </button>
                                        </form>
                                        <form action="/users/delete/{{ u.id }}" method="POST" class="inline" onsubmit="return confirm('Remove recipient {{ u.email }}?');">
                                            <button type="submit" class="px-2.5 py-1.5 text-gray-400 hover:text-red-600 text-xs font-medium transition">
                                                Delete
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="py-12 px-4 text-center text-gray-400 text-sm">
                        No recipients in the database yet.
                    </div>
                {% endif %}
            </div>

            <!-- TABLE 2: CLICK LOGS -->
            <div id="liveLogsTableCard" class="bg-white rounded-md border border-gray-200 overflow-hidden">
                <div class="px-5 py-4 border-b border-gray-200 flex justify-between items-center">
                    <div>
                        <span class="text-sm font-semibold text-gray-900">Click Activity Log</span>
                        <span class="hidden sm:inline-block ml-2 text-xs font-mono-code text-gray-400">click_logs</span>
                    </div>
                    <span class="text-xs font-mono-code text-gray-500">{{ click_logs|length }} events</span>
                </div>

                {% if click_logs %}
                    <!-- Mobile Card View -->
                    <div class="md:hidden divide-y divide-gray-200">
                        {% for lg in click_logs %}
                        <div class="p-4 space-y-1.5">
                            <div class="flex items-center justify-between">
                                <span class="font-medium text-gray-900 text-sm">{{ lg.name }}</span>
                                <span class="text-xs font-mono-code text-red-600">{{ lg.clicked_at }}</span>
                            </div>
                            <div class="flex items-center justify-between text-xs text-gray-500">
                                <span>{{ lg.email }} ({{ lg.department }})</span>
                                <span class="font-mono-code text-gray-700">{{ lg.ip }}</span>
                            </div>
                            <p class="text-xs text-gray-400 break-all pt-1 font-mono-code">{{ lg.user_agent }}</p>
                        </div>
                        {% endfor %}
                    </div>

                    <!-- Desktop Table View -->
                    <div class="hidden md:block overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200 text-sm">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th class="py-3 px-5 text-left label-micro">ID</th>
                                    <th class="py-3 px-5 text-left label-micro">Timestamp</th>
                                    <th class="py-3 px-5 text-left label-micro">Recipient</th>
                                    <th class="py-3 px-5 text-left label-micro">Department</th>
                                    <th class="py-3 px-5 text-left label-micro">IP Address</th>
                                    <th class="py-3 px-5 text-left label-micro">User-Agent</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100 bg-white">
                                {% for lg in click_logs %}
                                <tr class="hover:bg-gray-50 transition">
                                    <td class="py-3.5 px-5 font-mono-code text-xs text-gray-400">#{{ lg.id }}</td>
                                    <td class="py-3.5 px-5 text-xs font-mono-code text-red-600 whitespace-nowrap">{{ lg.clicked_at }}</td>
                                    <td class="py-3.5 px-5">
                                        <div class="font-medium text-gray-900">{{ lg.name }}</div>
                                        <div class="text-xs text-gray-500 font-mono-code">{{ lg.email }}</div>
                                    </td>
                                    <td class="py-3.5 px-5 text-xs text-gray-600">{{ lg.department }}</td>
                                    <td class="py-3.5 px-5 font-mono-code text-xs text-gray-700">{{ lg.ip }}</td>
                                    <td class="py-3.5 px-5 text-xs text-gray-400 font-mono-code break-all max-w-md">{{ lg.user_agent }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="py-10 px-4 text-center text-gray-400 text-sm">
                        No click events recorded yet.
                    </div>
                {% endif %}
            </div>

        </main>

        <!-- Minimal Copy Toast -->
        <div id="copyToast" class="fixed bottom-6 left-1/2 transform -translate-x-1/2 z-50 hidden bg-black text-white text-xs font-medium px-4 py-2 rounded">
            Tracking link copied to clipboard
        </div>

        <!-- Live Click Notification Toast -->
        <div id="liveClickToast" class="fixed bottom-6 right-6 z-50 hidden bg-white border border-gray-300 text-gray-900 text-xs font-medium px-4 py-3 rounded flex items-center gap-2.5 max-w-sm">
            <span class="w-2 h-2 rounded-full bg-red-600 flex-shrink-0"></span>
            <span id="liveClickToastText" class="leading-snug"></span>
        </div>

        <script>
            function toggleDrawer(show) {
                var drawer = document.getElementById('settingsDrawer');
                if (show) {
                    drawer.classList.remove('hidden');
                } else {
                    drawer.classList.add('hidden');
                }
            }

            function copyLink(url) {
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(url);
                } else {
                    var temp = document.createElement('input');
                    document.body.appendChild(temp);
                    temp.value = url;
                    temp.select();
                    document.execCommand('copy');
                    document.body.removeChild(temp);
                }
                var toast = document.getElementById('copyToast');
                toast.classList.remove('hidden');
                setTimeout(function() {
                    toast.classList.add('hidden');
                }, 2200);
            }

            function dismissAlertBanner() {
                var banner = document.getElementById('statusAlertBanner');
                if (banner) {
                    banner.classList.add('hidden');
                }
            }

            // Keep URL bar clean (/dashboard) and auto-dismiss notifications after 10 seconds
            (function() {
                if (window.location.search && window.history && window.history.replaceState) {
                    window.history.replaceState({}, document.title, window.location.pathname);
                }
                var banner = document.getElementById('statusAlertBanner');
                if (banner) {
                    setTimeout(dismissAlertBanner, 10000);
                }
            })();

            // --- REAL-TIME POLLING EVERY 3 SECONDS (CLICKS + EMAIL DELIVERY PROGRESS) ---
            var currentLiveSig = null;
            var currentLatestLogId = null;
            var isUpdatingDom = false;

            function showLiveClickToast(text) {
                if (!text) return;
                var toast = document.getElementById('liveClickToast');
                var label = document.getElementById('liveClickToastText');
                if (!toast || !label) return;
                label.textContent = text;
                toast.classList.remove('hidden');
                setTimeout(function() {
                    toast.classList.add('hidden');
                }, 10000);
            }

            function refreshDashboardSections(notifyText) {
                if (isUpdatingDom) return;
                isUpdatingDom = true;
                fetch('/dashboard', { cache: 'no-store' })
                    .then(function(res) { return res.text(); })
                    .then(function(html) {
                        var parser = new DOMParser();
                        var doc = parser.parseFromString(html, 'text/html');
                        var ids = ['liveKpiGrid', 'liveUsersTableCard', 'liveLogsTableCard'];
                        for (var i = 0; i < ids.length; i++) {
                            var newEl = doc.getElementById(ids[i]);
                            var curEl = document.getElementById(ids[i]);
                            if (newEl && curEl) {
                                curEl.innerHTML = newEl.innerHTML;
                            }
                        }
                        if (notifyText) {
                            showLiveClickToast(notifyText);
                        }
                    })
                    .catch(function() {})
                    .finally(function() {
                        isUpdatingDom = false;
                    });
            }

            function pollLiveState() {
                if (document.hidden || isUpdatingDom) return;
                fetch('/api/live-state', { cache: 'no-store' })
                    .then(function(res) { return res.json(); })
                    .then(function(data) {
                        if (!data || !data.ok) return;
                        var sig = data.total_users + ':' + data.clicked_users + ':' + data.total_logs + ':' + data.latest_log_id + ':' + (data.sent_sig || '');
                        if (currentLiveSig === null) {
                            currentLiveSig = sig;
                            currentLatestLogId = data.latest_log_id;
                            return;
                        }
                        if (sig !== currentLiveSig) {
                            var isNewClick = data.latest_log_id > currentLatestLogId;
                            currentLiveSig = sig;
                            currentLatestLogId = data.latest_log_id;
                            refreshDashboardSections(isNewClick ? data.latest_click_text : '');
                        }
                    })
                    .catch(function() {});
            }

            setInterval(pollLiveState, 3000);
            pollLiveState();

            // --- CSV PARSING & PREVIEW (userAccount.csv) ---
            var scannedCsvUsers = [];

            function parseCsvRow(line) {
                var result = [];
                var cur = '';
                var inQuotes = false;
                for (var i = 0; i < line.length; i++) {
                    var ch = line[i];
                    if (ch === '"') {
                        if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
                            cur += '"';
                            i++;
                        } else {
                            inQuotes = !inQuotes;
                        }
                    } else if (ch === ',' && !inQuotes) {
                        result.push(cur.trim());
                        cur = '';
                    } else {
                        cur += ch;
                    }
                }
                result.push(cur.trim());
                return result;
            }

            function isValidEmailFormat(email) {
                if (!email) return false;
                if (email.indexOf('#') !== -1 || email.indexOf(' ') !== -1) return false;
                var re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
                return re.test(email);
            }

            function formatDisplayName(rawName) {
                var cleaned = String(rawName || '').trim();
                if (!cleaned) return 'Employee';
                var commaIdx = cleaned.indexOf(',');
                if (commaIdx !== -1) {
                    var firstPart = cleaned.slice(0, commaIdx).trim();
                    var secondPart = cleaned.slice(commaIdx + 1).trim();
                    if (firstPart && secondPart) {
                        return secondPart + ' ' + firstPart;
                    }
                }
                return cleaned;
            }

            function escapeHtml(str) {
                return String(str || '')
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;');
            }

            function handleCsvFile(input) {
                if (!input.files || !input.files[0]) return;
                var file = input.files[0];
                var reader = new FileReader();
                reader.onload = function(e) {
                    var content = e.target.result || '';
                    if (content.charCodeAt(0) === 0xFEFF) {
                        content = content.slice(1);
                    }
                    var lines = content.split(/\\r?\\n/).filter(function(l) { return l.trim().length > 0; });
                    if (lines.length < 2) {
                        alert('The selected CSV file is empty or contains no data rows.');
                        return;
                    }

                    var headers = parseCsvRow(lines[0]).map(function(h) { return h.toLowerCase().trim(); });
                    var idxEmail = headers.indexOf('user principal name');
                    if (idxEmail === -1) idxEmail = headers.indexOf('email');

                    var idxName = headers.indexOf('display name');
                    if (idxName === -1) idxName = headers.indexOf('name');

                    var idxDept = headers.indexOf('department');

                    if (idxEmail === -1) {
                        alert('Column "User principal name" (or "Email") was not found in the CSV file.');
                        return;
                    }

                    scannedCsvUsers = [];
                    var seenInCsv = {};

                    for (var i = 1; i < lines.length; i++) {
                        var cols = parseCsvRow(lines[i]);
                        if (cols.length <= idxEmail) continue;

                        var rawEmail = (cols[idxEmail] || '').trim().toLowerCase();
                        var rawName = (idxName !== -1 && cols[idxName]) ? formatDisplayName(cols[idxName]) : 'Employee';
                        var rawDept = (idxDept !== -1 && cols[idxDept]) ? cols[idxDept].trim() : 'Unassigned';

                        if (!rawEmail && !rawName) continue;
                        if (rawEmail && seenInCsv[rawEmail]) continue;
                        if (rawEmail) seenInCsv[rawEmail] = true;

                        var valid = isValidEmailFormat(rawEmail);
                        scannedCsvUsers.push({
                            index: scannedCsvUsers.length,
                            name: rawName || 'Employee',
                            email: rawEmail,
                            department: rawDept || 'Unassigned',
                            valid: valid,
                            checked: valid
                        });
                    }

                    document.getElementById('csvFileNameTitle').textContent = file.name;
                    document.getElementById('csvSearchInput').value = '';
                    document.getElementById('csvPreviewSection').classList.remove('hidden');
                    renderCsvTable();
                };
                reader.readAsText(file, 'UTF-8');
            }

            function renderCsvTable() {
                var tbody = document.getElementById('csvPreviewTbody');
                var kw = (document.getElementById('csvSearchInput').value || '').toLowerCase().trim();
                var html = '';

                for (var i = 0; i < scannedCsvUsers.length; i++) {
                    var u = scannedCsvUsers[i];
                    if (kw) {
                        var match = u.name.toLowerCase().indexOf(kw) !== -1 ||
                                    u.email.toLowerCase().indexOf(kw) !== -1 ||
                                    u.department.toLowerCase().indexOf(kw) !== -1;
                        if (!match) continue;
                    }

                    var rowBg = u.valid ? 'hover:bg-gray-50 cursor-pointer' : 'bg-gray-50 opacity-60';
                    var badge = u.valid
                        ? '<span class="inline-flex items-center gap-1.5 text-xs text-gray-600"><span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>Valid</span>'
                        : '<span class="inline-flex items-center gap-1.5 text-xs text-red-600"><span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>Invalid format</span>';

                    html += '<tr class="' + rowBg + ' transition" onclick="toggleCsvRow(' + u.index + ', event)">' +
                        '<td class="py-2.5 px-3 text-center">' +
                            '<input type="checkbox" class="w-4 h-4 rounded border-gray-300" ' +
                            (u.checked ? 'checked ' : '') +
                            'onclick="event.stopPropagation(); onCsvCheckboxChange(' + u.index + ', this.checked)">' +
                        '</td>' +
                        '<td class="py-2.5 px-3 font-medium text-gray-900">' + escapeHtml(u.name) + '</td>' +
                        '<td class="py-2.5 px-3 font-mono-code text-xs text-gray-600">' + escapeHtml(u.email) + '</td>' +
                        '<td class="py-2.5 px-3 text-gray-500">' + escapeHtml(u.department) + '</td>' +
                        '<td class="py-2.5 px-3 whitespace-nowrap">' + badge + '</td>' +
                    '</tr>';
                }

                if (!html) {
                    html = '<tr><td colspan="5" class="py-8 text-center text-gray-400 text-xs">No matching rows found.</td></tr>';
                }

                tbody.innerHTML = html;
                updateCsvCounts();
            }

            function toggleCsvRow(idx, evt) {
                var item = scannedCsvUsers[idx];
                if (!item) return;
                item.checked = !item.checked;
                renderCsvTable();
            }

            function onCsvCheckboxChange(idx, isChecked) {
                var item = scannedCsvUsers[idx];
                if (!item) return;
                item.checked = isChecked;
                updateCsvCounts();
            }

            function toggleAllCsvValid(checkValid) {
                for (var i = 0; i < scannedCsvUsers.length; i++) {
                    scannedCsvUsers[i].checked = checkValid ? scannedCsvUsers[i].valid : false;
                }
                renderCsvTable();
            }

            function filterCsvTable() {
                renderCsvTable();
            }

            function updateCsvCounts() {
                var total = scannedCsvUsers.length;
                var validCount = 0;
                var selectedCount = 0;
                for (var i = 0; i < scannedCsvUsers.length; i++) {
                    if (scannedCsvUsers[i].valid) validCount++;
                    if (scannedCsvUsers[i].checked) selectedCount++;
                }
                document.getElementById('csvStatsBadge').textContent =
                    total + ' rows · ' + validCount + ' valid · ' + selectedCount + ' selected';
                document.getElementById('csvSubmitBtnText').textContent =
                    'Import Selected (' + selectedCount + ')';
            }

            function closeCsvPreview() {
                scannedCsvUsers = [];
                document.getElementById('csvFileInput').value = '';
                document.getElementById('csvPreviewSection').classList.add('hidden');
            }

            function submitSelectedCsvUsers() {
                var selected = [];
                for (var i = 0; i < scannedCsvUsers.length; i++) {
                    if (scannedCsvUsers[i].checked && scannedCsvUsers[i].email) {
                        selected.push({
                            name: scannedCsvUsers[i].name,
                            email: scannedCsvUsers[i].email,
                            department: scannedCsvUsers[i].department
                        });
                    }
                }
                if (selected.length === 0) {
                    alert('Please select at least one recipient to import.');
                    return false;
                }
                document.getElementById('csvUsersJsonInput').value = JSON.stringify(selected);
                var btn = document.getElementById('csvSubmitBtn');
                btn.disabled = true;
                document.getElementById('csvSubmitBtnText').textContent = 'Importing ' + selected.length + ' recipients...';
                return true;
            }
        </script>
    </body>
    </html>
    """

    return render_template_string(
        html_content,
        total_users=total_users,
        clicked_users=clicked_users,
        unsent_users=unsent_users,
        click_rate=click_rate,
        user_list=user_list,
        click_logs=click_logs,
        base_url=base_url,
        tracking_path=tracking_path,
        saved_webhook=saved_webhook,
        saved_smtp_username=saved_smtp_username,
        saved_smtp_password=saved_smtp_password,
        saved_sender_name=saved_sender_name,
        saved_email_subject=saved_email_subject,
        sending_running=sending_running,
        sending_sent=sending_sent,
        sending_total=sending_total,
        msg=msg,
        status=status
    )

# --- Main Entrypoint ---
if __name__ == '__main__':
    server_conf = config.get("server", {})
    host = server_conf.get("host", "0.0.0.0")
    port = int(os.environ.get("PORT", server_conf.get("port", 5000)))

    safe_log(f"\n[OK] Starting Flask Server at http://{host}:{port}/dashboard")
    app.run(host=host, port=port, debug=True)
