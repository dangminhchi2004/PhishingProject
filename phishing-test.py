import os
import sys
import json
import uuid
import base64
import smtplib
import urllib.request
import urllib.error
import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from flask import Flask, request, redirect, url_for, render_template_string, session as flask_session
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# Đảm bảo mã hóa UTF-8 trên Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def safe_log(msg):
    """In log an toàn trên mọi môi trường"""
    try:
        print(msg, flush=True)
    except Exception:
        try:
            print(str(msg).encode('ascii', errors='replace').decode('ascii'), flush=True)
        except Exception:
            pass

# --- Khởi tạo ứng dụng Flask ---
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "phishing-sim-secret-key-2026-admin-lock")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')

# Cấu hình dự phòng được mã hóa Base64
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
            safe_log(f"[!] Lỗi khi đọc config.json ({e}), dùng cấu hình mặc định.")

    # Hỗ trợ rút gọn đường dẫn cũ /verify/portal-auth thành /v
    if default_config['campaign'].get('tracking_path') == '/verify/portal-auth':
        default_config['campaign']['tracking_path'] = '/v'

    # Ưu tiên biến môi trường khi triển khai trên Cloud (Render)
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

# --- Cấu hình Database SQLAlchemy (Aiven PostgreSQL) ---
Base = declarative_base()

class User(Base):
    """Bảng lưu danh sách User mục tiêu"""
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), default='Nhân viên')
    department = Column(String(255), default='Chưa phân loại')
    token = Column(String(64), unique=True, nullable=False, index=True)
    clicked = Column(Boolean, default=False)
    ip_address = Column(String(100), default='N/A')
    user_agent = Column(Text, default='N/A')
    clicked_at = Column(String(100), default='N/A')
    last_sent_at = Column(String(100), default='Chưa gửi')

class ClickLog(Base):
    """Bảng lưu lịch sử từng lượt click"""
    __tablename__ = 'click_logs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_email = Column(String(255), nullable=False)
    user_name = Column(String(255), default='Nhân viên')
    department = Column(String(255), default='Chưa phân loại')
    token = Column(String(64), nullable=False)
    ip_address = Column(String(100), default='N/A')
    user_agent = Column(Text, default='N/A')
    clicked_at = Column(String(100), default='N/A')

class AppSetting(Base):
    """Bảng lưu cấu hình hệ thống (Webhook URL, Mật khẩu Admin...)"""
    __tablename__ = 'app_settings'
    key = Column(String(100), primary_key=True)
    value = Column(Text, default='')

engine = None
Session = None
last_db_error = ""

def ensure_pg_driver():
    """Đảm bảo thư viện kết nối PostgreSQL (psycopg2 hoặc psycopg) luôn có sẵn"""
    for mod_name in ("psycopg2", "psycopg"):
        try:
            __import__(mod_name)
            return mod_name
        except ImportError:
            pass
    try:
        import subprocess
        safe_log("[AUTO-INSTALL] Đang tự động cài đặt driver PostgreSQL...")
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
    """Làm sạch chuỗi DATABASE_URL và tự động gán đúng driver PostgreSQL hiện có"""
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
                safe_log(f"[DB INFO] Bảng đã tồn tại: {table_err}")

            last_db_error = ""
            safe_log("[DB OK] Đã kết nối Aiven PostgreSQL (bảng users & click_logs sẵn sàng)!")
            return True
        except Exception as e:
            last_db_error = str(e)
            safe_log(f"[DB THỬ LẠI] URL không hợp lệ hoặc lỗi kết nối ({e}), thử URL dự phòng...")

    engine = None
    Session = None
    return False

def get_db_session():
    """Lấy session DB, tự động kết nối lại nếu trước đó bị ngắt"""
    global Session
    if Session is None:
        init_database()
    if Session is not None:
        return Session()
    return None

init_database()

def get_vn_now_str():
    """Lấy thời gian hiện tại theo múi giờ Việt Nam (UTC+7)"""
    vn_tz = datetime.timezone(datetime.timedelta(hours=7))
    return datetime.datetime.now(vn_tz).strftime("%Y-%m-%d %H:%M:%S")

# --- Quản lý quyền Admin ---
def get_admin_password():
    """Lấy mật khẩu Admin từ Database hoặc cấu hình mặc định (admin123)"""
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
    """Decorator chặn người dùng thường truy cập vào trang quản trị"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not flask_session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def get_active_base_url():
    """Tự động lấy domain hiện tại (Render hoặc Local)"""
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
    """Đọc cấu hình từ bảng app_settings trên Database"""
    session = get_db_session()
    if session:
        try:
            row = session.query(AppSetting).filter_by(key=key).first()
            if row and row.value and row.value.strip():
                return row.value.strip()
        except Exception:
            session.rollback()
    return default_val

def get_saved_webhook_url():
    """Lấy Webhook URL gửi mail qua HTTPS từ Database hoặc cấu hình"""
    return get_saved_setting('webhook_url', config.get("smtp", {}).get("webhook_url", "").strip())

def get_saved_smtp_username():
    """Lấy SMTP_USERNAME từ Database (app_settings) hoặc cấu hình mặc định"""
    return get_saved_setting('smtp_username', config.get("smtp", {}).get("username", "").strip())

def get_saved_smtp_password():
    """Lấy SMTP_PASSWORD từ Database (app_settings) hoặc cấu hình mặc định"""
    return get_saved_setting('smtp_password', config.get("smtp", {}).get("password", "").strip())

# --- Hàm gửi email định dạng HTML với Hyperlink ẩn đường dẫn ---
def send_phishing_email(recipient_email, recipient_name, unique_link):
    """
    Gửi email HTML sử dụng Hyperlink (ẩn hoàn toàn đường dẫn thô trong nội dung email).
    Trả về tuple: (success: bool, message: str)
    """
    camp_conf = config.get("campaign", {})
    smtp_conf = config.get("smtp", {})

    sender_name = get_saved_setting("sender_name", camp_conf.get("sender_display_name", "Cổng Thông Tin Nhân Sự"))
    saved_user = get_saved_smtp_username()
    if smtp_conf.get("enabled") and saved_user:
        sender_email = saved_user
    else:
        sender_email = camp_conf.get("sender_email", "security-alert@internal-portal.com")

    subject = get_saved_setting("email_subject", camp_conf.get("email_subject", "Thông báo quan trọng: Xác nhận tài khoản và quyền lợi nhân viên"))

    # Nội dung văn bản thuần dự phòng (luôn kèm link rút gọn phòng trường hợp Apps Script chưa bật htmlBody)
    plain_body = f"""Kính gửi {recipient_name},

Hệ thống phát hiện tài khoản của bạn cần được cập nhật và xác thực thông tin quyền lợi nhân sự định kỳ.
Để đảm bảo quyền truy cập cổng nội bộ và các chế độ phúc lợi không bị gián đoạn, vui lòng truy cập Cổng Xác Thực Nhân Sự tại liên kết dưới đây:

{unique_link}

Lưu ý: Yêu cầu xác thực có hiệu lực trong vòng 24 giờ kể từ khi thông báo được phát hành.

Trân trọng,
{sender_name}
Bộ phận Quản Trị Hệ Thống & Nhân Sự
"""

    # Nội dung HTML chuyên nghiệp: Dùng Hyperlink và Nút bấm, KHÔNG hiển thị đường link thô
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

    # 1. Nếu có cấu hình Webhook HTTPS (Google Apps Script) -> gửi qua cổng 443
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
                    safe_log(f"[WEBHOOK OK] Đã gửi email HTML qua HTTPS tới {recipient_email}")
                    return True, f"Đã gửi email (kèm Hyperlink) thành công tới {recipient_email}!"
            except urllib.error.HTTPError as he:
                if he.code in (200, 302, 405):
                    return True, f"Đã gửi email (kèm Hyperlink) thành công tới {recipient_email}!"
                raise he
        except Exception as e:
            safe_log(f"[WEBHOOK LỖI] {e}")
            return False, f"Lỗi Webhook HTTPS: {e}"

    # 2. Gửi qua SMTP (Hỗ trợ đầy đủ HTML + Hyperlink)
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

            safe_log(f"[SMTP OK] Đã gửi email HTML đến: {recipient_email}")
            return True, f"Đã gửi email (kèm Hyperlink) thành công đến {recipient_email}"
        except Exception as e:
            err_str = str(e)
            safe_log(f"[SMTP LỖI] Gửi đến {recipient_email} thất bại: {err_str}")
            if "timed out" in err_str.lower() or "101" in err_str or "110" in err_str or "network is unreachable" in err_str.lower():
                return False, f"Kết nối SMTP bị chặn trên Render Free. Hãy cấu hình Google Apps Script Webhook ở khung màu xanh bên dưới!"
            return False, f"Lỗi gửi SMTP tới {recipient_email}: {err_str}"
    else:
        return True, f"Đã tạo link mô phỏng cho {recipient_email}"

# --- Flask Routes ---

@app.route('/')
def home():
    """
    Chặn toàn bộ User thường truy cập vào trang chủ (/).
    Thiết kế theo phong cách Minimalism (NameThatUI): Tối giản, nhiều khoảng trắng, chữ sắc nét.
    """
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 — Truy Cập Bị Hạn Chế</title>
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
            <h1 class="text-xl font-semibold tracking-tight text-gray-900 mb-3">Truy cập trực tiếp bị từ chối</h1>
            <p class="text-sm text-gray-500 leading-relaxed mb-8">
                Hệ thống chỉ tiếp nhận yêu cầu thông qua liên kết xác thực định danh được gửi trực tiếp trong email cá nhân của nhân viên.
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
    """Trang đăng nhập dành riêng cho Admin — Phong cách Minimalism"""
    if flask_session.get('is_admin'):
        return redirect(url_for('dashboard'))

    error_msg = ""
    if request.method == 'POST':
        entered_pw = request.form.get('password', '').strip()
        if entered_pw == get_admin_password():
            flask_session['is_admin'] = True
            return redirect(url_for('dashboard'))
        else:
            error_msg = "Mật khẩu quản trị không chính xác."

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Đăng Nhập Quản Trị</title>
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
                    <label class="block text-xs uppercase tracking-wider text-gray-500 font-medium mb-2">Mật khẩu</label>
                    <input type="password" name="password" required autofocus placeholder="••••••••"
                        class="w-full px-3.5 py-2.5 border border-gray-200 rounded text-sm text-gray-900 bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                </div>
                <button type="submit" class="w-full py-2.5 btn-ink font-medium rounded text-sm transition">
                     Tiếp tục
                </button>
            </form>
        </div>
    </body>
    </html>
    """, error_msg=error_msg)

@app.route('/logout', methods=['POST', 'GET'])
def admin_logout():
    flask_session.pop('is_admin', None)
    return redirect(url_for('admin_login'))

@app.route('/settings/webhook', methods=['POST'])
@admin_required
def save_webhook():
    """Lưu Google Apps Script HTTPS Webhook URL vào bảng app_settings"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    webhook_url = request.form.get('webhook_url', '').strip()
    try:
        row = session.query(AppSetting).filter_by(key='webhook_url').first()
        if row:
            row.value = webhook_url
        else:
            session.add(AppSetting(key='webhook_url', value=webhook_url))
        session.commit()
        if webhook_url:
            return redirect(url_for('dashboard', msg="Đã lưu HTTPS Gmail Webhook URL thành công!", status="success"))
        else:
            return redirect(url_for('dashboard', msg="Đã xóa cấu hình Webhook URL.", status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi lưu cấu hình: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/settings/smtp', methods=['POST'])
@admin_required
def save_smtp_settings():
    """Lưu cấu hình SMTP_USERNAME và SMTP_PASSWORD vào bảng app_settings trên Database"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    smtp_username = request.form.get('smtp_username', '').strip()
    smtp_password = request.form.get('smtp_password', '').strip()

    try:
        user_row = session.query(AppSetting).filter_by(key='smtp_username').first()
        if user_row:
            user_row.value = smtp_username
        else:
            session.add(AppSetting(key='smtp_username', value=smtp_username))

        if smtp_password:
            pw_row = session.query(AppSetting).filter_by(key='smtp_password').first()
            if pw_row:
                pw_row.value = smtp_password
            else:
                session.add(AppSetting(key='smtp_password', value=smtp_password))

        session.commit()
        return redirect(url_for('dashboard', msg=f"Đã lưu cấu hình SMTP ({smtp_username}) thành công!", status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi lưu cấu hình SMTP: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/settings/password', methods=['POST'])
@admin_required
def change_admin_password():
    """Đổi mật khẩu Admin trực tiếp trên giao diện Web"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    new_pw = request.form.get('new_password', '').strip()
    if len(new_pw) < 4:
        Session.remove()
        return redirect(url_for('dashboard', msg="Mật khẩu mới phải có ít nhất 4 ký tự!", status="error"))

    try:
        row = session.query(AppSetting).filter_by(key='admin_password').first()
        if row:
            row.value = new_pw
        else:
            session.add(AppSetting(key='admin_password', value=new_pw))
        session.commit()
        return redirect(url_for('dashboard', msg="Đã cập nhật mật khẩu Admin mới thành công!", status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi đổi mật khẩu: {e}", status="error"))
    finally:
        Session.remove()

def normalize_display_name(raw_name):
    """Đảo lại tên có dấu phẩy: VD 'Chí, Đặng Minh' -> 'Đặng Minh Chí', tên không có dấu phẩy giữ nguyên"""
    cleaned = (raw_name or '').strip()
    if not cleaned:
        return 'Nhân viên'
    if ',' in cleaned:
        parts = [p.strip() for p in cleaned.split(',', 1)]
        if len(parts) == 2 and parts[0] and parts[1]:
            return f"{parts[1]} {parts[0]}"
    return cleaned

@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """Thêm User mới trực tiếp từ giao diện Web vào bảng users (với token ngắn 8 ký tự)"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    name = normalize_display_name(request.form.get('name', ''))
    email = request.form.get('email', '').strip().lower()
    department = request.form.get('department', '').strip() or 'Chưa phân loại'

    if not email or '@' not in email:
        Session.remove()
        return redirect(url_for('dashboard', msg="Vui lòng nhập địa chỉ Email hợp lệ!", status="error"))

    try:
        existing = session.query(User).filter_by(email=email).first()
        if existing:
            existing.name = name
            existing.department = department
            session.commit()
            msg = f"Đã cập nhật thông tin cho user: {name} ({email})"
        else:
            # Token rút gọn 8 ký tự giúp URL cực kỳ ngắn gọn (/v/a1b2c3d4)
            token = uuid.uuid4().hex[:8]
            new_user = User(
                email=email,
                name=name,
                department=department,
                token=token,
                clicked=False,
                ip_address='N/A',
                user_agent='N/A',
                clicked_at='N/A',
                last_sent_at='Chưa gửi'
            )
            session.add(new_user)
            session.commit()
            msg = f"Đã thêm thành công user: {name} ({email}) vào Database!"
        return redirect(url_for('dashboard', msg=msg, status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi khi thêm user: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/users/import-bulk', methods=['POST'])
@admin_required
def import_bulk_users():
    """Thêm hàng loạt các User đã được chọn từ bảng xem trước CSV vào Database"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    users_json = request.form.get('users_json', '[]')
    try:
        items = json.loads(users_json)
        if not isinstance(items, list) or len(items) == 0:
            return redirect(url_for('dashboard', msg="Chưa có user nào được chọn để thêm!", status="error"))

        existing_users = session.query(User).all()
        existing_map = {u.email.lower(): u for u in existing_users}

        added_count = 0
        updated_count = 0
        seen_emails = set()

        for item in items:
            email = (item.get('email') or '').strip().lower()
            name = normalize_display_name(item.get('name'))
            department = (item.get('department') or '').strip() or 'Chưa phân loại'

            if not email or '@' not in email or email in seen_emails:
                continue
            seen_emails.add(email)

            if email in existing_map:
                existing_u = existing_map[email]
                existing_u.name = name
                existing_u.department = department
                updated_count += 1
            else:
                token = uuid.uuid4().hex[:8]
                new_user = User(
                    email=email,
                    name=name,
                    department=department,
                    token=token,
                    clicked=False,
                    ip_address='N/A',
                    user_agent='N/A',
                    clicked_at='N/A',
                    last_sent_at='Chưa gửi'
                )
                session.add(new_user)
                added_count += 1

        session.commit()
        msg = f"Đã nhập từ file CSV thành công: Thêm mới {added_count} user, Cập nhật {updated_count} user!"
        return redirect(url_for('dashboard', msg=msg, status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi khi nhập danh sách CSV: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Xóa 1 user khỏi bảng users"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    try:
        u = session.query(User).filter_by(id=user_id).first()
        if u:
            email = u.email
            session.delete(u)
            session.commit()
            return redirect(url_for('dashboard', msg=f"Đã xóa user {email} khỏi Database.", status="success"))
        return redirect(url_for('dashboard', msg="Không tìm thấy user cần xóa.", status="error"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi khi xóa user: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/users/send/<int:user_id>', methods=['POST'])
@admin_required
def send_single_user(user_id):
    """Gửi email cho 1 user cụ thể"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/v").strip("/")

    try:
        u = session.query(User).filter_by(id=user_id).first()
        if not u:
            return redirect(url_for('dashboard', msg="Không tìm thấy user!", status="error"))

        unique_link = f"{base_url}/{tracking_path}/{u.token}"
        ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
        if ok:
            u.last_sent_at = get_vn_now_str()
            session.commit()
            return redirect(url_for('dashboard', msg=detail_msg, status="success"))
        else:
            return redirect(url_for('dashboard', msg=detail_msg, status="error"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi hệ thống: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/campaign/send-all', methods=['POST', 'GET'])
@app.route('/reload', methods=['POST', 'GET'])
@admin_required
def send_all_users():
    """Gửi email chiến dịch cho toàn bộ user trong bảng users"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/v").strip("/")

    try:
        users = session.query(User).all()
        if not users:
            return redirect(url_for('dashboard', msg="Danh sách User đang trống! Hãy thêm User ở form bên dưới trước khi gửi.", status="error"))

        success_count = 0
        last_err = ""
        now_str = get_vn_now_str()

        for u in users:
            unique_link = f"{base_url}/{tracking_path}/{u.token}"
            ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
            if ok:
                success_count += 1
                u.last_sent_at = now_str
            else:
                last_err = detail_msg
                if "bị chặn" in detail_msg or "timed out" in detail_msg.lower():
                    break

        session.commit()

        if success_count == len(users):
            return redirect(url_for('dashboard', msg=f"Đã gửi thành công {success_count}/{len(users)} email (ẩn link bằng Hyperlink)!", status="success"))
        elif success_count > 0:
            return redirect(url_for('dashboard', msg=f"Đã gửi {success_count}/{len(users)} email. Lỗi: {last_err}", status="error"))
        else:
            return redirect(url_for('dashboard', msg=f"Không thể gửi email: {last_err}", status="error"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi khi gửi chiến dịch: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/db/clear-clicks', methods=['POST'])
@admin_required
def clear_clicks():
    """Xóa sạch bảng click_logs và đặt lại trạng thái clicked=False cho toàn bộ bảng users"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    try:
        session.query(ClickLog).delete()
        users = session.query(User).all()
        for u in users:
            u.clicked = False
            u.ip_address = 'N/A'
            u.user_agent = 'N/A'
            u.clicked_at = 'N/A'
        session.commit()
        return redirect(url_for('dashboard', msg="Đã xóa sạch lịch sử Click và đặt lại trạng thái tất cả User về AN TOÀN!", status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi khi xóa lịch sử click: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/db/clear-all', methods=['POST'])
@admin_required
def clear_all_tables():
    """Xóa sạch dữ liệu trong cả 2 bảng: users và click_logs"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    try:
        session.query(ClickLog).delete()
        session.query(User).delete()
        session.commit()
        return redirect(url_for('dashboard', msg="Đã xóa trắng toàn bộ dữ liệu bảng Users và bảng Click Logs trên Database!", status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi khi xóa toàn bộ bảng: {e}", status="error"))
    finally:
        Session.remove()

# Danh sách các dải IP của Bot quét link tự động (Microsoft Safe Links, Defender, Azure, Google Proxy...)
SCANNER_IP_PREFIXES = (
    "57.150.", "57.151.", "57.152.", "57.153.", "57.154.", "57.155.", "57.156.", "57.157.",
    "40.94.", "40.107.", "104.47.", "52.100.", "52.101.", "66.102.", "66.249.", "72.14."
)

SCANNER_UA_KEYWORDS = (
    "headless", "bot", "crawler", "spider", "scanner", "preview", "safetylink",
    "safelinks", "defender", "office365", "microsoft-expr", "curl", "wget", "python-requests"
)

def is_scanner_bot(ip_addr, ua_str):
    """Kiểm tra xem request có phải từ Bot quét link tự động của Microsoft/Google hay không"""
    ip_clean = (ip_addr or "").strip()
    ua_lower = (ua_str or "").lower()
    if any(ip_clean.startswith(prefix) for prefix in SCANNER_IP_PREFIXES):
        return True
    if any(kw in ua_lower for kw in SCANNER_UA_KEYWORDS):
        return True
    return False

# Route bắt bẫy click link mã hóa token (Chống Bot quét tự động của Microsoft Safe Links)
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

    # Kiểm tra token có tồn tại không
    session = get_db_session()
    user_exists = False
    user_display_name = "Nhân viên"
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

    # BƯỚC 1: Nếu là request GET hoặc đến từ IP Bot của Microsoft (VD: 57.155.170.192)
    # -> Trả về trang Biểu mẫu nội bộ sạch 100% (HTTP 200 OK), KHÔNG ghi nhận click ảo, KHÔNG chứa từ khóa Phishing
    if request.method == 'GET' or is_scanner_bot(ip_address, user_agent):
        if is_scanner_bot(ip_address, user_agent):
            safe_log(f"[BOT BLOCKED] Đã chặn Bot quét link tự động từ IP: {ip_address} | UA: {user_agent}")
        return render_template_string("""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Biểu Mẫu Rà Soát Thông Tin Nhân Sự</title>
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
                <h1 class="text-lg font-semibold text-gray-900 mb-3">Cổng Thông Tin Hành Chính - Nhân Sự</h1>
                <p class="text-sm text-gray-500 leading-relaxed mb-8">
                    Xin chào <strong class="text-gray-900 font-medium">{{ user_display_name }}</strong>, hệ thống đang tải biểu mẫu rà soát chế độ phúc lợi định kỳ của bạn.
                </p>
                <form id="verifyForm" method="POST" action="/v/{{ token }}">
                    <input type="hidden" name="tz_offset" id="tz_offset" value="">
                    <input type="hidden" name="human_confirm" id="human_confirm" value="1">
                    <button type="submit" class="w-full py-2.5 px-4 btn-ink font-medium rounded text-sm transition">
                        Xem &amp; Xác Nhận Biểu Mẫu
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
                    // Nếu trình duyệt người thật ở múi giờ Việt Nam (UTC+7 => offset -420), tự động chuyển tiếp mượt mà
                    if (!isBot && tzOffset === -420) {
                        setTimeout(submitHuman, 450);
                    }
                    // Hoặc ngay khi người dùng di chuột / chạm màn hình cảm ứng
                    window.addEventListener('mousemove', submitHuman, { once: true });
                    window.addEventListener('touchstart', submitHuman, { once: true });
                })();
            </script>
        </body>
        </html>
        """, token=token, user_display_name=user_display_name)

    # BƯỚC 2: Khi nhận POST từ trình duyệt người dùng thật -> Ghi nhận lượt Click vào Database
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
                safe_log(f"[REAL CLICK LOGGED] User: {db_user.name} ({db_user.email}) | IP: {ip_address}")
        except Exception as e:
            session.rollback()
            safe_log(f"[DB LỖI GHI LOG] {e}")
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
    Trang giáo dục nhận thức an toàn thông tin — Phong cách Minimalism (NameThatUI).
    Tuyệt đối KHÔNG có nút dẫn về Trang chủ hay Dashboard của Admin.
    """
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cảnh Báo Nhận Thức An Toàn Thông Tin</title>
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
                Bạn vừa nhấp vào một liên kết mô phỏng Phishing
            </h1>
            <p class="text-gray-500 mb-8 text-sm sm:text-base leading-relaxed">
                Đây là bài kiểm tra nhận thức an toàn thông tin định kỳ của tổ chức nhằm giúp nhân viên rèn luyện kỹ năng nhận diện và phòng ngừa các cuộc tấn công giả mạo thực tế.
            </p>

            <div class="border-t border-b border-gray-200 py-6 mb-8">
                <h2 class="text-xs uppercase tracking-widest text-gray-400 font-semibold mb-4">Các quy tắc kiểm tra an toàn</h2>
                <div class="space-y-4 text-sm text-gray-700 leading-relaxed">
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">01</span>
                        <p><strong class="text-gray-900 font-medium">Kiểm tra liên kết ẩn (Hyperlink):</strong> Luôn rê chuột (hover) hoặc nhấn giữ vào liên kết để kiểm tra tên miền đích thực sự trước khi nhấp.</p>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">02</span>
                        <p><strong class="text-gray-900 font-medium">Cảnh giác với yếu tố khẩn cấp:</strong> Các thông báo yêu cầu xác thực gấp trong 24 giờ thường là dấu hiệu thao túng tâm lý.</p>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">03</span>
                        <p><strong class="text-gray-900 font-medium">Đối chiếu địa chỉ người gửi:</strong> Tên hiển thị có thể giống phòng ban nội bộ, nhưng hãy luôn kiểm tra phần đuôi tên miền sau dấu <code>@</code>.</p>
                    </div>
                    <div class="flex items-start gap-3">
                        <span class="text-xs font-mono text-gray-400 mt-0.5">04</span>
                        <p><strong class="text-gray-900 font-medium">Xác minh qua kênh độc lập:</strong> Khi nghi ngờ, hãy liên hệ trực tiếp bộ phận IT hoặc Nhân sự qua kênh nội bộ chính thức.</p>
                    </div>
                </div>
            </div>

            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <p class="text-xs text-gray-400">
                    An toàn thông tin bắt đầu từ sự cẩn trọng của mỗi cá nhân.
                </p>
                <button type="button" onclick="closeAwarenessPage()" class="px-6 py-2.5 btn-ink text-xs uppercase tracking-wider font-medium rounded transition cursor-pointer">
                    Đã hiểu &amp; Đóng trang
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
                        '<h2 class="text-lg font-semibold text-gray-900 mb-2">Đã ghi nhận hoàn tất</h2>' +
                        '<p class="text-sm text-gray-500">Cảm ơn bạn đã hoàn thành nội dung hướng dẫn an toàn thông tin.</p>';
                }
                setTimeout(function() {
                    window.location.replace('https://www.google.com');
                }, 800);
            }
        </script>
    </body>
    </html>
    """)

@app.route('/dashboard')
@admin_required
def dashboard():
    """Bảng điều khiển chỉ dành riêng cho Admin đã đăng nhập"""
    msg = request.args.get('msg', '')
    status = request.args.get('status', 'info')

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
                    'department': u.department,
                    'token': u.token,
                    'clicked': u.clicked,
                    'ip': u.ip_address,
                    'timestamp': u.clicked_at,
                    'last_sent_at': u.last_sent_at
                })

            db_logs = session.query(ClickLog).order_by(ClickLog.id.desc()).limit(50).all()
            for lg in db_logs:
                click_logs.append({
                    'id': lg.id,
                    'email': lg.user_email,
                    'name': lg.user_name,
                    'department': lg.department,
                    'ip': lg.ip_address,
                    'user_agent': lg.user_agent,
                    'clicked_at': lg.clicked_at
                })
        except Exception as e:
            session.rollback()
            msg = f"Lỗi truy vấn Database: {e}"
            status = "error"
        finally:
            Session.remove()
    elif not msg:
        msg = f"Không thể kết nối Database: {last_db_error}"
        status = "error"

    total_users = len(user_list)
    clicked_users = sum(1 for u in user_list if u['clicked'])
    click_rate = (clicked_users / total_users * 100) if total_users > 0 else 0

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/v").strip("/")
    saved_webhook = get_saved_webhook_url()
    saved_smtp_username = get_saved_smtp_username()
    saved_smtp_password = get_saved_smtp_password()

    html_content = """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>Phishing Simulation — Admin</title>
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
                            Cài đặt
                        </button>

                        <form action="/db/clear-clicks" method="POST" class="inline" onsubmit="return confirm('Xóa lịch sử Click và đặt lại trạng thái tất cả User về AN TOÀN?');">
                            <button type="submit" class="px-3.5 py-2 btn-outline rounded text-xs font-medium transition">
                                Đặt lại Click
                            </button>
                        </form>

                        <form action="/db/clear-all" method="POST" class="inline" onsubmit="return confirm('CẢNH BÁO: Bạn có chắc chắn muốn XÓA SẠCH toàn bộ User và Lịch sử Click?');">
                            <button type="submit" class="px-3.5 py-2 bg-white hover:bg-red-50 text-red-600 border border-gray-200 hover:border-red-200 rounded text-xs font-medium transition">
                                Xóa dữ liệu
                            </button>
                        </form>

                        <a href="/logout" class="px-3.5 py-2 text-gray-500 hover:text-gray-900 text-xs font-medium transition">
                            Đăng xuất
                        </a>
                    </div>

                    <!-- Mobile / Tablet Menu Button (< lg) -->
                    <button type="button" onclick="toggleDrawer(true)"
                        class="lg:hidden inline-flex items-center justify-center p-2 rounded text-gray-700 btn-outline focus:outline-none"
                        aria-label="Mở menu cài đặt">
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
                                <h2 class="text-sm font-semibold text-gray-900 mt-0.5">Cài đặt &amp; Quản trị</h2>
                            </div>
                            <button type="button" onclick="toggleDrawer(false)" class="p-1.5 rounded text-gray-400 hover:text-gray-900 transition">
                                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                            </button>
                        </div>

                        <div class="p-6 space-y-8 divide-y divide-gray-100">
                            <!-- 1. HTTPS Gmail Webhook -->
                            <div class="space-y-3">
                                <div class="flex items-center justify-between">
                                    <span class="label-micro">01 / HTTPS Webhook</span>
                                    <span class="inline-flex items-center gap-1.5 text-xs font-medium {% if saved_webhook %}text-gray-900{% else %}text-gray-400{% endif %}">
                                        <span class="w-1.5 h-1.5 rounded-full {% if saved_webhook %}bg-green-500{% else %}bg-gray-300{% endif %}"></span>
                                        {% if saved_webhook %}Đã kết nối{% else %}Chưa cấu hình{% endif %}
                                    </span>
                                </div>
                                <p class="text-xs text-gray-500 leading-relaxed">
                                    Google Apps Script Webhook giúp gửi email qua cổng 443 trên Render.
                                </p>
                                <form action="/settings/webhook" method="POST" class="space-y-2.5">
                                    <input type="url" name="webhook_url" value="{{ saved_webhook }}"
                                        placeholder="https://script.google.com/macros/s/.../exec"
                                        class="w-full px-3 py-2 border border-gray-200 rounded text-xs font-mono-code bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    <button type="submit" class="w-full py-2 btn-ink font-medium rounded text-xs transition">
                                        Lưu Webhook URL
                                    </button>
                                </form>
                            </div>

                            <!-- 2. SMTP_USERNAME & SMTP_PASSWORD -->
                            <div class="pt-6 space-y-3">
                                <div class="flex items-center justify-between">
                                    <span class="label-micro">02 / Tài khoản SMTP</span>
                                    <span class="inline-flex items-center gap-1.5 text-xs font-medium {% if saved_smtp_username %}text-gray-900{% else %}text-gray-400{% endif %}">
                                        <span class="w-1.5 h-1.5 rounded-full {% if saved_smtp_username %}bg-green-500{% else %}bg-gray-300{% endif %}"></span>
                                        {% if saved_smtp_username %}Đã cấu hình{% else %}Chưa cấu hình{% endif %}
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
                                        Lưu cấu hình SMTP
                                    </button>
                                </form>
                            </div>

                            <!-- 3. Admin Password -->
                            <div class="pt-6 space-y-3">
                                <span class="label-micro block">03 / Bảo mật Admin</span>
                                <form action="/settings/password" method="POST" class="flex gap-2">
                                    <input type="password" name="new_password" required placeholder="Mật khẩu Admin mới..."
                                        class="flex-1 px-3 py-2 border border-gray-200 rounded text-xs bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                                    <button type="submit" class="px-4 py-2 btn-outline font-medium rounded text-xs transition whitespace-nowrap">
                                        Cập nhật
                                    </button>
                                </form>
                            </div>

                            <!-- 4. Database Maintenance -->
                            <div class="pt-6 space-y-2.5">
                                <span class="label-micro block mb-2">04 / Quản trị dữ liệu</span>

                                <form action="/db/clear-clicks" method="POST" onsubmit="return confirm('Bạn muốn xóa lịch sử Click và đặt lại trạng thái tất cả User về AN TOÀN?');">
                                    <button type="submit" class="w-full py-2 px-4 btn-outline rounded font-medium text-xs transition text-left flex items-center justify-between">
                                        <span>Đặt lại lịch sử Click (Giữ User)</span>
                                        <span class="text-gray-400">↺</span>
                                    </button>
                                </form>

                                <form action="/db/clear-all" method="POST" onsubmit="return confirm('CẢNH BÁO: Bạn có chắc chắn muốn XÓA SẠCH toàn bộ User và Lịch sử Click trong Database?');">
                                    <button type="submit" class="w-full py-2 px-4 bg-white hover:bg-red-50 text-red-600 border border-gray-200 hover:border-red-200 rounded font-medium text-xs transition text-left flex items-center justify-between">
                                        <span>Xóa trắng toàn bộ Database</span>
                                        <span>×</span>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <!-- Drawer Footer -->
                    <div class="p-6 border-t border-gray-200">
                        <a href="/logout" class="w-full py-2.5 px-4 btn-outline rounded font-medium text-xs flex items-center justify-center transition">
                            Đăng xuất khỏi phiên quản trị
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content Area — Generous Whitespace & Hairline Grid -->
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-10 space-y-8">

            <!-- Status Notification Banner -->
            {% if msg %}
            <div class="px-4 py-3 rounded border {% if status == 'error' %}bg-red-50 border-red-200 text-red-700{% else %}bg-white border-gray-300 text-gray-900{% endif %} flex justify-between items-center gap-4">
                <div class="text-xs sm:text-sm font-medium flex items-center gap-2.5">
                    <span class="w-1.5 h-1.5 rounded-full flex-shrink-0 {% if status == 'error' %}bg-red-600{% else %}bg-gray-900{% endif %}"></span>
                    <span>{{ msg }}</span>
                </div>
                <a href="/dashboard" class="text-xs text-gray-400 hover:text-gray-900 font-medium flex-shrink-0">Đóng</a>
            </div>
            {% endif %}

            <!-- Architectural KPI Grid (Minimalist Hairline Matrix) -->
            <div class="bg-white border border-gray-200 rounded-md grid grid-cols-2 lg:grid-cols-4 divide-y lg:divide-y-0 sm:divide-x divide-gray-200">
                <div class="p-5 sm:p-7">
                    <p class="label-micro">Tổng mục tiêu</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight text-gray-900 mt-2 font-mono-code">{{ total_users }}</p>
                </div>
                <div class="p-5 sm:p-7 border-l border-gray-200">
                    <p class="label-micro">Đã nhấp liên kết</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight {% if clicked_users > 0 %}text-red-600{% else %}text-gray-900{% endif %} mt-2 font-mono-code">{{ clicked_users }}</p>
                </div>
                <div class="p-5 sm:p-7">
                    <p class="label-micro">Tỷ lệ sập bẫy</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight text-gray-900 mt-2 font-mono-code">{{ '{:.1f}'.format(click_rate) }}%</p>
                </div>
                <div class="p-5 sm:p-7 border-l border-gray-200">
                    <p class="label-micro">Tổng lượt ghi nhận</p>
                    <p class="text-3xl sm:text-4xl font-light tracking-tight text-gray-900 mt-2 font-mono-code">{{ click_logs|length }}</p>
                </div>
            </div>

            <!-- Add Target User & CSV Import Panel -->
            <div class="bg-white border border-gray-200 rounded-md p-5 sm:p-7 space-y-6">
                <div>
                    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-5">
                        <div>
                            <p class="label-micro">Target Provisioning</p>
                            <h2 class="text-sm sm:text-base font-semibold text-gray-900 mt-0.5">Thêm mục tiêu diễn tập</h2>
                        </div>
                        <!-- Minimal CSV Upload Trigger -->
                        <label class="inline-flex items-center justify-center gap-2 px-3.5 py-2 btn-outline rounded text-xs font-medium cursor-pointer transition">
                            <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
                            </svg>
                            <span>Nhập từ file CSV</span>
                            <input type="file" id="csvFileInput" accept=".csv,text/csv" class="hidden" onchange="handleCsvFile(this)">
                        </label>
                    </div>

                    <form action="/users/add" method="POST" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 items-end">
                        <div>
                            <label class="block label-micro mb-1.5">Họ và tên *</label>
                            <input type="text" name="name" required placeholder="Nguyễn Văn A"
                                class="w-full px-3 py-2 border border-gray-200 rounded text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                        </div>
                        <div>
                            <label class="block label-micro mb-1.5">Địa chỉ Email *</label>
                            <input type="email" name="email" required placeholder="name@company.com"
                                class="w-full px-3 py-2 border border-gray-200 rounded text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                        </div>
                        <div>
                            <label class="block label-micro mb-1.5">Phòng ban</label>
                            <input type="text" name="department" placeholder="CNTT / Kế toán"
                                class="w-full px-3 py-2 border border-gray-200 rounded text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">
                        </div>
                        <div>
                            <button type="submit" class="w-full py-2 px-4 btn-ink font-medium rounded text-sm transition">
                                Lưu mục tiêu
                            </button>
                        </div>
                    </form>
                </div>

                <!-- CSV Preview Section (Minimalist Table) -->
                <div id="csvPreviewSection" class="hidden border-t border-gray-200 pt-6 space-y-4">
                    <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3 bg-gray-50 p-4 rounded border border-gray-200">
                        <div>
                            <div class="flex items-center gap-3 flex-wrap">
                                <span class="text-xs font-semibold text-gray-900" id="csvFileNameTitle">File CSV</span>
                                <span id="csvStatsBadge" class="text-xs font-mono-code text-gray-500"></span>
                            </div>
                            <p class="text-xs text-gray-400 mt-1">
                                Cột: <code class="font-mono-code text-gray-600">Display name</code> &rarr; Tên | <code class="font-mono-code text-gray-600">User principal name</code> &rarr; Email | <code class="font-mono-code text-gray-600">Department</code> &rarr; Phòng ban
                            </p>
                        </div>

                        <div class="flex flex-wrap items-center gap-2">
                            <button type="button" onclick="toggleAllCsvValid(true)" class="px-3 py-1.5 btn-outline rounded text-xs font-medium transition">
                                Chọn tất cả hợp lệ
                            </button>
                            <button type="button" onclick="toggleAllCsvValid(false)" class="px-3 py-1.5 btn-outline rounded text-xs font-medium transition">
                                Bỏ chọn tất cả
                            </button>
                            <button type="button" onclick="closeCsvPreview()" class="px-3 py-1.5 text-gray-400 hover:text-gray-900 text-xs font-medium transition">
                                Đóng
                            </button>
                        </div>
                    </div>

                    <div class="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                        <input type="text" id="csvSearchInput" oninput="filterCsvTable()" placeholder="Lọc theo tên, email hoặc phòng ban..."
                            class="flex-1 px-3 py-2 border border-gray-200 rounded text-xs sm:text-sm bg-gray-50 focus:bg-white focus:outline-none focus:border-gray-900 transition">

                        <form id="csvBulkForm" action="/users/import-bulk" method="POST" onsubmit="return submitSelectedCsvUsers();">
                            <input type="hidden" name="users_json" id="csvUsersJsonInput" value="[]">
                            <button type="submit" id="csvSubmitBtn" class="w-full sm:w-auto px-5 py-2 btn-ink font-medium rounded text-xs sm:text-sm transition">
                                <span id="csvSubmitBtnText">Thêm các user đã chọn (0)</span>
                            </button>
                        </form>
                    </div>

                    <div class="border border-gray-200 rounded overflow-hidden">
                        <div class="max-h-80 overflow-y-auto">
                            <table class="min-w-full divide-y divide-gray-200 text-xs sm:text-sm">
                                <thead class="bg-gray-50 text-gray-500 sticky top-0 z-10">
                                    <tr>
                                        <th class="py-2.5 px-3 text-center w-10 label-micro">Chọn</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Họ và tên</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Email</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Phòng ban</th>
                                        <th class="py-2.5 px-3 text-left label-micro">Trạng thái</th>
                                    </tr>
                                </thead>
                                <tbody id="csvPreviewTbody" class="divide-y divide-gray-100 bg-white">
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TABLE 1: TARGET USERS -->
            <div class="bg-white rounded-md border border-gray-200 overflow-hidden">
                <div class="px-5 py-4 border-b border-gray-200 flex justify-between items-center gap-3">
                    <div class="flex items-center gap-2 min-w-0">
                        <span class="text-sm font-semibold text-gray-900">Danh sách mục tiêu</span>
                        <span class="hidden sm:inline-block text-xs font-mono-code text-gray-400">({{ total_users }})</span>
                    </div>
                    <div class="flex items-center gap-3 flex-shrink-0">
                        <form action="/campaign/send-all" method="POST" class="inline">
                            <button type="submit" class="inline-flex items-center gap-2 px-3.5 sm:px-4 py-2 btn-ink rounded text-xs font-medium tracking-wide transition">
                                <span>Gửi mail cho tất cả</span>
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
                                            Đã click
                                        </span>
                                    {% else %}
                                        <span class="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500">
                                            <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                            An toàn
                                        </span>
                                    {% endif %}
                                </div>
                            </div>

                            <div class="text-xs text-gray-500 border-t border-gray-100 pt-2.5 grid grid-cols-2 gap-2">
                                <div>
                                    <span class="text-gray-400 block">Gửi lúc</span>
                                    <span class="font-mono-code text-gray-700">{{ u.last_sent_at }}</span>
                                </div>
                                <div>
                                    <span class="text-gray-400 block">IP / Click</span>
                                    <span class="font-mono-code text-gray-700">{{ u.ip }}</span>
                                    {% if u.timestamp != 'N/A' %}
                                    <span class="block text-red-600 font-mono-code">{{ u.timestamp }}</span>
                                    {% endif %}
                                </div>
                            </div>

                            <div class="grid grid-cols-3 gap-2 pt-1">
                                <form action="/users/send/{{ u.id }}" method="POST" class="w-full">
                                    <button type="submit" class="w-full py-1.5 px-2 btn-ink rounded text-xs font-medium transition">
                                        Gửi mail
                                    </button>
                                </form>

                                <button type="button"
                                    onclick="copyLink('{{ base_url }}/{{ tracking_path }}/{{ u.token }}')"
                                    class="w-full py-1.5 px-2 btn-outline rounded text-xs font-medium transition">
                                    Sao chép
                                </button>

                                <form action="/users/delete/{{ u.id }}" method="POST" class="w-full" onsubmit="return confirm('Xóa user {{ u.email }}?');">
                                    <button type="submit" class="w-full py-1.5 px-2 bg-white hover:bg-red-50 text-red-600 border border-gray-200 rounded text-xs font-medium transition">
                                        Xóa
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
                                    <th class="py-3 px-5 text-left label-micro">Nhân sự</th>
                                    <th class="py-3 px-5 text-left label-micro">Phòng ban</th>
                                    <th class="py-3 px-5 text-left label-micro">Trạng thái</th>
                                    <th class="py-3 px-5 text-left label-micro">IP &amp; Thời gian</th>
                                    <th class="py-3 px-5 text-left label-micro">Đường dẫn</th>
                                    <th class="py-3 px-5 text-right label-micro">Thao tác</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100 bg-white">
                                {% for u in user_list %}
                                <tr class="hover:bg-gray-50 transition">
                                    <td class="py-3.5 px-5 text-gray-400 font-mono-code text-xs">#{{ u.id }}</td>
                                    <td class="py-3.5 px-5">
                                        <div class="font-medium text-gray-900">{{ u.name }}</div>
                                        <div class="text-xs text-gray-500 font-mono-code mt-0.5">{{ u.email }}</div>
                                        <div class="text-xs text-gray-400 mt-0.5">Gửi lúc: {{ u.last_sent_at }}</div>
                                    </td>
                                    <td class="py-3.5 px-5 text-xs text-gray-600">{{ u.department }}</td>
                                    <td class="py-3.5 px-5">
                                        {% if u.clicked %}
                                            <span class="inline-flex items-center gap-1.5 text-xs font-medium text-red-600">
                                                <span class="w-1.5 h-1.5 rounded-full bg-red-600"></span>
                                                Đã click
                                            </span>
                                        {% else %}
                                            <span class="inline-flex items-center gap-1.5 text-xs font-medium text-gray-500">
                                                <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
                                                An toàn
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
                                                Gửi mail
                                            </button>
                                        </form>
                                        <form action="/users/delete/{{ u.id }}" method="POST" class="inline" onsubmit="return confirm('Xóa user {{ u.email }}?');">
                                            <button type="submit" class="px-2.5 py-1.5 text-gray-400 hover:text-red-600 text-xs font-medium transition">
                                                Xóa
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
                        Chưa có mục tiêu nào trong cơ sở dữ liệu.
                    </div>
                {% endif %}
            </div>

            <!-- TABLE 2: CLICK LOGS -->
            <div class="bg-white rounded-md border border-gray-200 overflow-hidden">
                <div class="px-5 py-4 border-b border-gray-200 flex justify-between items-center">
                    <div>
                        <span class="text-sm font-semibold text-gray-900">Nhật ký truy cập</span>
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
                                    <th class="py-3 px-5 text-left label-micro">Thời gian</th>
                                    <th class="py-3 px-5 text-left label-micro">Nhân sự</th>
                                    <th class="py-3 px-5 text-left label-micro">Phòng ban</th>
                                    <th class="py-3 px-5 text-left label-micro">Địa chỉ IP</th>
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
                        Chưa có sự kiện click nào được ghi nhận.
                    </div>
                {% endif %}
            </div>

        </main>

        <!-- Minimal Toast -->
        <div id="copyToast" class="fixed bottom-6 left-1/2 transform -translate-x-1/2 z-50 hidden bg-black text-white text-xs font-medium px-4 py-2 rounded">
            Đã sao chép liên kết vào bộ nhớ tạm
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

            // --- XỬ LÝ QUÉT & XEM TRƯỚC FILE CSV (userAccount.csv) ---
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
                // Loại bỏ các tài khoản Guest chứa #EXT# hoặc sai cấu trúc email chuẩn
                if (email.indexOf('#') !== -1 || email.indexOf(' ') !== -1) return false;
                var re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
                return re.test(email);
            }

            function formatDisplayName(rawName) {
                var cleaned = String(rawName || '').trim();
                if (!cleaned) return 'Nhân viên';
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
                        alert('File CSV trống hoặc không có dữ liệu!');
                        return;
                    }

                    var headers = parseCsvRow(lines[0]).map(function(h) { return h.toLowerCase().trim(); });
                    var idxEmail = headers.indexOf('user principal name');
                    if (idxEmail === -1) idxEmail = headers.indexOf('email');

                    var idxName = headers.indexOf('display name');
                    if (idxName === -1) idxName = headers.indexOf('name');

                    var idxDept = headers.indexOf('department');

                    if (idxEmail === -1) {
                        alert('Không tìm thấy cột "User principal name" (hoặc "Email") trong file CSV!');
                        return;
                    }

                    scannedCsvUsers = [];
                    var seenInCsv = {};

                    for (var i = 1; i < lines.length; i++) {
                        var cols = parseCsvRow(lines[i]);
                        if (cols.length <= idxEmail) continue;

                        var rawEmail = (cols[idxEmail] || '').trim().toLowerCase();
                        var rawName = (idxName !== -1 && cols[idxName]) ? formatDisplayName(cols[idxName]) : 'Nhân viên';
                        var rawDept = (idxDept !== -1 && cols[idxDept]) ? cols[idxDept].trim() : 'Chưa phân loại';

                        if (!rawEmail && !rawName) continue;
                        if (rawEmail && seenInCsv[rawEmail]) continue;
                        if (rawEmail) seenInCsv[rawEmail] = true;

                        var valid = isValidEmailFormat(rawEmail);
                        scannedCsvUsers.push({
                            index: scannedCsvUsers.length,
                            name: rawName || 'Nhân viên',
                            email: rawEmail,
                            department: rawDept || 'Chưa phân loại',
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
                        ? '<span class="inline-flex items-center gap-1.5 text-xs text-gray-600"><span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>Hợp lệ</span>'
                        : '<span class="inline-flex items-center gap-1.5 text-xs text-red-600"><span class="w-1.5 h-1.5 rounded-full bg-red-500"></span>Sai định dạng</span>';

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
                    html = '<tr><td colspan="5" class="py-8 text-center text-gray-400 text-xs">Không tìm thấy kết quả phù hợp.</td></tr>';
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
                    'Thêm các user đã chọn (' + selectedCount + ')';
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
                    alert('Vui lòng tick chọn ít nhất 1 user để thêm vào Database!');
                    return false;
                }
                document.getElementById('csvUsersJsonInput').value = JSON.stringify(selected);
                var btn = document.getElementById('csvSubmitBtn');
                btn.disabled = true;
                document.getElementById('csvSubmitBtnText').textContent = 'Đang lưu ' + selected.length + ' user...';
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
        click_rate=click_rate,
        user_list=user_list,
        click_logs=click_logs,
        base_url=base_url,
        tracking_path=tracking_path,
        saved_webhook=saved_webhook,
        saved_smtp_username=saved_smtp_username,
        saved_smtp_password=saved_smtp_password,
        msg=msg,
        status=status
    )

# --- Điểm chạy chính ---
if __name__ == '__main__':
    server_conf = config.get("server", {})
    host = server_conf.get("host", "0.0.0.0")
    port = int(os.environ.get("PORT", server_conf.get("port", 5000)))

    safe_log(f"\n[OK] Khởi động Flask Server tại http://{host}:{port}/dashboard")
    app.run(host=host, port=port, debug=True)
