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
            "email_subject": "Kế hoạch rà soát và đăng ký chế độ phúc lợi định kỳ",
            "sender_display_name": "Ban Hành Chính - Nhân Sự",
            "sender_email": "hr-office@internal-portal.com"
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

# --- Hàm gửi email định dạng HTML tự nhiên (Tối ưu vượt bộ lọc Junk Mail của Outlook/M365) ---
def send_phishing_email(recipient_email, recipient_name, unique_link):
    """
    Gửi email HTML sử dụng Hyperlink với văn phong hành chính nội bộ tự nhiên,
    tránh các từ khóa nhạy cảm khiến Microsoft 365 đưa vào Junk Mail.
    """
    camp_conf = config.get("campaign", {})
    smtp_conf = config.get("smtp", {})

    sender_name = get_saved_setting("sender_name", camp_conf.get("sender_display_name", "Ban Hành Chính - Nhân Sự"))
    if smtp_conf.get("enabled") and smtp_conf.get("username"):
        sender_email = smtp_conf.get("username")
    else:
        sender_email = camp_conf.get("sender_email", "hr-office@internal-portal.com")

    subject = get_saved_setting("email_subject", camp_conf.get("email_subject", "Kế hoạch rà soát và đăng ký chế độ phúc lợi định kỳ"))

    plain_body = f"""Chào {recipient_name},

Ban Hành Chính - Nhân Sự gửi đến bạn phiếu rà soát thông tin phúc lợi và chế độ nhân viên định kỳ trong quý này.

Bạn vui lòng kiểm tra và xác nhận thông tin cá nhân tại biểu mẫu nội bộ:
{unique_link}

Nếu có thông tin cần điều chỉnh, vui lòng phản hồi trước ngày kết thúc đợt rà soát để bộ phận tổng hợp danh sách.

Trân trọng,
{sender_name}
"""

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin: 0; padding: 0; background-color: #f9fafb;">
    <div style="font-family: 'Segoe UI', Tahoma, Arial, sans-serif; color: #1f2937; max-width: 580px; margin: 20px auto; line-height: 1.6; border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; background-color: #ffffff;">
        <p style="margin-top: 0; font-size: 14px; color: #4b5563;">
            <strong>{sender_name}</strong> &bull; Thông báo nội bộ
        </p>
        <hr style="border: none; border-top: 1px solid #f3f4f6; margin: 12px 0 20px 0;">
        <p style="font-size: 15px;">Chào <strong>{recipient_name}</strong>,</p>
        <p style="font-size: 15px;">
            Theo kế hoạch định kỳ, bộ phận Nhân sự đang tiến hành rà soát và cập nhật danh sách đăng ký chế độ phúc lợi cho nhân viên trong quý này.
        </p>
        <p style="font-size: 15px;">
            Bạn vui lòng mở <a href="{unique_link}" style="color: #1d4ed8; font-weight: 600; text-decoration: underline;">Biểu mẫu xác nhận thông tin nhân sự</a> hoặc nhấn vào mục bên dưới để kiểm tra lại hồ sơ của mình:
        </p>
        <div style=" margin: 24px 0;">
            <a href="{unique_link}"
               style="background-color: #1d4ed8; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: 600; display: inline-block;">
               Xem &amp; Xác nhận biểu mẫu
            </a>
        </div>
        <p style="font-size: 13px; color: #6b7280;">
            Nếu thông tin không có gì thay đổi, bạn chỉ cần mở biểu mẫu để hệ thống ghi nhận trạng thái hoàn tất.
        </p>
        <hr style="border: none; border-top: 1px solid #f3f4f6; margin: 20px 0 12px 0;">
        <p style="font-size: 13px; color: #6b7280; margin-bottom: 0;">
            Trân trọng,<br>
            <strong>{sender_name}</strong>
        </p>
    </div>
</body>
</html>"""

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
            username = smtp_conf.get("username", "").strip()
            password = smtp_conf.get("password", "").strip()

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
    Chỉ hiển thị thông báo cổng xác thực nội bộ, không lộ bất kỳ thông tin hay đường dẫn Admin nào.
    """
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>403 Forbidden - Cổng Xác Thực Nội Bộ</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-xl shadow-lg p-8 max-w-md w-full text-center border-t-4 border-gray-700">
            <div class="text-5xl mb-4">🔒</div>
            <h1 class="text-xl font-bold text-gray-800 mb-2">Truy Cập Trực Tiếp Bị Từ Chối (403)</h1>
            <p class="text-sm text-gray-600 mb-6">
                Hệ thống này chỉ tiếp nhận yêu cầu thông qua <strong>liên kết xác thực định danh</strong> được gửi trực tiếp trong email cá nhân của nhân viên.
            </p>
            <div class="text-xs text-gray-400 border-t border-gray-100 pt-4">
                Internal Authentication Gateway &bull; Security Service
            </div>
        </div>
    </body>
    </html>
    """), 403

@app.route('/login', methods=['GET', 'POST'])
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    """Trang đăng nhập dành riêng cho Admin"""
    if flask_session.get('is_admin'):
        return redirect(url_for('dashboard'))

    error_msg = ""
    if request.method == 'POST':
        entered_pw = request.form.get('password', '').strip()
        if entered_pw == get_admin_password():
            flask_session['is_admin'] = True
            return redirect(url_for('dashboard'))
        else:
            error_msg = "Mật khẩu Quản trị viên không chính xác!"

    return render_template_string("""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Đăng Nhập Quản Trị Viên</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-900 flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-xl shadow-2xl p-8 max-w-sm w-full">
            <div class="text-center mb-6">
                <div class="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-100 text-blue-600 mb-3 font-bold text-xl">
                    🛡️
                </div>
                <h1 class="text-2xl font-extrabold text-gray-900">Admin Portal</h1>
                <p class="text-xs text-gray-500 mt-1">Chỉ Quản trị viên mới được phép truy cập Dashboard</p>
            </div>

            {% if error_msg %}
            <div class="mb-4 p-3 bg-red-50 border border-red-200 text-red-700 text-xs font-semibold rounded-lg text-center">
                ⚠️ {{ error_msg }}
            </div>
            {% endif %}

            <form method="POST" class="space-y-4">
                <div>
                    <label class="block text-xs font-semibold text-gray-600 uppercase mb-1">Mật khẩu Admin</label>
                    <input type="password" name="password" required autofocus placeholder="Nhập mật khẩu quản trị..."
                        class="w-full px-3 py-2.5 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-600">
                </div>
                <button type="submit" class="w-full py-2.5 bg-blue-600 text-white font-bold rounded-lg hover:bg-blue-700 transition text-sm shadow">
                    🔓 Đăng Nhập Quản Trị
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

@app.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    """Thêm User mới trực tiếp từ giao diện Web vào bảng users (với token ngắn 8 ký tự)"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    name = request.form.get('name', '').strip() or 'Nhân viên'
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
        </head>
        <body class="bg-gray-50 flex items-center justify-center min-h-screen p-4">
            <div class="bg-white rounded-xl shadow-md p-8 max-w-md w-full text-center border border-gray-200">
                <div class="w-12 h-12 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center mx-auto mb-4 font-bold text-xl">
                    📋
                </div>
                <h1 class="text-lg font-bold text-gray-800 mb-2">Cổng Thông Tin Hành Chính - Nhân Sự</h1>
                <p class="text-sm text-gray-600 mb-6">
                    Xin chào <strong>{{ user_display_name }}</strong>, hệ thống đang tải biểu mẫu rà soát chế độ phúc lợi định kỳ của bạn.
                </p>
                <form id="verifyForm" method="POST" action="/v/{{ token }}">
                    <input type="hidden" name="tz_offset" id="tz_offset" value="">
                    <input type="hidden" name="human_confirm" id="human_confirm" value="1">
                    <button type="submit" class="w-full py-2.5 px-4 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 text-sm transition shadow-sm">
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
    Trang giáo dục nhận thức an toàn thông tin khi nhân viên nhấp vào link.
    Tuyệt đối KHÔNG có nút dẫn về Trang chủ hay Dashboard của Admin.
    """
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cảnh Báo An Toàn Thông Tin</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-xl shadow-2xl p-8 max-w-2xl w-full text-center border-t-8 border-red-500">
            <div class="mb-4 inline-flex p-3 bg-red-100 rounded-full text-red-600">
                <svg class="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                </svg>
            </div>
            <h1 class="text-3xl font-extrabold text-red-600 mb-3">Bạn Vừa Nhấp Vào Một Liên Kết Mô Phỏng Phishing!</h1>
            <p class="text-gray-700 mb-6 text-base">
                Đừng quá lo lắng! Đây là một <strong>bài kiểm tra nhận thức an toàn định kỳ</strong> của tổ chức nhằm giúp bạn nâng cao kỹ năng phòng ngừa các cuộc tấn công mạng thực tế.
            </p>

            <div class="bg-blue-50 border border-blue-200 rounded-lg p-5 mb-6 text-left">
                <h2 class="text-lg font-bold text-blue-900 mb-3">🔍 Các Dấu Hiệu Bạn Cần Cảnh Giác:</h2>
                <ul class="space-y-2 text-sm text-gray-800 list-disc list-inside">
                    <li><strong>Liên kết ẩn dưới chữ (Hyperlink):</strong> Kẻ tấn công thường ẩn đường dẫn giả mạo bên dưới các nút bấm hoặc dòng chữ như <em>"Xác thực tại đây"</em>. Hãy luôn rê chuột (hover) hoặc giữ vào liên kết để xem địa chỉ thực sự trước khi bấm.</li>
                    <li><strong>Áp lực khẩn cấp:</strong> Thư đe dọa tài khoản bị khóa trong 24h hoặc mất quyền lợi để bạn bấm vội.</li>
                    <li><strong>Kiểm tra người gửi:</strong> Tên hiển thị có thể là "Nhân Sự", nhưng hãy nhìn kỹ địa chỉ email thực tế.</li>
                    <li><strong>Xác minh kênh phụ:</strong> Khi nghi ngờ, hãy hỏi trực tiếp bộ phận IT/Nhân sự qua Zalo, Slack, Teams hoặc điện thoại nội bộ.</li>
                </ul>
            </div>

            <p class="text-sm text-gray-500 mb-6">
                Bảo mật thông tin bắt đầu từ sự cảnh giác của mỗi cá nhân. Bạn có thể đóng tab trình duyệt này lại.
            </p>
            <button onclick="window.close();" class="inline-block px-6 py-2.5 bg-gray-700 text-white font-semibold rounded-lg hover:bg-gray-800 transition">
                Đã Hiểu &amp; Đóng Trang Này
            </button>
        </div>
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

    html_content = """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <title>Quản Trị Chiến Dịch Phishing</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
        <style>
            body { -webkit-tap-highlight-color: transparent; }
            .drawer-backdrop { background-color: rgba(17, 24, 39, 0.6); backdrop-filter: blur(2px); }
        </style>
    </head>
    <body class="bg-gray-100 min-h-screen pb-10">

        <!-- Thanh Navigation Cố Định (Sticky Top Header) tối ưu cho cả Mobile & Desktop -->
        <header class="sticky top-0 z-30 bg-white border-b border-gray-200 shadow-sm">
            <div class="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-2">
                <!-- Logo & Tên hệ thống -->
                <div class="flex items-center gap-2.5 min-w-0">
                    <div class="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white font-bold text-lg shadow-sm flex-shrink-0">
                        🛡️
                    </div>
                    <div class="truncate">
                        <div class="flex items-center gap-2">
                            <h1 class="text-base sm:text-xl font-extrabold text-gray-900 truncate">Phishing Admin</h1>
                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700 border border-green-300">
                                ● Online
                            </span>
                        </div>
                        <p class="hidden sm:block text-xs text-gray-500 truncate">
                            Link rút gọn: <code class="text-blue-600 font-mono">{{ base_url }}/{{ tracking_path }}/&lt;token&gt;</code>
                        </p>
                    </div>
                </div>

                <!-- Cụm nút hành động bên phải -->
                <div class="flex items-center gap-2 flex-shrink-0">
                    <!-- Nút Gửi Tất Cả (Luôn hiển thị trên cả Điện thoại & Máy tính) -->
                    <form action="/campaign/send-all" method="POST" class="inline">
                        <button type="submit" class="inline-flex items-center gap-1.5 px-3 sm:px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 active:bg-blue-800 font-semibold text-xs sm:text-sm transition shadow-sm">
                            <span>🚀</span>
                            <span>Gửi Tất Cả</span>
                        </button>
                    </form>

                    <!-- Các nút phụ chỉ hiện trên màn hình Máy tính (Desktop >= lg) -->
                    <div class="hidden lg:flex items-center gap-2">
                        <button type="button" onclick="toggleDrawer(true)" class="inline-flex items-center gap-1.5 px-3 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 font-semibold text-xs sm:text-sm border border-gray-300 transition">
                            <span>⚙️</span>
                            <span>Cài Đặt</span>
                        </button>

                        <form action="/db/clear-clicks" method="POST" class="inline" onsubmit="return confirm('Xóa lịch sử Click và đặt lại trạng thái tất cả User về AN TOÀN?');">
                            <button type="submit" class="px-3 py-2 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 font-semibold text-xs sm:text-sm transition shadow-sm">
                                🧹 Reset Click
                            </button>
                        </form>

                        <form action="/db/clear-all" method="POST" class="inline" onsubmit="return confirm('CẢNH BÁO: Bạn có chắc chắn muốn XÓA SẠCH toàn bộ User và Lịch sử Click?');">
                            <button type="submit" class="px-3 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 font-semibold text-xs sm:text-sm transition shadow-sm">
                                🔥 Clear DB
                            </button>
                        </form>

                        <a href="/logout" class="px-3 py-2 bg-gray-800 text-white rounded-lg hover:bg-gray-900 font-semibold text-xs sm:text-sm transition shadow-sm">
                            🔒 Thoát
                        </a>
                    </div>

                    <!-- Nút Icon Menu (Hamburger / Gear) cho Điện thoại & Tablet (< lg) -->
                    <button type="button" onclick="toggleDrawer(true)"
                        class="lg:hidden inline-flex items-center justify-center p-2 rounded-lg text-gray-700 bg-gray-100 hover:bg-gray-200 border border-gray-300 focus:outline-none"
                        aria-label="Mở menu cài đặt">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>
                        </svg>
                    </button>
                </div>
            </div>
        </header>

        <!-- Menu Trượt (Drawer / Modal) chứa Cài đặt Webhook, Đổi mật khẩu & Xóa DB (Ẩn mặc định, mở khi bấm Icon Menu) -->
        <div id="settingsDrawer" class="fixed inset-0 z-50 hidden">
            <!-- Lớp nền mờ -->
            <div class="fixed inset-0 drawer-backdrop transition-opacity" onclick="toggleDrawer(false)"></div>

            <!-- Khung nội dung Menu bên phải -->
            <div class="fixed inset-y-0 right-0 max-w-full flex pl-10">
                <div class="w-screen max-w-md bg-white shadow-2xl flex flex-col justify-between overflow-y-auto">
                    <div>
                        <!-- Header của Menu -->
                        <div class="p-4 sm:p-5 bg-gray-900 text-white flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <span class="text-lg">⚙️</span>
                                <h2 class="text-base font-bold">Menu Cài Đặt &amp; Quản Trị</h2>
                            </div>
                            <button type="button" onclick="toggleDrawer(false)" class="p-1.5 rounded-lg text-gray-300 hover:text-white hover:bg-gray-800">
                                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                                </svg>
                            </button>
                        </div>

                        <div class="p-4 sm:p-5 space-y-6">
                            <!-- 1. Cấu hình HTTPS Gmail Webhook -->
                            <div class="bg-blue-50 p-4 rounded-xl border border-blue-200">
                                <div class="flex items-center justify-between mb-2">
                                    <h3 class="text-xs font-bold text-blue-900 uppercase">⚡ Gửi Mail HTTPS (Webhook)</h3>
                                    <span class="text-xs font-semibold px-2 py-0.5 rounded-full {% if saved_webhook %}bg-green-100 text-green-800{% else %}bg-yellow-100 text-yellow-800{% endif %}">
                                        {% if saved_webhook %}Đã bật{% else %}Chưa bật{% endif %}
                                    </span>
                                </div>
                                <p class="text-xs text-blue-700 mb-3">
                                    Link Google Apps Script giúp gửi mail HTML &amp; Hyperlink từ Render:
                                </p>
                                <form action="/settings/webhook" method="POST" class="space-y-2">
                                    <input type="url" name="webhook_url" value="{{ saved_webhook }}"
                                        placeholder="https://script.google.com/macros/s/.../exec"
                                        class="w-full px-3 py-2 border border-blue-300 rounded-lg text-xs bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                                    <button type="submit" class="w-full py-2 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 text-xs transition shadow-sm">
                                        💾 Lưu Webhook URL
                                    </button>
                                </form>
                            </div>

                            <!-- 2. Đổi mật khẩu Admin -->
                            <div class="bg-gray-50 p-4 rounded-xl border border-gray-200">
                                <h3 class="text-xs font-bold text-gray-800 uppercase mb-1">🔑 Đổi Mật Khẩu Admin</h3>
                                <p class="text-xs text-gray-500 mb-3">Mật khẩu bảo vệ trang Quản trị (Mặc định: <code>admin123</code>)</p>
                                <form action="/settings/password" method="POST" class="flex gap-2">
                                    <input type="password" name="new_password" required placeholder="Nhập mật khẩu mới..."
                                        class="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-xs bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                                    <button type="submit" class="px-4 py-2 bg-gray-800 text-white font-semibold rounded-lg hover:bg-gray-900 text-xs transition whitespace-nowrap">
                                        Cập Nhật
                                    </button>
                                </form>
                            </div>

                            <!-- 3. Quản lý & Làm sạch Database -->
                            <div class="space-y-2.5 pt-2 border-t border-gray-200">
                                <h3 class="text-xs font-bold text-gray-500 uppercase">🗄️ Công Cụ Dữ Liệu (Database)</h3>

                                <form action="/db/clear-clicks" method="POST" onsubmit="return confirm('Bạn muốn xóa lịch sử Click và đặt lại trạng thái tất cả User về AN TOÀN?');">
                                    <button type="submit" class="w-full py-2.5 px-4 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 font-semibold text-xs flex items-center justify-center gap-2 shadow-sm transition">
                                        <span>🧹</span>
                                        <span>Reset Lịch Sử Click (Giữ lại User)</span>
                                    </button>
                                </form>

                                <form action="/db/clear-all" method="POST" onsubmit="return confirm('CẢNH BÁO: Bạn có chắc chắn muốn XÓA SẠCH toàn bộ User và Lịch sử Click trong Database?');">
                                    <button type="submit" class="w-full py-2.5 px-4 bg-red-600 text-white rounded-lg hover:bg-red-700 font-semibold text-xs flex items-center justify-center gap-2 shadow-sm transition">
                                        <span>🔥</span>
                                        <span>Xóa Trắng Toàn Bộ Database</span>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>

                    <!-- Footer của Menu: Nút Đăng Xuất -->
                    <div class="p-4 border-t border-gray-200 bg-gray-50">
                        <a href="/logout" class="w-full py-2.5 px-4 bg-gray-800 text-white rounded-lg hover:bg-gray-900 font-semibold text-xs flex items-center justify-center gap-2 shadow transition">
                            <span>🔒</span>
                            <span>Đăng Xuất Khỏi Admin</span>
                        </a>
                    </div>
                </div>
            </div>
        </div>

        <!-- Nội dung chính -->
        <main class="max-w-7xl mx-auto px-3 sm:px-6 lg:px-8 pt-4 sm:pt-6 space-y-4 sm:space-y-6">

            <!-- Thông báo trạng thái (Alert) -->
            {% if msg %}
            <div class="p-3.5 sm:p-4 rounded-xl border {% if status == 'error' %}bg-red-50 border-red-300 text-red-800{% else %}bg-green-50 border-green-300 text-green-800{% endif %} flex justify-between items-start sm:items-center gap-3 shadow-sm">
                <div class="text-xs sm:text-sm font-medium leading-relaxed">
                    {% if status == 'error' %}⚠️ {% else %}✅ {% endif %}{{ msg }}
                </div>
                <a href="/dashboard" class="text-xs font-bold underline flex-shrink-0">Đóng</a>
            </div>
            {% endif %}

            <!-- Thống kê tổng quan: Lưới 2x2 trên Điện thoại, 4 cột trên Máy tính -->
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
                <div class="bg-white p-3.5 sm:p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs font-semibold text-gray-500 uppercase truncate">Tổng User</p>
                    <p class="text-2xl sm:text-3xl font-extrabold text-gray-900 mt-1">{{ total_users }}</p>
                </div>
                <div class="bg-white p-3.5 sm:p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs font-semibold text-gray-500 uppercase truncate">Đã Sập Bẫy</p>
                    <p class="text-2xl sm:text-3xl font-extrabold text-red-600 mt-1">{{ clicked_users }}</p>
                </div>
                <div class="bg-white p-3.5 sm:p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs font-semibold text-gray-500 uppercase truncate">Tỷ Lệ Click</p>
                    <p class="text-2xl sm:text-3xl font-extrabold text-blue-600 mt-1">{{ '{:.1f}'.format(click_rate) }}%</p>
                </div>
                <div class="bg-white p-3.5 sm:p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs font-semibold text-gray-500 uppercase truncate">Lượt Click</p>
                    <p class="text-2xl sm:text-3xl font-extrabold text-purple-600 mt-1">{{ click_logs|length }}</p>
                </div>
            </div>

            <!-- Form thêm User trực tiếp vào Database -->
            <div class="bg-white p-4 sm:p-6 rounded-xl shadow-sm border border-gray-200">
                <h2 class="text-sm sm:text-base font-bold text-gray-800 mb-3">➕ Thêm User Mục Tiêu Mới</h2>
                <form action="/users/add" method="POST" class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 items-end">
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Họ và Tên *</label>
                        <input type="text" name="name" required placeholder="VD: Nguyễn Văn A"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Địa chỉ Email *</label>
                        <input type="email" name="email" required placeholder="VD: nguyenvana@gmail.com"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 mb-1">Phòng Ban</label>
                        <input type="text" name="department" placeholder="VD: CNTT / Kế Toán"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <button type="submit" class="w-full py-2.5 sm:py-2 px-4 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 active:bg-green-800 text-sm transition shadow-sm">
                            ➕ Lưu Vào DB
                        </button>
                    </div>
                </form>
            </div>

            <!-- BẢNG 1: DANH SÁCH MỤC TIÊU (Tự động chuyển đổi Thẻ trên Mobile & Bảng trên Desktop) -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div class="px-4 py-3.5 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                    <span class="font-bold text-gray-800 text-sm sm:text-base">📋 Danh Sách Mục Tiêu (<code>users</code>)</span>
                    <span class="text-xs font-medium text-gray-500 bg-white px-2.5 py-0.5 rounded-full border border-gray-200">{{ total_users }} user</span>
                </div>

                {% if user_list %}
                    <!-- Giao diện Thẻ (Card View) dành cho Điện thoại (Mobile < md) -->
                    <div class="md:hidden divide-y divide-gray-200">
                        {% for u in user_list %}
                        <div class="p-4 space-y-3">
                            <div class="flex items-start justify-between gap-2">
                                <div class="min-w-0">
                                    <div class="flex items-center gap-1.5">
                                        <span class="text-xs font-mono text-gray-400">#{{ u.id }}</span>
                                        <h3 class="font-bold text-gray-900 text-sm truncate">{{ u.name }}</h3>
                                    </div>
                                    <p class="text-xs text-gray-600 truncate mt-0.5">{{ u.email }}</p>
                                    <span class="inline-block mt-1 text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">
                                        🏢 {{ u.department }}
                                    </span>
                                </div>
                                <div class="flex-shrink-0">
                                    {% if u.clicked %}
                                        <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold bg-red-100 text-red-800">
                                            ⚠️ ĐÃ CLICK
                                        </span>
                                    {% else %}
                                        <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-bold bg-green-100 text-green-800">
                                            🛡️ AN TOÀN
                                        </span>
                                    {% endif %}
                                </div>
                            </div>

                            <div class="text-xs text-gray-500 bg-gray-50 p-2.5 rounded-lg grid grid-cols-2 gap-2">
                                <div>
                                    <span class="text-gray-400 block">Gửi mail lúc:</span>
                                    <span class="font-medium text-gray-700">{{ u.last_sent_at }}</span>
                                </div>
                                <div>
                                    <span class="text-gray-400 block">IP / Lúc click:</span>
                                    <span class="font-mono text-gray-700">{{ u.ip }}</span>
                                    {% if u.timestamp != 'N/A' %}
                                    <span class="block text-red-600">{{ u.timestamp }}</span>
                                    {% endif %}
                                </div>
                            </div>

                            <!-- Hàng nút thao tác tối ưu cảm ứng trên Điện thoại -->
                            <div class="grid grid-cols-3 gap-2 pt-1">
                                <form action="/users/send/{{ u.id }}" method="POST" class="w-full">
                                    <button type="submit" class="w-full py-2 px-2 bg-blue-50 hover:bg-blue-100 active:bg-blue-200 text-blue-700 border border-blue-200 rounded-lg text-xs font-semibold flex items-center justify-center gap-1">
                                        <span>📨</span>
                                        <span>Gửi Mail</span>
                                    </button>
                                </form>

                                <button type="button"
                                    onclick="copyLink('{{ base_url }}/{{ tracking_path }}/{{ u.token }}')"
                                    class="w-full py-2 px-2 bg-gray-50 hover:bg-gray-100 active:bg-gray-200 text-gray-700 border border-gray-300 rounded-lg text-xs font-semibold flex items-center justify-center gap-1">
                                    <span>📋</span>
                                    <span>Copy Link</span>
                                </button>

                                <form action="/users/delete/{{ u.id }}" method="POST" class="w-full" onsubmit="return confirm('Xóa user {{ u.email }}?');">
                                    <button type="submit" class="w-full py-2 px-2 bg-red-50 hover:bg-red-100 active:bg-red-200 text-red-700 border border-red-200 rounded-lg text-xs font-semibold flex items-center justify-center gap-1">
                                        <span>🗑️</span>
                                        <span>Xóa</span>
                                    </button>
                                </form>
                            </div>
                        </div>
                        {% endfor %}
                    </div>

                    <!-- Giao diện Bảng (Table View) dành cho Máy tính (Desktop >= md) -->
                    <div class="hidden md:block overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200 text-sm">
                            <thead class="bg-gray-100 text-gray-600 text-xs uppercase font-semibold">
                                <tr>
                                    <th class="py-3 px-4 text-left">ID</th>
                                    <th class="py-3 px-4 text-left">Họ Tên &amp; Email</th>
                                    <th class="py-3 px-4 text-left">Phòng Ban</th>
                                    <th class="py-3 px-4 text-left">Trạng Thái</th>
                                    <th class="py-3 px-4 text-left">IP &amp; Thời Gian Click</th>
                                    <th class="py-3 px-4 text-left">Link Rút Gọn</th>
                                    <th class="py-3 px-4 text-right">Thao Tác</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100">
                                {% for u in user_list %}
                                <tr class="hover:bg-gray-50 transition">
                                    <td class="py-3 px-4 text-gray-500 font-mono text-xs">#{{ u.id }}</td>
                                    <td class="py-3 px-4">
                                        <div class="font-semibold text-gray-900">{{ u.name }}</div>
                                        <div class="text-xs text-gray-500">{{ u.email }}</div>
                                        <div class="text-xs text-gray-400">Gửi lúc: {{ u.last_sent_at }}</div>
                                    </td>
                                    <td class="py-3 px-4 text-gray-700">{{ u.department }}</td>
                                    <td class="py-3 px-4">
                                        {% if u.clicked %}
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-100 text-red-800">
                                                ⚠️ ĐÃ CLICK
                                            </span>
                                        {% else %}
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-800">
                                                🛡️ AN TOÀN
                                            </span>
                                        {% endif %}
                                    </td>
                                    <td class="py-3 px-4 text-xs">
                                        <div class="font-mono text-gray-700">IP: {{ u.ip }}</div>
                                        <div class="text-gray-500">Lúc: {{ u.timestamp }}</div>
                                    </td>
                                    <td class="py-3 px-4">
                                        <div class="flex items-center gap-2">
                                            <a href="{{ base_url }}/{{ tracking_path }}/{{ u.token }}" target="_blank"
                                                class="text-blue-600 hover:underline font-mono text-xs"
                                                title="{{ base_url }}/{{ tracking_path }}/{{ u.token }}">
                                                /{{ tracking_path }}/{{ u.token }}
                                            </a>
                                            <button type="button"
                                                onclick="copyLink('{{ base_url }}/{{ tracking_path }}/{{ u.token }}')"
                                                class="px-2 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded text-xs border border-gray-300">
                                                📋 Copy
                                            </button>
                                        </div>
                                    </td>
                                    <td class="py-3 px-4 text-right whitespace-nowrap space-x-1">
                                        <form action="/users/send/{{ u.id }}" method="POST" class="inline">
                                            <button type="submit" class="px-2.5 py-1.5 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded-lg text-xs font-semibold">
                                                📨 Gửi Mail
                                            </button>
                                        </form>
                                        <form action="/users/delete/{{ u.id }}" method="POST" class="inline" onsubmit="return confirm('Xóa user {{ u.email }}?');">
                                            <button type="submit" class="px-2.5 py-1.5 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded-lg text-xs font-semibold">
                                                🗑️ Xóa
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="py-8 px-4 text-center text-gray-500 text-sm">
                        Chưa có User nào trong Database. Hãy nhập thông tin ở khung <strong>Thêm User Mục Tiêu Mới</strong> bên trên!
                    </div>
                {% endif %}
            </div>

            <!-- BẢNG 2: NHẬT KÝ LƯỢT CLICK CHI TIẾT -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div class="px-4 py-3.5 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                    <span class="font-bold text-gray-800 text-sm sm:text-base">🕒 Nhật Ký Lượt Click (<code>click_logs</code>)</span>
                    <span class="text-xs font-medium text-gray-500 bg-white px-2.5 py-0.5 rounded-full border border-gray-200">{{ click_logs|length }} lượt</span>
                </div>

                {% if click_logs %}
                    <!-- Giao diện Thẻ trên Điện thoại -->
                    <div class="md:hidden divide-y divide-gray-200">
                        {% for lg in click_logs %}
                        <div class="p-4 space-y-1.5">
                            <div class="flex items-center justify-between">
                                <span class="font-bold text-gray-900 text-sm">{{ lg.name }}</span>
                                <span class="text-xs font-semibold text-red-600">{{ lg.clicked_at }}</span>
                            </div>
                            <div class="flex items-center justify-between text-xs text-gray-500">
                                <span>{{ lg.email }} ({{ lg.department }})</span>
                                <span class="font-mono text-gray-700">IP: {{ lg.ip }}</span>
                            </div>
                            <p class="text-xs text-gray-400 break-all pt-1">{{ lg.user_agent }}</p>
                        </div>
                        {% endfor %}
                    </div>

                    <!-- Giao diện Bảng trên Máy tính -->
                    <div class="hidden md:block overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200 text-sm">
                            <thead class="bg-gray-100 text-gray-600 text-xs uppercase font-semibold">
                                <tr>
                                    <th class="py-3 px-4 text-left">ID</th>
                                    <th class="py-3 px-4 text-left">Thời Gian Click</th>
                                    <th class="py-3 px-4 text-left">Nhân Viên</th>
                                    <th class="py-3 px-4 text-left">Phòng Ban</th>
                                    <th class="py-3 px-4 text-left">Địa Chỉ IP</th>
                                    <th class="py-3 px-4 text-left">Thiết Bị (User-Agent)</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-gray-100">
                                {% for lg in click_logs %}
                                <tr class="hover:bg-gray-50 transition">
                                    <td class="py-3 px-4 font-mono text-xs text-gray-500">#{{ lg.id }}</td>
                                    <td class="py-3 px-4 text-xs font-semibold text-red-600 whitespace-nowrap">{{ lg.clicked_at }}</td>
                                    <td class="py-3 px-4">
                                        <div class="font-medium text-gray-900">{{ lg.name }}</div>
                                        <div class="text-xs text-gray-500">{{ lg.email }}</div>
                                    </td>
                                    <td class="py-3 px-4 text-gray-700">{{ lg.department }}</td>
                                    <td class="py-3 px-4 font-mono text-xs text-gray-700">{{ lg.ip }}</td>
                                    <td class="py-3 px-4 text-xs text-gray-500 break-all max-w-md">{{ lg.user_agent }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                {% else %}
                    <div class="py-6 px-4 text-center text-gray-500 text-sm">
                        Chưa có lượt click nào được ghi nhận.
                    </div>
                {% endif %}
            </div>

        </main>

        <!-- Thông báo nổi (Toast) khi Copy Link -->
        <div id="copyToast" class="fixed bottom-5 left-1/2 transform -translate-x-1/2 z-50 hidden bg-gray-900 text-white text-xs sm:text-sm font-semibold px-4 py-2.5 rounded-full shadow-lg">
            ✅ Đã sao chép liên kết rút gọn!
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
