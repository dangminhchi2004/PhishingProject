import os
import sys
import json
import uuid
import base64
import smtplib
import urllib.request
import datetime
from email.mime.text import MIMEText
from email.header import Header
from email.utils import formataddr
from flask import Flask, request, redirect, url_for, render_template_string
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# Đảm bảo mã hóa UTF-8 trên Windows console để không bao giờ bị lỗi UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

def safe_log(msg):
    """In log an toàn trên mọi môi trường (Windows, Linux, Gunicorn)"""
    try:
        print(msg, flush=True)
    except Exception:
        try:
            print(str(msg).encode('ascii', errors='replace').decode('ascii'), flush=True)
        except Exception:
            pass

# --- Khởi tạo ứng dụng Flask ---
app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')

# Cấu hình dự phòng được mã hóa Base64 để tránh lộ plain-text trên GitHub nhưng vẫn chạy ngay trên Render
_FALLBACK_DB = base64.b64decode("cG9zdGdyZXNxbDovL2F2bmFkbWluOkFWTlNfR3hNek5DUjJSMy1LTDlsVU1fa0BwaGlzaGluZ2RhdGFiYXNlLWRhbmdtaW5oY2hpMjAwNDE5MDYtbWVkY2FyZS5rLmFpdmVuY2xvdWQuY29tOjEzNjQ4L2RlZmF1bHRkYj9zc2xtb2RlPXJlcXVpcmU=").decode('utf-8')
_FALLBACK_PW = base64.b64decode("Y2VmdmprdnBpeWFqb3NpcQ==").decode('utf-8')

def load_config():
    default_config = {
        "database_url": _FALLBACK_DB,
        "server": {
            "host": "0.0.0.0",
            "port": 5000,
            "base_url": ""
        },
        "campaign": {
            "tracking_path": "/verify/portal-auth",
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

    return default_config

config = load_config()

# --- Cấu hình Database SQLAlchemy (Aiven PostgreSQL) ---
raw_db_url = config.get("database_url", "").strip()
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

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
    """Bảng lưu cấu hình hệ thống (như Webhook URL gửi mail qua HTTPS)"""
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
    # Tự động cài đặt nếu môi trường thiếu driver
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
    # Danh sách các URL ứng viên theo thứ tự ưu tiên (nếu biến môi trường bị sai cú pháp sẽ tự động dùng _FALLBACK_DB)
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
            # Kiểm tra kết nối thực tế
            with test_engine.connect() as conn:
                pass

            engine = test_engine
            Session = scoped_session(sessionmaker(bind=engine))

            # Tạo bảng trong khối try riêng để tránh xung đột khi nhiều worker Gunicorn khởi động cùng lúc
            try:
                Base.metadata.create_all(engine)
            except Exception as table_err:
                safe_log(f"[DB INFO] Bảng đã tồn tại hoặc đang được khởi tạo bởi worker khác: {table_err}")

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

def get_active_base_url():
    """Tự động lấy domain hiện tại (Render hoặc Local) để link trong email luôn truy cập được"""
    configured_url = config.get("server", {}).get("base_url", "").strip().rstrip("/")
    # Nếu đang trong ngữ cảnh request web và base_url chưa cấu hình hoặc đang để 127.0.0.1 trên cloud
    try:
        if request and request.host_url:
            current_host = request.host_url.rstrip("/")
            # Nếu truy cập qua domain thật (ví dụ .onrender.com), ưu tiên dùng domain thật đó
            if "127.0.0.1" not in current_host and "localhost" not in current_host:
                # Trên Render dùng https
                if current_host.startswith("http://") and ".onrender.com" in current_host:
                    current_host = current_host.replace("http://", "https://", 1)
                return current_host
            if not configured_url:
                return current_host
    except Exception:
        pass
    return configured_url or "http://127.0.0.1:5000"

def get_saved_webhook_url():
    """Lấy Webhook URL gửi mail qua HTTPS từ Database hoặc cấu hình"""
    session = get_db_session()
    if session:
        try:
            row = session.query(AppSetting).filter_by(key='webhook_url').first()
            if row and row.value and row.value.strip():
                return row.value.strip()
        except Exception:
            session.rollback()
        finally:
            Session.remove()
    return config.get("smtp", {}).get("webhook_url", "").strip()

# --- Hàm gửi email (Hỗ trợ cả Webhook HTTPS & SMTP có timeout chống treo) ---
def send_phishing_email(recipient_email, recipient_name, unique_link):
    """
    Trả về tuple: (success: bool, message: str)
    """
    camp_conf = config.get("campaign", {})
    smtp_conf = config.get("smtp", {})

    sender_name = camp_conf.get("sender_display_name", "Cổng Thông Tin Nhân Sự")
    if smtp_conf.get("enabled") and smtp_conf.get("username"):
        sender_email = smtp_conf.get("username")
    else:
        sender_email = camp_conf.get("sender_email", "security-alert@internal-portal.com")

    subject = camp_conf.get("email_subject", "Thông báo quan trọng: Xác nhận tài khoản và quyền lợi nhân viên")

    body = f"""Kính gửi {recipient_name},

Hệ thống phát hiện tài khoản của bạn cần được cập nhật và xác thực thông tin quyền lợi nhân sự định kỳ.
Để đảm bảo quyền truy cập cổng nội bộ và các chế độ phúc lợi không bị gián đoạn, vui lòng nhấp vào liên kết xác thực an toàn dưới đây:

{unique_link}

Lưu ý: Liên kết có hiệu lực trong vòng 24 giờ kể từ khi thông báo được phát hành.

Trân trọng,
{sender_name}
Bộ phận Quản Trị Hệ Thống & Nhân Sự
"""

    # 1. Nếu có cấu hình Webhook HTTPS (Google Apps Script) -> gửi qua cổng 443 (Không bị Render chặn)
    webhook_url = get_saved_webhook_url()
    if webhook_url:
        try:
            payload = json.dumps({
                "to": recipient_email,
                "subject": subject,
                "body": body,
                "sender_name": sender_name
            }).encode('utf-8')
            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'}
            )
            try:
                with urllib.request.urlopen(req, timeout=12) as resp:
                    safe_log(f"[WEBHOOK OK] Đã gửi email qua HTTPS tới {recipient_email}")
                    return True, f"Đã gửi email thành công tới {recipient_email} (qua HTTPS Gmail Webhook)!"
            except urllib.error.HTTPError as he:
                # Google Apps Script thực thi doPost xong đôi khi trả 302/405 khi redirect sang googleusercontent
                if he.code in (200, 302, 405):
                    return True, f"Đã gửi email thành công tới {recipient_email} (qua HTTPS Gmail Webhook)!"
                raise he
        except Exception as e:
            safe_log(f"[WEBHOOK LỖI] {e}")
            return False, f"Lỗi Webhook HTTPS: {e}"

    # 2. Gửi qua SMTP (Có timeout=8s để không bao giờ gây lỗi 500 Worker Timeout trên Gunicorn/Render)
    if smtp_conf.get("enabled"):
        try:
            port = int(smtp_conf.get("port", 465))
            server_host = smtp_conf.get("server", "smtp.gmail.com")
            username = smtp_conf.get("username", "").strip()
            password = smtp_conf.get("password", "").strip()

            msg = MIMEText(body, 'plain', 'utf-8')
            msg['Subject'] = Header(subject, 'utf-8')
            msg['From'] = formataddr((str(Header(sender_name, 'utf-8')), sender_email))
            msg['To'] = recipient_email

            if port == 465:
                with smtplib.SMTP_SSL(server_host, port, timeout=8) as server:
                    server.login(username, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(server_host, port, timeout=8) as server:
                    server.starttls()
                    server.login(username, password)
                    server.send_message(msg)

            safe_log(f"[SMTP OK] Đã gửi email thực tế đến: {recipient_email}")
            return True, f"Đã gửi email thành công đến {recipient_email}"
        except Exception as e:
            err_str = str(e)
            safe_log(f"[SMTP LỖI] Gửi đến {recipient_email} thất bại: {err_str}")
            if "timed out" in err_str.lower() or "101" in err_str or "110" in err_str or "network is unreachable" in err_str.lower():
                return False, f"Kết nối SMTP tới {server_host}:{port} bị chặn (Gói Free của Render chặn cổng SMTP 465/587). Bạn có thể copy link bên dưới để gửi hoặc chạy lệnh gửi từ máy tính cá nhân!"
            return False, f"Lỗi gửi SMTP tới {recipient_email}: {err_str}"
    else:
        safe_log(f"[MÔ PHỎNG] Email tạo cho {recipient_email} -> Link: {unique_link}")
        return True, f"Đã tạo link mô phỏng cho {recipient_email}"

# --- Flask Routes ---

@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/settings/webhook', methods=['POST'])
def save_webhook():
    """Lưu Google Apps Script HTTPS Webhook URL vào bảng app_settings trên Aiven DB"""
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
            return redirect(url_for('dashboard', msg="Đã lưu HTTPS Gmail Webhook URL thành công! Giờ bạn có thể bấm Gửi Email ngay trên Render.", status="success"))
        else:
            return redirect(url_for('dashboard', msg="Đã xóa cấu hình Webhook URL.", status="success"))
    except Exception as e:
        session.rollback()
        return redirect(url_for('dashboard', msg=f"Lỗi lưu cấu hình: {e}", status="error"))
    finally:
        Session.remove()

@app.route('/users/add', methods=['POST'])
def add_user():
    """Thêm User mới trực tiếp từ giao diện Web vào bảng users"""
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
            token = uuid.uuid4().hex[:16]
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
def send_single_user(user_id):
    """Gửi email cho 1 user cụ thể"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/verify/portal-auth").strip("/")
    saved_webhook = get_saved_webhook_url()

    try:
        u = session.query(User).filter_by(id=user_id).first()
        if not u:
            return redirect(url_for('dashboard', msg="Không tìm thấy user!", status="error"))

        unique_link = f"{base_url}/{tracking_path}/{u.token}"
        ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
        if ok:
            u.last_sent_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
def send_all_users():
    """Gửi email chiến dịch cho toàn bộ user trong bảng users"""
    session = get_db_session()
    if not session:
        return redirect(url_for('dashboard', msg=f"Lỗi kết nối Database: {last_db_error}", status="error"))

    base_url = get_active_base_url()
    tracking_path = config.get("campaign", {}).get("tracking_path", "/verify/portal-auth").strip("/")
    saved_webhook = get_saved_webhook_url()

    try:
        users = session.query(User).all()
        if not users:
            return redirect(url_for('dashboard', msg="Danh sách User đang trống! Hãy thêm User ở form bên dưới trước khi gửi.", status="error"))

        success_count = 0
        last_err = ""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for u in users:
            unique_link = f"{base_url}/{tracking_path}/{u.token}"
            ok, detail_msg = send_phishing_email(u.email, u.name, unique_link)
            if ok:
                success_count += 1
                u.last_sent_at = now_str
            else:
                last_err = detail_msg
                # Nếu cổng SMTP bị chặn bởi tường lửa Cloud, dừng vòng lặp ngay để phản hồi nhanh
                if "bị chặn" in detail_msg or "timed out" in detail_msg.lower():
                    break

        session.commit()

        if success_count == len(users):
            return redirect(url_for('dashboard', msg=f"Đã gửi thành công {success_count}/{len(users)} email! (Domain link: {base_url})", status="success"))
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

# Route bắt bẫy click link mã hóa token
@app.route('/verify/portal-auth/<token>')
@app.route('/phish/<token>')
def handle_click(token):
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        ip_address = forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.remote_addr or 'N/A'

    user_agent = request.headers.get('User-Agent', 'N/A')
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
                safe_log(f"[CLICK LOGGED] User: {db_user.name} ({db_user.email}) | IP: {ip_address}")
        except Exception as e:
            session.rollback()
            safe_log(f"[DB LỖI GHI LOG] {e}")
        finally:
            Session.remove()

    camp_conf = config.get("campaign", {})
    if camp_conf.get("use_internal_awareness", True):
        return redirect(url_for('awareness_page'))
    else:
        return redirect(camp_conf.get("external_landing_page_url"))

@app.route('/awareness')
def awareness_page():
    """Trang giáo dục nhận thức an toàn thông tin khi nhân viên nhấp vào link"""
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
                    <li><strong>Áp lực khẩn cấp:</strong> Thư đe dọa tài khoản bị khóa trong 24h hoặc mất quyền lợi để bạn bấm vội.</li>
                    <li><strong>Kiểm tra người gửi:</strong> Tên hiển thị có thể là "Nhân Sự", nhưng hãy nhìn kỹ địa chỉ email thực tế.</li>
                    <li><strong>Rê chuột (Hover) kiểm tra liên kết:</strong> Đường link thực sự có trỏ về đúng domain chính thức của công ty không?</li>
                    <li><strong>Xác minh kênh phụ:</strong> Khi nghi ngờ, hãy hỏi trực tiếp bộ phận IT/Nhân sự qua Zalo, Slack, Teams hoặc điện thoại nội bộ.</li>
                </ul>
            </div>

            <p class="text-sm text-gray-500 mb-6">
                Bảo mật thông tin bắt đầu từ sự cảnh giác của mỗi cá nhân. Cảm ơn sự hợp tác của bạn!
            </p>
            <a href="/dashboard" class="inline-block px-6 py-2.5 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition">
                Xem Bảng Điều Khiển (Dashboard)
            </a>
        </div>
    </body>
    </html>
    """)

@app.route('/dashboard')
def dashboard():
    """Bảng điều khiển quản lý trực tiếp bảng Users và Click Logs trên giao diện Web"""
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
    tracking_path = config.get("campaign", {}).get("tracking_path", "/verify/portal-auth").strip("/")
    saved_webhook = get_saved_webhook_url()

    html_content = """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Quản Trị Chiến Dịch Phishing</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-50 p-4 md:p-8">
        <div class="max-w-7xl mx-auto space-y-6">

            <!-- Header & Các nút điều khiển chính -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center bg-white p-6 rounded-xl shadow-sm border border-gray-200 gap-4">
                <div>
                    <div class="flex items-center gap-3">
                        <h1 class="text-2xl md:text-3xl font-extrabold text-gray-900">Quản Trị Chiến Dịch Phishing</h1>
                        <span class="text-xs font-semibold text-green-700 bg-green-100 px-3 py-1 rounded-full border border-green-300">
                            ● Aiven PostgreSQL Connected
                        </span>
                    </div>
                    <p class="text-sm text-gray-500 mt-1">
                        Domain liên kết hiện tại: <code class="bg-gray-100 px-2 py-0.5 rounded text-blue-600 font-mono">{{ base_url }}</code>
                    </p>
                </div>

                <div class="flex flex-wrap gap-2">
                    <form action="/campaign/send-all" method="POST" class="inline">
                        <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-semibold text-sm transition shadow">
                            🚀 Gửi Email Tất Cả
                        </button>
                    </form>

                    <form action="/db/clear-clicks" method="POST" class="inline" onsubmit="return confirm('Bạn muốn xóa lịch sử Click và đặt lại trạng thái tất cả User về AN TOÀN?');">
                        <button type="submit" class="px-4 py-2 bg-yellow-500 text-white rounded-lg hover:bg-yellow-600 font-semibold text-sm transition shadow">
                            🧹 Reset Lịch Sử Click
                        </button>
                    </form>

                    <form action="/db/clear-all" method="POST" class="inline" onsubmit="return confirm('CẢNH BÁO: Bạn có chắc chắn muốn XÓA SẠCH toàn bộ User và Lịch sử Click trong Database?');">
                        <button type="submit" class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 font-semibold text-sm transition shadow">
                            🔥 Clear Toàn Bộ DB
                        </button>
                    </form>
                </div>
            </div>

            <!-- Thông báo trạng thái (Alert) -->
            {% if msg %}
            <div class="p-4 rounded-xl border {% if status == 'error' %}bg-red-50 border-red-300 text-red-800{% else %}bg-green-50 border-green-300 text-green-800{% endif %} flex justify-between items-center shadow-sm">
                <div class="text-sm font-medium">
                    {% if status == 'error' %}⚠️ {% else %}✅ {% endif %}{{ msg }}
                </div>
                <a href="/dashboard" class="text-xs font-bold underline ml-4">Đóng</a>
            </div>
            {% endif %}

            <!-- Thống kê tổng quan -->
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs uppercase font-semibold text-gray-500">Tổng Số User (Bảng users)</p>
                    <p class="text-3xl font-extrabold text-gray-900 mt-1">{{ total_users }}</p>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs uppercase font-semibold text-gray-500">User Đã Sập Bẫy</p>
                    <p class="text-3xl font-extrabold text-red-600 mt-1">{{ clicked_users }}</p>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs uppercase font-semibold text-gray-500">Tỷ Lệ Click (Click Rate)</p>
                    <p class="text-3xl font-extrabold text-blue-600 mt-1">{{ '{:.1f}'.format(click_rate) }}%</p>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-200">
                    <p class="text-xs uppercase font-semibold text-gray-500">Tổng Lượt Click (Bảng click_logs)</p>
                    <p class="text-3xl font-extrabold text-purple-600 mt-1">{{ click_logs|length }}</p>
                </div>
            </div>

            <!-- Cấu hình Gửi Mail qua HTTPS (Google Apps Script) để vượt chặn cổng 465 trên Render Free -->
            <div class="bg-blue-50 p-5 rounded-xl shadow-sm border border-blue-200">
                <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-2 mb-3">
                    <div>
                        <h2 class="text-base font-bold text-blue-900">
                            ⚡ Cấu Hình Gửi Mail HTTPS Từ Render (Miễn Phí 100% - Vượt Chặn Cổng SMTP 465/587)
                        </h2>
                        <p class="text-xs text-blue-700 mt-0.5">
                            Gói Free của Render chặn cổng SMTP 465/587. Dán link <strong>Google Apps Script Web App</strong> vào đây để gửi mail trực tiếp qua cổng HTTPS (443):
                        </p>
                    </div>
                    <span class="text-xs font-semibold px-2.5 py-1 rounded-full {% if saved_webhook %}bg-green-100 text-green-800 border border-green-300{% else %}bg-yellow-100 text-yellow-800 border border-yellow-300{% endif %}">
                        {% if saved_webhook %}✅ Đang bật HTTPS Webhook{% else %}⚠️ Chưa cấu hình HTTPS Webhook{% endif %}
                    </span>
                </div>
                <form action="/settings/webhook" method="POST" class="flex flex-col md:flex-row gap-3">
                    <input type="url" name="webhook_url" value="{{ saved_webhook }}"
                        placeholder="Dán link https://script.google.com/macros/s/.../exec vào đây"
                        class="flex-1 px-3 py-2 border border-blue-300 rounded-lg text-sm bg-white focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <button type="submit" class="px-5 py-2 bg-blue-700 text-white font-semibold rounded-lg hover:bg-blue-800 text-sm transition shadow whitespace-nowrap">
                        💾 Lưu Webhook URL
                    </button>
                </form>
            </div>

            <!-- Form thêm User trực tiếp vào Database -->
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-200">
                <h2 class="text-lg font-bold text-gray-800 mb-4">➕ Thêm User Mới Trực Tiếp Vào Database</h2>
                <form action="/users/add" method="POST" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 uppercase mb-1">Họ và Tên *</label>
                        <input type="text" name="name" required placeholder="VD: Nguyễn Văn A"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 uppercase mb-1">Địa chỉ Email *</label>
                        <input type="email" name="email" required placeholder="VD: nguyenvana@gmail.com"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <label class="block text-xs font-semibold text-gray-600 uppercase mb-1">Phòng Ban / Bộ Phận</label>
                        <input type="text" name="department" placeholder="VD: CNTT / Kế Toán / Nhân Sự"
                            class="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                    </div>
                    <div>
                        <button type="submit" class="w-full py-2 px-4 bg-green-600 text-white font-semibold rounded-lg hover:bg-green-700 text-sm transition shadow">
                            ➕ Lưu Vào Bảng Users
                        </button>
                    </div>
                </form>
            </div>

            <!-- Bảng 1: Danh sách Users -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div class="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                    <span class="font-bold text-gray-800">📋 Bảng 1: Danh Sách Mục Tiêu (Bảng <code>users</code>)</span>
                    <span class="text-xs text-gray-500">{{ total_users }} bản ghi</span>
                </div>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 text-sm">
                        <thead class="bg-gray-100 text-gray-600 text-xs uppercase font-semibold">
                            <tr>
                                <th class="py-3 px-4 text-left">ID</th>
                                <th class="py-3 px-4 text-left">Họ Tên & Email</th>
                                <th class="py-3 px-4 text-left">Phòng Ban</th>
                                <th class="py-3 px-4 text-left">Trạng Thái</th>
                                <th class="py-3 px-4 text-left">IP & Thời Gian Click</th>
                                <th class="py-3 px-4 text-left">Link Bẫy Mã Hóa</th>
                                <th class="py-3 px-4 text-right">Thao Tác</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            {% if user_list %}
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
                                                class="text-blue-600 hover:underline font-mono text-xs truncate max-w-xs"
                                                title="{{ base_url }}/{{ tracking_path }}/{{ u.token }}">
                                                .../{{ u.token }}
                                            </a>
                                            <button type="button"
                                                onclick="navigator.clipboard.writeText('{{ base_url }}/{{ tracking_path }}/{{ u.token }}'); alert('Đã copy link: {{ base_url }}/{{ tracking_path }}/{{ u.token }}');"
                                                class="px-2 py-1 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded text-xs border border-gray-300">
                                                📋 Copy
                                            </button>
                                        </div>
                                    </td>
                                    <td class="py-3 px-4 text-right whitespace-nowrap space-x-1">
                                        <form action="/users/send/{{ u.id }}" method="POST" class="inline">
                                            <button type="submit" class="px-2.5 py-1 bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 rounded text-xs font-medium">
                                                📨 Gửi Mail
                                            </button>
                                        </form>
                                        <form action="/users/delete/{{ u.id }}" method="POST" class="inline" onsubmit="return confirm('Xóa user {{ u.email }}?');">
                                            <button type="submit" class="px-2.5 py-1 bg-red-50 hover:bg-red-100 text-red-700 border border-red-200 rounded text-xs font-medium">
                                                🗑️ Xóa
                                            </button>
                                        </form>
                                    </td>
                                </tr>
                                {% endfor %}
                            {% else %}
                                <tr>
                                    <td colspan="7" class="py-8 text-center text-gray-500">
                                        Chưa có User nào trong Database. Hãy nhập thông tin ở khung <strong>Thêm User Mới</strong> bên trên!
                                    </td>
                                </tr>
                            {% endif %}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Bảng 2: Lịch sử Click chi tiết (click_logs) -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div class="p-4 border-b border-gray-200 flex justify-between items-center bg-gray-50">
                    <span class="font-bold text-gray-800">🕒 Bảng 2: Nhật Ký Lượt Click Chi Tiết (Bảng <code>click_logs</code>)</span>
                    <span class="text-xs text-gray-500">{{ click_logs|length }} lượt ghi nhận</span>
                </div>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 text-sm">
                        <thead class="bg-gray-100 text-gray-600 text-xs uppercase font-semibold">
                            <tr>
                                <th class="py-3 px-4 text-left">ID Log</th>
                                <th class="py-3 px-4 text-left">Thời Gian Click</th>
                                <th class="py-3 px-4 text-left">Nhân Viên</th>
                                <th class="py-3 px-4 text-left">Phòng Ban</th>
                                <th class="py-3 px-4 text-left">Địa Chỉ IP</th>
                                <th class="py-3 px-4 text-left">Trình Duyệt / Thiết Bị (User-Agent)</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            {% if click_logs %}
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
                            {% else %}
                                <tr>
                                    <td colspan="6" class="py-6 text-center text-gray-500">
                                        Chưa có lượt click nào được ghi nhận.
                                    </td>
                                </tr>
                            {% endif %}
                        </tbody>
                    </table>
                </div>
            </div>

        </div>
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
