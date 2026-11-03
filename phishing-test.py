import os
import sys
import json
import uuid
import smtplib
import datetime
from email.mime.text import MIMEText
from email.header import Header

# Đảm bảo mã hóa UTF-8 trên Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
from flask import Flask, request, redirect, url_for, render_template_string
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session

# --- Khởi tạo ứng dụng Flask ---
app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, 'config.json')
USERS_PATH = os.path.join(BASE_DIR, 'users.json')

# --- Hàm nạp cấu hình (Hỗ trợ biến môi trường & file JSON) ---
def load_config():
    default_config = {
        "database_url": "",
        "server": {
            "host": "0.0.0.0",
            "port": 5000,
            "base_url": "http://127.0.0.1:5000"
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
            "enabled": False,
            "server": "smtp.gmail.com",
            "port": 465,
            "username": "",
            "password": ""
        }
    }
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                default_config.update(loaded)
        except Exception as e:
            print(f"[!] Lỗi khi đọc config.json ({e}), dùng cấu hình mặc định.")

    # Ưu tiên biến môi trường khi triển khai trên Cloud (Render, Heroku, etc.)
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

    return default_config

def load_users():
    default_users = [
        {"email": "dangminhchi20041906@gmail.com", "name": "Đặng Minh Chí", "department": "CNTT"}
    ]
    if os.path.exists(USERS_PATH):
        try:
            with open(USERS_PATH, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Lỗi khi đọc users.json ({e}), dùng danh sách mặc định.")
    return default_users

config = load_config()

# --- Cấu hình Database SQLAlchemy (Aiven PostgreSQL) ---
raw_db_url = config.get("database_url", "")
# Chuẩn hóa tiền tố postgres:// thành postgresql:// cho tương thích SQLAlchemy 2.0
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

Base = declarative_base()

class CampaignUser(Base):
    __tablename__ = 'campaign_users'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), default='Nhân viên')
    department = Column(String(255), default='Chưa phân loại')
    token = Column(String(64), unique=True, nullable=False, index=True)
    clicked = Column(Boolean, default=False)
    ip_address = Column(String(100), default='N/A')
    user_agent = Column(Text, default='N/A')
    clicked_at = Column(String(100), default='N/A')

class ClickLog(Base):
    __tablename__ = 'click_logs'
    id = Column(Integer, primary_key=True)
    user_email = Column(String(255), nullable=False)
    token = Column(String(64), nullable=False)
    ip_address = Column(String(100))
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

engine = None
Session = None

def init_database():
    global engine, Session
    if raw_db_url:
        try:
            engine = create_engine(raw_db_url, pool_pre_ping=True, pool_recycle=300)
            Base.metadata.create_all(engine)
            Session = scoped_session(sessionmaker(bind=engine))
            print("[DB OK] Kết nối thành công Aiven PostgreSQL và đồng bộ bảng!")
        except Exception as e:
            print(f"[DB LỖI] Không thể kết nối Database ({e}), chuyển sang chế độ dự phòng.")
            engine = None
            Session = None

init_database()

# Dữ liệu fallback in-memory (phòng trường hợp DB gián đoạn)
memory_users = {}

def sync_campaign_users():
    """Đồng bộ danh sách người dùng từ users.json vào Aiven DB"""
    global config
    config = load_config()
    users_data = load_users()

    if Session:
        session = Session()
        try:
            for u in users_data:
                email = u.get("email")
                db_user = session.query(CampaignUser).filter_by(email=email).first()
                if not db_user:
                    token = uuid.uuid4().hex[:16]
                    new_user = CampaignUser(
                        email=email,
                        name=u.get("name", "Nhân viên"),
                        department=u.get("department", "Chưa phân loại"),
                        token=token,
                        clicked=False
                    )
                    session.add(new_user)
                else:
                    db_user.name = u.get("name", db_user.name)
                    db_user.department = u.get("department", db_user.department)
            session.commit()
            print(f"[DB SYNC] Đã đồng bộ {len(users_data)} người dùng vào PostgreSQL.")
        except Exception as e:
            session.rollback()
            print(f"[DB SYNC LỖI] {e}")
        finally:
            session.close()
    else:
        # Fallback In-memory
        for u in users_data:
            email = u.get("email")
            if email not in memory_users:
                memory_users[email] = {
                    'name': u.get("name", "Nhân viên"),
                    'department': u.get("department", "Chưa phân loại"),
                    'token': uuid.uuid4().hex[:16],
                    'clicked': False,
                    'ip': 'N/A',
                    'user_agent': 'N/A',
                    'timestamp': 'N/A'
                }

# Đồng bộ dữ liệu khi khởi động
sync_campaign_users()

# --- Hàm gửi email (Mô phỏng hoặc qua SMTP) ---
def send_phishing_email(recipient_email, recipient_name, unique_link):
    camp_conf = config.get("campaign", {})
    smtp_conf = config.get("smtp", {})

    sender_name = camp_conf.get("sender_display_name", "Phòng Nhân Sự")
    
    # Với Gmail SMTP, địa chỉ gửi cần là tài khoản đăng nhập để tránh bị chặn 553 / Spam
    if smtp_conf.get("enabled") and smtp_conf.get("username"):
        sender_email = smtp_conf.get("username")
    else:
        sender_email = camp_conf.get("sender_email", "hr-benefits@yourcompany.com")

    subject = camp_conf.get("email_subject", "Khẩn cấp: Xác thực thông tin tài khoản nhân viên")

    body = f"""Kính gửi {recipient_name},

Hệ thống phát hiện tài khoản của bạn cần được cập nhật và xác thực thông tin quyền lợi nhân sự định kỳ.
Để đảm bảo quyền truy cập cổng nội bộ và các chế độ phúc lợi không bị gián đoạn, vui lòng nhấp vào liên kết xác thực an toàn dưới đây:

{unique_link}

Lưu ý: Liên kết có hiệu lực trong vòng 24 giờ kể từ khi thông báo được phát hành.

Trân trọng,
{sender_name}
Bộ phận Quản Trị Hệ Thống & Nhân Sự
"""

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = f"{Header(sender_name, 'utf-8').encode()} <{sender_email}>"
    msg['To'] = recipient_email

    if smtp_conf.get("enabled"):
        try:
            port = int(smtp_conf.get("port", 465))
            server_host = smtp_conf.get("server", "smtp.gmail.com")
            username = smtp_conf.get("username", "")
            password = smtp_conf.get("password", "")

            if port == 465:
                with smtplib.SMTP_SSL(server_host, port) as server:
                    server.login(username, password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(server_host, port) as server:
                    server.starttls()
                    server.login(username, password)
                    server.send_message(msg)
            print(f"[SMTP OK] Đã gửi email thực tế đến: {recipient_email}")
        except Exception as e:
            print(f"[SMTP LỖI] Gửi đến {recipient_email} thất bại: {e}")
    else:
        print(f"\n--- [MÔ PHỎNG EMAIL] Gửi đến {recipient_email} ---")
        print(f"Từ: {sender_name} <{sender_email}>")
        print(f"Tiêu đề: {subject}")
        print(f"Liên kết xác thực mã hóa: {unique_link}")
        print("--------------------------------------------------\n")

def dispatch_campaign():
    """Tạo liên kết an toàn và tiến hành phát tán email"""
    base_url = config.get("server", {}).get("base_url", "http://127.0.0.1:5000").rstrip("/")
    tracking_path = config.get("campaign", {}).get("tracking_path", "/verify/portal-auth").strip("/")

    sync_campaign_users()

    print("==================================================================")
    print("🚀 BẮT ĐẦU CHIẾN DỊCH PHISHING SIMULATION")
    print("==================================================================")

    if Session:
        session = Session()
        try:
            users = session.query(CampaignUser).all()
            for u in users:
                unique_link = f"{base_url}/{tracking_path}/{u.token}"
                send_phishing_email(u.email, u.name, unique_link)
        finally:
            session.close()
    else:
        for email, data in memory_users.items():
            unique_link = f"{base_url}/{tracking_path}/{data['token']}"
            send_phishing_email(email, data['name'], unique_link)

    print("==================================================================")
    print(f"👉 Bảng điều khiển (Dashboard): {base_url}/dashboard")
    print("==================================================================\n")

# --- Flask Routes ---

@app.route('/')
def home():
    """Trang chủ hệ thống"""
    return """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Phishing Campaign Simulator</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 flex items-center justify-center min-h-screen p-6">
        <div class="bg-white rounded-xl shadow-lg p-8 max-w-xl text-center">
            <h1 class="text-3xl font-extrabold text-blue-700 mb-3">Phishing Campaign Simulator</h1>
            <p class="text-gray-600 mb-6">
                Nền tảng kiểm tra và nâng cao nhận thức an toàn thông tin nội bộ. Dữ liệu được lưu vĩnh viễn trên <strong>Aiven PostgreSQL</strong>.
            </p>
            <div class="space-y-3">
                <a href="/dashboard" class="block w-full py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition">
                    Xem Bảng Điều Khiển (Dashboard)
                </a>
                <a href="/reload" class="block w-full py-2 bg-gray-200 text-gray-700 font-medium rounded-lg hover:bg-gray-300 transition">
                    🚀 Gửi Email & Tải Lại Dữ Liệu
                </a>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/reload')
def reload_data():
    """Đồng bộ database và gửi lại email chiến dịch"""
    dispatch_campaign()
    return redirect(url_for('dashboard'))

# Route bắt bẫy click link mã hóa token
@app.route('/verify/portal-auth/<token>')
@app.route('/phish/<token>')
def handle_click(token):
    # Lấy IP thực (hỗ trợ reverse proxy, Cloudflare, tunnel, Render)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        ip_address = forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.remote_addr or 'N/A'

    user_agent = request.headers.get('User-Agent', 'N/A')
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    user_email = "Unknown"
    user_name = "N/A"

    if Session:
        session = Session()
        try:
            db_user = session.query(CampaignUser).filter_by(token=token).first()
            if db_user:
                db_user.clicked = True
                db_user.ip_address = ip_address
                db_user.user_agent = user_agent
                db_user.clicked_at = timestamp
                user_email = db_user.email
                user_name = db_user.name

                # Ghi nhật ký vào click_logs
                log_entry = ClickLog(
                    user_email=db_user.email,
                    token=token,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                session.add(log_entry)
                session.commit()
                print(f"\n⚠️  [LƯU VÀO POSTGRESQL] User: {user_name} ({user_email})")
                print(f"    IP: {ip_address} | Thời gian: {timestamp}\n")
        except Exception as e:
            session.rollback()
            print(f"[DB LỖI GHI LOG] {e}")
        finally:
            session.close()
    else:
        # Fallback in-memory
        for email, data in memory_users.items():
            if data.get('token') == token:
                data['clicked'] = True
                data['ip'] = ip_address
                data['user_agent'] = user_agent
                data['timestamp'] = timestamp
                user_email = email
                user_name = data['name']
                break

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
            <a href="/" class="inline-block px-6 py-2.5 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition">
                Quay lại Trang Chủ
            </a>
        </div>
    </body>
    </html>
    """)

@app.route('/dashboard')
def dashboard():
    """Bảng điều khiển kết nối trực tiếp Aiven PostgreSQL"""
    user_list = []
    if Session:
        session = Session()
        try:
            db_users = session.query(CampaignUser).order_by(CampaignUser.id).all()
            for u in db_users:
                user_list.append({
                    'name': u.name,
                    'email': u.email,
                    'department': u.department,
                    'token': u.token,
                    'clicked': u.clicked,
                    'ip': u.ip_address,
                    'timestamp': u.clicked_at
                })
        finally:
            session.close()
    else:
        for email, data in memory_users.items():
            user_list.append({
                'name': data['name'],
                'email': email,
                'department': data['department'],
                'token': data['token'],
                'clicked': data['clicked'],
                'ip': data['ip'],
                'timestamp': data['timestamp']
            })

    total_users = len(user_list)
    clicked_users = sum(1 for u in user_list if u['clicked'])
    click_rate = (clicked_users / total_users * 100) if total_users > 0 else 0

    base_url = config.get("server", {}).get("base_url", "http://127.0.0.1:5000").rstrip("/")
    tracking_path = config.get("campaign", {}).get("tracking_path", "/verify/portal-auth").strip("/")

    html_content = """
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <title>Dashboard Chiến Dịch Phishing</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-50 p-6">
        <div class="max-w-6xl mx-auto">
            <div class="flex justify-between items-center mb-6">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">Bảng Thống Kê Chiến Dịch Phishing</h1>
                    <p class="text-sm text-gray-500 mt-1">Dữ liệu thời gian thực được đồng bộ trên <strong>Aiven PostgreSQL</strong></p>
                </div>
                <div class="space-x-2">
                    <a href="/reload" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium text-sm transition shadow">
                        🚀 Gửi Email Chiến Dịch / Tải Lại
                    </a>
                    <a href="/" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 font-medium text-sm transition">
                        Trang Chủ
                    </a>
                </div>
            </div>

            <!-- Thẻ tóm tắt -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-100">
                    <p class="text-sm font-medium text-gray-500">Tổng Số Mục Tiêu</p>
                    <p class="text-3xl font-extrabold text-gray-900 mt-2">{{ total_users }}</p>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-100">
                    <p class="text-sm font-medium text-gray-500">Số Lượng Đã Click</p>
                    <p class="text-3xl font-extrabold text-red-600 mt-2">{{ clicked_users }}</p>
                </div>
                <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-100">
                    <p class="text-sm font-medium text-gray-500">Tỷ Lệ Mắc Bẫy (Click Rate)</p>
                    <p class="text-3xl font-extrabold text-blue-600 mt-2">{{ '{:.1f}'.format(click_rate) }}%</p>
                </div>
            </div>

            <!-- Bảng chi tiết -->
            <div class="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div class="p-4 border-b border-gray-200 font-bold text-gray-700 flex justify-between items-center">
                    <span>Chi Tiết Từng Nhân Viên</span>
                    <span class="text-xs font-normal text-green-600 bg-green-50 px-2.5 py-1 rounded-full border border-green-200">
                        ● PostgreSQL Active
                    </span>
                </div>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200 text-sm">
                        <thead class="bg-gray-50 text-gray-600 text-xs uppercase font-semibold">
                            <tr>
                                <th class="py-3 px-4 text-left">Họ Tên / Email</th>
                                <th class="py-3 px-4 text-left">Phòng Ban</th>
                                <th class="py-3 px-4 text-left">Trạng Thái</th>
                                <th class="py-3 px-4 text-left">Địa Chỉ IP</th>
                                <th class="py-3 px-4 text-left">Thời Gian Click</th>
                                <th class="py-3 px-4 text-left">Liên Kết Giả Lập Đã Gửi</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-100">
                            {% for u in user_list %}
                            <tr class="hover:bg-gray-50 transition">
                                <td class="py-3 px-4">
                                    <div class="font-semibold text-gray-900">{{ u.name }}</div>
                                    <div class="text-xs text-gray-500">{{ u.email }}</div>
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
                                <td class="py-3 px-4 text-gray-600 font-mono text-xs">{{ u.ip }}</td>
                                <td class="py-3 px-4 text-gray-600 text-xs">{{ u.timestamp }}</td>
                                <td class="py-3 px-4">
                                    <a href="{{ base_url }}/{{ tracking_path }}/{{ u.token }}" target="_blank" class="text-blue-600 hover:underline font-mono text-xs">
                                        .../{{ tracking_path }}/{{ u.token }}
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
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
        base_url=base_url,
        tracking_path=tracking_path
    )

# --- Điểm chạy chính ---
if __name__ == '__main__':
    dispatch_campaign()

    server_conf = config.get("server", {})
    host = server_conf.get("host", "0.0.0.0")
    port = server_conf.get("port", 5000)

    print(f"\n[OK] Khởi động Flask Server tại http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
