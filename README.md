# Phishing Campaign Simulator & Security Awareness Platform

A full-stack **Phishing Campaign Simulator & Security Awareness Platform** built with **Python (Flask)** and **PostgreSQL (SQLAlchemy)**, designed with a clean **Minimalist UI** ([NameThatUI Minimalism](https://namethatui.com/styles/minimalism)).

The platform enables security teams and administrators to conduct realistic internal phishing exercises, track real human clicks while filtering out automated email security scanners (e.g., Microsoft Defender Safe Links), and deliver immediate security awareness training to employees.

---

## Key Features

### 1. Target Provisioning & Microsoft 365 / Azure AD CSV Import
- **Single & Bulk Provisioning**: Add individual recipients or bulk-import employee exports (`userAccount.csv`) directly in the browser.
- **Smart CSV Parsing & Filtering**:
  - Automatically maps `Display name` $\rightarrow$ **Full Name**, `User principal name` $\rightarrow$ **Email**, and `Department` $\rightarrow$ **Department**.
  - Normalizes comma-formatted names (e.g., `"Chí, Đặng Minh"` $\rightarrow$ `"Đặng Minh Chí"`) while leaving standard names unchanged.
  - Automatically validates email syntax and unchecks external/guest accounts (`#EXT#`) before import.
- **Collision-Free Tracking Tokens**: Each recipient is assigned a unique 8-character hexadecimal token (`/v/<token>`) verified against the database.

### 2. Dual-Channel Email Delivery & Asynchronous Batch Dispatch
- **HTTPS Webhook (Port 443)**: Supports Google Apps Script HTTPS Webhooks to bypass outbound SMTP port restrictions (`465`/`587`) on free cloud hosts such as Render.
- **Direct SMTP (`SSL/TLS`)**: Supports standard SMTP servers (`smtp.gmail.com`) with configurable `SMTP_USERNAME` and masked `SMTP_PASSWORD` directly from the Admin Settings drawer.
- **Customizable Email Template**: Configure the **Sender Display Name** and **Email Subject Line** directly from the web UI (`app_settings`), delivering professional HTML emails with masked hyperlinks and a fallback plain-text body.
- **Asynchronous Background Delivery**: Bulk campaigns (**Send Email to All** or **Send to Unsent**) run in a background worker thread (`threading.Thread`) to prevent HTTP worker timeouts on large recipient lists.

### 3. Anti-Bot / Safe Links Scanner Protection
- **Two-Stage Human Verification (`/v/<token>`)**:
  - **Stage 1 (`GET`)**: Returns a clean internal portal verification page (`HTTP 200 OK`) without logging a click, preventing false positives from email pre-fetchers and link scanners.
  - **Stage 2 (`POST`)**: Requires a verified browser form submission (`human_confirm=1`), client timezone/interaction check, and filters out known scanner IP ranges and User-Agent signatures (`SCANNER_IP_PREFIXES` & `SCANNER_UA_KEYWORDS`).

### 4. Real-Time Admin Console (`/dashboard`)
- **Live 3-Second AJAX Polling (`/api/live-state`)**: Automatically updates the KPI matrix (**Total Recipients**, **Clicked Link**, **Click Rate**, **Total Click Events**), recipient delivery timestamps, and the **Click Activity Log** in real time without page reloads, complete with live click toast notifications.
- **Clean URLs & Auto-Dismiss Alerts**: Status notifications are stored in Flask session state so `/dashboard` URLs remain clean and banners automatically dismiss after 10 seconds.
- **Protected Access**: Root path (`/`) returns a `403 — Access Restricted` gateway page; administrative routes require session authentication via `/login`.

### 5. Built-In Security Awareness Briefing (`/awareness`)
- Immediately educates employees who click a simulated phishing link with actionable security verification guidelines (**Inspect Hyperlinks**, **Beware of Artificial Urgency**, **Verify the Sender Address**, **Confirm via Independent Channels**).

---

## Architecture & Workflow

```mermaid
flowchart LR
    A["Admin Console (/dashboard)"] -->|SMTP or HTTPS Webhook| B["Employee Inbox"]
    B -->|Clicks /v/token| C["Verification Gateway (GET /v/token)"]
    C -->|Bot / Safe Links Scanner| D["Ignored (No Click Logged)"]
    C -->|Verified Human POST| E["PostgreSQL (users & click_logs)"]
    E -->|Redirect| F["Security Awareness Briefing (/awareness)"]
    E -->|3s Live Polling| A
```

---

## Database Schema (PostgreSQL)

The application automatically initializes three tables via SQLAlchemy:

| Table | Purpose | Key Columns |
| :--- | :--- | :--- |
| `users` | Campaign recipients & latest status | `id`, `email` (unique), `name`, `department`, `token` (unique), `clicked`, `ip_address`, `user_agent`, `clicked_at`, `last_sent_at` |
| `click_logs` | Audit trail of every verified click event | `id`, `user_email`, `user_name`, `department`, `token`, `ip_address`, `user_agent`, `clicked_at` |
| `app_settings` | Persistent runtime configuration | `key` (`admin_password`, `webhook_url`, `smtp_username`, `smtp_password`, `sender_name`, `email_subject`), `value` |

---

## Project Structure

```text
├── icon/
│   └── PhisingIconOk.png      # Browser tab favicon
├── screenshots/               # UI reference screenshots
├── .gitignore                 # Excludes .env, config.json, *.csv, __pycache__/
├── config.example.json        # Example local configuration file
├── phishing-test.py           # Main Flask application, ORM models, routes & Minimalist UI
├── requirements.txt           # Python dependencies (Flask, Gunicorn, SQLAlchemy, psycopg2)
└── README.md                  # Project documentation
```

---

## Installation & Local Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/dangminhchi2004/PhishingProject.git
   cd PhishingProject
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables (Optional)**
   You can configure settings via `config.json` (copied from `config.example.json`), environment variables, or directly inside the **Admin Console Settings Drawer**:
   ```bash
   export DATABASE_URL="postgresql://user:password@host:port/dbname?sslmode=require"
   export ADMIN_PASSWORD="your-admin-password"
   export SMTP_USERNAME="your-email@gmail.com"
   export SMTP_PASSWORD="your-app-password"
   export EMAIL_WEBHOOK_URL="https://script.google.com/macros/s/.../exec"
   ```

4. **Run the Server**
   ```bash
   python phishing-test.py
   ```
   Open `http://127.0.0.1:5000/login` to sign in to the Admin Console.

---

## Deployment on Render

- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `gunicorn phishing-test:app`
- **Tip for Render Free Tier**: Since Render Free blocks outbound SMTP ports (`25`, `465`, `587`), configure the **HTTPS Webhook** (`02 / HTTPS Webhook` in the Settings drawer) using a Google Apps Script Web App URL to send emails reliably over HTTPS port `443`.

---

## License

This project is open-source under the MIT License.
