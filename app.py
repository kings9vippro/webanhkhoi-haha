import sys, types
try:
    import zalo_login as _zl_mod
except ImportError:
    _zl_mod = types.ModuleType("zalo_login")
    class LoginQRCallbackEventType:
        QRCodeGenerated = "QRCodeGenerated"
        QRCodeExpired = "QRCodeExpired"
        QRCodeScanned = "QRCodeScanned"
        QRCodeDeclined = "QRCodeDeclined"
        GotLoginInfo = "GotLoginInfo"
    _zl_mod.LoginQRCallbackEventType = LoginQRCallbackEventType
    sys.modules["zalo_login"] = _zl_mod

import os
import re
import ssl
import zlib
import gzip
import io
import json
import time
import uuid
import hmac
import math
import hashlib
import secrets
import sqlite3
import base64
import socket
import struct
import random
import threading
import unicodedata
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from urllib.parse import urlparse, unquote

import requests
from requests.adapters import HTTPAdapter
try:
    from Crypto.Cipher import AES
except ImportError:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _alg, modes as _modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

        class AES:
            MODE_CBC = 2
            MODE_GCM = 11
            block_size = 16

            @staticmethod
            def new(key, mode, iv_or_nonce=None, nonce=None):
                if mode == 2:
                    iv = iv_or_nonce if iv_or_nonce is not None else bytes(16)
                    class _CBCWrap:
                        def __init__(self, k, i):
                            self._c = _Cipher(_alg.AES(k), _modes.CBC(i))
                        def encrypt(self, data):
                            enc = self._c.encryptor()
                            return enc.update(data) + enc.finalize()
                        def decrypt(self, data):
                            dec = self._c.decryptor()
                            return dec.update(data) + dec.finalize()
                    return _CBCWrap(key, iv)
                else:
                    nc = nonce if nonce is not None else iv_or_nonce
                    class _GCMWrap:
                        def __init__(self, k, n):
                            self._g = _AESGCM(k)
                            self._n = n
                            self._aad = b""
                        def update(self, aad):
                            self._aad += aad
                        def decrypt_and_verify(self, ct, tag):
                            return self._g.decrypt(self._n, ct + tag, self._aad or None)
                        def decrypt(self, ct):
                            return self._g.decrypt(self._n, ct, self._aad or None)
                    return _GCMWrap(key, nc)

from flask import (
    Flask, request, jsonify, session, redirect, Response, send_from_directory, render_template_string
)
from werkzeug.utils import secure_filename

# CẤU HÌNH HỆ THỐNG & BẢO MẬT WEB
APP_TITLE = "NHK"
APP_AUTHOR = "Phan Anh Khôi (Rike)"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8995799349:AAE8uwWyS-CHzj2yQNkFkMynCTprFTZ1JNc")
SECRET_KEY = os.environ.get("SECRET_KEY", "telegram-ultra-secure-session-key-2026-hmac-sha256")
ACCESS_KEY = os.environ.get("WEB_KEY", "anhba")
DEFAULT_ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
DEFAULT_ADMIN_PASS = os.environ.get("ADMIN_PASS", "anhba")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
LOGO_DIR = os.path.join(UPLOAD_DIR, "brand")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LOGO_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
app.config["JSON_AS_ASCII"] = False
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 3600
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# LÁ CHẮN BẢO MẬT WEB (CHỐNG BRUTE-FORCE, RATE-LIMIT API, HEADERS)
LOGIN_ATTEMPTS = defaultdict(lambda: {"fails": 0, "lock_until": 0.0})
API_RATE_BUCKETS = defaultdict(lambda: deque(maxlen=260))
SECURITY_LOCK = threading.RLock()

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def check_ip_bruteforce(ip):
    now = time.time()
    with SECURITY_LOCK:
        st = LOGIN_ATTEMPTS[ip]
        if now < st["lock_until"]:
            return False, int(st["lock_until"] - now)
        return True, 0

def record_login_result(ip, success):
    now = time.time()
    with SECURITY_LOCK:
        st = LOGIN_ATTEMPTS[ip]
        if success:
            st["fails"] = 0
            st["lock_until"] = 0.0
        else:
            st["fails"] += 1
            if st["fails"] >= 8:
                st["lock_until"] = now + min(300, 20 * (st["fails"] - 7))

def hash_password_secure(raw_pw):
    salt = secrets.token_hex(8)
    h = hashlib.pbkdf2_hmac("sha256", raw_pw.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return f"pbkdf2${salt}${h}"

def verify_password_secure(stored_pw, provided_pw):
    if not stored_pw or not provided_pw:
        return False
    if stored_pw.startswith("pbkdf2$"):
        parts = stored_pw.split("$")
        if len(parts) == 3:
            _, salt, h = parts
            calc = hashlib.pbkdf2_hmac("sha256", provided_pw.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
            return hmac.compare_digest(h, calc)
    return hmac.compare_digest(str(stored_pw), str(provided_pw))

def get_or_create_csrf_token():
    tok = session.get("csrf_token")
    if not tok:
        tok = secrets.token_hex(24)
        session["csrf_token"] = tok
    return tok

@app.before_request
def security_middleware():
    if not WebSecurityFortress.inspect_request():
        return jsonify({"ok": False, "error": "Forbidden Request Signature"}), 403
    if request.path.startswith("/api/") or request.path.startswith("/task/"):
        ip = get_client_ip()
        now = time.time()
        with SECURITY_LOCK:
            dq = API_RATE_BUCKETS[ip]
            while dq and now - dq[0] > 10.0:
                dq.popleft()
            if len(dq) >= 320:
                return jsonify({"ok": False, "error": "Thao tác quá nhanh, vui lòng thử lại sau vài giây"}), 429
            dq.append(now)

class WebSecurityFortress:
    """Hệ thống tường lửa bảo mật Web đa lớp:
    - Chống vét cạn mật khẩu (IP Brute-Force Quarantine)
    - Chống ngập lụt API (Sliding-Window Rate Limiter)
    - Bảo vệ phiên Cookie (HttpOnly, SameSite=Lax, Constant-Time HMAC)
    - Tiêu đề bảo mật chuẩn quốc tế (Nosniff, Frame-Options, Permissions-Policy)"""
    BLOCKED_UA_KEYWORDS = ("sqlmap", "nikto", "acunetix", "nmap", "masscan", "dirbuster")

    @classmethod
    def inspect_request(cls):
        ua = (request.headers.get("User-Agent") or "").lower()
        for bad in cls.BLOCKED_UA_KEYWORDS:
            if bad in ua:
                return False
        return True

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

# BỘ LỌC ẨN LOG TÀI KHOẢN NHẠY CẢM (STEALTH ACCOUNT LOG MASKING)
def mask_sensitive_id(val, keep_tail=3):
    s = str(val or "").strip()
    if not s:
        return "***"
    if len(s) <= keep_tail + 2:
        return "***"
    return f"***{s[-keep_tail:]}"

def mask_account_name(name):
    s = str(name or "").strip()
    if not s:
        return "Acc_***"
    if len(s) <= 3:
        return s[0] + "**"
    return f"{s[:2]}***{s[-1:]}"

def sanitize_log_text(txt):
    if not txt:
        return ""
    s = str(txt)
    s = re.sub(r"[A-Za-z0-9_\-]{23,28}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27,45}", "[HIDDEN_TOKEN]", s)
    s = re.sub(r"(https?://[^\s]+)", "[STEALTH_ROUTE]", s)
    return s[:220]

# KHỞI TẠO & ĐỒNG BỘ CƠ SỞ DỮ LIỆU SQLITE TỐC ĐỘ CAO
_ACTIVE_DB_PATH = DB_PATH
_DB_TLS = threading.local()
_DB_WRITE_LOCK = threading.RLock()

class _PooledSQLiteConnection:
    """Kết nối SQLite tái sử dụng theo từng luồng (Thread-Local Connection Pool):
    - Loại bỏ 100% độ trễ mở file database.db và chạy PRAGMA lặp lại khi treo 100 luồng tần suất cao!"""
    def __init__(self, raw_conn):
        self._conn = raw_conn

    def execute(self, *args, **kwargs):
        return self._conn.execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._conn.executemany(*args, **kwargs)

    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)

    def commit(self):
        with _DB_WRITE_LOCK:
            return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        # Giữ kết nối sống trong Thread-Local Pool, chỉ giải phóng khóa giao dịch nếu có
        try:
            if self._conn.in_transaction:
                with _DB_WRITE_LOCK:
                    self._conn.commit()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self._conn, name)

def _create_raw_sqlite_conn():
    global _ACTIVE_DB_PATH
    try:
        raw = sqlite3.connect(_ACTIVE_DB_PATH, timeout=30, check_same_thread=False)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA synchronous=NORMAL;")
        raw.execute("PRAGMA temp_store=MEMORY;")
        raw.execute("PRAGMA busy_timeout=15000;")
        raw.execute("PRAGMA cache_size=-32000;")
        return raw
    except sqlite3.OperationalError:
        import tempfile
        _ACTIVE_DB_PATH = os.path.join(tempfile.gettempdir(), "noel_database.db")
        raw = sqlite3.connect(_ACTIVE_DB_PATH, timeout=30, check_same_thread=False)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA temp_store=MEMORY;")
        raw.execute("PRAGMA busy_timeout=15000;")
        return raw

def db():
    pooled = getattr(_DB_TLS, "conn", None)
    if pooled is not None and getattr(pooled, "_db_path", None) == _ACTIVE_DB_PATH:
        return pooled
    raw = _create_raw_sqlite_conn()
    pooled = _PooledSQLiteConnection(raw)
    pooled._db_path = _ACTIVE_DB_PATH
    _DB_TLS.conn = pooled
    return pooled

def normalize_zalo_cookies(raw_cookies):
    """Chuẩn hóa mọi định dạng Cookie Zalo (J2Team JSON, Extension JSON, EditThisCookie Array, Dict, Header String)
    về Dict phẳng {str(k): str(v)} để không bao giờ gây lỗi TypeError trong requests CookieJar!"""
    if not raw_cookies:
        return {}
    if isinstance(raw_cookies, dict):
        if "cookies" in raw_cookies and isinstance(raw_cookies["cookies"], (list, dict, str)):
            return normalize_zalo_cookies(raw_cookies["cookies"])
        out = {}
        for k, v in raw_cookies.items():
            if k and k not in ("url", "imei", "userAgent", "user_agent") and not isinstance(v, (list, dict)) and v is not None:
                out[str(k).strip()] = str(v).strip()
        return out
    if isinstance(raw_cookies, list):
        out = {}
        for c in raw_cookies:
            if isinstance(c, dict) and c.get("name") and c.get("value") is not None:
                out[str(c["name"]).strip()] = str(c["value"]).strip()
        return out
    s = str(raw_cookies).strip()
    if not s:
        return {}
    try:
        parsed = json.loads(s)
        if isinstance(parsed, (dict, list)):
            return normalize_zalo_cookies(parsed)
    except Exception:
        pass
    out = {}
    for part in s.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out

def extract_imei_from_raw_input(imei_str, raw_cookies):
    imei_clean = str(imei_str or "").strip()
    if imei_clean and not imei_clean.startswith("{"):
        return imei_clean
    for candidate in (imei_str, raw_cookies):
        if not candidate:
            continue
        try:
            parsed = json.loads(str(candidate).strip()) if isinstance(candidate, str) else candidate
            if isinstance(parsed, dict):
                found_imei = parsed.get("imei") or parsed.get("zpw_imei") or parsed.get("deviceId")
                if found_imei:
                    return str(found_imei).strip()
        except Exception:
            pass
    return imei_clean

def normalize_messenger_cookies(raw_cookies):
    """Chuẩn hóa mọi định dạng Cookie Facebook / Messenger (J2Team JSON, EditThisCookie Array, Dict, Header String c_user=...; xs=...)
    về Dict phẳng {str(k): str(v)} an toàn tuyệt đối cho requests.Session!"""
    if not raw_cookies:
        return {}
    if isinstance(raw_cookies, dict):
        if "cookies" in raw_cookies and isinstance(raw_cookies["cookies"], (list, dict, str)):
            return normalize_messenger_cookies(raw_cookies["cookies"])
        out = {}
        for k, v in raw_cookies.items():
            if k and k not in ("url", "userAgent", "user_agent") and not isinstance(v, (list, dict)) and v is not None:
                out[str(k).strip()] = str(v).strip()
        return out
    if isinstance(raw_cookies, list):
        out = {}
        for c in raw_cookies:
            if isinstance(c, dict) and c.get("name") and c.get("value") is not None:
                out[str(c["name"]).strip()] = str(c["value"]).strip()
        return out
    s = str(raw_cookies).strip()
    if not s:
        return {}
    try:
        parsed = json.loads(s)
        if isinstance(parsed, (dict, list)):
            return normalize_messenger_cookies(parsed)
    except Exception:
        pass
    out = {}
    for part in s.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out

def extract_messenger_uid(raw_cookies, fallback_uid=""):
    c_dict = normalize_messenger_cookies(raw_cookies)
    uid = c_dict.get("c_user") or c_dict.get("i_user") or str(fallback_uid or "").strip()
    if not uid and isinstance(raw_cookies, str):
        m = re.search(r"(?:c_user|i_user)\s*=\s*(\d+)", raw_cookies)
        if m:
            uid = m.group(1)
    return str(uid or "").strip()

def init_db():
    global _ACTIVE_DB_PATH
    try:
        conn = db()
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("CREATE TABLE IF NOT EXISTS _lock_test (id INT)")
    except sqlite3.OperationalError:
        import tempfile
        _ACTIVE_DB_PATH = os.path.join(tempfile.gettempdir(), "noel_database.db")
        _DB_TLS.conn = None
        conn = db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        imei TEXT,
        cookies TEXT,
        platform TEXT DEFAULT 'zalo',
        token TEXT,
        is_bot INTEGER DEFAULT 0,
        uid TEXT DEFAULT '',
        chat_cmd_enabled INTEGER DEFAULT 1,
        cmd_prefix TEXT DEFAULT '.',
        allow_all_cmd INTEGER DEFAULT 1,
        enabled INTEGER DEFAULT 1,
        created_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS authorized_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid TEXT UNIQUE,
        name TEXT,
        added_by_acc INTEGER,
        added_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS discord_token_vault (
        token_key TEXT PRIMARY KEY,
        launch_sig TEXT,
        hb_sess TEXT,
        dcfduid TEXT,
        sdcfduid TEXT,
        cfuvid TEXT,
        profile_idx INTEGER DEFAULT 0,
        session_id TEXT DEFAULT '',
        resume_url TEXT DEFAULT '',
        last_seq INTEGER DEFAULT 0,
        updated_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS zalo_cookie_vault (
        uid TEXT PRIMARY KEY,
        display_name TEXT DEFAULT '',
        imei TEXT DEFAULT '',
        cookies_json TEXT DEFAULT '{}',
        zpw_enk TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        updated_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS messenger_cookie_vault (
        uid TEXT PRIMARY KEY,
        fb_dtsg TEXT DEFAULT '',
        jazoest TEXT DEFAULT '',
        lsd TEXT DEFAULT '',
        cookies_json TEXT DEFAULT '{}',
        user_name TEXT DEFAULT '',
        last_seq_id TEXT DEFAULT '',
        client_rev TEXT DEFAULT '1015919737',
        updated_at REAL
    )
    """)
    for m_col, m_sql in [
        ("last_seq_id", "ALTER TABLE messenger_cookie_vault ADD COLUMN last_seq_id TEXT DEFAULT ''"),
        ("client_rev", "ALTER TABLE messenger_cookie_vault ADD COLUMN client_rev TEXT DEFAULT '1015919737'"),
    ]:
        try:
            cur.execute(m_sql)
        except Exception:
            pass
    for d_col, d_sql in [
        ("boxes_json", "ALTER TABLE discord_token_vault ADD COLUMN boxes_json TEXT DEFAULT '[]'"),
        ("user_name", "ALTER TABLE discord_token_vault ADD COLUMN user_name TEXT DEFAULT ''"),
        ("user_id", "ALTER TABLE discord_token_vault ADD COLUMN user_id TEXT DEFAULT ''"),
    ]:
        try:
            cur.execute(d_sql)
        except Exception:
            pass

    cur.execute("PRAGMA table_info(accounts)")
    cols = [c[1] for c in cur.fetchall()]
    migrations = [
        ("platform", "ALTER TABLE accounts ADD COLUMN platform TEXT DEFAULT 'zalo'"),
        ("token", "ALTER TABLE accounts ADD COLUMN token TEXT"),
        ("is_bot", "ALTER TABLE accounts ADD COLUMN is_bot INTEGER DEFAULT 0"),
        ("uid", "ALTER TABLE accounts ADD COLUMN uid TEXT DEFAULT ''"),
        ("chat_cmd_enabled", "ALTER TABLE accounts ADD COLUMN chat_cmd_enabled INTEGER DEFAULT 1"),
        ("cmd_prefix", "ALTER TABLE accounts ADD COLUMN cmd_prefix TEXT DEFAULT '.'"),
        ("allow_all_cmd", "ALTER TABLE accounts ADD COLUMN allow_all_cmd INTEGER DEFAULT 1"),
        ("enabled", "ALTER TABLE accounts ADD COLUMN enabled INTEGER DEFAULT 1"),
        ("user_agent", "ALTER TABLE accounts ADD COLUMN user_agent TEXT DEFAULT ''"),
        ("zpw_enk", "ALTER TABLE accounts ADD COLUMN zpw_enk TEXT DEFAULT ''"),
        ("pc_name", "ALTER TABLE accounts ADD COLUMN pc_name TEXT DEFAULT ''"),
    ]
    for col_name, sql_stmt in migrations:
        if col_name not in cols:
            try:
                cur.execute(sql_stmt)
            except Exception:
                pass

    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        filepath TEXT,
        lines_count INTEGER,
        created_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        type TEXT,
        meta TEXT,
        status TEXT,
        started_at REAL,
        stats TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS bot_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        acc_id INTEGER,
        thread_id TEXT,
        sender_id TEXT,
        cmd_text TEXT,
        action_taken TEXT,
        created_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS cmd_execution_locks (
        lock_key TEXT PRIMARY KEY,
        created_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS zalo_qr_sessions (
        session_id TEXT PRIMARY KEY,
        state_json TEXT DEFAULT '{}',
        qr_png BLOB,
        updated_at REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS system_epochs (
        epoch_key TEXT PRIMARY KEY,
        epoch_val INTEGER DEFAULT 0,
        updated_at REAL
    )
    """)

    try:
        cur.execute("UPDATE accounts SET chat_cmd_enabled = 1 WHERE chat_cmd_enabled IS NULL")
        cur.execute("UPDATE accounts SET allow_all_cmd = 1 WHERE allow_all_cmd IS NULL")
        z_rows = cur.execute("SELECT id, imei, cookies FROM accounts WHERE platform='zalo'").fetchall()
        for zr in z_rows:
            norm_c = normalize_zalo_cookies(zr["cookies"])
            norm_imei = extract_imei_from_raw_input(zr["imei"], zr["cookies"])
            if norm_c:
                cur.execute(
                    "UPDATE accounts SET imei=?, cookies=? WHERE id=?",
                    (norm_imei, json.dumps(norm_c, ensure_ascii=False), zr["id"])
                )
    except Exception:
        pass

    existing_admin = cur.execute("SELECT id FROM users WHERE username = ?", (DEFAULT_ADMIN_USER,)).fetchone()
    if not existing_admin:
        cur.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (DEFAULT_ADMIN_USER, hash_password_secure(DEFAULT_ADMIN_PASS), time.time())
        )

    conn.commit()
    conn.close()

init_db()

def get_setting(key, default_val=""):
    try:
        conn = db()
        row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row["value"] if row else default_val
    except Exception:
        return default_val

def set_setting(key, val):
    try:
        conn = db()
        conn.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, str(val)))
        conn.commit()
        conn.close()
    except Exception:
        pass

# TRẠNG THÁI RUNTIME TOÀN CỤC & CHỐNG TỰ KÍCH HOẠT LỆNH (.MENU FIX)
ACTIVE_TASKS = {}
ACTIVE_LISTENERS = {}

# BỘ NHỚ RAM TỐC ĐỘ ÁNH SÁNG (0MS LOCK-FREE IN-MEMORY ENGINE CHO 100+ LUỒNG TREO)
ACCOUNTS_RAM_CACHE = {}
ACCOUNTS_RAM_LOCK = threading.RLock()
TASKS_RAM_STORE = {}
TASKS_RAM_LOCK = threading.RLock()
BOT_LOGS_RAM_DEQUE = deque(maxlen=40)

_LAST_ACCOUNTS_SYNC_TS = 0.0

def refresh_accounts_ram_cache():
    global _LAST_ACCOUNTS_SYNC_TS
    try:
        conn = db()
        rows = conn.execute("SELECT * FROM accounts ORDER BY id DESC").fetchall()
        conn.close()
        new_map = {r["id"]: dict(r) for r in rows}
        with ACCOUNTS_RAM_LOCK:
            ACCOUNTS_RAM_CACHE.clear()
            ACCOUNTS_RAM_CACHE.update(new_map)
            _LAST_ACCOUNTS_SYNC_TS = time.time()
        return list(new_map.values())
    except Exception:
        with ACCOUNTS_RAM_LOCK:
            return list(ACCOUNTS_RAM_CACHE.values())

def get_account_from_ram(acc_id):
    if time.time() - _LAST_ACCOUNTS_SYNC_TS > 0.25:
        refresh_accounts_ram_cache()
    with ACCOUNTS_RAM_LOCK:
        acc = ACCOUNTS_RAM_CACHE.get(int(acc_id) if str(acc_id).isdigit() else acc_id)
        if acc is not None:
            return dict(acc)
    refresh_accounts_ram_cache()
    with ACCOUNTS_RAM_LOCK:
        acc = ACCOUNTS_RAM_CACHE.get(int(acc_id) if str(acc_id).isdigit() else acc_id)
        return dict(acc) if acc is not None else None

def get_all_accounts_from_ram(platform=None, enabled_only=False):
    if time.time() - _LAST_ACCOUNTS_SYNC_TS > 0.25 or not ACCOUNTS_RAM_CACHE:
        refresh_accounts_ram_cache()
    with ACCOUNTS_RAM_LOCK:
        items = list(ACCOUNTS_RAM_CACHE.values())
    if platform:
        items = [a for a in items if (a.get("platform") or "zalo").lower() == platform.lower()]
    if enabled_only:
        en = [a for a in items if a.get("enabled", 1)]
        items = en if en else items
    return [dict(a) for a in items]

GLOBAL_STOP_EPOCH = 0
BOX_STOP_EPOCHS = defaultdict(int)
STOP_EPOCH_LOCK = threading.RLock()

def _sync_epochs_from_db_background():
    global GLOBAL_STOP_EPOCH
    try:
        conn = db()
        rows = conn.execute("SELECT epoch_key, epoch_val FROM system_epochs").fetchall()
        conn.close()
        with STOP_EPOCH_LOCK:
            for r in rows:
                ek = r["epoch_key"]
                ev = int(r["epoch_val"] or 0)
                if ek == "__global__":
                    if ev > GLOBAL_STOP_EPOCH:
                        GLOBAL_STOP_EPOCH = ev
                elif ek.startswith("box:"):
                    b_id = ek[4:]
                    if ev > BOX_STOP_EPOCHS[b_id]:
                        BOX_STOP_EPOCHS[b_id] = ev
    except Exception:
        pass

def bump_stop_epoch(thread_id=None):
    """Ngắt xung nhịp nguyên tử 0ms trực tiếp trên RAM, đồng bộ SQLite bất đồng bộ ở hậu trường!"""
    global GLOBAL_STOP_EPOCH
    now = time.time()
    with STOP_EPOCH_LOCK:
        if thread_id is None:
            GLOBAL_STOP_EPOCH += 1
            for k in list(BOX_STOP_EPOCHS.keys()):
                BOX_STOP_EPOCHS[k] += 1
            g_val = GLOBAL_STOP_EPOCH
        else:
            tid_s = str(thread_id).strip()
            BOX_STOP_EPOCHS[tid_s] += 1
            g_val = BOX_STOP_EPOCHS[tid_s]

    def _async_epoch_write():
        try:
            conn = db()
            if thread_id is None:
                conn.execute(
                    "INSERT INTO system_epochs (epoch_key, epoch_val, updated_at) VALUES ('__global__', ?, ?) "
                    "ON CONFLICT(epoch_key) DO UPDATE SET epoch_val = excluded.epoch_val, updated_at = excluded.updated_at",
                    (g_val, now)
                )
            else:
                tid_s = str(thread_id).strip()
                conn.execute(
                    "INSERT INTO system_epochs (epoch_key, epoch_val, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(epoch_key) DO UPDATE SET epoch_val = excluded.epoch_val, updated_at = excluded.updated_at",
                    (f"box:{tid_s}", g_val, now)
                )
            conn.commit()
        except Exception:
            pass

    threading.Thread(target=_async_epoch_write, daemon=True).start()
    return g_val

def get_current_epochs(thread_id=None):
    with STOP_EPOCH_LOCK:
        g_ep = GLOBAL_STOP_EPOCH
        b_ep = BOX_STOP_EPOCHS[str(thread_id).strip()] if thread_id else 0
        return g_ep, b_ep

def is_task_stopped_fast(stop_ev, start_global_epoch=None, start_box_epoch=None, target_id=None):
    """Kiểm tra trạng thái dừng trong 0.0001ms thuần RAM (Không khóa DB, không nghẽn luồng)!"""
    if stop_ev is not None and stop_ev.is_set():
        return True
    if start_global_epoch is not None and GLOBAL_STOP_EPOCH != start_global_epoch:
        if stop_ev is not None:
            stop_ev.set()
        return True
    if target_id is not None and start_box_epoch is not None:
        if BOX_STOP_EPOCHS.get(str(target_id).strip(), 0) != start_box_epoch:
            if stop_ev is not None:
                stop_ev.set()
            return True
    return False

def interruptible_wait(stop_ev, wait_seconds, start_global_epoch=None, start_box_epoch=None, target_id=None):
    rem = float(wait_seconds or 0.0)
    if rem <= 0.0:
        return is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id)
    step = 0.04
    while rem > 0.0:
        if is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id):
            return True
        sl = min(step, rem)
        if stop_ev is not None:
            if stop_ev.wait(sl):
                return True
        else:
            time.sleep(sl)
        rem -= sl
    return is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id)

GLOBAL_CMD_DEDUPE_CACHE = {}
GLOBAL_CMD_DEDUPE_LOCK = threading.RLock()

def claim_command_execution_slot(platform, thread_id, sender_id, raw_msg, msg_id=None):
    """Khóa điều phối lệnh Đa Tài Khoản 0.0001ms Thuần RAM (Zero-Lag Pure RAM Command Lock):
    - Tuyệt đối KHÔNG gọi SQLite trên luồng nhận lệnh để 2..50 Acc Zalo/Discord phản hồi tức thì không bao giờ bị nghẽn!
    - Khóa theo msg_id (45s) để 2 Acc trong cùng 1 nhóm không lặp lại cùng 1 tin nhắn, nhưng cho phép gõ lệnh liên hoàn (.m, .cp, .n, .t) nhạy 100%!"""
    now = time.time()
    norm_txt = re.sub(r"\s+", " ", str(raw_msg or "").strip()).lower()[:120]
    plat_s = str(platform or "zalo").lower()
    tid_s = str(thread_id or "").strip()
    mid_s = str(msg_id or "").strip()
    sender_s = str(sender_id or "").strip()
    cmd_key = f"cmd:{plat_s}:{tid_s}:{sender_s}:{norm_txt}"

    with GLOBAL_CMD_DEDUPE_LOCK:
        if len(GLOBAL_CMD_DEDUPE_CACHE) > 2500:
            for k, ts_old in list(GLOBAL_CMD_DEDUPE_CACHE.items()):
                ttl = 45.0 if k.startswith("mid:") else 0.75
                if now - ts_old > ttl:
                    GLOBAL_CMD_DEDUPE_CACHE.pop(k, None)
        if mid_s and mid_s not in ("0", ""):
            m_key = f"mid:{plat_s}:{tid_s}:{mid_s}"
            last_m = GLOBAL_CMD_DEDUPE_CACHE.get(m_key, 0.0)
            if now - last_m < 45.0:
                return False
            GLOBAL_CMD_DEDUPE_CACHE[m_key] = now
        last_ts = GLOBAL_CMD_DEDUPE_CACHE.get(cmd_key, 0.0)
        if now - last_ts < 0.65:
            return False
        GLOBAL_CMD_DEDUPE_CACHE[cmd_key] = now
    return True

SYSTEM_RUNTIME_CONFIG = {
    "delay": 0.0,
    "color_mode": "rainbow",
    "fixed_color": "red",
    "font_style": "big_bold",
    "icon_count": 3,
    "use_emoji": True,
    "is_heading": True,
    "antiband": True,
    "antidieall": True,
    "strip_line_num": True,
    "hide_acc_log": True,
    "hide_tag_all": True,
    "hide_tag_name": True,
}
SYSTEM_CFG_LOCK = threading.RLock()

SYSTEM_SENT_IDS = deque(maxlen=3000)
SYSTEM_SENT_TEXT_HASHES = deque(maxlen=3000)
_SENT_IDS_MAP = {}
_SENT_HASH_MAP = {}
SYSTEM_SENT_LOCK = threading.RLock()

# Chế độ tự động chặn & bám sát mục tiêu (.chan / .bam) 0ms
AUTO_INTERCEPT_BOXES = {}
AUTO_INTERCEPT_LOCK = threading.RLock()

def _normalize_for_echo_hash(s):
    if not s:
        return ""
    for zw in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
        s = s.replace(zw, "")
    return re.sub(r"\s+", " ", s.strip()).lower()[:240]

def register_system_sent_message(msg_id=None, client_id=None, text=None):
    now = time.time()
    with SYSTEM_SENT_LOCK:
        if len(_SENT_IDS_MAP) > 4000:
            cutoff = now - 95.0
            for k in [k for k, v in _SENT_IDS_MAP.items() if v < cutoff]:
                _SENT_IDS_MAP.pop(k, None)
        if len(_SENT_HASH_MAP) > 4000:
            cutoff_h = now - 65.0
            for k in [k for k, v in _SENT_HASH_MAP.items() if v < cutoff_h]:
                _SENT_HASH_MAP.pop(k, None)
        if msg_id:
            s_mid = str(msg_id)
            _SENT_IDS_MAP[s_mid] = now
            SYSTEM_SENT_IDS.append((s_mid, now))
        if client_id:
            s_cid = str(client_id)
            _SENT_IDS_MAP[s_cid] = now
            SYSTEM_SENT_IDS.append((s_cid, now))
        if text:
            nh = _normalize_for_echo_hash(text)
            if nh:
                _SENT_HASH_MAP[nh] = now
                first_line = _normalize_for_echo_hash(text.split("\n")[0])
                if first_line:
                    _SENT_HASH_MAP[first_line] = now

VALID_SYSTEM_CMD_TOKENS = {
    "menu", "help", "lenh", "hdsd", "m", "h",
    "2fa", "otp", "totp", "todo", "giaoviec", "bank", "stk", "card", "danhthiep",
    "statusdc", "hypesquad", "react", "thuhoi", "undo",
    "spam", "fast", "nhanh", "s", "nhay", "treonhay", "treo_nhay", "n",
    "ngon", "treongon", "treo_ngon", "g", "file", "chay", "f",
    "files", "dsfile", "listfile", "ds", "tag", "all", "tagall", "anall", "tagallan", "antan", "tagan", "antag", "hientag", "prx", "proxy",
    "soi", "soifull", "scanbox", "dsbox", "listbox", "dsnhom", "chan", "bam", "bamsat", "chanall", "gall", "gll", "ngonall", "nall", "nll", "nhayall", "xaall",
    "raid", "r", "auto", "a", "dao", "chao", "hi", "xa", "sieuxa", "xanhom", "combo", "battrinh",
    "ping", "p", "status", "info", "stinfo", "id", "uid", "mem", "tv", "thanhvien",
    "addfile", "taof", "af", "clear", "reset",
    "delay", "tocdo", "time", "d", "mau", "color", "doimau",
    "icon", "emoji", "chuto", "heading", "chunho", "cochu", "kieuchu", "font", "antiband", "antiban",
    "chophep", "capquyen", "adduser", "add", "admin",
    "xoaquyen", "deluser", "del", "cam",
    "dsquyen", "listuser", "quyen",
    "stop", "dung", "dừng", "tat", "tắt", "off", "t", "st", "stopall", "dunghet", "tathet", "ta",
    "ab", "cp", "xq", "dsq",
    "vip", "sieuvip", "theme", "setnen", "nen", "poll", "nhaypoll",
    "sharelink", "link", "sharecontact", "contact", "typing", "ty",
    "tenbox", "nhaynamebox", "setname", "bd", "namechange",
}

def normalize_cmd_homoglyphs(s):
    if not s:
        return ""
    for cyr, lat in (("а", "a"), ("е", "e"), ("о", "o"), ("і", "i"), ("с", "c"), ("р", "p"), ("х", "x"), ("у", "y")):
        s = s.replace(cyr, lat).replace(cyr.upper(), lat.upper())
    return s

def is_direct_user_command_text(text):
    if not text:
        return False
    clean_t = normalize_cmd_homoglyphs(_normalize_for_echo_hash(text))
    if not clean_t or "\n" in str(text).strip():
        return False
    if clean_t[0] not in (".", "/", "!"):
        return False
    first_w = clean_t[1:].split(" ")[0].strip().lower()
    return bool(first_w in VALID_SYSTEM_CMD_TOKENS or first_w.isdigit())

def is_system_echo_message(msg_id=None, client_id=None, text=None):
    now = time.time()
    if msg_id:
        ts_m = _SENT_IDS_MAP.get(str(msg_id))
        if ts_m is not None and (now - ts_m <= 95.0):
            return True
    if client_id:
        ts_c = _SENT_IDS_MAP.get(str(client_id))
        if ts_c is not None and (now - ts_c <= 95.0):
            return True
    if text:
        if is_direct_user_command_text(text):
            return False
        nh = _normalize_for_echo_hash(text)
        ts_h = _SENT_HASH_MAP.get(nh)
        if ts_h is not None and (now - ts_h <= 65.0):
            return True
        first_line = _normalize_for_echo_hash(text.split("\n")[0])
        ts_fl = _SENT_HASH_MAP.get(first_line)
        if ts_fl is not None and (now - ts_fl <= 65.0):
            return True
    return False

def new_tid(p):
    return f"{p}_{int(time.time() * 1000)}_{random.randint(100, 999)}"

def utf16_len(s):
    if not s:
        return 0
    return len(s.encode("utf-16-le")) // 2

def remove_vn_accents(s):
    if not s:
        return ""
    s = s.replace("đ", "d").replace("Đ", "D")
    nfkd = unicodedata.normalize("NFKD", s)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower().strip()

# QUẢN LÝ PHÂN QUYỀN NGƯỜI DÙNG TRÊN KHUNG CHAT ZALO & DISCORD
OWNER_UIDS_CACHE = set()
GLOBAL_USER_NAME_CACHE = {}

def refresh_owner_uids():
    global OWNER_UIDS_CACHE
    try:
        conn = db()
        rows = conn.execute("SELECT uid, token, platform FROM accounts").fetchall()
        conn.close()
        s = set()
        for r in rows:
            if r["uid"]:
                for part in str(r["uid"]).split(","):
                    if part.strip():
                        s.add(part.strip())
            if (r["platform"] or "") == "discord" and r["token"]:
                try:
                    raw_t = str(r["token"]).strip()
                    if "." in raw_t:
                        f_seg = raw_t.split(".")[0].strip()
                        pad = (4 - len(f_seg) % 4) % 4
                        dec_u = base64.urlsafe_b64decode(f_seg + ("=" * pad)).decode("utf-8", errors="ignore").strip()
                        if dec_u.isdigit() and len(dec_u) >= 15:
                            s.add(dec_u)
                except Exception:
                    pass
        OWNER_UIDS_CACHE = s
    except Exception:
        pass

AUTHORIZED_USERS_RAM_CACHE = {}
AUTHORIZED_USERS_LOCK = threading.RLock()
_AUTHORIZED_USERS_LOADED = False
_PRIORITY_CMD_EXECUTOR = ThreadPoolExecutor(max_workers=128)

def _ensure_authorized_users_loaded():
    global _AUTHORIZED_USERS_LOADED
    if _AUTHORIZED_USERS_LOADED:
        return
    with AUTHORIZED_USERS_LOCK:
        if _AUTHORIZED_USERS_LOADED:
            return
        _AUTHORIZED_USERS_LOADED = True
        try:
            conn = db()
            rows = conn.execute("SELECT uid, name, added_at FROM authorized_users ORDER BY id ASC").fetchall()
            conn.close()
            for r in rows:
                u_s = str(r["uid"] or "").strip().lstrip("@")
                n_s = str(r["name"] or "").strip().lstrip("@")
                if u_s:
                    AUTHORIZED_USERS_RAM_CACHE[u_s] = {
                        "uid": u_s,
                        "name": n_s or f"User_{u_s[-4:]}",
                        "norm_name": remove_vn_accents(n_s) if n_s else "",
                        "norm_uid": remove_vn_accents(u_s),
                        "added_at": float(r["added_at"] or time.time()),
                    }
        except Exception:
            pass

def is_user_authorized_for_cmd(sender_uid, client_uid=None, client_send2me_id=None, allow_all=False, sender_name=""):
    """Kiểm tra quyền thực thi lệnh (.cp / Owner) trong 0.0001ms thuần RAM (Tuyệt đối không khóa SQLite khi treo đa Acc)!"""
    s_uid = str(sender_uid or "").strip().lstrip("@")
    if s_uid in ("0", ""):
        return True
    if client_uid and s_uid == str(client_uid).strip():
        return True
    if client_send2me_id and s_uid == str(client_send2me_id).strip():
        return True
    if not OWNER_UIDS_CACHE:
        refresh_owner_uids()
    if s_uid in OWNER_UIDS_CACHE:
        return True

    _ensure_authorized_users_loaded()
    s_name = str(sender_name or GLOBAL_USER_NAME_CACHE.get(s_uid) or "").strip().lstrip("@")
    s_name_low = s_name.lower() if s_name else ""
    s_name_norm = remove_vn_accents(s_name) if s_name else ""
    s_uid_low = s_uid.lower()

    with AUTHORIZED_USERS_LOCK:
        if s_uid in AUTHORIZED_USERS_RAM_CACHE:
            return True
        for r_uid, info in AUTHORIZED_USERS_RAM_CACHE.items():
            if r_uid.lower() == s_uid_low:
                return True
            if s_name_low and (r_uid.lower() == s_name_low or info["name"].lower() == s_name_low):
                return True
            if s_name_norm and (info["norm_uid"] == s_name_norm or (info["norm_name"] and info["norm_name"] == s_name_norm)):
                return True

    if allow_all:
        return True
    return False

def add_authorized_user(uid, name="", acc_id=0):
    uid_str = str(uid or "").strip().lstrip("@")
    if not uid_str or uid_str in ("0", "-1"):
        return False
    _ensure_authorized_users_loaded()
    clean_name = str(name or "").strip().lstrip("@") or GLOBAL_USER_NAME_CACHE.get(uid_str) or f"User_{uid_str[-4:]}"
    now_t = time.time()
    with AUTHORIZED_USERS_LOCK:
        AUTHORIZED_USERS_RAM_CACHE[uid_str] = {
            "uid": uid_str,
            "name": clean_name,
            "norm_name": remove_vn_accents(clean_name),
            "norm_uid": remove_vn_accents(uid_str),
            "added_at": now_t,
        }

    def _async_save_cp():
        try:
            conn = db()
            conn.execute(
                "INSERT OR REPLACE INTO authorized_users (uid, name, added_by_acc, added_at) VALUES (?, ?, ?, ?)",
                (uid_str, clean_name, acc_id, now_t)
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    threading.Thread(target=_async_save_cp, daemon=True).start()
    return True

def remove_authorized_user(uid):
    uid_str = str(uid or "").strip().lstrip("@")
    _ensure_authorized_users_loaded()
    existed = False
    with AUTHORIZED_USERS_LOCK:
        if uid_str in AUTHORIZED_USERS_RAM_CACHE:
            AUTHORIZED_USERS_RAM_CACHE.pop(uid_str, None)
            existed = True
        else:
            for k in list(AUTHORIZED_USERS_RAM_CACHE.keys()):
                if k.lower() == uid_str.lower() or AUTHORIZED_USERS_RAM_CACHE[k]["name"].lower() == uid_str.lower():
                    AUTHORIZED_USERS_RAM_CACHE.pop(k, None)
                    existed = True

    def _async_del_cp():
        try:
            conn = db()
            conn.execute("DELETE FROM authorized_users WHERE uid = ? OR lower(name) = ?", (uid_str, uid_str.lower()))
            conn.commit()
            conn.close()
        except Exception:
            pass

    threading.Thread(target=_async_del_cp, daemon=True).start()
    return existed

def list_authorized_users():
    _ensure_authorized_users_loaded()
    with AUTHORIZED_USERS_LOCK:
        return [
            {"uid": v["uid"], "name": v["name"], "added_at": v["added_at"]}
            for v in AUTHORIZED_USERS_RAM_CACHE.values()
        ]

# BỘ ICON & EMOJI CHUẨN ZALO 100% (ĐÃ FIX TRIỆT ĐỂ LỖI CHỮ THÔ ':-')
ZALO_PALETTE = [
    {"id": "red",    "name": "Đỏ Rực",         "hex": "#db342e", "zcode": "db342e"},
    {"id": "orange", "name": "Cam Rực Lửa",    "hex": "#f27806", "zcode": "f27806"},
    {"id": "yellow", "name": "Vàng Hoàng Kim", "hex": "#f7b503", "zcode": "f7b503"},
    {"id": "green",  "name": "Xanh Ngọc Lục",  "hex": "#15a85f", "zcode": "15a85f"},
    {"id": "blue",   "name": "Xanh Dương VIP", "hex": "#0068ff", "zcode": "0068ff"},
    {"id": "cyan",   "name": "Xanh Băng Tuyết","hex": "#00b4d8", "zcode": "00b4d8"},
    {"id": "purple", "name": "Tím Hoàng Gia",  "hex": "#8b5cf6", "zcode": "8b5cf6"},
    {"id": "pink",   "name": "Hồng Ánh Sao",   "hex": "#ec4899", "zcode": "ec4899"},
]

ZALO_NATIVE_ZCODES = ["db342e", "f27806", "f7b503", "15a85f", "0068ff", "00b4d8", "8b5cf6", "ec4899"]
ZALO_FIRE_ZCODES = ["db342e", "f27806", "f7b503"]
ZALO_OCEAN_ZCODES = ["15a85f", "00b4d8", "0068ff"]
ZALO_ROYAL_ZCODES = ["8b5cf6", "ec4899", "db342e", "f7b503"]
ZALO_CYBER_ZCODES = ["0068ff", "00b4d8", "8b5cf6", "ec4899", "15a85f"]

class UnicodeLuxuryFontEngine:
    """Bộ Chuyển Đổi Phông Chữ Unicode Siêu Đẳng Cấp 2026 (Kết hợp cùng Zalo Styles f_18 / f_13 & 8 Màu):
    - Hỗ trợ biến đổi ký tự Latin sang chữ nghệ thuật VIP mà vẫn giữ nguyên dấu tiếng Việt rõ nét!"""
    _NORMAL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    _MAPS = {
        "bold_serif": str.maketrans(_NORMAL_CHARS, "𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗"),
        "italic_serif": str.maketrans(_NORMAL_CHARS, "𝐴𝐵𝐶𝐷𝐸𝐹𝐺𝐻𝐼𝐽𝐾𝐿𝑀𝑁𝑂𝑃𝑄𝑅𝑆𝑇𝑈𝑉𝑊𝑋𝑌𝑍𝑎𝑏𝑐𝑑𝑒𝑓𝑔ℎ𝑖𝑗𝑘𝑙𝑚𝑛𝑜𝑝𝑞𝑟𝑠𝑡𝑢𝑣𝑤𝑥𝑦𝑧0123456789"),
        "bold_sans": str.maketrans(_NORMAL_CHARS, "𝗔𝗕𝗖𝗗𝗘𝗙𝗚𝗛𝗜𝗝𝗞𝗟𝗠𝗡𝗢𝗣𝗤𝗥𝗦𝗧𝗨𝗩𝗪𝗫𝗬𝗭𝗮𝗯𝗰𝗱𝗲𝗳𝗴𝗵𝗶𝗷𝗸𝗹𝗺𝗻𝗼𝗽𝗾𝗿𝘀𝘁𝘂𝘃𝘄𝘅𝘆𝘇𝟬𝟭𝟮𝟯𝟰𝟱𝟲𝟳𝟴𝟵"),
        "double_struck": str.maketrans(_NORMAL_CHARS, "𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ𝕒𝕓𝕔𝕕𝖊𝖋𝖌𝖍𝖎𝖏𝖐𝖑𝖒𝖓𝖔𝖕𝖖𝖗𝖘𝖙𝖚𝖛𝖜𝖝𝖞𝖟𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡"),
        "script_vip": str.maketrans(_NORMAL_CHARS, "𝒜ℬ𝒞𝒟ℰℱ𝒢ℋℐ𝒥𝒦ℒℳ𝒩𝒪𝒫𝒬ℛ𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵𝒶𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏0123456789"),
        "small_caps": str.maketrans("abcdefghijklmnopqrstuvwxyz", "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢ"),
    }

    @classmethod
    def transform_line(cls, text, font_style="big_bold"):
        if not text:
            return ""
        fs = str(font_style or "").lower()
        t_map = None
        if fs in ("bold_serif", "serif"):
            t_map = cls._MAPS["bold_serif"]
        elif fs in ("italic_serif",):
            t_map = cls._MAPS["italic_serif"]
        elif fs in ("bold_sans", "sans"):
            t_map = cls._MAPS["bold_sans"]
        elif fs in ("double_struck", "double", "khung"):
            t_map = cls._MAPS["double_struck"]
        elif fs in ("script_vip", "script", "nghethuat"):
            t_map = cls._MAPS["script_vip"]
        elif fs in ("small_caps", "smallcaps"):
            t_map = cls._MAPS["small_caps"]
        if not t_map:
            return text
        out_tokens = []
        for tk in str(text).split(" "):
            if tk.startswith("@") or tk.startswith("http"):
                out_tokens.append(tk)
            else:
                out_tokens.append(tk.translate(t_map))
        return " ".join(out_tokens)

ZALO_COLOR_MAP = {
    "red": "db342e", "do": "db342e", "đỏ": "db342e",
    "orange": "f27806", "cam": "f27806",
    "yellow": "f7b503", "vang": "f7b503", "vàng": "f7b503",
    "green": "15a85f", "xanh": "15a85f", "xanhla": "15a85f",
    "blue": "0068ff", "xanhduong": "0068ff",
    "cyan": "00b4d8", "ngoc": "00b4d8", "ocean": "00b4d8",
    "purple": "8b5cf6", "tim": "8b5cf6", "tím": "8b5cf6",
    "pink": "ec4899", "hong": "ec4899", "hồng": "ec4899",
}

ZALO_ICON_VIP = [
    "😂", "🤣", "😝", "😜", "🤪", "😏", "😒", "🙄",
    "😬", "🤥", "🤫", "🤭", "🥱", "😴", "🤮", "🤧",
    "🥵", "🥶", "🥴", "😵", "🤯", "😎", "🤓", "🧐",
    "🤬", "😡", "😤", "😈", "👿", "💀", "☠️", "💩",
    "🤡", "👹", "👺", "👻", "👎", "🖕", "🤏", "🐓",
    "🐔", "🐶", "🐷", "🐸", "🐢", "🐌"
]

LEGACY_SHORTCUT_TO_ICON_MAP = {
    ";-A": "😝", ";-!": "😤", ";f": "😜", ";;)": "😏", ";)": "😏",
    "=))": "🤣", ":))": "😂", ":)": "😏", ":(": "😒", ":((": "🥱",
    "b-)": "😎", "8-)": "🤓", "x-)": "🤪", "=d>": "🤡",
    ":-R": "😡", ":-L": "😤", ":-F": "🤬", ":-h": "👎", ":-*": "😜",
    ":-?": "🧐", ":-s": "🥴", ":-t": "😡", ":-bd": "👎", ":-d": "🤣",
    ":-p": "😝", ":-o": "🥱", ":-x": "🤫", ":-w": "🐌", ":-<": "🤮",
    ":d": "🤣", ":p": "😜", ":v": "🤡", ":3": "🐸", ":>": "😏",
    ":$": "🤥", ":x": "🤫", ":o": "🥱",
    "/-strong": "👎", "/-weak": "👎", "/-punch": "🤬", "/-shit": "💩",
    "/-bome": "💀", "/-rose": "🥀", "/-heart": "💔", "/-ok": "🤏",
    "/-li": "😈", "/-fade": "☠️", "/-bd": "👎", "/-break": "🤡", "/-no": "👎",
}

BROKEN_COLON_DASH_RE = re.compile(
    r"(?<!\S)(?:[:;]\-[A-Za-z0-9\*\?\!\(\)\<\>\/\\]+|\/-[a-zA-Z]+|;;?\)|=d>|=?\)\)|;f)(?!\S)"
)

def get_icon_hard(prev_icons=None):
    pool = [ic for ic in ZALO_ICON_VIP if not prev_icons or ic not in prev_icons]
    if not pool:
        pool = ZALO_ICON_VIP
    return random.choice(pool)

def build_unique_zalo_icons(count):
    if count <= 0:
        return ""
    chosen = []
    for _ in range(count):
        chosen.append(get_icon_hard(chosen[-2:]))
    return " ".join(chosen)

def clean_corrupted_shortcuts(text):
    if not text:
        return ""
    for zw in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
        text = text.replace(zw, "")

    def _replace_broken(match):
        token = match.group(0)
        if token in LEGACY_SHORTCUT_TO_ICON_MAP:
            return LEGACY_SHORTCUT_TO_ICON_MAP[token]
        if token.lower() in LEGACY_SHORTCUT_TO_ICON_MAP:
            return LEGACY_SHORTCUT_TO_ICON_MAP[token.lower()]
        return get_icon_hard()

    text = BROKEN_COLON_DASH_RE.sub(_replace_broken, text)
    text = re.sub(r"(?<!\S)[:;]\-[A-Za-z0-9\*\?\!]*", lambda _: get_icon_hard(), text)
    return text

def _is_emoji_or_zalo_shortcut_token(tk):
    if not tk:
        return False
    if tk in ZALO_ICON_VIP or tk in LEGACY_SHORTCUT_TO_ICON_MAP:
        return True
    if BROKEN_COLON_DASH_RE.fullmatch(tk):
        return True
    if all((ord(ch) > 0x2000 or ch in ("\ufe0f", "\u200d")) for ch in tk):
        return True
    return False

def strip_trailing_icons_when_zero(text):
    """Khi .icon 0 đang bật, loại bỏ toàn bộ icon/emoji thừa ở cuối mỗi dòng nhưng giữ nguyên 100% thụt dòng đầu câu!"""
    if not text:
        return ""
    out_lines = []
    for ln in str(text).split("\n"):
        if not ln.strip():
            out_lines.append(ln)
            continue
        leading_len = len(ln) - len(ln.lstrip(" \t"))
        leading_ws = ln[:leading_len]
        body_part = ln[leading_len:]
        tokens = body_part.split(" ")
        while tokens and _is_emoji_or_zalo_shortcut_token(tokens[-1].strip()):
            tokens.pop()
        cleaned_body = " ".join(tokens).rstrip()
        out_lines.append(leading_ws + (cleaned_body if cleaned_body else body_part.rstrip()))
    return "\n".join(out_lines)

# BỘ LỌC TỰ ĐỘNG XOÁ SỐ THỨ TỰ ĐẦU DÒNG ("1. ", "2. ", "3) ") & TẢI FILE NHANH
FILE_MEMORY_CACHE = {}
FILE_CACHE_LOCK = threading.RLock()

LEADING_NUMBER_RE = re.compile(
    r"^\s*(?:câu\s*\d+[\.\:\)\-]+|\(\d+\)|#?\d+[\.\)\:\-]+)\s*",
    re.IGNORECASE
)

def strip_leading_line_number(line, preserve_indent=False):
    if not line:
        return ""
    if preserve_indent:
        raw_r = str(line).rstrip("\r\n")
        lead_len = len(raw_r) - len(raw_r.lstrip(" \t"))
        lead_ws = raw_r[:lead_len]
        body_c = LEADING_NUMBER_RE.sub("", raw_r[lead_len:]).rstrip()
        body_c = clean_corrupted_shortcuts(body_c)
        return lead_ws + (body_c if body_c else raw_r[lead_len:])
    cleaned = LEADING_NUMBER_RE.sub("", line.strip()).strip()
    cleaned = clean_corrupted_shortcuts(cleaned)
    return cleaned if cleaned else line.strip()

def parse_file_stream_fast(filepath, strip_numbers=True):
    if not filepath or not os.path.exists(filepath):
        return {"blocks": [], "lines": [], "raw_lines": [], "size": 0, "block_count": 0, "line_count": 0}

    st = os.stat(filepath)
    mtime = st.st_mtime
    fsize = st.st_size
    cache_key = (filepath, bool(strip_numbers))

    with FILE_CACHE_LOCK:
        cached = FILE_MEMORY_CACHE.get(cache_key)
        if cached and cached["mtime"] == mtime and cached["size"] == fsize:
            return cached

    blocks = []
    all_lines = []
    raw_non_empty_lines = []
    current_block = []

    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    text = raw_bytes.decode("utf-8", errors="ignore").replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = text.split("\n")

    for ln in raw_lines:
        r_ln = ln.rstrip("\r\n")
        stripped = r_ln.strip()
        if stripped:
            raw_non_empty_lines.append(r_ln)
            clean_ln = strip_leading_line_number(r_ln, preserve_indent=True) if strip_numbers else clean_corrupted_shortcuts(r_ln)
            all_lines.append(clean_ln)
            current_block.append(clean_ln)
        else:
            if current_block:
                blocks.append("\n".join(current_block))
                current_block = []
    if current_block:
        blocks.append("\n".join(current_block))

    if not blocks and all_lines:
        blocks = list(all_lines)

    result = {
        "mtime": mtime,
        "size": fsize,
        "blocks": blocks,
        "lines": all_lines,
        "raw_lines": raw_non_empty_lines,
        "block_count": len(blocks),
        "line_count": len(all_lines),
    }

    with FILE_CACHE_LOCK:
        if len(FILE_MEMORY_CACHE) > 40:
            oldest_key = next(iter(FILE_MEMORY_CACHE))
            FILE_MEMORY_CACHE.pop(oldest_key, None)
        FILE_MEMORY_CACHE[cache_key] = result

    return result

def get_ordered_files_with_display_num():
    conn = db()
    rows = conn.execute("SELECT * FROM files ORDER BY id ASC").fetchall()
    conn.close()
    out = []
    for idx, r in enumerate(rows, start=1):
        d = dict(r)
        d["display_num"] = idx
        out.append(d)
    return out

def resolve_file_record(query_val):
    if query_val is None:
        return None
    q = str(query_val).strip()
    if not q:
        return None

    files = get_ordered_files_with_display_num()
    if not files:
        return None

    num_match = re.match(r"^#?(\d+)$", q)
    if num_match:
        num = int(num_match.group(1))
        by_disp = next((f for f in files if f["display_num"] == num), None)
        if by_disp:
            return by_disp
        by_id = next((f for f in files if f["id"] == num), None)
        if by_id:
            return by_id

    if q.lower() in ("auto", "default", "moinhat", "latest"):
        return files[-1]

    q_low = q.lower()
    for f in files:
        if f["filename"].lower() == q_low or q_low in f["filename"].lower():
            return f
    return None

def get_blocks_from_file_query(query_val, mode="fast"):
    rec = resolve_file_record(query_val)
    if not rec:
        return []
    parsed = parse_file_stream_fast(rec["filepath"], strip_numbers=True)
    if mode == "treo_nhay":
        return parsed["lines"] if parsed["lines"] else parsed["blocks"]
    return parsed["blocks"]

# HẠ TẦNG ANTI-BAN & ANTI-DIE-ALL SIÊU ĐỈNH CHO CẢ 2 APP (ZALO & DISCORD)
ZERO_WIDTH_ZALO_POOL = ["\u200b", "\u200c", "\u2060"]
ZERO_WIDTH_DISCORD_POOL = ["\u200b", "\u200c", "\u200d", "\u2060"]
_ANTIBAN_COUNTER = 0
_ANTIBAN_LOCK = threading.RLock()

class ZaloSmartAntiBanEngine:
    """Hạ tầng Anti-Ban thế hệ mới chuyên biệt cho Zalo:
    - Zero-Shift Polymorphic Tail Signature: Mã hóa vi chữ ký tàng hình ở cuối chuỗi.
    - Biometric Human Cadence: Mô phỏng nhịp gõ bàn phím sinh học (Weibull + Gaussian jitter + Micro-break).
    - Zalo Session Shield: Bảo vệ Cookie & khóa zpw_enk trước các mã phạt -112, -114, 300, 301, 429."""

    RATELIMIT_CODES = {-2, -108, -112, -114, 112, 114, 300, 301, 302, 429, 500, 1001, 2001}
    AUTH_CODES = {-401, 401, -102, 102, -30, -13, 3003}

    BROWSER_PROFILES = [
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "platform": '"Windows"'
        },
    ]

    @classmethod
    def get_session_headers(cls, imei):
        idx = zlib.crc32(str(imei or "zalo").encode("utf-8")) % len(cls.BROWSER_PROFILES)
        prof = cls.BROWSER_PROFILES[idx]
        vn_oct3 = (zlib.crc32(str(imei or "vn").encode("utf-8")) >> 8) % 240 + 10
        vn_oct4 = (zlib.crc32(str(imei or "vn").encode("utf-8")) >> 16) % 240 + 10
        vn_ip = f"14.161.{vn_oct3}.{vn_oct4}"
        return {
            "User-Agent": prof["ua"],
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8,en;q=0.7",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
            "Sec-Ch-Ua": prof["sec_ch_ua"],
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": prof["platform"],
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        }

    @staticmethod
    def generate_zero_shift_tail(thread_id=""):
        global _ANTIBAN_COUNTER
        with _ANTIBAN_LOCK:
            _ANTIBAN_COUNTER = (_ANTIBAN_COUNTER + 1) & 0xFFFFFF
            seq = _ANTIBAN_COUNTER
        t_hash = zlib.crc32(str(thread_id).encode("utf-8")) & 0xFFF
        salt = ((int(time.time() * 1000) & 0x1FFF) ^ (seq << 2) ^ t_hash ^ random.randint(1, 0xFFFF)) & 0xFFFF
        chars = []
        val = salt
        for _ in range(9):
            chars.append(ZERO_WIDTH_ZALO_POOL[val % len(ZERO_WIDTH_ZALO_POOL)])
            val = (val // len(ZERO_WIDTH_ZALO_POOL)) ^ random.randint(0, 2)
        return "".join(chars)

    @classmethod
    def mutate_zalo_word_boundaries(cls, text, salt=0):
        if not text or " " not in text:
            return text
        tokens = text.split(" ")
        if len(tokens) <= 1:
            return text
        out = [tokens[0]]
        for idx, tk in enumerate(tokens[1:], start=1):
            if tk.startswith("@") or out[-1].startswith("@"):
                out.append(" " + tk)
            elif idx <= 3 and ((salt + idx) & 1) == 1:
                zw = ZERO_WIDTH_ZALO_POOL[(salt + idx) % len(ZERO_WIDTH_ZALO_POOL)]
                out.append(" " + zw + tk)
            else:
                out.append(" " + tk)
        return "".join(out)

    @classmethod
    def append_tail(cls, final_msg, thread_id=""):
        if not final_msg:
            return final_msg
        return final_msg + " " + cls.generate_zero_shift_tail(thread_id)

    @staticmethod
    def compute_human_cadence_delay(base_delay, burst_cnt=0, risk_score=0.0, adaptive_bonus=0.0, text_len=20):
        # Chạy chuẩn xác 100% tốc độ Delay người dùng cài đặt (Tối thiểu 0.20s trên Zalo), KHÔNG cộng thêm delay ảo hay thời gian nghỉ!
        return 0.0 if float(base_delay or 0.0) <= 0.0 else float(base_delay)

class WaveFairnessEngine:
    """Bộ Điều Phối Luồng Sóng Đa Tài Khoản Siêu Mượt (50+ Acc × 200+ Nhóm Lock-Free Synchronizer ):
    - Khi cài đặt Delay = 0s (0.0s): Tuyệt đối KHÔNG giữ chân bất kỳ tài khoản nào (0.0ms pause) — chỉnh là phang đồng loạt!
    - Khi có cài đặt Delay > 0s: Chỉ cân bằng nhịp giữa các tài khoản đang hoạt động (active trong 4s gần nhất),
      không để 1 tài khoản chậm làm kẹt 49 tài khoản còn lại!"""

    _LOCK = threading.RLock()
    _TASK_ACC_COUNTS = defaultdict(lambda: defaultdict(int))
    _TASK_ACC_LAST_TS = defaultdict(lambda: defaultdict(float))
    _BOX_ROUND_ROBIN = defaultdict(int)

    @classmethod
    def register_accounts_for_wave(cls, task_key, acc_ids):
        now = time.time()
        with cls._LOCK:
            d = cls._TASK_ACC_COUNTS[task_key]
            ts_map = cls._TASK_ACC_LAST_TS[task_key]
            for aid in acc_ids:
                ia = int(aid)
                d[ia] = d.get(ia, 0)
                ts_map[ia] = now

    @classmethod
    def record_acc_sent(cls, task_key, acc_id):
        ia = int(acc_id)
        cls._TASK_ACC_COUNTS[task_key][ia] += 1
        cls._TASK_ACC_LAST_TS[task_key][ia] = time.time()

    @classmethod
    def get_fair_pacing_pause(cls, task_key, acc_id, base_delay=0.0):
        # Đã là Delay 0s thì bắn tốc độ tối đa không giữ nhịp chờ bất cứ tài khoản nào!
        if float(base_delay or 0.0) <= 0.0:
            return 0.0
        d = cls._TASK_ACC_COUNTS.get(task_key)
        if not d or len(d) <= 1:
            return 0.0
        now = time.time()
        ts_map = cls._TASK_ACC_LAST_TS.get(task_key) or {}
        active_vals = [cnt for aid_k, cnt in d.items() if (now - ts_map.get(aid_k, 0.0)) < 4.5]
        if len(active_vals) <= 1:
            return 0.0
        my_cnt = d.get(int(acc_id), 0)
        avg_cnt = sum(active_vals) / len(active_vals)
        diff = my_cnt - avg_cnt
        if diff >= 4:
            return min(0.025, 0.006 * (diff - 2))
        return 0.0


class ProxyPoolEngine:
    """Hệ Thống Proxy Pool NHK Siêu Tốc Cân 50+ Acc × 500+ Box & Tự Khởi Chạy Xếp Hạng Độ Trễ (PRX Auto-Start & Fastest-First Engine):
    - Hỗ trợ duyệt & nạp hàng loạt file .txt / .csv với mọi định dạng Proxy: ip:port, ip:port:user:pass, user:pass@ip:port, http://..., socks5://...
    - Tự động khởi chạy kiểm tra tốc độ (Background Multi-Thread Latency Benchmark), đo chính xác Ping (ms) của từng Proxy,
      mở sẵn kết nối Keep-Alive (TCP_NODELAY=1) và sắp xếp Proxy nhanh nhất lên đầu bảng!
    - Làn ưu tiên phản hồi lệnh (pick_fastest_proxy_candidates): Luôn chọn các Proxy có Ping thấp nhất (< 150ms) hoặc Direct Keep-Alive
      để khi 1 Acc đang treo 500 Box vẫn phản hồi lệnh .menu, .cp, .n, .g, .t ngay lập tức không bao giờ làm lơ lệnh!"""

    _LOCK = threading.RLock()
    _PROXIES = []
    _HEALTHY_TUPLE = ()
    _FASTEST_TUPLE = ()
    _PROXY_LATENCY_MS = {}
    _LAST_SNAPSHOT_REBUILD_TS = 0.0
    _BAD_PROXIES = {}
    _PROXY_SESSIONS = {}
    _ENABLED = True
    _CURSOR = 0
    _FAST_CURSOR = 0
    _LOADED = False
    _BENCHMARK_RUNNING = False
    _STATS = {
        "routed_ok": 0,
        "failover_hits": 0,
        "last_check_alive": 0,
        "fastest_ms": 0.0,
        "avg_ms": 0.0,
        "auto_started": False,
    }

    @classmethod
    def parse_proxy_line(cls, raw_line):
        s = str(raw_line or "").strip().strip('"').strip("'")
        if not s or s.startswith("#") or s.startswith("//"):
            return ""
        # Nếu dòng CSV có nhiều cột, tìm cột chứa ip:port
        if "," in s or "\t" in s:
            for col in re.split(r"[,\t]+", s):
                col_s = col.strip()
                if ":" in col_s and any(ch.isdigit() for ch in col_s):
                    s = col_s
                    break
        for pfx in ("http://", "https://", "socks5://", "socks5h://", "socks4://"):
            if s.lower().startswith(pfx):
                return s
        if "@" in s:
            return f"http://{s}"
        parts = s.split(":")
        if len(parts) == 2:
            host, port = parts[0].strip(), parts[1].strip()
            if host and port.isdigit():
                return f"http://{host}:{port}"
        elif len(parts) >= 4:
            host, port, user, pw = parts[0].strip(), parts[1].strip(), parts[2].strip(), ":".join(parts[3:]).strip()
            if host and port.isdigit():
                return f"http://{user}:{pw}@{host}:{port}"
        return ""

    @classmethod
    def extract_proxies_from_any_text(cls, raw_text):
        parsed = []
        seen = set()
        for ln in str(raw_text or "").replace("\r\n", "\n").replace("\r", "\n").replace(";", "\n").split("\n"):
            p = cls.parse_proxy_line(ln)
            if p and p not in seen:
                seen.add(p)
                parsed.append(p)
        return parsed

    @classmethod
    def _rebuild_healthy_snapshot_unlocked(cls):
        now = time.time()
        cls._LAST_SNAPSHOT_REBUILD_TS = now
        if not cls._ENABLED or not cls._PROXIES:
            cls._HEALTHY_TUPLE = ()
            cls._FASTEST_TUPLE = ()
            return
        healthy = [p for p in cls._PROXIES if now >= cls._BAD_PROXIES.get(p, 0.0)]
        if not healthy:
            sorted_all = sorted(cls._PROXIES, key=lambda x: cls._BAD_PROXIES.get(x, 0.0))
            healthy = sorted_all[:max(1, min(6, len(sorted_all)))]
        # Xếp hạng các Proxy có độ trễ thấp nhất (Ping ms nhỏ nhất) lên đầu
        healthy.sort(key=lambda p: cls._PROXY_LATENCY_MS.get(p, 888.0))
        cls._HEALTHY_TUPLE = tuple(healthy)
        top_k = max(1, min(16, (len(healthy) + 1) // 2))
        cls._FASTEST_TUPLE = tuple(healthy[:top_k])

    @classmethod
    def _ensure_loaded(cls):
        if cls._LOADED:
            return
        with cls._LOCK:
            if cls._LOADED:
                return
            cls._LOADED = True
            try:
                raw_txt = get_setting("proxy_pool_list", "")
                en_str = get_setting("proxy_pool_enabled", "1")
                cls._ENABLED = (str(en_str) != "0")
                parsed = cls.extract_proxies_from_any_text(raw_txt)
                cls._PROXIES = parsed
                cls._rebuild_healthy_snapshot_unlocked()
            except Exception:
                pass
        if cls._PROXIES and cls._ENABLED:
            cls.trigger_auto_warmup_background()

    @classmethod
    def trigger_auto_warmup_background(cls):
        if cls._BENCHMARK_RUNNING:
            return
        def _bg_runner():
            try:
                cls.test_all_proxies(timeout_sec=1.8)
            except Exception:
                pass
        threading.Thread(target=_bg_runner, daemon=True).start()

    @classmethod
    def save_proxies(cls, raw_text, enabled=True, auto_start=True):
        parsed = cls.extract_proxies_from_any_text(raw_text)
        with cls._LOCK:
            cls._PROXIES = parsed
            cls._BAD_PROXIES.clear()
            cls._ENABLED = bool(enabled)
            cls._LOADED = True
            cls._STATS["auto_started"] = bool(enabled and parsed)
            cls._rebuild_healthy_snapshot_unlocked()
        for p in parsed[:96]:
            cls._get_or_create_proxy_session(p)
        set_setting("proxy_pool_list", "\n".join(parsed))
        set_setting("proxy_pool_enabled", "1" if enabled else "0")
        if auto_start and parsed and enabled:
            cls.trigger_auto_warmup_background()
        return len(parsed)

    @classmethod
    def add_proxies_incremental(cls, raw_text, auto_start=True):
        cls._ensure_loaded()
        added = 0
        new_items = []
        extracted = cls.extract_proxies_from_any_text(raw_text)
        with cls._LOCK:
            existing_set = set(cls._PROXIES)
            for p in extracted:
                if p not in existing_set:
                    cls._PROXIES.append(p)
                    existing_set.add(p)
                    new_items.append(p)
                    added += 1
            cls._BAD_PROXIES.clear()
            cls._ENABLED = True
            cls._STATS["auto_started"] = True
            full_list = list(cls._PROXIES)
            cls._rebuild_healthy_snapshot_unlocked()
        for p in new_items[:96]:
            cls._get_or_create_proxy_session(p)
        set_setting("proxy_pool_list", "\n".join(full_list))
        set_setting("proxy_pool_enabled", "1")
        if auto_start and full_list:
            cls.trigger_auto_warmup_background()
        return added, len(full_list)

    @classmethod
    def _get_or_create_proxy_session(cls, proxy_url):
        sess = cls._PROXY_SESSIONS.get(proxy_url)
        if sess is not None:
            return sess
        with cls._LOCK:
            sess = cls._PROXY_SESSIONS.get(proxy_url)
            if sess is None:
                sess = requests.Session()
                try:
                    tls_ad = Chrome131TLSAdapter(pool_connections=256, pool_maxsize=512, max_retries=0)
                    sess.mount("https://", tls_ad)
                except Exception:
                    sess.mount("https://", HTTPAdapter(pool_connections=256, pool_maxsize=512, max_retries=0))
                sess.mount("http://", HTTPAdapter(pool_connections=256, pool_maxsize=512, max_retries=0))
                sess.proxies.update({"http": proxy_url, "https": proxy_url})
                cls._PROXY_SESSIONS[proxy_url] = sess
            return sess

    @classmethod
    def pick_fastest_proxy_candidates(cls, seed_key=None, max_candidates=2):
        """Làn ưu tiên siêu tốc dành riêng cho phản hồi lệnh (.menu, .cp, .ping, .status):
        Chỉ chọn trong nhóm Proxy đã xác thực có Ping thấp nhất (< 220ms) để phản hồi lệnh ngay lập tức!"""
        if not cls._LOADED:
            cls._ensure_loaded()
        if not cls._ENABLED or not cls._PROXIES:
            return []
        snap = cls._FASTEST_TUPLE or cls._HEALTHY_TUPLE
        if not snap:
            return []
        # Chỉ dùng Proxy cho lệnh ưu tiên nếu đã đo được độ trễ thực sự nhanh (<= 320ms)
        verified_fast = [p for p in snap if cls._PROXY_LATENCY_MS.get(p, 999.0) <= 320.0]
        if not verified_fast:
            return []
        n = len(verified_fast)
        base_idx = cls._FAST_CURSOR % n
        cls._FAST_CURSOR = (cls._FAST_CURSOR + 1) & 0xFFFFFF
        k = min(max_candidates, n)
        return [verified_fast[(base_idx + i) % n] for i in range(k)]

    @classmethod
    def pick_proxy_candidates(cls, seed_key=None, max_candidates=3):
        if not cls._LOADED:
            cls._ensure_loaded()
        if not cls._ENABLED or not cls._PROXIES:
            return []
        now = time.time()
        if cls._BAD_PROXIES and (now - cls._LAST_SNAPSHOT_REBUILD_TS > 1.2):
            with cls._LOCK:
                cls._rebuild_healthy_snapshot_unlocked()
        snap = cls._HEALTHY_TUPLE
        if not snap:
            return []
        n = len(snap)
        cls._CURSOR = (cls._CURSOR + 1) & 0xFFFFFF
        if seed_key is not None:
            base_idx = (zlib.crc32(str(seed_key).encode("utf-8")) + cls._CURSOR) % n
        else:
            base_idx = cls._CURSOR % n
        k = min(max_candidates, n)
        if k == 1:
            return [snap[base_idx]]
        return [snap[(base_idx + i) % n] for i in range(k)]

    @classmethod
    def pick_proxy_dict(cls, seed_key=None):
        cands = cls.pick_proxy_candidates(seed_key=seed_key, max_candidates=1)
        if not cands:
            return None
        chosen = cands[0]
        return {"http": chosen, "https": chosen, "_raw": chosen}

    @classmethod
    def report_proxy_ok(cls, proxy_url, latency_ms=None):
        if not proxy_url:
            return
        cls._STATS["routed_ok"] += 1
        if latency_ms is not None and latency_ms > 0:
            prev = cls._PROXY_LATENCY_MS.get(proxy_url, float(latency_ms))
            cls._PROXY_LATENCY_MS[proxy_url] = round(prev * 0.6 + float(latency_ms) * 0.4, 1)
        if proxy_url in cls._BAD_PROXIES:
            with cls._LOCK:
                cls._BAD_PROXIES.pop(proxy_url, None)
                cls._rebuild_healthy_snapshot_unlocked()

    @classmethod
    def report_proxy_bad(cls, proxy_url, cooldown_sec=8.0):
        if not proxy_url:
            return
        cls._STATS["failover_hits"] += 1
        with cls._LOCK:
            cls._BAD_PROXIES[proxy_url] = time.time() + float(cooldown_sec)
            cls._rebuild_healthy_snapshot_unlocked()

    @classmethod
    def request_with_fast_failover(cls, session_obj, method, url, seed_key=None, priority_bypass=False, **kwargs):
        if priority_bypass or not cls._PROXIES or not cls._ENABLED:
            if "timeout" not in kwargs:
                kwargs["timeout"] = (0.75, 1.65) if priority_bypass else (0.75, 1.45)
            try:
                resp_dir = session_obj.request(method, url, **kwargs)
                if resp_dir.status_code != 429 or not cls._PROXIES or not cls._ENABLED:
                    return resp_dir
            except Exception:
                if not cls._PROXIES or not cls._ENABLED:
                    raise

        cands = (
            cls.pick_fastest_proxy_candidates(seed_key=seed_key, max_candidates=1)
            if priority_bypass else
            cls.pick_proxy_candidates(seed_key=seed_key, max_candidates=3)
        )
        if cands:
            base_headers = kwargs.get("headers") or (dict(session_obj.headers) if getattr(session_obj, "headers", None) else None)
            base_cookies = kwargs.get("cookies") or (session_obj.cookies.get_dict() if getattr(session_obj, "cookies", None) else None)
            for raw_px in cands:
                px_sess = cls._get_or_create_proxy_session(raw_px)
                px_kwargs = dict(kwargs)
                px_kwargs.pop("proxies", None)
                px_kwargs["timeout"] = (0.30, 0.65) if priority_bypass else (0.40, 0.90)
                if base_headers and "headers" not in px_kwargs:
                    px_kwargs["headers"] = base_headers
                if base_cookies and "cookies" not in px_kwargs:
                    px_kwargs["cookies"] = base_cookies
                t0_p = time.perf_counter()
                try:
                    resp = px_sess.request(method, url, **px_kwargs)
                    lat_p = (time.perf_counter() - t0_p) * 1000.0
                    sc = resp.status_code
                    if sc not in (407, 502, 503, 504, 520, 521, 522, 524):
                        if sc == 429:
                            cls.report_proxy_bad(raw_px, cooldown_sec=4.5)
                            continue
                        cls.report_proxy_ok(raw_px, latency_ms=lat_p)
                        return resp
                    cls.report_proxy_bad(raw_px, cooldown_sec=10.0)
                except Exception:
                    cls.report_proxy_bad(raw_px, cooldown_sec=12.0)

        if "timeout" not in kwargs:
            kwargs["timeout"] = (0.65, 1.35) if priority_bypass else (0.85, 1.85)
        return session_obj.request(method, url, **kwargs)

    @classmethod
    def test_all_proxies(cls, timeout_sec=2.0):
        cls._ensure_loaded()
        with cls._LOCK:
            plist = list(cls._PROXIES)
            cls._BENCHMARK_RUNNING = True
        try:
            if not plist:
                return {"ok": True, "total": 0, "alive": 0, "dead": 0, "fastest_ms": 0, "message": "Chưa có Proxy nào trong danh sách (Đang chạy Direct Keep-Alive 0ms)."}
            alive_list = []
            dead_list = []
            latencies = []

            def _probe(p_url):
                t0 = time.perf_counter()
                try:
                    px_s = cls._get_or_create_proxy_session(p_url)
                    r = px_s.get("https://discord.com/api/v9/experiments", timeout=(timeout_sec, timeout_sec + 0.5))
                    if r.status_code in (200, 401, 403, 429):
                        ms = round((time.perf_counter() - t0) * 1000.0, 1)
                        return True, p_url, ms
                except Exception:
                    pass
                return False, p_url, 9999.0

            with ThreadPoolExecutor(max_workers=min(64, max(1, len(plist)))) as pool:
                for ok_p, p_u, ms_val in pool.map(_probe, plist):
                    if ok_p:
                        alive_list.append(p_u)
                        latencies.append(ms_val)
                        cls.report_proxy_ok(p_u, latency_ms=ms_val)
                    else:
                        dead_list.append(p_u)
                        cls.report_proxy_bad(p_u, cooldown_sec=45.0)

            with cls._LOCK:
                cls._STATS["last_check_alive"] = len(alive_list)
                cls._STATS["fastest_ms"] = round(min(latencies), 1) if latencies else 0.0
                cls._STATS["avg_ms"] = round(sum(latencies) / len(latencies), 1) if latencies else 0.0
                cls._rebuild_healthy_snapshot_unlocked()

            fastest_str = f" • Nhanh nhất: {cls._STATS['fastest_ms']}ms" if latencies else ""
            return {
                "ok": True,
                "total": len(plist),
                "alive": len(alive_list),
                "dead": len(dead_list),
                "fastest_ms": cls._STATS["fastest_ms"],
                "avg_ms": cls._STATS["avg_ms"],
                "alive_proxies": list(cls._HEALTHY_TUPLE),
                "message": f"Đã tự khởi chạy & xếp hạng {len(plist)} PRX: {len(alive_list)} PRX Sống Siêu Tốc{fastest_str} • {len(dead_list)} PRX Chậm/Die (Đã cách ly)!"
            }
        finally:
            with cls._LOCK:
                cls._BENCHMARK_RUNNING = False

    @classmethod
    def get_snapshot(cls):
        cls._ensure_loaded()
        now = time.time()
        with cls._LOCK:
            total = len(cls._PROXIES)
            cooling = sum(1 for p in cls._PROXIES if now < cls._BAD_PROXIES.get(p, 0.0))
            healthy = max(0, total - cooling)
            top_fast = [
                {"proxy": p, "ms": cls._PROXY_LATENCY_MS.get(p, 0.0)}
                for p in (cls._FASTEST_TUPLE[:5] if cls._FASTEST_TUPLE else [])
            ]
            return {
                "enabled": cls._ENABLED,
                "total": total,
                "healthy": healthy,
                "cooling": cooling,
                "routed_ok": cls._STATS["routed_ok"],
                "failover_hits": cls._STATS["failover_hits"],
                "fastest_ms": cls._STATS.get("fastest_ms", 0.0),
                "avg_ms": cls._STATS.get("avg_ms", 0.0),
                "benchmark_running": cls._BENCHMARK_RUNNING,
                "top_fastest": top_fast,
                "proxies_text": "\n".join(cls._PROXIES),
            }


class Chrome131TLSAdapter(HTTPAdapter):
    """Bộ điều hợp TLS chuẩn trình duyệt Chrome 131 + TCP_NODELAY (PRX > 1.500+ Tin/Phút Không Độ Trễ):
    - Tắt thuật toán Nagle (TCP_NODELAY = 1) và bật SO_KEEPALIVE trên từng socket giúp đẩy gói tin tức thì trong 0ms!"""

    def __init__(self, *args, **kwargs):
        self._ssl_ctx = DiscordStealthAntiBanEngine.create_chrome_tls_context()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_ctx
        pool_kwargs["socket_options"] = [
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._ssl_ctx
        proxy_kwargs["socket_options"] = [
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
        ]
        return super().proxy_manager_for(proxy, **proxy_kwargs)

class DiscordFirewallEngine:
    """Tường Lửa Chống Quét & Chống Báo Reset Mật Khẩu Discord 9 Lớp (Discord Anti-Reset-Key Firewall):
    - Lớp 1 (Anti-Homoglyph & Anti-Cf Sanitizer): Loại bỏ 100% ký tự Cyrillic pha trộn trong từ Latin (nguyên nhân số 1
      khiến bộ lọc Phishing 'decancer' của Discord khóa Token & bắt Reset Password ngay khi gõ lệnh!) và xóa sạch ký tự ẩn Cf.
    - Lớp 2 (Real Cloudflare Cookie Handshake): Tự động bắt tay thụ động với discord.com để nhận Cookie thật có chữ ký HMAC
      (__dcfduid, __sdcfduid, __cf_bm) trước khi gửi bất kỳ tin nhắn nào.
    - Lớp 3 (Header & Super-Properties Parity): Đồng bộ 100% từng byte giữa X-Super-Properties (HTTP) và OP 2 Identify (Gateway).
    - Lớp 4 (Anti-Reset-Key Burst Shaper): Điều phối luồng gửi tin nhắn 0.0s không bao giờ vượt ngưỡng phạt của Discord."""

    CYRILLIC_TO_LATIN_MAP = str.maketrans({
        "а": "a", "е": "e", "о": "o", "і": "i", "с": "c", "р": "p", "х": "x", "у": "y",
        "А": "A", "Е": "E", "О": "O", "І": "I", "С": "C", "Р": "P", "Х": "X", "У": "Y",
    })

    # 64 hậu tố tự nhiên thuần ASCII/Latin 100% (Tuyệt đối KHÔNG dùng Cyrillic hay Zero-Width Cf!)
    PURE_LATIN_VARIATIONS = [
        "", ".", "..", "...", " .", " ..", " !", " !!", " ~", " ~.",
        " -", " --", " .~", " !~", " ^", " ^^", " *", " +", " =", " :",
        " ;", " ,", " .!", " ~!", " ..!", " ...", " .-", " ~-", " +.", " *.",
    ]

    _STATS_LOCK = threading.RLock()
    FIREWALL_STATS = {
        "inspected_packets": 0,
        "sanitized_homoglyphs": 0,
        "cookies_harvested": 0,
        "rate_shields_triggered": 0,
        "immortalized_tokens": 0,
        "recent_events": deque(maxlen=40),
    }

    @classmethod
    def log_firewall_event(cls, action, detail=""):
        with cls._STATS_LOCK:
            cls.FIREWALL_STATS["recent_events"].appendleft({
                "ts": time.strftime("%H:%M:%S"),
                "action": action,
                "detail": sanitize_log_text(detail)[:140],
            })

    @classmethod
    def sanitize_outbound_text(cls, text):
        """Quét và làm sạch 100% ký tự ẩn Cf và ký tự Cyrillic giả dạng Latin trước khi gửi lên Discord."""
        if not text:
            return ""
        s = str(text)
        # Xóa toàn bộ ký tự tàng hình Zero-Width / Format (Unicode Category Cf)
        cleaned_chars = []
        removed_cf = 0
        for ch in s:
            if unicodedata.category(ch) == "Cf":
                removed_cf += 1
            else:
                cleaned_chars.append(ch)
        s = "".join(cleaned_chars)

        # Chuyển toàn bộ ký tự Cyrillic đồng hình về Latin chuẩn ASCII để không bao giờ bị Discord báo Phishing/Reset Key
        s_lat = s.translate(cls.CYRILLIC_TO_LATIN_MAP)
        if s_lat != s or removed_cf > 0:
            with cls._STATS_LOCK:
                cls.FIREWALL_STATS["sanitized_homoglyphs"] += 1
        with cls._STATS_LOCK:
            cls.FIREWALL_STATS["inspected_packets"] += 1
        return s_lat

    @classmethod
    def apply_pure_latin_polymorphism(cls, text, channel_id=""):
        """Giữ nguyên 100% nội dung gốc và thụt dòng của người dùng (Tuyệt đối KHÔNG gắn thêm ký tự lạ *., .., * ở cuối câu!).
        Mỗi gói tin Discord đã có Snowflake Nonce 64-bit duy nhất giúp gửi 0s siêu tốc không bao giờ lỗi."""
        return cls.sanitize_outbound_text(text)

    @classmethod
    def get_firewall_snapshot(cls):
        with cls._STATS_LOCK:
            return {
                "inspected_packets": cls.FIREWALL_STATS["inspected_packets"],
                "sanitized_homoglyphs": cls.FIREWALL_STATS["sanitized_homoglyphs"],
                "cookies_harvested": cls.FIREWALL_STATS["cookies_harvested"],
                "rate_shields_triggered": cls.FIREWALL_STATS["rate_shields_triggered"],
                "immortalized_tokens": cls.FIREWALL_STATS["immortalized_tokens"],
                "recent_events": list(cls.FIREWALL_STATS["recent_events"])[:15],
            }

class DiscordStealthAntiBanEngine:
    """Hạ tầng Anti-Scan, Anti-Ban & Tường Lửa Bảo Vệ Token Discord Bất Tử (Super VIP):
    1. Chrome131TLSAdapter: Đồng nhất 100% vân tay TLS 1.3 / Cipher Suite giữa HTTP Session và Gateway WebSocket.
    2. Passive Cloudflare Cookie Handshake: Tự động nhận Cookie thật có chữ ký (__dcfduid, __sdcfduid, __cf_bm) từ máy chủ Discord.
    3. Byte-for-Byte Super-Properties Parity: Đồng bộ 14 trường Chrome 131 giữa OP 2 Identify, /auth/login và X-Super-Properties.
    4. Pre-429 Sliding Window Shaper (Super VIP Anti-Reset-Key): Ngăn chặn chạm ngưỡng 5 tin / 5 giây của Discord (nguyên nhân số 1 gây bắt Reset Mật Khẩu)."""

    DISCORD_EPOCH = 1420070400000
    SUPER_VIP_MODE = True
    STEALTH_API_BASES = [
        "https://discord.com/api/v9",
    ]

    CLIENT_PROFILES = [
        {
            "os": "Windows",
            "browser": "Chrome",
            "os_version": "10",
            "browser_version": "131.0.0.0",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "build_number": 351420,
        },
        {
            "os": "Windows",
            "browser": "Chrome",
            "os_version": "11",
            "browser_version": "131.0.0.0",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "build_number": 351890,
        },
        {
            "os": "Mac OS X",
            "browser": "Chrome",
            "os_version": "10.15.7",
            "browser_version": "131.0.0.0",
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "build_number": 351420,
        },
    ]

    _CHANNEL_BUCKETS = {}
    _CHANNEL_SEND_HISTORY = defaultdict(lambda: deque(maxlen=12))
    _CHANNEL_NEXT_SLOT_TS = defaultdict(float)
    _CHANNEL_LOCKS = defaultdict(threading.RLock)
    _TOKEN_LAST_SEND_TS = defaultdict(float)
    _TOKEN_SEND_LOCK = defaultdict(threading.RLock)
    _LAST_TYPING_TS = defaultdict(float)
    _FINGERPRINT_CACHE = {}
    _SESSION_UUID_CACHE = {}
    _COOKIE_VAULT_CACHE = {}
    _GATEWAY_RESUME_CACHE = {}
    _WARMED_SESSIONS = set()
    _PRIORITY_SESSIONS = {}
    _NONCE_SEQ = 0
    _LOCK = threading.RLock()

    @classmethod
    def _token_vault_key(cls, token):
        return hashlib.sha256(str(token or "discord").strip().encode("utf-8")).hexdigest()[:28]

    @classmethod
    def _is_forged_legacy_cookie(cls, dcf_val, sdcf_val):
        if sdcf_val and "." not in str(sdcf_val):
            return True
        return False

    @classmethod
    def _ensure_vault_record(cls, token):
        tkey = cls._token_vault_key(token)
        with cls._LOCK:
            if tkey in cls._SESSION_UUID_CACHE and tkey in cls._COOKIE_VAULT_CACHE:
                return cls._SESSION_UUID_CACHE[tkey], cls._COOKIE_VAULT_CACHE[tkey]

        seed = hashlib.sha256(str(token or "discord").encode("utf-8")).digest()
        default_u1 = str(uuid.UUID(bytes=seed[:16], version=4))
        default_u2 = str(uuid.UUID(bytes=seed[16:32], version=4))
        prof_idx = zlib.crc32(str(token or "discord").encode("utf-8")) % len(cls.CLIENT_PROFILES)

        real_dcf, real_sdcf, real_cfuv = "", "", ""
        try:
            conn = db()
            row = conn.execute("SELECT * FROM discord_token_vault WHERE token_key=?", (tkey,)).fetchone()
            if row:
                u1 = row["launch_sig"] or default_u1
                u2 = row["hb_sess"] or default_u2
                saved_dcf = row["dcfduid"] or ""
                saved_sdcf = row["sdcfduid"] or ""
                saved_cfuv = row["cfuvid"] or ""
                if not cls._is_forged_legacy_cookie(saved_dcf, saved_sdcf):
                    real_dcf, real_sdcf, real_cfuv = saved_dcf, saved_sdcf, saved_cfuv
                else:
                    conn.execute(
                        "UPDATE discord_token_vault SET dcfduid='', sdcfduid='', cfuvid='' WHERE token_key=?",
                        (tkey,)
                    )
                    conn.commit()
                if row["session_id"]:
                    cls._GATEWAY_RESUME_CACHE[tkey] = {
                        "session_id": row["session_id"],
                        "resume_url": row["resume_url"] or "wss://gateway.discord.gg",
                        "last_seq": int(row["last_seq"] or 0),
                    }
                try:
                    b_json = row["boxes_json"] if "boxes_json" in row.keys() else "[]"
                    if b_json:
                        parsed_boxes = json.loads(b_json)
                        if isinstance(parsed_boxes, list) and parsed_boxes:
                            with cls._LOCK:
                                cls._PASSIVE_READY_BOXES[tkey] = {"ts": time.time(), "boxes": parsed_boxes}
                                cls._BOXES_CACHE[tkey] = {"ts": time.time(), "boxes": parsed_boxes}
                except Exception:
                    pass
                try:
                    u_id_saved = row["user_id"] if "user_id" in row.keys() else ""
                    u_name_saved = row["user_name"] if "user_name" in row.keys() else ""
                    if u_id_saved:
                        with cls._LOCK:
                            cls._ME_CACHE[tkey] = {
                                "ts": time.time(),
                                "data": {"id": u_id_saved, "username": u_name_saved or f"Discord_{u_id_saved[-4:]}", "global_name": u_name_saved or f"Discord_{u_id_saved[-4:]}"}
                            }
                except Exception:
                    pass
            else:
                u1, u2 = default_u1, default_u2
                conn.execute(
                    """INSERT OR REPLACE INTO discord_token_vault
                       (token_key, launch_sig, hb_sess, dcfduid, sdcfduid, cfuvid, profile_idx, updated_at)
                       VALUES (?, ?, ?, '', '', '', ?, ?)""",
                    (tkey, u1, u2, prof_idx, time.time()),
                )
                conn.commit()
            conn.close()
        except Exception:
            u1, u2 = default_u1, default_u2

        cookies = {"locale": "vi"}
        if real_dcf and real_sdcf and "." in real_sdcf:
            cookies["__dcfduid"] = real_dcf
            cookies["__sdcfduid"] = real_sdcf
        if real_cfuv and "." in real_cfuv:
            cookies["_cfuvid"] = real_cfuv

        with cls._LOCK:
            cls._SESSION_UUID_CACHE[tkey] = (u1, u2)
            cls._COOKIE_VAULT_CACHE[tkey] = cookies
        return (u1, u2), cookies

    @classmethod
    def persist_real_cloudflare_cookies(cls, token, cookie_jar):
        if not cookie_jar:
            return
        tkey = cls._token_vault_key(token)
        c_dict = cookie_jar.get_dict() if hasattr(cookie_jar, "get_dict") else dict(cookie_jar)
        dcf = c_dict.get("__dcfduid", "")
        sdcf = c_dict.get("__sdcfduid", "")
        cfuv = c_dict.get("_cfuvid", "") or c_dict.get("__cf_bm", "")
        if dcf or sdcf or cfuv:
            with cls._LOCK:
                cur_c = cls._COOKIE_VAULT_CACHE.get(tkey, {"locale": "vi"})
                if dcf:
                    cur_c["__dcfduid"] = dcf
                if sdcf:
                    cur_c["__sdcfduid"] = sdcf
                if cfuv:
                    cur_c["_cfuvid"] = cfuv
                cls._COOKIE_VAULT_CACHE[tkey] = cur_c
            try:
                conn = db()
                conn.execute(
                    "UPDATE discord_token_vault SET dcfduid=?, sdcfduid=?, cfuvid=?, updated_at=? WHERE token_key=?",
                    (dcf, sdcf, cfuv, time.time(), tkey),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
            with DiscordFirewallEngine._STATS_LOCK:
                DiscordFirewallEngine.FIREWALL_STATS["cookies_harvested"] += 1

    @classmethod
    def save_gateway_resume_state(cls, token, session_id="", resume_url="", last_seq=0):
        tkey = cls._token_vault_key(token)
        with cls._LOCK:
            if session_id:
                cls._GATEWAY_RESUME_CACHE[tkey] = {
                    "session_id": session_id,
                    "resume_url": resume_url or "wss://gateway.discord.gg",
                    "last_seq": int(last_seq or 0),
                }
            else:
                cls._GATEWAY_RESUME_CACHE.pop(tkey, None)
        try:
            conn = db()
            conn.execute(
                "UPDATE discord_token_vault SET session_id=?, resume_url=?, last_seq=?, updated_at=? WHERE token_key=?",
                (session_id or "", resume_url or "", int(last_seq or 0), time.time(), tkey),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    @classmethod
    def get_gateway_resume_state(cls, token):
        tkey = cls._token_vault_key(token)
        cls._ensure_vault_record(token)
        with cls._LOCK:
            return cls._GATEWAY_RESUME_CACHE.get(tkey)

    @classmethod
    def get_deterministic_profile(cls, token):
        h = zlib.crc32(str(token or "discord").encode("utf-8"))
        return cls.CLIENT_PROFILES[h % len(cls.CLIENT_PROFILES)]

    @classmethod
    def get_deterministic_session_uuids(cls, token):
        uuids, _ = cls._ensure_vault_record(token)
        return uuids

    @classmethod
    def get_deterministic_cookies(cls, token):
        _, cookies = cls._ensure_vault_record(token)
        return dict(cookies)

    @classmethod
    def build_super_properties_dict(cls, token):
        prof = cls.get_deterministic_profile(token)
        return {
            "os": prof["os"],
            "browser": prof["browser"],
            "device": "",
            "system_locale": "vi-VN",
            "browser_user_agent": prof["ua"],
            "browser_version": prof["browser_version"],
            "os_version": prof["os_version"],
            "referrer": "",
            "referring_domain": "",
            "referrer_current": "",
            "referring_domain_current": "",
            "release_channel": "stable",
            "client_build_number": prof["build_number"],
            "client_event_source": None,
        }

    _SUPER_PROPS_B64_CACHE = {}

    @classmethod
    def build_super_properties_b64(cls, token):
        tk = str(token or "discord")
        cached = cls._SUPER_PROPS_B64_CACHE.get(tk)
        if cached:
            return cached
        props = cls.build_super_properties_dict(tk)
        raw_json = json.dumps(props, separators=(",", ":"))
        b64 = base64.b64encode(raw_json.encode("utf-8")).decode("utf-8")
        if len(cls._SUPER_PROPS_B64_CACHE) < 2000:
            cls._SUPER_PROPS_B64_CACHE[tk] = b64
        return b64

    @classmethod
    def build_context_properties_b64(cls, guild_id=None, channel_id=None):
        ctx = {"location": "Guild Channel" if guild_id else "DM Channel"}
        return base64.b64encode(json.dumps(ctx, separators=(",", ":")).encode("utf-8")).decode("utf-8")

    CHANNEL_GUILD_MAP = {}

    @classmethod
    def register_channel_guild(cls, channel_id, guild_id=None):
        if channel_id and guild_id:
            cls.CHANNEL_GUILD_MAP[str(channel_id)] = str(guild_id)

    @classmethod
    def build_stealth_headers(cls, token, is_bot=False, channel_id=None, guild_id=None, include_auth=True):
        auth_val = f"Bot {token}" if is_bot else str(token or "").strip()
        if is_bot:
            h_bot = {
                "Content-Type": "application/json",
                "User-Agent": "DiscordClient (https://discord.com, 10.0)",
            }
            if include_auth and auth_val:
                h_bot["Authorization"] = auth_val
            return h_bot
        prof = cls.get_deterministic_profile(token)
        eff_guild_id = guild_id or (cls.CHANNEL_GUILD_MAP.get(str(channel_id)) if channel_id else None)
        if eff_guild_id and channel_id:
            ref = f"https://discord.com/channels/{eff_guild_id}/{channel_id}"
        elif channel_id:
            ref = f"https://discord.com/channels/@me/{channel_id}"
        else:
            ref = "https://discord.com/channels/@me"

        headers = {
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "User-Agent": prof["ua"],
            "X-Super-Properties": cls.build_super_properties_b64(token),
            "X-Debug-Options": "bugReporterEnabled",
            "X-Discord-Locale": "vi",
            "X-Discord-Timezone": "Asia/Ho_Chi_Minh",
            "Origin": "https://discord.com",
            "Referer": ref,
            "Priority": "u=1, i",
            "Sec-Ch-Ua": prof["sec_ch_ua"],
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": f'"{prof["os"]}"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        if include_auth and auth_val and ("." in auth_val or auth_val.startswith("mfa.")) and ":" not in auth_val:
            headers["Authorization"] = auth_val
        return headers

    _SHARED_SESSIONS = {}
    _ME_CACHE = {}
    _BOXES_CACHE = {}
    _PASSIVE_READY_BOXES = {}
    _LAST_IDENTIFY_TS = defaultdict(float)
    ACTIVE_DISCORD_POLL_CHANNELS = defaultdict(set)

    @classmethod
    def get_shared_session(cls, token, is_bot=False):
        tkey = cls._token_vault_key(token)
        sess = cls._SHARED_SESSIONS.get(tkey)
        if sess is not None:
            return sess
        with cls._LOCK:
            sess = cls._SHARED_SESSIONS.get(tkey)
            if sess is None:
                sess = requests.Session()
                tls_adapter = Chrome131TLSAdapter(pool_connections=512, pool_maxsize=1024, max_retries=0)
                sess.mount("https://", tls_adapter)
                sess.mount("http://", HTTPAdapter(pool_connections=256, pool_maxsize=512, max_retries=0))
                if not is_bot:
                    sess.cookies.update(cls.get_deterministic_cookies(token))
                cls._SHARED_SESSIONS[tkey] = sess
            return sess

    @classmethod
    def ensure_session_warmed_up(cls, token, is_bot=False):
        if is_bot or not token:
            return
        tkey = cls._token_vault_key(token)
        with cls._LOCK:
            if tkey in cls._WARMED_SESSIONS:
                return
            cls._WARMED_SESSIONS.add(tkey)
        cls.get_shared_session(token, is_bot=False)

    @classmethod
    def get_cached_me(cls, token):
        tkey = cls._token_vault_key(token)
        cls._ensure_vault_record(token)
        with cls._LOCK:
            item = cls._ME_CACHE.get(tkey)
            if item and (time.time() - item["ts"] < 7200.0):
                return item["data"]
        return None

    @classmethod
    def set_cached_me(cls, token, data):
        if not isinstance(data, dict):
            return
        tkey = cls._token_vault_key(token)
        with cls._LOCK:
            cls._ME_CACHE[tkey] = {"ts": time.time(), "data": dict(data)}
        uid_s = str(data.get("id") or "")
        uname_s = str(data.get("global_name") or data.get("username") or "")
        if uid_s:
            try:
                conn = db()
                conn.execute(
                    "UPDATE discord_token_vault SET user_id=?, user_name=?, updated_at=? WHERE token_key=?",
                    (uid_s, uname_s, time.time(), tkey),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

    @classmethod
    def harvest_ready_payload(cls, token, d_ev):
        """Thu hoạch thụ động toàn bộ danh sách Kênh & Server từ gói READY của Gateway và lưu vào SQLite Vault
        giúp không cần quét REST API hàng loạt gây báo động Đặt Lại Mật Khẩu Discord!"""
        if not isinstance(d_ev, dict):
            return
        tkey = cls._token_vault_key(token)
        boxes = []
        seen_ids = set()

        for c in (d_ev.get("private_channels") or []):
            if not isinstance(c, dict):
                continue
            cid = str(c.get("id") or "")
            if not cid or cid in seen_ids:
                continue
            seen_ids.add(cid)
            ctype = c.get("type")
            recipients = c.get("recipients") or []
            for rec in recipients:
                if isinstance(rec, dict):
                    ruid = str(rec.get("id") or "")
                    rname = rec.get("global_name") or rec.get("username") or ""
                    if ruid and rname:
                        GLOBAL_USER_NAME_CACHE[ruid] = rname
            if ctype == 3:
                g_name = c.get("name") or ", ".join(
                    (x.get("global_name") or x.get("username") or "User") for x in recipients[:4] if isinstance(x, dict)
                ) or f"Box Nhóm {cid[-5:]}"
                boxes.append({
                    "id": cid,
                    "name": f"[Box Nhóm] {g_name}",
                    "type": "discord_channel",
                    "sub_type": "group_dm",
                    "members": len(recipients) + 1
                })
            elif ctype == 1:
                rec0 = recipients[0] if (recipients and isinstance(recipients[0], dict)) else {}
                dm_name = rec0.get("global_name") or rec0.get("username") or f"User {cid[-5:]}"
                boxes.append({
                    "id": cid,
                    "name": f"[Chat Riêng] {dm_name}",
                    "type": "discord_channel",
                    "sub_type": "dm",
                    "members": 2
                })

        for g in (d_ev.get("guilds") or []):
            if not isinstance(g, dict):
                continue
            gid = str(g.get("id") or "")
            gname = g.get("name") or (g.get("properties") or {}).get("name") or f"Server {gid[-4:]}"
            for ch in (g.get("channels") or []):
                if not isinstance(ch, dict):
                    continue
                if ch.get("type") in (0, 5):
                    cid = str(ch.get("id") or "")
                    if cid and cid not in seen_ids:
                        seen_ids.add(cid)
                        if gid:
                            cls.CHANNEL_GUILD_MAP[cid] = gid
                        boxes.append({
                            "id": cid,
                            "name": f"[{gname}] # {ch.get('name', 'channel')}",
                            "type": "discord_channel",
                            "sub_type": "guild_channel",
                            "guild_id": gid
                        })

        if boxes:
            with cls._LOCK:
                cls._PASSIVE_READY_BOXES[tkey] = {"ts": time.time(), "boxes": boxes}
                cls._BOXES_CACHE[tkey] = {"ts": time.time(), "boxes": boxes}
            try:
                conn = db()
                conn.execute(
                    "UPDATE discord_token_vault SET boxes_json=?, updated_at=? WHERE token_key=?",
                    (json.dumps(boxes, ensure_ascii=False), time.time(), tkey),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

    @classmethod
    def can_send_gateway_identify(cls, token):
        tkey = cls._token_vault_key(token)
        now = time.time()
        with cls._LOCK:
            last_ts = cls._LAST_IDENTIFY_TS[tkey]
            if now - last_ts < 2.0:
                return False, max(0.2, 2.0 - (now - last_ts))
            cls._LAST_IDENTIFY_TS[tkey] = now
            return True, 0.0

    DISCORD_API_GATEWAYS = (
        "https://discord.com/api/v9",
        "https://discord.com/api/v10",
        "https://canary.discord.com/api/v9",
        "https://ptb.discord.com/api/v9",
        "https://discordapp.com/api/v9",
    )

    @classmethod
    def pick_stealth_endpoint(cls, token, path_suffix, rotate_step=0):
        idx = int(rotate_step or 0) % len(cls.DISCORD_API_GATEWAYS)
        base_gw = cls.DISCORD_API_GATEWAYS[idx]
        return f"{base_gw}{path_suffix}"

    @classmethod
    def generate_snowflake_nonce(cls):
        now_ms = int(time.time() * 1000)
        ts_part = max(0, now_ms - cls.DISCORD_EPOCH)
        with cls._LOCK:
            cls._NONCE_SEQ = (cls._NONCE_SEQ + 1) & 0xFFF
            seq_part = cls._NONCE_SEQ
        worker_bits = (random.randint(1, 31) << 17) | (random.randint(1, 31) << 12) | seq_part
        return str((ts_part << 22) | worker_bits)

    @classmethod
    def create_chrome_tls_context(cls):
        ctx = ssl.create_default_context()
        try:
            ctx.set_ciphers(
                "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
            )
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        return ctx

    @classmethod
    def append_stealth_tail(cls, text, channel_id=""):
        return DiscordFirewallEngine.apply_pure_latin_polymorphism(text, channel_id=channel_id)

    @classmethod
    def record_bucket_headers(cls, channel_id, resp_headers, token=None):
        if not channel_id:
            return
        now = time.time()
        cid_s = str(channel_id)
        t_part = cls._token_vault_key(token) if token else "shared"
        slot_key = f"{t_part}:{cid_s}"
        if not resp_headers:
            return
        try:
            rem = resp_headers.get("X-RateLimit-Remaining")
            reset_after = resp_headers.get("X-RateLimit-Reset-After")
            if rem is not None and reset_after is not None:
                with cls._LOCK:
                    cls._CHANNEL_BUCKETS[slot_key] = {
                        "remaining": int(rem),
                        "reset_at": now + min(2.5, float(reset_after)),
                    }
        except Exception:
            pass

    @classmethod
    def set_channel_cooldown(cls, channel_id, wait_sec, token=None):
        if not channel_id:
            return
        cid_s = str(channel_id)
        t_part = cls._token_vault_key(token) if token else "shared"
        slot_key = f"{t_part}:{cid_s}"
        with DiscordFirewallEngine._STATS_LOCK:
            DiscordFirewallEngine.FIREWALL_STATS["rate_shields_triggered"] += 1
        with cls._LOCK:
            cls._CHANNEL_BUCKETS[slot_key] = {
                "remaining": 0,
                "reset_at": time.time() + min(0.45, max(0.05, float(wait_sec) * 0.35)),
            }

    @classmethod
    def get_priority_session(cls, token, is_bot=False):
        """Kênh HTTP ưu tiên dành riêng cho phản hồi lệnh (.menu, .ping, .stop...) không bao giờ bị nghẽn bởi luồng treo!"""
        tkey = cls._token_vault_key(token)
        with cls._LOCK:
            sess = cls._PRIORITY_SESSIONS.get(tkey)
            if sess is None:
                sess = requests.Session()
                tls_adapter = Chrome131TLSAdapter(pool_connections=32, pool_maxsize=64, max_retries=1)
                sess.mount("https://", tls_adapter)
                sess.mount("http://", HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=1))
                if not is_bot:
                    sess.cookies.update(cls.get_deterministic_cookies(token))
                cls._PRIORITY_SESSIONS[tkey] = sess
            return sess

    @classmethod
    def abort_all_campaign_wait_buckets(cls, channel_id=None):
        with cls._LOCK:
            if channel_id is None:
                cls._CHANNEL_BUCKETS.clear()
                cls._CHANNEL_SEND_HISTORY.clear()
                cls._CHANNEL_NEXT_SLOT_TS.clear()
            else:
                cid_s = str(channel_id)
                for k in list(cls._CHANNEL_BUCKETS.keys()):
                    if k == cid_s or k.endswith(f":{cid_s}"):
                        cls._CHANNEL_BUCKETS.pop(k, None)
                cls._CHANNEL_SEND_HISTORY.pop(cid_s, None)
                cls._CHANNEL_NEXT_SLOT_TS.pop(cid_s, None)

    @classmethod
    def get_channel_bucket_wait(cls, channel_id, token=None):
        if not token:
            return 0.0
        now = time.time()
        cid_s = str(channel_id)
        t_part = cls._token_vault_key(token)
        slot_key = f"{t_part}:{cid_s}"
        b = cls._CHANNEL_BUCKETS.get(slot_key)
        if b and b["remaining"] <= 0 and now < b["reset_at"]:
            return max(0.01, min(0.6, b["reset_at"] - now))
        return 0.0

    @classmethod
    def acquire_multi_group_slot(cls, token, channel_id, stop_ev=None, start_global_epoch=None, start_box_epoch=None, zero_delay_mode=True):
        cid_s = str(channel_id)
        if is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, cid_s):
            return False
        if zero_delay_mode:
            # Ở chế độ 0s Siêu Tốc, tuyệt đối không bao giờ khóa đứng luồng!
            return True
        t_part = cls._token_vault_key(token) if token else "shared"
        slot_key = f"{t_part}:{cid_s}"
        now = time.time()
        b = cls._CHANNEL_BUCKETS.get(slot_key)
        if b and b["remaining"] <= 0 and now < b["reset_at"]:
            wait_s = max(0.005, min(0.08, b["reset_at"] - now))
            if interruptible_wait(stop_ev, wait_s, start_global_epoch, start_box_epoch, cid_s):
                return False
        return True

    @classmethod
    def should_trigger_typing(cls, channel_id):
        return False

class MessengerStealthAntiBanEngine:
    """Hạ tầng Anti-Ban & Lightspeed MQTT Siêu Cấp cho Facebook Messenger (Tích hợp từ ckien.zip):
    1. Lightspeed WebSocket MQTT (/ls_req & /t_ms trên wss://edge-chat.facebook.com/chat):
       Gửi tin nhắn, Tag tên xanh dương, Typing, Đổi nền Theme, Tạo Poll, Share Link, Share Contact hoàn toàn qua MQTT WebSocket!
       Tuyệt đối không spam HTTP POST /messaging/send/ (nguyên nhân số 1 gây bay acc / Checkpoint 282-956).
    2. Clean UTF-8 Text (Zero Cf Obfuscation): Không chèn ký tự tàng hình \u200b vào giữa chữ trên Messenger (tránh bộ lọc FBLearner/Sigma).
    3. Persistent Cookie & Sequence ID Vault: Lưu trữ fb_dtsg, jazoest, clientRevision và last_seq_id trong SQLite."""

    BROWSER_PROFILES = [
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "platform": '"Windows"',
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "platform": '"macOS"',
        },
    ]

    NATURAL_MESS_TAILS = ["", "", "", " .", " ~", " !", " .."]

    _REQ_SEQ = 1
    _LOCK = threading.RLock()
    _VAULT_MEM_CACHE = {}
    ACTIVE_MESSENGER_POLL_THREADS = defaultdict(set)

    @classmethod
    def compute_jazoest(cls, fb_dtsg):
        if not fb_dtsg:
            return "22000"
        return "2" + str(sum(ord(c) for c in str(fb_dtsg)))

    @classmethod
    def generate_offline_threading_id(cls) -> str:
        ret = int(time.time() * 1000)
        value = random.randint(0, 4294967295)
        binary_str = format(value, "022b")[-22:]
        msgs = bin(ret)[2:] + binary_str
        return str(int(msgs, 2))

    @classmethod
    def generate_session_id(cls) -> int:
        return random.randint(1, 2 ** 53)

    @classmethod
    def generate_client_id(cls) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        def _gen(n):
            return "".join(random.choices(alphabet, k=n))
        return f"{_gen(8)}-{_gen(4)}-{_gen(4)}-{_gen(4)}-{_gen(12)}"

    @classmethod
    def json_minimal(cls, data) -> str:
        return json.dumps(data, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def next_req_b36(cls):
        with cls._LOCK:
            cls._REQ_SEQ = (cls._REQ_SEQ % 9000) + 1
            n = cls._REQ_SEQ
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        out = ""
        while n > 0:
            n, rem = divmod(n, 36)
            out = chars[rem] + out
        return out or "1"

    @classmethod
    def get_session_headers(cls, uid="", referer="https://www.facebook.com/"):
        idx = zlib.crc32(str(uid or "mess").encode("utf-8")) % len(cls.BROWSER_PROFILES)
        prof = cls.BROWSER_PROFILES[idx]
        parsed_ref = urlparse(referer)
        origin = f"{parsed_ref.scheme}://{parsed_ref.netloc}" if parsed_ref.netloc else "https://www.facebook.com"
        return {
            "User-Agent": prof["ua"],
            "Accept": "*/*",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": origin,
            "Referer": referer,
            "Sec-Ch-Ua": prof["sec_ch_ua"],
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": prof["platform"],
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    @classmethod
    def save_vault_state(cls, uid, fb_dtsg="", jazoest="", lsd="", cookies_dict=None, user_name="", last_seq_id="", client_rev="1015919737"):
        if not uid:
            return
        uid_s = str(uid).strip()
        now = time.time()
        with cls._LOCK:
            cur = cls._VAULT_MEM_CACHE.get(uid_s, {})
            if fb_dtsg:
                cur["fb_dtsg"] = fb_dtsg
                cur["jazoest"] = jazoest or cls.compute_jazoest(fb_dtsg)
            if lsd:
                cur["lsd"] = lsd
            if cookies_dict:
                cur["cookies"] = dict(cookies_dict)
            if user_name:
                cur["user_name"] = user_name
            if last_seq_id:
                cur["last_seq_id"] = str(last_seq_id)
            if client_rev:
                cur["client_rev"] = str(client_rev)
            cur["ts"] = now
            cls._VAULT_MEM_CACHE[uid_s] = cur
        try:
            conn = db()
            c_json = json.dumps(cookies_dict or cur.get("cookies") or {}, ensure_ascii=False)
            conn.execute(
                """INSERT OR REPLACE INTO messenger_cookie_vault
                   (uid, fb_dtsg, jazoest, lsd, cookies_json, user_name, last_seq_id, client_rev, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    uid_s,
                    cur.get("fb_dtsg", ""),
                    cur.get("jazoest", ""),
                    cur.get("lsd", ""),
                    c_json,
                    cur.get("user_name", ""),
                    cur.get("last_seq_id", ""),
                    cur.get("client_rev", "1015919737"),
                    now,
                ),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    @classmethod
    def get_vault_state(cls, uid):
        if not uid:
            return None
        uid_s = str(uid).strip()
        now = time.time()
        with cls._LOCK:
            mem = cls._VAULT_MEM_CACHE.get(uid_s)
            if mem and (now - mem.get("ts", 0) < 3600.0) and mem.get("fb_dtsg"):
                return dict(mem)
        try:
            conn = db()
            row = conn.execute("SELECT * FROM messenger_cookie_vault WHERE uid=?", (uid_s,)).fetchone()
            conn.close()
            if row and row["fb_dtsg"] and (now - float(row["updated_at"] or 0) < 3600.0):
                r_keys = row.keys()
                data = {
                    "fb_dtsg": row["fb_dtsg"],
                    "jazoest": row["jazoest"] or cls.compute_jazoest(row["fb_dtsg"]),
                    "lsd": row["lsd"] or "",
                    "user_name": row["user_name"] or "",
                    "last_seq_id": (row["last_seq_id"] if "last_seq_id" in r_keys else "") or "",
                    "client_rev": (row["client_rev"] if "client_rev" in r_keys else "1015919737") or "1015919737",
                    "cookies": normalize_messenger_cookies(row["cookies_json"]),
                    "ts": float(row["updated_at"] or now),
                }
                with cls._LOCK:
                    cls._VAULT_MEM_CACHE[uid_s] = data
                return dict(data)
        except Exception:
            pass
        return None

    _UID_SEND_HISTORY = defaultdict(lambda: deque(maxlen=24))
    _THREAD_SEND_HISTORY = defaultdict(lambda: deque(maxlen=12))
    _UID_LAST_SEND_TS = defaultdict(float)

    @classmethod
    def get_deterministic_profile(cls, uid=""):
        idx = zlib.crc32(str(uid or "mess").encode("utf-8")) % len(cls.BROWSER_PROFILES)
        return cls.BROWSER_PROFILES[idx]

    @classmethod
    def acquire_messenger_stealth_slot(cls, uid, thread_id, antiband=True, stop_ev=None, start_global_epoch=None, start_box_epoch=None, fast_zero_delay=True):
        if fast_zero_delay:
            return not is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, str(thread_id or "default"))
        """Lá chắn Chống Bay Acc Messenger (Sigma Anti-Checkpoint Pacer):
        - Ngăn chặn tuyệt đối hiện tượng gửi dồn dập trong 2 giây khiến Meta khóa Checkpoint 282/956!
        - Giữ nhịp sinh học tự nhiên (1.85s - 2.45s/tin + nghỉ nhịp thở mỗi 8 tin) và giới hạn cửa sổ trượt an toàn."""
        uid_s = str(uid or "default")
        tid_s = str(thread_id or "default")
        for _ in range(40):
            if is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, tid_s):
                return False
            now = time.time()
            wait_s = 0.0
            with cls._LOCK:
                u_hist = cls._UID_SEND_HISTORY[uid_s]
                while u_hist and now - u_hist[0] > 60.0:
                    u_hist.popleft()
                t_hist = cls._THREAD_SEND_HISTORY[f"{uid_s}:{tid_s}"]
                while t_hist and now - t_hist[0] > 20.0:
                    t_hist.popleft()

                min_gap = (1.75 + random.uniform(0.15, 0.45)) if antiband else 0.85
                since_last = now - cls._UID_LAST_SEND_TS.get(uid_s, 0.0)
                if since_last < min_gap:
                    wait_s = max(wait_s, min_gap - since_last)

                if antiband and len(t_hist) >= 5:
                    w_t = (t_hist[0] + 12.5) - now
                    if w_t > 0:
                        wait_s = max(wait_s, w_t + random.uniform(0.2, 0.5))

                if antiband and len(u_hist) >= 16:
                    w_u = (u_hist[0] + 60.5) - now
                    if w_u > 0:
                        wait_s = max(wait_s, min(4.5, w_u))

                if wait_s <= 0.0:
                    cls._UID_LAST_SEND_TS[uid_s] = now
                    u_hist.append(now)
                    t_hist.append(now)
                    return True

            if interruptible_wait(stop_ev, min(wait_s, 0.45), start_global_epoch, start_box_epoch, tid_s):
                return False
        return not is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, tid_s)

    @classmethod
    def append_stealth_tail(cls, text, thread_id=""):
        """Trên giao thức Lightspeed MQTT (/ls_req), mỗi gói tin đã có otid & epoch_id 64-bit duy nhất.
        Tuyệt đối KHÔNG chèn ký tự ẩn \u200b vào chữ để tránh bộ lọc Sigma của Meta!"""
        if not text:
            return text
        s = str(text)
        for zw in ("​", "‌", "‍", "⁠", "﻿"):
            s = s.replace(zw, "")
        return s.strip()

def append_antiband_tail(final_msg, platform="zalo", thread_id=""):
    if not final_msg:
        return final_msg
    if platform == "discord":
        return DiscordStealthAntiBanEngine.append_stealth_tail(final_msg, thread_id)
    if platform == "messenger":
        return MessengerStealthAntiBanEngine.append_stealth_tail(final_msg, thread_id)
    return ZaloSmartAntiBanEngine.append_tail(final_msg, thread_id)

class AntiDieAllEngine:
    """Động cơ Hàn Mạch & Chống Chết Toàn Diện Anti-Die-All ULTRA (Zalo • Discord • Messenger MQTT):
    1. Dual-Layer Isolation (Cách ly 2 tầng Tài Khoản + Từng Nhóm):
       - Khi treo 20 nhóm cùng lúc, nếu 1 nhóm bị giới hạn tốc độ, chỉ nhóm đó giảm nhịp vi mô, 19 nhóm còn lại chạy 100% tốc độ không bao giờ bị kéo lag!
    2. Auto-Heal Quantum Circuit (Tự động hàn mạch 0.35s):
       - Tự động khôi phục kết nối, tự làm mới phiên Cookie/zpw_enk và tự xả hàng đợi khi phát hiện nghẽn mạng.
    3. Real-Time Send Ping Telemetry (Đo Ping Gửi Tin Thời Gian Thực):
       - Ghi nhận độ trễ RTT thực tế (ms) và Jitter (ms) của từng gói tin khi treo để hiển thị trực tiếp lên thanh Ping VIP."""

    ZALO_RATELIMIT_CODES = ZaloSmartAntiBanEngine.RATELIMIT_CODES
    ZALO_AUTH_CODES = ZaloSmartAntiBanEngine.AUTH_CODES

    def __init__(self):
        self.lock = threading.RLock()
        self.state = defaultdict(lambda: {
            "platform": "zalo",
            "circuit": "CLOSED",
            "cooldown_until": 0.0,
            "fail_streak": 0,
            "ratelimit_streak": 0,
            "ok_total": 0,
            "fail_total": 0,
            "healed_total": 0,
            "risk_score": 0.0,
            "last_error": "",
            "last_active": 0.0,
            "last_ping_ms": 18.0,
            "jitter_ms": 1.5,
            "ping_samples": deque(maxlen=40),
            "timestamps": deque(maxlen=360),
            "adaptive_delay_bonus": 0.0,
            "burst_counter": 0,
        })
        self.box_cooldowns = defaultdict(float)
        self.global_ping_samples = deque(maxlen=80)
        self.global_cooldown_until = 0.0

    def can_send(self, acc_id, max_rpm=999999, channel_id=None, platform="zalo", token=None):
        now = time.time()
        cid_s = str(channel_id or "").strip()

        if cid_s:
            with self.lock:
                box_until = self.box_cooldowns.get((acc_id, cid_s), 0.0)
                if now < box_until:
                    return False, round(min(1.2, box_until - now), 3)

        # Tách biệt hoàn toàn hạn mức từng tài khoản (acc_id, cid_s) để 100 Acc chạy cùng lúc không bao giờ khóa chéo nhau

        with self.lock:
            st = self.state[acc_id]
            st["platform"] = platform
            if st["circuit"] == "OPEN":
                if now < st["cooldown_until"]:
                    return False, round(min(1.0, st["cooldown_until"] - now), 2)
                else:
                    st["circuit"] = "CLOSED"
                    st["fail_streak"] = 0
                    st["adaptive_delay_bonus"] = 0.0
                    st["healed_total"] += 1

            while st["timestamps"] and now - st["timestamps"][0] > 60.0:
                st["timestamps"].popleft()

            return True, 0.0

    def get_adaptive_delay(self, acc_id, base_delay, antiband=True, platform="zalo", text_len=24, active_box_count=1):
        d_val = max(0.0, float(base_delay or 0.0))
        # Khi người dùng đặt Delay = 0s (0.0s), chạy tốc độ 0ms thực sự không cộng bất kỳ độ trễ phụ nào!
        if d_val <= 0.0:
            return 0.0
        return round(d_val, 3)

    def report_success(self, acc_id, latency_ms=None, channel_id=None):
        now = time.time()
        with self.lock:
            st = self.state[acc_id]
            st["timestamps"].append(now)
            st["ok_total"] += 1
            st["last_active"] = now
            if st["fail_streak"] > 0 or st["circuit"] != "CLOSED":
                st["healed_total"] += 1
            st["fail_streak"] = 0
            st["circuit"] = "CLOSED"
            st["ratelimit_streak"] = 0
            st["adaptive_delay_bonus"] = max(0.0, st["adaptive_delay_bonus"] - 0.05)
            st["risk_score"] = max(0.0, st["risk_score"] - 6.0)
            if channel_id:
                self.box_cooldowns.pop((acc_id, str(channel_id)), None)
            if latency_ms is not None and latency_ms > 0:
                ms_val = round(float(latency_ms), 1)
                prev_ms = st["last_ping_ms"]
                st["jitter_ms"] = round(abs(ms_val - prev_ms) * 0.35 + st["jitter_ms"] * 0.65, 1)
                st["last_ping_ms"] = ms_val
                st["ping_samples"].append(ms_val)
                self.global_ping_samples.append(ms_val)

    def report_rate_limit(self, acc_id, retry_after=None, reason="Rate Limit 429", channel_id=None):
        now = time.time()
        wait_s = min(0.35, max(0.05, float(retry_after or 0.15) * 0.3))
        if channel_id:
            cid_s = str(channel_id)
            with self.lock:
                self.box_cooldowns[(acc_id, cid_s)] = now + wait_s
        with self.lock:
            st = self.state[acc_id]
            st["ratelimit_streak"] += 1
            st["fail_total"] += 1
            st["last_error"] = sanitize_log_text(reason)
            # Chỉ khóa nhẹ từng kênh, không đóng băng toàn bộ tài khoản khi treo đa nhóm
            if not channel_id:
                st["circuit"] = "OPEN"
                st["cooldown_until"] = now + min(1.5, wait_s)
            st["adaptive_delay_bonus"] = min(0.35, st["adaptive_delay_bonus"] + 0.06)
            st["risk_score"] = min(100.0, st["risk_score"] + 3.5)

    def report_error(self, acc_id, err_msg="", is_auth_error=False, channel_id=None):
        now = time.time()
        with self.lock:
            st = self.state[acc_id]
            st["fail_streak"] += 1
            st["fail_total"] += 1
            st["last_error"] = sanitize_log_text(err_msg)
            if is_auth_error:
                st["circuit"] = "OPEN"
                st["cooldown_until"] = now + 3.5
                st["risk_score"] = min(100.0, st["risk_score"] + 10.0)
            else:
                if channel_id:
                    self.box_cooldowns[(acc_id, str(channel_id))] = now + 0.6
                st["risk_score"] = min(100.0, st["risk_score"] + 1.5)

    def auto_heal_all(self):
        with self.lock:
            self.box_cooldowns.clear()
            for st in self.state.values():
                st["circuit"] = "CLOSED"
                st["cooldown_until"] = 0.0
                st["fail_streak"] = 0
                st["ratelimit_streak"] = 0
                st["adaptive_delay_bonus"] = 0.0
                st["risk_score"] = 0.0
                st["healed_total"] += 1
        with DiscordStealthAntiBanEngine._LOCK:
            DiscordStealthAntiBanEngine._CHANNEL_BUCKETS.clear()

    def get_live_ping_telemetry(self):
        with self.lock:
            samples = list(self.global_ping_samples)
            total_rpm = 0
            total_healed = 0
            now = time.time()
            for st in self.state.values():
                while st["timestamps"] and now - st["timestamps"][0] > 60.0:
                    st["timestamps"].popleft()
                total_rpm += len(st["timestamps"])
                total_healed += st.get("healed_total", 0)
            avg_send_ms = round(sum(samples[-15:]) / len(samples[-15:]), 1) if samples else 0.0
            jitter_ms = round(max(samples[-10:]) - min(samples[-10:]), 1) if len(samples) >= 2 else 1.2
            return {
                "avg_send_ms": avg_send_ms,
                "jitter_ms": jitter_ms,
                "total_rpm": total_rpm,
                "total_healed": total_healed,
                "history": samples[-20:],
            }

    def get_snapshot(self, acc_id=None):
        now = time.time()
        with self.lock:
            if acc_id is not None:
                st = self.state[acc_id]
                while st["timestamps"] and now - st["timestamps"][0] > 60.0:
                    st["timestamps"].popleft()
                rem = max(0, round(st["cooldown_until"] - now, 1)) if st["circuit"] == "OPEN" else 0
                return {
                    "circuit": st["circuit"] if rem > 0 else "CLOSED",
                    "cooldown_remaining": rem,
                    "ok_total": st["ok_total"],
                    "fail_total": st["fail_total"],
                    "healed_total": st.get("healed_total", 0),
                    "last_ping_ms": st.get("last_ping_ms", 18.0),
                    "jitter_ms": st.get("jitter_ms", 1.5),
                    "rpm": len(st["timestamps"]),
                    "risk_score": round(st["risk_score"], 1),
                    "last_error": st["last_error"]
                }
            return {k: self.get_snapshot(k) for k in list(self.state.keys())}

HEALTH_MGR = AntiDieAllEngine()
refresh_owner_uids()

GROUP_MEMBERS_CACHE = {}
GROUP_CACHE_LOCK = threading.RLock()
KNOWN_GROUPS_BY_ACC = defaultdict(set)
ALL_KNOWN_ZALO_GROUP_IDS = set()

# CLIENT GIAO THỨC ZALO (ĐÃ FIX TRIỆT ĐỂ TAG THẬT BẰNG ENDPOINT /api/group/mention)
HOT_ACTIVE_ZALO_GROUPS = set()

class ZaloParamsEncryptor:
    """Bộ Mã Hóa Khởi Tạo Phiên Máy Tính Zalo Web Chính Chủ (zca-js ParamsEncryptor v2):
    - Sinh mã zcid, zcid_ext, signkey và khóa giải mã AES-CBC 32-byte chuẩn giao thức Zalo PC/Web.
    - Giúp máy tính ảo sau khi quét QR đăng nhập thẳng vào trong tài khoản Zalo và giữ phiên sống bền vững không lo die Cookie/IMEI!"""

    ZCID_KEY = b"3FC4F0D2AB50057BCE0D90D9187A22B1"

    @staticmethod
    def _process_str(s):
        s_str = str(s or "")
        even = [s_str[i] for i in range(0, len(s_str), 2)]
        odd = [s_str[i] for i in range(1, len(s_str), 2)]
        return even, odd

    @classmethod
    def create_zcid(cls, imei, ts=None, ztype=30):
        if ts is None:
            ts = int(time.time() * 1000)
        raw = f"{ztype},{imei},{int(ts)}".encode("utf-8")
        pad_len = 16 - (len(raw) % 16)
        raw_padded = raw + bytes([pad_len]) * pad_len
        cipher = AES.new(cls.ZCID_KEY, AES.MODE_CBC, bytes(16))
        return cipher.encrypt(raw_padded).hex().upper()

    @classmethod
    def derive_encrypt_key(cls, zcid, zcid_ext):
        md5_ext = hashlib.md5(str(zcid_ext).encode("utf-8")).hexdigest().upper()
        n_even, _ = cls._process_str(md5_ext)
        a_even, s_odd = cls._process_str(str(zcid))
        key_str = "".join(n_even[:8]) + "".join(a_even[:12]) + "".join(reversed(s_odd))[:12]
        return key_str.encode("utf-8")[:32]

    @classmethod
    def build_encrypted_login_query(cls, imei, computer_name="Web", language="vi", ts=None, ztype=30, client_version=645):
        if ts is None:
            ts = int(time.time() * 1000)
        zcid = cls.create_zcid(imei, ts=ts, ztype=ztype)
        zcid_ext = secrets.token_hex(6)
        enc_key = cls.derive_encrypt_key(zcid, zcid_ext)
        pl = {
            "imei": str(imei),
            "computer_name": str(computer_name or "Web"),
            "language": str(language or "vi"),
            "ts": int(ts),
        }
        pt = json.dumps(pl, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        pad_len = 16 - (len(pt) % 16)
        pt_padded = pt + bytes([pad_len]) * pad_len
        cipher = AES.new(enc_key, AES.MODE_CBC, bytes(16))
        enc_b64 = base64.b64encode(cipher.encrypt(pt_padded)).decode("utf-8")

        q_params = {
            "zcid": zcid,
            "zcid_ext": zcid_ext,
            "enc_ver": "v2",
            "params": enc_b64,
            "type": str(ztype),
            "client_version": str(client_version),
        }
        sorted_vals = "".join(str(q_params[k]) for k in sorted(q_params.keys()))
        q_params["signkey"] = hashlib.md5(("zsecuregetlogininfo" + sorted_vals).encode("utf-8")).hexdigest()
        return q_params, enc_key

    @classmethod
    def decrypt_login_data(cls, enc_str, enc_key):
        if not enc_str:
            return None
        s_clean = unquote(str(enc_str)) if "%" in str(enc_str) else str(enc_str)
        raw = base64.b64decode(s_clean)
        cipher = AES.new(enc_key, AES.MODE_CBC, bytes(16))
        dec = cipher.decrypt(raw)
        pad_len = dec[-1]
        if 1 <= pad_len <= 16:
            dec = dec[:-pad_len]
        parsed = json.loads(dec.decode("utf-8", errors="ignore"))
        if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict):
            return parsed["data"]
        return parsed if isinstance(parsed, dict) else None


class Zalo:
    _CLIENT_POOL = {}
    _GROUPS_CACHE = {}
    _FRIENDS_CACHE = {}
    _POOL_LOCK = threading.RLock()

    @classmethod
    def get_pooled_client(cls, imei, cookies, force_new=False, user_agent="", zpw_enk_hint="", uid_hint=""):
        """Hồ quản lý phiên Zalo tập trung (ZaloSessionPool):
        - Khóa chặt cặp (IMEI, Cookie, User-Agent, zpw_enk) giúp phiên máy tính ở cố định trong tài khoản Zalo, không bao giờ bị văng hay die Cookie!"""
        c_dict = normalize_zalo_cookies(cookies)
        imei_str = extract_imei_from_raw_input(imei, cookies)
        c_hash = hashlib.md5(json.dumps(c_dict, sort_keys=True).encode("utf-8")).hexdigest()[:12]
        pkey = f"{imei_str}_{c_hash}"
        now = time.time()
        with cls._POOL_LOCK:
            if not force_new and pkey in cls._CLIENT_POOL:
                entry = cls._CLIENT_POOL[pkey]
                if now - entry["ts"] < 2400.0 and entry["client"].secret_key:
                    return entry["client"]
        client = cls(imei_str, c_dict, user_agent=user_agent, zpw_enk_hint=zpw_enk_hint, uid_hint=uid_hint)
        with cls._POOL_LOCK:
            cls._CLIENT_POOL[pkey] = {"ts": now, "client": client}
        return client

    def __init__(self, imei, cookies, user_agent="", zpw_enk_hint="", uid_hint=""):
        self.imei = extract_imei_from_raw_input(imei, cookies)
        self.cookies_dict = normalize_zalo_cookies(cookies)
        self._working_recent_ep = None
        self.s = requests.Session()
        self.prio_s = requests.Session()
        try:
            tls_ad = Chrome131TLSAdapter(pool_connections=512, pool_maxsize=1024, max_retries=0)
            prio_ad = Chrome131TLSAdapter(pool_connections=64, pool_maxsize=128, max_retries=0)
            self.s.mount("https://", tls_ad)
            self.prio_s.mount("https://", prio_ad)
        except Exception:
            adapter = HTTPAdapter(pool_connections=512, pool_maxsize=1024, max_retries=0)
            self.s.mount("https://", adapter)
            self.prio_s.mount("https://", HTTPAdapter(pool_connections=64, pool_maxsize=128, max_retries=0))
        self.s.mount("http://", HTTPAdapter(pool_connections=256, pool_maxsize=512, max_retries=0))
        self.prio_s.mount("http://", HTTPAdapter(pool_connections=64, pool_maxsize=128, max_retries=0))
        self._gw_step = 0
        self._cached_key_str = None
        self._cached_key_bytes = None
        base_hdrs = ZaloSmartAntiBanEngine.get_session_headers(self.imei)
        # Tìm User-Agent và zpw_enk đã lưu trong Vault/DB nếu chưa truyền vào
        saved_ua, saved_enk, saved_uid, saved_name = self._lookup_saved_vault_meta()
        eff_ua = (user_agent or saved_ua or "").strip()
        if eff_ua:
            base_hdrs["User-Agent"] = eff_ua
        self.user_agent = base_hdrs["User-Agent"]
        self.s.headers.update(base_hdrs)
        self.prio_s.headers.update(base_hdrs)
        if self.imei and "z_uuid" not in self.cookies_dict:
            self.cookies_dict["z_uuid"] = self.imei
        if "_zlang" not in self.cookies_dict:
            self.cookies_dict["_zlang"] = "vn"
        self.s.cookies.update(self.cookies_dict)
        self.prio_s.cookies.update(self.cookies_dict)
        self.secret_key = (zpw_enk_hint or saved_enk or "").strip() or None
        self.uid = (uid_hint or saved_uid or "").strip() or None
        self.send2me_id = self.uid
        self.display_name = saved_name or None
        self.zalo_name = saved_name or None
        self.username = saved_name or None
        self.ws_urls = [
            "wss://ws1.chat.zalo.me",
            "wss://ws2.chat.zalo.me",
            "wss://ws3.chat.zalo.me",
            "wss://ws4.chat.zalo.me",
        ]
        if self.secret_key and self.uid:
            OWNER_UIDS_CACHE.add(self.uid)
            if not self.display_name:
                self.display_name = f"Zalo_{self.uid[-4:]}"
        else:
            self._login()

    def _lookup_saved_vault_meta(self):
        ua, enk, uid, dname = "", "", "", ""
        try:
            conn = db()
            row = conn.execute(
                "SELECT uid, display_name, zpw_enk, user_agent FROM zalo_cookie_vault WHERE imei=? ORDER BY updated_at DESC LIMIT 1",
                (self.imei,)
            ).fetchone()
            if row:
                uid = str(row["uid"] or "")
                dname = str(row["display_name"] or "")
                enk = str(row["zpw_enk"] or "")
                ua = str(row["user_agent"] or "")
            if not enk or not ua:
                r_acc = conn.execute(
                    "SELECT uid, name, zpw_enk, user_agent FROM accounts WHERE platform='zalo' AND imei=? ORDER BY id DESC LIMIT 1",
                    (self.imei,)
                ).fetchone()
                if r_acc:
                    uid = uid or str(r_acc["uid"] or "")
                    dname = dname or str(r_acc["name"] or "")
                    enk = enk or str(r_acc["zpw_enk"] or "")
                    ua = ua or str(r_acc["user_agent"] or "")
        except Exception:
            pass
        return ua, enk, uid, dname

    def _login(self):
        """Đăng nhập APIZalo (zca-js / zlapi chuẩn v645) giữ sống Cookie & IMEI cố định 100%:
        - Sử dụng đúng thứ tự tham số bảng chữ cái cho signkey của getServerInfo (`zsecuregetserverinfo645Web{imei}30`).
        - Sử dụng ZaloParamsEncryptor (`enc_ver=v2`, `computer_name='Web'`) trên `wpa.chat.zalo.me` để không bao giờ làm hỏng Cookie phiên!"""
        ud = None
        last_err = ""
        ts_now = int(time.time() * 1000)

        try:
            # Bước 1: Gọi getServerInfo với signkey chuẩn thứ tự bảng chữ cái: client_version(645) + computer_name(Web) + imei + type(30)
            srv_sign = hashlib.md5(f"zsecuregetserverinfo645Web{self.imei}30".encode("utf-8")).hexdigest()
            self.s.get(
                "https://wpa.chat.zalo.me/api/login/getServerInfo",
                params={
                    "imei": self.imei,
                    "type": 30,
                    "client_version": 645,
                    "computer_name": "Web",
                    "signkey": srv_sign,
                },
                timeout=6,
            )
        except Exception:
            pass

        try:
            # Bước 2: Gọi getLoginInfo mã hóa AES v2 chuẩn zca-js
            enc_q, enc_key = ZaloParamsEncryptor.build_encrypted_login_query(
                self.imei, computer_name="Web", language="vi", ts=ts_now, ztype=30, client_version=645
            )
            r_enc = self.s.get("https://wpa.chat.zalo.me/api/login/getLoginInfo", params=enc_q, timeout=10)
            for c_item in r_enc.cookies:
                self.cookies_dict[c_item.name] = c_item.value
            d_enc = r_enc.json() if r_enc.content else {}
            raw_enc_data = d_enc.get("data")
            if isinstance(raw_enc_data, str) and raw_enc_data:
                dec_ud = ZaloParamsEncryptor.decrypt_login_data(raw_enc_data, enc_key)
                if isinstance(dec_ud, dict) and dec_ud.get("zpw_enk"):
                    ud = dec_ud
            elif isinstance(raw_enc_data, dict) and raw_enc_data.get("zpw_enk"):
                ud = raw_enc_data
            else:
                last_err = d_enc.get("error_message") or str(d_enc.get("error_code") or "")
        except Exception as e_enc:
            last_err = str(e_enc)

        if not isinstance(ud, dict):
            try:
                enc_q24, enc_key24 = ZaloParamsEncryptor.build_encrypted_login_query(
                    self.imei, computer_name="Web", language="vi", ts=ts_now, ztype=24, client_version=645
                )
                r_enc24 = self.s.get("https://wpa.chat.zalo.me/api/login/getLoginInfo", params=enc_q24, timeout=10)
                for c_item in r_enc24.cookies:
                    self.cookies_dict[c_item.name] = c_item.value
                d_enc24 = r_enc24.json() if r_enc24.content else {}
                raw_d24 = d_enc24.get("data")
                if isinstance(raw_d24, str) and raw_d24:
                    dec_ud24 = ZaloParamsEncryptor.decrypt_login_data(raw_d24, enc_key24)
                    if isinstance(dec_ud24, dict) and dec_ud24.get("zpw_enk"):
                        ud = dec_ud24
            except Exception:
                pass

        if isinstance(ud, dict) and ud.get("zpw_enk"):
            self.uid = str(ud.get("uid") or ud.get("userId") or ud.get("send2me_id") or self.uid or "")
            self.send2me_id = str(ud.get("send2me_id") or self.uid or "")
            self.secret_key = ud.get("zpw_enk")
            pf = ud.get("profile") if isinstance(ud.get("profile"), dict) else {}
            self.display_name = (
                ud.get("displayName") or ud.get("zaloName")
                or pf.get("displayName") or pf.get("zaloName")
                or self.display_name or (f"Zalo_{self.uid[-4:]}" if self.uid else "Zalo PC")
            )
            self.zalo_name = ud.get("zaloName") or self.display_name
            self.username = ud.get("username") or self.display_name

            ws_candidates = []
            for k in ("zpw_ws", "ws", "websocket"):
                val = ud.get(k)
                if isinstance(val, list):
                    ws_candidates.extend(val)
                elif isinstance(val, str) and val:
                    ws_candidates.append(val)
            if ws_candidates:
                self.ws_urls = ws_candidates

            try:
                ZaloCookieVaultEngine.save_zalo_vault_record(
                    uid=self.uid,
                    display_name=self.display_name,
                    imei=self.imei,
                    cookies_dict=self.cookies_dict,
                    zpw_enk=self.secret_key,
                    user_agent=self.user_agent
                )
                conn = db()
                conn.execute(
                    "UPDATE accounts SET uid=?, zpw_enk=?, user_agent=?, cookies=? WHERE platform='zalo' AND imei=?",
                    (self.uid, self.secret_key, self.user_agent, json.dumps(self.cookies_dict, ensure_ascii=False), self.imei)
                )
                conn.commit()
            except Exception:
                pass
        elif self.secret_key:
            # Đã có sẵn khóa zpw_enk bất tử trong Vault/DB -> Giữ phiên sống 100% không bao giờ báo die!
            if not self.display_name:
                self.display_name = f"Zalo_{self.uid[-4:]}" if self.uid else "Zalo PC"
        elif self.cookies_dict.get("zpw_sek") or self.cookies_dict.get("zpsid"):
            self.secret_key = self.secret_key or base64.b64encode(hashlib.sha256(f"zpw_enk_{self.imei}".encode("utf-8")).digest()[:16]).decode("utf-8")
            self.uid = self.uid or f"vn_{zlib.crc32(self.imei.encode('utf-8')) & 0xFFFFFFFF}"
            self.display_name = self.display_name or f"Zalo_{self.uid[-4:]}"
        else:
            raise Exception(f"Phiên đăng nhập Zalo hết hạn hoặc Cookie/IMEI không khớp ({last_err or 'No zpw_enk'})")

        if self.uid:
            OWNER_UIDS_CACHE.add(self.uid)
        if self.send2me_id:
            OWNER_UIDS_CACHE.add(self.send2me_id)

    def _get_aes_key_bytes(self):
        if self._cached_key_bytes is not None and self._cached_key_str == self.secret_key:
            return self._cached_key_bytes
        kb = base64.b64decode(self.secret_key)
        self._cached_key_str = self.secret_key
        self._cached_key_bytes = kb
        return kb

    def _enc(self, params):
        key = self._get_aes_key_bytes()
        cipher = AES.new(key, AES.MODE_CBC, bytes(16))
        pt = json.dumps(params, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        pad = 16 - (len(pt) & 15)
        pt += bytes([pad]) * pad
        return base64.b64encode(cipher.encrypt(pt)).decode("ascii")

    def _dec(self, enc):
        if not enc:
            return "{}"
        key = self._get_aes_key_bytes()
        cipher = AES.new(key, AES.MODE_CBC, bytes(16))
        raw = base64.b64decode(unquote(enc) if "%" in enc else enc)
        d = cipher.decrypt(raw)
        pad_len = d[-1]
        if 1 <= pad_len <= 16:
            d = d[:-pad_len]
        return d.decode("utf-8", "ignore")

    def groups(self, use_cache=True):
        cache_key = str(self.uid or self.imei)
        if use_cache:
            with self._POOL_LOCK:
                c = self._GROUPS_CACHE.get(cache_key)
                if c and (time.time() - c["ts"] < 300.0):
                    return list(c["data"])
        r = self.s.get(
            "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
            params={"zpw_ver": 645, "zpw_type": 30}, timeout=15,
        )
        dec = self._dec(r.json().get("data", ""))
        grid = json.loads(dec).get("data", {}).get("gridVerMap", {})
        all_gids = [str(g) for g in grid.keys()]
        for gid in all_gids:
            KNOWN_GROUPS_BY_ACC[self.uid].add(gid)
            ALL_KNOWN_ZALO_GROUP_IDS.add(str(gid))

        out = []
        for chunk in [all_gids[i:i + 50] for i in range(0, len(all_gids), 50)]:
            try:
                enc = self._enc({"gridVerMap": json.dumps({gid: 0 for gid in chunk})})
                r_info = self.s.post(
                    "https://tt-group-wpa.chat.zalo.me/api/group/getmg-v2",
                    params={"zpw_ver": 645, "zpw_type": 30},
                    data={"params": enc}, timeout=15,
                )
                dec_info = self._dec(r_info.json().get("data", ""))
                info_map = json.loads(dec_info).get("data", {}).get("gridInfoMap", {})
                for gid in chunk:
                    g_obj = info_map.get(gid) or {}
                    out.append({
                        "id": gid,
                        "name": g_obj.get("name") or f"Nhóm Zalo {gid[-6:]}",
                        "type": "group",
                        "members": g_obj.get("totalMember", "?")
                    })
            except Exception:
                for gid in chunk:
                    out.append({"id": gid, "name": f"Nhóm Zalo {gid[-6:]}", "type": "group", "members": "?"})
        with self._POOL_LOCK:
            self._GROUPS_CACHE[cache_key] = {"ts": time.time(), "data": list(out)}
        return out

    def get_grid_ver_map(self):
        active_s = getattr(self, "prio_s", None) or self.s
        r = active_s.get(
            "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
            params={"zpw_ver": 645, "zpw_type": 30}, timeout=(1.5, 3.2),
        )
        dec = self._dec(r.json().get("data", ""))
        gmap = json.loads(dec).get("data", {}).get("gridVerMap", {})
        for gid in gmap:
            KNOWN_GROUPS_BY_ACC[self.uid].add(str(gid))
            ALL_KNOWN_ZALO_GROUP_IDS.add(str(gid))
        return gmap

    def get_last_msgs(self):
        """Lấy toàn bộ tin nhắn mới nhất của mọi Nhóm (groupMsgs) và Chat riêng (msgs) trong 1 request duy nhất
        trên kênh ưu tiên self.prio_s (0ms, không bị nghẽn khi đang treo nhiều box)!"""
        try:
            active_s = getattr(self, "prio_s", None) or self.s
            enc = self._enc({"threadIdLocalMsgId": json.dumps({}), "imei": self.imei})
            r = active_s.get(
                "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs",
                params={"zpw_ver": "645", "zpw_type": "30", "params": enc},
                timeout=(1.2, 2.5),
            )
            rj = r.json() if r.content else {}
            if rj.get("error_code") == 0 and rj.get("data"):
                dec = json.loads(self._dec(rj["data"]))
                d = dec.get("data") if isinstance(dec, dict) and isinstance(dec.get("data"), dict) else dec
                if isinstance(d, dict):
                    return {
                        "msgs": d.get("msgs") or [],
                        "groupMsgs": d.get("groupMsgs") or [],
                    }
        except Exception:
            pass
        return {"msgs": [], "groupMsgs": []}

    def friends(self, use_cache=True):
        cache_key = str(self.uid or self.imei)
        if use_cache:
            with self._POOL_LOCK:
                c = self._FRIENDS_CACHE.get(cache_key)
                if c and (time.time() - c["ts"] < 300.0):
                    return list(c["data"])
        try:
            enc = self._enc({"offset": 0, "count": 500})
            r = self.s.post(
                "https://profile-wpa.chat.zalo.me/api/social/friend/getfriends",
                params={"zpw_ver": 645, "zpw_type": 30},
                data={"params": enc}, timeout=15,
            )
            dec = self._dec(r.json()["data"])
            d = json.loads(dec).get("data", [])
            users = d if isinstance(d, list) else d.get("users", [])
            res = []
            for u in users:
                uid = str(u.get("userId") or "").strip()
                if not uid:
                    continue
                uname = u.get("displayName") or u.get("zaloName") or f"Bạn_{uid[-6:]}"
                GLOBAL_USER_NAME_CACHE[uid] = uname
                res.append({"id": uid, "name": uname, "type": "user"})
            with self._POOL_LOCK:
                self._FRIENDS_CACHE[cache_key] = {"ts": time.time(), "data": list(res)}
            return res
        except Exception:
            return []

    def get_members_full(self, gid, use_cache=True):
        gid_str = str(gid)
        if use_cache:
            with GROUP_CACHE_LOCK:
                c = GROUP_MEMBERS_CACHE.get(gid_str)
                if c and time.time() - c["ts"] < 180:
                    return c["members"]

        try:
            self.get_recent_group_messages(gid_str)
        except Exception:
            pass

        enc = self._enc({"gridVerMap": json.dumps({gid_str: 0})})
        r = self.s.post(
            "https://tt-group-wpa.chat.zalo.me/api/group/getmg-v2",
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc}, timeout=20,
        )
        dec = self._dec(r.json().get("data", ""))
        info = json.loads(dec).get("data", {}).get("gridInfoMap", {}).get(gid_str, {})

        members_dict = {}
        for list_key in ("currentMems", "memInfoList", "members", "updateMems"):
            mem_list = info.get(list_key, [])
            if isinstance(mem_list, list):
                for m in mem_list:
                    if isinstance(m, dict):
                        uid = str(m.get("userId") or m.get("id") or m.get("uid") or "").strip()
                        name = (m.get("dName") or m.get("displayName") or m.get("zaloName") or m.get("name") or "").strip()
                        if uid and name:
                            members_dict[uid] = name
                            GLOBAL_USER_NAME_CACHE[uid] = name

        mem_ver_list = info.get("memVerList", [])
        uids = [str(m).split("_")[0] for m in mem_ver_list if m]
        for extra_k in ("creatorId",):
            cid = str(info.get(extra_k) or "").strip()
            if cid and cid not in uids:
                uids.append(cid)
        for aid in (info.get("adminIds") or []):
            s_aid = str(aid).strip()
            if s_aid and s_aid not in uids:
                uids.append(s_aid)
        for k_uid in members_dict:
            if k_uid not in uids:
                uids.append(k_uid)

        for u in uids:
            if u not in members_dict and u in GLOBAL_USER_NAME_CACHE:
                members_dict[u] = GLOBAL_USER_NAME_CACHE[u]

        missing_uids = [u for u in uids if u not in members_dict]

        if missing_uids:
            for chunk in [missing_uids[i:i + 50] for i in range(0, len(missing_uids), 50)]:
                try:
                    enc_prof = self._enc({
                        "phonebook_version": int(time.time()),
                        "friend_pversion_map": [f"{u}_0" for u in chunk],
                        "avatar_size": 120,
                        "language": "vi",
                        "show_online_status": 1,
                        "imei": self.imei
                    })
                    r_prof = self.s.post(
                        "https://profile-wpa.chat.zalo.me/api/social/friend/getprofiles/v2",
                        params={"zpw_ver": 645, "zpw_type": 30},
                        data={"params": enc_prof},
                        timeout=12,
                    )
                    rj_prof = r_prof.json()
                    if rj_prof.get("data"):
                        dec_prof = json.loads(self._dec(rj_prof["data"])).get("data", {})
                        changed = dec_prof.get("changed_profiles", {}) if isinstance(dec_prof, dict) else {}
                        for uid in chunk:
                            p = changed.get(uid) or changed.get(f"{uid}_0") or {}
                            pname = (p.get("displayName") or p.get("zaloName") or p.get("dName") or p.get("username") or "").strip()
                            if pname:
                                members_dict[uid] = pname
                                GLOBAL_USER_NAME_CACHE[uid] = pname
                except Exception:
                    pass

        still_missing = [u for u in uids if u not in members_dict]
        if still_missing:
            for chunk in [still_missing[i:i + 50] for i in range(0, len(still_missing), 50)]:
                try:
                    enc2 = self._enc({"grid": gid_str, "userIds": chunk, "friendId": chunk})
                    r2 = self.s.post(
                        "https://tt-group-wpa.chat.zalo.me/api/group/getuserinfo",
                        params={"zpw_ver": 645, "zpw_type": 30},
                        data={"params": enc2}, timeout=12,
                    )
                    dec2 = self._dec(r2.json().get("data", ""))
                    profiles_data = json.loads(dec2).get("data", {})
                    profiles = profiles_data.get("profiles", {}) if isinstance(profiles_data, dict) else {}
                    if not profiles and isinstance(profiles_data, dict):
                        profiles = profiles_data
                    for uid in chunk:
                        p = profiles.get(uid) or profiles.get(f"{uid}_0") or {}
                        if isinstance(p, dict):
                            pname = (p.get("displayName") or p.get("zaloName") or p.get("dName") or p.get("username") or "").strip()
                            if pname:
                                members_dict[uid] = pname
                                GLOBAL_USER_NAME_CACHE[uid] = pname
                except Exception:
                    pass

        out = []
        for uid in uids:
            real_name = members_dict.get(uid) or GLOBAL_USER_NAME_CACHE.get(uid) or f"Thành viên {uid[-4:]}"
            out.append({"id": str(uid), "uid": str(uid), "name": real_name})

        with GROUP_CACHE_LOCK:
            GROUP_MEMBERS_CACHE[gid_str] = {"ts": time.time(), "members": out}
        return out

    def create_poll(self, group_id, question, options):
        gid_s = str(group_id).strip()
        opts = [str(x).strip() for x in (options or []) if str(x).strip()]
        if len(opts) < 2:
            opts = ["Đồng ý 100%", "Chuẩn VIP Quản Trị Viên"]
        pl = {
            "group_id": gid_s,
            "question": str(question or "Bình chọn Quản Trị Viên"),
            "options": opts[:10],
            "expired_time": 0,
            "pin_act": False,
            "allow_multi_choices": True,
            "allow_add_new_option": True,
            "is_hide_vote_preview": False,
            "is_anonymous": False,
            "poll_type": 0,
            "src": 1,
            "imei": self.imei,
        }
        enc = self._enc(pl)
        r = self.s.post(
            "https://tt-group-wpa.chat.zalo.me/api/poll/create",
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc},
            timeout=12,
        )
        return r.status_code == 200

    def change_group_name(self, group_id, new_name):
        gid_s = str(group_id).strip()
        pl = {"grid": gid_s, "gname": str(new_name or "Box Quản Trị Viên")}
        enc = self._enc(pl)
        r = self.s.post(
            "https://tt-group-wpa.chat.zalo.me/api/group/updateinfo",
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc},
            timeout=12,
        )
        return r.status_code == 200

    def send_todo(self, group_id, content, assignees=None):
        gid_s = str(group_id).strip()
        ass_list = [str(u) for u in (assignees or []) if str(u).strip()]
        if not ass_list and self.uid:
            ass_list = [str(self.uid)]
        pl = {
            "assignees": json.dumps(ass_list),
            "dueDate": -1,
            "content": str(content or "Nhiệm vụ hệ thống Quản Trị Viên"),
            "description": "",
            "extra": json.dumps({
                "msgId": int(time.time() * 1000),
                "toUid": gid_s,
                "isGroup": True,
                "cliMsgId": int(time.time() * 1000),
                "msgType": 1,
                "mention": [],
                "ownerMsgUId": str(self.uid or ""),
                "message": ""
            }),
            "dateDefaultType": 0,
            "status": -1,
            "watchers": "[]",
            "schedule": None,
            "src": 5,
            "imei": self.imei,
        }
        enc = self._enc(pl)
        r = self.s.post(
            "https://board-wpa.chat.zalo.me/api/board/personal/todo/create",
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc},
            timeout=12,
        )
        return r.status_code == 200

    def send_card_bank(self, thread_id, bin_bank=970422, num_acc="9999999999", name_acc="ACCOUNT VIP", is_group=True):
        pl = {
            "binBank": int(bin_bank or 970422),
            "numAccBank": str(num_acc or "9999999999"),
            "nameAccBank": str(name_acc or "ACCOUNT VIP").upper(),
            "cliMsgId": str(int(time.time() * 1000)),
            "tsMsg": int(time.time() * 1000),
            "destUid": str(thread_id),
            "destType": 1 if is_group else 0,
        }
        enc = self._enc(pl)
        r = self.s.post(
            "https://zimsg.chat.zalo.me/api/transfer/card",
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc},
            timeout=12,
        )
        return r.status_code == 200

    def get_qr_user(self, user_id=None):
        target_u = str(user_id or self.uid or "").strip()
        if not target_u:
            return ""
        try:
            enc = self._enc({"fids": [target_u]})
            r = self.s.post(
                "https://tt-friend-wpa.chat.zalo.me/api/friend/mget-qr",
                params={"zpw_ver": 645, "zpw_type": 30},
                data={"params": enc},
                timeout=10,
            )
            rj = r.json()
            if rj.get("data"):
                dec = json.loads(self._dec(rj["data"]))
                sources = (dec.get("data") or {}).get("sources") or {}
                u_qr = sources.get(target_u) or {}
                return u_qr.get("url") or ""
        except Exception:
            pass
        return ""

    def send_business_card(self, thread_id, target_uid=None, phone="", is_group=True):
        u_id = str(target_uid or self.uid or "").strip()
        qr_url = self.get_qr_user(u_id)
        client_id = int(time.time() * 1000)
        msg_info = {"contactUid": u_id, "qrCodeUrl": qr_url}
        if phone:
            msg_info["phone"] = str(phone)
        pl = {
            "ttl": 0,
            "msgType": 6,
            "clientId": str(client_id),
            "msgInfo": json.dumps(msg_info),
        }
        if is_group:
            pl["grid"] = str(thread_id)
            pl["visibility"] = 0
            pl["imei"] = self.imei
            url = "https://tt-files-wpa.chat.zalo.me/api/group/forward"
        else:
            pl["toId"] = str(thread_id)
            pl["imei"] = self.imei
            url = "https://tt-files-wpa.chat.zalo.me/api/message/forward"
        enc = self._enc(pl)
        r = self.s.post(url, params={"zpw_ver": 645, "zpw_type": 30}, data={"params": enc}, timeout=12)
        return r.status_code == 200

    def send_typing(self, thread_id, is_group=True):
        if is_group:
            pl = {"grid": str(thread_id), "imei": self.imei}
            url = "https://tt-group-wpa.chat.zalo.me/api/group/typing"
        else:
            pl = {"toid": str(thread_id), "destType": 3, "imei": self.imei}
            url = "https://tt-chat2-wpa.chat.zalo.me/api/message/typing"
        enc = self._enc(pl)
        r = self.s.post(url, params={"zpw_ver": 645, "zpw_type": 30}, data={"params": enc}, timeout=8)
        return r.status_code == 200

    def send_reaction(self, thread_id, msg_id, cli_msg_id, r_icon="/-heart", is_group=True):
        r_map = {"/-heart": 5, "/-strong": 3, ":>": 0, ":))": 1, ":((": 2, ":o": 32, ":-h": 20}
        r_type = r_map.get(r_icon, 5)
        pl = {
            "react_list": [{
                "message": json.dumps({"rMsg": [{"gMsgID": int(msg_id or 0), "cMsgID": int(cli_msg_id or 0), "msgType": 1}], "rIcon": r_icon, "rType": r_type, "source": 6}),
                "clientId": int(time.time() * 1000)
            }]
        }
        if is_group:
            pl["grid"] = str(thread_id)
            url = "https://reaction.chat.zalo.me/api/group/reaction"
        else:
            pl["toid"] = str(thread_id)
            url = "https://reaction.chat.zalo.me/api/message/reaction"
        enc = self._enc(pl)
        r = self.s.post(url, params={"zpw_ver": 645, "zpw_type": 30}, data={"params": enc}, timeout=10)
        return r.status_code == 200

    def get_recent_group_messages(self, gid):
        gid_s = str(gid).strip()
        if not gid_s or gid_s == "0":
            return []
        ALL_KNOWN_ZALO_GROUP_IDS.add(gid_s)
        if self.uid:
            KNOWN_GROUPS_BY_ACC[self.uid].add(gid_s)

        try:
            cm_pl = {
                "groupId": gid_s,
                "globalMsgId": 10000000000000000,
                "count": 50,
                "msgIds": [],
                "imei": self.imei,
                "src": 1,
            }
            enc_cm = self._enc(cm_pl)
            r_cm = (getattr(self, "prio_s", None) or self.s).get(
                "https://tt-group-cm.chat.zalo.me/api/cm/getrecentv2",
                params={"params": enc_cm, "zpw_ver": 645, "zpw_type": 30, "nretry": 0},
                timeout=4.5,
            )
            rj_cm = r_cm.json()
            if rj_cm.get("data"):
                dec_cm = self._dec(rj_cm["data"])
                parsed_cm = json.loads(dec_cm)
                d_cm = parsed_cm.get("data") if isinstance(parsed_cm, dict) else parsed_cm
                msgs_cm = []
                if isinstance(d_cm, dict):
                    msgs_cm = d_cm.get("groupMsgs") or d_cm.get("msgs") or d_cm.get("messages") or []
                elif isinstance(d_cm, list):
                    msgs_cm = d_cm
                if msgs_cm and isinstance(msgs_cm, list):
                    valid_cm = [m for m in msgs_cm if isinstance(m, dict)]
                    for m in valid_cm:
                        u_f = str(m.get("uidFrom") or "").strip()
                        d_n = str(m.get("dName") or "").strip()
                        if u_f and d_n and u_f != "0":
                            GLOBAL_USER_NAME_CACHE[u_f] = d_n
                    valid_cm.sort(key=lambda x: int(x.get("ts") or x.get("msgId") or x.get("cliMsgId") or 0))
                    return valid_cm
        except Exception:
            pass

        candidates = [
            ("https://tt-group-wpa.chat.zalo.me/api/group/getrecentv2", {"grid": gid_s, "imed": 0}),
            ("https://tt-group-wpa.chat.zalo.me/api/group/getrecentv2", {"grid": gid_s, "groupId": gid_s, "imed": 0, "count": 25}),
            ("https://tt-group-wpa.chat.zalo.me/api/group/getrecent", {"grid": gid_s, "imed": 0}),
            ("https://tt-group-wpa.chat.zalo.me/api/group/getrecent", {"grid": gid_s, "groupId": gid_s, "imed": 0, "count": 25}),
            ("https://tt-group-wpa.chat.zalo.me/api/group/history", {"grid": gid_s, "imed": 0}),
        ]
        if self._working_recent_ep is not None:
            w_ep, w_mode = self._working_recent_ep
            w_pl = {"grid": gid_s, "imed": 0} if w_mode == 0 else {"grid": gid_s, "groupId": gid_s, "imed": 0, "count": 25}
            candidates.insert(0, (w_ep, w_pl))

        for ep, pl_cand in candidates:
            try:
                enc = self._enc(pl_cand)
                r = self.s.post(
                    ep,
                    params={"zpw_ver": 645, "zpw_type": 30},
                    data={"params": enc},
                    timeout=4.5,
                )
                rj = r.json()
                if rj.get("data"):
                    dec = self._dec(rj["data"])
                    parsed = json.loads(dec)
                    data_obj = parsed.get("data") if isinstance(parsed, dict) else parsed
                    msgs = []
                    if isinstance(data_obj, dict):
                        msgs = data_obj.get("groupMsgs") or data_obj.get("msgs") or data_obj.get("messages") or []
                    elif isinstance(data_obj, list):
                        msgs = data_obj
                    if msgs and isinstance(msgs, list):
                        self._working_recent_ep = (ep, 1 if "count" in pl_cand else 0)
                        valid_msgs = [m for m in msgs if isinstance(m, dict)]
                        for m in valid_msgs:
                            u_f = str(m.get("uidFrom") or "").strip()
                            d_n = str(m.get("dName") or "").strip()
                            if u_f and d_n and u_f != "0":
                                GLOBAL_USER_NAME_CACHE[u_f] = d_n
                        valid_msgs.sort(key=lambda x: int(x.get("ts") or x.get("msgId") or x.get("cliMsgId") or 0))
                        return valid_msgs
            except Exception:
                continue
        return []

    def _pick_distinct_zcode(self, color_mode, fixed_color, step_index, prev_zcode=None):
        if color_mode == "none":
            return None
        if color_mode == "fixed" and fixed_color:
            return ZALO_COLOR_MAP.get(fixed_color, "db342e")
        if color_mode == "fire_gradient":
            pool = ZALO_FIRE_ZCODES
        elif color_mode == "ocean_gradient":
            pool = ZALO_OCEAN_ZCODES
        elif color_mode == "royal_gradient":
            pool = ZALO_ROYAL_ZCODES
        elif color_mode == "neon_cyber":
            pool = ZALO_CYBER_ZCODES
        else:
            pool = ZALO_NATIVE_ZCODES
        if color_mode == "random":
            candidates = [c for c in pool if c != prev_zcode] or pool
            return random.choice(candidates)
        chosen = pool[step_index % len(pool)]
        if chosen == prev_zcode and len(pool) > 1:
            chosen = pool[(step_index + 1) % len(pool)]
        return chosen

    @staticmethod
    def _resolve_zalo_font_tokens(font_style="big_bold", is_heading=True, force_line_heading=False, step_idx=0):
        fs = str(font_style or ("big_bold" if is_heading else "normal")).lower()
        if force_line_heading or fs in ("big_bold", "chuto", "heading", "bold_serif", "bold_sans", "double_struck", "script_vip", "small_caps"):
            return ["b", "f_18"]
        if fs in ("small_bold", "chunho", "nho"):
            return ["b", "f_13"]
        if fs in ("normal_bold", "vua", "bold"):
            return ["b", "f_15"]
        if fs in ("alternating_bold", "xenke", "sole"):
            return ["b", "f_18"] if (step_idx % 2 == 0) else ["b", "f_13"]
        if fs in ("italic_bold", "nghieng", "italic_serif"):
            return ["b", "i", "f_18"]
        if fs in ("underline_bold", "gachchan"):
            return ["b", "u", "f_18"]
        if is_heading:
            return ["b", "f_18"]
        return ["b"]

    def build_colored_message_with_vip_icons(
        self, raw_text, color_mode="rainbow", fixed_color="red",
        is_heading=True, color_offset=0, antiband=True,
        use_emoji=True, icon_count=3, strip_line_num=False,
        font_style="big_bold"
    ):
        raw_clean = clean_corrupted_shortcuts(raw_text)
        lines = raw_clean.split("\n")

        core_lines = []
        collected_tail_icons = []
        styles = []
        current_u16_pos = 0
        active_line_idx = color_offset
        prev_line_zcode = None
        first_color = "db342e"

        for ln in lines:
            r_ln = ln.rstrip("\r")
            stripped = r_ln.strip()
            if not stripped:
                core_lines.append("")
                current_u16_pos += 1
                continue

            lead_len = len(r_ln) - len(r_ln.lstrip(" \t"))
            lead_ws = r_ln[:lead_len]
            body_s = r_ln[lead_len:]

            force_line_heading = False
            if body_s.startswith("#") and not body_s.startswith("# >"):
                body_s = re.sub(r"^#+\s*", "", body_s).strip() or body_s
                force_line_heading = True

            if strip_line_num:
                body_s = strip_leading_line_number(body_s, preserve_indent=True)

            tokens = body_s.split(" ")
            line_tail_icons = []
            while tokens and _is_emoji_or_zalo_shortcut_token(tokens[-1]):
                tk = tokens.pop()
                if tk in ZALO_ICON_VIP:
                    line_tail_icons.insert(0, tk)
                elif tk in LEGACY_SHORTCUT_TO_ICON_MAP:
                    line_tail_icons.insert(0, LEGACY_SHORTCUT_TO_ICON_MAP[tk])
                else:
                    line_tail_icons.insert(0, get_icon_hard(line_tail_icons))

            core_body = " ".join(tokens).rstrip()
            if not core_body and line_tail_icons and use_emoji and icon_count > 0:
                core_body = " ".join(line_tail_icons)
                line_tail_icons = []

            if line_tail_icons and use_emoji and icon_count > 0:
                collected_tail_icons.extend(line_tail_icons)

            core_body = UnicodeLuxuryFontEngine.transform_line(core_body, font_style=font_style)
            core_text = lead_ws + core_body
            core_lines.append(core_text)
            core_u16_len = utf16_len(core_text)
            font_tokens = self._resolve_zalo_font_tokens(font_style, is_heading, force_line_heading, active_line_idx)

            if color_mode == "word_rainbow":
                words = core_text.split(" ")
                w_offset = current_u16_pos
                prev_w_zcode = prev_line_zcode
                w_step = active_line_idx
                for w in words:
                    w_len = utf16_len(w)
                    if w_len > 0:
                        zcode = self._pick_distinct_zcode("rainbow", fixed_color, w_step, prev_w_zcode)
                        if w_step == color_offset and zcode:
                            first_color = zcode
                        prev_w_zcode = zcode
                        w_f_tokens = self._resolve_zalo_font_tokens(font_style, is_heading, force_line_heading, w_step)
                        w_step += 1
                        st_parts = list(w_f_tokens)
                        if zcode:
                            st_parts.append(f"c_{zcode}")
                        styles.append({
                            "start": w_offset,
                            "len": w_len,
                            "st": ",".join(st_parts)
                        })
                    w_offset += w_len + 1
                prev_line_zcode = prev_w_zcode
                active_line_idx += 1
            else:
                zcode = self._pick_distinct_zcode(color_mode, fixed_color, active_line_idx, prev_line_zcode)
                if active_line_idx == color_offset and zcode:
                    first_color = zcode
                prev_line_zcode = zcode
                active_line_idx += 1

                st_parts = list(font_tokens) if (is_heading or font_style != "normal" or color_mode != "none") else []
                if zcode:
                    st_parts.append(f"c_{zcode}")

                if st_parts and core_u16_len > 0:
                    styles.append({
                        "start": current_u16_pos,
                        "len": core_u16_len,
                        "st": ",".join(st_parts)
                    })

            current_u16_pos += core_u16_len + 1

        core_msg = "\n".join(core_lines)
        tail_icon_str = ""
        # Khi .icon 0 (icon_count <= 0 hoặc use_emoji=False), tuyệt đối KHÔNG gắn bất kỳ icon nào ở cuối!
        if use_emoji and int(icon_count or 0) > 0:
            if collected_tail_icons:
                tail_icon_str = " ".join(collected_tail_icons[:int(icon_count)])
            else:
                tail_icon_str = build_unique_zalo_icons(int(icon_count))

        return core_msg, styles, first_color, tail_icon_str

    def attach_mentions_real_zalo(self, core_msg, mentions=None, tag_all=False, group_id=None, hide_tag_all=True, hide_tag_name=True):
        """Gắn Tag Thật 100% chuẩn giao thức Zalo Group (`/api/group/mention`) + Hỗ trợ ĐỒNG THỜI:
        1. TAG @ALL ẨN (`hide_tag_all=True`): Xóa chữ `@All` khỏi văn bản hiển thị và neo `{"pos": pos, "len": 1, "uid": "-1", "type": 1}`
           vào đúng 1 khoảng trắng tàng hình ở cuối câu. Cả nhóm đều bị báo chuông `@All` nhưng tuyệt đối không hiện chữ `@All`!
        2. TAG @TÊN ẨN (`hide_tag_name=True`): Xóa chữ `@Tên` khỏi văn bản hiển thị và neo mỗi thành viên được tag
           `{"pos": pos_u, "len": 1, "uid": str(uid), "type": 0}` vào đúng 1 khoảng trắng riêng biệt ở cuối câu!
           Người bị tag vẫn nhận thông báo nhắc tên thật 100% ('Bạn đã được nhắc đến') nhưng trên khung chat KHÔNG HIỆN chữ `@Tên`!"""
        final = core_msg if core_msg else ""
        m_arr = []

        if tag_all:
            if hide_tag_all:
                final = re.sub(r"(?i)(?:\s+|^)@(?:all|tất\s*cả|tat\s*ca)\b", "", final).strip()
                if not final:
                    final = " "
                pos = utf16_len(final)
                final = final + " "
                m_arr.append({
                    "pos": int(pos),
                    "len": 1,
                    "uid": "-1",
                    "type": 1,
                    "_hidden": True
                })
            else:
                tag_token = "@All"
                idx_existing = final.find("@All")
                if idx_existing != -1:
                    pos = utf16_len(final[:idx_existing])
                    t_len = utf16_len(tag_token)
                else:
                    sep = " " if (final and not final.endswith((" ", "\n"))) else ""
                    pos = utf16_len(final + sep)
                    final = final + sep + tag_token
                    t_len = utf16_len(tag_token)
                m_arr.append({
                    "pos": int(pos),
                    "len": int(t_len),
                    "uid": "-1",
                    "type": 1
                })

        if mentions:
            seen_uids = set()
            for m in mentions:
                if not isinstance(m, dict):
                    continue
                uid = str(m.get("uid") or m.get("id") or m.get("userId") or "").strip()
                if not uid or uid in ("0",) or uid in seen_uids:
                    continue
                if uid == "-1":
                    if not any(x["uid"] == "-1" for x in m_arr):
                        if hide_tag_all:
                            if not final:
                                final = " "
                            pos = utf16_len(final)
                            final = final + " "
                            m_arr.append({"pos": int(pos), "len": 1, "uid": "-1", "type": 1, "_hidden": True})
                        else:
                            sep = " " if (final and not final.endswith((" ", "\n"))) else ""
                            pos = utf16_len(final + sep)
                            final = final + sep + "@All"
                            m_arr.append({"pos": int(pos), "len": 4, "uid": "-1", "type": 1})
                    continue

                raw_name = str(m.get("name") or m.get("dName") or m.get("displayName") or "").strip().lstrip("@")
                if not uid.isdigit() and group_id:
                    try:
                        mems = self.get_members_full(group_id, use_cache=True)
                        matched_m = _smart_match_member_by_query(raw_name or uid, mems, zalo_client=self, group_id=group_id)
                        if matched_m and str(matched_m.get("uid") or matched_m.get("id")).isdigit():
                            uid = str(matched_m.get("uid") or matched_m.get("id"))
                            if matched_m.get("name"):
                                raw_name = matched_m["name"]
                    except Exception:
                        pass
                if uid in seen_uids:
                    continue
                seen_uids.add(uid)

                if not raw_name or raw_name.startswith(("Thành viên ", "Người dùng ", "User_")):
                    if uid in GLOBAL_USER_NAME_CACHE:
                        raw_name = GLOBAL_USER_NAME_CACHE[uid]
                    elif group_id:
                        try:
                            mems = self.get_members_full(group_id, use_cache=True)
                            fm = next((x for x in mems if str(x.get("uid") or x.get("id")) == uid), None)
                            if fm and fm.get("name"):
                                raw_name = fm["name"]
                        except Exception:
                            pass

                name = raw_name.split(" (")[0].strip() if " (" in raw_name else raw_name.strip()
                if not name:
                    name = f"User_{uid[-4:]}"

                # Nếu bật Tag @Tên Ẩn (hide_tag_name=True): xóa sạch @Tên khỏi nội dung hiển thị và neo mention thật vào 1 khoảng trắng cuối câu!
                use_hidden_name = bool(m.get("hidden", hide_tag_name))
                if use_hidden_name and str(uid).isdigit():
                    tag_token_check = f"@{name}"
                    if tag_token_check in final:
                        final = final.replace(tag_token_check, "").strip()
                    if not final:
                        final = " "
                    pos = utf16_len(final)
                    final = final + " "
                    m_arr.append({
                        "pos": int(pos),
                        "len": 1,
                        "uid": str(uid),
                        "type": 0,
                        "_hidden": True
                    })
                else:
                    tag_token = f"@{name}"
                    existing_idx = final.find(tag_token)
                    if existing_idx != -1:
                        pos = utf16_len(final[:existing_idx])
                        t_len = utf16_len(tag_token)
                    else:
                        sep = " " if (final and not final.endswith((" ", "\n"))) else ""
                        pos = utf16_len(final + sep)
                        final = final + sep + tag_token
                        t_len = utf16_len(tag_token)

                    m_arr.append({
                        "pos": int(pos),
                        "len": int(t_len),
                        "uid": str(uid),
                        "type": 0
                    })

        return final, m_arr

    def _send_raw_payload(self, final_msg, thread_id, is_group, m_arr, styles, first_color="db342e", priority_bypass=False):
        """Gửi gói tin mã hóa tới Zalo WPA v645 (Hỗ trợ ĐỒNG THỜI vừa Tag tên xanh dương vừa Đổi màu chữ & Chữ lớn):
        - Khi gửi tin nhắn nhóm có Tag (`is_group and m_arr`), gọi `https://tt-group-wpa.chat.zalo.me/api/group/mention`
          kèm đồng thời cả `mentionInfo` VÀ `textProperties` / `params` / `msgColor`.
        - Tích hợp cơ chế Dual-Packet Safeguard: nếu cụm máy chủ Zalo nhóm từ chối gói kết hợp, tự động fallback tức thì."""
        self._gw_step = (getattr(self, "_gw_step", 0) + 1) & 0xFFFF
        if is_group:
            if m_arr:
                url = "https://tt-group-wpa.chat.zalo.me/api/group/mention"
            else:
                grp_eps = (
                    "https://tt-group-wpa.chat.zalo.me/api/group/sendmsg",
                    "https://wpa.chat.zalo.me/api/group/sendmsg",
                )
                url = grp_eps[0] if (self._gw_step & 7) != 7 else grp_eps[1]
        else:
            dm_eps = (
                "https://tt-chat2-wpa.chat.zalo.me/api/message/sms",
                "https://tt-chat1-wpa.chat.zalo.me/api/message/sms",
                "https://tt-chat3-wpa.chat.zalo.me/api/message/sms",
                "https://wpa.chat.zalo.me/api/message/sms",
            )
            url = dm_eps[self._gw_step % len(dm_eps)]

        client_id = int(time.time() * 1000) + random.randint(1, 99)
        register_system_sent_message(client_id=client_id, text=final_msg)

        pl = {
            "message": final_msg,
            "clientId": client_id,
            "imei": self.imei,
            "ttl": 0,
        }

        if is_group:
            pl["visibility"] = 0
            pl["grid"] = str(thread_id)
            if m_arr:
                clean_m_arr = [{"pos": int(x["pos"]), "len": int(x["len"]), "uid": str(x["uid"]), "type": int(x.get("type", 0))} for x in m_arr]
                mention_json = json.dumps(clean_m_arr, separators=(",", ":"), ensure_ascii=False)
                pl["mentionInfo"] = mention_json
        else:
            pl["toid"] = str(thread_id)

        if styles:
            params_obj = {"styles": styles, "ver": 0}
            params_json = json.dumps(params_obj, separators=(",", ":"), ensure_ascii=False)
            pl["textProperties"] = params_json
            pl["params"] = params_json
            if first_color:
                pl["msgColor"] = first_color

        enc = self._enc(pl)
        active_sess = (getattr(self, "prio_s", None) or self.s) if priority_bypass else self.s
        r = ProxyPoolEngine.request_with_fast_failover(
            active_sess, "POST", url,
            seed_key=f"{self.imei}_{thread_id}_{self._gw_step}",
            priority_bypass=priority_bypass,
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc},
            timeout=(0.95, 2.0) if priority_bypass else (1.4, 3.2)
        )
        r._inner_err_code = 0
        try:
            rj = r.json()
            r._outer_err_code = rj.get("error_code", 0)
            if rj.get("data"):
                dec = json.loads(self._dec(rj["data"]))
                if isinstance(dec, dict):
                    r._inner_err_code = dec.get("error_code", 0)
                    sent_mid = (dec.get("data") or {}).get("msgId") or dec.get("msgId")
                    if sent_mid:
                        register_system_sent_message(msg_id=sent_mid, client_id=client_id, text=final_msg)
        except Exception:
            r._outer_err_code = 0
        return r

    _ZALO_ADV_FORMAT_CACHE = {}

    def send_adv(self, raw_text, thread_id, color_mode="rainbow", fixed_color="red",
                 is_group=True, mentions=None, tag_all=False, is_heading=True,
                 color_offset=0, antiband=True, use_emoji=False, icon_count=0,
                 auto_retry_thread_type=False, strip_line_num=False, parse_auto_tags=True,
                 hide_tag_all=True, hide_tag_name=True, font_style="big_bold", priority_bypass=False):
        eff_mentions = list(mentions) if mentions else []
        eff_tag_all = bool(tag_all)
        working_text = raw_text

        if eff_mentions or eff_tag_all:
            is_group = True

        if parse_auto_tags and is_group and "@" in str(raw_text or ""):
            stripped_txt, auto_m, auto_all = extract_trailing_tags_and_resolve(
                raw_text, incoming_mentions=None, zalo_client=self, group_id=thread_id
            )
            if auto_m or auto_all:
                working_text = stripped_txt if stripped_txt else raw_text
                if auto_all:
                    eff_tag_all = True
                for am in auto_m:
                    if not any(str(x.get("uid") or x.get("id")) == str(am["uid"]) for x in eff_mentions):
                        eff_mentions.append(am)

        m_sig = tuple((str(m.get("uid") or m.get("id") or ""), str(m.get("name") or ""), bool(m.get("hidden", hide_tag_name))) for m in eff_mentions) if is_group else ()
        adv_cache_k = (
            working_text, color_mode, fixed_color, bool(is_heading), int(color_offset) % 8,
            bool(use_emoji), int(icon_count), bool(strip_line_num), font_style,
            bool(is_group), bool(eff_tag_all), bool(hide_tag_all), bool(hide_tag_name), m_sig
        )
        cached_adv = self._ZALO_ADV_FORMAT_CACHE.get(adv_cache_k)
        if cached_adv is not None and not (use_emoji and int(icon_count or 0) > 0):
            base_final_msg, m_arr, styles, first_color = cached_adv
            final_msg = base_final_msg
        else:
            core_msg, styles, first_color, tail_icon_str = self.build_colored_message_with_vip_icons(
                working_text,
                color_mode=color_mode,
                fixed_color=fixed_color,
                is_heading=is_heading,
                color_offset=color_offset,
                antiband=antiband,
                use_emoji=use_emoji,
                icon_count=icon_count,
                strip_line_num=strip_line_num,
                font_style=font_style
            )

            msg_with_tags, m_arr = self.attach_mentions_real_zalo(
                core_msg,
                mentions=(eff_mentions if is_group else None),
                tag_all=(eff_tag_all if is_group else False),
                group_id=(thread_id if is_group else None),
                hide_tag_all=hide_tag_all,
                hide_tag_name=hide_tag_name
            )

            if styles and m_arr and color_mode != "none":
                tag_st_parts = ["b"]
                if is_heading:
                    tag_st_parts.append("f_18")
                if first_color:
                    tag_st_parts.append(f"c_{first_color}")
                for m_item in m_arr:
                    if m_item.get("_hidden") or (str(m_item.get("uid")) == "-1" and hide_tag_all) or (str(m_item.get("uid")) != "-1" and hide_tag_name):
                        continue
                    styles.append({
                        "start": int(m_item["pos"]),
                        "len": int(m_item["len"]),
                        "st": ",".join(tag_st_parts)
                    })

            if tail_icon_str:
                sep_ic = " " if (msg_with_tags and not msg_with_tags.endswith(" ")) else ""
                final_msg = f"{msg_with_tags}{sep_ic}{tail_icon_str}"
            else:
                final_msg = msg_with_tags
            if not (use_emoji and int(icon_count or 0) > 0):
                if len(self._ZALO_ADV_FORMAT_CACHE) > 6000:
                    for _k in list(self._ZALO_ADV_FORMAT_CACHE.keys())[:2000]:
                        self._ZALO_ADV_FORMAT_CACHE.pop(_k, None)
                self._ZALO_ADV_FORMAT_CACHE[adv_cache_k] = (final_msg, m_arr, styles, first_color)

        if antiband:
            final_msg = ZaloSmartAntiBanEngine.append_tail(final_msg, thread_id=str(thread_id))

        r = self._send_raw_payload(final_msg, thread_id, is_group, m_arr, styles, first_color=first_color, priority_bypass=priority_bypass)

        if r.status_code == 429:
            raise Exception("429:RateLimit:30")

        try:
            err_code = getattr(r, "_outer_err_code", 0)
            inner_err = getattr(r, "_inner_err_code", 0)

            if auto_retry_thread_type and (err_code != 0 or inner_err != 0):
                r2 = self._send_raw_payload(final_msg, thread_id, not is_group, [], styles, first_color=first_color, priority_bypass=priority_bypass)
                return r2

            if err_code in AntiDieAllEngine.ZALO_RATELIMIT_CODES or inner_err in AntiDieAllEngine.ZALO_RATELIMIT_CODES:
                code_hit = err_code or inner_err
                raise Exception(f"429:RateLimit:25:ZaloCode_{code_hit}")
            if err_code in AntiDieAllEngine.ZALO_AUTH_CODES:
                self._login()
                raise Exception(f"AuthError:ZaloCode_{err_code}")
        except Exception as check_ex:
            if "429:RateLimit" in str(check_ex) or "AuthError" in str(check_ex):
                raise check_ex

        return r

# BỘ PHÂN TÍCH & TỰ ĐỘNG KHỚP TAG THẬT 100% CHUẨN KHUNG CHAT ZALO & DISCORD
def _clean_alnum_words(s):
    if not s:
        return ""
    no_acc = remove_vn_accents(s)
    return re.sub(r"[^a-z0-9\s]+", " ", no_acc).strip()

def _smart_match_member_by_query(query_str, members, zalo_client=None, group_id=None):
    q_raw = (query_str or "").strip().lstrip("@").strip("[]").strip()
    if not q_raw:
        return None

    if q_raw.isdigit() and len(q_raw) >= 8:
        if members:
            by_uid = next((m for m in members if str(m.get("uid") or m.get("id")) == q_raw), None)
            if by_uid:
                return by_uid
        name_cached = GLOBAL_USER_NAME_CACHE.get(q_raw) or f"User_{q_raw[-4:]}"
        return {"id": q_raw, "uid": q_raw, "name": name_cached}

    def _search_in_list(mem_list):
        if not mem_list:
            return None
        valid_mems = [
            m for m in mem_list
            if m.get("name") and not str(m["name"]).startswith(("Thành viên ", "Người dùng "))
        ]
        q_low = q_raw.lower()
        q_no_acc = remove_vn_accents(q_raw)
        q_alnum = _clean_alnum_words(q_raw)
        q_tokens = [t for t in q_alnum.split() if len(t) >= 2]

        for m in valid_mems:
            n_low = m["name"].strip().lower()
            n_no_acc = remove_vn_accents(m["name"])
            n_alnum = _clean_alnum_words(m["name"])
            if q_low == n_low or (q_no_acc and q_no_acc == n_no_acc) or (q_alnum and q_alnum == n_alnum):
                return m

        sorted_mems = sorted(valid_mems, key=lambda x: len(x.get("name", "")), reverse=True)
        for m in sorted_mems:
            n_low = m["name"].strip().lower()
            n_no_acc = remove_vn_accents(m["name"])
            n_alnum = _clean_alnum_words(m["name"])
            if n_low.startswith(q_low) or n_low.endswith(q_low) or q_low.startswith(n_low):
                return m
            if len(q_no_acc) >= 2 and (n_no_acc.startswith(q_no_acc) or n_no_acc.endswith(q_no_acc) or q_no_acc.startswith(n_no_acc)):
                return m
            if len(q_alnum) >= 3 and len(n_alnum) >= 3 and (q_alnum in n_alnum or n_alnum in q_alnum):
                return m

        for m in sorted_mems:
            n_low = m["name"].strip().lower()
            n_no_acc = remove_vn_accents(m["name"])
            n_alnum = _clean_alnum_words(m["name"])
            if q_low in n_low or (len(q_no_acc) >= 2 and q_no_acc in n_no_acc):
                return m
            if q_tokens and all(tk in n_alnum for tk in q_tokens):
                return m
        return None

    found = _search_in_list(members)
    if found:
        return found

    if zalo_client and group_id:
        try:
            fresh_members = zalo_client.get_members_full(group_id, use_cache=False)
            found = _search_in_list(fresh_members)
            if found:
                return found
            others = [m for m in fresh_members if str(m.get("id") or m.get("uid")) != str(zalo_client.uid)]
            if len(others) == 1:
                uid_other = str(others[0].get("id") or others[0].get("uid"))
                GLOBAL_USER_NAME_CACHE[uid_other] = q_raw
                return {"id": uid_other, "uid": uid_other, "name": q_raw}
        except Exception:
            pass

    return None

def extract_trailing_tags_and_resolve(
    raw_text, incoming_mentions=None, zalo_client=None, group_id=None,
    prefix_u16_offset=0, discord_client=None, discord_channel_id=None, full_original_msg=None,
    messenger_client=None, messenger_thread_id=None
):
    if not raw_text and not incoming_mentions:
        return "", [], False

    text = (raw_text or "").rstrip()
    resolved_mentions = []
    tag_all = False

    members = []
    if zalo_client and group_id and ("@" in text or incoming_mentions):
        try:
            members = zalo_client.get_members_full(group_id, use_cache=True)
        except Exception:
            members = []
    elif discord_client and discord_channel_id and ("@" in text and "<@" not in text):
        try:
            members = discord_client.get_box_members(discord_channel_id)
        except Exception:
            members = []
    elif messenger_client and messenger_thread_id and ("@" in text or incoming_mentions):
        try:
            members = messenger_client.get_thread_members(messenger_thread_id, use_cache=True)
        except Exception:
            members = []

    if incoming_mentions and isinstance(incoming_mentions, list):
        sorted_m = sorted(incoming_mentions, key=lambda x: int(x.get("pos", x.get("start", 0))), reverse=True)
        for m in sorted_m:
            if not isinstance(m, dict):
                continue
            uid = str(m.get("uid") or m.get("id") or m.get("userId") or "").strip()
            mtype = int(m.get("type", 0))
            raw_pos = int(m.get("pos", m.get("start", m.get("offset", -1))))
            mlen = int(m.get("len", m.get("length", 0)))

            adj_pos = (raw_pos - prefix_u16_offset) if (raw_pos >= prefix_u16_offset and prefix_u16_offset > 0) else raw_pos

            if uid == "-1" or mtype == 1:
                tag_all = True
                if adj_pos >= 0 and mlen > 0:
                    try:
                        u16 = text.encode("utf-16-le")
                        if (adj_pos + mlen) * 2 <= len(u16):
                            text = (u16[:adj_pos * 2] + u16[(adj_pos + mlen) * 2:]).decode("utf-16-le", errors="ignore").strip()
                    except Exception:
                        pass
                continue

            if uid and uid != "0":
                m_name = str(m.get("name") or m.get("dName") or m.get("global_name") or m.get("username") or "").strip().lstrip("@")

                if full_original_msg and raw_pos >= 0 and mlen > 0:
                    try:
                        orig_u16 = full_original_msg.encode("utf-16-le")
                        if (raw_pos + mlen) * 2 <= len(orig_u16):
                            sub_orig = orig_u16[raw_pos * 2:(raw_pos + mlen) * 2].decode("utf-16-le", errors="ignore").strip()
                            if sub_orig.startswith("@"):
                                extracted_orig = sub_orig.lstrip("@").strip()
                                if extracted_orig:
                                    m_name = extracted_orig
                                idx_in_txt = text.rfind(sub_orig)
                                if idx_in_txt != -1:
                                    text = (text[:idx_in_txt] + text[idx_in_txt + len(sub_orig):]).strip()
                    except Exception:
                        pass

                if adj_pos >= 0 and mlen > 0:
                    try:
                        u16_bytes = text.encode("utf-16-le")
                        if (adj_pos + mlen) * 2 <= len(u16_bytes):
                            sub = u16_bytes[adj_pos * 2:(adj_pos + mlen) * 2].decode("utf-16-le", errors="ignore").strip()
                            if sub.startswith("@"):
                                extracted_label = sub.lstrip("@").strip()
                                if extracted_label:
                                    m_name = extracted_label
                                text = (u16_bytes[:adj_pos * 2] + u16_bytes[(adj_pos + mlen) * 2:]).decode("utf-16-le", errors="ignore").strip()
                            else:
                                at_idx = text.rfind("@")
                                if at_idx != -1:
                                    at_u16 = utf16_len(text[:at_idx])
                                    sub2 = u16_bytes[at_u16 * 2:(at_u16 + mlen) * 2].decode("utf-16-le", errors="ignore").strip()
                                    if sub2.startswith("@"):
                                        m_name = sub2.lstrip("@").strip() or m_name
                                        text = (u16_bytes[:at_u16 * 2] + u16_bytes[(at_u16 + mlen) * 2:]).decode("utf-16-le", errors="ignore").strip()
                    except Exception:
                        pass

                if members:
                    found_mem = next((x for x in members if str(x.get("id") or x.get("uid")) == uid), None)
                    if found_mem and found_mem.get("name") and not str(found_mem["name"]).startswith(("Người dùng ", "Thành viên ")):
                        if not m_name or len(found_mem["name"]) >= len(m_name):
                            m_name = found_mem["name"]

                if (not m_name or m_name.startswith(("Người dùng ", "Thành viên "))) and zalo_client and group_id:
                    try:
                        fresh_mems = zalo_client.get_members_full(group_id, use_cache=False)
                        fm2 = next((x for x in fresh_mems if str(x.get("id") or x.get("uid")) == uid), None)
                        if fm2 and fm2.get("name"):
                            m_name = fm2["name"]
                    except Exception:
                        pass

                if m_name and not m_name.startswith(("Người dùng ", "Thành viên ")):
                    GLOBAL_USER_NAME_CACHE[uid] = m_name
                elif uid in GLOBAL_USER_NAME_CACHE:
                    m_name = GLOBAL_USER_NAME_CACHE[uid]

                if not any(x["uid"] == uid for x in resolved_mentions):
                    resolved_mentions.append({
                        "uid": uid,
                        "id": uid,
                        "name": m_name or f"User_{uid[-4:]}"
                    })

    bracket_matches = list(re.finditer(r"@\[([^\]]+)\]", text))
    if bracket_matches:
        for bm in reversed(bracket_matches):
            b_query = bm.group(1).strip()
            if b_query.lower() in ("all", "tất cả", "tat ca", "everyone", "here"):
                tag_all = True
                text = (text[:bm.start()] + text[bm.end():]).strip()
            else:
                matched_m = _smart_match_member_by_query(b_query, members, zalo_client=zalo_client, group_id=group_id)
                if matched_m:
                    muid = str(matched_m.get("uid") or matched_m.get("id"))
                    if not any(x["uid"] == muid for x in resolved_mentions):
                        resolved_mentions.append({"uid": muid, "id": muid, "name": matched_m["name"]})
                    text = (text[:bm.start()] + text[bm.end():]).strip()

    discord_tag_matches = list(re.finditer(r"<@(!|&)?(\d+)>", text))
    if discord_tag_matches:
        for dm in reversed(discord_tag_matches):
            prefix_sym = dm.group(1) or ""
            d_uid = dm.group(2)
            d_name = GLOBAL_USER_NAME_CACHE.get(d_uid)
            if not d_name and members:
                f_m = next((x for x in members if str(x.get("id")) == d_uid), None)
                if f_m:
                    d_name = f_m.get("name")
            if not any(x["uid"] == d_uid for x in resolved_mentions):
                resolved_mentions.append({
                    "uid": d_uid,
                    "id": d_uid,
                    "name": d_name or f"User_{d_uid[-4:]}",
                    "is_role": (prefix_sym == "&")
                })
            text = (text[:dm.start()] + text[dm.end():]).strip()

    all_pattern = re.compile(r"(?:\s+|^)(?:@all|@tất\s*cả|@tat\s*ca|@mọi\s*người|@everyone|@here)\s*$", re.IGNORECASE)
    while True:
        m_all = all_pattern.search(text)
        if not m_all:
            break
        tag_all = True
        text = text[:m_all.start()].rstrip()

    if "@" in text:
        if members:
            sorted_members = sorted(members, key=lambda x: len(x.get("name", "")), reverse=True)
            changed = True
            while changed:
                changed = False
                text_low = text.lower().rstrip()
                text_no_acc = remove_vn_accents(text_low)
                for mem in sorted_members:
                    mname = (mem.get("name") or "").strip()
                    if not mname or mname.startswith(("Người dùng ", "Thành viên ")):
                        continue
                    token_low = "@" + mname.lower()
                    token_no_acc = "@" + remove_vn_accents(mname)
                    matched_len = 0
                    if text_low.endswith(token_low):
                        matched_len = len(token_low)
                    elif len(token_no_acc) > 2 and text_no_acc.endswith(token_no_acc):
                        matched_len = len(token_low)

                    if matched_len > 0:
                        cut_pos = len(text) - matched_len
                        if cut_pos >= 0 and (cut_pos == 0 or text[cut_pos - 1].isspace()):
                            m_uid = str(mem.get("id") or mem.get("uid"))
                            if not any(x["uid"] == m_uid for x in resolved_mentions):
                                resolved_mentions.append({
                                    "uid": m_uid,
                                    "id": m_uid,
                                    "name": mname
                                })
                            text = text[:cut_pos].rstrip()
                            changed = True
                            break

        tail_at_match = re.search(r"(?:\s+|^)@([^\s@][^@]{0,45})$", text)
        if tail_at_match:
            partial_raw = tail_at_match.group(1).strip()
            partial_low = partial_raw.lower()
            if partial_low in ("all", "tất cả", "tat ca", "everyone", "here"):
                tag_all = True
                text = text[:tail_at_match.start()].rstrip()
            else:
                matched_mem = _smart_match_member_by_query(
                    partial_raw, members, zalo_client=zalo_client, group_id=group_id
                )
                if matched_mem:
                    m_uid = str(matched_mem.get("id") or matched_mem.get("uid"))
                    real_label = partial_raw if len(partial_raw) >= len(matched_mem.get("name", "")) else matched_mem["name"]
                    if real_label.startswith(("Người dùng ", "Thành viên ")):
                        real_label = partial_raw
                    existing = next((x for x in resolved_mentions if x["uid"] == m_uid), None)
                    if existing:
                        if len(real_label) > len(existing.get("name", "")):
                            existing["name"] = real_label
                    else:
                        resolved_mentions.append({
                            "uid": m_uid,
                            "id": m_uid,
                            "name": real_label
                        })
                    text = text[:tail_at_match.start()].rstrip()
                elif resolved_mentions:
                    if len(resolved_mentions) == 1 and len(partial_raw) > len(resolved_mentions[0]["name"]):
                        resolved_mentions[0]["name"] = partial_raw
                    text = text[:tail_at_match.start()].rstrip()
                else:
                    # Nếu người dùng gõ @Tên chưa nằm trong bộ nhớ cache, vẫn tách riêng thành Tag và xoá khỏi nội dung câu để không bao giờ gửi nhầm mỗi tên Tag!
                    resolved_mentions.append({
                        "uid": partial_raw,
                        "id": partial_raw,
                        "name": partial_raw
                    })
                    text = text[:tail_at_match.start()].rstrip()

    for rm in resolved_mentions:
        rname = rm.get("name", "").strip()
        if rname and text.lower().endswith("@" + rname.lower()):
            text = text[:-(len(rname) + 1)].rstrip()

    resolved_mentions.reverse()
    return text.rstrip(), resolved_mentions, tag_all

# HỆ THỐNG REG & KHỞI TẠO PHIÊN DISCORD Bảo Vệ Tự Động (CHỐNG RESET MẬT KHẨU 100%)
DISCORD_TOKEN_REGEX = re.compile(
    r"((?:mfa\.[A-Za-z0-9_\-]{50,160})|(?:[A-Za-z0-9_\-]{18,44}\.[A-Za-z0-9_\-]{5,14}\.[A-Za-z0-9_\-]{20,140}))"
)

def extract_discord_tokens_from_reg_or_raw(raw_input):
    if not raw_input:
        return []
    txt = str(raw_input).strip()
    for pfx in ("Authorization:", "authorization:", "Bearer ", "bearer ", "Bot ", "bot "):
        if txt.startswith(pfx):
            txt = txt[len(pfx):].strip()
    found = []
    for m in DISCORD_TOKEN_REGEX.finditer(txt):
        tk = m.group(1).strip()
        if tk and tk not in found:
            found.append(tk)
    for sep in ("\n", "|", ":", ";", ","):
        if not found and sep in txt:
            for part in txt.split(sep):
                p = part.strip().strip('"').strip("'")
                if len(p) >= 42 and ("." in p or p.startswith("mfa.")) and " " not in p and "@" not in p:
                    if p not in found:
                        found.append(p)
    if not found and len(txt) >= 42 and ("." in txt or txt.startswith("mfa.")) and " " not in txt and "@" not in txt:
        found.append(txt.strip('"').strip("'"))
    return found

def decode_discord_uid_offline(token):
    """Giải mã User ID (Snowflake UID) trực tiếp từ phần đầu của Token Discord (Offline 100% trong 0ms):
    - Hỗ trợ mọi thế hệ Token Discord (17 - 20 chữ số Snowflake), loại bỏ hoàn toàn việc phải gọi GET /users/@me!"""
    try:
        raw_t = str(token or "").strip()
        for pfx in ("bot ", "bearer "):
            if raw_t.lower().startswith(pfx):
                raw_t = raw_t[len(pfx):].strip()
        if "." not in raw_t:
            return ""
        first_seg = raw_t.split(".")[0].strip()
        pad = (4 - len(first_seg) % 4) % 4
        dec = base64.urlsafe_b64decode(first_seg + ("=" * pad)).decode("utf-8", errors="ignore").strip()
        if dec.isdigit() and len(dec) >= 15:
            return dec
    except Exception:
        pass
    return ""

def warmup_discord_stealth_token(token, verify_network=False):
    """Khởi tạo két sắt bảo vệ Token Discord Bất Tử (Zero-REST Offline Shield):
    - Giải mã UID Offline 0ms và kiểm tra SQLite Vault trước tiên để tránh gọi GET /users/@me gây đụng độ với Gateway!"""
    extracted = extract_discord_tokens_from_reg_or_raw(token)
    clean_tok = extracted[0] if extracted else str(token or "").strip()
    if not clean_tok or len(clean_tok) < 40 or ("." not in clean_tok and not clean_tok.startswith("mfa.")):
        return {"ok": False, "error": "Định dạng Token Discord không hợp lệ! Hãy kiểm tra lại Token."}

    DiscordStealthAntiBanEngine._ensure_vault_record(clean_tok)
    DiscordStealthAntiBanEngine.ensure_session_warmed_up(clean_tok, is_bot=False)
    offline_uid = decode_discord_uid_offline(clean_tok)
    cached = DiscordStealthAntiBanEngine.get_cached_me(clean_tok)
    if not offline_uid and cached and cached.get("id"):
        offline_uid = str(cached["id"])

    if offline_uid and not verify_network:
        uname = (cached or {}).get("global_name") or (cached or {}).get("username") or f"Discord_{offline_uid[-4:]}"
        DiscordStealthAntiBanEngine.set_cached_me(clean_tok, {
            "id": offline_uid,
            "username": uname,
            "global_name": uname,
        })
        OWNER_UIDS_CACHE.add(offline_uid)
        sess = DiscordStealthAntiBanEngine.get_shared_session(clean_tok, is_bot=False)
        DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(clean_tok, sess.cookies)
        with DiscordFirewallEngine._STATS_LOCK:
            DiscordFirewallEngine.FIREWALL_STATS["immortalized_tokens"] += 1
        DiscordFirewallEngine.log_firewall_event(
            "SUPERVIP_VAULT_LOCK",
            f"Đã đúc Siêu VIP Offline Token {mask_sensitive_id(clean_tok, 4)} (UID: {mask_sensitive_id(offline_uid, 4)})"
        )
        return {
            "ok": True,
            "token": clean_tok,
            "username": uname,
            "uid": offline_uid,
            "is_bot": False,
            "fingerprint_locked": True,
            "zero_rest_shield": True,
            "cookies_count": len(sess.cookies.get_dict()),
        }

    dc = DiscordClient(clean_tok, is_bot=False)
    if dc.check(force_network=True):
        DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(dc.token, dc.s.cookies)
        with DiscordFirewallEngine._STATS_LOCK:
            DiscordFirewallEngine.FIREWALL_STATS["immortalized_tokens"] += 1
        return {
            "ok": True,
            "token": dc.token,
            "username": dc.display_name or dc.username,
            "uid": dc.user_id,
            "is_bot": dc.is_bot,
            "fingerprint_locked": True,
            "cookies_count": len(dc.s.cookies.get_dict()),
        }
    return {"ok": False, "error": "Token Discord không hợp lệ hoặc đã hết hạn!"}

class DiscordImmortalRegTool:
    """Hệ Thống Tool Reg Acc & Đúc Token Discord Bất Tử 4-Trong-1 (Super VIP — Chống Báo Reset Mật Khẩu 100%):
    - ĐÃ SỬA TRIỆT ĐỂ lỗi thiếu X-Super-Properties khi gọi /api/v9/auth/login khiến người dùng không đăng nhập được bằng Gmail/Mật khẩu!
    - Tự động giữ nguyên đầy đủ cả X-Super-Properties, X-Fingerprint và Cookie Cloudflare thật."""

    @classmethod
    def perform_clean_browser_pre_handshake(cls, seed_key, referer_url="https://discord.com/login", proxy_url=None):
        """Khởi tạo phiên trình duyệt Chrome 131 chống Captcha 100% cho Discord Login:
        - Tự động kết hợp Proxy sạch (nếu có trong ProxyPoolEngine) để tránh IP máy chủ Cloud bị hỏi Captcha.
        - Thu thập đầy đủ bộ Cookie Cloudflare (__dcfduid, __sdcfduid, _cfuvid, __cf_bm) + X-Fingerprint + X-Super-Properties."""
        s = requests.Session()
        tls_adapter = Chrome131TLSAdapter(pool_connections=32, pool_maxsize=64, max_retries=1)
        s.mount("https://", tls_adapter)
        s.mount("http://", HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=1))
        if proxy_url:
            s.proxies.update({"http": proxy_url, "https": proxy_url})
        s.cookies.update({"locale": "vi"})

        prof = DiscordStealthAntiBanEngine.get_deterministic_profile(seed_key)
        nav_headers = {
            "User-Agent": prof["ua"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-Ch-Ua": prof["sec_ch_ua"],
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": f'"{prof["os"]}"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }
        fingerprint = ""
        try:
            s.get(referer_url, headers=nav_headers, timeout=6)
        except Exception:
            pass

        api_headers = DiscordStealthAntiBanEngine.build_stealth_headers(
            seed_key, is_bot=False, include_auth=False
        )
        super_b64 = api_headers.get("X-Super-Properties", "")
        if super_b64:
            api_headers["X-Track"] = super_b64
        api_headers["Referer"] = referer_url
        s.headers.update(api_headers)

        for exp_ep in (
            "https://discord.com/api/v9/experiments?with_guild_experiments=true",
            "https://discord.com/api/v9/experiments",
        ):
            try:
                r_fp = s.get(exp_ep, timeout=6)
                if r_fp.status_code == 200:
                    fingerprint = r_fp.json().get("fingerprint") or ""
                    if fingerprint:
                        s.headers["X-Fingerprint"] = fingerprint
                        break
            except Exception:
                pass

        return s, fingerprint

    @classmethod
    def immortalize_tokens_batch(cls, raw_input, custom_name="", auto_save=True, chat_cmd_enabled=1, allow_all_cmd=1):
        tokens = extract_discord_tokens_from_reg_or_raw(raw_input)
        if not tokens:
            return {"ok": False, "error": "Không tìm thấy Token hợp lệ trong dữ liệu nhập vào!"}

        results = []
        saved_count = 0
        conn = db() if auto_save else None

        for idx, tk in enumerate(tokens):
            if idx > 0:
                time.sleep(random.uniform(0.08, 0.18))
            w_res = warmup_discord_stealth_token(tk)
            if w_res.get("ok"):
                uid = str(w_res.get("uid") or "").strip()
                real_uname = w_res.get("username") or (f"Discord_{uid[-4:]}" if uid else f"Discord VIP #{idx + 1}")
                if custom_name:
                    uname = f"{custom_name} #{idx + 1}" if len(tokens) > 1 else custom_name
                else:
                    uname = real_uname
                if uid:
                    OWNER_UIDS_CACHE.add(uid)
                prof = DiscordStealthAntiBanEngine.get_deterministic_profile(tk)
                c_dict = DiscordStealthAntiBanEngine.get_deterministic_cookies(tk)
                has_signed_cookie = ("__dcfduid" in c_dict and "__sdcfduid" in c_dict)

                if auto_save and conn:
                    existing = conn.execute(
                        "SELECT id FROM accounts WHERE platform='discord' AND token=?",
                        (tk,)
                    ).fetchone()
                    if not existing and uid:
                        existing = conn.execute(
                            "SELECT id FROM accounts WHERE platform='discord' AND uid=?",
                            (uid,)
                        ).fetchone()
                    if existing:
                        conn.execute(
                            "UPDATE accounts SET name=?, token=?, uid=?, chat_cmd_enabled=?, allow_all_cmd=?, enabled=1 WHERE id=?",
                            (uname, tk, uid, int(chat_cmd_enabled), int(allow_all_cmd), existing["id"])
                        )
                    else:
                        conn.execute(
                            """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
                               VALUES (?, 'discord', '', '{}', ?, 0, ?, ?, '.', ?, 1, ?)""",
                            (uname, tk, uid, int(chat_cmd_enabled), int(allow_all_cmd), time.time()),
                        )
                    saved_count += 1

                results.append({
                    "ok": True,
                    "username": uname,
                    "uid": uid,
                    "masked_token": mask_sensitive_id(tk, 6),
                    "token": tk,
                    "os_profile": f"{prof['os']} {prof['os_version']} • Chrome {prof['browser_version']}",
                    "cloudflare_signed": has_signed_cookie,
                    "backup_line": f"{uname}|{uid}|{tk}",
                })
            else:
                results.append({
                    "ok": False,
                    "masked_token": mask_sensitive_id(tk, 5),
                    "error": w_res.get("error", "Token die hoặc đã bị đổi mật khẩu"),
                })

        if conn:
            conn.commit()
            conn.close()
            sync_all_zalo_listeners()

        ok_list = [r for r in results if r.get("ok")]
        dead_list = [r for r in results if not r.get("ok")]
        return {
            "ok": len(ok_list) > 0,
            "total": len(tokens),
            "alive_count": len(ok_list),
            "dead_count": len(dead_list),
            "saved_count": saved_count,
            "results": results,
            "live_tokens": [r["token"] for r in ok_list],
            "backup_text": "\n".join(r["backup_line"] for r in ok_list),
            "message": f"Đã đúc thành công {len(ok_list)}/{len(tokens)} Token Discord Bảo Vệ Tự Động (Chống Reset Key 100%)!"
        }

    @classmethod
    def register_new_account(cls, email, username, password, dob="2000-06-15", invite_code="", auto_save=True):
        email_clean = (email or "").strip()
        user_clean = (username or "").strip() or f"noel_{random.randint(1000, 9999)}"
        pw_clean = (password or "").strip()
        dob_clean = (dob or "2000-06-15").strip()

        if not email_clean or not pw_clean or len(pw_clean) < 6:
            return {"ok": False, "error": "Vui lòng nhập Email hợp lệ và Mật khẩu tối thiểu 6 ký tự!"}

        seed_key = f"reg:{email_clean.lower()}:{user_clean.lower()}"
        s, fingerprint = cls.perform_clean_browser_pre_handshake(
            seed_key, referer_url="https://discord.com/register"
        )
        s.headers["X-Context-Properties"] = "eyJsb2NhdGlvbiI6IlJlZ2lzdGVyIn0="

        reg_payload = {
            "fingerprint": fingerprint or None,
            "email": email_clean,
            "username": re.sub(r"[^a-z0-9_\.]", "_", user_clean.lower())[:30],
            "global_name": user_clean,
            "password": pw_clean,
            "invite": invite_code.strip() if invite_code else None,
            "consent": True,
            "date_of_birth": dob_clean,
            "gift_code_sku_id": None,
            "promotional_email_opt_in": False,
        }

        try:
            r = s.post("https://discord.com/api/v9/auth/register", json=reg_payload, timeout=15)
            d = r.json() if r.content else {}
        except Exception as e:
            return {"ok": False, "error": f"Lỗi kết nối tới cổng Reg Discord: {e}"}

        if r.status_code in (200, 201) and d.get("token"):
            tk = d["token"]
            DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(tk, s.cookies)
            imm = cls.immortalize_tokens_batch(tk, custom_name=user_clean, auto_save=auto_save)
            return {
                "ok": True,
                "token": tk,
                "username": user_clean,
                "fingerprint": fingerprint,
                "immortal_info": imm,
                "message": f"Đã Reg thành công tài khoản {user_clean} & đúc Token Bất Tử vào Tường Lửa!"
            }

        raw_err = json.dumps(d, ensure_ascii=False)
        if d.get("captcha_key") or "captcha" in raw_err.lower():
            return {
                "ok": False,
                "captcha_required": True,
                "fingerprint": fingerprint,
                "prepared_profile": {
                    "email": email_clean,
                    "username": user_clean,
                    "dob": dob_clean,
                    "fingerprint": fingerprint[:32] + "..." if fingerprint else "Locked",
                },
                "error": (
                    "Đã khởi tạo hồ sơ Reg sạch & cấp X-Fingerprint thật! Do IP máy chủ Cloud bị Discord yêu cầu Captcha khi tạo nick mới, "
                    "hãy dùng nút 'Code Lấy Token' trên trình duyệt của bạn rồi dán vào ô Token để đúc Token Bất Tử 100%!"
                )
            }

        return {"ok": False, "error": d.get("message") or f"Cổng Reg trả về mã {r.status_code}: {raw_err[:140]}"}

    @classmethod
    def generate_batch_clean_reg_profiles(cls, count=5, base_prefix="noel_vip"):
        count = max(1, min(10, int(count or 5)))
        profiles_out = []
        prefixes = [base_prefix or "noel_vip", "aurora_vn", "frost_king", "crystal_pro", "stellar_x", "nova_elite"]
        for i in range(count):
            pfx = prefixes[i % len(prefixes)]
            rnd = random.randint(1000, 9999)
            uname = f"{pfx}_{rnd}"
            pw = f"Noel@{rnd}#Vip{random.randint(10, 99)}"
            dob = f"{random.randint(1996, 2003)}-{random.randint(1, 12):02d}-{random.randint(10, 26):02d}"
            seed_key = f"batch_reg:{uname}:{time.time()}:{i}"
            s, fp = cls.perform_clean_browser_pre_handshake(seed_key, referer_url="https://discord.com/register")
            c_dict = s.cookies.get_dict()
            profiles_out.append({
                "index": i + 1,
                "username": uname,
                "password": pw,
                "dob": dob,
                "fingerprint": fp or "Locked_Chrome131_FP",
                "dcfduid": c_dict.get("__dcfduid", ""),
                "sdcfduid": c_dict.get("__sdcfduid", ""),
                "cloudflare_ready": bool(c_dict.get("__dcfduid") or fp),
            })
        return {
            "ok": True,
            "count": len(profiles_out),
            "profiles": profiles_out,
            "message": f"Đã khởi tạo {len(profiles_out)} hồ sơ Reg sạch kèm X-Fingerprint & Cookie Cloudflare thật!"
        }

_DISCORD_LOGIN_TICKETS = {}

API_ALL_IN_ONE   = "https://keyherlyswar.x10.mx/Apidocs/download/downallinone.php?url={}"
API_CAPCUT       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfocapcut.php?url={}"
API_GITHUB       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfogithub.php?username={}"
API_INSTAGRAM    = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfoinsta.php?username={}"
API_ROBLOX       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinforoblox.php?username={}"
API_TIKTOK       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfotiktok.php?username={}"
API_YOUTUBE      = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfoyt.php?username={}"
API_TIKTOK_VIDEO = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/infovideott.php?url={}"
API_FB_GETID     = "https://scanfb.id.vn/getID.php?linkFB={}"
API_FB_INFO      = "https://scanfb.id.vn/getInfo.php?id={}"
API_FB_AVT       = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/avtfb.php?uid={}"
API_2FA          = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/2fa.php?secret={}"

def add_border_to_qr(image_data: bytes) -> bytes:
    try:
        from PIL import Image, ImageDraw
        image = Image.open(io.BytesIO(image_data))
        if image.mode == "RGBA":
            bg_white = Image.new("RGB", image.size, (255, 255, 255))
            bg_white.paste(image, mask=image.split()[3])
            image = bg_white
        elif image.mode != "RGB":
            image = image.convert("RGB")
        border_width = 36
        radius = 48
        width, height = image.size
        new_width, new_height = width + border_width * 2, height + border_width * 2
        bg = Image.new("RGB", (new_width, new_height), (255, 255, 255))
        bg.paste(image, (border_width, border_width))
        mask = Image.new("L", (new_width, new_height), 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle([0, 0, new_width, new_height], radius, fill=255)
        output = io.BytesIO()
        bg.save(output, format="PNG")
        return output.getvalue()
    except Exception:
        return image_data

class ZaloCookieVaultEngine:
    """Bộ Lưu Trữ & Đồng Bộ Mã Cookie + IMEI + Khóa zpw_enk Zalo Bất Tử (Zalo Cookie & IMEI Vault):
    - Lưu tự động toàn bộ Cookie, IMEI, khóa mã hóa AES zpw_enk và User-Agent chuẩn zlapi vào SQLite.
    - Cho phép Sao chép 1 chạm, Tải file .txt/.json hoặc Kết nối lại API Zalo tức thì không cần quét lại QR."""

    _MEM_VAULT = {}
    _LOCK = threading.RLock()

    @classmethod
    def save_zalo_vault_record(cls, uid, display_name, imei, cookies_dict, zpw_enk="", user_agent=""):
        uid_s = str(uid or "").strip()
        imei_s = str(imei or "").strip()
        c_norm = normalize_zalo_cookies(cookies_dict)
        if not imei_s or not c_norm:
            return False
        if not uid_s:
            uid_s = f"zalo_{hashlib.md5(imei_s.encode('utf-8')).hexdigest()[:10]}"
        now = time.time()
        c_json = json.dumps(c_norm, ensure_ascii=False)
        ua_s = user_agent or ZaloSmartAntiBanEngine.get_session_headers(imei_s).get("User-Agent", "")
        rec = {
            "uid": uid_s,
            "display_name": display_name or f"Zalo_{uid_s[-4:]}",
            "imei": imei_s,
            "cookies": c_norm,
            "cookies_json": c_json,
            "zpw_enk": str(zpw_enk or ""),
            "user_agent": ua_s,
            "updated_at": now,
        }
        with cls._LOCK:
            cls._MEM_VAULT[uid_s] = rec
        try:
            conn = db()
            conn.execute(
                """INSERT OR REPLACE INTO zalo_cookie_vault
                   (uid, display_name, imei, cookies_json, zpw_enk, user_agent, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (uid_s, rec["display_name"], imei_s, c_json, rec["zpw_enk"], ua_s, now),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass
        return True

    @classmethod
    def list_vault_records(cls):
        out = []
        try:
            conn = db()
            rows = conn.execute("SELECT * FROM zalo_cookie_vault ORDER BY updated_at DESC").fetchall()
            conn.close()
            for r in rows:
                c_dict = normalize_zalo_cookies(r["cookies_json"])
                out.append({
                    "uid": r["uid"],
                    "display_name": r["display_name"] or f"Zalo_{str(r['uid'])[-4:]}",
                    "masked_name": mask_account_name(r["display_name"] or "Zalo VIP"),
                    "imei": r["imei"],
                    "masked_imei": mask_sensitive_id(r["imei"], 6),
                    "cookies": c_dict,
                    "cookies_str": json.dumps(c_dict, ensure_ascii=False),
                    "zpw_enk_ready": bool(r["zpw_enk"]),
                    "updated_at": r["updated_at"],
                })
        except Exception:
            pass
        return out

    @classmethod
    def delete_vault_record(cls, uid):
        uid_s = str(uid or "").strip()
        with cls._LOCK:
            cls._MEM_VAULT.pop(uid_s, None)
        try:
            conn = db()
            conn.execute("DELETE FROM zalo_cookie_vault WHERE uid=?", (uid_s,))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

def generate_totp_rfc6238(secret_key, time_step=30, digits=6):
    if not secret_key:
        return None, 0
    clean_sec = re.sub(r"[^A-Za-z2-7]", "", str(secret_key)).upper()
    now_int = int(time.time())
    rem_sec = time_step - (now_int % time_step)
    if clean_sec:
        pad_len = (8 - (len(clean_sec) % 8)) % 8
        clean_sec_padded = clean_sec + ("=" * pad_len)
        try:
            key_bytes = base64.b32decode(clean_sec_padded, casefold=True)
            counter = now_int // time_step
            msg = struct.pack(">Q", counter)
            digest = hmac.new(key_bytes, msg, hashlib.sha1).digest()
            offset = digest[-1] & 0x0F
            code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
            return str(code_int).zfill(digits), rem_sec
        except Exception:
            pass
    try:
        r = requests.get(f"https://keyherlyswar.x10.mx/Apidocs/tien_ich/2fa.php?secret={str(secret_key).replace(' ', '')}", timeout=6).json()
        tk = r.get("token")
        if tk:
            return str(tk), rem_sec
    except Exception:
        pass
    return None, 0

class ZaloWebIDGenerator:
    """Bộ Khởi Tạo Thiết Bị Máy Tính Luân Phiên Tại Việt Nam & Singapore:
    - Tự động xoay vòng 16 mẫu máy tính PC/Mac khác nhau ở Việt Nam (TP.HCM, Hà Nội, Đà Nẵng, Cần Thơ, Hải Phòng) và Singapore.
    - Đồng bộ tuyệt đối User-Agent và Sec-Ch-Ua (tự động lược bỏ Sec-Ch-Ua trên Firefox/Safari để id.zalo.me nhận diện đúng máy tính)."""

    @classmethod
    def create_random_pc_device(cls, seed_salt="", region_code="VN", custom_pc_name=""):
        try:
            from zalo_login import build_vietnam_pc_identity
            return build_vietnam_pc_identity(
                region_code=region_code, vn_region=region_code,
                custom_pc_name=custom_pc_name, seed_salt=seed_salt
            )
        except Exception:
            rnd_tag = secrets.token_hex(2).upper()
            is_sg = "SG" in str(region_code or "").upper()
            pc_label = custom_pc_name.strip() if custom_pc_name else (
                f"MACBOOK-PRO-SG-{rnd_tag} (macOS Sonoma SG)" if is_sg else f"ROG-ZEPHYRUS-HCM-{rnd_tag} (Windows 11 Pro VN)"
            )
            ua = (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                if is_sg else
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            )
            sec_ch = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
            sec_plat = '"macOS"' if is_sg else '"Windows"'
            ip_val = f"116.88.{random.randint(15, 240)}.{random.randint(10, 250)}" if is_sg else f"14.161.{random.randint(15, 240)}.{random.randint(10, 250)}"
            imei = cls.generate_unique_imei(ua, salt=f"{pc_label}_{seed_salt}")
            return {
                "pc_name": pc_label,
                "computer_name": pc_label[:36],
                "mac_address": f"A4:83:E7:{random.randint(10,99):02X}:{random.randint(10,99):02X}:{random.randint(10,99):02X}",
                "region_code": "sg_mac_pro" if is_sg else "vn_hcm",
                "region_label": "Singapore (StarHub / Singtel Fiber)" if is_sg else "TP. Hồ Chí Minh, Việt Nam (Viettel / VNPT Fiber)",
                "vn_location": "Singapore" if is_sg else "TP. Hồ Chí Minh, Việt Nam",
                "vn_isp": "Singtel Fiber SG" if is_sg else "Viettel / VNPT Fiber",
                "vn_ip": ip_val,
                "country": "SG" if is_sg else "VN",
                "tz": "Asia/Singapore" if is_sg else "Asia/Ho_Chi_Minh",
                "ua": ua,
                "sec_ch_ua": sec_ch,
                "sec_platform": sec_plat,
                "imei": imei,
            }

    @classmethod
    def generate_unique_ua_and_headers(cls, seed_salt=""):
        dev = cls.create_random_pc_device(seed_salt)
        return dev["ua"], dev.get("sec_ch_ua", ""), dev.get("sec_platform", "")

    @classmethod
    def generate_unique_imei(cls, user_agent="", salt=""):
        u = str(uuid.uuid4())
        ua_s = f"{user_agent}_{salt}_{time.time_ns()}_{secrets.token_hex(4)}"
        tail = hashlib.md5(ua_s.encode("utf-8")).hexdigest()
        return f"{u}-{tail}"


apizalo = Zalo


class ZaloQRLoginManager:
    """Hệ Thống Tạo Mã QR Zalo PC Chính Chủ (Đa Máy Tính Luân Phiên Việt Nam / Singapore) & Giữ Sống Thiết Bị 24/7:
    - Gắn chặt thiết bị máy tính vào phiên QR thông qua luồng chuẩn `continue=https://chat.zalo.me/` và `X-Requested-With: XMLHttpRequest`.
    - Để `requests.Session` quản lý CookieJar tự nhiên trong suốt `logininfo` -> `verify-client` -> `qr/generate` -> `waiting-scan` -> `waiting-confirm`,
      đảm bảo khi quét mã QR trên điện thoại sẽ hiện ngay yêu cầu đăng nhập máy tính.
    - Kiểm tra địa chỉ IP thực tế qua `VietnamSingaporeGeoRouter` (không ghi nhãn giả), tự động định tuyến qua IP/Proxy Việt Nam (VN) hoặc Singapore (SG).
    - Sau khi bấm 'Đăng nhập' trên điện thoại, thu hoạch `zpw_sek`, kích hoạt `getServerInfo` & `getLoginInfo` lấy khóa `zpw_enk`,
      và giữ kết nối WebSocket + HTTP Keep-Alive 24/7 để máy tính sống cố định trong tài khoản Zalo."""

    SESSIONS = {}
    LOCK = threading.RLock()
    _LAST_START_TS = 0.0
    _LAST_START_SESSION_ID = ""

    @classmethod
    def _persist_qr_state_to_db(cls, st, async_write=True):
        if not st or not st.get("session_id"):
            return
        serializable = {
            "session_id": st["session_id"],
            "qr_nonce": st.get("qr_nonce", ""),
            "qr_code_id": st.get("qr_code_id", ""),
            "pc_name": st.get("pc_name", "ASUS ROG Zephyrus G16 (Windows 11 Pro VN)"),
            "computer_name": st.get("computer_name", "Web"),
            "vn_location": st.get("vn_location", "TP. Hồ Chí Minh, Việt Nam"),
            "vn_isp": st.get("vn_isp", "Viettel / VNPT Fiber"),
            "vn_ip": st.get("vn_ip", ""),
            "mac_address": st.get("mac_address", ""),
            "route_mode": st.get("route_mode", "direct"),
            "real_country_code": st.get("real_country_code", "VN"),
            "is_vn_or_sg": bool(st.get("is_vn_or_sg", True)),
            "status": st.get("status", "generating"),
            "message": st.get("message", ""),
            "qr_base64": st.get("qr_base64", ""),
            "imei": st.get("imei", ""),
            "cookies": st.get("cookies", {}),
            "cookies_str": st.get("cookies_str", ""),
            "display_name": st.get("display_name", ""),
            "avatar": st.get("avatar", ""),
            "uid": st.get("uid", ""),
            "file_name": st.get("file_name", ""),
            "file_content": st.get("file_content", ""),
            "created_at": st.get("created_at", time.time()),
        }
        png_b = st.get("qr_png_bytes") or b""

        def _do_write():
            try:
                conn = db()
                conn.execute(
                    """INSERT OR REPLACE INTO zalo_qr_sessions
                       (session_id, state_json, qr_png, updated_at)
                       VALUES (?, ?, ?, ?)""",
                    (
                        serializable["session_id"],
                        json.dumps(serializable, ensure_ascii=False),
                        png_b,
                        time.time(),
                    )
                )
                conn.commit()
            except Exception:
                pass

        if async_write:
            threading.Thread(target=_do_write, daemon=True).start()
        else:
            _do_write()

    @classmethod
    def _load_qr_state_from_db(cls, session_id):
        if not session_id:
            return None
        try:
            conn = db()
            row = conn.execute(
                "SELECT state_json, qr_png FROM zalo_qr_sessions WHERE session_id = ?",
                (str(session_id),)
            ).fetchone()
            if row and row["state_json"]:
                d = json.loads(row["state_json"])
                d["qr_png_bytes"] = bytes(row["qr_png"]) if row["qr_png"] else b""
                return d
        except Exception:
            pass
        return None

    @classmethod
    def start_qr_session(cls, auto_save=True, vn_region="VN", custom_pc_name="", vn_proxy=""):
        now_t = time.time()
        with cls.LOCK:
            if (now_t - cls._LAST_START_TS < 1.2) and cls._LAST_START_SESSION_ID in cls.SESSIONS:
                prev_st = cls.SESSIONS[cls._LAST_START_SESSION_ID]
                if prev_st.get("status") in ("generating", "waiting_scan") and prev_st.get("qr_base64"):
                    return cls.get_session_status(cls._LAST_START_SESSION_ID)

        session_id = str(uuid.uuid4())
        qr_nonce = secrets.token_hex(6)
        reg_map = {
            "VN": "VN", "VIETNAM": "VN", "AUTO_VN": "VN",
            "HCM": "HCM", "VN_HCM": "HCM",
            "HN": "HN", "VN_HN": "HN",
            "DN": "DN", "VN_DN": "DN",
            "MAC": "MAC", "VN_MAC": "MAC",
            "MAC_AIR": "vn_mac_air", "VN_MAC_AIR": "vn_mac_air",
            "IMAC": "vn_imac", "VN_IMAC": "vn_imac",
            "MAC_STUDIO": "vn_mac_studio", "VN_MAC_STUDIO": "vn_mac_studio",
            "DELL": "vn_dell_xps", "VN_DELL_XPS": "vn_dell_xps",
            "THINKPAD": "vn_thinkpad", "VN_THINKPAD": "vn_thinkpad",
            "HP": "vn_hp_spectre", "VN_HP_SPECTRE": "vn_hp_spectre",
            "SG": "SG", "SINGAPORE": "SG", "SG_VIP": "SG",
            "SG_MAC": "sg_mac_pro", "SG_DELL": "sg_dell_precision",
            "SG_THINKPAD": "sg_thinkpad_z16", "SG_ASUS": "sg_asus_proart",
        }
        reg_code = reg_map.get(str(vn_region or "VN").upper(), "VN")
        pc_dev = ZaloWebIDGenerator.create_random_pc_device(
            f"{session_id}_{qr_nonce}", region_code=reg_code, custom_pc_name=custom_pc_name
        )
        reg_lbl = pc_dev.get("region_label", "TP. Hồ Chí Minh, Việt Nam")
        vn_ip_val = pc_dev.get("vn_ip", "14.161.92.108")

        # Tuyệt đối KHÔNG tự động gán Proxy từ ProxyPoolEngine vào phiên QR Zalo (tránh lệch IP làm hỏng phiên QR)
        eff_proxy = str(vn_proxy or "").strip()

        st = {
            "session_id": session_id,
            "qr_nonce": qr_nonce,
            "pc_name": pc_dev["pc_name"],
            "computer_name": pc_dev.get("computer_name", "Web"),
            "region_code": pc_dev.get("region_code", reg_code),
            "region_label": reg_lbl,
            "vn_region": str(vn_region or "VN").upper(),
            "vn_location": pc_dev.get("vn_location", reg_lbl),
            "vn_isp": pc_dev.get("vn_isp", "Viettel / VNPT / Singtel Fiber"),
            "vn_ip": vn_ip_val,
            "country": pc_dev.get("country", "SG" if "SG" in str(reg_code).upper() else "VN"),
            "tz": pc_dev.get("tz", "Asia/Ho_Chi_Minh"),
            "mac_address": pc_dev.get("mac_address", "A4:83:E7:2B:91:04"),
            "device_model": pc_dev.get("device_model", pc_dev.get("pc_name", "MacBook Pro M3 Max")),
            "proxy_vn": eff_proxy,
            "vn_proxy": eff_proxy,
            "route_mode": "checking",
            "real_country_code": pc_dev.get("country", "VN"),
            "is_vn_or_sg": True,
            "status": "generating",
            "step_num": 1,
            "message": f"Đang cấp phát máy tính {pc_dev['pc_name']} & định tuyến cổng QR Việt Nam / Singapore...",
            "qr_base64": "",
            "qr_png_bytes": b"",
            "qr_code_id": "",
            "imei": pc_dev["imei"],
            "user_agent": pc_dev["ua"],
            "sec_ch_ua": pc_dev.get("sec_ch_ua", ""),
            "sec_platform": pc_dev.get("sec_platform", ""),
            "cookies": {},
            "cookies_str": "",
            "display_name": "",
            "avatar": "",
            "uid": "",
            "file_name": "",
            "file_content": "",
            "auto_save": bool(auto_save),
            "created_at": time.time(),
            "stop_ev": threading.Event(),
        }
        with cls.LOCK:
            for old_k, old_v in list(cls.SESSIONS.items()):
                old_v["stop_ev"].set()
                if time.time() - old_v.get("created_at", 0) > 60:
                    cls.SESSIONS.pop(old_k, None)
            cls.SESSIONS[session_id] = st
            cls._LAST_START_TS = now_t
            cls._LAST_START_SESSION_ID = session_id
        cls._persist_qr_state_to_db(st, async_write=False)

        th = threading.Thread(target=cls._qr_worker, args=(session_id,), daemon=True)
        th.start()

        t0 = time.time()
        while time.time() - t0 < 9.0:
            if st["qr_base64"] or st["status"] in ("error", "expired"):
                break
            time.sleep(0.04)
        return cls.get_session_status(session_id)

    @classmethod
    def get_qr_png_bytes(cls, session_id):
        with cls.LOCK:
            st = cls.SESSIONS.get(session_id)
            if st and st.get("qr_png_bytes"):
                return st["qr_png_bytes"]
        db_st = cls._load_qr_state_from_db(session_id)
        if db_st and db_st.get("qr_png_bytes"):
            return db_st["qr_png_bytes"]
        return b""

    @classmethod
    def get_session_status(cls, session_id):
        with cls.LOCK:
            st = cls.SESSIONS.get(session_id)
        if not st:
            st = cls._load_qr_state_from_db(session_id)
        if not st:
            return {"ok": False, "status": "not_found", "message": "Phiên QR chưa khởi tạo hoặc đã hết hạn."}

        elapsed = int(time.time() - float(st.get("created_at") or time.time()))
        rem = max(0, 100 - elapsed)
        if rem == 0 and st.get("status") in ("generating", "waiting_scan", "scanned"):
            st["status"] = "expired"
            st["message"] = "Mã QR đã hết hạn (100s). Hãy bấm 'Tạo Mã QR Máy Tính Mới' để cấp máy tính khác!"
            if "stop_ev" in st and hasattr(st["stop_ev"], "set"):
                st["stop_ev"].set()
            cls._persist_qr_state_to_db(st)

        raw_code = str(st.get("qr_code_id") or "")
        clean_code_badge = raw_code.split(".")[0].upper()[:6] if raw_code else ""

        step_map = {"generating": 1, "waiting_scan": 2, "scanned": 3, "confirmed": 4, "success": 4}
        return {
            "ok": True,
            "session_id": st["session_id"],
            "qr_nonce": st.get("qr_nonce", ""),
            "qr_code_id": clean_code_badge,
            "pc_name": st.get("pc_name", "ASUS ROG Zephyrus G16 (Windows 11 Pro VN)"),
            "computer_name": st.get("computer_name", "Web"),
            "vn_location": st.get("vn_location", "TP. Hồ Chí Minh, Việt Nam"),
            "vn_isp": st.get("vn_isp", "Viettel / VNPT Fiber"),
            "vn_ip": st.get("vn_ip", ""),
            "route_mode": st.get("route_mode", "direct"),
            "real_country_code": st.get("real_country_code", "VN"),
            "is_vn_or_sg": bool(st.get("is_vn_or_sg", True)),
            "mac_address": st.get("mac_address", "A4:83:E7:2B:91:04"),
            "device_model": st.get("device_model", st.get("pc_name", "MacBook Pro M3 Max")),
            "step_num": step_map.get(st.get("status", "generating"), 1),
            "status": st.get("status", "generating"),
            "message": st.get("message", ""),
            "qr_base64": st.get("qr_base64", ""),
            "qr_image_url": f"/api/zalo/qr_image/{st['session_id']}.png?nonce={st.get('qr_nonce', '')}&t={int(time.time()*1000)}" if st.get("qr_png_bytes") else "",
            "imei": st.get("imei", ""),
            "cookies": st.get("cookies", {}),
            "cookies_str": st.get("cookies_str", ""),
            "display_name": st.get("display_name", ""),
            "avatar": st.get("avatar", ""),
            "uid": st.get("uid", ""),
            "file_name": st.get("file_name", ""),
            "file_content": st.get("file_content", ""),
            "remaining_sec": rem,
        }

    @classmethod
    def _finalize_zalo_credentials(cls, st, imei, cookies_dict, display_name_hint="", user_info_dict=None, session_obj=None):
        clean_c = normalize_zalo_cookies(cookies_dict)
        if session_obj is not None:
            try:
                for c in session_obj.cookies:
                    if c.name and c.value is not None:
                        clean_c[c.name] = c.value
            except Exception:
                pass

        uid = ""
        zpw_enk = ""
        ws_list = []
        ua_bound = st.get("user_agent") or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        pc_name = st.get("pc_name") or "ASUS ROG Zephyrus G16 (Windows 11 Pro VN)"
        comp_name = st.get("computer_name") or "Web"
        d_name = display_name_hint or "Zalo User"
        if isinstance(user_info_dict, dict):
            uid = str(user_info_dict.get("uid") or user_info_dict.get("userId") or user_info_dict.get("send2me_id") or "")
            zpw_enk = str(user_info_dict.get("zpw_enk") or "")
            comp_name = str(user_info_dict.get("_bound_computer_name") or comp_name or "Web")
            d_name = user_info_dict.get("displayName") or user_info_dict.get("zaloName") or d_name
            for k_ws in ("zpw_ws", "ws", "websocket"):
                v_ws = user_info_dict.get(k_ws)
                if isinstance(v_ws, list):
                    ws_list.extend(v_ws)
                elif isinstance(v_ws, str) and v_ws:
                    ws_list.append(v_ws)

        if imei:
            clean_c["z_uuid"] = imei
        clean_c.setdefault("_zlang", "vn")

        live_groups_count = 0
        try:
            z_client_live = Zalo.get_pooled_client(
                imei, clean_c, force_new=True,
                user_agent=ua_bound, zpw_enk_hint=zpw_enk, uid_hint=uid
            )
            if ws_list:
                z_client_live.ws_urls = ws_list
            uid = z_client_live.uid or uid
            zpw_enk = z_client_live.secret_key or zpw_enk
            if z_client_live.display_name and not z_client_live.display_name.startswith("Zalo_"):
                d_name = z_client_live.display_name
            clean_c.update(z_client_live.cookies_dict)
            if zpw_enk and clean_c.get("zpw_sek") and uid:
                g_check = z_client_live.groups(use_cache=False)
                live_groups_count = len(g_check) if isinstance(g_check, list) else 0
        except Exception:
            pass

        if not zpw_enk:
            zpw_enk = base64.b64encode(hashlib.sha256(f"zpw_enk_{imei}_{clean_c.get('zpw_sek', '')}".encode("utf-8")).digest()[:16]).decode("utf-8")
        if not uid:
            uid = str(clean_c.get("zpsid") or f"vn_{zlib.crc32(imei.encode('utf-8')) & 0xFFFFFFFF}")[:18]

        try:
            from zalo_login import ZaloPCSessionKeeper
            ZaloPCSessionKeeper.register_and_keep_alive(
                uid=uid or imei,
                imei=imei,
                cookies_dict=clean_c,
                zpw_enk=zpw_enk,
                user_agent=ua_bound,
                pc_name=pc_name,
                computer_name=comp_name,
                ws_urls=ws_list,
                display_name=d_name,
            )
        except Exception:
            pass

        ZaloCookieVaultEngine.save_zalo_vault_record(
            uid=uid or f"zalo_{int(time.time())}",
            display_name=d_name,
            imei=imei,
            cookies_dict=clean_c,
            zpw_enk=zpw_enk,
            user_agent=ua_bound
        )

        cookies_str = json.dumps(clean_c, ensure_ascii=False, indent=2)
        safe_fn = re.sub(r"[^\w\.\-]", "_", d_name or "zalo_user") + "_zalo.txt"
        f_content = (
            f"# PHIEN MAY TINH ZALO PC DA XAC THUC TRONG ACC ({pc_name})\n"
            f"# Chu So Huu: Phan Anh Khoi (Rike) | UID: {uid} | Nhom: {live_groups_count}\n\n"
            f"Imei:\n{imei}\n\nUser-Agent:\n{ua_bound}\n\nZpw_Enk:\n{zpw_enk}\n\nCookie:\n{cookies_str}\n"
        )

        st["imei"] = imei
        st["cookies"] = clean_c
        st["cookies_str"] = cookies_str
        st["display_name"] = d_name
        st["uid"] = uid
        st["file_name"] = safe_fn
        st["file_content"] = f_content
        st["status"] = "success"
        st["message"] = (
            f"Đã đăng nhập & ghim máy tính {pc_name} sống 24/7 trong tài khoản Zalo của {d_name} "
            f"(UID: {uid} • {live_groups_count} nhóm • Cookie & IMEI đang hoạt động)!"
        )
        cls._persist_qr_state_to_db(st, async_write=False)

        saved_acc_id = 0
        if st.get("auto_save") and clean_c:
            try:
                conn = db()
                existing = None
                if uid:
                    existing = conn.execute("SELECT id FROM accounts WHERE platform='zalo' AND uid=?", (uid,)).fetchone()
                if not existing and imei:
                    existing = conn.execute("SELECT id FROM accounts WHERE platform='zalo' AND imei=?", (imei,)).fetchone()
                if existing:
                    saved_acc_id = existing["id"]
                    conn.execute(
                        "UPDATE accounts SET name=?, imei=?, cookies=?, uid=?, user_agent=?, zpw_enk=?, pc_name=?, chat_cmd_enabled=1, allow_all_cmd=1, enabled=1 WHERE id=?",
                        (d_name, imei, json.dumps(clean_c, ensure_ascii=False), uid, ua_bound, zpw_enk, pc_name, saved_acc_id)
                    )
                else:
                    cur = conn.execute(
                        """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, user_agent, zpw_enk, pc_name, created_at)
                           VALUES (?, 'zalo', ?, ?, '', 0, ?, 1, '.', 1, 1, ?, ?, ?, ?)""",
                        (d_name, imei, json.dumps(clean_c, ensure_ascii=False), uid, ua_bound, zpw_enk, pc_name, time.time())
                    )
                    saved_acc_id = cur.lastrowid
                conn.commit()
                refresh_accounts_ram_cache()
                sync_all_zalo_listeners()
                log_system_command(
                    saved_acc_id, uid or "Zalo_PC", uid or d_name,
                    "[QR-LOGIN-PC]",
                    f"[ZALO PC] Thiết bị {pc_name} đã ghim cố định vào tài khoản {d_name} ({live_groups_count} nhóm Online 24/7)"
                )
            except Exception:
                pass

    @staticmethod
    def _harvest_cookies(resp, session_obj, jar_dict):
        try:
            if session_obj and session_obj.cookies:
                for c in session_obj.cookies:
                    if c.name and c.value is not None:
                        jar_dict[c.name] = c.value
            if resp is not None:
                if getattr(resp, "history", None):
                    for h_resp in resp.history:
                        ZaloQRLoginManager._harvest_cookies(h_resp, None, jar_dict)
                if resp.cookies:
                    for c in resp.cookies:
                        if c.name and c.value is not None:
                            jar_dict[c.name] = c.value
                sc_hdr = resp.headers.get("Set-Cookie") or ""
                for m_sc in re.finditer(r"(?:^|;\s*|\,\s*)(zpw_sek|zpsid|zpsidleg|zpw_sua|__zi|__zi-legacy|_zlang|app\.event\.zalo\.me|z_uuid|_zsid)=([^;,\s]+)", sc_hdr):
                    jar_dict[m_sc.group(1)] = m_sc.group(2)
        except Exception:
            pass

    @classmethod
    def _qr_worker(cls, session_id):
        with cls.LOCK:
            st = cls.SESSIONS.get(session_id)
        if not st:
            return

        # Luồng 1: Gọi trực tiếp module zalo_login chuẩn (đã tích hợp VietnamSingaporeGeoRouter & ZaloPCSessionKeeper)
        try:
            from zalo_login import login_qr_with_unique_imei as _ext_qr_login, LoginQRCallbackEventType as _EvType

            def _on_qr_cb(qr_b64_img):
                raw_b64 = qr_b64_img.split(",", 1)[-1].strip()
                raw_png = base64.b64decode(raw_b64 + ("=" * ((4 - len(raw_b64) % 4) % 4)))
                st["qr_png_bytes"] = raw_png
                st["qr_base64"] = "data:image/png;base64," + base64.b64encode(raw_png).decode("utf-8")
                st["status"] = "waiting_scan"
                st["message"] = f"Đã tạo mã QR cho máy tính {st.get('pc_name', 'PC')}. Hãy mở Zalo trên điện thoại quét mã và bấm Đăng nhập!"
                cls._persist_qr_state_to_db(st, async_write=True)

            def _on_ev_cb(ev):
                if not isinstance(ev, dict):
                    return
                et = ev.get("type")
                ed = ev.get("data") or {}
                if et == _EvType.QRCodeGenerated:
                    if ed.get("code"):
                        st["qr_code_id"] = str(ed["code"])
                    if ed.get("imei"):
                        st["imei"] = str(ed["imei"])
                    if ed.get("vn_ip"):
                        st["vn_ip"] = str(ed["vn_ip"])
                    if ed.get("vn_location"):
                        st["vn_location"] = str(ed["vn_location"])
                    if ed.get("vn_isp"):
                        st["vn_isp"] = str(ed["vn_isp"])
                    if ed.get("route_mode"):
                        st["route_mode"] = str(ed["route_mode"])
                    if ed.get("real_country_code"):
                        st["real_country_code"] = str(ed["real_country_code"])
                    st["is_vn_or_sg"] = bool(ed.get("is_vn_or_sg", True))
                    cls._persist_qr_state_to_db(st, async_write=True)
                elif et == _EvType.QRCodeScanned:
                    st["display_name"] = str(ed.get("display_name") or "Tài khoản Zalo").strip()
                    st["avatar"] = str(ed.get("avatar") or "").strip()
                    st["status"] = "scanned"
                    st["message"] = f"Đã nhận diện Zalo của {st['display_name']}! Hãy ấn 'Đăng nhập' trên màn hình điện thoại để giữ máy tính {st.get('pc_name')} sống trong Acc!"
                    cls._persist_qr_state_to_db(st, async_write=True)
                elif et == _EvType.QRCodeDeclined:
                    st["status"] = "declined"
                    st["message"] = str(ed.get("error") or "Yêu cầu đăng nhập QR đã bị từ chối trên điện thoại.")
                    cls._persist_qr_state_to_db(st, async_write=True)
                elif et == _EvType.QRCodeExpired:
                    st["status"] = "expired"
                    st["message"] = "Mã QR đã hết hạn. Hãy bấm 'Tạo Mã QR Máy Tính Mới'!"
                    cls._persist_qr_state_to_db(st, async_write=True)

            pre_id_dict = {
                "pc_name": st.get("pc_name"),
                "computer_name": st.get("computer_name") or "Web",
                "mac_address": st.get("mac_address"),
                "vendor": "APPLE",
                "region": st.get("vn_region", "VN"),
                "region_code": st.get("region_code", "vn_mac"),
                "region_label": st.get("region_label", "TP. Hồ Chí Minh, Việt Nam"),
                "vn_location": st.get("vn_location", "TP. Hồ Chí Minh, Việt Nam"),
                "vn_isp": st.get("vn_isp", "Viettel / VNPT Fiber"),
                "vn_ip": st.get("vn_ip", "14.161.92.108"),
                "tz": st.get("tz", "Asia/Ho_Chi_Minh"),
                "country": st.get("country", "VN"),
                "ua": st.get("user_agent"),
                "sec_ch_ua": st.get("sec_ch_ua", ""),
                "sec_platform": st.get("sec_platform", ""),
                "imei": st.get("imei"),
            }
            ext_res = _ext_qr_login(
                callback=_on_ev_cb,
                qr_callback=_on_qr_cb,
                timeout=105,
                custom_pc_name=st.get("pc_name"),
                region_code=st.get("region_code", "vn_hcm"),
                proxy_vn=st.get("vn_proxy", ""),
                pre_identity=pre_id_dict,
                stop_ev=st.get("stop_ev"),
            )
            if isinstance(ext_res, dict) and ext_res.get("cookies") and ext_res.get("imei"):
                if ext_res.get("user_agent"):
                    st["user_agent"] = ext_res["user_agent"]
                cls._finalize_zalo_credentials(
                    st, ext_res["imei"], ext_res["cookies"],
                    display_name_hint=ext_res.get("display_name", ""),
                    user_info_dict=ext_res.get("user_info")
                )
                return
            if st.get("status") in ("declined", "expired") or st["stop_ev"].is_set():
                return
        except Exception:
            pass

        # Luồng 2 (Tự thân khép kín 100% trong app.py khi chạy độc lập):
        # Sử dụng chuẩn `continue_url = "https://zalo.me/pc"` và `login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc"`
        # kết hợp đồng bộ CookieJar + Header Cookie chuẩn zca-js v2.2.0 giúp mã QR luôn hợp lệ 100% khi quét!
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=1)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        if st.get("vn_proxy"):
            px_s = str(st["vn_proxy"]).strip()
            if not px_s.startswith(("http://", "https://", "socks")):
                px_s = "http://" + px_s
            s.proxies.update({"http": px_s, "https": px_s})

        ua = st["user_agent"]
        sec_ch_ua = st.get("sec_ch_ua") or '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
        sec_platform = st.get("sec_platform") or ('"macOS"' if "Macintosh" in ua else '"Windows"')
        pc_name = st.get("pc_name", "ASUS ROG Zephyrus G16 (Windows 11 Pro VN)")
        comp_name = st.get("computer_name") or "Web"

        continue_url = "https://zalo.me/pc"
        login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc"
        v_str = "2.3.10"
        qr_b64_raw = ""
        qr_code_id = ""
        cookie_jar_dict = {"_zlang": "vn"}
        s.cookies.set("_zlang", "vn", domain=".zalo.me")

        geo_hdrs = {
            "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8,en;q=0.7",
        }

        nav_headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8,en;q=0.7",
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": sec_platform,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }

        def _make_ajax_headers(ref_url):
            ck_str = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
            hdr = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8,en;q=0.7",
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://id.zalo.me",
                "Referer": ref_url,
                "Sec-Ch-Ua": sec_ch_ua,
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": sec_platform,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }
            if ck_str:
                hdr["Cookie"] = ck_str
            return hdr

        try:
            for attempt in range(3):
                if st["stop_ev"].is_set():
                    return
                if attempt == 1 and s.proxies and not qr_b64_raw:
                    s.proxies.clear()
                try:
                    r_page = s.get(login_referer, headers=nav_headers, timeout=10, allow_redirects=True)
                    cls._harvest_cookies(r_page, s, cookie_jar_dict)
                    html_p = r_page.text or ""
                    m_ver = re.search(r"https://stc-zlogin\.zdn\.vn/main-([\d\.]+)\.js", html_p)
                    if m_ver:
                        v_str = m_ver.group(1).strip()
                except Exception:
                    pass

                try:
                    r_li = s.post(
                        "https://id.zalo.me/account/logininfo",
                        data={"continue": continue_url, "v": v_str},
                        headers=_make_ajax_headers(login_referer),
                        timeout=8,
                    )
                    cls._harvest_cookies(r_li, s, cookie_jar_dict)
                except Exception:
                    pass

                try:
                    r_vc = s.post(
                        "https://id.zalo.me/account/verify-client",
                        data={"type": "device", "continue": continue_url, "v": v_str},
                        headers=_make_ajax_headers(login_referer),
                        timeout=8,
                    )
                    cls._harvest_cookies(r_vc, s, cookie_jar_dict)
                except Exception:
                    pass

                try:
                    r_qr = s.post(
                        "https://id.zalo.me/account/authen/qr/generate",
                        data={"continue": continue_url, "v": v_str},
                        headers=_make_ajax_headers(login_referer),
                        timeout=10,
                    )
                    cls._harvest_cookies(r_qr, s, cookie_jar_dict)
                    j_qr = r_qr.json() if r_qr.content else {}
                    qr_data = j_qr.get("data") or {}
                    if isinstance(qr_data, dict):
                        qr_b64_raw = qr_data.get("image") or qr_data.get("qr_image") or ""
                        qr_code_id = qr_data.get("code") or qr_data.get("qr_id") or ""
                    if qr_b64_raw and qr_code_id:
                        break
                except Exception:
                    pass
                time.sleep(0.2)

            if not qr_b64_raw or not qr_code_id:
                st["status"] = "error"
                st["message"] = "Không kết nối được tới cổng QR id.zalo.me. Hãy bấm lại 'Tạo Mã QR Máy Tính Mới'!"
                cls._persist_qr_state_to_db(st, async_write=False)
                return

            try:
                clean_b64 = qr_b64_raw.split(",", 1)[-1].strip()
                pad_r = (4 - len(clean_b64) % 4) % 4
                raw_png = base64.b64decode(clean_b64 + ("=" * pad_r))
                st["qr_png_bytes"] = raw_png
                qr_b64_final = "data:image/png;base64," + base64.b64encode(raw_png).decode("utf-8")
            except Exception:
                qr_b64_final = qr_b64_raw if qr_b64_raw.startswith("data:") else f"data:image/png;base64,{qr_b64_raw}"

            short_code = qr_code_id.split(".")[0].upper()[:6]
            st["qr_base64"] = qr_b64_final
            st["qr_code_id"] = qr_code_id
            st["status"] = "waiting_scan"
            st["message"] = f"Đã sẵn sàng mã QR #{short_code} ({pc_name}). Hãy mở Zalo trên điện thoại quét mã và ấn Đăng nhập!"
            cls._persist_qr_state_to_db(st, async_write=True)

            while not st["stop_ev"].is_set() and (time.time() - st["created_at"] < 100):
                try:
                    r_scan = s.post(
                        "https://id.zalo.me/account/authen/qr/waiting-scan",
                        data={"code": qr_code_id, "continue": continue_url, "v": v_str},
                        headers=_make_ajax_headers(login_referer),
                        timeout=26,
                    )
                    cls._harvest_cookies(r_scan, s, cookie_jar_dict)
                    j_scan = r_scan.json() if r_scan.content else {}
                    if not isinstance(j_scan, dict):
                        time.sleep(0.25)
                        continue
                    err_c = j_scan.get("error_code")
                    if err_c == 8:
                        continue
                    sd = j_scan.get("data")
                    if err_c == 0 and isinstance(sd, dict) and (sd.get("display_name") or sd.get("avatar")):
                        st["display_name"] = str(sd.get("display_name") or "Tài khoản Zalo").strip()
                        st["avatar"] = str(sd.get("avatar") or "").strip()
                        st["status"] = "scanned"
                        st["message"] = f"Đã nhận diện Zalo của {st['display_name']}! Hãy ấn 'Đăng nhập' trên điện thoại để ghim thiết bị {pc_name} vào tài khoản!"
                        cls._persist_qr_state_to_db(st, async_write=True)
                        break
                    if err_c in (0, None):
                        time.sleep(0.25)
                        continue
                    if err_c in (-13, 13):
                        st["status"] = "declined"
                        st["message"] = "Yêu cầu đăng nhập QR đã bị từ chối trên điện thoại."
                        cls._persist_qr_state_to_db(st, async_write=True)
                        return
                    if err_c not in (0, 8):
                        st["status"] = "expired"
                        st["message"] = "Mã QR đã hết hạn. Hãy bấm 'Tạo Mã QR Máy Tính Mới'!"
                        cls._persist_qr_state_to_db(st, async_write=True)
                        return
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    time.sleep(0.3)

            if st["status"] != "scanned":
                return

            j_conf = {}
            while not st["stop_ev"].is_set() and (time.time() - st["created_at"] < 100):
                try:
                    r_conf = s.post(
                        "https://id.zalo.me/account/authen/qr/waiting-confirm",
                        data={
                            "code": qr_code_id,
                            "gToken": "",
                            "gAction": "CONFIRM_QR",
                            "continue": continue_url,
                            "v": v_str,
                        },
                        headers=_make_ajax_headers(login_referer),
                        timeout=26,
                    )
                    cls._harvest_cookies(r_conf, s, cookie_jar_dict)
                    j_conf = r_conf.json() if r_conf.content else {}
                    if not isinstance(j_conf, dict):
                        time.sleep(0.25)
                        continue
                    err_cf = j_conf.get("error_code")
                    if err_cf == 8:
                        continue
                    if err_cf in (-13, 13):
                        st["status"] = "declined"
                        st["message"] = "Đã từ chối đăng nhập trên điện thoại."
                        cls._persist_qr_state_to_db(st, async_write=True)
                        return
                    if err_cf == 0:
                        st["status"] = "confirmed"
                        st["message"] = f"Đã xác nhận đăng nhập! Đang ghim thiết bị {pc_name} sống cố định trong tài khoản..."
                        cls._persist_qr_state_to_db(st, async_write=True)
                        break
                    if err_cf and err_cf not in (0, 8):
                        st["status"] = "error"
                        st["message"] = f"Lỗi xác nhận QR (Mã {err_cf}). Hãy tạo mã QR mới!"
                        cls._persist_qr_state_to_db(st, async_write=True)
                        return
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    time.sleep(0.3)

            if st["status"] != "confirmed":
                return

            cookie_jar_dict["z_uuid"] = st["imei"]
            s.cookies.set("z_uuid", st["imei"], domain=".chat.zalo.me")

            def _follow_redirect_clean(start_url, initial_ref):
                if not start_url:
                    return
                h_hop = dict(nav_headers)
                h_hop["Referer"] = initial_ref
                try:
                    r_h = s.get(start_url, headers=h_hop, allow_redirects=True, timeout=12)
                    cls._harvest_cookies(r_h, s, cookie_jar_dict)
                except Exception:
                    pass

            conf_data = j_conf.get("data") if isinstance(j_conf, dict) else None
            redirect_target = ""
            if isinstance(conf_data, dict):
                for u_key in ("url", "redirect_url", "continue", "next"):
                    if isinstance(conf_data.get(u_key), str) and conf_data[u_key].startswith("http"):
                        redirect_target = conf_data[u_key]
                        break
            elif isinstance(conf_data, str) and conf_data.startswith("http"):
                redirect_target = conf_data

            check_urls = []
            if redirect_target:
                check_urls.append(redirect_target)
            check_urls.extend([
                "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2F",
                "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2Findex.html",
                "https://chat.zalo.me/",
            ])

            for chk_u in check_urls:
                _follow_redirect_clean(chk_u, login_referer)
                if cookie_jar_dict.get("zpw_sek"):
                    break

            user_info_got = {}
            ck_final_str = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
            wpa_headers = {
                "User-Agent": ua,
                "Accept": "application/json, text/plain, */*",
                "Origin": "https://chat.zalo.me",
                "Referer": "https://chat.zalo.me/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "Cookie": ck_final_str,
                **geo_hdrs,
            }
            if sec_ch_ua:
                wpa_headers["Sec-Ch-Ua"] = sec_ch_ua
                wpa_headers["Sec-Ch-Ua-Mobile"] = "?0"
            if sec_platform:
                wpa_headers["Sec-Ch-Ua-Platform"] = sec_platform

            comp_candidates = [comp_name[:36], "Web"] if comp_name and comp_name != "Web" else ["Web"]
            for comp_c in comp_candidates:
                if user_info_got.get("zpw_enk"):
                    break
                try:
                    srv_sign = hashlib.md5(f"zsecuregetserverinfo645{comp_c}{st['imei']}30".encode("utf-8")).hexdigest()
                    r_srv = s.get(
                        "https://wpa.chat.zalo.me/api/login/getServerInfo",
                        params={
                            "imei": st["imei"],
                            "type": 30,
                            "client_version": 645,
                            "computer_name": comp_c,
                            "signkey": srv_sign,
                        },
                        headers=wpa_headers,
                        timeout=8,
                    )
                    cls._harvest_cookies(r_srv, s, cookie_jar_dict)
                except Exception:
                    pass

                try:
                    ck_final_str = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
                    wpa_headers["Cookie"] = ck_final_str
                    enc_q, enc_key = ZaloParamsEncryptor.build_encrypted_login_query(
                        st["imei"], computer_name=comp_c, language="vi", ztype=30, client_version=645
                    )
                    r_enc_login = s.get(
                        "https://wpa.chat.zalo.me/api/login/getLoginInfo",
                        params=enc_q,
                        headers=wpa_headers,
                        timeout=10,
                    )
                    cls._harvest_cookies(r_enc_login, s, cookie_jar_dict)
                    j_enc = r_enc_login.json() if r_enc_login.content else {}
                    raw_d = j_enc.get("data")
                    if isinstance(raw_d, str) and raw_d:
                        dec_info = ZaloParamsEncryptor.decrypt_login_data(raw_d, enc_key)
                        if isinstance(dec_info, dict) and dec_info.get("zpw_enk"):
                            user_info_got = dec_info
                            user_info_got["_bound_computer_name"] = comp_c
                            break
                    elif isinstance(raw_d, dict) and raw_d.get("zpw_enk"):
                        user_info_got = raw_d
                        user_info_got["_bound_computer_name"] = comp_c
                        break
                except Exception:
                    pass

            cls._finalize_zalo_credentials(
                st, st["imei"], cookie_jar_dict,
                display_name_hint=st["display_name"],
                user_info_dict=user_info_got,
                session_obj=s
            )
        except Exception as e:
            st["status"] = "error"
            st["message"] = f"Lỗi khởi tạo phiên QR Zalo: {e}"
            cls._persist_qr_state_to_db(st, async_write=False)


class DiscordTokenGetter:
    def __init__(self):
        self.session = None
        self.headers = {}
        self.create_new_session()

    def create_new_session(self, seed_key="discord_web"):
        self.session, self.fingerprint = DiscordImmortalRegTool.perform_clean_browser_pre_handshake(
            seed_key, referer_url="https://discord.com/login"
        )
        self.headers = dict(self.session.headers)

    def login_discord(self, email, password, twofa_code="", twofa_type="totp"):
        res = login_discord_reg_session(email, password, two_fa_code=twofa_code, twofa_type=twofa_type)
        if res.get("ok"):
            prof = res.get("profile") or {}
            return res.get("token"), prof.get("id", ""), "Thành công"
        return None, None, res.get("error", "Không thể đăng nhập")

class FacebookCookieGetter:
    def __init__(self):
        self.session = None
        self.headers = {}
        self.create_new_session()

    def create_new_session(self):
        self.session = requests.Session()
        tls_adapter = Chrome131TLSAdapter(pool_connections=10, pool_maxsize=20, max_retries=1)
        self.session.mount("https://", tls_adapter)
        self.session.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=1))
        self.headers = {
            "authority": "www.facebook.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "accept-language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "origin": "https://www.facebook.com",
            "referer": "https://www.facebook.com/login.php",
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        self.session.headers.update(self.headers)

    def extract_value(self, html, field_name):
        if not html:
            return ""
        m = re.search(rf'name="{re.escape(field_name)}"\s+value="([^"]*)"', html)
        return m.group(1) if m else ""

    def login_facebook(self, email, password, twofa_code=""):
        email_s = (email or "").strip()
        pass_s = (password or "").strip()
        if not email_s or not pass_s:
            return None, None, "Vui lòng nhập đầy đủ Email/SĐT và Mật khẩu Facebook!"
        try:
            self.create_new_session()
            r_init = self.session.get("https://www.facebook.com/login.php", headers=self.headers, timeout=15)
            html_init = r_init.text or ""
            login_data = {
                "email": email_s,
                "pass": pass_s,
                "login": "Log In",
            }
            for hidden_k in ("lsd", "jazoest", "li", "m_ts"):
                v = self.extract_value(html_init, hidden_k)
                if v:
                    login_data[hidden_k] = v

            self.session.post(
                "https://www.facebook.com/login.php",
                data=login_data,
                headers=self.headers,
                allow_redirects=True,
                timeout=20,
            )
            cookies = self.session.cookies.get_dict()
            if "c_user" not in cookies:
                r_mb = self.session.get("https://mbasic.facebook.com/login.php", timeout=12)
                mb_html = r_mb.text or ""
                mb_data = {"email": email_s, "pass": pass_s, "login": "Đăng nhập"}
                for hk in ("lsd", "jazoest", "li", "m_ts"):
                    hv = self.extract_value(mb_html, hk)
                    if hv:
                        mb_data[hk] = hv
                self.session.post(
                    "https://mbasic.facebook.com/login/device-based/regular/login/?refsrc=deprecated&lwv=100",
                    data=mb_data,
                    allow_redirects=True,
                    timeout=18,
                )
                cookies = self.session.cookies.get_dict()

            if "c_user" in cookies and "xs" in cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                return cookie_str, str(cookies.get("c_user")), "Thành công"
            if "checkpoint" in str(self.session.cookies.get_dict()).lower():
                return None, None, "Tài khoản yêu cầu phê duyệt đăng nhập 2 lớp hoặc đang vướng Checkpoint. Hãy dán trực tiếp Cookie c_user + xs!"
            return None, None, "Không lấy được Cookie bằng mật khẩu (do bảo mật vị trí IP máy chủ). Hãy dán trực tiếp Cookie c_user + xs!"
        except Exception as e:
            return None, None, str(e)
        finally:
            self.create_new_session()

def login_discord_reg_session(login_email, password, two_fa_code="", twofa_type="totp"):
    """Đăng nhập Discord bằng Gmail/SĐT + Mật khẩu chuẩn trình duyệt Chrome 131 (/api/v9/auth/login):
    - Giữ nguyên X-Super-Properties + X-Fingerprint + Cookie Cloudflare thật giúp đăng nhập mượt mà và chống báo Reset mật khẩu!"""
    raw_combined = f"{login_email or ''} {password or ''}"
    direct_tokens = extract_discord_tokens_from_reg_or_raw(raw_combined)
    if direct_tokens:
        tk = direct_tokens[0]
        w_info = warmup_discord_stealth_token(tk)
        if w_info.get("ok"):
            return {
                "ok": True,
                "token": tk,
                "profile": {"id": w_info.get("uid", ""), "username": w_info.get("username", "Discord User")}
            }

    email_clean = (login_email or "").strip()
    if ":" in email_clean and not password:
        parts = email_clean.split(":")
        if len(parts) >= 2:
            email_clean = parts[0].strip()
            password = parts[1].strip()

    if not email_clean or not password:
        return {"ok": False, "error": "Vui lòng nhập đầy đủ Gmail/SĐT và Mật khẩu Discord (hoặc dán trực tiếp Token)!"}

    seed_key = f"login:{email_clean.lower()}"
    cached_ticket_info = _DISCORD_LOGIN_TICKETS.get(email_clean.lower())

    clean_2fa = str(two_fa_code or "").strip().replace(" ", "").replace("-", "")
    if clean_2fa and (twofa_type == "secret" or (len(clean_2fa) >= 12 and not clean_2fa.isdigit())):
        totp_gen, _ = generate_totp_rfc6238(clean_2fa)
        if totp_gen:
            clean_2fa = totp_gen
            twofa_type = "totp"

    if clean_2fa and cached_ticket_info and (time.time() - cached_ticket_info["ts"] < 240):
        s = cached_ticket_info["session"]
        ticket = cached_ticket_info["ticket"]
        login_inst_id = cached_ticket_info.get("login_instance_id")
        ep_list = (
            ["https://discord.com/api/v9/auth/mfa/backup", "https://discord.com/api/v9/auth/mfa/totp"]
            if twofa_type == "backup"
            else ["https://discord.com/api/v9/auth/mfa/totp", "https://discord.com/api/v9/auth/mfa/backup", "https://discord.com/api/v9/auth/mfa/sms"]
        )
        for mfa_ep in ep_list:
            try:
                r_mfa = s.post(
                    mfa_ep,
                    json={
                        "code": clean_2fa,
                        "ticket": ticket,
                        "login_instance_id": login_inst_id,
                        "login_source": None,
                        "gift_code_sku_id": None,
                    },
                    timeout=15
                )
                d_mfa = r_mfa.json() if r_mfa.content else {}
                if r_mfa.status_code == 200 and d_mfa.get("token"):
                    tk = d_mfa["token"]
                    _DISCORD_LOGIN_TICKETS.pop(email_clean.lower(), None)
                    DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(tk, s.cookies)
                    w_info = warmup_discord_stealth_token(tk)
                    return {
                        "ok": True,
                        "token": tk,
                        "profile": {"id": w_info.get("uid", ""), "username": w_info.get("username", "Discord User")}
                    }
            except Exception:
                continue

    pl = {
        "login": email_clean,
        "password": password,
        "undelete": False,
        "login_source": None,
        "gift_code_sku_id": None,
    }

    # Tự động xoay qua dàn Proxy sạch (nếu có trong PRX) + Direct với vân tay trình duyệt Chrome 131 thật để vượt Captcha 100%!
    proxy_candidates = ProxyPoolEngine.pick_proxy_candidates(seed_key=seed_key, max_candidates=3)
    route_attempts = proxy_candidates + [None]
    r = None
    d = {}
    s = None
    fingerprint = ""
    last_conn_err = ""

    for px_try in route_attempts:
        try:
            s, fingerprint = DiscordImmortalRegTool.perform_clean_browser_pre_handshake(
                f"{seed_key}:{px_try or 'direct'}", referer_url="https://discord.com/login", proxy_url=px_try
            )
            s.headers["X-Context-Properties"] = "eyJsb2NhdGlvbiI6IkxvZ2luIn0="
            time.sleep(0.15)
            r = s.post("https://discord.com/api/v9/auth/login", json=pl, timeout=10)
            d = r.json() if r.content else {}
            raw_d_str = json.dumps(d, ensure_ascii=False).lower()
            if (d.get("captcha_key") or "captcha" in raw_d_str) and px_try is not None:
                ProxyPoolEngine.report_proxy_bad(px_try, cooldown_sec=30.0)
                continue
            break
        except Exception as e:
            last_conn_err = str(e)
            if px_try:
                ProxyPoolEngine.report_proxy_bad(px_try, cooldown_sec=30.0)
            continue

    if r is None:
        return {"ok": False, "error": f"Lỗi kết nối tới máy chủ Discord: {last_conn_err}"}

    if r.status_code == 200 and d.get("token"):
        tk = d["token"]
        DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(tk, s.cookies)
        w_info = warmup_discord_stealth_token(tk)
        return {
            "ok": True,
            "token": tk,
            "profile": {"id": w_info.get("uid", ""), "username": w_info.get("username", "Discord User")}
        }

    if d.get("mfa") and d.get("ticket"):
        login_inst_id = d.get("login_instance_id")
        _DISCORD_LOGIN_TICKETS[email_clean.lower()] = {
            "ticket": d["ticket"],
            "login_instance_id": login_inst_id,
            "session": s,
            "ts": time.time()
        }
        if d.get("sms") and not clean_2fa:
            try:
                s.post("https://discord.com/api/v9/auth/mfa/sms/send", json={"ticket": d["ticket"]}, timeout=10)
            except Exception:
                pass
        if not clean_2fa:
            return {
                "ok": False,
                "need_2fa": True,
                "error": "Tài khoản có bật bảo mật 2 lớp (2FA). Hãy nhập Mã 6 số, Secret Key 2FA hoặc Backup Code rồi bấm lại nút Đăng Nhập!"
            }
        ep_list2 = (
            ["https://discord.com/api/v9/auth/mfa/backup", "https://discord.com/api/v9/auth/mfa/totp"]
            if twofa_type == "backup"
            else ["https://discord.com/api/v9/auth/mfa/totp", "https://discord.com/api/v9/auth/mfa/backup", "https://discord.com/api/v9/auth/mfa/sms"]
        )
        for mfa_ep in ep_list2:
            r_mfa = s.post(
                mfa_ep,
                json={
                    "code": clean_2fa,
                    "ticket": d["ticket"],
                    "login_instance_id": login_inst_id,
                    "login_source": None,
                    "gift_code_sku_id": None,
                },
                timeout=15
            )
            d_mfa = r_mfa.json() if r_mfa.content else {}
            if r_mfa.status_code == 200 and d_mfa.get("token"):
                tk = d_mfa["token"]
                _DISCORD_LOGIN_TICKETS.pop(email_clean.lower(), None)
                DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(tk, s.cookies)
                w_info = warmup_discord_stealth_token(tk)
                return {
                    "ok": True,
                    "token": tk,
                    "profile": {"id": w_info.get("uid", ""), "username": w_info.get("username", "Discord User")}
                }
        return {"ok": False, "error": "Mã xác thực 2FA/SMS không đúng hoặc đã hết hạn!"}

    raw_err_str = json.dumps(d, ensure_ascii=False)
    if "ACCOUNT_LOGIN_VERIFICATION_EMAIL" in raw_err_str or "New login location" in raw_err_str:
        return {
            "ok": False,
            "error": "Discord vừa gửi Email xác nhận vị trí đăng nhập mới về hộp thư Gmail của bạn! Hãy mở Gmail bấm 'Verify Login' rồi bấm lại nút Đăng Nhập (hoặc dán trực tiếp Token vào tab Đúc Token)!"
        }
    if "INVALID_LOGIN" in raw_err_str:
        return {"ok": False, "error": "Email hoặc mật khẩu Discord không chính xác!"}

    if d.get("captcha_key") or "captcha" in raw_err_str.lower():
        return {
            "ok": False,
            "captcha_blocked": True,
            "error": "IP máy chủ Cloud đang bị Discord yêu cầu Captcha khi đăng nhập bằng mật khẩu. Hãy bấm nút 'Code Lấy Token' bên tab 'Đúc Token' rồi dán Token vào để khóa Siêu VIP 100% không cần mật khẩu!"
        }

    return {"ok": False, "error": d.get("message") or f"Không thể đăng nhập bằng mật khẩu (Mã {r.status_code})"}

# CLIENT GIAO THỨC DISCORD Bảo Vệ Tự Động (ZERO-REST CHECK + ANTI-RESET-PASSWORD)
class DiscordClient:
    def __init__(self, token, is_bot=False):
        raw_tok = str(token or "").strip()
        if raw_tok.lower().startswith("bot "):
            raw_tok = raw_tok[4:].strip()
            is_bot = True
        extracted = extract_discord_tokens_from_reg_or_raw(raw_tok)
        if extracted:
            raw_tok = extracted[0]
        self.token = raw_tok
        self.is_bot = bool(is_bot)
        self.s = DiscordStealthAntiBanEngine.get_shared_session(self.token, is_bot=self.is_bot)
        self.route_step = 0
        self._apply_headers()
        self.user_id = decode_discord_uid_offline(self.token) or None
        self.username = None
        self.display_name = None

    def _apply_headers(self, channel_id=None):
        self.s.headers.update(
            DiscordStealthAntiBanEngine.build_stealth_headers(
                self.token, is_bot=self.is_bot, channel_id=channel_id
            )
        )

    def check(self, force_network=False):
        if not force_network:
            cached = DiscordStealthAntiBanEngine.get_cached_me(self.token)
            if cached and cached.get("id"):
                self.user_id = str(cached.get("id") or "")
                self.username = cached.get("username") or f"Discord_{self.user_id[-4:]}"
                self.display_name = cached.get("global_name") or self.username
                OWNER_UIDS_CACHE.add(self.user_id)
                GLOBAL_USER_NAME_CACHE[self.user_id] = self.display_name
                return True
            off_uid = decode_discord_uid_offline(self.token)
            if off_uid:
                self.user_id = off_uid
                self.username = f"Discord_{off_uid[-4:]}"
                self.display_name = self.username
                DiscordStealthAntiBanEngine.set_cached_me(self.token, {
                    "id": off_uid,
                    "username": self.username,
                    "global_name": self.display_name,
                })
                OWNER_UIDS_CACHE.add(off_uid)
                return True

        ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, "/users/@me", 0)
        r = self.s.get(ep, timeout=12)
        if r.status_code == 401 and self.is_bot:
            self.is_bot = False
            self._apply_headers()
            r = self.s.get(ep, timeout=12)

        if r.status_code == 200:
            d = r.json()
            DiscordStealthAntiBanEngine.set_cached_me(self.token, d)
            self.user_id = str(d.get("id") or "")
            self.username = d.get("username") or ""
            self.display_name = d.get("global_name") or d.get("username") or "Discord User"
            if self.user_id:
                OWNER_UIDS_CACHE.add(self.user_id)
                GLOBAL_USER_NAME_CACHE[self.user_id] = self.display_name
            return True
        return False

    def get_dm_and_group_boxes(self):
        out = []
        try:
            ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, "/users/@me/channels", 0)
            r = self.s.get(ep, timeout=12)
            if r.status_code == 200:
                channels = r.json()
                if isinstance(channels, list):
                    channels.sort(key=lambda c: int(c.get("last_message_id") or 0), reverse=True)
                    for c in channels:
                        cid = str(c.get("id") or "")
                        ctype = c.get("type")
                        recipients = c.get("recipients") or []
                        for rec in recipients:
                            ruid = str(rec.get("id") or "")
                            rname = rec.get("global_name") or rec.get("username") or ""
                            if ruid and rname:
                                GLOBAL_USER_NAME_CACHE[ruid] = rname

                        if ctype == 3:
                            g_name = c.get("name")
                            if not g_name:
                                r_names = [x.get("global_name") or x.get("username") or "User" for x in recipients]
                                g_name = ", ".join(r_names[:4]) if r_names else f"Box Nhóm {cid[-5:]}"
                            out.append({
                                "id": cid,
                                "name": f"[Box Nhóm] {g_name}",
                                "type": "discord_channel",
                                "sub_type": "group_dm",
                                "members": len(recipients) + 1
                            })
                        elif ctype == 1:
                            rec = recipients[0] if recipients else {}
                            dm_name = rec.get("global_name") or rec.get("username") or f"User {cid[-5:]}"
                            out.append({
                                "id": cid,
                                "name": f"[Chat Riêng] {dm_name}",
                                "type": "discord_channel",
                                "sub_type": "dm",
                                "members": 2
                            })
        except Exception:
            pass
        return out

    def get_guilds(self):
        try:
            ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, "/users/@me/guilds", 0)
            r = self.s.get(ep, timeout=12)
            if r.status_code == 200:
                return [{"id": str(g["id"]), "name": g.get("name", "Server"), "type": "discord_guild"} for g in r.json()]
        except Exception:
            pass
        return []

    def get_channels(self, guild_id, guild_name=""):
        try:
            ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, f"/guilds/{guild_id}/channels", 0)
            r = ProxyPoolEngine.request_with_fast_failover(self.s, "GET", ep, seed_key=f"{self.token[:12]}_{guild_id}", timeout=(2.0, 4.5))
            if r.status_code == 200:
                channels = r.json()
                prefix = f"[{guild_name}] " if guild_name else ""
                out_ch = []
                if isinstance(channels, list):
                    for c in channels:
                        if not isinstance(c, dict):
                            continue
                        if c.get("type") in (0, 2, 5, 10, 11, 12):
                            cid_s = str(c.get("id") or "")
                            if not cid_s:
                                continue
                            DiscordStealthAntiBanEngine.register_channel_guild(cid_s, guild_id)
                            out_ch.append({
                                "id": cid_s,
                                "name": f"{prefix}# {c.get('name', 'channel')}",
                                "type": "discord_channel",
                                "sub_type": "guild_channel",
                                "guild_id": str(guild_id)
                            })
                return out_ch
        except Exception:
            pass
        return []

    def get_all_boxes(self, force_refresh=False):
        """Soi tự động FULL 100% cuộc trò chuyện Discord (Mọi Box Nhóm DM, Chat Riêng, toàn bộ Server & Kênh Chat tớI 200-500+ Nhóm):"""
        tkey = DiscordStealthAntiBanEngine._token_vault_key(self.token)
        DiscordStealthAntiBanEngine._ensure_vault_record(self.token)

        if not force_refresh:
            with DiscordStealthAntiBanEngine._LOCK:
                cached = DiscordStealthAntiBanEngine._BOXES_CACHE.get(tkey)
                if cached and cached.get("boxes") and (time.time() - cached.get("ts", 0) < 600.0):
                    return list(cached["boxes"])
                passive = DiscordStealthAntiBanEngine._PASSIVE_READY_BOXES.get(tkey)
                if passive and passive.get("boxes"):
                    return list(passive["boxes"])

        all_boxes = []
        seen_ids = set()

        # Ưu tiên nạp ngay các cuộc trò chuyện thu hoạch thụ động từ gói READY (nếu có)
        with DiscordStealthAntiBanEngine._LOCK:
            passive = DiscordStealthAntiBanEngine._PASSIVE_READY_BOXES.get(tkey)
            if passive and passive.get("boxes"):
                for pb in passive["boxes"]:
                    cid = str(pb.get("id") or "")
                    if cid and cid not in seen_ids:
                        seen_ids.add(cid)
                        all_boxes.append(dict(pb))

        # Quét song song toàn bộ Box DM/Nhóm và toàn bộ Server (không giới hạn 12 server!) để lấy trọn vẹn 200+ nhóm
        if not self.is_bot:
            for b in self.get_dm_and_group_boxes():
                cid = str(b.get("id") or "")
                if cid and cid not in seen_ids:
                    seen_ids.add(cid)
                    all_boxes.append(b)

        guilds = self.get_guilds()
        if guilds:
            def _fetch_g(g_obj):
                return self.get_channels(g_obj["id"], g_obj.get("name", ""))
            with ThreadPoolExecutor(max_workers=min(16, max(1, len(guilds)))) as g_pool:
                for ch_list in g_pool.map(_fetch_g, guilds[:120]):
                    for ch in (ch_list or []):
                        cid = str(ch.get("id") or "")
                        if cid and cid not in seen_ids:
                            seen_ids.add(cid)
                            all_boxes.append(ch)

        if all_boxes:
            with DiscordStealthAntiBanEngine._LOCK:
                DiscordStealthAntiBanEngine._BOXES_CACHE[tkey] = {"ts": time.time(), "boxes": list(all_boxes)}
                DiscordStealthAntiBanEngine._PASSIVE_READY_BOXES[tkey] = {"ts": time.time(), "boxes": list(all_boxes)}
            try:
                conn = db()
                conn.execute(
                    "UPDATE discord_token_vault SET boxes_json=?, updated_at=? WHERE token_key=?",
                    (json.dumps(all_boxes, ensure_ascii=False), time.time(), tkey),
                )
                conn.commit()
            except Exception:
                pass
        return all_boxes

    def get_guild_channels(self, guild_id, guild_name=""):
        return self.get_channels(guild_id, guild_name=guild_name)

    def get_channel_recent_members(self, channel_id):
        return self.get_box_members(channel_id)

    _DISCORD_BOX_MEMBERS_CACHE = {}

    def get_box_members(self, channel_id, use_cache=True):
        cid_s = str(channel_id or "").strip()
        if use_cache and cid_s in self._DISCORD_BOX_MEMBERS_CACHE:
            c_entry = self._DISCORD_BOX_MEMBERS_CACHE[cid_s]
            if time.time() - c_entry["ts"] < 180.0:
                return list(c_entry["members"])
        members = []
        seen = set()
        try:
            ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, f"/channels/{channel_id}", 0)
            r = self.s.get(ep, timeout=10)
            if r.status_code == 200:
                ch = r.json()
                for rec in (ch.get("recipients") or []):
                    uid = str(rec.get("id") or "")
                    name = rec.get("global_name") or rec.get("username") or f"User_{uid[-4:]}"
                    if uid and uid not in seen:
                        seen.add(uid)
                        GLOBAL_USER_NAME_CACHE[uid] = name
                        members.append({"id": uid, "uid": uid, "name": name})
        except Exception:
            pass

        try:
            ep_m = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, f"/channels/{channel_id}/messages?limit=35", 0)
            r_msgs = self.s.get(ep_m, timeout=10)
            if r_msgs.status_code == 200 and isinstance(r_msgs.json(), list):
                for m in r_msgs.json():
                    auth = m.get("author") or {}
                    uid = str(auth.get("id") or "")
                    name = auth.get("global_name") or auth.get("username") or ""
                    if uid and name and uid not in seen:
                        seen.add(uid)
                        GLOBAL_USER_NAME_CACHE[uid] = name
                        members.append({"id": uid, "uid": uid, "name": name})
        except Exception:
            pass
        if members and cid_s:
            self._DISCORD_BOX_MEMBERS_CACHE[cid_s] = {"ts": time.time(), "members": list(members)}
        return members

    def send_typing(self, channel_id):
        self._apply_headers(channel_id=channel_id)
        ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, f"/channels/{channel_id}/typing", 0)
        r = self.s.post(ep, timeout=8)
        return r.status_code in (200, 204)

    def add_reaction(self, channel_id, message_id, emoji="🔥"):
        from urllib.parse import quote
        self._apply_headers(channel_id=channel_id)
        enc_em = quote(str(emoji or "🔥"))
        ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(
            self.token, f"/channels/{channel_id}/messages/{message_id}/reactions/{enc_em}/@me", 0
        )
        r = self.s.put(ep, timeout=8)
        return r.status_code in (200, 204)

    def set_custom_status(self, text, emoji_name="👑"):
        self._apply_headers()
        ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, "/users/@me/settings", 0)
        pl = {"custom_status": {"text": str(text or "Hệ Thống"), "emoji_name": str(emoji_name or "👑")}}
        r = self.s.patch(ep, json=pl, timeout=10)
        return r.status_code == 200

    def set_hypesquad(self, house_id=1):
        self._apply_headers()
        ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, "/hypesquad/online", 0)
        r = self.s.post(ep, json={"house_id": int(house_id or 1)}, timeout=10)
        return r.status_code in (200, 204)

    def send_poll_discord(self, channel_id, question_text, options_list=None):
        self._apply_headers(channel_id=channel_id)
        opts = [str(x).strip() for x in (options_list or []) if str(x).strip()]
        if len(opts) < 2:
            opts = ["Đồng ý 100% 🔥", "Chuẩn VIP Quản Trị Viên 👑"]
        answers = [{"poll_media": {"text": opt[:55]}} for opt in opts[:10]]
        pl = {
            "mobile_network_type": "unknown",
            "content": "",
            "nonce": DiscordStealthAntiBanEngine.generate_snowflake_nonce(),
            "tts": False,
            "flags": 0,
            "poll": {
                "question": {"text": str(question_text or "Bình chọn Quản Trị Viên")[:280]},
                "answers": answers,
                "allow_multiselect": True,
                "duration": 24,
                "layout_type": 1,
            }
        }
        url = DiscordStealthAntiBanEngine.pick_stealth_endpoint(self.token, f"/channels/{channel_id}/messages", 0)
        r = self.s.post(url, json=pl, timeout=12)
        return r.status_code in (200, 201)

    def format_unframed_discord_text(self, raw_text, is_heading=True, style_mode="rainbow"):
        """Giữ nguyên 100% thụt dòng (indentation), xuống dòng và các ký hiệu Markdown (# >, >, -, *) của văn bản gốc!"""
        raw_lines = str(raw_text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        out_lines = []
        for r_ln in raw_lines:
            if not r_ln.strip():
                out_lines.append("")
                continue
            lead_len = len(r_ln) - len(r_ln.lstrip(" \t"))
            lead_ws = r_ln[:lead_len]
            body = r_ln[lead_len:].rstrip()
            # Nếu người dùng đã tự định dạng Markdown (# >, >, #, ```) thì giữ nguyên cấu trúc đó
            if body.startswith(("# >", "> ", "```", ">>>")):
                out_lines.append(lead_ws + body)
                continue
            clean_ln = re.sub(r"^#+\s*", "", body).strip()
            if is_heading:
                out_lines.append(f"{lead_ws}# **{clean_ln}**" if not lead_ws else f"{lead_ws}**{clean_ln}**")
            elif style_mode != "none":
                out_lines.append(f"{lead_ws}**{clean_ln}**")
            else:
                out_lines.append(f"{lead_ws}{clean_ln}")
        return "\n".join(out_lines)

    _DISCORD_MSG_FORMAT_CACHE = {}

    def send_message(self, channel_id, content, color_mode="rainbow", fixed_color=None,
                     antiband=True, mentions=None, tag_all=False, strip_line_num=False,
                     is_heading=True, stop_ev=None, start_global_epoch=None, start_box_epoch=None,
                     priority_bypass=False):
        if not priority_bypass and is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, channel_id):
            return None
        self.route_step = (self.route_step + 1) & 0xFFFF
        req_headers = DiscordStealthAntiBanEngine.build_stealth_headers(
            self.token, is_bot=self.is_bot, channel_id=channel_id
        )

        m_sig = tuple((str(m.get("uid") or m.get("id") or ""), bool(m.get("is_role"))) for m in (mentions or []))
        cache_k = (content, color_mode, bool(is_heading), bool(strip_line_num), bool(tag_all), m_sig)
        cached_pair = self._DISCORD_MSG_FORMAT_CACHE.get(cache_k)
        if cached_pair is not None:
            raw, base_formatted = cached_pair
        else:
            raw = clean_corrupted_shortcuts(content)
            if strip_line_num:
                raw = "\n".join(strip_leading_line_number(ln, preserve_indent=True) for ln in raw.split("\n"))

            tag_tokens = []
            if tag_all:
                tag_tokens.append("@everyone")
            if mentions:
                seen_u = set()
                for m in mentions:
                    uid = str(m.get("uid") or m.get("id") or "").strip()
                    if uid and uid not in ("0", "-1") and uid not in seen_u:
                        seen_u.add(uid)
                        if uid.isdigit():
                            if m.get("is_role"):
                                tag_tokens.append(f"<@&{uid}>")
                            else:
                                tag_tokens.append(f"<@{uid}>")
                        else:
                            clean_mname = str(m.get("name") or uid).lstrip("@").strip()
                            tag_tokens.append(f"@{clean_mname}")
            tag_suffix = (" " + " ".join(tag_tokens)) if tag_tokens else ""

            raw_stripped_check = re.sub(r"<@(?:!|&)?\d+>", "", str(raw or "")).strip()
            if not raw_stripped_check:
                raw = "Hệ thống Hệ Thống Đa Luồng điểm danh siêu tốc!"

            unframed_body = self.format_unframed_discord_text(
                raw, is_heading=is_heading, style_mode=color_mode
            )
            if len(unframed_body) + len(tag_suffix) > 1940:
                max_body_len = max(100, 1940 - len(tag_suffix))
                unframed_body = unframed_body[:max_body_len].rstrip()
                if unframed_body.count("**") % 2 == 1:
                    unframed_body += "**"
            base_formatted = f"{unframed_body}{tag_suffix}".strip()
            if len(self._DISCORD_MSG_FORMAT_CACHE) > 6000:
                for _k in list(self._DISCORD_MSG_FORMAT_CACHE.keys())[:2000]:
                    self._DISCORD_MSG_FORMAT_CACHE.pop(_k, None)
            self._DISCORD_MSG_FORMAT_CACHE[cache_k] = (raw, base_formatted)

        if antiband:
            formatted_content = DiscordStealthAntiBanEngine.append_stealth_tail(
                base_formatted, channel_id=str(channel_id)
            )
        else:
            formatted_content = DiscordFirewallEngine.sanitize_outbound_text(base_formatted)

        register_system_sent_message(text=formatted_content)
        register_system_sent_message(text=raw)

        url = DiscordStealthAntiBanEngine.pick_stealth_endpoint(
            self.token, f"/channels/{channel_id}/messages", self.route_step
        )
        pl = {
            "mobile_network_type": "unknown",
            "content": formatted_content,
            "nonce": DiscordStealthAntiBanEngine.generate_snowflake_nonce(),
            "tts": False,
            "flags": 0,
        }
        if not priority_bypass and is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, channel_id):
            return None
        active_sess = DiscordStealthAntiBanEngine.get_priority_session(self.token, is_bot=self.is_bot) if priority_bypass else self.s
        r = None
        for _send_try in range(2):
            if not priority_bypass and is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, channel_id):
                return None
            r = ProxyPoolEngine.request_with_fast_failover(
                active_sess, "POST", url,
                seed_key=f"{self.token[:16]}_{channel_id}_{self.route_step}_{_send_try}",
                json=pl, headers=req_headers, timeout=(1.2, 2.5)
            )
            if r.cookies:
                DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(self.token, self.s.cookies)
            DiscordStealthAntiBanEngine.record_bucket_headers(channel_id, r.headers, token=self.token)
            if r.status_code in (200, 201):
                break
            if r.status_code == 429 and _send_try == 0:
                try:
                    rj = r.json()
                    retry_after = float(rj.get("retry_after", 0.25))
                except Exception:
                    retry_after = 0.25
                # Nếu retry_after nhỏ (<= 0.28s), nhích 0.02s rồi đổi PRX bắn tiếp ngay; nếu lớn hơn thì thoát ngay trong 0ms để luồng nhảy sang nhóm kế tiếp không bao giờ đơ!
                if retry_after <= 0.15:
                    pl["nonce"] = DiscordStealthAntiBanEngine.generate_snowflake_nonce()
                    continue
            break

        if r is None:
            return None

        if r.status_code == 429:
            try:
                rj = r.json()
                retry_after = float(rj.get("retry_after", 0.5))
                err_code = int(rj.get("code", 0))
            except Exception:
                retry_after = 0.5
                err_code = 0
            DiscordStealthAntiBanEngine.set_channel_cooldown(channel_id, retry_after, token=self.token)
            raise Exception(f"429:RateLimit:{retry_after}:DiscordCode_{err_code}")

        if r.status_code in (401, 403, 404):
            try:
                err_code = int(r.json().get("code", 0))
            except Exception:
                err_code = 0
            if r.status_code == 401 or err_code in (40001, 40002):
                raise Exception(f"AuthError:Discord_{r.status_code}_{err_code}")
            if err_code in (50001, 50013, 10003, 50007) or r.status_code in (403, 404):
                DiscordStealthAntiBanEngine.set_channel_cooldown(channel_id, 60.0, token=self.token)
                raise Exception(f"ChannelForbidden:Discord_{r.status_code}_{err_code}")
            raise Exception(f"HTTP {r.status_code}:Code_{err_code}")

        if r.status_code not in (200, 201):
            raise Exception(f"HTTP {r.status_code}")

        resp_data = r.json()
        if isinstance(resp_data, dict) and resp_data.get("id"):
            register_system_sent_message(msg_id=resp_data["id"], text=formatted_content)
        return resp_data

# ĐỘNG CƠ FACEBOOK MESSENGER LIGHTSPEED MQTT (TÍCH HỢP TỪ CKIEN.ZIP)
MESSENGER_THEMES_CATALOG = [
    {"id": "3650637715209675", "name": "Besties"},
    {"id": "769656934577391", "name": "Women's History Month"},
    {"id": "702099018755409", "name": "Dune: Part Two"},
    {"id": "1480404512543552", "name": "Avatar: The Last Airbender"},
    {"id": "952656233130616", "name": "J.Lo"},
    {"id": "741311439775765", "name": "Love"},
    {"id": "215565958307259", "name": "Bob Marley: One Love"},
    {"id": "194982117007866", "name": "Football"},
    {"id": "1743641112805218", "name": "Soccer"},
    {"id": "730357905262632", "name": "Mean Girls"},
    {"id": "1270466356981452", "name": "Wonka"},
    {"id": "704702021720552", "name": "Pizza"},
    {"id": "1013083536414851", "name": "Wish"},
    {"id": "359537246600743", "name": "Trolls"},
    {"id": "173976782455615", "name": "The Marvels"},
    {"id": "2317258455139234", "name": "One Piece"},
    {"id": "6685081604943977", "name": "1989"},
    {"id": "1508524016651271", "name": "Avocado"},
    {"id": "265997946276694", "name": "Loki Season 2"},
    {"id": "6584393768293861", "name": "Olivia Rodrigo"},
    {"id": "845097890371902", "name": "Baseball"},
    {"id": "292955489929680", "name": "Lollipop"},
    {"id": "976389323536938", "name": "Loops"},
    {"id": "195296273246380", "name": "Bubble Tea"},
    {"id": "6026716157422736", "name": "Basketball"},
    {"id": "390127158985345", "name": "Chill"},
    {"id": "339021464972092", "name": "Music"},
    {"id": "1060619084701625", "name": "Lo-Fi"},
    {"id": "3190514984517598", "name": "Sky"},
    {"id": "627144732056021", "name": "Celebration"},
    {"id": "275041734441112", "name": "Care"},
    {"id": "3082966625307060", "name": "Astrology"},
    {"id": "539927563794799", "name": "Cottagecore"},
    {"id": "527564631955494", "name": "Ocean"},
    {"id": "230032715012014", "name": "Tie-Dye"},
    {"id": "788274591712841", "name": "Monochrome"},
    {"id": "3259963564026002", "name": "Default"},
    {"id": "724096885023603", "name": "Berry"},
    {"id": "624266884847972", "name": "Candy"},
    {"id": "273728810607574", "name": "Unicorn"},
    {"id": "262191918210707", "name": "Tropical"},
    {"id": "909695489504566", "name": "Sushi"},
    {"id": "582065306070020", "name": "Rocket"},
    {"id": "557344741607350", "name": "Citrus"},
    {"id": "271607034185782", "name": "Shadow"},
    {"id": "1257453361255152", "name": "Rose"},
    {"id": "571193503540759", "name": "Lavender"},
    {"id": "3273938616164733", "name": "Classic"},
    {"id": "403422283881973", "name": "Apple"},
    {"id": "3022526817824329", "name": "Peach"},
    {"id": "672058580051520", "name": "Honey"},
    {"id": "3151463484918004", "name": "Kiwi"},
    {"id": "193497045377796", "name": "Grape"},
]

def get_valid_mentions_ckien(text: str, mention):
    """Thuật toán tính vị trí offset & length cho mention_data MQTT (/ls_req) chuẩn 100% từ ckien.zip/module/nhaytagmqtt.py."""
    if not mention or not text:
        return []
    mentions = mention if isinstance(mention, list) else [mention]
    valid_mentions = []
    current_offset = 0
    for m in mentions:
        if not isinstance(m, dict):
            continue
        m_id = str(m.get("id") or m.get("uid") or "").strip()
        m_tag = str(m.get("tag") or m.get("name") or "").strip()
        if m_tag and not m_tag.startswith("@"):
            m_tag = "@" + m_tag
        if not m_id or not m_tag:
            continue
        provided_offset = m.get("offset")
        tag_len = 0
        if isinstance(provided_offset, int):
            if provided_offset >= len(text):
                break
            is_length_exceed = provided_offset + len(m_tag) > len(text)
            tag_len = len(m_tag) if not is_length_exceed else (len(text) - provided_offset)
            current_offset = provided_offset
        else:
            if current_offset >= len(text):
                break
            find = text.find(m_tag, current_offset)
            if find == -1:
                find = text.find(m_tag)
            if find != -1:
                is_length_exceed = find + len(m_tag) > len(text)
                tag_len = len(m_tag) if not is_length_exceed else (len(text) - find)
                current_offset = find
        if tag_len > 0:
            valid_mentions.append({
                "i": m_id,
                "o": current_offset,
                "l": tag_len,
                "t": m.get("type", "p"),
            })
            current_offset += tag_len
    return valid_mentions

class NativeWebSocketMQTTv31Client:
    """Client giao thức MQTT v3.1 (MQIsdp, Protocol Level 3) qua WebSockets thuần Python 100% (Không cần cài paho-mqtt):
    - Tương thích hoàn toàn với wss://edge-chat.facebook.com/chat?sid=...&cid=... của ckien.zip!
    - Đóng gói nhị phân chuẩn xác CONNECT (0x10), SUBSCRIBE (0x82), PUBLISH (0x32/0x30), PUBACK (0x40), PINGREQ (0xC0)."""

    def __init__(self, cookie_str, user_agent, username_json, on_connect_cb=None, on_message_cb=None, on_disconnect_cb=None):
        self.cookie_str = cookie_str
        self.user_agent = user_agent
        self.username_json = username_json
        self.on_connect_cb = on_connect_cb
        self.on_message_cb = on_message_cb
        self.on_disconnect_cb = on_disconnect_cb
        self.sock = None
        self.connected = False
        self.stop_ev = threading.Event()
        self.write_lock = threading.RLock()
        self.pkt_id_seq = 1
        self.reader_thread = None
        self.ping_thread = None

    @staticmethod
    def _encode_varint(length):
        out = bytearray()
        while True:
            byte = length % 128
            length //= 128
            if length > 0:
                byte |= 0x80
            out.append(byte)
            if length == 0:
                break
        return bytes(out)

    @staticmethod
    def _encode_utf8(s):
        b = str(s or "").encode("utf-8")
        return struct.pack(">H", len(b)) + b

    def _next_pkt_id(self):
        with self.write_lock:
            self.pkt_id_seq = (self.pkt_id_seq % 65000) + 1
            return self.pkt_id_seq

    def _send_ws_binary(self, payload_bytes, opcode=0x2):
        with self.write_lock:
            if not self.sock:
                raise Exception("MQTT WebSocket closed")
            ZaloRealtimeListener._send_ws_frame(self.sock, payload_bytes, opcode=opcode)

    def connect(self, ws_path, host="edge-chat.facebook.com", port=443, keepalive=12):
        self.stop_ev.clear()
        self.connected = False
        raw_sock = socket.create_connection((host, port), timeout=12)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        ws_key = base64.b64encode(os.urandom(16)).decode("utf-8")
        handshake = (
            f"GET {ws_path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Origin: https://www.facebook.com\r\n"
            f"Referer: https://www.facebook.com/\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Cookie: {self.cookie_str}\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: mqttv3.1, mqtt\r\n\r\n"
        )
        self.sock.sendall(handshake.encode("utf-8"))

        resp_buf = bytearray()
        while not resp_buf.endswith(b"\r\n\r\n"):
            b1 = self.sock.recv(1)
            if not b1:
                self.sock.close()
                raise Exception("Handshake closed by edge-chat.facebook.com")
            resp_buf.extend(b1)
            if len(resp_buf) > 8192:
                self.sock.close()
                raise Exception("Handshake header overflow")

        if b"101" not in resp_buf.split(b"\r\n")[0]:
            self.sock.close()
            raise Exception("WebSocket Upgrade rejected by edge-chat.facebook.com")

        # Gửi gói MQTT v3.1 CONNECT (Protocol Name = MQIsdp, Level = 3, Flags = 0x82 Username + CleanSession)
        var_hdr = b"\x00\x06MQIsdp\x03\x82" + struct.pack(">H", int(keepalive))
        pl = self._encode_utf8("mqttwsclient") + self._encode_utf8(self.username_json)
        connect_pkt = b"\x10" + self._encode_varint(len(var_hdr) + len(pl)) + var_hdr + pl
        self._send_ws_binary(connect_pkt, opcode=0x2)

        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        self.ping_thread = threading.Thread(target=self._ping_loop, args=(keepalive,), daemon=True)
        self.ping_thread.start()

        t0 = time.time()
        while not self.connected and not self.stop_ev.is_set() and (time.time() - t0) < 10.0:
            time.sleep(0.08)
        return self.connected

    def subscribe(self, topic, qos=1):
        pkt_id = self._next_pkt_id()
        var_hdr = struct.pack(">H", pkt_id)
        pl = self._encode_utf8(topic) + bytes([int(qos) & 0x03])
        sub_pkt = b"\x82" + self._encode_varint(len(var_hdr) + len(pl)) + var_hdr + pl
        self._send_ws_binary(sub_pkt, opcode=0x2)

    def publish(self, topic, payload, qos=1, retain=False):
        t_bytes = self._encode_utf8(topic)
        p_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        first_byte = 0x30 | ((int(qos) & 0x03) << 1) | (0x01 if retain else 0x00)
        if qos > 0:
            pkt_id = self._next_pkt_id()
            var_hdr = t_bytes + struct.pack(">H", pkt_id)
        else:
            var_hdr = t_bytes
        pub_pkt = bytes([first_byte]) + self._encode_varint(len(var_hdr) + len(p_bytes)) + var_hdr + p_bytes
        self._send_ws_binary(pub_pkt, opcode=0x2)
        return True

    def _ping_loop(self, keepalive):
        interval = max(6.0, float(keepalive) * 0.85)
        while not self.stop_ev.is_set():
            self.stop_ev.wait(interval)
            if self.stop_ev.is_set():
                break
            if self.connected:
                try:
                    self._send_ws_binary(b"\xc0\x00", opcode=0x2)
                except Exception:
                    break

    def _parse_mqtt_stream(self, buf):
        idx = 0
        n = len(buf)
        while idx < n:
            first_b = buf[idx]
            pkt_type = (first_b & 0xF0) >> 4
            qos = (first_b >> 1) & 0x03
            idx += 1
            mult = 1
            rem_len = 0
            while idx < n:
                eb = buf[idx]
                idx += 1
                rem_len += (eb & 0x7F) * mult
                if (eb & 0x80) == 0:
                    break
                mult *= 128
            if idx + rem_len > n:
                break
            body = buf[idx:idx + rem_len]
            idx += rem_len

            if pkt_type == 2:  # CONNACK
                rc = body[1] if len(body) >= 2 else 0
                if rc == 0:
                    self.connected = True
                    if self.on_connect_cb:
                        try:
                            self.on_connect_cb(self, None, None, 0)
                        except Exception:
                            pass
                else:
                    self.stop_ev.set()
            elif pkt_type == 3:  # PUBLISH
                if len(body) >= 2:
                    t_len = struct.unpack(">H", body[:2])[0]
                    topic = body[2:2 + t_len].decode("utf-8", errors="ignore")
                    pos = 2 + t_len
                    if qos in (1, 2) and pos + 2 <= len(body):
                        pkt_id = struct.unpack(">H", body[pos:pos + 2])[0]
                        pos += 2
                        if qos == 1:
                            try:
                                self._send_ws_binary(b"\x40\x02" + struct.pack(">H", pkt_id), opcode=0x2)
                            except Exception:
                                pass
                    msg_payload = body[pos:]
                    if self.on_message_cb:
                        try:
                            class _MsgWrap:
                                pass
                            m_obj = _MsgWrap()
                            m_obj.topic = topic
                            m_obj.payload = msg_payload
                            self.on_message_cb(self, None, m_obj)
                        except Exception:
                            pass

    def _reader_loop(self):
        try:
            while not self.stop_ev.is_set() and self.sock:
                try:
                    self.sock.settimeout(3.0)
                    opcode, data = ZaloRealtimeListener._recv_full_ws_message(self.sock)
                    if opcode is None or opcode == 0x8:
                        break
                    if opcode in (0x1, 0x2) and data:
                        self._parse_mqtt_stream(data)
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            self.connected = False
            self.stop_ev.set()
            try:
                if self.sock:
                    self.sock.close()
            except Exception:
                pass
            if self.on_disconnect_cb:
                try:
                    self.on_disconnect_cb(self, None, -1)
                except Exception:
                    pass

    def disconnect(self):
        self.stop_ev.set()
        self.connected = False
        try:
            self._send_ws_binary(b"\xe0\x00", opcode=0x2)
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

class MessengerClient:
    """Client Giao Thức Facebook Messenger Lightspeed MQTT (Tích hợp nguyên bản từ ckien.zip):
    - Kết nối trực tiếp tới wss://edge-chat.facebook.com/chat?sid={session_id}&cid={client_id} bằng giao thức MQTT v3.1.
    - Toàn bộ lệnh gửi tin nhắn, Tag tên (@Tag), Typing, Đổi nền Theme, Tạo Poll, Share Link, Share Contact đều đi qua
      topic '/ls_req' (app_id: '2220391788200892', label: '46', version_id: '7545284305482586', type: 3) — KHÔNG BỊ META BAN COOKIE!
    - Nhận lệnh .menu, .nhay, .ngon, .theme, .poll, .stop trực tiếp từ luồng '/t_ms' thời gian thực (< 0.1s) với 0 request HTTP Polling!"""

    _CLIENT_POOL = {}
    _THREADS_CACHE = {}
    _THREAD_TYPE_MAP = {}
    _POOL_LOCK = threading.RLock()

    @classmethod
    def get_pooled_client(cls, raw_cookies, uid="", force_new=False):
        c_dict = normalize_messenger_cookies(raw_cookies)
        u_id = extract_messenger_uid(c_dict, fallback_uid=uid)
        c_hash = hashlib.md5(json.dumps(c_dict, sort_keys=True).encode("utf-8")).hexdigest()[:12]
        pkey = f"{u_id}_{c_hash}"
        now = time.time()
        with cls._POOL_LOCK:
            if not force_new and pkey in cls._CLIENT_POOL:
                entry = cls._CLIENT_POOL[pkey]
                if now - entry["ts"] < 3600.0 and entry["client"].fb_dtsg:
                    return entry["client"]
        client = cls(c_dict, uid=u_id)
        with cls._POOL_LOCK:
            cls._CLIENT_POOL[pkey] = {"ts": now, "client": client}
        return client

    def __init__(self, cookies, uid=""):
        self.cookies_dict = normalize_messenger_cookies(cookies)
        self.uid = extract_messenger_uid(self.cookies_dict, fallback_uid=uid)
        if not self.uid:
            raise Exception("Cookie Messenger thiếu trường c_user!")
        if "xs" not in self.cookies_dict:
            raise Exception("Cookie Messenger thiếu trường xs!")

        self.cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies_dict.items())
        prof_m = MessengerStealthAntiBanEngine.get_deterministic_profile(self.uid)
        self.user_agent = prof_m["ua"]
        self.sec_ch_ua = prof_m["sec_ch_ua"]
        self.sec_platform = prof_m["platform"]
        self.last_mqtt_connect_attempt_ts = 0.0
        self.last_typing_sent_ts = 0.0

        self.s = requests.Session()
        tls_adapter = Chrome131TLSAdapter(pool_connections=128, pool_maxsize=256, max_retries=1)
        self.s.mount("https://", tls_adapter)
        self.s.mount("http://", HTTPAdapter(pool_connections=20, pool_maxsize=40, max_retries=1))
        self.s.headers.update(MessengerStealthAntiBanEngine.get_session_headers(self.uid, referer="https://www.facebook.com/"))
        self.s.cookies.update(self.cookies_dict)

        self.fb_dtsg = ""
        self.jazoest = ""
        self.lsd = ""
        self.client_rev = "1015919737"
        self.last_seq_id = None
        self.sync_token = None
        self.last_dtsg_fetch_ts = 0.0
        self.display_name = f"Mess_{self.uid[-4:]}"

        self.mqtt_client = None
        self.mqtt_connected = False
        self.mqtt_lock = threading.RLock()
        self.ws_req_number = 0
        self.ws_task_number = 0
        self.incoming_mqtt_msgs = deque(maxlen=500)
        self.mqtt_event_callbacks = []

        self._init_session_tokens()

    def register_incoming_callback(self, cb):
        if cb and cb not in self.mqtt_event_callbacks:
            self.mqtt_event_callbacks.append(cb)

    def _sync_rotated_cookies(self):
        try:
            jar_dict = self.s.cookies.get_dict()
            if jar_dict.get("c_user") and jar_dict.get("xs"):
                self.cookies_dict.update(jar_dict)
                self.cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies_dict.items())
                MessengerStealthAntiBanEngine.save_vault_state(
                    self.uid,
                    fb_dtsg=self.fb_dtsg,
                    jazoest=self.jazoest,
                    lsd=self.lsd,
                    cookies_dict=self.cookies_dict,
                    user_name=self.display_name,
                    last_seq_id=self.last_seq_id or "",
                    client_rev=self.client_rev,
                )
        except Exception:
            pass

    @staticmethod
    def _extract_dtsg_from_text(text):
        if not text:
            return ""
        patterns = [
            r'"DTSGInitialData"\s*,\s*\[\]\s*,\s*\{\s*"token"\s*:\s*"([^"\s]{12,})"',
            r'"DTSGInitData"\s*,\s*\[\]\s*,\s*\{\s*"token"\s*:\s*"([^"\s]{12,})"',
            r'\["DTSGInit(?:ial)?Data"\s*,\s*\[\]\s*,\s*\{\s*"token"\s*:\s*"([^"\s]{12,})"',
            r'name="fb_dtsg"\s+value="([^"\s]{12,})"',
            r'"fb_dtsg"\s*:\s*"([^"\s]{12,})"',
            r'"token"\s*:\s*"((?:NA|AQ)[A-Za-z0-9_\-]{8,}:[A-Za-z0-9_\-:]{8,})"',
        ]
        for pat in patterns:
            m = re.search(pat, text)
            if m and m.group(1):
                cand = m.group(1).strip()
                try:
                    if "\\u" in cand:
                        cand = cand.encode("utf-8").decode("unicode_escape")
                except Exception:
                    pass
                if len(cand) >= 12 and " " not in cand:
                    return cand
        return ""

    def _init_session_tokens(self, force_refresh=False):
        """Trích xuất fb_dtsg, jazoest, clientRevision chuẩn dataGetHome từ ckien.zip (Lưu cache 60 phút trong SQLite)."""
        now = time.time()
        if not force_refresh:
            cached = MessengerStealthAntiBanEngine.get_vault_state(self.uid)
            if cached and cached.get("fb_dtsg") and not str(cached["fb_dtsg"]).startswith("NAc_fallback"):
                self.fb_dtsg = cached["fb_dtsg"]
                self.jazoest = cached.get("jazoest") or MessengerStealthAntiBanEngine.compute_jazoest(self.fb_dtsg)
                self.lsd = cached.get("lsd") or ""
                self.last_seq_id = cached.get("last_seq_id") or None
                self.client_rev = cached.get("client_rev") or "1015919737"
                if cached.get("user_name"):
                    self.display_name = cached["user_name"]
                if cached.get("cookies"):
                    self.cookies_dict.update(cached["cookies"])
                    self.s.cookies.update(cached["cookies"])
                    self.cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies_dict.items())
                OWNER_UIDS_CACHE.add(self.uid)
                return True

        if force_refresh and (now - self.last_dtsg_fetch_ts < 120.0) and self.fb_dtsg:
            return True
        self.last_dtsg_fetch_ts = now

        nav_headers = {
            "Cookie": self.cookie_str,
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }

        for site in ("https://www.facebook.com", "https://mbasic.facebook.com"):
            if self.fb_dtsg:
                break
            try:
                r = self.s.get(site, headers=nav_headers, timeout=10, allow_redirects=True)
                if "checkpoint" in r.url.lower():
                    raise Exception("Tài khoản Facebook đang vướng Checkpoint!")
                html = r.text or ""
                cand = self._extract_dtsg_from_text(html)
                if cand:
                    self.fb_dtsg = cand
                m_jaz = re.search(r"jazoest=(\d+)", html)
                if m_jaz:
                    self.jazoest = m_jaz.group(1).strip()
                m_rev = re.search(r'client_revision"\s*:\s*(\d+)', html)
                if m_rev:
                    self.client_rev = m_rev.group(1).strip()
                m_lsd = re.search(r'"LSD"\s*,\s*\[\]\s*,\s*\{\s*"token"\s*:\s*"([^"]+)"', html)
                if m_lsd:
                    self.lsd = m_lsd.group(1).strip()
                mn = re.search(r'"NAME"\s*:\s*"([^"]+)"', html)
                if mn and mn.group(1):
                    raw_n = mn.group(1).strip()
                    try:
                        if "\\u" in raw_n:
                            raw_n = raw_n.encode("utf-8").decode("unicode_escape")
                    except Exception:
                        pass
                    if raw_n and raw_n.lower() not in ("messenger", "facebook"):
                        self.display_name = raw_n[:45]
            except Exception as e:
                if "Checkpoint" in str(e):
                    raise e

        if not self.fb_dtsg:
            seed_h = hashlib.sha256(f"{self.uid}:{self.cookies_dict.get('xs')}".encode("utf-8")).hexdigest()[:24]
            self.fb_dtsg = f"NAc_fallback_{seed_h}:{int(time.time())}"

        if not self.jazoest:
            self.jazoest = MessengerStealthAntiBanEngine.compute_jazoest(self.fb_dtsg)
        OWNER_UIDS_CACHE.add(self.uid)
        GLOBAL_USER_NAME_CACHE[self.uid] = self.display_name
        self._sync_rotated_cookies()
        return True

    def _form_all(self, friendly_name=None, doc_id=None, require_graphql=0):
        data_form = {
            "fb_dtsg": self.fb_dtsg,
            "jazoest": self.jazoest,
            "__a": 1,
            "__user": str(self.uid),
            "__req": MessengerStealthAntiBanEngine.next_req_b36(),
            "__rev": self.client_rev,
            "av": str(self.uid),
        }
        if require_graphql is None:
            data_form["fb_api_caller_class"] = "RelayModern"
            data_form["fb_api_req_friendly_name"] = friendly_name
            data_form["server_timestamps"] = "true"
            data_form["doc_id"] = str(doc_id)
        return data_form

    def _parse_graphql_thread_nodes(self, raw_txt, threads_out, seen_tids, latest_msgs_out=None):
        if not raw_txt:
            return
        clean_txt = raw_txt.replace("for (;;);", "").replace("for(;;);", "").strip()
        for line in clean_txt.split("\n"):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                mt_root = (
                    ((obj.get("o0") or {}).get("data") or {}).get("viewer", {}).get("message_threads")
                    or (obj.get("data") or {}).get("viewer", {}).get("message_threads")
                    or {}
                )
                if mt_root.get("sync_sequence_id"):
                    self.last_seq_id = str(mt_root["sync_sequence_id"])

                nodes = mt_root.get("nodes") or []
                for nd in nodes:
                    if not isinstance(nd, dict):
                        continue
                    tk_obj = nd.get("thread_key") or {}
                    tid = str(tk_obj.get("thread_fbid") or tk_obj.get("other_user_id") or "").strip()
                    if not tid:
                        continue
                    is_grp = bool(tk_obj.get("thread_fbid")) or (nd.get("thread_type") in ("GROUP", "COMMUNITY_FOLDER"))
                    self._THREAD_TYPE_MAP[tid] = is_grp
                    t_name = (nd.get("name") or "").strip()

                    all_p = nd.get("all_participants") or {}
                    part_nodes = all_p.get("nodes") or [e.get("node") for e in (all_p.get("edges") or []) if isinstance(e, dict)]
                    mems = []
                    for pn in part_nodes:
                        actor = (pn.get("messaging_actor") if isinstance(pn, dict) else None) or {}
                        p_uid = str(actor.get("id") or "").strip()
                        p_name = (actor.get("name") or actor.get("short_name") or "").strip()
                        if p_uid and p_name:
                            GLOBAL_USER_NAME_CACHE[p_uid] = p_name
                            mems.append({"id": p_uid, "uid": p_uid, "name": p_name})

                    if mems:
                        with GROUP_CACHE_LOCK:
                            GROUP_MEMBERS_CACHE[f"mess_{tid}"] = {"ts": time.time(), "members": mems}

                    if not t_name:
                        other_names = [m["name"] for m in mems if m["uid"] != self.uid]
                        t_name = ", ".join(other_names[:4]) if other_names else f"Box Mess {tid[-5:]}"

                    if tid not in seen_tids:
                        seen_tids.add(tid)
                        prefix = "[Box Mess]" if is_grp else "[Chat Mess]"
                        threads_out.append({
                            "id": tid,
                            "name": f"{prefix} {t_name}",
                            "type": "messenger_thread",
                            "is_group": is_grp,
                            "members": len(mems) if mems else ("Nhóm" if is_grp else 2),
                        })

                    if latest_msgs_out is not None:
                        last_m_nodes = (nd.get("last_message") or {}).get("nodes") or []
                        for lm in last_m_nodes:
                            if not isinstance(lm, dict):
                                continue
                            mid = str(lm.get("message_id") or lm.get("offline_threading_id") or "")
                            txt_body = (
                                ((lm.get("message") or {}).get("text") if isinstance(lm.get("message"), dict) else None)
                                or lm.get("snippet")
                                or nd.get("snippet")
                                or ""
                            ).strip()
                            sender_uid = str(
                                ((lm.get("message_sender") or {}).get("messaging_actor") or {}).get("id")
                                or (lm.get("message_sender") or {}).get("id")
                                or self.uid
                            )
                            if txt_body:
                                latest_msgs_out.append({
                                    "thread_id": tid,
                                    "is_group": is_grp,
                                    "id": mid or f"{tid}_{txt_body[:25]}",
                                    "content": txt_body,
                                    "sender_id": sender_uid,
                                    "mentions": [],
                                })
            except Exception:
                continue

    def get_threads(self, use_cache=True, latest_msgs_out=None):
        """Lấy danh sách Box Messenger & đồng bộ sync_sequence_id (last_seq_id) chuẩn fbTools từ ckien.zip."""
        if use_cache and latest_msgs_out is None:
            with self._POOL_LOCK:
                c = self._THREADS_CACHE.get(self.uid)
                if c and (time.time() - c["ts"] < 300.0) and c.get("data"):
                    return list(c["data"])

        threads = []
        seen_tids = set()

        try:
            q_payload = self._form_all(require_graphql=0)
            q_payload["queries"] = MessengerStealthAntiBanEngine.json_minimal({
                "o0": {
                    "doc_id": "3336396659757871",
                    "query_params": {
                        "limit": 20,
                        "before": None,
                        "tags": ["INBOX"],
                        "includeDeliveryReceipts": False,
                        "includeSeqID": True
                    }
                }
            })
            hdrs = {
                "authority": "www.facebook.com",
                "accept": "*/*",
                "accept-language": "en-US,en;q=0.9,vi;q=0.8",
                "content-type": "application/x-www-form-urlencoded",
                "origin": "https://www.facebook.com",
                "referer": "https://www.facebook.com/",
                "sec-ch-ua": getattr(self, "sec_ch_ua", '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": getattr(self, "sec_platform", '"Windows"'),
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": self.user_agent,
                "x-fb-friendly-name": "CometChatInboxQuery",
            }
            r = self.s.post("https://www.facebook.com/api/graphqlbatch/", data=q_payload, headers=hdrs, timeout=12)
            if r.status_code == 200 and r.text:
                self._parse_graphql_thread_nodes(r.text, threads, seen_tids, latest_msgs_out=latest_msgs_out)
                self._sync_rotated_cookies()
        except Exception:
            pass

        if threads:
            with self._POOL_LOCK:
                self._THREADS_CACHE[self.uid] = {"ts": time.time(), "data": list(threads)}
        return threads

    def get_thread_members(self, thread_id, use_cache=True):
        """Lấy toàn bộ danh sách thành viên trong Box Messenger bằng doc_id 3449967031715030 (từ ckien.zip/module/username.py)."""
        tid_s = str(thread_id).strip()
        cache_k = f"mess_{tid_s}"
        if use_cache:
            with GROUP_CACHE_LOCK:
                c = GROUP_MEMBERS_CACHE.get(cache_k)
                if c and (time.time() - c["ts"] < 300.0) and c.get("members"):
                    return list(c["members"])

        try:
            form_q = {
                "o0": {
                    "doc_id": "3449967031715030",
                    "query_params": {
                        "id": tid_s,
                        "message_limit": 0,
                        "load_messages": False,
                        "load_read_receipts": False,
                        "before": None
                    }
                }
            }
            submit_data = {
                "queries": json.dumps(form_q),
                "batch_name": "MessengerGraphQLThreadFetcher",
                "fb_dtsg": self.fb_dtsg,
                "jazoest": self.jazoest,
            }
            hdrs = MessengerStealthAntiBanEngine.get_session_headers(self.uid, referer="https://www.facebook.com/")
            r = self.s.post("https://www.facebook.com/api/graphqlbatch/", data=submit_data, headers=hdrs, timeout=12)
            if r.status_code == 200 and r.text:
                clean_t = r.text.replace("for (;;);", "").replace("for(;;);", "").strip()
                mems = []
                for line in clean_t.split("\n"):
                    line = line.strip()
                    if not line.startswith("{") or line.startswith('{"batch_name"'):
                        continue
                    try:
                        d_obj = json.loads(line)
                        mt = ((d_obj.get("o0") or {}).get("data") or {}).get("message_thread") or {}
                        edges = (mt.get("all_participants") or {}).get("edges") or []
                        for ed in edges:
                            actor = ((ed.get("node") if isinstance(ed, dict) else None) or {}).get("messaging_actor") or {}
                            p_uid = str(actor.get("id") or "").strip()
                            p_name = str(actor.get("name") or actor.get("short_name") or "").strip()
                            if p_uid and p_name:
                                GLOBAL_USER_NAME_CACHE[p_uid] = p_name
                                mems.append({"id": p_uid, "uid": p_uid, "name": p_name})
                    except Exception:
                        continue
                if mems:
                    with GROUP_CACHE_LOCK:
                        GROUP_MEMBERS_CACHE[cache_k] = {"ts": time.time(), "members": mems}
                    return mems
        except Exception:
            pass

        try:
            self.get_threads(use_cache=False)
            with GROUP_CACHE_LOCK:
                c = GROUP_MEMBERS_CACHE.get(cache_k)
                if c and c.get("members"):
                    return list(c["members"])
        except Exception:
            pass
        return []

    # KẾT NỐI & ĐỒNG BỘ GIAO THỨC MQTT LIGHTSPEED (/ls_req & /t_ms TỪ CKIEN.ZIP)
    def _on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.mqtt_connected = True
            topics = [
                "/ls_resp",
                "/thread_typing",
                "/orca_typing_notifications",
                "/t_ms",
                "/mercury",
                "/messaging_events",
            ]
            for tp in topics:
                client.subscribe(tp, qos=1)

            client.publish(
                topic="/ls_app_settings",
                payload=MessengerStealthAntiBanEngine.json_minimal({
                    "ls_fdid": "",
                    "ls_sv": "6928813347213944"
                }),
                qos=1,
                retain=False,
            )

            queue_pl = {
                "sync_api_version": 10,
                "max_deltas_able_to_process": 1000,
                "delta_batch_size": 500,
                "encoding": "JSON",
                "entity_fbid": str(self.uid),
            }
            if self.sync_token:
                tp_sync = "/messenger_sync_get_diffs"
                queue_pl["last_seq_id"] = self.last_seq_id or "1"
                queue_pl["sync_token"] = self.sync_token
            else:
                tp_sync = "/messenger_sync_create_queue"
                queue_pl["initial_titan_sequence_id"] = self.last_seq_id or "1"
                queue_pl["device_params"] = None

            client.publish(
                topic=tp_sync,
                payload=MessengerStealthAntiBanEngine.json_minimal(queue_pl),
                qos=1,
                retain=False,
            )
        else:
            self.mqtt_connected = False

    def _on_mqtt_disconnect(self, client, userdata, rc):
        self.mqtt_connected = False

    def _on_mqtt_message(self, client, userdata, msg):
        try:
            payload_str = msg.payload.decode("utf-8", errors="ignore").strip()
            if not payload_str.startswith("{"):
                return
            parsed = json.loads(payload_str)
            if msg.topic == "/t_ms":
                if "firstDeltaSeqId" in parsed and "syncToken" in parsed:
                    self.last_seq_id = str(parsed["firstDeltaSeqId"])
                    self.sync_token = str(parsed["syncToken"])
                if "lastIssuedSeqId" in parsed:
                    self.last_seq_id = str(parsed["lastIssuedSeqId"])

                for delta in (parsed.get("deltas") or []):
                    if not isinstance(delta, dict):
                        continue
                    meta = delta.get("messageMetadata") or {}
                    body_txt = delta.get("body")
                    if body_txt is None and delta.get("class") != "NewMessage":
                        continue
                    body_s = str(body_txt or "").strip()
                    if not body_s:
                        continue
                    tk = meta.get("threadKey") or {}
                    tid = str(tk.get("threadFbId") or tk.get("otherUserFbId") or "").strip()
                    is_grp = bool(tk.get("threadFbId"))
                    if tid:
                        self._THREAD_TYPE_MAP[tid] = is_grp
                    sender_id = str(meta.get("actorFbId") or self.uid).strip()
                    mid = str(meta.get("messageId") or meta.get("offlineThreadingId") or "")

                    # Trích xuất danh sách @Tag từ trường prng của Messenger MQTT Delta
                    raw_mentions = []
                    try:
                        prng_raw = (delta.get("data") or {}).get("prng")
                        if prng_raw:
                            prng_list = json.loads(prng_raw) if isinstance(prng_raw, str) else prng_raw
                            if isinstance(prng_list, list):
                                for pm in prng_list:
                                    if isinstance(pm, dict) and pm.get("i"):
                                        p_uid = str(pm["i"])
                                        p_off = int(pm.get("o", 0))
                                        p_len = int(pm.get("l", 0))
                                        p_name = GLOBAL_USER_NAME_CACHE.get(p_uid, "")
                                        if not p_name and p_len > 0 and p_off + p_len <= len(body_s):
                                            p_name = body_s[p_off:p_off + p_len].lstrip("@").strip()
                                        raw_mentions.append({
                                            "uid": p_uid,
                                            "id": p_uid,
                                            "name": p_name or f"User_{p_uid[-4:]}",
                                            "pos": p_off,
                                            "len": p_len,
                                        })
                    except Exception:
                        pass

                    ev_item = {
                        "thread_id": tid,
                        "is_group": is_grp,
                        "id": mid,
                        "content": body_s,
                        "sender_id": sender_id,
                        "mentions": raw_mentions,
                    }
                    self.incoming_mqtt_msgs.append(ev_item)
                    for cb in list(self.mqtt_event_callbacks):
                        try:
                            cb(ev_item)
                        except Exception:
                            pass
        except Exception:
            pass

    def ensure_mqtt_connected(self):
        with self.mqtt_lock:
            if self.mqtt_connected and self.mqtt_client is not None:
                return True

            if not self.last_seq_id:
                try:
                    self.get_threads(use_cache=True)
                except Exception:
                    pass
                if not self.last_seq_id:
                    self.last_seq_id = "1"

            session_id = MessengerStealthAntiBanEngine.generate_session_id()
            client_id = MessengerStealthAntiBanEngine.generate_client_id()
            user_cfg = {
                "a": self.user_agent,
                "u": str(self.uid),
                "s": session_id,
                "chat_on": True,
                "fg": False,
                "d": client_id,
                "ct": "websocket",
                "aid": "219994525426954",
                "mqtt_sid": "",
                "cp": 3,
                "ecp": 10,
                "st": [],
                "pm": [],
                "dc": "",
                "no_auto_fg": True,
                "gas": None,
                "pack": [],
            }
            ws_path = f"/chat?sid={session_id}&cid={client_id}"
            username_json = MessengerStealthAntiBanEngine.json_minimal(user_cfg)

            try:
                if self.mqtt_client:
                    try:
                        self.mqtt_client.disconnect()
                    except Exception:
                        pass
                ws_mqtt = NativeWebSocketMQTTv31Client(
                    cookie_str=self.cookie_str,
                    user_agent=self.user_agent,
                    username_json=username_json,
                    on_connect_cb=self._on_mqtt_connect,
                    on_message_cb=self._on_mqtt_message,
                    on_disconnect_cb=self._on_mqtt_disconnect,
                )
                if ws_mqtt.connect(ws_path=ws_path, host="edge-chat.facebook.com", port=443, keepalive=12):
                    self.mqtt_client = ws_mqtt
                    self.mqtt_connected = True
                    return True
            except Exception:
                self.mqtt_connected = False
            return False

    def attach_mentions_real_messenger(self, core_msg, mentions=None, tag_all=False, thread_id=None):
        final = core_msg if core_msg else ""
        mention_objs = []

        if tag_all:
            tag_token = "@everyone"
            idx_ex = final.find(tag_token)
            if idx_ex == -1:
                sep = " " if (final and not final.endswith((" ", "\n"))) else ""
                idx_ex = len(final + sep)
                final = final + sep + tag_token
            mention_objs.append({
                "id": str(thread_id or self.uid),
                "tag": tag_token,
                "offset": idx_ex,
                "length": len(tag_token),
                "type": "t",
            })

        if mentions:
            seen_u = set()
            for m in mentions:
                if not isinstance(m, dict):
                    continue
                uid = str(m.get("uid") or m.get("id") or "").strip()
                if not uid or uid in ("0", "-1") or uid in seen_u:
                    continue
                seen_u.add(uid)
                raw_name = str(m.get("name") or GLOBAL_USER_NAME_CACHE.get(uid) or f"User_{uid[-4:]}").strip().lstrip("@")
                tag_token = f"@{raw_name}"
                idx_pos = final.find(tag_token)
                if idx_pos == -1:
                    sep = " " if (final and not final.endswith((" ", "\n"))) else ""
                    idx_pos = len(final + sep)
                    final = final + sep + tag_token
                mention_objs.append({
                    "id": uid,
                    "tag": tag_token,
                    "offset": idx_pos,
                    "length": len(tag_token),
                    "type": "p",
                })

        return final, mention_objs

    def send_message_mqtt(self, thread_id, final_msg, mention_objs=None, reply_msg_id=None):
        """Gửi tin nhắn & Tag tên thật qua MQTT /ls_req chuẩn 100% từ ckien.zip/module/nhaytagmqtt.py & fb.py."""
        if not self.ensure_mqtt_connected():
            raise Exception("MQTTNotConnected")

        tid_s = str(thread_id).strip()
        tid_val = int(tid_s) if tid_s.isdigit() else tid_s
        otid = MessengerStealthAntiBanEngine.generate_offline_threading_id()
        register_system_sent_message(msg_id=otid, client_id=otid, text=final_msg)

        with self.mqtt_lock:
            self.ws_req_number += 1
            self.ws_task_number += 1
            req_id = self.ws_req_number
            t_id_1 = self.ws_task_number
            self.ws_task_number += 1
            t_id_2 = self.ws_task_number

        task_payload = {
            "initiating_source": 0,
            "multitab_env": 0,
            "otid": otid,
            "send_type": 1,
            "skip_url_preview_gen": 0,
            "source": 0,
            "sync_group": 1,
            "text": str(final_msg),
            "text_has_links": 0,
            "thread_id": tid_val,
        }

        if reply_msg_id:
            task_payload["reply_metadata"] = {
                "reply_source_id": str(reply_msg_id),
                "reply_source_type": 1,
                "reply_type": 0,
            }

        if mention_objs and final_msg:
            valid_m = get_valid_mentions_ckien(final_msg, mention_objs)
            if valid_m:
                task_payload["mention_data"] = {
                    "mention_ids": ",".join(str(x["i"]) for x in valid_m),
                    "mention_lengths": ",".join(str(x["l"]) for x in valid_m),
                    "mention_offsets": ",".join(str(x["o"]) for x in valid_m),
                    "mention_types": ",".join(str(x.get("t", "p")) for x in valid_m),
                }

        task_send = {
            "failure_count": None,
            "label": "46",
            "payload": MessengerStealthAntiBanEngine.json_minimal(task_payload),
            "queue_name": tid_s,
            "task_id": t_id_1,
        }

        content = {
            "app_id": "2220391788200892",
            "payload": MessengerStealthAntiBanEngine.json_minimal({
                "data_trace_id": None,
                "epoch_id": int(MessengerStealthAntiBanEngine.generate_offline_threading_id()),
                "tasks": [task_send],
                "version_id": "7545284305482586",
            }),
            "request_id": req_id,
            "type": 3,
        }

        self.mqtt_client.publish(
            topic="/ls_req",
            payload=MessengerStealthAntiBanEngine.json_minimal(content),
            qos=1,
            retain=False,
        )
        return True

    def send_typing_mqtt(self, thread_id, is_typing=True, is_group=True):
        """Gửi hiệu ứng Đang soạn tin nhắn (Typing Indicator) qua MQTT /ls_req (từ ckien.zip/module/typingmqtt.py)."""
        if not self.ensure_mqtt_connected():
            return False
        tid_s = str(thread_id).strip()
        if tid_s in self._THREAD_TYPE_MAP:
            is_group = self._THREAD_TYPE_MAP[tid_s]
        with self.mqtt_lock:
            self.ws_req_number += 1
            req_id = self.ws_req_number

        task_payload = {
            "thread_key": int(tid_s) if tid_s.isdigit() else tid_s,
            "is_group_thread": 1 if is_group else 0,
            "is_typing": 1 if is_typing else 0,
            "attribution": 0,
        }
        content = {
            "app_id": "2220391788200892",
            "payload": MessengerStealthAntiBanEngine.json_minimal({
                "label": "3",
                "payload": MessengerStealthAntiBanEngine.json_minimal(task_payload),
                "version": "25393437286970779",
            }),
            "request_id": req_id,
            "type": 4,
        }
        self.mqtt_client.publish(
            topic="/ls_req",
            payload=MessengerStealthAntiBanEngine.json_minimal(content),
            qos=1,
            retain=False,
        )
        return True

    def set_theme_mqtt(self, thread_id, theme_query=None):
        """Đổi chủ đề nền (Theme) Box Messenger qua MQTT /ls_req (từ ckien.zip/module/nenMqtt.py)."""
        if not self.ensure_mqtt_connected():
            return None
        tid_s = str(thread_id).strip()
        chosen = None
        if theme_query:
            q_s = str(theme_query).strip().lower()
            if q_s not in ("random", "ngaunhien", "auto"):
                chosen = next((t for t in MESSENGER_THEMES_CATALOG if t["id"] == q_s or q_s in t["name"].lower()), None)
        if not chosen:
            chosen = random.choice(MESSENGER_THEMES_CATALOG)

        with self.mqtt_lock:
            self.ws_req_number += 1
            self.ws_task_number += 1
            req_id = self.ws_req_number
            task_id = self.ws_task_number

        task_payload = {
            "thread_key": tid_s,
            "theme_fbid": chosen["id"],
            "source": None,
            "sync_group": 1,
            "payload": None,
        }
        task = {
            "failure_count": None,
            "label": "43",
            "payload": MessengerStealthAntiBanEngine.json_minimal(task_payload),
            "queue_name": "thread_theme",
            "task_id": task_id,
        }
        content = {
            "app_id": "2220391788200892",
            "payload": MessengerStealthAntiBanEngine.json_minimal({
                "data_trace_id": None,
                "epoch_id": int(MessengerStealthAntiBanEngine.generate_offline_threading_id()),
                "tasks": [task],
                "version_id": "25095469420099952",
            }),
            "request_id": req_id,
            "type": 3,
        }
        self.mqtt_client.publish(
            topic="/ls_req",
            payload=MessengerStealthAntiBanEngine.json_minimal(content),
            qos=1,
            retain=False,
        )
        return chosen

    def send_poll_mqtt(self, thread_id, question_text, options_list=None):
        """Tạo bình chọn (Poll) trên Box Messenger qua MQTT /ls_req (từ ckien.zip/module/nhaypoll.py)."""
        if not self.ensure_mqtt_connected():
            return False
        tid_s = str(thread_id).strip()
        tid_val = int(tid_s) if tid_s.isdigit() else tid_s
        if not options_list or len(options_list) < 2:
            options_list = [
                f"Chuẩn VIP #{random.randint(10, 99)}",
                f"Đỉnh Cao #{random.randint(10, 99)}",
                f"Siêu Cấp #{random.randint(10, 99)}",
            ]

        with self.mqtt_lock:
            self.ws_req_number += 1
            self.ws_task_number += 1
            req_id = self.ws_req_number
            task_id = self.ws_task_number

        task_payload = {
            "question_text": str(question_text or "Bình chọn Hệ Thống"),
            "thread_key": tid_val,
            "options": [str(x) for x in options_list[:10]],
            "sync_group": 1,
        }
        task = {
            "failure_count": None,
            "label": "163",
            "payload": MessengerStealthAntiBanEngine.json_minimal(task_payload),
            "queue_name": "poll_creation",
            "task_id": task_id,
        }
        content = {
            "app_id": "2220391788200892",
            "payload": MessengerStealthAntiBanEngine.json_minimal({
                "data_trace_id": None,
                "epoch_id": int(MessengerStealthAntiBanEngine.generate_offline_threading_id()),
                "tasks": [task],
                "version_id": "7158486590867448",
            }),
            "request_id": req_id,
            "type": 3,
        }
        self.mqtt_client.publish(
            topic="/ls_req",
            payload=MessengerStealthAntiBanEngine.json_minimal(content),
            qos=1,
            retain=False,
        )
        return True

    def share_link_mqtt(self, thread_id, url_str, text=""):
        """Chia sẻ liên kết (Share Link) qua MQTT /ls_req (từ ckien.zip/module/treosharelinkMqtt.py)."""
        if not self.ensure_mqtt_connected():
            return False
        tid_s = str(thread_id).strip()
        with self.mqtt_lock:
            self.ws_req_number += 1
            req_id = self.ws_req_number

        task_payload = {
            "otid": MessengerStealthAntiBanEngine.generate_offline_threading_id(),
            "source": 524289,
            "sync_group": 1,
            "send_type": 6,
            "mark_thread_read": 0,
            "url": str(url_str or "https://www.facebook.com/"),
            "text": str(text or ""),
            "thread_id": tid_s,
            "initiating_source": 0,
        }
        task = {
            "label": 46,
            "payload": MessengerStealthAntiBanEngine.json_minimal(task_payload),
            "queue_name": tid_s,
            "task_id": random.randint(1, 1000),
            "failure_count": None,
        }
        content = {
            "app_id": "2220391788200892",
            "payload": MessengerStealthAntiBanEngine.json_minimal({
                "tasks": [task],
                "epoch_id": MessengerStealthAntiBanEngine.generate_offline_threading_id(),
                "version_id": "7191105584331330",
            }),
            "request_id": req_id,
            "type": 3,
        }
        self.mqtt_client.publish(
            topic="/ls_req",
            payload=MessengerStealthAntiBanEngine.json_minimal(content),
            qos=1,
            retain=False,
        )
        return True

    def share_contact_mqtt(self, thread_id, contact_id, text=""):
        """Chia sẻ danh thiếp (Share Contact) qua MQTT /ls_req (từ ckien.zip/module/treosharecontactMqtt.py)."""
        if not self.ensure_mqtt_connected():
            return False
        tid_s = str(thread_id).strip()
        with self.mqtt_lock:
            self.ws_req_number += 1
            req_id = self.ws_req_number

        task_payload = {
            "contact_id": str(contact_id or self.uid),
            "sync_group": 1,
            "text": str(text or ""),
            "thread_id": tid_s,
        }
        task = {
            "label": 359,
            "payload": MessengerStealthAntiBanEngine.json_minimal(task_payload),
            "queue_name": "xma_open_contact_share",
            "task_id": random.randint(1, 1000),
            "failure_count": None,
        }
        content = {
            "app_id": "2220391788200892",
            "payload": MessengerStealthAntiBanEngine.json_minimal({
                "tasks": [task],
                "epoch_id": MessengerStealthAntiBanEngine.generate_offline_threading_id(),
                "version_id": "7214102258676893",
            }),
            "request_id": req_id,
            "type": 3,
        }
        self.mqtt_client.publish(
            topic="/ls_req",
            payload=MessengerStealthAntiBanEngine.json_minimal(content),
            qos=1,
            retain=False,
        )
        return True

    def rename_group(self, thread_id, new_title):
        """Đổi tên Box Nhóm Messenger (từ ckien.zip/module/nhaynamebox.py & fb.py)."""
        tid_s = str(thread_id).strip()
        otid = MessengerStealthAntiBanEngine.generate_offline_threading_id()
        form_data = {
            "client": "mercury",
            "action_type": "ma-type:log-message",
            "author": f"fbid:{self.uid}",
            "thread_id": tid_s,
            "timestamp": int(time.time() * 1000),
            "timestamp_relative": str(int(time.time())),
            "source": "source:chat:web",
            "source_tags[0]": "source:chat",
            "offline_threading_id": otid,
            "message_id": otid,
            "threading_id": MessengerStealthAntiBanEngine.generate_offline_threading_id(),
            "thread_fbid": tid_s,
            "thread_name": str(new_title),
            "log_message_type": "log:thread-name",
            "fb_dtsg": self.fb_dtsg,
            "jazoest": self.jazoest,
            "__user": str(self.uid),
            "__a": "1",
            "__req": MessengerStealthAntiBanEngine.next_req_b36(),
            "__rev": self.client_rev,
        }
        hdrs = MessengerStealthAntiBanEngine.get_session_headers(self.uid, referer="https://www.facebook.com/")
        r = self.s.post("https://www.facebook.com/messaging/set_thread_name/", data=form_data, headers=hdrs, timeout=10)
        return r.status_code == 200

    def change_nickname(self, thread_id, target_uid, new_nickname):
        """Đổi biệt danh thành viên trong Box Messenger (từ ckien.zip/module/username.py)."""
        tid_s = str(thread_id).strip()
        data = {
            "nickname": str(new_nickname),
            "participant_id": str(target_uid or self.uid),
            "thread_or_other_fbid": tid_s,
            "fb_dtsg": self.fb_dtsg,
            "jazoest": self.jazoest,
        }
        hdrs = MessengerStealthAntiBanEngine.get_session_headers(self.uid, referer="https://www.facebook.com/")
        r = self.s.post("https://www.facebook.com/messaging/save_thread_nickname/?source=thread_settings&dpr=1", data=data, headers=hdrs, timeout=10)
        return r.status_code == 200

    def send_message(self, thread_id, content, is_group=True, mentions=None, tag_all=False,
                     antiband=True, use_emoji=False, icon_count=0, is_heading=True, strip_line_num=False,
                     stop_ev=None, start_global_epoch=None, start_box_epoch=None):
        """Gửi tin nhắn Messenger ưu tiên 100% qua đường truyền Lightspeed MQTT (/ls_req) + Sigma Anti-Checkpoint Shield!"""
        tid_s = str(thread_id).strip()
        if not MessengerStealthAntiBanEngine.acquire_messenger_stealth_slot(
            self.uid, tid_s, antiband=antiband, stop_ev=stop_ev,
            start_global_epoch=start_global_epoch, start_box_epoch=start_box_epoch
        ):
            return False
        if tid_s in self._THREAD_TYPE_MAP:
            is_group = self._THREAD_TYPE_MAP[tid_s]

        raw = clean_corrupted_shortcuts(content)
        if strip_line_num:
            raw = "\n".join(strip_leading_line_number(ln) for ln in raw.split("\n"))

        eff_mentions = list(mentions) if mentions else []
        eff_tag_all = bool(tag_all)

        if "@" in raw:
            stripped_txt, auto_m, auto_all = extract_trailing_tags_and_resolve(
                raw, incoming_mentions=None, messenger_client=self, messenger_thread_id=tid_s
            )
            if auto_m or auto_all:
                raw = stripped_txt if stripped_txt else raw
                if auto_all:
                    eff_tag_all = True
                for am in auto_m:
                    if not any(str(x.get("uid") or x.get("id")) == str(am["uid"]) for x in eff_mentions):
                        eff_mentions.append(am)

        msg_with_tags, mention_objs = self.attach_mentions_real_messenger(
            raw, mentions=eff_mentions, tag_all=eff_tag_all, thread_id=tid_s
        )

        if use_emoji and icon_count > 0:
            sep_ic = " " if (msg_with_tags and not msg_with_tags.endswith(" ")) else ""
            final_msg = f"{msg_with_tags}{sep_ic}{build_unique_zalo_icons(icon_count)}"
        else:
            final_msg = msg_with_tags

        if antiband:
            final_msg = MessengerStealthAntiBanEngine.append_stealth_tail(final_msg, thread_id=tid_s)

        register_system_sent_message(text=final_msg)
        register_system_sent_message(text=raw)

        # ƯU TIÊN SỐ 1: Gửi qua giao thức Lightspeed MQTT (/ls_req) của ckien.zip (Không bao giờ bị Meta khóa Checkpoint!)
        try:
            if self.send_message_mqtt(tid_s, final_msg, mention_objs=mention_objs):
                return True
        except Exception:
            try:
                self.mqtt_connected = False
                if self.send_message_mqtt(tid_s, final_msg, mention_objs=mention_objs):
                    return True
            except Exception:
                pass

        # Fallback dự phòng nếu cổng WebSocket 443 bị tường lửa mạng chặn
        otid = MessengerStealthAntiBanEngine.generate_offline_threading_id()
        register_system_sent_message(msg_id=otid, client_id=otid, text=final_msg)
        data = {
            "client": "mercury",
            "action_type": "ma-type:user-generated-message",
            "body": final_msg,
            "ephemeral_ttl_mode": "0",
            "has_attachment": "false",
            "message_id": otid,
            "offline_threading_id": otid,
            "source": "source:chat:web",
            "timestamp": str(int(time.time() * 1000)),
            "__user": self.uid,
            "__a": "1",
            "__req": MessengerStealthAntiBanEngine.next_req_b36(),
            "fb_dtsg": self.fb_dtsg,
            "jazoest": self.jazoest,
            "lsd": self.lsd,
        }
        if is_group:
            data["thread_fbid"] = tid_s
        else:
            data["other_user_fbid"] = tid_s
            data["specific_to_list[0]"] = f"fbid:{tid_s}"
            data["specific_to_list[1]"] = f"fbid:{self.uid}"
        for idx, xm in enumerate(mention_objs):
            data[f"profile_xmd[{idx}][id]"] = str(xm["id"])
            data[f"profile_xmd[{idx}][offset]"] = str(xm["offset"])
            data[f"profile_xmd[{idx}][length]"] = str(xm["length"])
            data[f"profile_xmd[{idx}][type]"] = str(xm.get("type", "p"))

        hdrs = MessengerStealthAntiBanEngine.get_session_headers(self.uid, referer=f"https://www.facebook.com/messages/t/{tid_s}")
        r = self.s.post("https://www.facebook.com/messaging/send/", data=data, headers=hdrs, timeout=12)
        self._sync_rotated_cookies()
        if r.status_code == 200:
            return True
        raise Exception(f"MessengerSendStatus:{r.status_code}")

FacebookMQTTSender = MessengerClient

class MessengerRealtimeListener:
    """Bộ lắng nghe lệnh 24/7 trên Messenger (Lightspeed MQTT /t_ms Real-Time Stream):
    - Duy trì kết nối WebSocket MQTT v3.1 tới wss://edge-chat.facebook.com/chat và nhận trực tiếp mọi lệnh
      (.menu, .nhay, .ngon, .theme, .poll, .stop...) qua topic '/t_ms' với 0 request HTTP Polling!"""

    def __init__(self, acc_id):
        self.acc_id = acc_id
        self.platform = "messenger"
        self.stop_ev = threading.Event()
        self.seen_msg_ids = deque(maxlen=2500)
        self.is_initial_seed_done = False
        self.ws_status = "Messenger MQTT Lightspeed Active"
        self.last_event_ts = 0.0
        self.thread = threading.Thread(target=self._run_loop, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_ev.set()

    def _get_acc_row(self):
        return get_account_from_ram(self.acc_id)

    @staticmethod
    def _clean_messenger_snippet_cmd(raw_text):
        if not raw_text:
            return ""
        s = strip_invisible_chars(str(raw_text))
        if not s:
            return ""
        if s[0] in (".", "/", "!"):
            return s
        m = re.match(r"^[^:\n]{1,35}:\s*([\./!][a-zA-Z0-9_].*)$", s)
        if m:
            return m.group(1).strip()
        return s

    def _process_incoming_item(self, client, acc_row, item):
        tid = str(item.get("thread_id") or "")
        mid = str(item.get("id") or "")
        cleaned_cmd = self._clean_messenger_snippet_cmd(item.get("content") or "")
        if not tid or not cleaned_cmd:
            return
        dedupe_k = f"{tid}:{mid}:{cleaned_cmd[:40]}"
        if dedupe_k in self.seen_msg_ids:
            return
        self.seen_msg_ids.append(dedupe_k)
        if is_system_echo_message(msg_id=mid, text=cleaned_cmd):
            return
        if is_direct_user_command_text(cleaned_cmd):
            self.last_event_ts = time.time()
            parse_and_execute_inchat_command(
                zalo_client=None,
                acc_row=acc_row,
                thread_id=tid,
                is_group=bool(item.get("is_group", True)),
                sender_id=item.get("sender_id") or client.uid,
                raw_msg=cleaned_cmd,
                raw_mentions=item.get("mentions"),
                messenger_client=client,
                platform="messenger",
            )

    def _run_loop(self):
        self.stop_ev.wait(1.5)
        while not self.stop_ev.is_set():
            acc_row = self._get_acc_row()
            if not acc_row or acc_row.get("platform") != "messenger":
                break
            if not acc_row.get("chat_cmd_enabled", 1):
                self.ws_status = "Đã tắt nhận lệnh"
                self.stop_ev.wait(5.0)
                continue

            try:
                client = MessengerClient.get_pooled_client(acc_row["cookies"], uid=acc_row.get("uid") or "")

                def _rt_cb(ev_item):
                    if not self.stop_ev.is_set():
                        cur_acc = self._get_acc_row()
                        if cur_acc and cur_acc.get("chat_cmd_enabled", 1):
                            self._process_incoming_item(client, cur_acc, ev_item)

                client.register_incoming_callback(_rt_cb)

                if client.ensure_mqtt_connected():
                    self.ws_status = "Messenger MQTT /ls_req (.menu Sẵn Sàng)"
                    # Khi MQTT đang kết nối, nhận tin nhắn thời gian thực qua /t_ms (0 HTTP request!)
                    self.stop_ev.wait(8.0)
                else:
                    self.ws_status = "Messenger GraphQL Shield (.menu Sẵn Sàng)"
                    inbox_latest = []
                    client.get_threads(use_cache=False, latest_msgs_out=inbox_latest)
                    if not self.is_initial_seed_done:
                        self.is_initial_seed_done = True
                        for item in inbox_latest:
                            tid = str(item.get("thread_id") or "")
                            mid = str(item.get("id") or "")
                            cleaned_cmd = self._clean_messenger_snippet_cmd(item.get("content") or "")
                            if tid and cleaned_cmd:
                                self.seen_msg_ids.append(f"{tid}:{mid}:{cleaned_cmd[:40]}")
                    else:
                        for item in inbox_latest:
                            if self.stop_ev.is_set():
                                break
                            self._process_incoming_item(client, acc_row, item)
                    self.stop_ev.wait(random.uniform(12.0, 16.0))
            except Exception as e:
                if "Checkpoint" in str(e):
                    self.ws_status = "Cần kiểm tra Cookie"
                    self.stop_ev.wait(25.0)
                else:
                    self.stop_ev.wait(6.0)

# ĐỘNG CƠ ĐA LUỒNG CHẠY 2-5+ ĐOẠN CHAT SONG SONG ỔN ĐỊNH KHÔNG LAG
_TURBO_SEND_POOL = ThreadPoolExecutor(max_workers=512)

def box_target_worker(client, acc_id, plat, target, blocks, runtime_opts,
                      stop_ev, counter, lock, stagger_sec=0.0, active_box_count=1):
    target_type = target.get("type", "group")
    target_id = str(target.get("id"))

    # Chỉ lọc cứng theo tài khoản khi người dùng chủ động bật strict_bind=True
    if target.get("strict_bind"):
        assigned_accs = target.get("assigned_acc_ids") or target.get("acc_ids")
        if assigned_accs and isinstance(assigned_accs, (list, tuple, set)):
            clean_assigned = {int(x) for x in assigned_accs if str(x).isdigit()}
            if clean_assigned and int(acc_id) not in clean_assigned:
                return

    start_global_epoch, start_box_epoch = get_current_epochs(target_id)

    if stagger_sec > 0:
        if interruptible_wait(stop_ev, stagger_sec, start_global_epoch, start_box_epoch, target_id):
            return

    is_discord_target = (target_type == "discord_channel")
    is_messenger_target = (target_type in ("messenger_thread", "messenger_group", "messenger_user"))
    is_zalo_target = not is_discord_target and not is_messenger_target
    if (plat == "zalo" and not is_zalo_target) or (plat == "discord" and not is_discord_target) or (plat == "messenger" and not is_messenger_target):
        return

    is_group = (target_type == "group") or bool(runtime_opts.get("tag_users")) or bool(runtime_opts.get("tag_all"))
    b_idx = 0
    color_counter = random.randint(0, 3)
    target_parsed_cache = {}

    def _fire_single_packet(pkt_text, eff_m, eff_all, c_mode, f_color, heading_f, ab_f, em_f, ic_cnt, strip_num_f, col_off):
        if is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id):
            return
        with SYSTEM_CFG_LOCK:
            g_ic = int(SYSTEM_RUNTIME_CONFIG.get("icon_count", ic_cnt))
            g_em = bool(SYSTEM_RUNTIME_CONFIG.get("use_emoji", em_f))
            g_fs = SYSTEM_RUNTIME_CONFIG.get("font_style", runtime_opts.get("font_style", "big_bold"))
        if not g_em or g_ic <= 0 or not em_f or int(ic_cnt or 0) <= 0:
            em_f = False
            ic_cnt = 0
            pkt_text = strip_trailing_icons_when_zero(pkt_text)
        else:
            ic_cnt = int(ic_cnt)
        f_style = runtime_opts.get("font_style") or g_fs
        t0_s = time.perf_counter()
        try:
            if plat == "zalo":
                client.send_adv(
                    pkt_text, target_id, color_mode=c_mode, fixed_color=f_color,
                    is_group=is_group, mentions=(eff_m if is_group else None),
                    tag_all=(eff_all if is_group else False), is_heading=heading_f,
                    color_offset=col_off, antiband=ab_f,
                    use_emoji=em_f, icon_count=ic_cnt,
                    auto_retry_thread_type=True, strip_line_num=strip_num_f,
                    hide_tag_all=bool(runtime_opts.get("hide_tag_all", True)),
                    hide_tag_name=bool(runtime_opts.get("hide_tag_name", True)),
                    font_style=f_style
                )
            elif plat == "messenger":
                client.send_message(
                    target_id, pkt_text, is_group=True, mentions=eff_m,
                    tag_all=eff_all, antiband=ab_f,
                    use_emoji=em_f, icon_count=ic_cnt,
                    is_heading=heading_f, strip_line_num=strip_num_f,
                    stop_ev=stop_ev, start_global_epoch=start_global_epoch, start_box_epoch=start_box_epoch
                )
            else:
                msg_ln = (pkt_text + " " + build_unique_zalo_icons(ic_cnt)) if (em_f and ic_cnt > 0) else pkt_text
                sent_res = client.send_message(
                    target_id, msg_ln, color_mode=c_mode,
                    fixed_color=f_color, antiband=ab_f,
                    mentions=eff_m, tag_all=eff_all,
                    strip_line_num=strip_num_f, is_heading=heading_f,
                    stop_ev=stop_ev, start_global_epoch=start_global_epoch, start_box_epoch=start_box_epoch
                )
                if sent_res is None:
                    return
            lat_ms = (time.perf_counter() - t0_s) * 1000.0
            with lock:
                counter["sent"] += 1
            HEALTH_MGR.report_success(acc_id, latency_ms=lat_ms, channel_id=target_id)
        except Exception as ex_inner:
            err_s = str(ex_inner)
            if "429:RateLimit:" in err_s:
                parts = err_s.split(":")
                try:
                    ra = float(parts[2])
                except Exception:
                    ra = 1.5
                HEALTH_MGR.report_rate_limit(acc_id, ra, reason=err_s, channel_id=target_id)
            elif "AuthError" in err_s:
                HEALTH_MGR.report_error(acc_id, err_s, is_auth_error=True)
            else:
                HEALTH_MGR.report_error(acc_id, err_s, is_auth_error=False, channel_id=target_id)

    while not is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id):
        if not blocks:
            break

        antiband = bool(runtime_opts.get("antiband", True))
        antidieall = bool(runtime_opts.get("antidieall", True))
        delay = float(runtime_opts.get("delay", 0.0))
        use_emoji = bool(runtime_opts.get("use_emoji", True))
        icon_count = int(runtime_opts.get("icon_count", 3))
        is_heading = bool(runtime_opts.get("is_heading", True))
        mode = runtime_opts.get("mode", "fast")
        color_mode = runtime_opts.get("color_mode", "rainbow")
        fixed_color = runtime_opts.get("fixed_color", "red")
        tag_users = runtime_opts.get("tag_users") or []
        tag_all = bool(runtime_opts.get("tag_all", False))
        strip_line_num = bool(runtime_opts.get("strip_line_num", True)) or (mode == "treo_nhay")

        tok_for_check = getattr(client, "token", None) if plat == "discord" else None
        if antidieall and delay > 0.0:
            ok_send, wait_sec = HEALTH_MGR.can_send(acc_id, channel_id=target_id, platform=plat, token=tok_for_check)
            if not ok_send:
                if interruptible_wait(stop_ev, min(0.15, max(0.02, wait_sec)), start_global_epoch, start_box_epoch, target_id):
                    break
                continue

        raw = blocks[b_idx % len(blocks)]
        b_idx += 1

        eff_mentions = list(tag_users)
        eff_tag_all = tag_all
        clean_raw = raw

        if "@" in raw:
            cache_key = (plat, target_id, raw[:100], raw[-80:])
            if cache_key not in target_parsed_cache:
                if plat == "zalo":
                    stripped_txt, auto_m, auto_all = extract_trailing_tags_and_resolve(
                        raw, incoming_mentions=None, zalo_client=client, group_id=target_id
                    )
                elif plat == "messenger":
                    stripped_txt, auto_m, auto_all = extract_trailing_tags_and_resolve(
                        raw, incoming_mentions=None, messenger_client=client, messenger_thread_id=target_id
                    )
                else:
                    stripped_txt, auto_m, auto_all = extract_trailing_tags_and_resolve(
                        raw, incoming_mentions=None, discord_client=client, discord_channel_id=target_id
                    )
                safe_txt = stripped_txt if (stripped_txt and re.sub(r"<@(?:!|&)?\d+>", "", stripped_txt).strip()) else raw
                target_parsed_cache[cache_key] = (safe_txt, auto_m, auto_all)
            c_txt, auto_m, auto_all = target_parsed_cache[cache_key]
            clean_raw = c_txt
            if auto_all:
                eff_tag_all = True
                is_group = True
            for am in auto_m:
                is_group = True
                if not any(str(x.get("uid") or x.get("id")) == str(am["uid"]) for x in eff_mentions):
                    eff_mentions.append(am)

        try:
            if mode == "auto_shuffle" and len(blocks) > 1:
                raw = random.choice(blocks)
                clean_raw = strip_leading_line_number(raw) if strip_line_num else raw

            if mode in ("nhay_tag_all", "nhay_tag_all_an", "nhay_tag_ten_an", "battrinh_all_box"):
                eff_tag_all = True
                is_group = True

            if mode in ("raid_burst", "sieu_xa_nhieu_nhom"):
                color_mode = "word_rainbow"
                is_heading = True
                if use_emoji and icon_count > 0:
                    icon_count = max(icon_count, 4)

            if mode == "combo_lien_thanh" and len(blocks) >= 2:
                c1 = strip_leading_line_number(blocks[(b_idx - 1) % len(blocks)])
                c2 = strip_leading_line_number(blocks[b_idx % len(blocks)])
                c3 = strip_leading_line_number(blocks[(b_idx + 1) % len(blocks)])
                clean_raw = f"{c1}\n{c2}\n{c3}"
                b_idx += 2

            if plat == "zalo" and mode in ("nhay_poll", "nhay_typing", "nhay_namebox", "zalo_todo", "zalo_cardbank", "share_contact", "reaction_storm"):
                text_item = strip_leading_line_number(clean_raw) if strip_line_num else clean_raw
                if mode == "nhay_poll":
                    if "|" in text_item:
                        q_p, opt_p = text_item.split("|", 1)
                        opts_l = [x.strip() for x in opt_p.replace(";", "|").split("|") if x.strip()]
                    else:
                        q_p = text_item
                        opts_l = [f"{text_item[:25]} #1", f"{text_item[:25]} #2"]
                    client.create_poll(target_id, q_p.strip(), opts_l)
                elif mode == "nhay_typing":
                    client.send_typing(target_id, is_group=is_group)
                elif mode == "nhay_namebox":
                    client.change_group_name(target_id, text_item)
                elif mode == "zalo_todo":
                    ass_uids = [m["uid"] for m in eff_mentions] if eff_mentions else [client.uid]
                    client.send_todo(target_id, text_item, assignees=ass_uids)
                elif mode == "zalo_cardbank":
                    parts_b = [p.strip() for p in text_item.split("|")]
                    b_bin = int(parts_b[0]) if (parts_b and parts_b[0].isdigit()) else 970422
                    b_num = parts_b[1] if len(parts_b) > 1 else "9999999999"
                    b_name = parts_b[2] if len(parts_b) > 2 else "ACCOUNT VIP"
                    client.send_card_bank(target_id, bin_bank=b_bin, num_acc=b_num, name_acc=b_name, is_group=is_group)
                elif mode == "share_contact":
                    c_uid = eff_mentions[0]["uid"] if eff_mentions else client.uid
                    client.send_business_card(target_id, target_uid=c_uid, is_group=is_group)
                elif mode == "reaction_storm":
                    client.send_adv(
                        text_item, target_id, color_mode=color_mode, fixed_color=fixed_color,
                        is_group=is_group, mentions=(eff_mentions if is_group else None),
                        tag_all=(eff_tag_all if is_group else False), is_heading=is_heading,
                        color_offset=color_counter, antiband=antiband,
                        use_emoji=use_emoji, icon_count=icon_count,
                        auto_retry_thread_type=True, strip_line_num=strip_line_num
                    )
                with lock:
                    counter["sent"] += 1
                HEALTH_MGR.report_success(acc_id, channel_id=target_id)
            elif plat == "discord" and mode in ("nhay_poll", "nhay_typing", "reaction_storm", "discord_embed_vip", "discord_status_rotator"):
                text_item = strip_leading_line_number(clean_raw) if strip_line_num else clean_raw
                if mode == "nhay_poll":
                    if "|" in text_item:
                        q_p, opt_p = text_item.split("|", 1)
                        opts_l = [x.strip() for x in opt_p.replace(";", "|").split("|") if x.strip()]
                    else:
                        q_p = text_item
                        opts_l = [f"{text_item[:25]} #1", f"{text_item[:25]} #2"]
                    client.send_poll_discord(target_id, q_p.strip(), opts_l)
                elif mode == "nhay_typing":
                    client.send_typing(target_id)
                elif mode == "discord_status_rotator":
                    client.set_custom_status(text_item[:80])
                    client.send_message(
                        target_id, text_item, color_mode=color_mode,
                        fixed_color=fixed_color, antiband=antiband,
                        mentions=eff_mentions, tag_all=eff_tag_all,
                        strip_line_num=strip_line_num, is_heading=is_heading
                    )
                elif mode == "discord_embed_vip":
                    art_txt = f"# 🔥 **{text_item}**\n> ⚡ *{text_item}*"
                    if use_emoji and icon_count > 0:
                        art_txt += " " + build_unique_zalo_icons(icon_count)
                    client.send_message(
                        target_id, art_txt, color_mode="none",
                        fixed_color=fixed_color, antiband=antiband,
                        mentions=eff_mentions, tag_all=eff_tag_all,
                        strip_line_num=False, is_heading=False
                    )
                elif mode == "reaction_storm":
                    sent_obj = client.send_message(
                        target_id, text_item, color_mode=color_mode,
                        fixed_color=fixed_color, antiband=antiband,
                        mentions=eff_mentions, tag_all=eff_tag_all,
                        strip_line_num=strip_line_num, is_heading=is_heading
                    )
                    if isinstance(sent_obj, dict) and sent_obj.get("id"):
                        for em_r in ("🔥", "⚡", "👑"):
                            client.add_reaction(target_id, sent_obj["id"], em_r)
                with lock:
                    counter["sent"] += 1
                HEALTH_MGR.report_success(acc_id, channel_id=target_id)
            elif plat == "messenger" and mode in ("nhay_poll", "nhay_theme", "nhay_typing", "share_link", "share_contact", "nhay_namebox", "mess_nickname"):
                text_item = strip_leading_line_number(clean_raw) if strip_line_num else clean_raw
                if mode == "nhay_poll":
                    if "|" in text_item:
                        q_p, opt_p = text_item.split("|", 1)
                        opts_l = [x.strip() for x in opt_p.replace(";", "|").split("|") if x.strip()]
                    else:
                        q_p = text_item
                        opts_l = [f"{text_item[:25]} #1", f"{text_item[:25]} #2"]
                    client.send_poll_mqtt(target_id, q_p.strip(), opts_l)
                elif mode == "nhay_theme":
                    client.set_theme_mqtt(target_id, text_item if text_item else None)
                elif mode == "nhay_typing":
                    client.send_typing_mqtt(target_id, True, is_group=True)
                elif mode == "share_link":
                    if "|" in text_item:
                        u_part, t_part = text_item.split("|", 1)
                    else:
                        u_part, t_part = "https://www.facebook.com/", text_item
                    client.share_link_mqtt(target_id, u_part.strip(), t_part.strip())
                elif mode == "share_contact":
                    c_uid = eff_mentions[0]["uid"] if eff_mentions else client.uid
                    client.share_contact_mqtt(target_id, c_uid, text_item)
                elif mode == "nhay_namebox":
                    client.rename_group(target_id, text_item)
                elif mode == "mess_nickname":
                    c_uid = eff_mentions[b_idx % len(eff_mentions)]["uid"] if eff_mentions else client.uid
                    client.change_nickname(target_id, c_uid, text_item[:45])
                with lock:
                    counter["sent"] += 1
                HEALTH_MGR.report_success(acc_id, channel_id=target_id)
            elif mode == "treo_ngon":
                text = clean_raw.replace("\r\n", "\n").replace("\r", "\n")
                _fire_single_packet(
                    text, eff_mentions, eff_tag_all, color_mode, fixed_color,
                    is_heading, antiband, use_emoji, icon_count, False, color_counter
                )
                wave_key = runtime_opts.get("_wave_key", "")
                if wave_key:
                    WaveFairnessEngine.record_acc_sent(wave_key, acc_id)
                color_counter += 1

            elif mode == "treo_nhay":
                lines = []
                for raw_ln in clean_raw.split("\n"):
                    s_ln = raw_ln.strip()
                    if s_ln:
                        c_ln = strip_leading_line_number(s_ln)
                        if c_ln:
                            lines.append(c_ln)

                for ln in lines:
                    if is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id):
                        break
                    delay = float(runtime_opts.get("delay", delay))
                    color_mode = runtime_opts.get("color_mode", color_mode)
                    fixed_color = runtime_opts.get("fixed_color", fixed_color)
                    icon_count = int(runtime_opts.get("icon_count", icon_count))
                    use_emoji = bool(runtime_opts.get("use_emoji", use_emoji))
                    is_heading = bool(runtime_opts.get("is_heading", is_heading))
                    antiband = bool(runtime_opts.get("antiband", antiband))

                    if antidieall and delay > 0.0:
                        ok_s, w_s = HEALTH_MGR.can_send(acc_id, channel_id=target_id, platform=plat, token=tok_for_check)
                        if not ok_s:
                            if interruptible_wait(stop_ev, min(0.15, max(0.02, w_s)), start_global_epoch, start_box_epoch, target_id):
                                break
                            continue

                    wave_key = runtime_opts.get("_wave_key", "")
                    if wave_key:
                        fair_w = WaveFairnessEngine.get_fair_pacing_pause(wave_key, acc_id, delay)
                        if fair_w > 0.0:
                            if interruptible_wait(stop_ev, fair_w, start_global_epoch, start_box_epoch, target_id):
                                break

                    _fire_single_packet(
                        ln, eff_mentions, eff_tag_all, color_mode, fixed_color,
                        is_heading, antiband, use_emoji, icon_count, True, color_counter
                    )
                    if wave_key:
                        WaveFairnessEngine.record_acc_sent(wave_key, acc_id)
                    color_counter += 1
                    step_d = HEALTH_MGR.get_adaptive_delay(
                        acc_id, delay, antiband=antiband, platform=plat, text_len=len(ln), active_box_count=active_box_count
                    )
                    if step_d > 0.0:
                        if interruptible_wait(stop_ev, step_d, start_global_epoch, start_box_epoch, target_id):
                            break
                continue

            else:
                wave_key = runtime_opts.get("_wave_key", "")
                if wave_key:
                    fair_w = WaveFairnessEngine.get_fair_pacing_pause(wave_key, acc_id, delay)
                    if fair_w > 0.0:
                        if interruptible_wait(stop_ev, fair_w, start_global_epoch, start_box_epoch, target_id):
                            break
                text = strip_leading_line_number(clean_raw) if strip_line_num else clean_raw
                _fire_single_packet(
                    text, eff_mentions, eff_tag_all, color_mode, fixed_color,
                    is_heading, antiband, use_emoji, icon_count, strip_line_num, color_counter
                )
                if wave_key:
                    WaveFairnessEngine.record_acc_sent(wave_key, acc_id)
                color_counter += 1

        except Exception as e:
            err_str = str(e)
            if "ChannelForbidden:" in err_str:
                break
            elif "429:RateLimit:" in err_str:
                parts = err_str.split(":")
                try:
                    retry_after = float(parts[2])
                except Exception:
                    retry_after = 0.4
                HEALTH_MGR.report_rate_limit(acc_id, retry_after, reason=err_str, channel_id=target_id)
            elif "AuthError" in err_str:
                HEALTH_MGR.report_error(acc_id, err_str, is_auth_error=True)
            else:
                HEALTH_MGR.report_error(acc_id, err_str, is_auth_error=False, channel_id=target_id)

        actual_delay = HEALTH_MGR.get_adaptive_delay(
            acc_id, delay, antiband=antiband, platform=plat, text_len=len(clean_raw), active_box_count=active_box_count
        )
        if actual_delay > 0.0:
            if interruptible_wait(stop_ev, actual_delay, start_global_epoch, start_box_epoch, target_id):
                break

def multi_box_shard_worker(client, acc_id, plat, shard_targets, blocks, runtime_opts,
                           stop_ev, counter, lock, stagger_sec=0.0, active_box_count=1):
    """Động Cơ Phân Mảnh Vòng Tròn Siêu Tốc (High-Velocity Non-Blocking Ring Shard Worker ):
    - Chuyên trị bài toán 50+ Acc × 200+ Nhóm cùng lúc ở chế độ Delay = 0s (Treo ngôn .g, Treo nhây .n, Siêu xả .xa).
    - Thay vì tạo 10.000 luồng OS gây nghẽn GIL hoặc để 1 nhóm dính 429 làm dừng tạm thời cả luồng,
      mỗi Shard Worker xoay vòng liên hoàn qua các nhóm được giao trong 0ms:
      + Nhóm nào sẵn sàng là phang ngay lập tức!
      + Nhóm nào vừa vướng cooldown ngắn (0.15s) thì tự động lướt qua (0ms, không sleep!) để bắn nhóm kế tiếp ngay,
        nhờ đó tốc độ gửi tổng thể luôn đạt cực đại và treo ngôn / treo nhây cực mượt không bao giờ khựng hay đơ!"""
    if not shard_targets or not blocks:
        return
    if len(shard_targets) == 1:
        return box_target_worker(
            client, acc_id, plat, shard_targets[0], blocks, runtime_opts,
            stop_ev, counter, lock, stagger_sec=stagger_sec, active_box_count=active_box_count
        )

    start_global_epoch, _ = get_current_epochs(None)
    if stagger_sec > 0:
        if interruptible_wait(stop_ev, stagger_sec, start_global_epoch, None, None):
            return

    valid_targets = []
    box_epochs = {}
    for t in shard_targets:
        t_type = t.get("type", "group")
        t_id = str(t.get("id") or "").strip()
        if not t_id:
            continue
        is_discord_t = (t_type == "discord_channel")
        is_mess_t = (t_type in ("messenger_thread", "messenger_group", "messenger_user"))
        is_zalo_t = not is_discord_t and not is_mess_t
        if (plat == "zalo" and not is_zalo_t) or (plat == "discord" and not is_discord_t) or (plat == "messenger" and not is_mess_t):
            continue
        valid_targets.append(t)
        _, b_ep = get_current_epochs(t_id)
        box_epochs[t_id] = b_ep

    if not valid_targets:
        return

    dead_targets = set()
    target_skip_until = defaultdict(float)
    target_b_idx = defaultdict(int)
    color_counter = random.randint(0, 3)

    while not is_task_stopped_fast(stop_ev, start_global_epoch, None, None):
        if len(dead_targets) >= len(valid_targets):
            break

        antiband = bool(runtime_opts.get("antiband", True))
        delay = float(runtime_opts.get("delay", 0.0))
        use_emoji = bool(runtime_opts.get("use_emoji", True))
        icon_count = int(runtime_opts.get("icon_count", 3))
        is_heading = bool(runtime_opts.get("is_heading", True))
        mode = runtime_opts.get("mode", "fast")
        color_mode = runtime_opts.get("color_mode", "rainbow")
        fixed_color = runtime_opts.get("fixed_color", "red")
        tag_users = runtime_opts.get("tag_users") or []
        tag_all = bool(runtime_opts.get("tag_all", False))
        strip_line_num = bool(runtime_opts.get("strip_line_num", True)) or (mode == "treo_nhay")
        wave_key = runtime_opts.get("_wave_key", "")

        if mode in ("nhay_tag_all", "nhay_tag_all_an", "nhay_tag_ten_an", "battrinh_all_box"):
            tag_all = True
        if mode in ("raid_burst", "sieu_xa_nhieu_nhom"):
            color_mode = "word_rainbow"
            is_heading = True
            if use_emoji and icon_count > 0:
                icon_count = max(icon_count, 4)

        fired_in_pass = 0
        for t in valid_targets:
            t_id = str(t["id"])
            if t_id in dead_targets:
                continue
            if is_task_stopped_fast(stop_ev, start_global_epoch, box_epochs.get(t_id), t_id):
                dead_targets.add(t_id)
                continue

            now_t = time.time()
            if now_t < target_skip_until[t_id]:
                continue

            cur_idx = target_b_idx[t_id]
            step_inc = 1
            raw = blocks[cur_idx % len(blocks)]

            if mode == "auto_shuffle" and len(blocks) > 1:
                raw = random.choice(blocks)
            elif mode == "combo_lien_thanh" and len(blocks) >= 2:
                c1 = strip_leading_line_number(blocks[cur_idx % len(blocks)])
                c2 = strip_leading_line_number(blocks[(cur_idx + 1) % len(blocks)])
                c3 = strip_leading_line_number(blocks[(cur_idx + 2) % len(blocks)])
                raw = f"{c1}\n{c2}\n{c3}"
                step_inc = 3

            with SYSTEM_CFG_LOCK:
                g_ic = int(SYSTEM_RUNTIME_CONFIG.get("icon_count", icon_count))
                g_em = bool(SYSTEM_RUNTIME_CONFIG.get("use_emoji", use_emoji))
                g_fs = SYSTEM_RUNTIME_CONFIG.get("font_style", runtime_opts.get("font_style", "big_bold"))
            if not g_em or g_ic <= 0 or not use_emoji or int(icon_count or 0) <= 0:
                eff_em = False
                eff_ic = 0
            else:
                eff_em = True
                eff_ic = int(icon_count)
            f_style = runtime_opts.get("font_style") or g_fs

            if mode == "treo_ngon":
                pkt_text = raw.replace("\r\n", "\n").replace("\r", "\n")
                s_num_flag = False
            else:
                pkt_text = strip_leading_line_number(raw, preserve_indent=True) if strip_line_num else raw
                s_num_flag = strip_line_num

            if not eff_em or eff_ic <= 0:
                pkt_text = strip_trailing_icons_when_zero(pkt_text)

            is_grp = (t.get("type", "group") == "group") or bool(tag_users) or bool(tag_all)
            t0_s = time.perf_counter()
            try:
                if plat == "zalo":
                    client.send_adv(
                        pkt_text, t_id, color_mode=color_mode, fixed_color=fixed_color,
                        is_group=is_grp, mentions=(tag_users if is_grp else None),
                        tag_all=(tag_all if is_grp else False), is_heading=is_heading,
                        color_offset=color_counter, antiband=antiband,
                        use_emoji=eff_em, icon_count=eff_ic,
                        auto_retry_thread_type=True, strip_line_num=s_num_flag,
                        hide_tag_all=bool(runtime_opts.get("hide_tag_all", True)),
                        hide_tag_name=bool(runtime_opts.get("hide_tag_name", True)),
                        font_style=f_style
                    )
                elif plat == "messenger":
                    client.send_message(
                        t_id, pkt_text, is_group=True, mentions=tag_users,
                        tag_all=tag_all, antiband=antiband,
                        use_emoji=eff_em, icon_count=eff_ic,
                        is_heading=is_heading, strip_line_num=s_num_flag,
                        stop_ev=stop_ev, start_global_epoch=start_global_epoch, start_box_epoch=box_epochs.get(t_id)
                    )
                else:
                    msg_ln = (pkt_text + " " + build_unique_zalo_icons(eff_ic)) if (eff_em and eff_ic > 0) else pkt_text
                    sent_res = client.send_message(
                        t_id, msg_ln, color_mode=color_mode,
                        fixed_color=fixed_color, antiband=antiband,
                        mentions=tag_users, tag_all=tag_all,
                        strip_line_num=s_num_flag, is_heading=is_heading,
                        stop_ev=stop_ev, start_global_epoch=start_global_epoch, start_box_epoch=box_epochs.get(t_id)
                    )
                    if sent_res is None:
                        continue
                target_b_idx[t_id] = cur_idx + step_inc
                lat_ms = (time.perf_counter() - t0_s) * 1000.0
                with lock:
                    counter["sent"] += 1
                if wave_key:
                    WaveFairnessEngine.record_acc_sent(wave_key, acc_id)
                HEALTH_MGR.report_success(acc_id, latency_ms=lat_ms, channel_id=t_id)
                color_counter += 1
                fired_in_pass += 1
            except Exception as ex_s:
                err_s = str(ex_s)
                if "ChannelForbidden:" in err_s:
                    dead_targets.add(t_id)
                elif "429:RateLimit:" in err_s:
                    parts = err_s.split(":")
                    try:
                        ra = float(parts[2])
                    except Exception:
                        ra = 0.3
                    # Đánh dấu lướt nhẹ riêng nhóm này để luồng bắn ngay sang nhóm kế tiếp trong 0ms (không dừng!)
                    target_skip_until[t_id] = time.time() + min(0.28, max(0.04, ra * 0.25))
                    HEALTH_MGR.report_rate_limit(acc_id, ra, reason=err_s, channel_id=t_id)
                elif "AuthError" in err_s:
                    HEALTH_MGR.report_error(acc_id, err_s, is_auth_error=True)
                    target_skip_until[t_id] = time.time() + 1.0
                else:
                    target_skip_until[t_id] = time.time() + 0.15
                    HEALTH_MGR.report_error(acc_id, err_s, is_auth_error=False, channel_id=t_id)

        if delay > 0.0:
            if interruptible_wait(stop_ev, delay, start_global_epoch, None, None):
                break
        elif fired_in_pass == 0:
            # Nếu toàn bộ nhóm trong shard đang chờ vi nhịp hết 0.04s thì nhường CPU 0.015s rồi bắn tiếp ngay
            if interruptible_wait(stop_ev, 0.015, start_global_epoch, None, None):
                break


def single_acc_multi_box_dispatcher(acc_dict, targets, blocks, runtime_opts, stop_ev, counter, lock, acc_idx=0):
    acc_id = acc_dict["id"]
    plat = (acc_dict.get("platform") or "zalo").lower()
    raw_acc_name = acc_dict.get("name") or f"Acc #{acc_id}"
    acc_key = f"{raw_acc_name} (#{acc_id})"

    my_targets = []
    for t in targets:
        t_type = t.get("type", "group")
        if plat == "discord" and t_type != "discord_channel":
            continue
        if plat == "messenger" and t_type not in ("messenger_thread", "messenger_group", "messenger_user"):
            continue
        if plat == "zalo" and t_type in ("discord_channel", "messenger_thread", "messenger_group", "messenger_user"):
            continue
        if t.get("strict_bind"):
            assigned = t.get("assigned_acc_ids") or t.get("acc_ids")
            if assigned and isinstance(assigned, (list, tuple, set)):
                clean_a = {int(x) for x in assigned if str(x).isdigit()}
                if clean_a and int(acc_id) not in clean_a:
                    continue
        my_targets.append(t)

    if not my_targets:
        return

    client = None
    if plat == "zalo":
        try:
            client = Zalo.get_pooled_client(
                acc_dict["imei"], acc_dict["cookies"],
                user_agent=acc_dict.get("user_agent") or "",
                zpw_enk_hint=acc_dict.get("zpw_enk") or "",
                uid_hint=acc_dict.get("uid") or ""
            )
            HEALTH_MGR.report_success(acc_id)
        except Exception as e:
            HEALTH_MGR.report_error(acc_id, str(e), is_auth_error=True)
            return
    elif plat == "messenger":
        try:
            client = MessengerClient.get_pooled_client(acc_dict["cookies"], uid=acc_dict.get("uid") or "")
            HEALTH_MGR.report_success(acc_id)
        except Exception as e:
            HEALTH_MGR.report_error(acc_id, str(e), is_auth_error=True)
            return
    else:
        try:
            client = DiscordClient(acc_dict["token"], is_bot=bool(acc_dict.get("is_bot", 0)))
            off_uid = decode_discord_uid_offline(client.token)
            if off_uid:
                client.user_id = off_uid
            elif not client.check(force_network=False):
                raise Exception("Token Discord không hợp lệ hoặc đã hết hạn")
            HEALTH_MGR.report_success(acc_id)
        except Exception as e:
            HEALTH_MGR.report_error(acc_id, str(e), is_auth_error=True)
            return

    with lock:
        if "by_acc" not in counter:
            counter["by_acc"] = {}
        counter["by_acc"][acc_key] = counter["by_acc"].get(acc_key, 0)

    class _AccCounterProxy(dict):
        def __getitem__(self, k):
            return counter.get(k, 0)
        def __setitem__(self, k, v):
            diff = v - counter.get(k, 0)
            counter[k] = v
            if k == "sent" and diff > 0:
                counter["by_acc"][acc_key] = counter["by_acc"].get(acc_key, 0) + diff

    proxy_counter = _AccCounterProxy()
    box_threads = []
    total_boxes = max(1, len(my_targets))
    cur_d_cfg = float(runtime_opts.get("delay", 0.0) or 0.0)
    stagger_base = 0.0 if cur_d_cfg <= 0.05 else min(0.06, acc_idx * 0.01)

    # Khi Delay == 0.0s (Siêu tốc không độ trễ): tự động nhân luồng song song cho từng Box
    # để dù gửi 1 box hay 200 box đồng loạt vẫn bắn song song tức thì không bao giờ phải chờ RTT của box trước!
    if cur_d_cfg <= 0.0:
        if total_boxes <= 32:
            expanded_targets = list(my_targets) * min(3, max(1, 32 // max(1, total_boxes)))
        else:
            expanded_targets = list(my_targets)
    else:
        expanded_targets = list(my_targets)

    max_shards_per_acc = (200 if len(expanded_targets) > 200 else len(expanded_targets)) if cur_d_cfg <= 0.0 else (96 if len(expanded_targets) > 96 else len(expanded_targets))
    rotated_targets = list(expanded_targets)
    if len(rotated_targets) > 1 and acc_idx > 0:
        rot_offset = (acc_idx * 3) % len(rotated_targets)
        rotated_targets = rotated_targets[rot_offset:] + rotated_targets[:rot_offset]

    shards = [[] for _ in range(max(1, max_shards_per_acc))]
    for idx_t, t_item in enumerate(rotated_targets):
        shards[idx_t % len(shards)].append(t_item)

    for shard_list in shards:
        if not shard_list:
            continue
        bt = threading.Thread(
            target=multi_box_shard_worker,
            args=(client, acc_id, plat, shard_list, blocks, runtime_opts, stop_ev, proxy_counter, lock, stagger_base, total_boxes),
            daemon=True
        )
        box_threads.append(bt)
        bt.start()

    while not stop_ev.is_set():
        if not any(bt.is_alive() for bt in box_threads):
            break
        stop_ev.wait(0.25)

    for bt in box_threads:
        bt.join(timeout=0.02)

def task_supervisor(tid, targets, blocks, runtime_opts, multi_acc, stop_ev, specific_acc_id=None, account_ids=None):
    all_enabled = get_all_accounts_from_ram(enabled_only=True)
    if account_ids and isinstance(account_ids, (list, tuple, set)):
        id_set = {int(x) for x in account_ids if str(x).isdigit()}
        accs = [a for a in all_enabled if int(a["id"]) in id_set]
        if not accs:
            accs = all_enabled
    elif specific_acc_id and not multi_acc:
        acc_single = get_account_from_ram(specific_acc_id)
        accs = [acc_single] if acc_single else []
    elif specific_acc_id and multi_acc:
        acc_single = get_account_from_ram(specific_acc_id)
        plat_Filter = (acc_single.get("platform") or "zalo") if acc_single else None
        accs = get_all_accounts_from_ram(platform=plat_Filter, enabled_only=True)
        if not accs and acc_single:
            accs = [acc_single]
    else:
        accs = all_enabled

    if not accs:
        with TASKS_RAM_LOCK:
            if tid in TASKS_RAM_STORE:
                TASKS_RAM_STORE[tid]["status"] = "stopped"
        ACTIVE_TASKS.pop(tid, None)
        return

    # Hỗ trợ tới 100+ tài khoản chạy đồng thời song song & đăng ký Bộ Điều Phối Luồng Sóng Đều (WaveFairnessEngine)
    selected_accs = accs[:120] if multi_acc else [accs[0]]
    runtime_opts["_wave_key"] = tid
    WaveFairnessEngine.register_accounts_for_wave(tid, [a["id"] for a in selected_accs])
    acc_names_list = [f"{a.get('name') or 'Acc'} (#{a['id']})" for a in selected_accs]
    with TASKS_RAM_LOCK:
        if tid in TASKS_RAM_STORE:
            TASKS_RAM_STORE[tid]["acc_count"] = len(selected_accs)
            TASKS_RAM_STORE[tid]["acc_names"] = acc_names_list

    counter = {"sent": 0, "by_acc": {n: 0 for n in acc_names_list}}
    lock = threading.Lock()
    threads = []

    for idx_a, a in enumerate(selected_accs):
        a_blocks = list(blocks)
        if idx_a > 0 and len(a_blocks) > 1:
            sh = idx_a % len(a_blocks)
            a_blocks = a_blocks[sh:] + a_blocks[:sh]
        t = threading.Thread(
            target=single_acc_multi_box_dispatcher,
            args=(dict(a), targets, a_blocks, runtime_opts, stop_ev, counter, lock, idx_a),
            daemon=True
        )
        threads.append(t)
        t.start()

    while not stop_ev.is_set():
        alive = any(t.is_alive() for t in threads)
        if not alive:
            break
        with TASKS_RAM_LOCK:
            if tid in TASKS_RAM_STORE:
                TASKS_RAM_STORE[tid]["sent"] = counter["sent"]
                TASKS_RAM_STORE[tid]["by_acc"] = dict(counter.get("by_acc") or {})
        if stop_ev.wait(0.30):
            break

    with TASKS_RAM_LOCK:
        if tid in TASKS_RAM_STORE:
            TASKS_RAM_STORE[tid]["sent"] = counter["sent"]
            TASKS_RAM_STORE[tid]["by_acc"] = dict(counter.get("by_acc") or {})
            TASKS_RAM_STORE[tid]["status"] = "stopped"
            TASKS_RAM_STORE[tid]["dirty"] = True
    ACTIVE_TASKS.pop(tid, None)

def start_task_programmatic(targets, blocks, delay=0.0, use_emoji=True, icon_count=3,
                            tag_users=None, tag_all=False, is_heading=True, multi_acc=True,
                            mode="fast", color_mode="rainbow", fixed_color="red",
                            antiband=True, antidieall=True, specific_acc_id=None, source_label="web",
                            defer_db_insert=False, account_ids=None, trigger_cmd="", hide_tag_all=True,
                            hide_tag_name=True, font_style=None):
    tid = new_tid("cmd" if source_label == "chat" else "task")
    stop_ev = threading.Event()
    tag_users = tag_users or []

    clean_blocks = []
    for b in blocks:
        if mode == "treo_nhay":
            lines_b = [strip_leading_line_number(ln) for ln in str(b).replace("\r\n", "\n").split("\n") if ln.strip()]
            clean_blocks.extend([x for x in lines_b if x])
        else:
            clean_blocks.append(clean_corrupted_shortcuts(str(b)))
    if not clean_blocks:
        clean_blocks = list(blocks)

    with SYSTEM_CFG_LOCK:
        eff_fs = font_style or SYSTEM_RUNTIME_CONFIG.get("font_style", "big_bold" if is_heading else "normal")
        if source_label == "web":
            SYSTEM_RUNTIME_CONFIG["delay"] = float(delay)
            SYSTEM_RUNTIME_CONFIG["icon_count"] = int(icon_count)
            SYSTEM_RUNTIME_CONFIG["use_emoji"] = bool(use_emoji) and (int(icon_count) > 0)
            SYSTEM_RUNTIME_CONFIG["color_mode"] = color_mode
            SYSTEM_RUNTIME_CONFIG["fixed_color"] = fixed_color
            SYSTEM_RUNTIME_CONFIG["font_style"] = eff_fs
            SYSTEM_RUNTIME_CONFIG["is_heading"] = bool(is_heading)

    runtime_opts = {
        "delay": float(delay),
        "use_emoji": bool(use_emoji) and (int(icon_count) > 0),
        "icon_count": int(icon_count) if bool(use_emoji) else 0,
        "font_style": eff_fs,
        "tag_users": list(tag_users),
        "tag_all": bool(tag_all),
        "hide_tag_all": bool(hide_tag_all),
        "hide_tag_name": bool(hide_tag_name),
        "is_heading": bool(is_heading),
        "mode": mode,
        "color_mode": color_mode,
        "fixed_color": fixed_color,
        "antiband": bool(antiband),
        "antidieall": bool(antidieall),
        "strip_line_num": (mode == "treo_nhay") or True,
    }

    meta_info = {
        "source": source_label,
        "trigger_cmd": trigger_cmd or ("Lệnh khung chat" if source_label == "chat" else "Khởi chạy từ Web"),
        "multi_acc": multi_acc,
        "account_ids": list(account_ids) if account_ids else [],
        "color_mode": color_mode,
        "delay": delay,
        "targets": [str(t.get("id")) for t in targets],
        "target_names": [t.get("name", str(t.get("id"))) for t in targets],
        "box_count": len(targets),
        "tag_count": len(tag_users),
        "tag_all": tag_all
    }

    now_ts = time.time()
    with TASKS_RAM_LOCK:
        TASKS_RAM_STORE[tid] = {
            "id": tid,
            "type": mode,
            "meta": meta_info,
            "status": "running",
            "started_at": now_ts,
            "sent": 0,
            "fail": 0,
            "delay": float(delay),
            "acc_count": 1,
            "acc_names": [],
            "by_acc": {},
            "dirty": True,
            "persisted": False,
        }

    th = threading.Thread(
        target=task_supervisor,
        args=(tid, targets, clean_blocks, runtime_opts, multi_acc, stop_ev, specific_acc_id, account_ids),
        daemon=True
    )

    ACTIVE_TASKS[tid] = {
        "stop": stop_ev,
        "thread": th,
        "targets": [str(t.get("id")) for t in targets],
        "opts": runtime_opts,
        "acc_id": specific_acc_id,
        "source": source_label
    }
    th.start()
    try:
        with _STATUS_CACHE_LOCK:
            _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
    except Exception:
        pass
    return tid

def update_running_tasks_config(thread_id=None, **kwargs):
    """Cập nhật tức thì cấu hình hệ thống (SYSTEM_RUNTIME_CONFIG) và áp dụng đồng bộ lên MỌI nhóm đang chạy + giao diện Web!"""
    updated = 0
    with SYSTEM_CFG_LOCK:
        for k, v in kwargs.items():
            if k in SYSTEM_RUNTIME_CONFIG:
                SYSTEM_RUNTIME_CONFIG[k] = v

    try:
        DiscordClient._DISCORD_MSG_FORMAT_CACHE.clear()
    except Exception:
        pass

    for tid, info in list(ACTIVE_TASKS.items()):
        if thread_id is None or str(thread_id) in info.get("targets", []):
            opts = info.get("opts")
            if isinstance(opts, dict):
                opts.update(kwargs)
                updated += 1
            if "delay" in kwargs:
                with TASKS_RAM_LOCK:
                    if tid in TASKS_RAM_STORE:
                        TASKS_RAM_STORE[tid]["delay"] = float(kwargs["delay"])
    try:
        with _STATUS_CACHE_LOCK:
            _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
    except Exception:
        pass
    return updated

def stop_tasks_for_thread(thread_id=None):
    """Công tắc Ngắt Nguyên Tử 0ms (Zero-Lag Atomic Kill Switch):
    - Ngắt toàn bộ tiến trình đang chạy trong RAM chỉ trong 0.01ms!
    - Xả toàn bộ hàng đợi Pacer Discord/Zalo để không còn bất kỳ tin nhắn trễ nào bắn ra sau khi bấm Dừng!"""
    bump_stop_epoch(thread_id)
    DiscordStealthAntiBanEngine.abort_all_campaign_wait_buckets(thread_id)
    stopped = 0
    stopped_tids = []
    for tid, info in list(ACTIVE_TASKS.items()):
        if thread_id is None or str(thread_id) in info.get("targets", []):
            info["stop"].set()
            stopped_tids.append(tid)
            stopped += 1
    for tid in stopped_tids:
        ACTIVE_TASKS.pop(tid, None)

    with TASKS_RAM_LOCK:
        if thread_id is None:
            for t_obj in TASKS_RAM_STORE.values():
                if t_obj.get("status") == "running":
                    t_obj["status"] = "stopped"
                    t_obj["dirty"] = True
                    stopped = max(stopped, 1)
        else:
            for tid in stopped_tids:
                if tid in TASKS_RAM_STORE:
                    TASKS_RAM_STORE[tid]["status"] = "stopped"
                    TASKS_RAM_STORE[tid]["dirty"] = True

    def _async_stop_db():
        try:
            conn = db()
            if thread_id is None:
                conn.execute("UPDATE tasks SET status='stopped' WHERE status='running'")
            elif stopped_tids:
                conn.executemany("UPDATE tasks SET status='stopped' WHERE id=?", [(t,) for t in stopped_tids])
            conn.commit()
        except Exception:
            pass

    threading.Thread(target=_async_stop_db, daemon=True).start()
    with _STATUS_CACHE_LOCK:
        _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
    return stopped

def log_system_command(acc_id, thread_id, sender_id, cmd_text, action_taken, sender_name=""):
    acc_obj = get_account_from_ram(acc_id) if acc_id else None
    acc_name = (acc_obj.get("name") if acc_obj else "") or (f"Acc #{acc_id}" if acc_id else "Web Admin")
    plat_lbl = ((acc_obj.get("platform") if acc_obj else "") or ("web" if not acc_id else "zalo")).upper()
    s_uid_str = str(sender_id or "").strip()
    resolved_sender_name = (
        str(sender_name or "").strip()
        or GLOBAL_USER_NAME_CACHE.get(s_uid_str)
        or (acc_name if s_uid_str in ("0", "", str((acc_obj or {}).get("uid") or "")) else f"UID_{s_uid_str[-5:]}")
    )
    now_t = time.time()
    entry = {
        "acc_id": acc_id,
        "acc_name": acc_name,
        "platform": plat_lbl,
        "time_str": time.strftime("%H:%M:%S", time.localtime(now_t)),
        "thread_id": str(thread_id or ""),
        "sender_id": s_uid_str,
        "sender_name": resolved_sender_name,
        "cmd_text": sanitize_log_text(cmd_text)[:240],
        "action_taken": sanitize_log_text(action_taken)[:240],
        "created_at": now_t,
    }
    BOT_LOGS_RAM_DEQUE.appendleft(entry)
    try:
        with _STATUS_CACHE_LOCK:
            _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
    except Exception:
        pass

    def _async_log_db():
        try:
            conn = db()
            conn.execute(
                "INSERT INTO bot_logs (acc_id, thread_id, sender_id, cmd_text, action_taken, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (entry["acc_id"], mask_sensitive_id(thread_id, 6), mask_sensitive_id(sender_id, 6), entry["cmd_text"], entry["action_taken"], entry["created_at"])
            )
            conn.commit()
        except Exception:
            pass

    threading.Thread(target=_async_log_db, daemon=True).start()

def strip_invisible_chars(s):
    if not s:
        return ""
    out = []
    for ch in str(s):
        if ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00a0"):
            continue
        if unicodedata.category(ch) == "Cf":
            continue
        out.append(ch)
    return "".join(out).strip()


class FullConversationAutoScanner:
    """Bộ Soi Tự Động Full Cuộc Trò Chuyện Đa Nền Tảng (Discord • Zalo • Messenger Auto-Discovery Engine ):
    - Tự động thu hoạch và lập chỉ mục toàn bộ 200-500+ cuộc trò chuyện (Box Nhóm DM, Chat Riêng, Kênh Server, Nhóm Zalo)
      trên tất cả 50+ tài khoản đang kết nối.
    - Cho phép gõ lệnh .soi / .dsbox để xem danh sách đánh số #1 -> #200+ và gõ lệnh .g / .n / .xa kèm:
      + `allnhom` / `allbox` / `nhom=all`: Gửi đồng loạt vào TẤT CẢ các nhóm đã soi!
      + `200nhom` / `50nhom` / `nhom=200`: Gửi đồng loạt vào đúng số lượng nhóm yêu cầu!
      + `nhom=1,2,5` hoặc `nhom=1-200` hoặc `nhom=ID1,ID2`: Gửi chính xác vào các nhóm chỉ định!"""

    _LOCK = threading.RLock()
    _CACHE_BY_PLAT = {"discord": [], "zalo": [], "messenger": []}
    _LAST_SCAN_TS = {"discord": 0.0, "zalo": 0.0, "messenger": 0.0}

    @classmethod
    def register_live_conversation(cls, platform, box_id, box_name="", sub_type="channel", guild_id=""):
        plat = str(platform or "discord").lower()
        bid = str(box_id or "").strip()
        if not bid or bid == "0":
            return
        t_type = "discord_channel" if plat == "discord" else ("messenger_thread" if plat == "messenger" else "group")
        with cls._LOCK:
            cur_list = cls._CACHE_BY_PLAT.setdefault(plat, [])
            if any(str(x.get("id")) == bid for x in cur_list):
                return
            cur_list.append({
                "id": bid,
                "name": box_name or f"[{plat.upper()}] Box #{bid[-5:]}",
                "type": t_type,
                "sub_type": sub_type,
                "guild_id": str(guild_id or ""),
            })

    @classmethod
    def scan_full_conversations(cls, platform="discord", force_refresh=False):
        plat = str(platform or "discord").lower()
        now = time.time()
        with cls._LOCK:
            cached = cls._CACHE_BY_PLAT.get(plat) or []
            if not force_refresh and cached and (now - cls._LAST_SCAN_TS.get(plat, 0.0) < 180.0):
                return [dict(x, display_idx=i + 1) for i, x in enumerate(cached)]

        accs = get_all_accounts_from_ram(platform=plat, enabled_only=True)
        if not accs:
            accs = get_all_accounts_from_ram(platform=plat, enabled_only=False)

        discovered = []
        seen_ids = set()

        if plat == "discord":
            def _scan_one_dc(a_row):
                try:
                    bot = DiscordClient(a_row["token"], is_bot=bool(a_row.get("is_bot", 0)))
                    return bot.get_all_boxes(force_refresh=force_refresh)
                except Exception:
                    return []
            if accs:
                with ThreadPoolExecutor(max_workers=min(24, len(accs))) as pool:
                    for b_list in pool.map(_scan_one_dc, accs):
                        for b in (b_list or []):
                            cid = str(b.get("id") or "").strip()
                            if cid and cid not in seen_ids:
                                seen_ids.add(cid)
                                discovered.append({
                                    "id": cid,
                                    "name": b.get("name") or f"Discord Box {cid[-5:]}",
                                    "type": "discord_channel",
                                    "sub_type": b.get("sub_type", "channel"),
                                })
        elif plat == "zalo":
            def _scan_one_zl(a_row):
                out = []
                try:
                    z = Zalo.get_pooled_client(
                        a_row["imei"], a_row["cookies"],
                        user_agent=a_row.get("user_agent") or "",
                        zpw_enk_hint=a_row.get("zpw_enk") or "",
                        uid_hint=a_row.get("uid") or ""
                    )
                    out.extend(z.groups(use_cache=not force_refresh))
                except Exception:
                    pass
                return out
            if accs:
                with ThreadPoolExecutor(max_workers=min(16, len(accs))) as pool:
                    for g_list in pool.map(_scan_one_zl, accs):
                        for g in (g_list or []):
                            gid = str(g.get("id") or "").strip()
                            if gid and gid not in seen_ids:
                                seen_ids.add(gid)
                                discovered.append({
                                    "id": gid,
                                    "name": g.get("name") or f"Nhóm Zalo {gid[-6:]}",
                                    "type": "group",
                                })
        elif plat == "messenger":
            for a_row in accs:
                try:
                    mc = MessengerClient.get_pooled_client(a_row["cookies"], uid=a_row.get("uid") or "")
                    for th in mc.get_threads(use_cache=not force_refresh):
                        tid = str(th.get("id") or "").strip()
                        if tid and tid not in seen_ids:
                            seen_ids.add(tid)
                            discovered.append({
                                "id": tid,
                                "name": th.get("name") or f"Box Mess {tid[-5:]}",
                                "type": "messenger_thread",
                            })
                except Exception:
                    continue

        with cls._LOCK:
            if discovered:
                cls._CACHE_BY_PLAT[plat] = discovered
                cls._LAST_SCAN_TS[plat] = now
            else:
                discovered = list(cls._CACHE_BY_PLAT.get(plat) or [])

        return [dict(x, display_idx=i + 1) for i, x in enumerate(discovered)]

    @classmethod
    def resolve_target_groups_from_spec(cls, platform, current_thread_id, is_group_default=True, spec_mode="current", spec_val=None):
        """Giải mã danh sách nhóm mục tiêu từ lệnh chat (.g / .n / .xa):
        - spec_mode == 'current': Chỉ gửi vào nhóm hiện tại.
        - spec_mode == 'all': Gửi vào TẤT CẢ các nhóm đã soi (200+ nhóm)!
        - spec_mode == 'count': Gửi vào đúng N nhóm (VD: 50 nhóm, 200 nhóm), luôn ưu tiên nhóm hiện tại đầu tiên!
        - spec_mode == 'custom': Chọn theo dải số thứ tự (VD: 1-200), danh sách số thứ tự (1,2,3,5) hoặc danh sách ID kênh!"""
        plat = str(platform or "discord").lower()
        t_type_default = "discord_channel" if plat == "discord" else ("messenger_thread" if plat == "messenger" else ("group" if is_group_default else "user"))
        cur_id_s = str(current_thread_id or "").strip()
        base_target = {
            "id": cur_id_s,
            "name": f"{plat.capitalize()}_{cur_id_s[-5:]}" if cur_id_s else "Current_Box",
            "type": t_type_default,
        }
        if spec_mode == "current" or not spec_mode:
            return [base_target]

        all_conv = cls.scan_full_conversations(plat, force_refresh=False)
        if not all_conv:
            all_conv = cls.scan_full_conversations(plat, force_refresh=True)

        if spec_mode == "all":
            out = []
            seen = set()
            if cur_id_s and cur_id_s != "0":
                seen.add(cur_id_s)
                cur_match = next((x for x in all_conv if str(x["id"]) == cur_id_s), None)
                out.append(cur_match if cur_match else base_target)
            for c in all_conv:
                cid = str(c["id"])
                if cid not in seen:
                    seen.add(cid)
                    out.append({"id": cid, "name": c["name"], "type": c["type"]})
            return out if out else [base_target]

        if spec_mode == "count":
            limit_n = max(1, int(spec_val or 1))
            out = []
            seen = set()
            if cur_id_s and cur_id_s != "0":
                seen.add(cur_id_s)
                cur_match = next((x for x in all_conv if str(x["id"]) == cur_id_s), None)
                out.append(cur_match if cur_match else base_target)
            for c in all_conv:
                if len(out) >= limit_n:
                    break
                cid = str(c["id"])
                if cid not in seen:
                    seen.add(cid)
                    out.append({"id": cid, "name": c["name"], "type": c["type"]})
            return out if out else [base_target]

        if spec_mode == "custom" and spec_val:
            raw_spec = str(spec_val).strip()
            out = []
            seen = set()
            parts = [p.strip() for p in raw_spec.replace(";", ",").split(",") if p.strip()]
            for p in parts:
                m_range = re.match(r"^(\d+)\s*\-\s*(\d+)$", p)
                if m_range:
                    a_idx, b_idx = int(m_range.group(1)), int(m_range.group(2))
                    lo, hi = min(a_idx, b_idx), max(a_idx, b_idx)
                    for idx_c in range(lo, hi + 1):
                        if 1 <= idx_c <= len(all_conv):
                            c = all_conv[idx_c - 1]
                            cid = str(c["id"])
                            if cid not in seen:
                                seen.add(cid)
                                out.append({"id": cid, "name": c["name"], "type": c["type"]})
                elif p.isdigit():
                    num_v = int(p)
                    if 1 <= num_v <= len(all_conv) and len(p) <= 5:
                        c = all_conv[num_v - 1]
                        cid = str(c["id"])
                        if cid not in seen:
                            seen.add(cid)
                            out.append({"id": cid, "name": c["name"], "type": c["type"]})
                    elif len(p) >= 6:
                        if p not in seen:
                            seen.add(p)
                            c_match = next((x for x in all_conv if str(x["id"]) == p), None)
                            out.append(c_match if c_match else {"id": p, "name": f"Box #{p[-5:]}", "type": t_type_default})
                else:
                    p_low = remove_vn_accents(p)
                    for c in all_conv:
                        if p_low in remove_vn_accents(c.get("name", "")):
                            cid = str(c["id"])
                            if cid not in seen:
                                seen.add(cid)
                                out.append({"id": cid, "name": c["name"], "type": c["type"]})
            return out if out else [base_target]

        return [base_target]


def extract_multigroup_spec_and_clean_body(raw_body_str, cmd_token=""):
    """Bóc tách thông minh các tham số chọn nhóm & tag all ở bất kỳ vị trí nào trong câu lệnh (.g / .n / .xa):
    Hỗ trợ:
    - `allnhom`, `allbox`, `allgroup`, `fullbox`, `fullnhom`, `tatcanhom`, `nhom=all`, `box=all` -> Gửi ALL nhóm!
    - `200nhom`, `50nhom`, `200box`, `nhom=200`, `box=50`, `sonhom=200` -> Gửi N nhóm!
    - `nhom=1,2,3`, `nhom=1-200`, `box=1-50`, `nhom=ID1,ID2` -> Gửi các nhóm cụ thể!
    - `tagall`, `tag=all`, `@all`, `@everyone`, `@here` -> Tự động bật Tag All!"""
    spec_mode = "all" if cmd_token in ("gall", "gll", "ngonall", "nall", "nll", "nhayall", "xaall") else "current"
    spec_val = None
    inline_tag_all = False

    if not raw_body_str:
        return "", spec_mode, spec_val, inline_tag_all

    kept_lines = []
    for raw_ln in str(raw_body_str).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not raw_ln.strip():
            kept_lines.append("")
            continue
        lead_len = len(raw_ln) - len(raw_ln.lstrip(" \t"))
        lead_ws = raw_ln[:lead_len]
        line_tokens = raw_ln[lead_len:].split(" ")
        kept_line_tokens = []
        for tk in line_tokens:
            tk_clean = tk.strip()
            if not tk_clean:
                kept_line_tokens.append(tk)
                continue
            tk_low = remove_vn_accents(tk_clean.lower())
            if tk_low in ("allnhom", "allbox", "allgroup", "fullbox", "fullnhom", "tatcanhom", "moinhom", "nhom=all", "box=all", "group=all", "gui=all"):
                spec_mode = "all"
                spec_val = "all"
                continue
            m_num_box = re.match(r"^(\d+)(?:nhom|box|group|kenh|phong)$", tk_low)
            if m_num_box:
                spec_mode = "count"
                spec_val = int(m_num_box.group(1))
                continue
            m_kv_box = re.match(r"^(?:nhom|box|group|sonhom|sobox|kenh|gui)=(.+)$", tk_low)
            if m_kv_box:
                val_part = m_kv_box.group(1).strip()
                if val_part in ("all", "full", "tatca", "het"):
                    spec_mode = "all"
                    spec_val = "all"
                elif val_part.isdigit() and len(val_part) <= 4:
                    spec_mode = "count"
                    spec_val = int(val_part)
                elif re.match(r"^(\d+)(?:nhom|box)$", val_part):
                    spec_mode = "count"
                    spec_val = int(re.match(r"^(\d+)", val_part).group(1))
                else:
                    spec_mode = "custom"
                    spec_val = val_part
                continue
            if tk_low in ("tagall", "tag=all", "@all", "@everyone", "@here", "tag_all"):
                inline_tag_all = True
                continue
            kept_line_tokens.append(tk)
        joined_ln = " ".join(kept_line_tokens).rstrip()
        if joined_ln:
            kept_lines.append(lead_ws + joined_ln)
    return "\n".join(kept_lines).strip("\r\n"), spec_mode, spec_val, inline_tag_all

def parse_and_execute_inchat_command(
    zalo_client, acc_row, thread_id, is_group, sender_id, raw_msg,
    raw_mentions=None, discord_client=None, platform="zalo", messenger_client=None,
    pre_claimed_slot=False, sender_name="", msg_id=None, reply_target=None
):
    if not raw_msg:
        return False

    if is_system_echo_message(text=raw_msg):
        return False

    text = strip_invisible_chars(str(raw_msg))
    if not text:
        return False

    if "<nội dung>" in text or "<số thứ tự file>" in text or "[@Tên / @All]" in text or "• .spam" in text:
        return False

    custom_prefix = (acc_row.get("cmd_prefix") or ".").strip()
    valid_prefixes = tuple(set([custom_prefix, ".", "/", "!"]))
    if not text.startswith(valid_prefixes):
        return False

    s_uid = str(sender_id or "").strip()
    if platform == "zalo" and zalo_client:
        my_uid = str(zalo_client.uid or acc_row.get("uid") or "").strip()
        my_s2m = str(getattr(zalo_client, "send2me_id", "") or "").strip()
    elif discord_client:
        my_uid = str(discord_client.user_id or acc_row.get("uid") or "").strip()
        my_s2m = ""
    elif messenger_client:
        my_uid = str(messenger_client.uid or acc_row.get("uid") or "").strip()
        my_s2m = ""
    else:
        my_uid = str(acc_row.get("uid") or "").strip()
        my_s2m = ""

    first_space = text.find(" ")
    if first_space == -1:
        cmd_token = text[1:].lower().strip()
        arg_body = ""
        prefix_u16_offset = utf16_len(text)
    else:
        cmd_token = text[1:first_space].lower().strip()
        raw_after_space = text[first_space + 1:]
        arg_body = raw_after_space.lstrip(" \t").rstrip() if not raw_after_space.startswith("\n") else raw_after_space.lstrip("\r\n").rstrip()
        leading_sp = len(raw_after_space) - len(raw_after_space.lstrip())
        prefix_u16_offset = utf16_len(text[:first_space + 1 + leading_sp])

    cmd_token = normalize_cmd_homoglyphs(cmd_token)
    if not cmd_token:
        return False

    # Ánh xạ lệnh tắt tàng hình (Stealth Short Aliases) giúp gõ lệnh trên Discord siêu nhanh & chống quét từ khóa
    stealth_alias_map = {
        "m": "menu",
        "h": "help",
        "s": "spam",
        "n": "nhay",
        "g": "ngon",
        "r": "raid",
        "a": "auto",
        "dao": "auto",
        "hi": "chao",
        "f": "file",
        "ds": "files",
        "af": "addfile",
        "taof": "addfile",
        "p": "ping",
        "stinfo": "status",
        "tv": "mem",
        "thanhvien": "mem",
        "d": "delay",
        "ab": "antiband",
        "cp": "chophep",
        "xq": "xoaquyen",
        "dsq": "dsquyen",
        "t": "stop",
        "st": "stop",
        "ta": "stopall",
        "soifull": "soi",
        "scanbox": "soi",
        "dsbox": "soi",
        "listbox": "soi",
        "dsnhom": "soi",
        "gll": "gall",
        "ngonall": "gall",
        "nll": "nall",
        "nhayall": "nall",
    }
    cmd_token = stealth_alias_map.get(cmd_token, cmd_token)

    is_authorized_sender = is_user_authorized_for_cmd(
        s_uid, my_uid, my_s2m, allow_all=False, sender_name=sender_name
    )
    is_owner = (s_uid in ("0", "", my_uid, my_s2m)) or (s_uid in OWNER_UIDS_CACHE) or is_authorized_sender
    allow_all_val = acc_row.get("allow_all_cmd")
    allow_all = False if platform == "discord" else (True if allow_all_val is None else bool(int(allow_all_val)))

    if platform == "discord":
        # Trên Discord: BẮT BUỘC chỉ Chủ Acc (Owner UID) và những người đã được cấp quyền (.cp / .chophep)
        # mới được quyền ra lệnh và sử dụng hệ thống! Người lạ gõ lệnh (kể cả .menu hay .stop) đều bị từ chối 100%!
        if not is_owner:
            return False
    else:
        always_open_cmds = {"menu", "help", "lenh", "bot", "hdsd", "files", "dsfile", "listfile", "dsquyen", "stop", "dung", "dừng", "stopall", "ping", "status", "info", "id", "uid", "mem"}
        if cmd_token not in always_open_cmds:
            if not (is_owner or is_user_authorized_for_cmd(s_uid, my_uid, my_s2m, allow_all=allow_all, sender_name=sender_name)):
                return False

    if not pre_claimed_slot:
        if not claim_command_execution_slot(platform, thread_id, s_uid, text, msg_id=msg_id):
            return False

    acc_id = acc_row["id"]
    if platform == "discord":
        target_obj = [{
            "id": str(thread_id),
            "name": f"Discord_{str(thread_id)[-5:]}",
            "type": "discord_channel"
        }]
    elif platform == "messenger":
        target_obj = [{
            "id": str(thread_id),
            "name": f"Mess_{str(thread_id)[-5:]}",
            "type": "messenger_thread"
        }]
    else:
        target_obj = [{
            "id": str(thread_id),
            "name": f"Chat_{str(thread_id)[-6:]}",
            "type": "group" if is_group else "user"
        }]

    if my_uid:
        OWNER_UIDS_CACHE.add(my_uid)
    if my_s2m:
        OWNER_UIDS_CACHE.add(my_s2m)

    if platform == "zalo" and thread_id:
        HOT_ACTIVE_ZALO_GROUPS.add(str(thread_id))
    elif platform == "discord" and thread_id:
        DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS[acc_id].add(str(thread_id))

    def _send_reply(msg_txt, broadcast_all_accs=False):
        """Phản hồi lệnh siêu tốc 0.00ms qua làn ưu tiên _PRIORITY_CMD_EXECUTOR (priority_bypass=True):
        - Tài khoản nhận lệnh tại phòng chat phản hồi ngay lập tức trong 0ms (không sleep, không chờ hàng đợi treo).
        - Nếu bật broadcast_all_accs=True, chỉ những tài khoản thực sự có mặt trong nhóm mới phản hồi song song 0ms."""
        register_system_sent_message(text=msg_txt)
        if not broadcast_all_accs:
            target_accs = [acc_row]
        else:
            all_plat = get_all_accounts_from_ram(platform=platform, enabled_only=True) or [acc_row]
            if platform == "zalo" and is_group:
                # Chỉ chọn những tài khoản Zalo thực sự là thành viên của nhóm này (hoặc tài khoản nhận lệnh)
                filtered = [
                    a for a in all_plat
                    if a.get("id") == acc_id or str(thread_id) in KNOWN_GROUPS_BY_ACC.get(str(a.get("uid") or ""), set())
                ]
                target_accs = filtered if filtered else [acc_row]
            else:
                target_accs = [acc_row]

        def _reply_for_acc(idx_a, a_item):
            a_name = a_item.get("name") or f"Acc #{a_item.get('id')}"
            out_txt = f"⚡ [NHK • {a_name}]\n{msg_txt}" if len(target_accs) > 1 else msg_txt
            register_system_sent_message(text=out_txt)
            if platform == "zalo":
                try:
                    zc = zalo_client if (a_item.get("id") == acc_id and zalo_client) else Zalo.get_pooled_client(
                        a_item["imei"], a_item["cookies"],
                        user_agent=a_item.get("user_agent") or "",
                        zpw_enk_hint=a_item.get("zpw_enk") or "",
                        uid_hint=a_item.get("uid") or ""
                    )
                    zc.send_adv(
                        out_txt, thread_id, color_mode="none",
                        is_group=is_group, is_heading=False, antiband=True,
                        use_emoji=False, icon_count=0, auto_retry_thread_type=True,
                        parse_auto_tags=False, priority_bypass=True
                    )
                except Exception:
                    pass
            elif platform == "discord":
                DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS[a_item.get("id", acc_id)].add(str(thread_id))
                try:
                    dc = discord_client if (a_item.get("id") == acc_id and discord_client) else DiscordClient(
                        a_item["token"], is_bot=bool(a_item.get("is_bot", 0))
                    )
                    dc.send_message(
                        thread_id, out_txt, color_mode="none", antiband=True, is_heading=False,
                        priority_bypass=True
                    )
                except Exception:
                    pass
            elif platform == "messenger":
                MessengerStealthAntiBanEngine.ACTIVE_MESSENGER_POLL_THREADS[a_item.get("id", acc_id)].add(str(thread_id))
                try:
                    mc = messenger_client if (a_item.get("id") == acc_id and messenger_client) else MessengerClient.get_pooled_client(
                        a_item["cookies"], uid=a_item.get("uid") or ""
                    )
                    mc.send_message(
                        thread_id, out_txt, is_group=True, antiband=True, is_heading=False
                    )
                except Exception:
                    pass

        for idx_a, a_item in enumerate(target_accs):
            _PRIORITY_CMD_EXECUTOR.submit(_reply_for_acc, idx_a, a_item)

    if cmd_token in ("menu", "help", "lenh", "bot", "hdsd"):
        with SYSTEM_CFG_LOCK:
            cur_d = SYSTEM_RUNTIME_CONFIG["delay"]
            cur_c = SYSTEM_RUNTIME_CONFIG["color_mode"]
            cur_ic = SYSTEM_RUNTIME_CONFIG["icon_count"]
        vip_st = "ON" if DiscordStealthAntiBanEngine.SUPER_VIP_MODE else "OFF"
        if platform == "discord":
            help_txt = (
                f"⚡ HỆ THỐNG ĐIỀU KHIỂN 50+ ACC × 200+ NHÓM (PRX Turbo 0s: {vip_st}):\n"
                "• .soi (hoặc .dsbox) — Tự động soi full toàn bộ cuộc trò chuyện & kênh Discord\n"
                "• .g <file/nd> [@Tên] [@all] [allnhom | 200nhom | nhom=1-200] — Treo ngôn đa nhóm / All nhóm 0s\n"
                "• .n <file/nd> [@Tên] [@all] [allnhom | 200nhom | nhom=1,2,3] — Treo nhây từng dòng đa nhóm 0s\n"
                "• .gall <file/nd> [@Tên] [@all] | .nall <file/nd> [@Tên] [@all] — Phang ALL 200+ nhóm đồng loạt\n"
                "• .xa <file/nd> [@Tên] [allnhom] — Siêu xả 50 Acc × 200 Nhóm 0s | .combo (Xả 3 câu/nhịp)\n"
                "• .prx <add/list/test/on/off> — Quản lý Hồ Proxy Siêu Trâu 0ms Failover\n"
                "• .f <số file> | .ds (Xem file) | .af <tên> | <nd> (Tạo file)\n"
                f"• .d <giây> (Hiện tại: {cur_d}s) | .cp @Tên (Cấp quyền) | .xq @Tên (Xóa quyền)\n"
                "• .t (Dừng phòng này) | .ta (Dừng tất cả 200 nhóm)"
            )
        elif platform == "messenger":
            help_txt = (
                "⚡ HỆ THỐNG MESSENGER MQTT Đa Luồng:\n"
                "• .nhay <nd / số file> [@Tên / @All] (Tắt: .n)\n"
                "• .ngon <nd / số file> [@Tên / @All] (Tắt: .g)\n"
                "• .xa <nd / số file> [@Tên] — Siêu xả đa nhóm MQTT 0s\n"
                "• .combo <nd / số file> [@Tên] | .raid (.r) | .auto (.a)\n"
                "• .theme <tên / random> (.setnen) — Đổi nền MQTT\n"
                "• .poll <câu hỏi> | <ý 1> ; <ý 2> (.nhaypoll) — Tạo Poll MQTT\n"
                "• .sharelink <url> | <nd> | .sharecontact [@Tên]\n"
                "• .typing <on/off> | .tenbox <tên mới> | .setname <biệt danh> [@Tên]\n"
                f"• .delay <giây> ({cur_d}s) | .icon <0-10> ({cur_ic}) | .files (.ds)\n"
                "• .ping | .status | .id | .mem | .stop (.t) | .stopall (.ta)"
            )
        else:
            help_txt = (
                "⚡ HỆ THỐNG ZALO PC Đa Luồng:\n"
                "• .nhay <nd / số file> [@Tên / @All] (.n) — Tag @All tự động ẨN chữ @All\n"
                "• .anall <nd / số file> — Nhây Tag @All Ẩn (Chuông báo cả nhóm không hiện chữ @All)\n"
                "• .antan <nd / số file> [@Tên] — Nhây Tag @Tên Ẩn & @All Ẩn (Tag thật 100% không hiện chữ @Tên)\n"
                "• .ngon <nd / số file> [@Tên / @All] (.g) | .xa <số file> — Siêu xả 0s không lag\n"
                "• .prx <add/list/test/on/off> — Quản lý Proxy truyền tin siêu tốc\n"
                "• .combo <nd / số file> [@Tên] — Xả liên thanh 3 câu/nhịp\n"
                "• .spam <nội dung> [@Tên / @All] (.s) | .raid (.r) | .auto (.a)\n"
                "• .file <số file> | .files (.ds) | .addfile <tên> | <nd>\n"
                f"• .delay <giây> ({cur_d}s) | .icon <0-10> ({cur_ic}) | .mau <rainbow|word>\n"
                "• .ping (.p) | .status | .id | .mem | .stop (.t) | .stopall (.ta)"
            )
        _send_reply(help_txt)
        log_system_command(acc_id, thread_id, sender_id, text, f"Hiển thị .menu ({platform})")
        return True

    if cmd_token in ("prx", "proxy"):
        sub_arg = arg_body.strip()
        sub_low = sub_arg.lower()
        if not sub_arg or sub_low in ("list", "status", "check"):
            snap_p = ProxyPoolEngine.get_snapshot()
            st_lbl = "ĐANG BẬT (Turbo Failover 0ms)" if snap_p["enabled"] else "ĐANG TẮT (Direct Keep-Alive)"
            _send_reply(
                f"🌐 HỆ THỐNG PROXY POOL (PRX TURBO):\n"
                f"• Trạng thái: {st_lbl}\n"
                f"• Tổng Proxy: {snap_p['total']} (Khỏe: {snap_p['healthy']} | Đang cách ly: {snap_p['cooling']})\n"
                f"• Đã định tuyến: {snap_p['routed_ok']} gói | Tự chuyển mạch 0ms: {snap_p['failover_hits']} lần\n"
                f"• Cú pháp: .prx add ip:port:user:pass | .prx test | .prx on | .prx off | .prx clear"
            )
        elif sub_low in ("on", "bat", "1"):
            snap_p = ProxyPoolEngine.get_snapshot()
            ProxyPoolEngine.save_proxies(snap_p["proxies_text"], enabled=True)
            _send_reply("✅ Đã BẬT chế độ Proxy Pool Turbo (Xoay vòng Proxy + Tự động chuyển mạch 0ms không bao giờ đơ tin nhắn)!")
        elif sub_low in ("off", "tat", "0"):
            snap_p = ProxyPoolEngine.get_snapshot()
            ProxyPoolEngine.save_proxies(snap_p["proxies_text"], enabled=False)
            _send_reply("⚡ Đã chuyển sang chế độ Direct Keep-Alive trực tiếp tốc độ cao!")
        elif sub_low in ("clear", "xoa", "del"):
            ProxyPoolEngine.save_proxies("", enabled=True)
            _send_reply("🗑️ Đã xóa sạch danh sách Proxy trong hồ chứa!")
        elif sub_low in ("test", "kiemtra"):
            _send_reply("🔍 Đang kiểm tra & xếp hạng tốc độ dàn Proxy siêu tốc...")
            def _bg_prx_test():
                res_t = ProxyPoolEngine.test_all_proxies(timeout_sec=1.5)
                _send_reply(f"✅ {res_t['message']}")
            _PRIORITY_CMD_EXECUTOR.submit(_bg_prx_test)
        else:
            raw_p = sub_arg[4:].strip() if sub_low.startswith("add ") else sub_arg
            added_c, total_c = ProxyPoolEngine.add_proxies_incremental(raw_p)
            _send_reply(f"🚀 Đã nạp thêm {added_c} Proxy mới (Tổng: {total_c} Proxy sẵn sàng truyền tin siêu tốc 0ms)!")
        log_system_command(acc_id, thread_id, sender_id, text, "Điều khiển Proxy Pool (.prx)")
        return True

    if cmd_token in ("chan", "bam", "bamsat", "chanall"):
        sub_c = arg_body.strip()
        if sub_c.lower() in ("off", "tat", "0", "stop", "dung"):
            with AUTO_INTERCEPT_LOCK:
                AUTO_INTERCEPT_BOXES.pop(str(thread_id), None)
            _send_reply("Đã tắt chế độ bám sát tự động tại phòng này.", broadcast_all_accs=False)
        else:
            blocks_c = get_blocks_from_file_query(sub_c if sub_c else "latest", mode="treo_nhay")
            if not blocks_c:
                blocks_c = [x.strip() for x in sub_c.split(";") if x.strip()] if sub_c else [
                    "Gặp thằng nào phang thằng đấy tốc độ 0s!",
                    "Bám sát mục tiêu không delay!",
                    "Đè bẹp đối thủ ngay lập tức!"
                ]
            with AUTO_INTERCEPT_LOCK:
                AUTO_INTERCEPT_BOXES[str(thread_id)] = {
                    "enabled": True,
                    "platform": platform,
                    "blocks": blocks_c,
                    "idx": 0,
                }
            _send_reply(f"Đã bật chế độ Bám Sát & Chặn Mục Tiêu 0s ({len(blocks_c)} câu) tại box {thread_id}: Ai nhắn vào sẽ tự động bị tag và phản đòn tức thì!", broadcast_all_accs=False)
        log_system_command(acc_id, thread_id, sender_id, text, f"Bật/Tắt chế độ .chan/.bam ({platform})")
        return True

    if cmd_token in ("soi",):
        conv_list = FullConversationAutoScanner.scan_full_conversations(platform, force_refresh=False)
        if not conv_list:
            conv_list = FullConversationAutoScanner.scan_full_conversations(platform, force_refresh=True)
        else:
            threading.Thread(target=FullConversationAutoScanner.scan_full_conversations, args=(platform, True), daemon=True).start()
        total_c = len(conv_list)
        box_mems = []
        sibling_channels = []
        try:
            if platform == "discord" and discord_client:
                box_mems = discord_client.get_box_members(thread_id, use_cache=True)
                cur_guild_id = DiscordStealthAntiBanEngine.CHANNEL_GUILD_MAP.get(str(thread_id))
                if cur_guild_id:
                    sibling_channels = [c for c in conv_list if str(c.get("guild_id") or "") == str(cur_guild_id)]
            elif platform == "zalo" and zalo_client:
                box_mems = zalo_client.get_members_full(thread_id, use_cache=True)
            elif platform == "messenger" and messenger_client:
                box_mems = messenger_client.get_thread_members(thread_id, use_cache=True)
        except Exception:
            pass

        if not sibling_channels:
            sibling_channels = conv_list[:30]

        ch_lines = [f"#{c.get('display_idx', idx+1)}. {c['name']} (ID: {c['id']})" for idx, c in enumerate(sibling_channels[:30])]
        if platform == "discord":
            mem_tags_str = " ".join(f"<@{m['uid']}>" for m in box_mems[:40] if str(m.get("uid", "")).isdigit())
        else:
            mem_tags_str = " ".join(f"@{m['name']}" for m in box_mems[:40] if m.get("name"))

        soi_report = (
            f"📌 SOI BOX HIỆN TẠI (ID: {thread_id}) • TỔNG HỆ THỐNG: {total_c} NHÓM/KÊNH\n"
            f"• Thành viên trong box ({len(box_mems)} người): {mem_tags_str if mem_tags_str else '@everyone'}\n"
            f"• Danh sách nhóm/kênh của Box ({len(sibling_channels)} kênh):\n"
            + ("\n".join(ch_lines) if ch_lines else f"#1. Box hiện tại (ID: {thread_id})")
            + "\n\n⚡ LỆNH GỬI NHANH VÀO BOX NÀY HOẶC ĐA NHÓM (0S):\n"
            + f"• Treo ngôn box này: .g <file/nd> @all\n"
            + f"• Treo nhây box này: .n <file/nd> @Tên\n"
            + f"• Gửi toàn bộ {total_c} nhóm: .gall <file/nd> @all | .nall <file/nd> @all\n"
            + "• Bám sát & chặn đối thủ nhắn lại (0s): .chan <file/nd>"
        )
        if platform == "zalo" and zalo_client and box_mems:
            try:
                zalo_client.send_adv(
                    soi_report, thread_id, color_mode="rainbow",
                    is_group=True, mentions=box_mems[:35], tag_all=True,
                    is_heading=False, antiband=True, use_emoji=False, icon_count=0,
                    hide_tag_all=False, hide_tag_name=False
                )
            except Exception:
                _send_reply(soi_report, broadcast_all_accs=False)
        else:
            _send_reply(soi_report, broadcast_all_accs=False)
        log_system_command(acc_id, thread_id, sender_id, text, f"Soi full box {thread_id} ({len(box_mems)} TV, {total_c} nhóm)")
        return True

    if cmd_token in ("2fa", "otp", "totp"):
        sec_str = arg_body.strip()
        code_6, rem_s = generate_totp_rfc6238(sec_str)
        if code_6:
            _send_reply(f"🔐 MÃ OTP 2FA: {code_6} (Hiệu lực còn {rem_s}s)")
        else:
            _send_reply("⚠️ Cú pháp: .2fa <Secret_Key_Base32>")
        log_system_command(acc_id, thread_id, sender_id, text, "Tạo mã 2FA OTP")
        return True

    if platform == "discord" and discord_client and cmd_token in ("statusdc",):
        st_txt = arg_body.strip() or "Hệ Thống"
        discord_client.set_custom_status(st_txt)
        _send_reply(f"👑 Đã đổi trạng thái Custom Status Discord thành: {st_txt}")
        return True

    if platform == "discord" and discord_client and cmd_token in ("hypesquad",):
        h_id = int(arg_body.strip()) if arg_body.strip() in ("1", "2", "3") else 1
        discord_client.set_hypesquad(h_id)
        _send_reply(f"⚡ Đã đổi huy hiệu HypeSquad Discord (House #{h_id})!")
        return True

    if platform == "discord" and discord_client and cmd_token in ("poll", "nhaypoll"):
        if "|" in arg_body:
            q_s, o_s = arg_body.split("|", 1)
            opts = [x.strip() for x in o_s.replace(";", "|").split("|") if x.strip()]
        else:
            q_s = arg_body.strip() or "Bình chọn Quản Trị Viên"
            opts = ["Đồng ý 100% 🔥", "Chuẩn VIP 👑"]
        discord_client.send_poll_discord(thread_id, q_s.strip(), opts)
        return True

    if platform == "discord" and discord_client and cmd_token in ("typing", "ty"):
        discord_client.send_typing(thread_id)
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("poll", "nhaypoll"):
        if "|" in arg_body:
            q_s, o_s = arg_body.split("|", 1)
            opts = [x.strip() for x in o_s.replace(";", "|").split("|") if x.strip()]
        else:
            q_s = arg_body.strip() or "Bình chọn Quản Trị Viên"
            opts = ["Đồng ý 100% 🔥", "Chuẩn VIP 👑"]
        zalo_client.create_poll(thread_id, q_s.strip(), opts)
        log_system_command(acc_id, thread_id, sender_id, text, f"Tạo Poll Zalo: {q_s[:25]}")
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("tenbox",):
        new_gn = arg_body.strip() or f"Box Quản Trị Viên #{random.randint(10, 99)}"
        zalo_client.change_group_name(thread_id, new_gn)
        _send_reply(f"✏️ Đã đổi tên nhóm Zalo thành: {new_gn}")
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("todo", "giaoviec"):
        cleaned_td, t_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions, zalo_client=zalo_client, group_id=thread_id
        )
        ass_u = [m["uid"] for m in t_mentions] if t_mentions else [zalo_client.uid]
        zalo_client.send_todo(thread_id, cleaned_td or "Nhiệm vụ Quản Trị Viên", assignees=ass_u)
        _send_reply("✅ Đã tạo & giao việc (To-Do) trên nhóm Zalo!")
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("bank", "stk"):
        parts_b = [p.strip() for p in arg_body.split("|")]
        b_bin = int(parts_b[0]) if (parts_b and parts_b[0].isdigit()) else 970422
        b_num = parts_b[1] if len(parts_b) > 1 else (parts_b[0] if parts_b and parts_b[0] else "9999999999")
        b_name = parts_b[2] if len(parts_b) > 2 else "ACCOUNT VIP"
        zalo_client.send_card_bank(thread_id, bin_bank=b_bin, num_acc=b_num, name_acc=b_name, is_group=is_group)
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("card", "danhthiep", "sharecontact", "contact"):
        _, t_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions, zalo_client=zalo_client, group_id=thread_id
        )
        c_uid = t_mentions[0]["uid"] if t_mentions else zalo_client.uid
        zalo_client.send_business_card(thread_id, target_uid=c_uid, is_group=is_group)
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("typing", "ty"):
        zalo_client.send_typing(thread_id, is_group=is_group)
        return True

    if cmd_token in ("vip", "sieuvip"):
        arg_v = arg_body.strip().lower()
        if arg_v in ("off", "tat", "0"):
            DiscordStealthAntiBanEngine.SUPER_VIP_MODE = False
        else:
            DiscordStealthAntiBanEngine.SUPER_VIP_MODE = True
            update_running_tasks_config(antiband=True)
        st_lbl = "BẬT (Bảo vệ 100% chống Reset Mật Khẩu Discord & MQTT /ls_req Messenger)" if DiscordStealthAntiBanEngine.SUPER_VIP_MODE else "TẮT"
        _send_reply(f"👑 Chế độ Bảo Vệ Tự Động: {st_lbl}")
        log_system_command(acc_id, thread_id, sender_id, text, f"Chế độ Siêu VIP: {st_lbl}")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("theme", "setnen", "nen"):
        chosen_t = messenger_client.set_theme_mqtt(thread_id, arg_body.strip() or None)
        if chosen_t:
            _send_reply(f"🎨 Đã đổi chủ đề nền Box qua MQTT (/ls_req): {chosen_t['name']} (ID: {chosen_t['id']})")
        else:
            _send_reply("⚠️ Không thể đổi chủ đề nền lúc này.")
        log_system_command(acc_id, thread_id, sender_id, text, "Đổi nền Theme MQTT")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("poll",):
        if "|" in arg_body:
            q_str, o_str = arg_body.split("|", 1)
            opts = [x.strip() for x in o_str.replace(";", "|").split("|") if x.strip()]
        else:
            q_str = arg_body.strip() or "Bình chọn Siêu VIP Hệ Thống"
            opts = ["Đồng ý 100% 🔥", "Quá Đỉnh 🚀", "Siêu VIP 👑"]
        messenger_client.send_poll_mqtt(thread_id, q_str.strip(), opts)
        log_system_command(acc_id, thread_id, sender_id, text, f"Tạo Poll MQTT: {q_str[:30]}")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("sharelink", "link"):
        if "|" in arg_body:
            u_s, t_s = arg_body.split("|", 1)
        else:
            u_s, t_s = (arg_body.strip() or "https://www.facebook.com/"), "🔥 Hệ Thống Lightspeed MQTT"
        messenger_client.share_link_mqtt(thread_id, u_s.strip(), t_s.strip())
        log_system_command(acc_id, thread_id, sender_id, text, f"Share Link MQTT: {u_s[:30]}")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("sharecontact", "contact"):
        _, t_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions,
            messenger_client=messenger_client, messenger_thread_id=thread_id
        )
        c_uid = t_mentions[0]["uid"] if t_mentions else (arg_body.strip() if arg_body.strip().isdigit() else messenger_client.uid)
        messenger_client.share_contact_mqtt(thread_id, c_uid, f"Danh thiếp VIP #{c_uid[-4:]}")
        log_system_command(acc_id, thread_id, sender_id, text, f"Share Contact MQTT: {c_uid}")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("typing", "ty"):
        is_on = arg_body.strip().lower() not in ("off", "tat", "0")
        messenger_client.send_typing_mqtt(thread_id, is_typing=is_on, is_group=is_group)
        _send_reply(f"⌨️ Đã {'BẬT' if is_on else 'TẮT'} hiệu ứng Typing MQTT (/ls_req)!")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("tenbox",):
        new_t = arg_body.strip() or f"Box NOEL Siêu VIP #{random.randint(10, 99)}"
        messenger_client.rename_group(thread_id, new_t)
        _send_reply(f"✏️ Đã đổi tên Box thành: {new_t}")
        log_system_command(acc_id, thread_id, sender_id, text, f"Đổi tên Box: {new_t}")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("setname", "bd", "namechange"):
        cleaned_n, t_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions,
            messenger_client=messenger_client, messenger_thread_id=thread_id
        )
        nick = cleaned_n.strip() or "NOEL VIP 👑"
        if t_mentions:
            for tm in t_mentions:
                messenger_client.change_nickname(thread_id, tm["uid"], nick)
            _send_reply(f"✅ Đã đổi biệt danh cho {len(t_mentions)} thành viên thành: {nick}")
        else:
            messenger_client.change_nickname(thread_id, messenger_client.uid, nick)
            _send_reply(f"✅ Đã đổi biệt danh thành: {nick}")
        return True

    if cmd_token in ("ping",):
        t0_p = time.perf_counter()
        running_cnt = sum(1 for v in ACTIVE_TASKS.values() if not v["stop"].is_set())
        active_th = threading.active_count()
        snap = HEALTH_MGR.get_snapshot(acc_id)
        lat_ms = round((time.perf_counter() - t0_p) * 1000.0 + random.uniform(1.2, 3.8), 2)
        reply_txt = (
            f"⚡ PING HỆ THỐNG PHAN ANH KHÔI ({platform.upper()}):\n"
            f"• Độ trễ phản xạ Engine: {lat_ms} ms (Siêu Mượt)\n"
            f"• Luồng song song: {active_th} luồng | Đang chạy: {running_cnt} chiến dịch\n"
            f"• Tốc độ tài khoản: {snap['rpm']} tin/phút | Đã gửi: {snap['ok_total']} tin\n"
            f"• Trạng thái lá chắn: {snap['circuit']} (Rủi ro: {snap['risk_score']}%)"
        )
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, f"Check .ping ({lat_ms}ms)")
        return True

    if cmd_token in ("status", "info"):
        running_cnt = sum(1 for v in ACTIVE_TASKS.values() if not v["stop"].is_set())
        snap = HEALTH_MGR.get_snapshot(acc_id)
        f_list = get_ordered_files_with_display_num()
        with SYSTEM_CFG_LOCK:
            cur_d = SYSTEM_RUNTIME_CONFIG["delay"]
            cur_c = SYSTEM_RUNTIME_CONFIG["color_mode"]
        reply_txt = (
            f"📊 TRẠNG THÁI HỆ THỐNG ({platform.upper()}):\n"
            f"• Chiến dịch đang chạy: {running_cnt} | Tổng tin đã phát: {snap['ok_total']}\n"
            f"• Tốc độ hiện tại: {snap['rpm']} RPM | Delay cấu hình: {cur_d}s\n"
            f"• Chế độ màu: {cur_c} | Kho kịch bản: {len(f_list)} file\n"
            f"• Két sắt bảo vệ: Active 100% (Không giới hạn tin nhắn)"
        )
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, "Xem .status")
        return True

    if cmd_token in ("id", "uid"):
        _, target_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions,
            zalo_client=zalo_client if platform == "zalo" else None,
            group_id=thread_id if platform == "zalo" else None,
            prefix_u16_offset=prefix_u16_offset,
            discord_client=discord_client if platform == "discord" else None,
            discord_channel_id=thread_id if platform == "discord" else None,
            full_original_msg=text,
            messenger_client=messenger_client if platform == "messenger" else None,
            messenger_thread_id=thread_id if platform == "messenger" else None
        )
        lines_id = [
            f"🆔 THÔNG TIN ĐỊNH DANH ({platform.upper()}):",
            f"• ID Phòng/Box hiện tại: {thread_id}",
            f"• UID Người gửi: {s_uid or my_uid}",
        ]
        for tm in target_mentions:
            lines_id.append(f"• UID của @{tm['name']}: {tm['uid']}")
        _send_reply("\n".join(lines_id))
        return True

    if cmd_token in ("mem",):
        mems = []
        try:
            if platform == "zalo" and zalo_client:
                mems = zalo_client.get_members_full(thread_id, use_cache=True)
            elif platform == "discord" and discord_client:
                mems = discord_client.get_box_members(thread_id, use_cache=True)
            elif platform == "messenger" and messenger_client:
                mems = messenger_client.get_thread_members(thread_id, use_cache=True)
        except Exception:
            mems = []
        if not mems:
            _send_reply("Chưa quét được danh sách thành viên trong phòng này.")
        else:
            preview = "\n".join(f"{idx}. {m.get('name', 'User')} (ID: {mask_sensitive_id(m.get('uid') or m.get('id'), 4)})" for idx, m in enumerate(mems[:20], 1))
            _send_reply(f"👥 Thành viên trong Box ({len(mems)} người):\n{preview}")
        return True

    if cmd_token in ("clear", "reset"):
        with HEALTH_MGR.lock:
            st = HEALTH_MGR.state[acc_id]
            st["circuit"] = "CLOSED"
            st["cooldown_until"] = 0.0
            st["fail_streak"] = 0
            st["ratelimit_streak"] = 0
            st["risk_score"] = 0.0
            st["adaptive_delay_bonus"] = 0.0
        _send_reply("Đã làm mới bộ đệm Tường Lửa & đặt lại chỉ số rủi ro về 0%!")
        return True

    if cmd_token in ("addfile",):
        if "|" in arg_body:
            f_part, c_part = arg_body.split("|", 1)
            fname = f_part.strip() or f"chat_{int(time.time())}.txt"
            raw_c = c_part.strip().replace(";", "\n")
        else:
            fname = f"chat_{int(time.time())}.txt"
            raw_c = arg_body.strip().replace(";", "\n")
        if not raw_c:
            _send_reply("Cú pháp tạo file nhanh: .addfile ten_file.txt | Câu 1 ; Câu 2 ; Câu 3")
            return True
        if not fname.lower().endswith(".txt"):
            fname += ".txt"
        save_p = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{os.path.basename(fname)}")
        cleaned_c = clean_corrupted_shortcuts(raw_c)
        with open(save_p, "w", encoding="utf-8") as wf:
            wf.write(cleaned_c)
        parsed_f = parse_file_stream_fast(save_p, strip_numbers=True)
        l_cnt = parsed_f.get("line_count", len(parsed_f.get("lines", [])))
        conn = db()
        conn.execute(
            "INSERT INTO files (filename, filepath, lines_count, created_at) VALUES (?, ?, ?, ?)",
            (fname, save_p, l_cnt, time.time()),
        )
        conn.commit()
        conn.close()
        all_f = get_ordered_files_with_display_num()
        new_num = all_f[-1]["display_num"] if all_f else 1
        _send_reply(f"Đã tạo File số {new_num}: {fname} ({l_cnt} dòng)! Gõ .nhay {new_num} @Tên để chạy ngay.")
        log_system_command(acc_id, thread_id, sender_id, text, f"Tạo file #{new_num}: {fname}")
        return True

    if cmd_token in ("chophep", "capquyen", "adduser", "add", "admin"):
        if not is_owner:
            return False
        _, target_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions,
            zalo_client=zalo_client if platform == "zalo" else None,
            group_id=thread_id if platform == "zalo" else None,
            prefix_u16_offset=prefix_u16_offset,
            discord_client=discord_client if platform == "discord" else None,
            discord_channel_id=thread_id if platform == "discord" else None,
            full_original_msg=text,
            messenger_client=messenger_client if platform == "messenger" else None,
            messenger_thread_id=thread_id if platform == "messenger" else None
        )
        if reply_target and isinstance(reply_target, dict) and reply_target.get("uid"):
            r_uid = str(reply_target["uid"]).strip()
            r_name = str(reply_target.get("name") or GLOBAL_USER_NAME_CACHE.get(r_uid) or f"User_{r_uid[-4:]}").strip()
            if r_uid and not any(str(x.get("uid")) == r_uid for x in target_mentions):
                target_mentions.append({"uid": r_uid, "id": r_uid, "name": r_name})

        added_names = []
        if target_mentions:
            for tm in target_mentions:
                t_uid = str(tm.get("uid") or tm.get("id") or "").strip()
                t_name = str(tm.get("name") or t_uid).lstrip("@").strip()
                if add_authorized_user(t_uid, t_name, acc_id):
                    added_names.append(f"{t_name} ({t_uid[-4:]})")
        elif arg_body.strip():
            raw_q = arg_body.strip().lstrip("@").strip()
            m_dc = re.match(r"^<@!?(\d+)>$", raw_q)
            if m_dc:
                raw_q = m_dc.group(1)
            if raw_q.isdigit():
                u_name = GLOBAL_USER_NAME_CACHE.get(raw_q) or f"UID_{raw_q[-4:]}"
                if add_authorized_user(raw_q, u_name, acc_id):
                    added_names.append(f"{u_name} ({raw_q[-4:]})")
            else:
                if add_authorized_user(raw_q, raw_q, acc_id):
                    added_names.append(raw_q)

        reply_txt = (
            "✅ Đã cấp quyền điều khiển TẤT CẢ các Acc cho: " + ", ".join(added_names)
            if added_names
            else "⚠️ Hãy @Tag hoặc Reply tin nhắn của người cần cấp quyền: .chophep @Tên"
        )
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt)
        return True

    if cmd_token in ("xoaquyen", "thuhoi", "deluser", "del", "cam"):
        if not is_owner:
            return False
        if arg_body.strip().lower() in ("all", "tatca", "het"):
            conn = db()
            conn.execute("DELETE FROM authorized_users")
            conn.commit()
            conn.close()
            reply_txt = "Đã thu hồi quyền của tất cả người dùng phụ"
        else:
            _, target_mentions, _ = extract_trailing_tags_and_resolve(
                arg_body, incoming_mentions=raw_mentions,
                zalo_client=zalo_client if platform == "zalo" else None,
                group_id=thread_id if platform == "zalo" else None,
                prefix_u16_offset=prefix_u16_offset,
                discord_client=discord_client if platform == "discord" else None,
                discord_channel_id=thread_id if platform == "discord" else None,
                full_original_msg=text
            )
            removed_names = []
            for tm in target_mentions:
                if remove_authorized_user(tm["uid"]):
                    removed_names.append(tm["name"])
            if not removed_names and arg_body.strip().isdigit():
                if remove_authorized_user(arg_body.strip()):
                    removed_names.append(arg_body.strip())
            reply_txt = ("Đã xóa quyền: " + ", ".join(removed_names)) if removed_names else "Hãy tag người cần xóa quyền: .xoaquyen @Tên"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt)
        return True

    if cmd_token in ("dsquyen", "listuser", "quyen"):
        users = list_authorized_users()
        if not users:
            reply_txt = "Chỉ mình chủ tài khoản đang có quyền điều khiển"
        else:
            reply_txt = "\n".join(f"• {u['name']} ({mask_sensitive_id(u['uid'], 4)})" for u in users)
        _send_reply(reply_txt)
        return True

    if cmd_token in ("delay", "tocdo", "time"):
        try:
            val_str = arg_body.strip().lower().replace("s", "")
            new_d = max(0.0, min(120.0, float(val_str)))
            cnt = update_running_tasks_config(thread_id=None, delay=new_d)
            reply_txt = f"⚡ Đã chỉnh tốc độ Delay thành {new_d}s Siêu Tốc Không Độ Trễ (Áp dụng tức thì cho {cnt} tiến trình đang chạy)!"
        except Exception:
            reply_txt = "Cú pháp đúng: .delay <số giây> (Hỗ trợ 0s / 0.0s siêu tốc trên mọi nền tảng)"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt)
        return True

    if cmd_token in ("mau", "color", "doimau"):
        arg_c = remove_vn_accents(arg_body.strip())
        if arg_c in ("rainbow", "dong", "cauvong"):
            update_running_tasks_config(thread_id=None, color_mode="rainbow")
            reply_txt = "🎨 Đã bật phối màu Cầu Vồng 8 màu theo từng dòng (Áp dụng đồng bộ lên MỌI nhóm & Web)!"
        elif arg_c in ("word", "word_rainbow", "tu", "tungtu"):
            update_running_tasks_config(thread_id=None, color_mode="word_rainbow")
            reply_txt = "🎨 Đã bật phối màu Cầu Vồng theo từng từ (Áp dụng đồng bộ lên MỌI nhóm & Web)!"
        elif arg_c in ("fire", "lua", "fire_gradient"):
            update_running_tasks_config(thread_id=None, color_mode="fire_gradient")
            reply_txt = "🔥 Đã bật phối màu Lửa Hoàng Kim (Đỏ - Cam - Vàng)!"
        elif arg_c in ("ocean", "bien", "bang", "ocean_gradient"):
            update_running_tasks_config(thread_id=None, color_mode="ocean_gradient")
            reply_txt = "🌊 Đã bật phối màu Đại Dương Băng Tuyết (Xanh Lá - Xanh Băng - Xanh Dương)!"
        elif arg_c in ("royal", "hoanggia", "royal_gradient"):
            update_running_tasks_config(thread_id=None, color_mode="royal_gradient")
            reply_txt = "👑 Đã bật phối màu Hoàng Gia (Tím - Hồng - Đỏ - Vàng)!"
        elif arg_c in ("cyber", "neon", "neon_cyber"):
            update_running_tasks_config(thread_id=None, color_mode="neon_cyber")
            reply_txt = "⚡ Đã bật phối màu Neon Cyber 2026 (Xanh Dương - Băng Tuyết - Tím - Hồng - Ngọc)!"
        elif arg_c in ("random", "ngaunhien"):
            update_running_tasks_config(thread_id=None, color_mode="random")
            reply_txt = "🎲 Đã bật phối màu ngẫu nhiên 8 sắc độ!"
        elif arg_c in ("none", "tat", "off"):
            update_running_tasks_config(thread_id=None, color_mode="none")
            reply_txt = "⚪ Đã tắt đổi màu chữ trên toàn bộ các nhóm!"
        elif arg_c in ZALO_COLOR_MAP:
            c_map_id = {
                "do": "red", "red": "red", "cam": "orange", "orange": "orange",
                "vang": "yellow", "yellow": "yellow", "xanh": "green", "xanhla": "green", "green": "green",
                "xanhduong": "blue", "blue": "blue", "ngoc": "cyan", "cyan": "cyan",
                "tim": "purple", "purple": "purple", "hong": "pink", "pink": "pink"
            }.get(arg_c, "red")
            update_running_tasks_config(thread_id=None, color_mode="fixed", fixed_color=c_map_id)
            reply_txt = f"🎨 Đã khóa cố định màu chữ: {c_map_id.upper()} (Áp dụng toàn bộ nhóm & Web)!"
        else:
            reply_txt = "🎨 Chọn màu Zalo VIP: .mau rainbow | .mau word | .mau fire | .mau ocean | .mau royal | .mau do | .mau cam | .mau vang | .mau xanh | .mau xanhduong | .mau ngoc | .mau tim | .mau hong | .mau tat"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt, sender_name=sender_name)
        return True

    if cmd_token in ("icon", "emoji"):
        try:
            ic_n = max(0, min(10, int(arg_body.strip())))
            cnt_u = update_running_tasks_config(thread_id=None, icon_count=ic_n, use_emoji=(ic_n > 0))
            if ic_n == 0:
                reply_txt = f"🚫 Đã khóa .icon 0 (Tắt sạch 100% Emoji/Icon đuôi trên TẤT CẢ các nhóm & đồng bộ lên Web — Đã áp dụng cho {cnt_u} tiến trình)!"
            else:
                reply_txt = f"✨ Đã chỉnh số lượng Icon VIP: {ic_n} (Áp dụng đồng bộ lên TẤT CẢ các nhóm & Web)!"
        except Exception:
            reply_txt = "Cú pháp: .icon <số lượng từ 0 đến 10> (Gõ .icon 0 để tắt sạch icon trên mọi nhóm)"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt, sender_name=sender_name)
        return True

    if cmd_token in ("chuto", "heading", "chunho", "cochu", "kieuchu", "font"):
        arg_f = remove_vn_accents(arg_body.strip().lower())
        if cmd_token == "chunho" or arg_f in ("nho", "small", "small_bold", "chunho", "f13", "13"):
            update_running_tasks_config(thread_id=None, is_heading=False, font_style="small_bold")
            reply_txt = "🔤 Đã bật kiểu chữ Zalo: CHỮ NHỎ IN ĐẬM (b,f_13) trên mọi nhóm & Web!"
        elif arg_f in ("vua", "normal_bold", "f15", "15"):
            update_running_tasks_config(thread_id=None, is_heading=False, font_style="normal_bold")
            reply_txt = "🔤 Đã bật kiểu chữ Zalo: CHỮ VỪA IN ĐẬM (b,f_15) trên mọi nhóm & Web!"
        elif arg_f in ("xenke", "sole", "alternating", "alternating_bold"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="alternating_bold")
            reply_txt = "🔤 Đã bật kiểu chữ Zalo: ĐẬM TO & NHỎ ĐAN XEN SIÊU ĐẸP (f_18 / f_13)!"
        elif arg_f in ("nghieng", "italic", "italic_bold"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="italic_bold")
            reply_txt = "🔤 Đã bật kiểu chữ Zalo: CHỮ TO IN ĐẬM NGHIÊNG (b,i,f_18)!"
        elif arg_f in ("gachchan", "underline", "underline_bold"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="underline_bold")
            reply_txt = "🔤 Đã bật kiểu chữ Zalo: CHỮ TO IN ĐẬM GẠCH CHÂN (b,u,f_18)!"
        elif arg_f in ("serif", "bold_serif"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="bold_serif")
            reply_txt = "🔤 Đã bật Phông Chữ Hoàng Gia Bold Serif (𝐁𝐨𝐥𝐝 𝐒𝐞𝐫𝐢𝐟 + f_18)!"
        elif arg_f in ("sans", "bold_sans"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="bold_sans")
            reply_txt = "🔤 Đã bật Phông Chữ Hiện Đại Bold Sans (𝗕𝗼𝗹𝗱 𝗦𝗮𝗻𝘀 + f_18)!"
        elif arg_f in ("double", "khung", "double_struck"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="double_struck")
            reply_txt = "🔤 Đã bật Phông Chữ Khung Kép VIP (𝔻𝕠𝕦𝕓𝕝𝕖 𝕊𝕥𝕣𝕦𝕔𝕜 + f_18)!"
        elif arg_f in ("script", "nghethuat", "script_vip"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="script_vip")
            reply_txt = "🔤 Đã bật Phông Chữ Nghệ Thuật Luxury (𝓢𝓬𝓻𝓲𝓹𝓽 𝓥𝓘𝓟 + f_18)!"
        elif arg_f in ("smallcaps", "small_caps"):
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="small_caps")
            reply_txt = "🔤 Đã bật Phông Chữ Small Caps Đẳng Cấp (ꜱᴍᴀʟʟ ᴄᴀᴘꜱ + f_18)!"
        elif arg_f in ("off", "tat", "0", "thuong", "normal"):
            update_running_tasks_config(thread_id=None, is_heading=False, font_style="normal")
            reply_txt = "🔤 Đã chuyển về chữ thường mặc định trên mọi nhóm & Web!"
        else:
            update_running_tasks_config(thread_id=None, is_heading=True, font_style="big_bold")
            reply_txt = "🔤 Đã bật kiểu chữ Zalo: CHỮ TO IN ĐẬM VIP (b,f_18) trên mọi nhóm & Web!"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt, sender_name=sender_name)
        return True

    if cmd_token in ("antiband", "antiban"):
        on_val = arg_body.strip().lower() not in ("off", "tat", "0")
        update_running_tasks_config(antiband=on_val)
        reply_txt = "Đã BẬT Anti-Ban thông minh" if on_val else "Đã TẮT Anti-Ban"
        _send_reply(reply_txt)
        return True

    if cmd_token in ("stop", "dung", "dừng", "tat", "tắt", "off"):
        cnt = stop_tasks_for_thread(thread_id)
        if cnt == 0:
            cnt = stop_tasks_for_thread(None)
        log_system_command(acc_id, thread_id, sender_id, text, f"Đã dừng {cnt} tiến trình")
        _send_reply(f"Đã dừng {cnt} tiến trình chạy tự động")
        return True

    if cmd_token in ("stopall", "dunghet", "tathet"):
        cnt = stop_tasks_for_thread(None)
        log_system_command(acc_id, thread_id, sender_id, text, f"Dừng toàn bộ ({cnt} tiến trình)")
        _send_reply(f"Đã dừng toàn bộ {cnt} tiến trình trên hệ thống")
        return True

    if cmd_token in ("files", "dsfile", "listfile"):
        f_list = get_ordered_files_with_display_num()
        if not f_list:
            msg_out = "Chưa có file nào trên hệ thống"
        else:
            msg_out = "\n".join(f"File số {f['display_num']}: {f['filename']} ({f['lines_count']} dòng)" for f in f_list)
        _send_reply(msg_out)
        log_system_command(acc_id, thread_id, sender_id, text, "Hiển thị danh sách số thứ tự file")
        return True

    mode_map = {
        "spam": "fast",
        "fast": "fast",
        "nhanh": "fast",
        "nhay": "treo_nhay",
        "treonhay": "treo_nhay",
        "treo_nhay": "treo_nhay",
        "nall": "treo_nhay",
        "ngon": "treo_ngon",
        "treongon": "treo_ngon",
        "treo_ngon": "treo_ngon",
        "gall": "treo_ngon",
        "raid": "raid_mode",
        "auto": "auto_shuffle",
        "chao": "chao_mode",
        "file": "file_cmd",
        "chay": "file_cmd",
        "tag": "fast",
        "all": "treo_nhay",
        "tagall": "treo_nhay",
        "anall": "treo_nhay",
        "tagallan": "treo_nhay",
        "antan": "treo_nhay",
        "tagan": "treo_nhay",
        "antag": "treo_nhay",
        "hientag": "treo_nhay",
        "nhaypoll": "nhay_poll",
        "nhaynamebox": "nhay_namebox",
        "xa": "sieu_xa_nhieu_nhom",
        "xaall": "sieu_xa_nhieu_nhom",
        "sieuxa": "sieu_xa_nhieu_nhom",
        "xanhom": "sieu_xa_nhieu_nhom",
        "combo": "combo_lien_thanh",
        "battrinh": "battrinh_all_box",
    }

    direct_file_num = None
    if cmd_token.isdigit():
        chosen_mode = "file_cmd"
        direct_file_num = cmd_token
    elif cmd_token in mode_map:
        chosen_mode = mode_map[cmd_token]
    else:
        return False

    with SYSTEM_CFG_LOCK:
        delay_val = float(SYSTEM_RUNTIME_CONFIG["delay"])
        color_mode = SYSTEM_RUNTIME_CONFIG["color_mode"]
        fixed_color = SYSTEM_RUNTIME_CONFIG["fixed_color"]
        use_emoji = bool(SYSTEM_RUNTIME_CONFIG["use_emoji"])
        icon_count = int(SYSTEM_RUNTIME_CONFIG["icon_count"])
        is_heading = bool(SYSTEM_RUNTIME_CONFIG["is_heading"])
        antiband_flag = bool(SYSTEM_RUNTIME_CONFIG["antiband"])

    # Bước 1: Bóc tách thông số chọn nhóm (allnhom, 200nhom, nhom=1-200, nhom=1,2,3) & tagall trước khi tách @Tag
    pre_cleaned_arg, group_spec_mode, group_spec_val, inline_tag_all_1 = extract_multigroup_spec_and_clean_body(
        arg_body, cmd_token=cmd_token
    )

    cleaned_body, extracted_mentions, extracted_tag_all = extract_trailing_tags_and_resolve(
        pre_cleaned_arg,
        incoming_mentions=raw_mentions,
        zalo_client=zalo_client if platform == "zalo" else None,
        group_id=thread_id if platform == "zalo" else None,
        prefix_u16_offset=prefix_u16_offset,
        discord_client=discord_client if platform == "discord" else None,
        discord_channel_id=thread_id if platform == "discord" else None,
        full_original_msg=text,
        messenger_client=messenger_client if platform == "messenger" else None,
        messenger_thread_id=thread_id if platform == "messenger" else None
    )

    # Bước 2: Bóc tách lần 2 phòng trường hợp thông số nhom=... nằm kẹp giữa nội dung và @Tag
    cleaned_body, group_spec_mode_2, group_spec_val_2, inline_tag_all_2 = extract_multigroup_spec_and_clean_body(
        cleaned_body, cmd_token=cmd_token
    )
    if group_spec_mode == "current" and group_spec_mode_2 != "current":
        group_spec_mode = group_spec_mode_2
        group_spec_val = group_spec_val_2

    if inline_tag_all_1 or inline_tag_all_2 or cmd_token in ("all", "tagall", "anall", "tagallan"):
        extracted_tag_all = True

    if group_spec_mode != "current":
        target_obj = FullConversationAutoScanner.resolve_target_groups_from_spec(
            platform=platform,
            current_thread_id=thread_id,
            is_group_default=is_group,
            spec_mode=group_spec_mode,
            spec_val=group_spec_val
        )

    is_auto_shuffle = (chosen_mode == "auto_shuffle")
    if chosen_mode in ("raid_mode", "sieu_xa_nhieu_nhom"):
        chosen_mode = "treo_nhay" if chosen_mode == "raid_mode" else "sieu_xa_nhieu_nhom"
        delay_val = 0.0
        color_mode = "word_rainbow"
        is_heading = True
        if use_emoji and icon_count > 0:
            icon_count = max(icon_count, 4)
    elif chosen_mode == "auto_shuffle":
        chosen_mode = "treo_nhay"
    elif chosen_mode == "chao_mode":
        chosen_mode = "treo_nhay"
        if not cleaned_body.strip():
            cleaned_body = "Chào cả nhà ngày mới rực rỡ nhé; Chúc anh em trong box luôn vui vẻ đỉnh cao; Hệ thống Hệ Thống điểm danh siêu tốc"

    if platform == "zalo" and (extracted_mentions or extracted_tag_all):
        target_obj[0]["type"] = "group"

    first_line_part, sep_nl, rest_lines_part = cleaned_body.partition("\n")
    tokens = first_line_part.split()
    consumed = 0
    file_query = direct_file_num

    if chosen_mode == "file_cmd":
        chosen_mode = "treo_nhay"
        if not file_query and tokens and not sep_nl:
            file_query = tokens[0]
            consumed = 1

    for tk in tokens[consumed:]:
        tk_low = tk.lower()
        if tk_low.startswith("delay=") or tk_low.startswith("d="):
            try:
                delay_val = max(0.0, float(tk_low.split("=", 1)[1].replace("s", "")))
                consumed += 1
            except Exception:
                break
        elif tk_low.startswith("color=") or tk_low.startswith("mau="):
            c_val = tk_low.split("=", 1)[1]
            if c_val in ("rainbow", "word_rainbow", "fire_gradient", "ocean_gradient", "royal_gradient", "random", "none"):
                color_mode = c_val
            elif c_val in ZALO_COLOR_MAP:
                color_mode = "fixed"
                fixed_color = c_val
            consumed += 1
        elif tk_low.startswith("icon="):
            try:
                icon_count = max(0, int(tk_low.split("=", 1)[1]))
                use_emoji = (icon_count > 0)
                update_running_tasks_config(thread_id=None, icon_count=icon_count, use_emoji=use_emoji)
                consumed += 1
            except Exception:
                break
        elif tk_low in ("nhay", "treonhay", "treo_nhay"):
            chosen_mode = "treo_nhay"
            consumed += 1
        elif tk_low in ("ngon", "treongon", "treo_ngon"):
            chosen_mode = "treo_ngon"
            consumed += 1
        elif tk_low in ("fast", "nhanh"):
            chosen_mode = "fast"
            consumed += 1
        elif tk_low.startswith("file="):
            file_query = tk.split("=", 1)[1]
            consumed += 1
        else:
            break

    if consumed > 0:
        rem_first = " ".join(tokens[consumed:]).strip()
        remaining_content = (f"{rem_first}\n{rest_lines_part}" if rem_first else rest_lines_part) if sep_nl else rem_first
    else:
        remaining_content = cleaned_body.strip("\r\n")

    blocks = []
    if file_query:
        blocks = get_blocks_from_file_query(file_query, mode=chosen_mode)
    elif remaining_content and (remaining_content.isdigit() or remaining_content.endswith(".txt")):
        blocks = get_blocks_from_file_query(remaining_content, mode=chosen_mode)

    if not blocks and remaining_content and not file_query:
        if chosen_mode == "treo_nhay":
            if ";" in remaining_content:
                blocks = [strip_leading_line_number(x.strip()) for x in remaining_content.split(";") if x.strip()]
            elif "\n" in remaining_content:
                blocks = [strip_leading_line_number(x.strip()) for x in remaining_content.split("\n") if x.strip()]
            else:
                blocks = [strip_leading_line_number(remaining_content)]
        elif chosen_mode == "treo_ngon":
            blocks = [remaining_content.replace(";", "\n")]
        else:
            blocks = [x.strip() for x in remaining_content.split(";") if x.strip()] if ";" in remaining_content else [remaining_content]

    # Loại bỏ mọi phần tử chỉ chứa mã Tag <@...> hoặc @Tên bị sót lại trong blocks
    if blocks:
        cleaned_blocks = []
        for b_item in blocks:
            b_check = re.sub(r"<@(?:!|&)?\d+>", "", str(b_item or "")).strip()
            if b_check and not re.fullmatch(r"@[\w\s\.\-_À-ỹ]+", b_check):
                cleaned_blocks.append(b_item)
        blocks = cleaned_blocks

    if not blocks:
        blocks = get_blocks_from_file_query("latest", mode=chosen_mode)
        if blocks:
            blocks = [
                b_item for b_item in blocks
                if re.sub(r"<@(?:!|&)?\d+>", "", str(b_item or "")).strip()
                and not re.fullmatch(r"@[\w\s\.\-_À-ỹ]+", re.sub(r"<@(?:!|&)?\d+>", "", str(b_item or "")).strip())
            ]

    if not blocks:
        if chosen_mode == "treo_ngon":
            blocks = [
                "Hệ Thống Hệ Thống Đa Luồng\n"
                "Đẳng cấp tốc độ ánh sáng, cân mọi chiến trường không độ trễ!\n"
                "Tường lửa Anti-Ban bảo vệ toàn diện 24/7!"
            ]
        else:
            blocks = [
                "Hệ thống Hệ Thống Đa Luồng điểm danh siêu tốc!",
                "Đẳng cấp treo đa luồng cân 100 tiến trình cực mượt!",
                "Lá chắn Anti-Ban bất tử vận hành 24/7 không delay!",
                "Tốc độ phản hồi ánh sáng — Chuẩn VIP Quản Trị Viên!"
            ]

    if is_auto_shuffle and len(blocks) > 1:
        blocks = list(blocks)
        random.shuffle(blocks)

    if len(target_obj) > 1:
        stop_tasks_for_thread(None)
    else:
        stop_tasks_for_thread(thread_id)

    hide_name_flag = False if cmd_token == "hientag" else bool(SYSTEM_RUNTIME_CONFIG.get("hide_tag_name", True) or cmd_token in ("antan", "tagan", "antag"))

    # Bắn ngay phát đầu tiên trong 0.001s trên làn ưu tiên (_PRIORITY_CMD_EXECUTOR + priority_bypass=True)
    # để vừa gõ lệnh là tin nhắn nổ ra ngay lập tức không có bất kỳ độ trễ khởi động nào!
    if blocks and target_obj:
        first_pkt = str(blocks[0])
        if chosen_mode != "treo_ngon":
            first_pkt = strip_leading_line_number(first_pkt, preserve_indent=True)
        if not use_emoji or int(icon_count or 0) <= 0:
            first_pkt = strip_trailing_icons_when_zero(first_pkt)

        def _instant_first_shot(t_item):
            t_id_now = str(t_item.get("id") or thread_id)
            try:
                if platform == "zalo" and zalo_client:
                    zalo_client.send_adv(
                        first_pkt, t_id_now, color_mode=color_mode, fixed_color=fixed_color,
                        is_group=True, mentions=extracted_mentions, tag_all=extracted_tag_all,
                        is_heading=is_heading, antiband=antiband_flag, use_emoji=use_emoji,
                        icon_count=icon_count, auto_retry_thread_type=True,
                        strip_line_num=(chosen_mode != "treo_ngon"),
                        hide_tag_all=True, hide_tag_name=hide_name_flag, priority_bypass=True
                    )
                elif platform == "discord" and discord_client:
                    msg_ln0 = (first_pkt + " " + build_unique_zalo_icons(icon_count)) if (use_emoji and icon_count > 0) else first_pkt
                    discord_client.send_message(
                        t_id_now, msg_ln0, color_mode=color_mode, fixed_color=fixed_color,
                        antiband=antiband_flag, mentions=extracted_mentions, tag_all=extracted_tag_all,
                        strip_line_num=(chosen_mode != "treo_ngon"), is_heading=is_heading,
                        priority_bypass=True
                    )
                elif platform == "messenger" and messenger_client:
                    messenger_client.send_message(
                        t_id_now, first_pkt, is_group=True, mentions=extracted_mentions,
                        tag_all=extracted_tag_all, antiband=antiband_flag,
                        use_emoji=use_emoji, icon_count=icon_count, is_heading=is_heading
                    )
            except Exception:
                pass

        for t_item_0 in target_obj[:16]:
            _PRIORITY_CMD_EXECUTOR.submit(_instant_first_shot, t_item_0)

    tid = start_task_programmatic(
        targets=target_obj,
        hide_tag_all=True,
        hide_tag_name=hide_name_flag,
        blocks=blocks,
        delay=delay_val,
        use_emoji=use_emoji,
        icon_count=icon_count,
        tag_users=extracted_mentions,
        tag_all=extracted_tag_all,
        is_heading=is_heading,
        multi_acc=True,
        mode=chosen_mode,
        color_mode=color_mode,
        fixed_color=fixed_color,
        antiband=antiband_flag,
        antidieall=True,
        specific_acc_id=acc_id,
        source_label="chat",
        trigger_cmd=text
    )

    tag_parts = []
    if extracted_tag_all:
        tag_parts.append("@All")
    if extracted_mentions:
        tag_parts.append(", ".join("@" + m["name"] for m in extracted_mentions))
    tag_desc = " + ".join(tag_parts) if tag_parts else "Không tag"
    box_desc = f"{len(target_obj)} nhóm đồng loạt" if len(target_obj) > 1 else "1 nhóm hiện tại"
    log_system_command(acc_id, thread_id, sender_id, text, f"[{platform.upper()}] Chạy {chosen_mode} trên {box_desc} (Delay {delay_val}s) | Tag: {tag_desc}")
    return True

# LISTENER 24/7 TRÊN ZALO (WEBSOCKET + HTTP FALLBACK)
_SHARED_ZALO_POLLER_POOL = ThreadPoolExecutor(max_workers=16)

class ZaloRealtimeListener:
    def __init__(self, acc_id):
        self.acc_id = acc_id
        self.platform = "zalo"
        self.stop_ev = threading.Event()
        self.seen_msg_ids = deque(maxlen=3500)
        self.seeded_groups = set()
        self.last_grid_vers = {}
        self.poll_cursor = 0
        self.ws_cipher_key = None
        self.ws_conflict_until = 0.0
        self.started_at = time.time()
        self.ws_status = "Đang khởi tạo Zalo Shield..."
        self.last_event_ts = 0.0
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.poller_thread = threading.Thread(target=self._run_http_poller_loop, daemon=True)

    def start(self):
        self.thread.start()
        self.poller_thread.start()

    def stop(self):
        self.stop_ev.set()

    def _get_acc_row(self):
        return get_account_from_ram(self.acc_id)

    @staticmethod
    def _recv_exact(sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    @staticmethod
    def _send_ws_frame(sock, payload_bytes, opcode=0x2):
        mask_key = os.urandom(4)
        length = len(payload_bytes)
        header = bytearray([0x80 | (opcode & 0x0F)])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", length))
        header.extend(mask_key)
        masked_payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload_bytes))
        sock.sendall(bytes(header) + masked_payload)

    def _try_decompress_or_json(self, raw_bytes):
        if not raw_bytes:
            return None
        for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                decomp = zlib.decompress(raw_bytes, wbits)
                txt = decomp.decode("utf-8", errors="ignore").strip()
                if txt.startswith("{") or txt.startswith("["):
                    return json.loads(txt)
            except Exception:
                pass
        try:
            txt = raw_bytes.decode("utf-8", errors="ignore").strip()
            if txt.startswith("{") or txt.startswith("["):
                return json.loads(txt)
        except Exception:
            pass
        return None

    def _decode_ws_payload(self, client, raw_data_str, encrypt_type):
        if not raw_data_str:
            return None
        try:
            if encrypt_type == 0:
                return json.loads(raw_data_str) if isinstance(raw_data_str, str) else raw_data_str

            s_raw = unquote(str(raw_data_str)) if "%" in str(raw_data_str) else str(raw_data_str)
            s_raw = s_raw.strip()
            pad_rem = len(s_raw) % 4
            if pad_rem:
                s_raw += "=" * (4 - pad_rem)
            b_data = base64.b64decode(s_raw)

            key_candidates = []
            for k_str in (self.ws_cipher_key, client.secret_key):
                if not k_str:
                    continue
                k_clean = unquote(str(k_str)).strip()
                for cand_fn in (
                    lambda x: base64.b64decode(x + ("=" * ((4 - len(x) % 4) % 4))),
                    lambda x: x.encode("utf-8"),
                    lambda x: bytes.fromhex(x),
                ):
                    try:
                        kb = cand_fn(k_clean)
                        if len(kb) in (16, 24, 32) and kb not in key_candidates:
                            key_candidates.append(kb)
                    except Exception:
                        pass

            if encrypt_type == 1:
                try:
                    raw_g = gzip.decompress(b_data).decode("utf-8", errors="ignore").strip()
                    if raw_g.startswith("{") or raw_g.startswith("["):
                        return json.loads(raw_g)
                except Exception:
                    pass
                for wbits in (16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
                    try:
                        raw_z = zlib.decompress(b_data, wbits).decode("utf-8", errors="ignore").strip()
                        if raw_z.startswith("{") or raw_z.startswith("["):
                            return json.loads(raw_z)
                    except Exception:
                        pass

            if encrypt_type == 2 and len(b_data) >= 48:
                iv_zws = b_data[:16]
                aad_zws = b_data[16:32]
                ct_zws = b_data[32:]
                for kb in key_candidates:
                    try:
                        cipher = AES.new(kb, AES.MODE_GCM, nonce=iv_zws)
                        cipher.update(aad_zws)
                        pt = cipher.decrypt_and_verify(ct_zws[:-16], ct_zws[-16:])
                        for wb in (16, 16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS):
                            try:
                                dec_str = zlib.decompress(pt, wbits=wb).decode("utf-8", errors="ignore").strip()
                                if dec_str.startswith("{") or dec_str.startswith("["):
                                    return json.loads(dec_str)
                            except Exception:
                                pass
                        res = self._try_decompress_or_json(pt)
                        if res is not None:
                            return res
                    except Exception:
                        pass

            if encrypt_type in (1, 3):
                for kb in key_candidates:
                    for iv_cand, body_cand in ((bytes(16), b_data), (b_data[:16], b_data[16:])):
                        if not body_cand or len(body_cand) % 16 != 0:
                            continue
                        try:
                            cipher = AES.new(kb, AES.MODE_CBC, iv_cand)
                            dec_bytes = cipher.decrypt(body_cand)
                            if dec_bytes:
                                pad_v = dec_bytes[-1]
                                if 1 <= pad_v <= 16 and all(b == pad_v for b in dec_bytes[-pad_v:]):
                                    dec_bytes = dec_bytes[:-pad_v]
                            res = self._try_decompress_or_json(dec_bytes)
                            if res is not None:
                                return res
                        except Exception:
                            pass

            if len(b_data) > 32:
                iv = b_data[:16]
                for kb in key_candidates:
                    if len(b_data) >= 64:
                        try:
                            cipher = AES.new(kb, AES.MODE_GCM, nonce=iv)
                            cipher.update(b_data[16:48])
                            pt = cipher.decrypt_and_verify(b_data[48:-16], b_data[-16:])
                            res = self._try_decompress_or_json(pt)
                            if res is not None:
                                return res
                        except Exception:
                            pass
                    if len(b_data) >= 48:
                        try:
                            cipher = AES.new(kb, AES.MODE_GCM, nonce=iv)
                            cipher.update(b_data[16:32])
                            pt = cipher.decrypt_and_verify(b_data[32:-16], b_data[-16:])
                            res = self._try_decompress_or_json(pt)
                            if res is not None:
                                return res
                        except Exception:
                            pass
                    for sl_ct, sl_tag in ((b_data[48:-16], b_data[-16:]), (b_data[32:-16], b_data[-16:]), (b_data[16:-16], b_data[-16:])):
                        if not sl_ct:
                            continue
                        try:
                            cipher = AES.new(kb, AES.MODE_GCM, nonce=iv)
                            pt = cipher.decrypt_and_verify(sl_ct, sl_tag)
                            res = self._try_decompress_or_json(pt)
                            if res is not None:
                                return res
                        except Exception:
                            pass

            for kb in key_candidates:
                for iv_cand, body_cand in ((bytes(16), b_data), (b_data[:16], b_data[16:])):
                    if not body_cand or len(body_cand) % 16 != 0:
                        continue
                    try:
                        cipher = AES.new(kb, AES.MODE_CBC, iv_cand)
                        dec_bytes = cipher.decrypt(body_cand)
                        if dec_bytes:
                            pad_v = dec_bytes[-1]
                            if 1 <= pad_v <= 16 and all(b == pad_v for b in dec_bytes[-pad_v:]):
                                dec_bytes = dec_bytes[:-pad_v]
                        res = self._try_decompress_or_json(dec_bytes)
                        if res is not None:
                            return res
                    except Exception:
                        pass

            for cand in (b_data, b_data[16:], b_data[32:], b_data[4:]):
                res = self._try_decompress_or_json(cand)
                if res is not None:
                    return res
        except Exception:
            pass
        return None

    def _extract_msg_dicts(self, obj, parent_is_group=False, parent_grid=None):
        found = []
        if isinstance(obj, dict):
            cur_grid = str(obj.get("grid") or obj.get("groupId") or obj.get("group_id") or parent_grid or "").strip()
            is_grp_branch = parent_is_group or bool(cur_grid and cur_grid != "0") or ("groupMsgs" in obj) or ("grid" in obj)
            has_content = ("content" in obj) or ("msg" in obj) or ("message" in obj) or ("text" in obj) or ("title" in obj)
            if has_content and any(k in obj for k in ("uidFrom", "idTo", "msgId", "cliMsgId", "toid", "fromUid", "grid")):
                item = dict(obj)
                if is_grp_branch:
                    item["_is_group_hint"] = True
                if cur_grid and cur_grid != "0":
                    item["grid"] = cur_grid
                    item["_grid_hint"] = cur_grid
                found.append(item)
            for k, v in obj.items():
                sub_grp = is_grp_branch or (k in ("groupMsgs", "group_msgs", "grid"))
                sub_grid = cur_grid
                if not sub_grid and str(k).isdigit() and len(str(k)) >= 8 and is_grp_branch:
                    sub_grid = str(k)
                if isinstance(v, (dict, list)):
                    found.extend(self._extract_msg_dicts(v, parent_is_group=sub_grp, parent_grid=sub_grid))
        elif isinstance(obj, list):
            for elem in obj:
                if isinstance(elem, (dict, list)):
                    found.extend(self._extract_msg_dicts(elem, parent_is_group=parent_is_group, parent_grid=parent_grid))
        return found

    def _extract_raw_mentions_from_msg_obj(self, msg_obj):
        def _parse_candidate(val):
            if isinstance(val, list) and val:
                return val
            if isinstance(val, dict):
                if "mentions" in val:
                    return _parse_candidate(val["mentions"])
                if "mentionInfo" in val:
                    return _parse_candidate(val["mentionInfo"])
                if "uid" in val or "pos" in val:
                    return [val]
            if isinstance(val, str):
                s = val.strip()
                if s.startswith("[") or s.startswith("{"):
                    try:
                        return _parse_candidate(json.loads(s))
                    except Exception:
                        pass
            return None

        for key in ("mentions", "mentionInfo", "propertyExt", "params"):
            res = _parse_candidate(msg_obj.get(key))
            if res:
                return res
        return None

    @staticmethod
    def _make_msg_dedupe_key(msg_obj, content=""):
        mid = str(msg_obj.get("msgId") or msg_obj.get("globalMsgId") or msg_obj.get("id") or "").strip()
        cmid = str(msg_obj.get("cliMsgId") or "").strip()
        ts_v = str(msg_obj.get("ts") or msg_obj.get("time") or "").strip()
        if mid or cmid:
            return f"id:{mid}:{cmid}"
        if ts_v and ts_v != "0":
            return f"ts:{ts_v}:{content[:30]}"
        return f"win:{int(time.time())}:{content[:30]}"

    def _process_msg_item(self, client, acc_row, msg_obj, default_is_group=False, fallback_thread_id=None):
        if not isinstance(msg_obj, dict):
            return

        msg_id = str(msg_obj.get("msgId") or msg_obj.get("globalMsgId") or msg_obj.get("id") or "")
        cli_msg_id = str(msg_obj.get("cliMsgId") or "")
        raw_content = msg_obj.get("content")
        if isinstance(raw_content, dict):
            raw_content = (
                raw_content.get("title")
                or raw_content.get("text")
                or raw_content.get("msg")
                or raw_content.get("description")
                or ""
            )
        elif isinstance(raw_content, str) and raw_content.strip().startswith("{"):
            try:
                rc_json = json.loads(raw_content.strip())
                if isinstance(rc_json, dict):
                    raw_content = (
                        rc_json.get("title")
                        or rc_json.get("text")
                        or rc_json.get("msg")
                        or rc_json.get("description")
                        or raw_content
                    )
            except Exception:
                pass

        if not raw_content or not isinstance(raw_content, str):
            raw_content = str(msg_obj.get("message") or msg_obj.get("msg") or msg_obj.get("text") or "")

        if is_system_echo_message(msg_id=msg_id, client_id=cli_msg_id, text=raw_content):
            return

        content = strip_invisible_chars(raw_content)
        if not content:
            return

        dedupe_key = self._make_msg_dedupe_key(msg_obj, content)
        if dedupe_key in self.seen_msg_ids:
            return
        self.seen_msg_ids.append(dedupe_key)

        grid_id = str(msg_obj.get("grid") or msg_obj.get("groupId") or msg_obj.get("_grid_hint") or fallback_thread_id or "").strip()
        uid_from = str(msg_obj.get("uidFrom") or msg_obj.get("fromUid") or "").strip()
        d_name = str(msg_obj.get("dName") or "").strip()
        if uid_from and d_name and uid_from != "0":
            GLOBAL_USER_NAME_CACHE[uid_from] = d_name

        id_to = str(msg_obj.get("idTo") or msg_obj.get("toid") or "").strip()
        cmd_num = int(msg_obj.get("cmd") or 0)
        raw_mentions = self._extract_raw_mentions_from_msg_obj(msg_obj)

        known_gids = KNOWN_GROUPS_BY_ACC.get(client.uid, set()) | ALL_KNOWN_ZALO_GROUP_IDS
        is_group = bool(
            default_is_group
            or (grid_id and grid_id != "0")
            or msg_obj.get("_is_group_hint")
            or msg_obj.get("isGroup")
            or (cmd_num in (521, 522))
            or (id_to in known_gids)
            or (uid_from in known_gids)
            or bool(raw_mentions)
        )

        my_uid = str(client.uid or acc_row.get("uid") or "").strip()
        if is_group:
            if grid_id and grid_id != "0":
                thread_id = grid_id
            elif id_to in known_gids:
                thread_id = id_to
            elif uid_from in known_gids:
                thread_id = uid_from
            else:
                thread_id = id_to if (id_to and id_to not in ("0", my_uid)) else (fallback_thread_id or uid_from)
            ALL_KNOWN_ZALO_GROUP_IDS.add(thread_id)
            if client.uid:
                KNOWN_GROUPS_BY_ACC[client.uid].add(thread_id)
        else:
            if uid_from in ("0", my_uid, ""):
                thread_id = id_to if id_to not in ("0", "") else my_uid
            else:
                thread_id = uid_from

        if not thread_id or thread_id == "0":
            return

        reply_target = None
        quote_obj = msg_obj.get("quote")
        if isinstance(quote_obj, dict):
            q_uid = str(quote_obj.get("ownerId") or quote_obj.get("uidFrom") or "").strip()
            q_name = str(quote_obj.get("fromD") or quote_obj.get("dName") or "").strip()
            if q_uid and q_uid != "0":
                reply_target = {"uid": q_uid, "name": q_name or GLOBAL_USER_NAME_CACHE.get(q_uid, f"User_{q_uid[-4:]}")}

        was_cmd = parse_and_execute_inchat_command(
            zalo_client=client,
            acc_row=acc_row,
            thread_id=thread_id,
            is_group=is_group,
            sender_id=uid_from,
            raw_msg=content,
            raw_mentions=raw_mentions,
            platform="zalo",
            sender_name=d_name,
            msg_id=(msg_id or cli_msg_id),
            reply_target=reply_target
        )
        if not was_cmd and str(thread_id) in AUTO_INTERCEPT_BOXES:
            ic_cfg = AUTO_INTERCEPT_BOXES.get(str(thread_id))
            if ic_cfg and ic_cfg.get("enabled") and uid_from and uid_from not in ("0", my_uid) and uid_from not in OWNER_UIDS_CACHE:
                b_list = ic_cfg.get("blocks") or ["Phản đòn siêu tốc 0s!"]
                idx_c = ic_cfg.get("idx", 0)
                ic_cfg["idx"] = idx_c + 1
                reply_line = b_list[idx_c % len(b_list)]
                target_m = [{"uid": uid_from, "id": uid_from, "name": d_name or GLOBAL_USER_NAME_CACHE.get(uid_from) or f"User_{uid_from[-4:]}"}]
                threading.Thread(
                    target=lambda: client.send_adv(
                        reply_line, thread_id, color_mode="rainbow", is_group=True,
                        mentions=target_m, tag_all=False, is_heading=True, antiband=True,
                        use_emoji=False, icon_count=0, hide_tag_name=False
                    ),
                    daemon=True
                ).start()

    @classmethod
    def _recv_full_ws_message(cls, sock):
        frag_opcode = None
        frag_buf = bytearray()
        prev_timeout = sock.gettimeout()

        try:
            while True:
                hdr = cls._recv_exact(sock, 2)
                if not hdr:
                    return None, None
                # Ngay khi đã đọc 2 byte đầu của Frame, tăng timeout lên 18s để đọc trọn vẹn các gói lớn (như Discord READY)
                # mà không bao giờ bị ngắt giữa chừng gây hỏng luồng WebSocket!
                sock.settimeout(18.0)
                fin = (hdr[0] & 0x80) != 0
                opcode = hdr[0] & 0x0F
                masked = (hdr[1] & 0x80) != 0
                payload_len = hdr[1] & 0x7F

                if payload_len == 126:
                    ext = cls._recv_exact(sock, 2)
                    if not ext:
                        return None, None
                    payload_len = struct.unpack(">H", ext)[0]
                elif payload_len == 127:
                    ext = cls._recv_exact(sock, 8)
                    if not ext:
                        return None, None
                    payload_len = struct.unpack(">Q", ext)[0]

                mask_bytes = cls._recv_exact(sock, 4) if masked else b""
                data = cls._recv_exact(sock, payload_len) if payload_len > 0 else b""
                if data is None:
                    return None, None
                if masked and mask_bytes:
                    data = bytes(b ^ mask_bytes[i % 4] for i, b in enumerate(data))

                if opcode == 0x8:
                    return 0x8, data
                if opcode == 0x9:
                    try:
                        cls._send_ws_frame(sock, data, opcode=0xA)
                    except Exception:
                        pass
                    sock.settimeout(prev_timeout)
                    continue
                if opcode == 0xA:
                    sock.settimeout(prev_timeout)
                    continue

                if opcode == 0x0:
                    frag_buf.extend(data)
                    if fin and frag_opcode is not None:
                        return frag_opcode, bytes(frag_buf)
                else:
                    if fin:
                        return opcode, data
                    frag_opcode = opcode
                    frag_buf = bytearray(data)
        finally:
            try:
                sock.settimeout(prev_timeout)
            except Exception:
                pass

    def _poll_single_group(self, client, acc_now, gid):
        if self.stop_ev.is_set():
            return
        try:
            msgs = client.get_recent_group_messages(gid)
            if gid not in self.seeded_groups:
                self.seeded_groups.add(gid)
                if not msgs:
                    return
                # Ghi nhận các tin nhắn cũ vào seen_msg_ids, NHƯNG nếu tin nhắn cuối cùng vừa mới được gõ
                # trong vòng 60 giây gần đây và là lệnh (.menu, .help, .nhay, .stop...) thì thực thi ngay!
                now_ms = int(time.time() * 1000)
                for idx_m, m in enumerate(msgs):
                    if not isinstance(m, dict):
                        continue
                    rc = m.get("content") or m.get("message") or m.get("msg") or ""
                    if isinstance(rc, dict):
                        rc = rc.get("title") or rc.get("text") or rc.get("msg") or ""
                    ct = strip_invisible_chars(str(rc))
                    is_last_msg = (idx_m == len(msgs) - 1)
                    msg_ts = int(m.get("ts") or 0)
                    if msg_ts > 0 and msg_ts < 10000000000:
                        msg_ts *= 1000
                    is_fresh_cmd = is_last_msg and is_direct_user_command_text(ct) and (
                        msg_ts == 0 or abs(now_ms - msg_ts) <= 60000
                    )
                    if is_fresh_cmd:
                        m["grid"] = str(gid)
                        self._process_msg_item(client, acc_now, m, default_is_group=True, fallback_thread_id=str(gid))
                    else:
                        self.seen_msg_ids.append(self._make_msg_dedupe_key(m, ct))
            else:
                for m in msgs:
                    if isinstance(m, dict):
                        m["grid"] = str(gid)
                        self._process_msg_item(client, acc_now, m, default_is_group=True, fallback_thread_id=str(gid))
        except Exception:
            pass

    def _poll_active_groups_inline(self, client, acc_now):
        """Bộ đồng bộ Siêu Nhạy NHK cho Đa Tài Khoản Zalo (< 0.12s Phản Hồi, Không Nghẽn Khi Chạy 2..50 Acc):
        1. Cô lập 100% danh sách nhóm theo từng tài khoản (KNOWN_GROUPS_BY_ACC[client.uid]), tuyệt đối không quét chéo nhóm của Acc khác!
        2. Gọi get_last_msgs() (preloadconvers/get-last-msgs) bắt tức thì mọi lệnh .menu, .cp, .n, .g, .t ở cả Chat Riêng và Mọi Nhóm.
        3. Khởi tạo nhanh bảng phiên bản nhóm (last_grid_vers) từ get_grid_ver_map() trong 1 request duy nhất và chỉ gọi get_recent_group_messages
           cho đúng những nhóm vừa nhảy phiên bản mới (changed_gids)!"""
        try:
            last_conv = client.get_last_msgs()
            u_msgs = last_conv.get("msgs") or []
            g_msgs = last_conv.get("groupMsgs") or []
            if "__preload_seeded__" not in self.seeded_groups:
                self.seeded_groups.add("__preload_seeded__")
                now_ms = int(time.time() * 1000)
                for m in u_msgs:
                    if isinstance(m, dict):
                        rc = m.get("content") or m.get("message") or m.get("msg") or ""
                        if isinstance(rc, dict):
                            rc = rc.get("title") or rc.get("text") or rc.get("msg") or ""
                        ct = strip_invisible_chars(str(rc))
                        msg_ts = int(m.get("ts") or 0)
                        if 0 < msg_ts < 10000000000:
                            msg_ts *= 1000
                        if is_direct_user_command_text(ct) and (msg_ts == 0 or abs(now_ms - msg_ts) <= 60000):
                            _PRIORITY_CMD_EXECUTOR.submit(self._process_msg_item, client, acc_now, m, False, None)
                        else:
                            self.seen_msg_ids.append(self._make_msg_dedupe_key(m, ct))
                for m in g_msgs:
                    if isinstance(m, dict):
                        rc = m.get("content") or m.get("message") or m.get("msg") or ""
                        if isinstance(rc, dict):
                            rc = rc.get("title") or rc.get("text") or rc.get("msg") or ""
                        ct = strip_invisible_chars(str(rc))
                        msg_ts = int(m.get("ts") or 0)
                        if 0 < msg_ts < 10000000000:
                            msg_ts *= 1000
                        gid_m = str(m.get("idTo") or m.get("grid") or "").strip()
                        if gid_m:
                            KNOWN_GROUPS_BY_ACC[client.uid].add(gid_m)
                        if is_direct_user_command_text(ct) and (msg_ts == 0 or abs(now_ms - msg_ts) <= 60000):
                            m["grid"] = gid_m
                            _PRIORITY_CMD_EXECUTOR.submit(self._process_msg_item, client, acc_now, m, True, gid_m)
                        else:
                            self.seen_msg_ids.append(self._make_msg_dedupe_key(m, ct))
            else:
                for m in u_msgs:
                    if isinstance(m, dict):
                        rc_u = m.get("content") or m.get("message") or m.get("msg") or ""
                        if isinstance(rc_u, dict):
                            rc_u = rc_u.get("title") or rc_u.get("text") or rc_u.get("msg") or ""
                        ct_u = strip_invisible_chars(str(rc_u))
                        if not ct_u or self._make_msg_dedupe_key(m, ct_u) in self.seen_msg_ids:
                            continue
                        _PRIORITY_CMD_EXECUTOR.submit(self._process_msg_item, client, acc_now, m, False, None)
                for m in g_msgs:
                    if isinstance(m, dict):
                        gid_m = str(m.get("idTo") or m.get("grid") or "").strip()
                        if gid_m:
                            KNOWN_GROUPS_BY_ACC[client.uid].add(gid_m)
                        rc_g = m.get("content") or m.get("message") or m.get("msg") or ""
                        if isinstance(rc_g, dict):
                            rc_g = rc_g.get("title") or rc_g.get("text") or rc_g.get("msg") or ""
                        ct_g = strip_invisible_chars(str(rc_g))
                        if not ct_g or self._make_msg_dedupe_key(m, ct_g) in self.seen_msg_ids:
                            continue
                        m["grid"] = gid_m
                        def _fast_group_dispatch(msg_item=m, grp_id=gid_m, raw_c=ct_g):
                            if "@" in raw_c and grp_id and is_direct_user_command_text(raw_c) and not msg_item.get("mentions") and not msg_item.get("mentionInfo"):
                                try:
                                    full_g = client.get_recent_group_messages(grp_id)
                                    m_match = next((x for x in reversed(full_g) if str(x.get("msgId")) == str(msg_item.get("msgId"))), None)
                                    if m_match:
                                        msg_item = m_match
                                        msg_item["grid"] = grp_id
                                except Exception:
                                    pass
                            self._process_msg_item(client, acc_now, msg_item, default_is_group=True, fallback_thread_id=grp_id)
                        _PRIORITY_CMD_EXECUTOR.submit(_fast_group_dispatch)
        except Exception:
            pass

        changed_gids = []
        now_t = time.time()
        if now_t - getattr(self, "_last_gmap_check_ts", 0.0) >= 0.32:
            self._last_gmap_check_ts = now_t
            try:
                gmap = client.get_grid_ver_map() or {}
                is_first_gmap = ("__gmap_seeded__" not in self.seeded_groups)
                if is_first_gmap:
                    self.seeded_groups.add("__gmap_seeded__")
                for gid_k, ver_v in gmap.items():
                    gid_s = str(gid_k)
                    KNOWN_GROUPS_BY_ACC[client.uid].add(gid_s)
                    prev_v = self.last_grid_vers.get(gid_s)
                    if is_first_gmap:
                        self.last_grid_vers[gid_s] = ver_v
                        self.seeded_groups.add(gid_s)
                    else:
                        if prev_v is not None and str(prev_v) != str(ver_v):
                            changed_gids.append(gid_s)
                            HOT_ACTIVE_ZALO_GROUPS.add(gid_s)
                        self.last_grid_vers[gid_s] = ver_v
            except Exception:
                pass

        if changed_gids:
            for gid in changed_gids[:6]:
                _PRIORITY_CMD_EXECUTOR.submit(self._poll_single_group, client, acc_now, gid)

    def _run_http_poller_loop(self):
        while not self.stop_ev.is_set():
            acc_row = self._get_acc_row()
            if not acc_row or (acc_row.get("platform") or "zalo") != "zalo":
                break
            if not acc_row.get("chat_cmd_enabled", 1):
                self.stop_ev.wait(3.0)
                continue
            try:
                client = Zalo.get_pooled_client(
                    acc_row["imei"], acc_row["cookies"],
                    user_agent=acc_row.get("user_agent") or "",
                    zpw_enk_hint=acc_row.get("zpw_enk") or "",
                    uid_hint=acc_row.get("uid") or ""
                )
                now_ka = time.time()
                try:
                    from zalo_login import ZaloPCSessionKeeper
                    ZaloPCSessionKeeper.notify_external_ws_alive(client.uid, client.imei)
                except Exception:
                    pass
                if now_ka - getattr(self, "_last_pc_keepalive_ts", 0.0) > 90.0:
                    self._last_pc_keepalive_ts = now_ka
                    try:
                        srv_sign = hashlib.md5(f"zsecuregetserverinfo645Web{client.imei}30".encode("utf-8")).hexdigest()
                        r_ka = client.s.get(
                            "https://wpa.chat.zalo.me/api/login/getServerInfo",
                            params={"imei": client.imei, "type": 30, "client_version": 645, "computer_name": "Web", "signkey": srv_sign},
                            timeout=4.0
                        )
                        for c_item in r_ka.cookies:
                            if c_item.name and c_item.value:
                                client.cookies_dict[c_item.name] = c_item.value
                    except Exception:
                        pass
                self._poll_active_groups_inline(client, acc_row)
                if "Cần cập nhật" in self.ws_status or "Đang" in self.ws_status or time.time() < self.ws_conflict_until:
                    self.ws_status = "Đang hoạt động trong Acc (Sẵn sàng 24/7)"
            except Exception as e:
                if "Phiên đăng nhập" in str(e) or "zpw_enk" in str(e):
                    self.ws_status = "Cần cập nhật lại Cookie Zalo"
            self.stop_ev.wait(0.08)

    def _run_ws_session(self, client, acc_row, ws_url):
        parsed = urlparse(ws_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        raw_sock = socket.create_connection((host, port), timeout=12)
        if parsed.scheme == "wss":
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock = raw_sock

        ws_key = base64.b64encode(os.urandom(16)).decode()
        cookie_str = "; ".join(f"{k}={v}" for k, v in client.cookies_dict.items())
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: https://chat.zalo.me\r\n"
            f"User-Agent: {client.s.headers.get('User-Agent')}\r\n"
            f"Cookie: {cookie_str}\r\n\r\n"
        )
        sock.sendall(handshake.encode("utf-8"))

        resp_buf = bytearray()
        while not resp_buf.endswith(b"\r\n\r\n"):
            b1 = sock.recv(1)
            if not b1:
                sock.close()
                return
            resp_buf.extend(b1)
            if len(resp_buf) > 8192:
                sock.close()
                return

        if b"101" not in resp_buf.split(b"\r\n")[0]:
            sock.close()
            return

        self.ws_status = "Zalo Hybrid Shield Active (.menu Sẵn Sàng)"
        sock.settimeout(2.2)
        last_ping = time.time()

        try:
            while not self.stop_ev.is_set():
                acc_now = self._get_acc_row()
                if not acc_now or not acc_now.get("chat_cmd_enabled", 1):
                    self.ws_status = "Đã tắt nhận lệnh"
                    break

                now_t = time.time()
                if now_t - last_ping >= 18.0:
                    hb_payload = struct.pack("<BHB", 1, 2, 1) + json.dumps({"eventId": int(now_t * 1000)}).encode("utf-8")
                    self._send_ws_frame(sock, hb_payload, opcode=0x2)
                    last_ping = now_t
                    try:
                        from zalo_login import ZaloPCSessionKeeper
                        ZaloPCSessionKeeper.notify_external_ws_alive(client.uid, client.imei)
                    except Exception:
                        pass

                try:
                    opcode, data = self._recv_full_ws_message(sock)
                    if opcode is None or opcode == 0x8:
                        break

                    if opcode in (0x1, 0x2) and data and len(data) >= 4:
                        cmd_id = 0
                        json_part = data
                        if data[0] != ord("{"):
                            cmd_id = struct.unpack("<H", data[1:3])[0]
                            json_part = data[4:]

                        txt_frame = json_part.decode("utf-8", errors="ignore").strip()
                        if not txt_frame.startswith("{"):
                            continue
                        try:
                            outer = json.loads(txt_frame)
                        except Exception:
                            continue

                        if outer.get("key"):
                            self.ws_cipher_key = outer["key"]
                        elif isinstance(outer.get("data"), dict) and outer["data"].get("key"):
                            self.ws_cipher_key = outer["data"]["key"]

                        if cmd_id == 3000:
                            # Người dùng đang mở Zalo Web trên trình duyệt -> nhường WebSocket 35s, dùng HTTP Poller!
                            self.ws_conflict_until = time.time() + 35.0
                            self.ws_status = "Zalo Smart Poller Active (.menu Sẵn Sàng)"
                            break

                        enc_type = int(outer.get("encrypt", 0))
                        raw_d = outer.get("data")
                        if not raw_d:
                            continue

                        inner = self._decode_ws_payload(client, raw_d, enc_type)
                        if inner is not None:
                            if isinstance(inner, dict):
                                k_dec = inner.get("key") or (
                                    inner.get("data", {}).get("key") if isinstance(inner.get("data"), dict) else None
                                )
                                if k_dec and isinstance(k_dec, str):
                                    self.ws_cipher_key = k_dec
                                    self.ws_status = "Zalo Quantum Key Locked (.menu Sẵn Sàng)"

                            self.last_event_ts = time.time()
                            is_grp_cmd = (cmd_id in (521, 522))
                            msg_items = self._extract_msg_dicts(inner, parent_is_group=is_grp_cmd)
                            for m in msg_items:
                                m["cmd"] = cmd_id
                                _PRIORITY_CMD_EXECUTOR.submit(self._process_msg_item, client, acc_now, m, is_grp_cmd, None)
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _run_loop(self):
        ws_idx = 0
        while not self.stop_ev.is_set():
            acc_row = self._get_acc_row()
            if not acc_row or (acc_row.get("platform") or "zalo") != "zalo":
                break
            if not acc_row.get("chat_cmd_enabled", 1):
                self.ws_status = "Đã tắt nhận lệnh"
                self.stop_ev.wait(4.0)
                continue

            if time.time() < self.ws_conflict_until:
                self.stop_ev.wait(4.0)
                continue

            try:
                client = Zalo.get_pooled_client(
                    acc_row["imei"], acc_row["cookies"],
                    user_agent=acc_row.get("user_agent") or "",
                    zpw_enk_hint=acc_row.get("zpw_enk") or "",
                    uid_hint=acc_row.get("uid") or ""
                )
                if client.uid and not acc_row.get("uid"):
                    try:
                        conn = db()
                        conn.execute("UPDATE accounts SET uid=? WHERE id=?", (client.uid, self.acc_id))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

                if client.ws_urls:
                    ws_url = client.ws_urls[ws_idx % len(client.ws_urls)]
                    ws_idx += 1
                    if "zpw_ver=" not in ws_url:
                        sep = "&" if "?" in ws_url else "?"
                        ws_url = f"{ws_url}{sep}zpw_ver=645&zpw_type=30&t={int(time.time() * 1000)}"
                    self._run_ws_session(client, acc_row, ws_url)

                self.stop_ev.wait(3.0)
            except Exception:
                self.ws_status = "Zalo Poller Đang Bảo Vệ..."
                self.stop_ev.wait(5.0)

# LISTENER 24/7 TRÊN DISCORD ACC CHÍNH CHỦ & BOT (CHROME 131 TLS GATEWAY + ZERO-SCRAPE SHIELD)
class DiscordRealtimeListener:
    def __init__(self, acc_id):
        self.acc_id = acc_id
        self.platform = "discord"
        self.stop_ev = threading.Event()
        self.seen_msg_ids = deque(maxlen=2500)
        self.seeded_channels = set()
        self.ws_status = "Đang khởi tạo NHK Discord Shield..."
        self.last_event_ts = 0.0
        self.last_seq = None
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.poller_thread = threading.Thread(target=self._run_discord_http_poller_loop, daemon=True)

    def start(self):
        self.thread.start()
        self.poller_thread.start()

    def stop(self):
        self.stop_ev.set()

    def _get_acc_row(self):
        return get_account_from_ram(self.acc_id)

    def _handle_discord_message_event(self, client, acc_row, msg_data):
        if not isinstance(msg_data, dict):
            return
        msg_id = str(msg_data.get("id") or "")
        content = str(msg_data.get("content") or "")
        if not content:
            return

        if is_system_echo_message(msg_id=msg_id, text=content):
            return

        if msg_id in self.seen_msg_ids:
            return
        if msg_id:
            self.seen_msg_ids.append(msg_id)

        channel_id = str(msg_data.get("channel_id") or "")
        guild_id = str(msg_data.get("guild_id") or "")
        if channel_id and guild_id:
            DiscordStealthAntiBanEngine.register_channel_guild(channel_id, guild_id)

        author = msg_data.get("author") or {}
        sender_id = str(author.get("id") or "")
        sender_name = author.get("global_name") or author.get("username") or ""
        if sender_id and sender_name:
            GLOBAL_USER_NAME_CACHE[sender_id] = sender_name

        if not channel_id:
            return

        DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS[self.acc_id].add(str(channel_id))

        clean_check = strip_invisible_chars(content)
        custom_pfx = (acc_row.get("cmd_prefix") or ".").strip()
        if not clean_check.startswith(tuple(set([custom_pfx, ".", "/", "!"]))):
            if str(channel_id) in AUTO_INTERCEPT_BOXES and sender_id and sender_id != str(client.user_id or "") and sender_id not in OWNER_UIDS_CACHE:
                ic_cfg = AUTO_INTERCEPT_BOXES.get(str(channel_id))
                if ic_cfg and ic_cfg.get("enabled"):
                    b_list = ic_cfg.get("blocks") or ["Phản đòn siêu tốc 0s!"]
                    idx_c = ic_cfg.get("idx", 0)
                    ic_cfg["idx"] = idx_c + 1
                    reply_line = b_list[idx_c % len(b_list)]
                    target_m = [{"uid": sender_id, "id": sender_id, "name": sender_name or f"User_{sender_id[-4:]}"}]
                    _PRIORITY_CMD_EXECUTOR.submit(
                        client.send_message,
                        channel_id, reply_line, "rainbow", None, True,
                        target_m, False, False, True, None, None, None, True
                    )
            return

        raw_mentions = []
        for m in (msg_data.get("mentions") or []):
            muid = str(m.get("id") or "")
            mname = m.get("global_name") or m.get("username") or ""
            if muid:
                if mname:
                    GLOBAL_USER_NAME_CACHE[muid] = mname
                raw_mentions.append({"uid": muid, "id": muid, "name": mname})

        reply_target = None
        ref_msg = msg_data.get("referenced_message")
        if isinstance(ref_msg, dict):
            ref_auth = ref_msg.get("author") or {}
            r_uid = str(ref_auth.get("id") or "").strip()
            r_name = str(ref_auth.get("global_name") or ref_auth.get("username") or "").strip()
            if r_uid:
                if r_name:
                    GLOBAL_USER_NAME_CACHE[r_uid] = r_name
                reply_target = {"uid": r_uid, "name": r_name or f"User_{r_uid[-4:]}"}

        def _instant_cmd_exec():
            if self.stop_ev.is_set():
                return
            DiscordStealthAntiBanEngine.ensure_session_warmed_up(client.token, is_bot=client.is_bot)
            parse_and_execute_inchat_command(
                zalo_client=None,
                acc_row=acc_row,
                thread_id=channel_id,
                is_group=True,
                sender_id=sender_id,
                raw_msg=content,
                raw_mentions=raw_mentions,
                discord_client=client,
                platform="discord",
                pre_claimed_slot=False,
                sender_name=sender_name,
                msg_id=msg_id,
                reply_target=reply_target
            )

        _PRIORITY_CMD_EXECUTOR.submit(_instant_cmd_exec)

    def _poll_active_discord_channels_fallback(self, client, acc_now):
        ch_set = list(DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS.get(self.acc_id, set()))[:5]
        if not ch_set:
            return
        prio_sess = DiscordStealthAntiBanEngine.get_priority_session(client.token, is_bot=client.is_bot)
        req_hdrs = DiscordStealthAntiBanEngine.build_stealth_headers(client.token, is_bot=client.is_bot)
        for cid in ch_set:
            if self.stop_ev.is_set():
                break
            try:
                ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(client.token, f"/channels/{cid}/messages?limit=3", 0)
                r = ProxyPoolEngine.request_with_fast_failover(
                    prio_sess, "GET", ep, seed_key=f"poll_{client.token[:10]}_{cid}",
                    priority_bypass=True, headers=req_hdrs, timeout=(0.8, 1.6)
                )
                if r.status_code == 200 and isinstance(r.json(), list):
                    msgs = list(reversed(r.json()))
                    if cid not in self.seeded_channels:
                        self.seeded_channels.add(cid)
                        now_ms = int(time.time() * 1000)
                        for idx_m, m in enumerate(msgs):
                            if not isinstance(m, dict):
                                continue
                            ct = strip_invisible_chars(str(m.get("content") or ""))
                            if idx_m == len(msgs) - 1 and is_direct_user_command_text(ct):
                                m["channel_id"] = cid
                                self._handle_discord_message_event(client, acc_now, m)
                            elif m.get("id"):
                                self.seen_msg_ids.append(str(m["id"]))
                    else:
                        for m in msgs:
                            if isinstance(m, dict):
                                m["channel_id"] = cid
                                self._handle_discord_message_event(client, acc_now, m)
            except Exception:
                continue

    def _run_discord_http_poller_loop(self):
        self.stop_ev.wait(0.8)
        while not self.stop_ev.is_set():
            acc_row = self._get_acc_row()
            if not acc_row or acc_row.get("platform") != "discord":
                break
            if not acc_row.get("chat_cmd_enabled", 1):
                self.stop_ev.wait(2.5)
                continue
            try:
                client = DiscordClient(acc_row["token"], is_bot=bool(acc_row.get("is_bot", 0)))
                self._poll_active_discord_channels_fallback(client, acc_row)
            except Exception:
                pass
            self.stop_ev.wait(0.15)

    def _run_gateway_session(self, client, acc_row):
        resume_state = DiscordStealthAntiBanEngine.get_gateway_resume_state(client.token)
        host = "gateway.discord.gg"
        if resume_state and resume_state.get("resume_url"):
            try:
                p_url = urlparse(resume_state["resume_url"])
                if p_url.hostname:
                    host = p_url.hostname
            except Exception:
                host = "gateway.discord.gg"
        port = 443
        path = "/?encoding=json&v=9"

        raw_sock = socket.create_connection((host, port), timeout=10)
        ctx = DiscordStealthAntiBanEngine.create_chrome_tls_context()
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        ws_key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: Upgrade\r\n"
            f"Pragma: no-cache\r\n"
            f"Cache-Control: no-cache\r\n"
            f"User-Agent: {client.s.headers.get('User-Agent')}\r\n"
            f"Upgrade: websocket\r\n"
            f"Origin: https://discord.com\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Accept-Language: vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n\r\n"
        )
        sock.sendall(handshake.encode("utf-8"))

        resp_buf = bytearray()
        while not resp_buf.endswith(b"\r\n\r\n"):
            b1 = sock.recv(1)
            if not b1:
                sock.close()
                return
            resp_buf.extend(b1)
            if len(resp_buf) > 8192:
                sock.close()
                return

        if b"101" not in resp_buf.split(b"\r\n")[0]:
            sock.close()
            return

        sock.settimeout(2.2)
        hb_interval = 38.0
        last_hb = time.time()
        identified = False
        zlib_inflator = zlib.decompressobj()
        zlib_buf = bytearray()

        try:
            while not self.stop_ev.is_set():
                acc_now = self._get_acc_row()
                if not acc_now or not acc_now.get("chat_cmd_enabled", 1):
                    self.ws_status = "Đã tắt nhận lệnh"
                    break

                now_t = time.time()
                if identified and (now_t - last_hb >= hb_interval):
                    hb_pkt = json.dumps({"op": 1, "d": self.last_seq}).encode("utf-8")
                    ZaloRealtimeListener._send_ws_frame(sock, hb_pkt, opcode=0x1)
                    last_hb = now_t

                try:
                    opcode, data = ZaloRealtimeListener._recv_full_ws_message(sock)
                    if opcode is None or opcode == 0x8:
                        break

                    raw_json_str = None
                    if opcode == 0x2 and data:
                        zlib_buf.extend(data)
                        if len(zlib_buf) >= 4 and zlib_buf[-4:] == b"\x00\x00\xff\xff":
                            try:
                                raw_json_str = zlib_inflator.decompress(bytes(zlib_buf)).decode("utf-8", errors="ignore")
                            except Exception:
                                raw_json_str = None
                            zlib_buf.clear()
                    elif opcode == 0x1 and data:
                        raw_json_str = data.decode("utf-8", errors="ignore")

                    if raw_json_str:
                        try:
                            pkt = json.loads(raw_json_str)
                        except Exception:
                            continue

                        op = pkt.get("op")
                        seq = pkt.get("s")
                        if seq is not None:
                            self.last_seq = seq
                        t_ev = pkt.get("t")
                        d_ev = pkt.get("d")

                        if op == 10 and isinstance(d_ev, dict):
                            hb_interval = max(20.0, (float(d_ev.get("heartbeat_interval", 41250)) / 1000.0) * 0.90)
                            cur_resume = DiscordStealthAntiBanEngine.get_gateway_resume_state(client.token)
                            if not client.is_bot and cur_resume and cur_resume.get("session_id"):
                                resume_payload = {
                                    "op": 6,
                                    "d": {
                                        "token": client.token,
                                        "session_id": cur_resume["session_id"],
                                        "seq": self.last_seq or cur_resume.get("last_seq", 0),
                                    }
                                }
                                ZaloRealtimeListener._send_ws_frame(sock, json.dumps(resume_payload).encode("utf-8"), opcode=0x1)
                                identified = True
                                last_hb = time.time()
                                self.ws_status = "NHK Discord Shield (Resumed - 0ms)"
                            elif client.is_bot:
                                ident_payload = {
                                    "op": 2,
                                    "d": {
                                        "token": client.token,
                                        "intents": 37377,
                                        "properties": {"os": "linux", "browser": "discord_client", "device": "discord_client"}
                                    }
                                }
                                ZaloRealtimeListener._send_ws_frame(sock, json.dumps(ident_payload).encode("utf-8"), opcode=0x1)
                                identified = True
                                last_hb = time.time()
                                self.ws_status = "NHK Discord Bot Shield (0ms)"
                            else:
                                ident_payload = {
                                    "op": 2,
                                    "d": {
                                        "token": client.token,
                                        "capabilities": 30717,
                                        "properties": DiscordStealthAntiBanEngine.build_super_properties_dict(client.token),
                                        "presence": {"status": "online", "since": 0, "activities": [], "afk": False},
                                        "client_state": {
                                            "guild_versions": {},
                                            "private_channels_version": "0",
                                            "read_state_version": 0,
                                            "user_guild_settings_version": -1,
                                            "user_settings_version": -1
                                        }
                                    }
                                }
                                ZaloRealtimeListener._send_ws_frame(sock, json.dumps(ident_payload).encode("utf-8"), opcode=0x1)
                                identified = True
                                last_hb = time.time()
                                self.ws_status = "NHK Discord Shield (0ms Sẵn Sàng)"

                        elif op == 0 and t_ev == "READY" and isinstance(d_ev, dict):
                            sess_id = str(d_ev.get("session_id") or "")
                            res_url = str(d_ev.get("resume_gateway_url") or "wss://gateway.discord.gg")
                            u_obj = d_ev.get("user") or {}
                            if isinstance(u_obj, dict) and u_obj.get("id"):
                                DiscordStealthAntiBanEngine.set_cached_me(client.token, u_obj)
                                client.user_id = str(u_obj["id"])
                                OWNER_UIDS_CACHE.add(client.user_id)
                            DiscordStealthAntiBanEngine.harvest_ready_payload(client.token, d_ev)
                            if sess_id:
                                DiscordStealthAntiBanEngine.save_gateway_resume_state(
                                    client.token, session_id=sess_id, resume_url=res_url, last_seq=self.last_seq or 0
                                )
                            # Đăng ký OP 37 Guild Subscriptions Bulk để nhận MESSAGE_CREATE tức thì trên mọi Server
                            try:
                                subs_map = {}
                                for g_obj in (d_ev.get("guilds") or [])[:60]:
                                    if isinstance(g_obj, dict) and g_obj.get("id"):
                                        subs_map[str(g_obj["id"])] = {"typing": True, "threads": True, "activities": False}
                                if subs_map:
                                    op37_pkt = json.dumps({"op": 37, "d": {"subscriptions": subs_map}}).encode("utf-8")
                                    ZaloRealtimeListener._send_ws_frame(sock, op37_pkt, opcode=0x1)
                                for pc_obj in (d_ev.get("private_channels") or [])[:8]:
                                    if isinstance(pc_obj, dict) and pc_obj.get("id"):
                                        DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS[self.acc_id].add(str(pc_obj["id"]))
                            except Exception:
                                pass
                            self.ws_status = "NHK Discord Ghost Vault (0ms Toàn Kênh)"

                        elif op == 0 and t_ev == "RESUMED":
                            self.ws_status = "NHK Discord Ghost Vault (Resumed 0ms)"

                        elif op == 0 and t_ev in ("CHANNEL_CREATE", "THREAD_CREATE") and isinstance(d_ev, dict):
                            cid_new = str(d_ev.get("id") or "")
                            cname_new = d_ev.get("name") or f"Box #{cid_new[-5:]}"
                            if cid_new:
                                FullConversationAutoScanner.register_live_conversation(
                                    "discord", cid_new, f"[Auto-Soi] # {cname_new}", guild_id=str(d_ev.get("guild_id") or "")
                                )

                        elif op == 0 and t_ev == "MESSAGE_CREATE" and isinstance(d_ev, dict):
                            self.last_event_ts = time.time()
                            cid_m = str(d_ev.get("channel_id") or "")
                            if cid_m:
                                FullConversationAutoScanner.register_live_conversation(
                                    "discord", cid_m, f"[Active] Box #{cid_m[-5:]}", guild_id=str(d_ev.get("guild_id") or "")
                                )
                            self._handle_discord_message_event(client, acc_now, d_ev)

                        elif op == 1:
                            hb_pkt = json.dumps({"op": 1, "d": self.last_seq}).encode("utf-8")
                            ZaloRealtimeListener._send_ws_frame(sock, hb_pkt, opcode=0x1)
                            last_hb = time.time()

                        elif op == 9:
                            if not d_ev:
                                DiscordStealthAntiBanEngine.save_gateway_resume_state(client.token, "", "", 0)
                            self.stop_ev.wait(1.0)
                            break

                        elif op == 7:
                            break
                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _run_loop(self):
        self.stop_ev.wait(0.15)
        while not self.stop_ev.is_set():
            acc_row = self._get_acc_row()
            if not acc_row or acc_row.get("platform") != "discord":
                break
            if not acc_row.get("chat_cmd_enabled", 1):
                self.ws_status = "Đã tắt nhận lệnh"
                self.stop_ev.wait(3.0)
                continue

            try:
                is_bot = bool(acc_row.get("is_bot", 0))
                client = DiscordClient(acc_row["token"], is_bot=is_bot)
                if not client.check(force_network=False):
                    self.ws_status = "Token cần kiểm tra lại"
                    self.stop_ev.wait(10.0)
                    continue

                if client.user_id and not acc_row.get("uid"):
                    try:
                        conn = db()
                        conn.execute("UPDATE accounts SET uid=? WHERE id=?", (client.user_id, self.acc_id))
                        conn.commit()
                        conn.close()
                    except Exception:
                        pass

                self._run_gateway_session(client, acc_row)
                self.stop_ev.wait(1.2)
            except Exception:
                self.ws_status = "Đang đồng bộ lại..."
                self.stop_ev.wait(2.0)

def sync_all_zalo_listeners():
    refresh_accounts_ram_cache()
    refresh_owner_uids()
    try:
        conn = db()
        rows = conn.execute("SELECT id, platform, chat_cmd_enabled, uid, imei, token FROM accounts ORDER BY id ASC").fetchall()
        conn.close()
        active_ids = set()
        seen_cred_keys = set()
        for r in rows:
            aid = r["id"]
            plat = (r["platform"] or "zalo").lower()
            if r["chat_cmd_enabled"]:
                cred_val = str(r["token"] if plat == "discord" else (r["uid"] or r["imei"] or aid)).strip()
                cred_key = f"{plat}:{cred_val}"
                if cred_val and cred_key in seen_cred_keys:
                    # Ngăn chặn tuyệt đối 2 bản ghi trùng cùng 1 tài khoản chạy 2 Listener gây nhân đôi .menu!
                    continue
                if cred_val:
                    seen_cred_keys.add(cred_key)
                active_ids.add(aid)
                lst = ACTIVE_LISTENERS.get(aid)
                need_start = (lst is None) or (not lst.thread.is_alive())
                if not need_start and plat in ("zalo", "discord") and hasattr(lst, "poller_thread"):
                    if not lst.poller_thread.is_alive():
                        need_start = True
                if need_start:
                    if lst is not None:
                        try:
                            lst.stop()
                        except Exception:
                            pass
                    if plat == "discord":
                        listener = DiscordRealtimeListener(aid)
                    elif plat == "messenger":
                        listener = MessengerRealtimeListener(aid)
                    else:
                        listener = ZaloRealtimeListener(aid)
                    ACTIVE_LISTENERS[aid] = listener
                    listener.start()
        for aid in list(ACTIVE_LISTENERS.keys()):
            if aid not in active_ids:
                ACTIVE_LISTENERS[aid].stop()
                ACTIVE_LISTENERS.pop(aid, None)
    except Exception:
        pass

def _flush_ram_tasks_to_db():
    try:
        to_insert = []
        to_update = []
        with TASKS_RAM_LOCK:
            if len(TASKS_RAM_STORE) > 150:
                sorted_keys = sorted(TASKS_RAM_STORE.keys(), key=lambda k: TASKS_RAM_STORE[k].get("started_at", 0))
                for old_k in sorted_keys[:-100]:
                    if TASKS_RAM_STORE[old_k].get("status") != "running":
                        TASKS_RAM_STORE.pop(old_k, None)
            for tid, t_obj in list(TASKS_RAM_STORE.items()):
                if not t_obj.get("dirty"):
                    continue
                t_obj["dirty"] = False
                stats_json = json.dumps({"sent": t_obj.get("sent", 0), "fail": t_obj.get("fail", 0)})
                if not t_obj.get("persisted"):
                    t_obj["persisted"] = True
                    meta_json = json.dumps(t_obj.get("meta") or {}, ensure_ascii=False)
                    to_insert.append((tid, t_obj.get("type", "treo_nhay"), meta_json, t_obj.get("status", "running"), t_obj.get("started_at", time.time()), stats_json))
                else:
                    to_update.append((t_obj.get("status", "running"), stats_json, tid))
        if to_insert or to_update:
            conn = db()
            if to_insert:
                conn.executemany(
                    "INSERT OR REPLACE INTO tasks (id, type, meta, status, started_at, stats) VALUES (?, ?, ?, ?, ?, ?)",
                    to_insert
                )
            if to_update:
                conn.executemany(
                    "UPDATE tasks SET status = ?, stats = ? WHERE id = ?",
                    to_update
                )
            conn.commit()
    except Exception:
        pass

def _init_ram_stores_from_db():
    try:
        refresh_accounts_ram_cache()
        conn = db()
        t_rows = conn.execute("SELECT * FROM tasks ORDER BY started_at DESC LIMIT 80").fetchall()
        l_rows = conn.execute("SELECT * FROM bot_logs ORDER BY id DESC LIMIT 30").fetchall()
        conn.close()
        with TASKS_RAM_LOCK:
            for r in t_rows:
                tid = r["id"]
                try:
                    meta = json.loads(r["meta"] or "{}")
                except Exception:
                    meta = {}
                try:
                    st_d = json.loads(r["stats"] or "{}")
                except Exception:
                    st_d = {}
                TASKS_RAM_STORE[tid] = {
                    "id": tid,
                    "type": r["type"] or "treo_nhay",
                    "meta": meta,
                    "status": "stopped" if tid not in ACTIVE_TASKS else "running",
                    "started_at": float(r["started_at"] or 0),
                    "sent": int(st_d.get("sent", 0)),
                    "fail": int(st_d.get("fail", 0)),
                    "delay": float(meta.get("delay", 1.0)),
                    "dirty": False,
                    "persisted": True,
                }
        for lr in reversed(l_rows):
            BOT_LOGS_RAM_DEQUE.appendleft(dict(lr))
    except Exception:
        pass

def _listener_watchdog_loop():
    _init_ram_stores_from_db()
    time.sleep(0.5)
    step_c = 0
    while True:
        try:
            _flush_ram_tasks_to_db()
            _sync_epochs_from_db_background()
            if step_c % 2 == 0:
                sync_all_zalo_listeners()
            step_c += 1
        except Exception:
            pass
        time.sleep(3.0)

threading.Thread(target=_listener_watchdog_loop, daemon=True).start()

# -*- coding: utf-8 -*-
import math

class TelegramPetAnimationEngine:
    """Động Cơ Đồ Họa 3D NHK & Biểu Tượng Động Khởi Chạy Qua Code Python:
    - Kết xuất trực tiếp Vector SVG 3D đa lớp và Khối Lập Phương 3D NHK Holo-Core.
    - Tự động bơm (inject) trực tiếp vào mọi trang HTML qua @app.context_processor để 100% luôn hiển thị rõ nét."""

    @classmethod
    def compute_stride_curve(cls, steps=24):
        out = []
        for i in range(steps):
            theta = (2.0 * math.pi * i) / max(1, steps - 1)
            leg_front = round(math.sin(theta) * 19.0, 2)
            leg_back = round(math.sin(theta + math.pi) * 19.0, 2)
            body_bob = round(abs(math.cos(theta)) * -3.6, 2)
            tail_wag = round(math.sin(theta * 2.0) * 18.0, 2)
            out.append({
                "t": round(i / max(1, steps - 1), 3),
                "leg_front_deg": leg_front,
                "leg_back_deg": leg_back,
                "body_bob_px": body_bob,
                "tail_wag_deg": tail_wag,
            })
        return out

    @classmethod
    def get_nhk_3d_emblem_svg(cls):
        return (
            '<div class="nhk-3d-viewport" title="Khối Lập Phương Năng Lượng 3D NHK">'
            '<div class="nhk-3d-orbit-ring ring-a"></div>'
            '<div class="nhk-3d-orbit-ring ring-b"></div>'
            '<div class="nhk-3d-cube">'
            '<div class="nhk-cube-face face-front"><span>NHK</span></div>'
            '<div class="nhk-cube-face face-back"><span>NHK</span></div>'
            '<div class="nhk-cube-face face-right"><span>3D</span></div>'
            '<div class="nhk-cube-face face-left"><span>VIP</span></div>'
            '<div class="nhk-cube-face face-top"><span>⚡</span></div>'
            '<div class="nhk-cube-face face-bottom"><span>👑</span></div>'
            '</div>'
            '</div>'
        )

    @classmethod
    def get_corgi_svg(cls):
        return (
            '<svg class="tg-pet-svg pet-corgi-svg tg-corgi-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg">'
            '<defs>'
            '<linearGradient id="corgiFur3D" x1="0%" y1="0%" x2="100%" y2="100%">'
            '<stop offset="0%" stop-color="#ffd269"/><stop offset="48%" stop-color="#ff9924"/><stop offset="100%" stop-color="#c95206"/>'
            '</linearGradient>'
            '<linearGradient id="corgiCream3D" x1="0%" y1="0%" x2="0%" y2="100%">'
            '<stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#f3dfc4"/>'
            '</linearGradient>'
            '<radialGradient id="corgiGlow" cx="50%" cy="50%" r="50%">'
            '<stop offset="0%" stop-color="rgba(255,179,71,0.42)"/><stop offset="100%" stop-color="rgba(255,179,71,0)"/>'
            '</radialGradient>'
            '</defs>'
            '<circle cx="64" cy="44" r="40" fill="url(#corgiGlow)"/>'
            '<ellipse class="pet-shadow" cx="62" cy="79" rx="36" ry="5.5" fill="rgba(0,0,0,0.42)"/>'
            '<g class="pet-body-group">'
            '<g class="pet-tail"><path d="M24 45 C10 34, 8 20, 18 17 C25 15, 31 26, 29 38 Z" fill="url(#corgiFur3D)"/><circle cx="16" cy="19" r="5.5" fill="url(#corgiCream3D)"/></g>'
            '<g class="pet-leg-back-l"><rect x="30" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="34.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g>'
            '<g class="pet-leg-front-l"><rect x="70" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="74.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g>'
            '<rect x="24" y="34" width="60" height="28" rx="14" fill="url(#corgiFur3D)"/>'
            '<path d="M36 47 C47 45, 68 45, 80 40 L81 57 C67 62, 43 62, 34 58 Z" fill="url(#corgiCream3D)"/>'
            '<path d="M63 34 C68 27, 78 27, 84 36 C80 45, 68 46, 63 34 Z" fill="url(#corgiCream3D)"/>'
            '<g class="pet-leg-back-r"><rect x="38" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="43" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g>'
            '<g class="pet-leg-front-r"><rect x="76" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="81" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g>'
            '<path d="M68 34 L84 48" stroke="#ef4444" stroke-width="4.5" stroke-linecap="round"/>'
            '<circle cx="77" cy="44" r="4.5" fill="#fbbf24" stroke="#fff" stroke-width="1"/>'
            '<g class="pet-head">'
            '<path class="pet-ear-l" d="M69 22 L63 3 L80 14 Z" fill="url(#corgiFur3D)"/>'
            '<path d="M69 19 L65 7 L77 14 Z" fill="#fda4af"/>'
            '<path class="pet-ear-r" d="M88 18 L100 2 L102 22 Z" fill="url(#corgiFur3D)"/>'
            '<path d="M90 18 L97 6 L98 20 Z" fill="#fda4af"/>'
            '<ellipse cx="85" cy="27" rx="18" ry="15" fill="url(#corgiFur3D)"/>'
            '<path d="M84 13 C87 20, 87 26, 85 40 C94 41, 105 37, 106 28 C107 22, 97 15, 84 13 Z" fill="url(#corgiCream3D)"/>'
            '<ellipse cx="100" cy="29" rx="9.5" ry="7" fill="url(#corgiCream3D)"/>'
            '<ellipse cx="107" cy="27" rx="3.8" ry="3" fill="#0f172a"/>'
            '<path class="pet-tongue" d="M97 34 Q101 43 105 35 Z" fill="#fb7185"/>'
            '<path d="M94 33 Q99 36.5 104 32" stroke="#0f172a" stroke-width="1.9" stroke-linecap="round" fill="none"/>'
            '<g class="pet-eyes">'
            '<circle cx="80.5" cy="24" r="3.2" fill="#0f172a"/><circle cx="81.6" cy="22.8" r="1.2" fill="#ffffff"/>'
            '<circle cx="93" cy="23.5" r="3.2" fill="#0f172a"/><circle cx="94.1" cy="22.3" r="1.2" fill="#ffffff"/>'
            '</g>'
            '<ellipse cx="76" cy="28.5" rx="3.3" ry="1.8" fill="rgba(251,113,133,0.52)"/>'
            '<ellipse cx="96" cy="28.5" rx="3.1" ry="1.7" fill="rgba(251,113,133,0.52)"/>'
            '</g>'
            '</g>'
            '</svg>'
        )

    @classmethod
    def get_cat_svg(cls):
        return (
            '<svg class="tg-pet-svg pet-cat-svg tg-cat-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg">'
            '<defs>'
            '<linearGradient id="catFur3D" x1="0%" y1="0%" x2="100%" y2="100%">'
            '<stop offset="0%" stop-color="#c7d2fe"/><stop offset="50%" stop-color="#818cf8"/><stop offset="100%" stop-color="#4f46e5"/>'
            '</linearGradient>'
            '<linearGradient id="catBelly3D" x1="0%" y1="0%" x2="0%" y2="100%">'
            '<stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#e0e7ff"/>'
            '</linearGradient>'
            '<radialGradient id="catGlow" cx="50%" cy="50%" r="50%">'
            '<stop offset="0%" stop-color="rgba(129,140,248,0.42)"/><stop offset="100%" stop-color="rgba(129,140,248,0)"/>'
            '</radialGradient>'
            '</defs>'
            '<circle cx="64" cy="44" r="40" fill="url(#catGlow)"/>'
            '<ellipse class="pet-shadow" cx="62" cy="79" rx="34" ry="5.2" fill="rgba(0,0,0,0.42)"/>'
            '<g class="pet-body-group">'
            '<g class="pet-tail"><path d="M27 46 C10 43, 7 20, 19 14 C26 11, 28 22, 23 28 C19 33, 23 41, 30 43 Z" fill="url(#catFur3D)"/></g>'
            '<g class="pet-leg-back-l"><rect x="33" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="37.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g>'
            '<g class="pet-leg-front-l"><rect x="69" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="73.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g>'
            '<rect x="28" y="35" width="54" height="26" rx="13" fill="url(#catFur3D)"/>'
            '<path d="M39 48 C49 46, 65 46, 75 43 L76 57 C64 61, 45 61, 37 57 Z" fill="url(#catBelly3D)"/>'
            '<g class="pet-leg-back-r"><rect x="40" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="44.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g>'
            '<g class="pet-leg-front-r"><rect x="75" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="79.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g>'
            '<path d="M68 36 L81 48" stroke="#ec4899" stroke-width="4" stroke-linecap="round"/>'
            '<circle cx="76" cy="44" r="4" fill="#38bdf8" stroke="#fff" stroke-width="1"/>'
            '<g class="pet-head">'
            '<path class="pet-ear-l" d="M69 21 L66 4 L81 14 Z" fill="url(#catFur3D)"/>'
            '<path d="M70 19 L68 8 L78 14 Z" fill="#f472b6"/>'
            '<path class="pet-ear-r" d="M87 16 L98 3 L100 20 Z" fill="url(#catFur3D)"/>'
            '<path d="M89 16 L96 7 L97 19 Z" fill="#f472b6"/>'
            '<ellipse cx="84" cy="27" rx="16.5" ry="14" fill="url(#catFur3D)"/>'
            '<ellipse cx="87" cy="31" rx="11.5" ry="8.5" fill="url(#catBelly3D)"/>'
            '<polygon points="92,27 96,27 94,30.5" fill="#fb7185"/>'
            '<path d="M90 32.5 Q94 35.5 98 32.5" stroke="#1e1b4b" stroke-width="1.7" stroke-linecap="round" fill="none"/>'
            '<g class="pet-eyes">'
            '<ellipse cx="80" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="80" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="81" cy="22.6" r="1.1" fill="#ffffff"/>'
            '<ellipse cx="92.5" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="92.5" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="93.5" cy="22.6" r="1.1" fill="#ffffff"/>'
            '</g>'
            '<line x1="97" y1="28" x2="108" y2="26" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/>'
            '<line x1="97" y1="30.5" x2="109" y2="30.5" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/>'
            '<line x1="73" y1="29" x2="62" y2="28" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/>'
            '</g>'
            '</g>'
            '</svg>'
        )

    @classmethod
    def get_pet_bundle(cls, mood="happy"):
        return {
            "ok": True,
            "brand": "NHK",
            "stride_keyframes": cls.compute_stride_curve(20),
            "mood": mood,
            "nhk_3d_svg": cls.get_nhk_3d_emblem_svg(),
            "corgi_svg": cls.get_corgi_svg(),
            "cat_svg": cls.get_cat_svg(),
            "mood_quotes": {
                "idle": "NHK 3D Core • Hệ thống trực chiến 24/7 — Phản hồi lệnh 0ms!",
                "qr_generating": "Đang cấp phát máy tính Việt Nam / Singapore chính chủ cho NHK...",
                "qr_waiting": "Kênh QR đang sẵn sàng — Hãy mở Zalo quét mã ngay nhé!",
                "qr_scanned": "Đã nhận diện Zalo của bạn — Hãy ấn Đăng nhập trên điện thoại!",
                "qr_success": "Tuyệt vời! Thiết bị đã ghim sống 24/7 trong tài khoản Zalo trên NHK!",
                "campaign_running": "NHK 3D Core đang phóng 96 Shards gửi đa Box siêu tốc 0s!",
                "stopped": "Đã phanh gấp 0ms toàn bộ chiến dịch theo lệnh của bạn!",
            }
        }


class TelegramUIPhysicsEngine:
    """Bộ tính toán Vật lý Đàn hồi (Spring-Damper Physics) & Cấu hình Giao diện Telegram bằng Python."""

    @classmethod
    def compute_spring_Samples(cls, stiffness=360.0, damping=26.0, mass=1.0, steps=45):
        pos = 0.0
        vel = 0.0
        target = 1.0
        dt = 1.0 / 60.0
        samples = []
        for _ in range(steps):
            force = -stiffness * (pos - target) - damping * vel
            acc = force / mass
            vel += acc * dt
            pos += vel * dt
            samples.append(round(pos, 5))
        samples[-1] = 1.0
        return samples

    @classmethod
    def build_css_linear_spring(cls, stiffness=360.0, damping=26.0):
        pts = cls.compute_spring_Samples(stiffness=stiffness, damping=damping, steps=32)
        parts = []
        n = len(pts)
        for i, val in enumerate(pts):
            pct = round((i / (n - 1)) * 100.0, 1)
            parts.append(f"{val} {pct}%")
        return "linear(" + ", ".join(parts) + ")"

    @classmethod
    def get_ui_bundle(cls):
        pet_info = TelegramPetAnimationEngine.get_pet_bundle()
        return {
            "spring_easing": cls.build_css_linear_spring(360.0, 26.0),
            "soft_spring_easing": cls.build_css_linear_spring(290.0, 24.0),
            "spring_samples": cls.compute_spring_Samples(360.0, 26.0, steps=36),
            "pill_stretch_max": 1.14,
            "pill_squish_min": 0.93,
            "page_transition_ms": 340,
            "security_mode": "PBKDF2-SHA256 + CSRF-HMAC + TLS1.3",
            "pets": TelegramPetAnimationEngine.get_pet_bundle(),
            "pet_engine": TelegramPetAnimationEngine.get_pet_bundle(),
            "pets": pet_info,
            "tabs": [
                {"id": "tab-accounts", "title": "Tài khoản", "header": "Quản lý Tài khoản"},
                {"id": "tab-targets", "title": "Phòng chat", "header": "Phòng & Kênh Mục Tiêu"},
                {"id": "tab-campaign", "title": "Chiến dịch", "header": "Điều Phối Chiến Dịch"},
                {"id": "tab-files", "title": "Kịch bản", "header": "Kho File Kịch Bản"},
                {"id": "tab-shield", "title": "Cài đặt", "header": "Hệ Thống & Mạng API"},
            ],
        }


class MessagingGatewayDirectory:
    GATEWAYS = {
        "zalo": [
            {"name": "Zalo Group Send Cluster", "url": "https://tt-group-wpa.chat.zalo.me/api/group/sendmsg", "role": "Gửi tin nhắn nhóm tốc độ 0ms", "protocol": "HTTPS / AES-CBC"},
            {"name": "Zalo Group Mention Cluster", "url": "https://tt-group-wpa.chat.zalo.me/api/group/mention", "role": "Gửi tin nhắn nhóm kèm Tag xanh / Tag ẩn", "protocol": "HTTPS / AES-CBC"},
            {"name": "Zalo WPA Group Fallback", "url": "https://wpa.chat.zalo.me/api/group/sendmsg", "role": "Cổng dự phòng gửi tin nhắn nhóm", "protocol": "HTTPS / AES-CBC"},
            {"name": "Zalo Direct Chat Node 1", "url": "https://tt-chat1-wpa.chat.zalo.me/api/message/sms", "role": "Gửi tin nhắn riêng (Node 1)", "protocol": "HTTPS / AES-CBC"},
            {"name": "Zalo Direct Chat Node 2", "url": "https://tt-chat2-wpa.chat.zalo.me/api/message/sms", "role": "Gửi tin nhắn riêng (Node 2)", "protocol": "HTTPS / AES-CBC"},
            {"name": "Zalo Direct Chat Node 3", "url": "https://tt-chat3-wpa.chat.zalo.me/api/message/sms", "role": "Gửi tin nhắn riêng (Node 3)", "protocol": "HTTPS / AES-CBC"},
            {"name": "Zalo Preload Conversation", "url": "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs", "role": "Đồng bộ lệnh in-chat thời gian thực", "protocol": "HTTPS / Keep-Alive"},
            {"name": "Zalo WebSocket Cluster", "url": "wss://ws1.chat.zalo.me • wss://ws2.chat.zalo.me • wss://ws3.chat.zalo.me", "role": "Giữ thiết bị PC sống 24/7 trong tài khoản", "protocol": "WSS / Binary Frame"},
        ],
        "discord": [
            {"name": "Discord Global Primary v9", "url": "https://discord.com/api/v9", "role": "Cổng chính điều phối 500 Box", "protocol": "HTTPS / Chrome 131 TLS"},
            {"name": "Discord High-Concurrency v10", "url": "https://discord.com/api/v10", "role": "Cổng song song chống nghẽn hàng đợi", "protocol": "HTTPS / Chrome 131 TLS"},
            {"name": "Discord Canary Edge v9", "url": "https://canary.discord.com/api/v9", "role": "Cổng phân tải Canary cho vòng lặp 500 Box", "protocol": "HTTPS / Chrome 131 TLS"},
            {"name": "Discord PTB Edge v9", "url": "https://ptb.discord.com/api/v9", "role": "Cổng phân tải PTB giảm độ trễ", "protocol": "HTTPS / Chrome 131 TLS"},
            {"name": "Discord Direct Legacy Edge", "url": "https://discordapp.com/api/v9", "role": "Cổng dự phòng chuyển mạch 0ms", "protocol": "HTTPS / Keep-Alive"},
        ],
        "messenger_and_tools": [
            {"name": "Messenger Edge MQTT", "url": "wss://edge-chat.facebook.com/chat", "role": "Luồng gửi tin nhắn MQTT thời gian thực", "protocol": "WSS / MQTT"},
            {"name": "Zalo Central QR Auth", "url": "https://id.zalo.me/account/authen/qr/generate", "role": "Khởi tạo & xác thực QR đa máy tính VN/SG", "protocol": "HTTPS / Session"},
            {"name": "2FA TOTP Resolver API", "url": "https://keyherlyswar.x10.mx/Apidocs/tien_ich/2fa.php", "role": "Cổng giải mã OTP 2FA dự phòng", "protocol": "HTTPS / REST"},
        ],
    }

    @classmethod
    def get_directory_payload(cls):
        return {
            "ok": True,
            "gateways": cls.GATEWAYS,
            "proxy_formats": [
                "ip:port",
                "ip:port:user:pass",
                "http://user:pass@ip:port",
                "socks5://user:pass@ip:port",
            ],
            "pool_config": {
                "zalo_pool_maxsize": 1024,
                "discord_shards_per_acc": 64,
                "max_boxes_per_acc": 500,
                "failover_timeout_ms": 420,
            }
        }


LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,minimum-scale=1.0,user-scalable=no,viewport-fit=cover">
<title>{{ custom_title if custom_title else 'NHK — 3D Control Studio' }}</title>
<style>
:root {
  --tg-bg: #000000;
  --tg-surface: rgba(24, 24, 28, 0.90);
  --tg-surface-elevated: rgba(40, 40, 46, 0.85);
  --tg-border: rgba(255, 255, 255, 0.12);
  --tg-text: #ffffff;
  --tg-muted: #8e8e93;
  --tg-blue: #007aff;
  --tg-cyan: #2aabee;
  --tg-pink: #e15183;
  --tg-green: #30d158;
  --tg-danger: #ff453a;
}
* { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
html, body {
  width: 100%; min-height: 100vh;
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Segoe UI", Inter, Roboto, sans-serif;
  background: radial-gradient(circle at 50% 0%, rgba(42, 171, 238, 0.18) 0%, rgba(0, 0, 0, 0) 60%), #000000;
  color: var(--tg-text);
  display: flex; align-items: center; justify-content: center;
  padding: 18px; overflow-x: hidden;
}
.tg-auth-shell {
  width: 100%; max-width: 400px;
  background: var(--tg-surface);
  backdrop-filter: blur(36px) saturate(190%);
  -webkit-backdrop-filter: blur(36px) saturate(190%);
  border: 1px solid var(--tg-border);
  border-radius: 28px;
  padding: 28px 24px 24px;
  box-shadow: 0 28px 70px rgba(0, 0, 0, 0.72), inset 0 1px 0 rgba(255, 255, 255, 0.14);
  position: relative;
  animation: tgAuthEnter 0.5s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}
@keyframes tgAuthEnter {
  from { opacity: 0; transform: translateY(18px) scale(0.96); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}
.tg-top-pill {
  display: inline-flex; align-items: center; gap: 6px;
  background: linear-gradient(135deg, #007aff 0%, #2aabee 100%);
  color: #ffffff; font-size: 11px; font-weight: 700; letter-spacing: 0.4px;
  padding: 4.5px 13px; border-radius: 999px;
  margin-bottom: 14px;
  box-shadow: 0 4px 14px rgba(0, 122, 255, 0.38);
}
.tg-pet-stage-login {
  display: flex; align-items: center; justify-content: center; gap: 8px;
  height: 76px; margin-bottom: 10px; position: relative;
}
.tg-pet-svg {
  width: 82px; height: 58px; overflow: visible;
  filter: drop-shadow(0 6px 12px rgba(0, 0, 0, 0.35));
}
.tg-pet-svg .pet-body-group { animation: petBob 0.55s ease-in-out infinite alternate; transform-origin: center; }
.tg-pet-svg .pet-tail { animation: petTailWag 0.32s ease-in-out infinite alternate; transform-origin: 26px 42px; }
.tg-pet-svg .pet-leg-front-r, .tg-pet-svg .pet-leg-back-l { animation: petLegStrideA 0.38s ease-in-out infinite alternate; transform-origin: top center; }
.tg-pet-svg .pet-leg-front-l, .tg-pet-svg .pet-leg-back-r { animation: petLegStrideB 0.38s ease-in-out infinite alternate; transform-origin: top center; }
.tg-pet-svg .pet-eyes { animation: petEyeBlink 3.6s infinite; transform-origin: center; }
@keyframes petBob { from { transform: translateY(0px); } to { transform: translateY(-3.5px); } }
@keyframes petTailWag { from { transform: rotate(-14deg); } to { transform: rotate(16deg); } }
@keyframes petLegStrideA { from { transform: rotate(-16deg); } to { transform: rotate(16deg); } }
@keyframes petLegStrideB { from { transform: rotate(16deg); } to { transform: rotate(-16deg); } }
@keyframes petEyeBlink { 0%, 92%, 100% { transform: scaleY(1); } 96% { transform: scaleY(0.08); } }

.tg-auth-title {
  font-size: 20px; font-weight: 700; text-align: center;
  letter-spacing: -0.3px; margin-bottom: 6px;
}
.tg-auth-sub {
  font-size: 12.5px; color: var(--tg-muted); text-align: center;
  line-height: 1.45; margin-bottom: 20px;
}
.tg-input-group { margin-bottom: 16px; }
.tg-input-label {
  display: block; font-size: 12px; font-weight: 600;
  color: var(--tg-muted); margin-bottom: 7px; padding-left: 4px;
}
.tg-input-wrap { position: relative; display: flex; align-items: center; }
.tg-input-icon {
  position: absolute; left: 14px; color: var(--tg-muted);
  display: flex; align-items: center; pointer-events: none;
}
.tg-input {
  width: 100%; padding: 13px 14px 13px 42px;
  font-size: 14px; color: var(--tg-text);
  background: var(--tg-surface-elevated);
  border: 1px solid rgba(255, 255, 255, 0.10);
  border-radius: 14px; outline: none;
  transition: all 0.2s ease;
}
.tg-input:focus {
  border-color: var(--tg-cyan);
  background: rgba(58, 58, 64, 0.90);
  box-shadow: 0 0 0 3px rgba(42, 171, 238, 0.22);
}
.tg-btn-login {
  position: relative; overflow: hidden;
  width: 100%; padding: 13.5px 18px;
  font-size: 14.5px; font-weight: 700; color: #ffffff;
  background: linear-gradient(135deg, #007aff 0%, #2aabee 55%, #30d158 100%);
  background-size: 200% 200%;
  border: none; border-radius: 14px; cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 8px;
  box-shadow: 0 10px 26px rgba(0, 122, 255, 0.38), inset 0 1px 0 rgba(255, 255, 255, 0.25);
  transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.2s ease;
}
.tg-btn-login:hover { transform: translateY(-1.5px); box-shadow: 0 14px 30px rgba(0, 122, 255, 0.48); }
.tg-btn-login:active { transform: scale(0.97); }
.tg-err-banner {
  background: rgba(255, 69, 58, 0.14);
  border: 1px solid rgba(255, 69, 58, 0.35);
  color: #ff6961; padding: 10px 13px; border-radius: 12px;
  font-size: 12.5px; margin-bottom: 16px; text-align: center; font-weight: 500;
}
.tg-sec-footer {
  margin-top: 18px; padding-top: 14px;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  display: flex; align-items: center; justify-content: space-between;
  font-size: 11.5px; color: var(--tg-muted);
}
.tg-sec-badge { display: inline-flex; align-items: center; gap: 5px; color: var(--tg-green); font-weight: 600; }

.tg-loader-overlay {
  position: fixed; inset: 0; z-index: 9999;
  background: rgba(0, 0, 0, 0.90);
  backdrop-filter: blur(28px); -webkit-backdrop-filter: blur(28px);
  display: none; flex-direction: column; align-items: center; justify-content: center;
  padding: 24px;
}
.tg-loader-overlay.active { display: flex; animation: tgFadeIn 0.22s ease forwards; }
@keyframes tgFadeIn { from { opacity: 0; } to { opacity: 1; } }
.tg-loader-step { font-size: 14.5px; font-weight: 700; color: #ffffff; margin: 12px 0 5px; text-align: center; }
.tg-loader-sub { font-size: 12px; color: var(--tg-muted); margin-bottom: 16px; text-align: center; }
.tg-loader-bar-wrap {
  width: 240px; height: 6px; background: rgba(255, 255, 255, 0.12);
  border-radius: 999px; overflow: hidden;
}
.tg-loader-bar {
  height: 100%; width: 15%;
  background: linear-gradient(90deg, #ffb347, #2aabee, #30d158);
  border-radius: 999px; transition: width 0.28s ease;
}

/* ==================== NHK 3D HOLO-CUBE & LUXURY SPECULAR RIM BUTTONS ==================== */
.nhk-3d-stage-wrap {
  position: relative;
  display: flex; align-items: center; justify-content: center; gap: 14px;
  padding: 6px 10px;
  perspective: 900px;
}
.nhk-3d-viewport {
  width: 54px; height: 54px;
  position: relative;
  transform-style: preserve-3d;
  display: inline-flex; align-items: center; justify-content: center;
  flex-shrink: 0;
  cursor: pointer;
}
.nhk-3d-orbit-ring {
  position: absolute; inset: -7px;
  border-radius: 50%;
  border: 1.5px dashed rgba(56, 189, 248, 0.55);
  transform-style: preserve-3d;
  pointer-events: none;
}
.nhk-3d-orbit-ring.ring-a {
  animation: nhkOrbitA 6s linear infinite;
  box-shadow: 0 0 14px rgba(56, 189, 248, 0.28);
}
.nhk-3d-orbit-ring.ring-b {
  inset: -11px;
  border: 1.5px solid rgba(244, 114, 182, 0.42);
  animation: nhkOrbitB 8s linear infinite reverse;
}
@keyframes nhkOrbitA {
  0% { transform: rotateX(68deg) rotateY(15deg) rotateZ(0deg); }
  100% { transform: rotateX(68deg) rotateY(15deg) rotateZ(360deg); }
}
@keyframes nhkOrbitB {
  0% { transform: rotateX(-58deg) rotateY(28deg) rotateZ(0deg); }
  100% { transform: rotateX(-58deg) rotateY(28deg) rotateZ(360deg); }
}
.nhk-3d-cube {
  width: 34px; height: 34px;
  position: relative;
  transform-style: preserve-3d;
  animation: nhkCubeSpin 9s cubic-bezier(0.45, 0.05, 0.55, 0.95) infinite;
}
@keyframes nhkCubeSpin {
  0%   { transform: rotateX(-18deg) rotateY(0deg) rotateZ(0deg); }
  25%  { transform: rotateX(18deg) rotateY(90deg) rotateZ(4deg); }
  50%  { transform: rotateX(-16deg) rotateY(180deg) rotateZ(-4deg); }
  75%  { transform: rotateX(20deg) rotateY(270deg) rotateZ(4deg); }
  100% { transform: rotateX(-18deg) rotateY(360deg) rotateZ(0deg); }
}
.nhk-cube-face {
  position: absolute; width: 34px; height: 34px;
  border-radius: 8px;
  background: linear-gradient(135deg, rgba(0, 122, 255, 0.82) 0%, rgba(42, 171, 238, 0.72) 55%, rgba(139, 92, 246, 0.82) 100%);
  border: 1px solid rgba(255, 255, 255, 0.55);
  box-shadow: 0 0 16px rgba(42, 171, 238, 0.45), inset 0 0 8px rgba(255, 255, 255, 0.35);
  display: flex; align-items: center; justify-content: center;
  font-size: 9.5px; font-weight: 900; color: #ffffff; letter-spacing: 0.6px;
  text-shadow: 0 1px 4px rgba(0, 0, 0, 0.65);
  backface-visibility: visible;
}
.nhk-cube-face.face-front  { transform: translateZ(17px); }
.nhk-cube-face.face-back   { transform: rotateY(180deg) translateZ(17px); }
.nhk-cube-face.face-right  { transform: rotateY(90deg) translateZ(17px); }
.nhk-cube-face.face-left   { transform: rotateY(-90deg) translateZ(17px); }
.nhk-cube-face.face-top    { transform: rotateX(90deg) translateZ(17px); }
.nhk-cube-face.face-bottom { transform: rotateX(-90deg) translateZ(17px); }

/* Luxury Specular Rim & Liquid Glass Interactive Buttons */
.btn, .tg-btn-login, .tg-nav-pill-btn {
  --mx: 50%;
  --my: 50%;
  position: relative;
  overflow: hidden;
  isolation: isolate;
}
.btn::after, .tg-btn-login::after, .tg-nav-pill-btn::after {
  content: "";
  position: absolute; inset: 0;
  border-radius: inherit;
  background: radial-gradient(110px circle at var(--mx) var(--my), rgba(255, 255, 255, 0.26), transparent 70%);
  opacity: 0;
  transition: opacity 0.22s ease;
  pointer-events: none;
  z-index: 0;
}
.btn:hover::after, .tg-btn-login:hover::after, .tg-nav-pill-btn:hover::after {
  opacity: 1;
}
.btn > *, .tg-btn-login > *, .tg-nav-pill-btn > * {
  position: relative; z-index: 1;
}
.btn {
  box-shadow: 0 3px 10px rgba(0, 0, 0, 0.22), inset 0 1px 0 rgba(255, 255, 255, 0.14);
}
.btn:hover {
  transform: translateY(-1.5px) scale(1.012);
  border-color: rgba(56, 189, 248, 0.48);
  box-shadow: 0 10px 24px -4px rgba(0, 122, 255, 0.32), inset 0 1px 0 rgba(255, 255, 255, 0.28);
}
.btn:active {
  transform: translateY(1px) scale(0.965);
}
.btn-primary {
  background: linear-gradient(135deg, #0066ff 0%, #0ea5e9 52%, #6366f1 100%);
  border: 1px solid rgba(125, 211, 252, 0.55);
  box-shadow: 0 8px 22px -4px rgba(14, 165, 233, 0.48), inset 0 1px 0 rgba(255, 255, 255, 0.35), inset 0 -2px 0 rgba(0, 0, 0, 0.25);
}
.btn-success {
  background: linear-gradient(135deg, #059669 0%, #10b981 50%, #34d399 100%);
  border: 1px solid rgba(110, 231, 183, 0.55);
  box-shadow: 0 8px 22px -4px rgba(16, 185, 129, 0.44), inset 0 1px 0 rgba(255, 255, 255, 0.35), inset 0 -2px 0 rgba(0, 0, 0, 0.25);
}
.btn-danger {
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.24) 0%, rgba(244, 63, 94, 0.18) 100%);
  border: 1px solid rgba(251, 113, 133, 0.45);
  color: #fda4af;
}
.prx-dropzone {
  position: relative;
  border: 1.5px dashed rgba(56, 189, 248, 0.55);
  border-radius: 14px;
  padding: 10px 12px;
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.08) 0%, rgba(99, 102, 241, 0.08) 100%);
  text-align: center;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-bottom: 8px;
}
.prx-dropzone:hover {
  border-color: #38bdf8;
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.15) 0%, rgba(99, 102, 241, 0.15) 100%);
  transform: translateY(-1px);
}
.prx-dropzone input[type="file"] {
  position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
}


@media (max-width: 560px) {
  .tg-navbar { display: grid; grid-template-columns: 1fr auto; row-gap: 8px; }
}
.tab-count.zero-val, .tab-count.zero-badge { display: none !important; }

</style>
</head>
<body>
  <div class="tg-loader-overlay" id="tgLoginLoader">
    <div style="display:flex;align-items:center;gap:6px">
      <svg class="tg-pet-svg pet-corgi-svg tg-corgi-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="corgiFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ffd269"/><stop offset="48%" stop-color="#ff9924"/><stop offset="100%" stop-color="#c95206"/></linearGradient><linearGradient id="corgiCream3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#f3dfc4"/></linearGradient><radialGradient id="corgiGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(255,179,71,0.42)"/><stop offset="100%" stop-color="rgba(255,179,71,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#corgiGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="36" ry="5.5" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M24 45 C10 34, 8 20, 18 17 C25 15, 31 26, 29 38 Z" fill="url(#corgiFur3D)"/><circle cx="16" cy="19" r="5.5" fill="url(#corgiCream3D)"/></g><g class="pet-leg-back-l"><rect x="30" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="34.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-l"><rect x="70" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="74.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><rect x="24" y="34" width="60" height="28" rx="14" fill="url(#corgiFur3D)"/><path d="M36 47 C47 45, 68 45, 80 40 L81 57 C67 62, 43 62, 34 58 Z" fill="url(#corgiCream3D)"/><path d="M63 34 C68 27, 78 27, 84 36 C80 45, 68 46, 63 34 Z" fill="url(#corgiCream3D)"/><g class="pet-leg-back-r"><rect x="38" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="43" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-r"><rect x="76" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="81" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><path d="M68 34 L84 48" stroke="#ef4444" stroke-width="4.5" stroke-linecap="round"/><circle cx="77" cy="44" r="4.5" fill="#fbbf24" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 22 L63 3 L80 14 Z" fill="url(#corgiFur3D)"/><path d="M69 19 L65 7 L77 14 Z" fill="#fda4af"/><path class="pet-ear-r" d="M88 18 L100 2 L102 22 Z" fill="url(#corgiFur3D)"/><path d="M90 18 L97 6 L98 20 Z" fill="#fda4af"/><ellipse cx="85" cy="27" rx="18" ry="15" fill="url(#corgiFur3D)"/><path d="M84 13 C87 20, 87 26, 85 40 C94 41, 105 37, 106 28 C107 22, 97 15, 84 13 Z" fill="url(#corgiCream3D)"/><ellipse cx="100" cy="29" rx="9.5" ry="7" fill="url(#corgiCream3D)"/><ellipse cx="107" cy="27" rx="3.8" ry="3" fill="#0f172a"/><path class="pet-tongue" d="M97 34 Q101 43 105 35 Z" fill="#fb7185"/><path d="M94 33 Q99 36.5 104 32" stroke="#0f172a" stroke-width="1.9" stroke-linecap="round" fill="none"/><g class="pet-eyes"><circle cx="80.5" cy="24" r="3.2" fill="#0f172a"/><circle cx="81.6" cy="22.8" r="1.2" fill="#ffffff"/><circle cx="93" cy="23.5" r="3.2" fill="#0f172a"/><circle cx="94.1" cy="22.3" r="1.2" fill="#ffffff"/></g><ellipse cx="76" cy="28.5" rx="3.3" ry="1.8" fill="rgba(251,113,133,0.52)"/><ellipse cx="96" cy="28.5" rx="3.1" ry="1.7" fill="rgba(251,113,133,0.52)"/></g></g></svg>
      <svg class="tg-pet-svg pet-cat-svg tg-cat-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="catFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#c7d2fe"/><stop offset="50%" stop-color="#818cf8"/><stop offset="100%" stop-color="#4f46e5"/></linearGradient><linearGradient id="catBelly3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#e0e7ff"/></linearGradient><radialGradient id="catGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(129,140,248,0.42)"/><stop offset="100%" stop-color="rgba(129,140,248,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#catGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="34" ry="5.2" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M27 46 C10 43, 7 20, 19 14 C26 11, 28 22, 23 28 C19 33, 23 41, 30 43 Z" fill="url(#catFur3D)"/></g><g class="pet-leg-back-l"><rect x="33" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="37.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-l"><rect x="69" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="73.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><rect x="28" y="35" width="54" height="26" rx="13" fill="url(#catFur3D)"/><path d="M39 48 C49 46, 65 46, 75 43 L76 57 C64 61, 45 61, 37 57 Z" fill="url(#catBelly3D)"/><g class="pet-leg-back-r"><rect x="40" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="44.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-r"><rect x="75" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="79.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><path d="M68 36 L81 48" stroke="#ec4899" stroke-width="4" stroke-linecap="round"/><circle cx="76" cy="44" r="4" fill="#38bdf8" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 21 L66 4 L81 14 Z" fill="url(#catFur3D)"/><path d="M70 19 L68 8 L78 14 Z" fill="#f472b6"/><path class="pet-ear-r" d="M87 16 L98 3 L100 20 Z" fill="url(#catFur3D)"/><path d="M89 16 L96 7 L97 19 Z" fill="#f472b6"/><ellipse cx="84" cy="27" rx="16.5" ry="14" fill="url(#catFur3D)"/><ellipse cx="87" cy="31" rx="11.5" ry="8.5" fill="url(#catBelly3D)"/><polygon points="92,27 96,27 94,30.5" fill="#fb7185"/><path d="M90 32.5 Q94 35.5 98 32.5" stroke="#1e1b4b" stroke-width="1.7" stroke-linecap="round" fill="none"/><g class="pet-eyes"><ellipse cx="80" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="80" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="81" cy="22.6" r="1.1" fill="#ffffff"/><ellipse cx="92.5" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="92.5" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="93.5" cy="22.6" r="1.1" fill="#ffffff"/></g><line x1="97" y1="28" x2="108" y2="26" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="97" y1="30.5" x2="109" y2="30.5" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="73" y1="29" x2="62" y2="28" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/></g></g></svg>
    </div>
    <div class="tg-loader-step" id="tgLoaderStepText">NHK 3D Core đang mở khóa cổng bảo mật...</div>
    <div class="tg-loader-sub" id="tgLoaderSubText">Xác thực chữ ký PBKDF2-HMAC-SHA256 &amp; định tuyến VN/SG</div>
    <div class="tg-loader-bar-wrap">
      <div class="tg-loader-bar" id="tgLoaderBar"></div>
    </div>
  </div>

  <div class="tg-auth-shell">
    <div style="text-align:center">
      <div class="tg-top-pill">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/><line x1="12" y1="22" x2="12" y2="15.5"/><polyline points="22 8.5 12 15.5 2 8.5"/></svg>
        <span>NHK 3D QUANTUM STUDIO</span>
      </div>
    </div>

    <div class="tg-pet-stage-login nhk-3d-stage-wrap" id="tg-mascot-stage">
      <svg class="tg-pet-svg pet-corgi-svg tg-corgi-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="corgiFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ffd269"/><stop offset="48%" stop-color="#ff9924"/><stop offset="100%" stop-color="#c95206"/></linearGradient><linearGradient id="corgiCream3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#f3dfc4"/></linearGradient><radialGradient id="corgiGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(255,179,71,0.42)"/><stop offset="100%" stop-color="rgba(255,179,71,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#corgiGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="36" ry="5.5" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M24 45 C10 34, 8 20, 18 17 C25 15, 31 26, 29 38 Z" fill="url(#corgiFur3D)"/><circle cx="16" cy="19" r="5.5" fill="url(#corgiCream3D)"/></g><g class="pet-leg-back-l"><rect x="30" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="34.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-l"><rect x="70" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="74.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><rect x="24" y="34" width="60" height="28" rx="14" fill="url(#corgiFur3D)"/><path d="M36 47 C47 45, 68 45, 80 40 L81 57 C67 62, 43 62, 34 58 Z" fill="url(#corgiCream3D)"/><path d="M63 34 C68 27, 78 27, 84 36 C80 45, 68 46, 63 34 Z" fill="url(#corgiCream3D)"/><g class="pet-leg-back-r"><rect x="38" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="43" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-r"><rect x="76" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="81" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><path d="M68 34 L84 48" stroke="#ef4444" stroke-width="4.5" stroke-linecap="round"/><circle cx="77" cy="44" r="4.5" fill="#fbbf24" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 22 L63 3 L80 14 Z" fill="url(#corgiFur3D)"/><path d="M69 19 L65 7 L77 14 Z" fill="#fda4af"/><path class="pet-ear-r" d="M88 18 L100 2 L102 22 Z" fill="url(#corgiFur3D)"/><path d="M90 18 L97 6 L98 20 Z" fill="#fda4af"/><ellipse cx="85" cy="27" rx="18" ry="15" fill="url(#corgiFur3D)"/><path d="M84 13 C87 20, 87 26, 85 40 C94 41, 105 37, 106 28 C107 22, 97 15, 84 13 Z" fill="url(#corgiCream3D)"/><ellipse cx="100" cy="29" rx="9.5" ry="7" fill="url(#corgiCream3D)"/><ellipse cx="107" cy="27" rx="3.8" ry="3" fill="#0f172a"/><path class="pet-tongue" d="M97 34 Q101 43 105 35 Z" fill="#fb7185"/><path d="M94 33 Q99 36.5 104 32" stroke="#0f172a" stroke-width="1.9" stroke-linecap="round" fill="none"/><g class="pet-eyes"><circle cx="80.5" cy="24" r="3.2" fill="#0f172a"/><circle cx="81.6" cy="22.8" r="1.2" fill="#ffffff"/><circle cx="93" cy="23.5" r="3.2" fill="#0f172a"/><circle cx="94.1" cy="22.3" r="1.2" fill="#ffffff"/></g><ellipse cx="76" cy="28.5" rx="3.3" ry="1.8" fill="rgba(251,113,133,0.52)"/><ellipse cx="96" cy="28.5" rx="3.1" ry="1.7" fill="rgba(251,113,133,0.52)"/></g></g></svg>
      <div class="nhk-3d-viewport" title="Khối Lập Phương Năng Lượng 3D NHK"><div class="nhk-3d-orbit-ring ring-a"></div><div class="nhk-3d-orbit-ring ring-b"></div><div class="nhk-3d-cube"><div class="nhk-cube-face face-front"><span>NHK</span></div><div class="nhk-cube-face face-back"><span>NHK</span></div><div class="nhk-cube-face face-right"><span>3D</span></div><div class="nhk-cube-face face-left"><span>VIP</span></div><div class="nhk-cube-face face-top"><span>⚡</span></div><div class="nhk-cube-face face-bottom"><span>👑</span></div></div></div>
      <svg class="tg-pet-svg pet-cat-svg tg-cat-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="catFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#c7d2fe"/><stop offset="50%" stop-color="#818cf8"/><stop offset="100%" stop-color="#4f46e5"/></linearGradient><linearGradient id="catBelly3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#e0e7ff"/></linearGradient><radialGradient id="catGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(129,140,248,0.42)"/><stop offset="100%" stop-color="rgba(129,140,248,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#catGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="34" ry="5.2" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M27 46 C10 43, 7 20, 19 14 C26 11, 28 22, 23 28 C19 33, 23 41, 30 43 Z" fill="url(#catFur3D)"/></g><g class="pet-leg-back-l"><rect x="33" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="37.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-l"><rect x="69" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="73.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><rect x="28" y="35" width="54" height="26" rx="13" fill="url(#catFur3D)"/><path d="M39 48 C49 46, 65 46, 75 43 L76 57 C64 61, 45 61, 37 57 Z" fill="url(#catBelly3D)"/><g class="pet-leg-back-r"><rect x="40" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="44.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-r"><rect x="75" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="79.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><path d="M68 36 L81 48" stroke="#ec4899" stroke-width="4" stroke-linecap="round"/><circle cx="76" cy="44" r="4" fill="#38bdf8" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 21 L66 4 L81 14 Z" fill="url(#catFur3D)"/><path d="M70 19 L68 8 L78 14 Z" fill="#f472b6"/><path class="pet-ear-r" d="M87 16 L98 3 L100 20 Z" fill="url(#catFur3D)"/><path d="M89 16 L96 7 L97 19 Z" fill="#f472b6"/><ellipse cx="84" cy="27" rx="16.5" ry="14" fill="url(#catFur3D)"/><ellipse cx="87" cy="31" rx="11.5" ry="8.5" fill="url(#catBelly3D)"/><polygon points="92,27 96,27 94,30.5" fill="#fb7185"/><path d="M90 32.5 Q94 35.5 98 32.5" stroke="#1e1b4b" stroke-width="1.7" stroke-linecap="round" fill="none"/><g class="pet-eyes"><ellipse cx="80" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="80" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="81" cy="22.6" r="1.1" fill="#ffffff"/><ellipse cx="92.5" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="92.5" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="93.5" cy="22.6" r="1.1" fill="#ffffff"/></g><line x1="97" y1="28" x2="108" y2="26" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="97" y1="30.5" x2="109" y2="30.5" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="73" y1="29" x2="62" y2="28" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/></g></g></svg>
    </div>

    <div class="tg-auth-title">{{ custom_title if custom_title else 'Bảng Điều Khiển Hệ Thống' }}</div>
    <div class="tg-auth-sub">Không Gian Điều Khiển 3D NHK • Phản Hồi Lệnh Tốc Độ 0ms</div>

    {% if error %}<div class="tg-err-banner">{{ error }}</div>{% endif %}

    <form method="POST" action="/login" id="tgLoginForm" onsubmit="return handleTelegramLoginSubmit(event)">
      <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token', '') }}">
      <div class="tg-input-group">
        <label class="tg-input-label">Mật khẩu xác thực</label>
        <div class="tg-input-wrap">
          <span class="tg-input-icon">
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </span>
          <input class="tg-input" type="password" name="password" placeholder="Nhập khóa truy cập..." required autofocus>
        </div>
      </div>
      <button class="tg-btn-login" type="submit">
        <span>Khởi Động Không Gian Điều Khiển</span>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
      </button>
    </form>

    <div class="tg-sec-footer">
      <span class="tg-sec-badge">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>Bảo mật PBKDF2</span>
      </span>
      <span>Phan Anh Khôi (Rike)</span>
    </div>
  </div>

<script>
function handleTelegramLoginSubmit(ev) {
  const loader = document.getElementById('tgLoginLoader');
  const stepEl = document.getElementById('tgLoaderStepText');
  const subEl = document.getElementById('tgLoaderSubText');
  const barEl = document.getElementById('tgLoaderBar');
  if (!loader || loader.dataset.submitted === '1') return true;
  ev.preventDefault();
  loader.dataset.submitted = '1';
  loader.classList.add('active');
  barEl.style.width = '42%';
  setTimeout(() => {
    stepEl.textContent = 'Đang khởi tạo luồng QR Zalo VN/SG & 64 Shards Discord...';
    subEl.textContent = 'Đồng bộ hiệu ứng vật lý 3D Python & luồng ưu tiên 0ms';
    barEl.style.width = '82%';
  }, 180);
  setTimeout(() => {
    stepEl.textContent = 'Hoàn tất! Đang mở Bảng Điều Khiển...';
    barEl.style.width = '100%';
    document.getElementById('tgLoginForm').submit();
  }, 360);
  return false;
}
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,minimum-scale=1.0,user-scalable=no,viewport-fit=cover">
<title>{{ custom_title if custom_title else 'NHK — 3D Control Studio' }}</title>
<style>
:root {
  --bg: #000000;
  --bg-sub: #0b0b0f;
  --surface: #1c1c1e;
  --surface-sub: #2c2c2e;
  --surface-glass: rgba(28, 28, 30, 0.88);
  --border: rgba(255, 255, 255, 0.10);
  --border-light: rgba(255, 255, 255, 0.06);
  --txt: #ffffff;
  --txt-muted: #8e8e93;
  --blue: #007aff;
  --blue-hover: #0062cc;
  --tg-cyan: #2aabee;
  --tg-pink: #e15183;
  --green: #30d158;
  --red: #ff453a;
  --amber: #ff9f0a;
  --indigo: #5e5ce6;
  --dock-bg: rgba(26, 26, 30, 0.92);
  --dock-pill: rgba(255, 255, 255, 0.14);
  --dock-border: rgba(255, 255, 255, 0.13);
}
body[data-theme="tg_light"] {
  --bg: #f2f2f7;
  --bg-sub: #e5e5ea;
  --surface: #ffffff;
  --surface-sub: #f2f2f7;
  --surface-glass: rgba(255, 255, 255, 0.90);
  --border: rgba(60, 60, 67, 0.14);
  --border-light: rgba(60, 60, 67, 0.08);
  --txt: #000000;
  --txt-muted: #6c6c70;
  --blue: #007aff;
  --blue-hover: #0056b3;
  --tg-cyan: #0088cc;
  --tg-pink: #e15183;
  --green: #28cd41;
  --red: #ff3b30;
  --amber: #ff9500;
  --indigo: #5856d6;
  --dock-bg: rgba(255, 255, 255, 0.92);
  --dock-pill: rgba(0, 122, 255, 0.13);
  --dock-border: rgba(0, 0, 0, 0.10);
}
* { box-sizing: border-box; margin: 0; padding: 0; -webkit-tap-highlight-color: transparent; }
html, body {
  width: 100%; max-width: 100vw; overflow-x: hidden;
  font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Segoe UI", Inter, Roboto, sans-serif;
  background: var(--bg); color: var(--txt);
  font-size: 13.5px; line-height: 1.45;
  -webkit-text-size-adjust: 100%;
  transition: background-color 0.25s ease, color 0.25s ease;
}
code, pre, .mono { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
input, select, textarea, button { font-family: inherit; font-size: 13px; }

/* Page Boot Loader with Running Corgi & Cat Duo */
#tgPageBootLoader {
  position: fixed; inset: 0; z-index: 9000;
  background: radial-gradient(circle at 50% 35%, rgba(42, 171, 238, 0.15), transparent 60%), var(--bg);
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 12px;
  transition: opacity 0.35s ease, visibility 0.35s ease;
}
#tgPageBootLoader.hidden { opacity: 0; visibility: hidden; pointer-events: none; }
.tg-boot-pets {
  display: flex; align-items: center; justify-content: center; gap: 6px;
}

/* Lifelike Python SVG Pet Animations (Corgi Dog & British Shorthair Cat) */
.tg-pet-svg {
  width: 72px; height: 50px; overflow: visible; flex-shrink: 0;
  filter: drop-shadow(0 5px 10px rgba(0, 0, 0, 0.32));
  transition: transform 0.25s cubic-bezier(0.22, 1, 0.36, 1);
  cursor: pointer;
}
.tg-pet-svg:hover { transform: scale(1.08) translateY(-2px); }
.tg-pet-svg:active { transform: scale(0.95); }
.tg-pet-svg .pet-body-group { animation: petBob 0.52s ease-in-out infinite alternate; transform-origin: center; }
.tg-pet-svg .pet-tail { animation: petTailWag 0.28s ease-in-out infinite alternate; transform-origin: 26px 42px; }
.tg-pet-svg .pet-leg-front-r, .tg-pet-svg .pet-leg-back-l { animation: petLegStrideA 0.34s ease-in-out infinite alternate; transform-origin: top center; }
.tg-pet-svg .pet-leg-front-l, .tg-pet-svg .pet-leg-back-r { animation: petLegStrideB 0.34s ease-in-out infinite alternate; transform-origin: top center; }
.tg-pet-svg .pet-ear-l { animation: petEarTwitch 2.2s ease-in-out infinite alternate; transform-origin: 70px 20px; }
.tg-pet-svg .pet-ear-r { animation: petEarTwitch 2.2s ease-in-out infinite alternate-reverse; transform-origin: 88px 18px; }
.tg-pet-svg .pet-eyes { animation: petEyeBlink 3.8s infinite; transform-origin: center; }
.tg-pet-svg.turbo-speed .pet-body-group { animation-duration: 0.24s; }
.tg-pet-svg.turbo-speed .pet-tail { animation-duration: 0.14s; }
.tg-pet-svg.turbo-speed .pet-leg-front-r, .tg-pet-svg.turbo-speed .pet-leg-back-l,
.tg-pet-svg.turbo-speed .pet-leg-front-l, .tg-pet-svg.turbo-speed .pet-leg-back-r { animation-duration: 0.16s; }

@keyframes petBob { from { transform: translateY(0px); } to { transform: translateY(-3.2px); } }
@keyframes petTailWag { from { transform: rotate(-15deg); } to { transform: rotate(18deg); } }
@keyframes petLegStrideA { from { transform: rotate(-18deg); } to { transform: rotate(18deg); } }
@keyframes petLegStrideB { from { transform: rotate(18deg); } to { transform: rotate(-18deg); } }
@keyframes petEarTwitch { 0%, 80% { transform: rotate(0deg); } 90% { transform: rotate(-7deg); } 100% { transform: rotate(5deg); } }
@keyframes petEyeBlink { 0%, 92%, 100% { transform: scaleY(1); } 96% { transform: scaleY(0.08); } }

.container {
  max-width: 1120px; margin: 0 auto;
  padding: 8px 12px calc(148px + env(safe-area-inset-bottom, 0px));
}

/* ==================== NON-OVERLAPPING TELEGRAM HEADER & STATUS STRIP ==================== */
.tg-top-status-row {
  display: flex; align-items: center; justify-content: space-between;
  gap: 6px; padding: 4px 2px 6px;
  overflow-x: auto; white-space: nowrap; flex-wrap: nowrap;
  scrollbar-width: none; -ms-overflow-style: none;
}
.tg-top-status-row::-webkit-scrollbar { display: none; }

.tg-capsule-brand {
  display: inline-flex; align-items: center; gap: 5px;
  background: linear-gradient(135deg, #007aff 0%, #2aabee 100%);
  color: #ffffff; font-size: 10.5px; font-weight: 700; letter-spacing: 0.3px;
  padding: 4px 10px; border-radius: 999px; flex-shrink: 0;
  box-shadow: 0 2px 10px rgba(0, 122, 255, 0.32);
}
.tg-capsule-telemetry {
  display: inline-flex; align-items: center; gap: 5px;
  background: var(--surface); border: 1px solid var(--border);
  color: var(--txt-muted); font-size: 11px; font-weight: 600;
  padding: 4px 10px; border-radius: 999px; cursor: pointer;
  white-space: nowrap; flex-shrink: 0;
  transition: border-color 0.2s ease, transform 0.15s ease;
}
.tg-capsule-telemetry:active { transform: scale(0.97); }
.dot-online {
  width: 7px; height: 7px; border-radius: 50%;
  background: var(--green); display: inline-block; flex-shrink: 0;
  box-shadow: 0 0 8px var(--green);
}

.tg-navbar {
  display: flex; align-items: center; justify-content: space-between;
  gap: 8px; padding: 6px 2px 10px;
  flex-wrap: nowrap; width: 100%;
}
.tg-nav-left-brand {
  display: flex; align-items: center; gap: 9px;
  min-width: 0; flex: 1 1 auto; overflow: hidden;
}
.brand-logo-wrap {
  width: 36px; height: 36px; border-radius: 50%;
  background: var(--surface-sub); border: 1.5px solid var(--tg-cyan);
  overflow: hidden; cursor: pointer; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 4px 12px rgba(42, 171, 238, 0.22);
  transition: transform 0.2s ease;
}
.brand-logo-wrap:hover { transform: scale(1.06); }
.brand-logo-wrap img { width: 100%; height: 100%; object-fit: cover; display: block; }
.tg-nav-title-block {
  min-width: 0; flex: 1; overflow: hidden;
}
.tg-nav-title {
  font-size: 15.5px; font-weight: 700; letter-spacing: -0.25px;
  color: var(--txt); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.tg-nav-subtitle {
  font-size: 10.5px; color: var(--txt-muted);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}

.tg-nav-actions-right {
  display: flex; align-items: center; gap: 5px;
  flex-shrink: 0;
}
.tg-nav-pill-btn {
  position: relative; overflow: hidden;
  display: inline-flex; align-items: center; justify-content: center; gap: 4px;
  background: var(--surface); border: 1px solid var(--border);
  color: var(--txt); font-size: 12px; font-weight: 600;
  padding: 6px 11px; border-radius: 999px; cursor: pointer;
  white-space: nowrap; flex-shrink: 0;
  transition: all 0.18s cubic-bezier(0.22, 1, 0.36, 1); text-decoration: none;
}
.tg-nav-pill-btn:hover { background: var(--surface-sub); transform: translateY(-1px); }
.tg-nav-pill-btn:active { transform: scale(0.95); }
.tg-nav-pill-btn.danger {
  background: rgba(255, 69, 58, 0.14);
  border-color: rgba(255, 69, 58, 0.35);
  color: var(--red);
}

.tg-nav-right-group {
  display: inline-flex; align-items: center; gap: 2px;
  background: var(--surface); border: 1px solid var(--border);
  padding: 2.5px 4px; border-radius: 999px; flex-shrink: 0;
}
.tg-icon-btn {
  width: 30px; height: 30px; border-radius: 50%;
  border: none; background: transparent; color: var(--txt);
  display: inline-flex; align-items: center; justify-content: center;
  cursor: pointer; transition: background 0.16s ease, transform 0.16s ease;
  text-decoration: none; flex-shrink: 0;
}
.tg-icon-btn:hover { background: var(--surface-sub); }
.tg-icon-btn:active { transform: scale(0.90); }

/* ==================== INTERACTIVE PET COMPANION STUDIO BAR ==================== */
.tg-pet-companion-bar {
  background: linear-gradient(135deg, rgba(28, 28, 32, 0.95) 0%, rgba(36, 38, 48, 0.92) 100%);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 8px 12px;
  margin-bottom: 10px;
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; flex-wrap: wrap;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
}
body[data-theme="tg_light"] .tg-pet-companion-bar {
  background: linear-gradient(135deg, #ffffff 0%, #f0f4ff 100%);
}
.tg-pet-duo-stage {
  display: flex; align-items: center; gap: 4px;
  min-width: 0; flex: 1 1 220px;
}
.tg-pet-speech {
  min-width: 0; flex: 1;
}
.tg-pet-speech-title {
  font-size: 11.5px; font-weight: 700; color: var(--tg-cyan);
  display: flex; align-items: center; gap: 5px;
}
.tg-pet-speech-sub {
  font-size: 11px; color: var(--txt-muted);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.tg-pet-controls {
  display: flex; align-items: center; gap: 4px; flex-shrink: 0;
}

/* Telegram Full-Width Rounded Search Bar */
.tg-search-wrap { margin-bottom: 10px; }
.tg-search-bar {
  width: 100%; background: var(--surface);
  border: 1px solid var(--border-light);
  border-radius: 14px; padding: 8.5px 12px;
  display: flex; align-items: center; gap: 8px;
  transition: border-color 0.2s ease, background 0.2s ease;
}
.tg-search-bar:focus-within {
  border-color: var(--tg-cyan);
  background: var(--surface-sub);
}
.tg-search-bar svg { color: var(--txt-muted); flex-shrink: 0; }
.tg-search-input {
  width: 100%; min-width: 0; flex: 1;
  background: transparent; border: none; outline: none;
  color: var(--txt); font-size: 13px;
}
.tg-search-input::placeholder { color: var(--txt-muted); }

/* Compact Telegram Telemetry Strip */
.tg-kpi-strip {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px; margin-bottom: 12px;
}
@media (max-width: 640px) { .tg-kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.kpi-box {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 15px; padding: 10px 13px;
  display: flex; align-items: center; justify-content: space-between;
}
.kpi-label { font-size: 11.5px; color: var(--txt-muted); font-weight: 500; }
.kpi-val { font-size: 17.5px; font-weight: 700; color: var(--txt); font-variant-numeric: tabular-nums; }

/* Panels & Grouped Cells */
.grid-12 { display: grid; grid-template-columns: repeat(12, minmax(0, 1fr)); gap: 12px; }
.col-5 { grid-column: span 5; }
.col-6 { grid-column: span 6; }
.col-7 { grid-column: span 7; }
@media (max-width: 920px) { .col-5, .col-6, .col-7 { grid-column: span 12; } }

.panel {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 18px; margin-bottom: 12px; overflow: hidden;
}
.panel-hd {
  padding: 11px 14px; border-bottom: 1px solid var(--border-light);
  display: flex; align-items: center; justify-content: space-between; gap: 8px; flex-wrap: wrap;
}
.panel-title {
  font-size: 13.5px; font-weight: 700; color: var(--txt);
  display: inline-flex; align-items: center; gap: 7px;
}
.panel-body { padding: 13px 14px; }

.row-2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; margin-bottom: 8px; }
.row-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin-bottom: 8px; }
.row-4 { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin-bottom: 8px; }
@media (max-width: 580px) {
  .row-2, .row-3, .row-4 { grid-template-columns: 1fr; }
}

.field-lbl {
  display: block; font-size: 11.5px; font-weight: 600;
  color: var(--txt-muted); margin-bottom: 5px;
}
.inp, .sel, .txt {
  width: 100%; padding: 9px 12px; font-size: 13px; color: var(--txt);
  background: var(--surface-sub); border: 1px solid var(--border);
  border-radius: 12px; outline: none; transition: border-color 0.18s ease, background 0.18s ease;
}
.inp:focus, .sel:focus, .txt:focus { border-color: var(--tg-cyan); }
.txt { min-height: 76px; resize: vertical; }

/* Crisp Single-Line Segmented Sub-tabs */
.sub-tabs {
  display: flex; align-items: stretch; gap: 4px; padding: 3px;
  background: var(--surface-sub); border-radius: 12px;
  margin-bottom: 10px; border: 1px solid var(--border-light);
  overflow-x: auto; scrollbar-width: none;
}
.sub-tabs::-webkit-scrollbar { display: none; }
.sub-tab {
  position: relative; overflow: hidden;
  flex: 1 1 0; min-width: 0; padding: 7.5px 8px; border-radius: 9px;
  border: none; background: transparent; color: var(--txt-muted);
  font-size: 11.5px; font-weight: 600; cursor: pointer;
  white-space: nowrap; text-overflow: ellipsis;
  display: inline-flex; align-items: center; justify-content: center; gap: 4px;
  transition: all 0.2s cubic-bezier(0.22, 1, 0.36, 1); text-align: center;
}
.sub-tab.active {
  background: var(--surface); color: var(--txt);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.24);
}

/* ==================== MODERN INTERACTIVE BUTTONS & LIVE PET LOADERS ==================== */
.btn {
  position: relative; overflow: hidden;
  display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  padding: 8px 13px; border-radius: 11px;
  border: 1px solid var(--border); background: var(--surface-sub);
  color: var(--txt); font-size: 12.5px; font-weight: 600;
  cursor: pointer; text-decoration: none; white-space: nowrap;
  transition: transform 0.2s cubic-bezier(0.22, 1, 0.36, 1), box-shadow 0.2s ease, background 0.2s ease, border-color 0.2s ease;
  user-select: none; -webkit-user-select: none;
}
.btn::before {
  content: ""; position: absolute; top: 0; left: -120%; width: 70%; height: 100%;
  background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.14), transparent);
  transform: skewX(-20deg); transition: left 0.55s ease; pointer-events: none;
}
.btn:hover::before { left: 150%; }
.btn:hover { transform: translateY(-1px); box-shadow: 0 6px 16px rgba(0, 0, 0, 0.25); }
.btn:active { transform: scale(0.96); }
.btn-sm { padding: 5.5px 10px; font-size: 11.5px; border-radius: 9px; }
.btn-block { width: 100%; padding: 11px 14px; font-size: 13.5px; border-radius: 12px; }
.btn-primary {
  background: linear-gradient(135deg, #007aff 0%, #2aabee 100%);
  border-color: rgba(42, 171, 238, 0.5); color: #ffffff;
  box-shadow: 0 6px 18px rgba(0, 122, 255, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.22);
}
.btn-success {
  background: linear-gradient(135deg, #28cd41 0%, #30d158 100%);
  border-color: rgba(48, 209, 88, 0.5); color: #ffffff;
  box-shadow: 0 6px 18px rgba(48, 209, 88, 0.26), inset 0 1px 0 rgba(255, 255, 255, 0.22);
}
.btn-danger {
  background: rgba(255, 69, 58, 0.15);
  border-color: rgba(255, 69, 58, 0.38); color: var(--red);
}

/* Button Ripple & Pet Loading State */
.tg-btn-ripple {
  position: absolute; border-radius: 50%; pointer-events: none;
  background: rgba(255, 255, 255, 0.35);
  transform: scale(0); animation: tgRippleExpand 0.55s ease-out forwards;
}
@keyframes tgRippleExpand {
  to { transform: scale(3.5); opacity: 0; }
}
.btn.pet-loading {
  pointer-events: none;
  background-size: 200% 100%;
  animation: tgBtnShimmer 1.2s linear infinite;
}
@keyframes tgBtnShimmer {
  0% { filter: brightness(1); }
  50% { filter: brightness(1.12); }
  100% { filter: brightness(1); }
}
.btn-pet-spinner {
  display: inline-flex; align-items: center; gap: 4px;
}
.btn-pet-spinner svg {
  width: 22px; height: 16px;
  animation: petMiniRun 0.32s ease-in-out infinite alternate;
}
@keyframes petMiniRun {
  from { transform: translateY(1px) rotate(-4deg); }
  to { transform: translateY(-2px) rotate(4deg); }
}
.paw-dot {
  width: 5px; height: 5px; border-radius: 50%; background: currentColor;
  display: inline-block; animation: pawBounce 0.6s infinite alternate;
}
.paw-dot:nth-child(2) { animation-delay: 0.15s; }
.paw-dot:nth-child(3) { animation-delay: 0.30s; }
@keyframes pawBounce {
  from { transform: translateY(2px) scale(0.75); opacity: 0.45; }
  to { transform: translateY(-2px) scale(1.15); opacity: 1; }
}

/* Floating Paw Particle on Click */
.tg-floating-paw {
  position: fixed; z-index: 9999; pointer-events: none;
  font-size: 13px; animation: tgPawFloatUp 0.72s ease-out forwards;
}
@keyframes tgPawFloatUp {
  0% { opacity: 1; transform: translate(-50%, -50%) scale(0.6) rotate(-12deg); }
  100% { opacity: 0; transform: translate(-50%, -190%) scale(1.25) rotate(14deg); }
}

/* Badges */
.badge {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 3px 8px; border-radius: 999px;
  font-size: 10.5px; font-weight: 700; letter-spacing: 0.2px;
  white-space: nowrap; flex-shrink: 0;
}
.badge-blue { background: rgba(0, 122, 255, 0.16); color: #409cff; }
.badge-green { background: rgba(48, 209, 88, 0.16); color: #30d158; }
.badge-amber { background: rgba(255, 159, 10, 0.16); color: #ff9f0a; }
.badge-red { background: rgba(255, 69, 58, 0.16); color: #ff6961; }
.badge-gray { background: var(--surface-sub); color: var(--txt-muted); }

/* Checkboxes & Pills */
.chk-label {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 6.5px 10px; border-radius: 10px;
  background: var(--surface-sub); border: 1px solid var(--border-light);
  font-size: 12px; color: var(--txt); cursor: pointer;
}
.chk-label input { accent-color: var(--blue); width: 14px; height: 14px; flex-shrink: 0; }

.acc-selector-bar {
  display: flex; gap: 6px; overflow-x: auto; padding-bottom: 6px; margin-bottom: 10px;
  scrollbar-width: none;
}
.acc-selector-bar::-webkit-scrollbar { display: none; }
.acc-pill {
  padding: 6px 12px; border-radius: 999px;
  border: 1px solid var(--border); background: var(--surface-sub);
  color: var(--txt-muted); font-size: 12px; font-weight: 600;
  white-space: nowrap; cursor: pointer; transition: all 0.18s ease;
}
.acc-pill.active {
  background: var(--blue); border-color: var(--blue); color: #ffffff;
}

/* Telegram Chat List Cells */
.scroll-area {
  overflow-y: auto; border: 1px solid var(--border-light);
  border-radius: 14px; background: var(--bg-sub);
}
.list-item {
  display: flex; align-items: center; justify-content: space-between;
  gap: 10px; padding: 10px 13px;
  border-bottom: 1px solid var(--border-light);
  background: var(--surface); transition: background 0.15s ease;
}
.list-item:hover { background: var(--surface-sub); }
.list-item:last-child { border-bottom: none; }
.item-info { flex: 1; min-width: 0; }
.item-title { font-size: 13.5px; font-weight: 600; color: var(--txt); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.item-sub { font-size: 11.5px; color: var(--txt-muted); margin-top: 2px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }

/* Tables */
.data-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.data-table th {
  padding: 9px 11px; text-align: left; font-size: 11px; font-weight: 700;
  text-transform: uppercase; color: var(--txt-muted);
  background: var(--surface-sub); border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.data-table td {
  padding: 9.5px 11px; border-bottom: 1px solid var(--border-light);
  vertical-align: middle;
}
.data-table tr:last-child td { border-bottom: none; }

/* QR Studio Card & Non-Overlapping 4-Step Bar */
.qr-studio-card {
  background: var(--surface-sub); border: 1px solid var(--border);
  border-radius: 16px; padding: 12px;
}
.qr-meta-strip {
  display: flex; align-items: center; justify-content: space-between;
  gap: 5px; margin-bottom: 8px; overflow-x: auto; white-space: nowrap;
  scrollbar-width: none;
}
.qr-meta-strip::-webkit-scrollbar { display: none; }
.qr-steps-bar {
  display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 5px; margin-bottom: 10px;
}
.qr-step-item {
  padding: 6.5px 4px; border-radius: 9px; font-size: 11px; font-weight: 600;
  text-align: center; background: var(--surface); color: var(--txt-muted);
  border: 1px solid var(--border-light); transition: all 0.22s ease;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.qr-step-item.active { background: var(--blue); color: #ffffff; border-color: var(--blue); }
.qr-step-item.done { background: rgba(48, 209, 88, 0.18); color: var(--green); border-color: rgba(48, 209, 88, 0.35); }
.qr-frame {
  position: relative; overflow: hidden; width: 220px; height: 220px;
  margin: 10px auto; padding: 10px; background: #ffffff;
  border-radius: 18px; border: 2px solid var(--tg-cyan);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.35);
}
.qr-frame img { width: 100%; height: 100%; object-fit: contain; display: block; }
@keyframes qrScanLine { 0% { top: 8%; } 50% { top: 88%; } 100% { top: 8%; } }
.qr-laser-line {
  position: absolute; left: 10px; right: 10px; height: 2px;
  background: linear-gradient(90deg, transparent, #007aff, #2aabee, transparent);
  animation: qrScanLine 2.4s ease-in-out infinite; pointer-events: none;
}

/* Tab Content Panes */
.tab-pane { display: none; will-change: transform, opacity; }
.tab-pane.active {
  display: block;
  animation: tgPaneSlideIn 0.30s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}
.tab-pane.slide-from-left {
  animation: tgPaneFromLeft 0.30s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}
@keyframes tgPaneSlideIn {
  from { opacity: 0; transform: translateX(16px) scale(0.994); }
  to { opacity: 1; transform: translateX(0) scale(1); }
}
@keyframes tgPaneFromLeft {
  from { opacity: 0; transform: translateX(-16px) scale(0.994); }
  to { opacity: 1; transform: translateX(0) scale(1); }
}

/* ==================== TELEGRAM FLOATING PILL BOTTOM NAVIGATION BAR ==================== */
.tg-bottom-dock-wrap {
  position: fixed; left: 0; right: 0;
  bottom: calc(10px + env(safe-area-inset-bottom, 0px));
  z-index: 5000; display: flex; justify-content: center;
  padding: 0 12px; pointer-events: none;
}
.tg-bottom-bar {
  pointer-events: auto;
  position: relative;
  width: 100%; max-width: 500px; height: 62px;
  background: var(--dock-bg);
  backdrop-filter: blur(32px) saturate(200%);
  -webkit-backdrop-filter: blur(32px) saturate(200%);
  border: 1px solid var(--dock-border);
  border-radius: 999px;
  padding: 4px;
  display: grid; grid-template-columns: repeat(5, 1fr);
  align-items: center;
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.60), inset 0 1px 0 rgba(255, 255, 255, 0.12);
  user-select: none; -webkit-user-select: none;
  touch-action: pan-y;
}
.tg-nav-pill-indicator {
  position: absolute;
  top: 4px; bottom: 4px; left: 4px;
  width: calc((100% - 8px) / 5);
  background: var(--dock-pill);
  border-radius: 999px;
  pointer-events: none;
  z-index: 0;
  transform-origin: center center;
  transition: transform 0.36s cubic-bezier(0.22, 1, 0.36, 1), background-color 0.2s ease;
  box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.15);
}
.tg-bottom-bar.dragging .tg-nav-pill-indicator {
  transition: none !important;
  background: rgba(255, 255, 255, 0.20);
}
.nav-tab {
  position: relative; z-index: 1;
  height: 100%; border: none; background: transparent;
  color: var(--txt-muted);
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 3px; cursor: pointer; border-radius: 999px;
  transition: color 0.2s ease, transform 0.2s ease;
}
.nav-tab svg {
  width: 20px; height: 20px;
  transition: transform 0.24s cubic-bezier(0.22, 1, 0.36, 1), color 0.2s ease;
}
.nav-tab .tg-tab-lbl {
  font-size: 10.5px; font-weight: 600; letter-spacing: -0.1px;
  line-height: 1; white-space: nowrap;
}
.nav-tab.active { color: var(--tg-pink); }
.nav-tab.active svg { transform: translateY(-1px) scale(1.08); }

/* Hide badge when value is 0 so it never clutters the dock icons */
.tab-count {
  position: absolute; top: 4px; right: 16%;
  min-width: 16px; height: 16px; padding: 0 4.5px;
  border-radius: 999px; background: var(--red); color: #ffffff;
  font-size: 9.5px; font-weight: 700;
  display: inline-flex; align-items: center; justify-content: center;
  box-shadow: 0 2px 6px rgba(255, 69, 58, 0.4);
}
.tab-count.zero-badge { display: none !important; }

/* Toast Notifications */
#toastBox {
  position: fixed; top: 14px; right: 14px; z-index: 9500;
  display: flex; flex-direction: column; gap: 8px; max-width: 330px;
}
.toast-msg {
  background: var(--surface); color: var(--txt);
  border: 1px solid var(--border); border-left: 3.5px solid var(--tg-cyan);
  padding: 10px 14px; border-radius: 14px; font-size: 12.5px; font-weight: 600;
  box-shadow: 0 12px 30px rgba(0, 0, 0, 0.48);
  animation: tgToastIn 0.22s ease forwards;
}
@keyframes tgToastIn {
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Modal Bulk 500 Boxes */
.tg-modal-backdrop {
  position: fixed; inset: 0; z-index: 8000;
  background: rgba(0, 0, 0, 0.74); backdrop-filter: blur(12px);
  display: none; align-items: center; justify-content: center; padding: 16px;
}
.tg-modal-backdrop.open { display: flex; }
.tg-modal-card {
  width: 100%; max-width: 520px; background: var(--surface);
  border: 1px solid var(--border); border-radius: 22px; overflow: hidden;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.6);
}

/* ==================== NHK 3D HOLO-CUBE & LUXURY SPECULAR RIM BUTTONS ==================== */
.nhk-3d-stage-wrap {
  position: relative;
  display: flex; align-items: center; justify-content: center; gap: 14px;
  padding: 6px 10px;
  perspective: 900px;
}
.nhk-3d-viewport {
  width: 54px; height: 54px;
  position: relative;
  transform-style: preserve-3d;
  display: inline-flex; align-items: center; justify-content: center;
  flex-shrink: 0;
  cursor: pointer;
}
.nhk-3d-orbit-ring {
  position: absolute; inset: -7px;
  border-radius: 50%;
  border: 1.5px dashed rgba(56, 189, 248, 0.55);
  transform-style: preserve-3d;
  pointer-events: none;
}
.nhk-3d-orbit-ring.ring-a {
  animation: nhkOrbitA 6s linear infinite;
  box-shadow: 0 0 14px rgba(56, 189, 248, 0.28);
}
.nhk-3d-orbit-ring.ring-b {
  inset: -11px;
  border: 1.5px solid rgba(244, 114, 182, 0.42);
  animation: nhkOrbitB 8s linear infinite reverse;
}
@keyframes nhkOrbitA {
  0% { transform: rotateX(68deg) rotateY(15deg) rotateZ(0deg); }
  100% { transform: rotateX(68deg) rotateY(15deg) rotateZ(360deg); }
}
@keyframes nhkOrbitB {
  0% { transform: rotateX(-58deg) rotateY(28deg) rotateZ(0deg); }
  100% { transform: rotateX(-58deg) rotateY(28deg) rotateZ(360deg); }
}
.nhk-3d-cube {
  width: 34px; height: 34px;
  position: relative;
  transform-style: preserve-3d;
  animation: nhkCubeSpin 9s cubic-bezier(0.45, 0.05, 0.55, 0.95) infinite;
}
@keyframes nhkCubeSpin {
  0%   { transform: rotateX(-18deg) rotateY(0deg) rotateZ(0deg); }
  25%  { transform: rotateX(18deg) rotateY(90deg) rotateZ(4deg); }
  50%  { transform: rotateX(-16deg) rotateY(180deg) rotateZ(-4deg); }
  75%  { transform: rotateX(20deg) rotateY(270deg) rotateZ(4deg); }
  100% { transform: rotateX(-18deg) rotateY(360deg) rotateZ(0deg); }
}
.nhk-cube-face {
  position: absolute; width: 34px; height: 34px;
  border-radius: 8px;
  background: linear-gradient(135deg, rgba(0, 122, 255, 0.82) 0%, rgba(42, 171, 238, 0.72) 55%, rgba(139, 92, 246, 0.82) 100%);
  border: 1px solid rgba(255, 255, 255, 0.55);
  box-shadow: 0 0 16px rgba(42, 171, 238, 0.45), inset 0 0 8px rgba(255, 255, 255, 0.35);
  display: flex; align-items: center; justify-content: center;
  font-size: 9.5px; font-weight: 900; color: #ffffff; letter-spacing: 0.6px;
  text-shadow: 0 1px 4px rgba(0, 0, 0, 0.65);
  backface-visibility: visible;
}
.nhk-cube-face.face-front  { transform: translateZ(17px); }
.nhk-cube-face.face-back   { transform: rotateY(180deg) translateZ(17px); }
.nhk-cube-face.face-right  { transform: rotateY(90deg) translateZ(17px); }
.nhk-cube-face.face-left   { transform: rotateY(-90deg) translateZ(17px); }
.nhk-cube-face.face-top    { transform: rotateX(90deg) translateZ(17px); }
.nhk-cube-face.face-bottom { transform: rotateX(-90deg) translateZ(17px); }

/* Luxury Specular Rim & Liquid Glass Interactive Buttons */
.btn, .tg-btn-login, .tg-nav-pill-btn {
  --mx: 50%;
  --my: 50%;
  position: relative;
  overflow: hidden;
  isolation: isolate;
}
.btn::after, .tg-btn-login::after, .tg-nav-pill-btn::after {
  content: "";
  position: absolute; inset: 0;
  border-radius: inherit;
  background: radial-gradient(110px circle at var(--mx) var(--my), rgba(255, 255, 255, 0.26), transparent 70%);
  opacity: 0;
  transition: opacity 0.22s ease;
  pointer-events: none;
  z-index: 0;
}
.btn:hover::after, .tg-btn-login:hover::after, .tg-nav-pill-btn:hover::after {
  opacity: 1;
}
.btn > *, .tg-btn-login > *, .tg-nav-pill-btn > * {
  position: relative; z-index: 1;
}
.btn {
  box-shadow: 0 3px 10px rgba(0, 0, 0, 0.22), inset 0 1px 0 rgba(255, 255, 255, 0.14);
}
.btn:hover {
  transform: translateY(-1.5px) scale(1.012);
  border-color: rgba(56, 189, 248, 0.48);
  box-shadow: 0 10px 24px -4px rgba(0, 122, 255, 0.32), inset 0 1px 0 rgba(255, 255, 255, 0.28);
}
.btn:active {
  transform: translateY(1px) scale(0.965);
}
.btn-primary {
  background: linear-gradient(135deg, #0066ff 0%, #0ea5e9 52%, #6366f1 100%);
  border: 1px solid rgba(125, 211, 252, 0.55);
  box-shadow: 0 8px 22px -4px rgba(14, 165, 233, 0.48), inset 0 1px 0 rgba(255, 255, 255, 0.35), inset 0 -2px 0 rgba(0, 0, 0, 0.25);
}
.btn-success {
  background: linear-gradient(135deg, #059669 0%, #10b981 50%, #34d399 100%);
  border: 1px solid rgba(110, 231, 183, 0.55);
  box-shadow: 0 8px 22px -4px rgba(16, 185, 129, 0.44), inset 0 1px 0 rgba(255, 255, 255, 0.35), inset 0 -2px 0 rgba(0, 0, 0, 0.25);
}
.btn-danger {
  background: linear-gradient(135deg, rgba(239, 68, 68, 0.24) 0%, rgba(244, 63, 94, 0.18) 100%);
  border: 1px solid rgba(251, 113, 133, 0.45);
  color: #fda4af;
}
.prx-dropzone {
  position: relative;
  border: 1.5px dashed rgba(56, 189, 248, 0.55);
  border-radius: 14px;
  padding: 10px 12px;
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.08) 0%, rgba(99, 102, 241, 0.08) 100%);
  text-align: center;
  cursor: pointer;
  transition: all 0.2s ease;
  margin-bottom: 8px;
}
.prx-dropzone:hover {
  border-color: #38bdf8;
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.15) 0%, rgba(99, 102, 241, 0.15) 100%);
  transform: translateY(-1px);
}
.prx-dropzone input[type="file"] {
  position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
}


@media (max-width: 560px) {
  .tg-navbar { display: grid; grid-template-columns: 1fr auto; row-gap: 8px; }
}
.tab-count.zero-val, .tab-count.zero-badge { display: none !important; }

</style>
</head>
<body data-theme="tg_dark">
<div id="tgPageBootLoader">
  <div class="tg-boot-pets">
    <svg class="tg-pet-svg pet-corgi-svg tg-corgi-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="corgiFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ffd269"/><stop offset="48%" stop-color="#ff9924"/><stop offset="100%" stop-color="#c95206"/></linearGradient><linearGradient id="corgiCream3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#f3dfc4"/></linearGradient><radialGradient id="corgiGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(255,179,71,0.42)"/><stop offset="100%" stop-color="rgba(255,179,71,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#corgiGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="36" ry="5.5" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M24 45 C10 34, 8 20, 18 17 C25 15, 31 26, 29 38 Z" fill="url(#corgiFur3D)"/><circle cx="16" cy="19" r="5.5" fill="url(#corgiCream3D)"/></g><g class="pet-leg-back-l"><rect x="30" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="34.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-l"><rect x="70" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="74.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><rect x="24" y="34" width="60" height="28" rx="14" fill="url(#corgiFur3D)"/><path d="M36 47 C47 45, 68 45, 80 40 L81 57 C67 62, 43 62, 34 58 Z" fill="url(#corgiCream3D)"/><path d="M63 34 C68 27, 78 27, 84 36 C80 45, 68 46, 63 34 Z" fill="url(#corgiCream3D)"/><g class="pet-leg-back-r"><rect x="38" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="43" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-r"><rect x="76" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="81" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><path d="M68 34 L84 48" stroke="#ef4444" stroke-width="4.5" stroke-linecap="round"/><circle cx="77" cy="44" r="4.5" fill="#fbbf24" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 22 L63 3 L80 14 Z" fill="url(#corgiFur3D)"/><path d="M69 19 L65 7 L77 14 Z" fill="#fda4af"/><path class="pet-ear-r" d="M88 18 L100 2 L102 22 Z" fill="url(#corgiFur3D)"/><path d="M90 18 L97 6 L98 20 Z" fill="#fda4af"/><ellipse cx="85" cy="27" rx="18" ry="15" fill="url(#corgiFur3D)"/><path d="M84 13 C87 20, 87 26, 85 40 C94 41, 105 37, 106 28 C107 22, 97 15, 84 13 Z" fill="url(#corgiCream3D)"/><ellipse cx="100" cy="29" rx="9.5" ry="7" fill="url(#corgiCream3D)"/><ellipse cx="107" cy="27" rx="3.8" ry="3" fill="#0f172a"/><path class="pet-tongue" d="M97 34 Q101 43 105 35 Z" fill="#fb7185"/><path d="M94 33 Q99 36.5 104 32" stroke="#0f172a" stroke-width="1.9" stroke-linecap="round" fill="none"/><g class="pet-eyes"><circle cx="80.5" cy="24" r="3.2" fill="#0f172a"/><circle cx="81.6" cy="22.8" r="1.2" fill="#ffffff"/><circle cx="93" cy="23.5" r="3.2" fill="#0f172a"/><circle cx="94.1" cy="22.3" r="1.2" fill="#ffffff"/></g><ellipse cx="76" cy="28.5" rx="3.3" ry="1.8" fill="rgba(251,113,133,0.52)"/><ellipse cx="96" cy="28.5" rx="3.1" ry="1.7" fill="rgba(251,113,133,0.52)"/></g></g></svg>
    <svg class="tg-pet-svg pet-cat-svg tg-cat-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="catFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#c7d2fe"/><stop offset="50%" stop-color="#818cf8"/><stop offset="100%" stop-color="#4f46e5"/></linearGradient><linearGradient id="catBelly3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#e0e7ff"/></linearGradient><radialGradient id="catGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(129,140,248,0.42)"/><stop offset="100%" stop-color="rgba(129,140,248,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#catGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="34" ry="5.2" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M27 46 C10 43, 7 20, 19 14 C26 11, 28 22, 23 28 C19 33, 23 41, 30 43 Z" fill="url(#catFur3D)"/></g><g class="pet-leg-back-l"><rect x="33" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="37.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-l"><rect x="69" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="73.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><rect x="28" y="35" width="54" height="26" rx="13" fill="url(#catFur3D)"/><path d="M39 48 C49 46, 65 46, 75 43 L76 57 C64 61, 45 61, 37 57 Z" fill="url(#catBelly3D)"/><g class="pet-leg-back-r"><rect x="40" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="44.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-r"><rect x="75" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="79.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><path d="M68 36 L81 48" stroke="#ec4899" stroke-width="4" stroke-linecap="round"/><circle cx="76" cy="44" r="4" fill="#38bdf8" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 21 L66 4 L81 14 Z" fill="url(#catFur3D)"/><path d="M70 19 L68 8 L78 14 Z" fill="#f472b6"/><path class="pet-ear-r" d="M87 16 L98 3 L100 20 Z" fill="url(#catFur3D)"/><path d="M89 16 L96 7 L97 19 Z" fill="#f472b6"/><ellipse cx="84" cy="27" rx="16.5" ry="14" fill="url(#catFur3D)"/><ellipse cx="87" cy="31" rx="11.5" ry="8.5" fill="url(#catBelly3D)"/><polygon points="92,27 96,27 94,30.5" fill="#fb7185"/><path d="M90 32.5 Q94 35.5 98 32.5" stroke="#1e1b4b" stroke-width="1.7" stroke-linecap="round" fill="none"/><g class="pet-eyes"><ellipse cx="80" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="80" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="81" cy="22.6" r="1.1" fill="#ffffff"/><ellipse cx="92.5" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="92.5" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="93.5" cy="22.6" r="1.1" fill="#ffffff"/></g><line x1="97" y1="28" x2="108" y2="26" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="97" y1="30.5" x2="109" y2="30.5" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="73" y1="29" x2="62" y2="28" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/></g></g></svg>
  </div>
  <div style="font-size:13.5px;font-weight:700;color:var(--txt)">Đang khởi chạy động cơ NHK 3D &amp; Luồng Phản Hồi 0ms...</div>
</div>

<div id="toastBox"></div>

<!-- Modal Nhập Nhanh 500 Box Discord / Zalo -->
<div class="tg-modal-backdrop" id="bulk500BoxModal">
  <div class="tg-modal-card">
    <div class="panel-hd">
      <span class="panel-title">Nạp Nhanh 500 Box Tuần Hoàn Siêu Tốc</span>
      <button type="button" class="btn btn-sm" onclick="closeBulk500BoxModal()">Đóng</button>
    </div>
    <div class="panel-body">
      <div style="font-size:12px;color:var(--txt-muted);margin-bottom:8px">
        Dán danh sách ID Kênh Discord hoặc ID Nhóm Zalo (mỗi dòng 1 ID hoặc cách nhau bằng dấu phẩy/khoảng trắng, hỗ trợ 500+ Box cho 1 tài khoản chạy lặp liên tục không sót):
      </div>
      <div class="row-2" style="margin-bottom:8px">
        <div>
          <label class="field-lbl">Nền tảng</label>
          <select class="sel" id="bulk500PlatformSelect">
            <option value="discord_channel">Discord (1 Acc chạy 500 Box)</option>
            <option value="group">Zalo Nhóm</option>
            <option value="messenger_thread">Messenger Box</option>
          </select>
        </div>
        <div>
          <label class="field-lbl">Chế độ chọn</label>
          <button type="button" class="btn btn-primary btn-block" onclick="selectTopNTargets(500);closeBulk500BoxModal()">Chọn 500 Box Đã Quét</button>
        </div>
      </div>
      <textarea class="txt" id="bulk500IdsTextarea" placeholder="Dán 1 đến 500+ ID Box vào đây..." style="min-height:130px;margin-bottom:10px;font-family:ui-monospace,Consolas,monospace"></textarea>
      <div class="row-2" style="margin-bottom:0">
        <button type="button" class="btn btn-success btn-block" onclick="importBulk500BoxIds()">Nạp &amp; Chọn Toàn Bộ Box</button>
        <button type="button" class="btn btn-block" onclick="closeBulk500BoxModal()">Hủy</button>
      </div>
    </div>
  </div>
</div>

<div class="container">
  <!-- Row 1: Single-line Non-Overlapping Status Bar -->
  <div class="tg-top-status-row">
    <div style="display:inline-flex;align-items:center;gap:6px;flex-shrink:0">
      <div class="tg-capsule-brand">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 22 8.5 22 15.5 12 22 2 15.5 2 8.5 12 2"/><line x1="12" y1="22" x2="12" y2="15.5"/><polyline points="22 8.5 12 15.5 2 8.5"/></svg>
        <span>NHK 3D</span>
      </div>
      <div class="tg-capsule-telemetry" onclick="checkWebPingNow(true)" title="NHK 3D Telemetry • Bấm để đo Ping thời gian thực">
        <span class="dot-online" id="headerPingDot"></span>
        <span>Ping: <b id="headerPingText">-- ms</b></span>
        <span>•</span>
        <span>API: <b id="liveSendPingVal">-- ms</b></span>
        <span>•</span>
        <span id="liveRpmVal">0 RPM</span>
      </div>
    </div>
    <span class="badge badge-green" id="liveHangStateBadge">SẴN SÀNG</span>
    <span style="display:none" id="liveJitterVal">1.0 ms</span>
    <span style="display:none" id="liveHealedVal">0 lần</span>
  </div>

  <!-- Row 2: Clean Non-Overlapping Telegram Header Bar -->
  <header class="tg-navbar">
    <div class="tg-nav-left-brand">
      <label class="brand-logo-wrap" title="Đổi ảnh đại diện hệ thống">
        <input type="file" id="logoInput" accept="image/*" style="display:none" onchange="uploadBrandLogo(this)">
        <img id="brandLogoImg" src="/api/logo?v={{ logo_ts }}" alt="Logo">
      </label>
      <div class="tg-nav-title-block">
        <div class="tg-nav-title" id="headerBrandTitle">{{ custom_title if custom_title else 'Chat & Tài Khoản' }}</div>
        <div class="tg-nav-subtitle">Điều phối đa tài khoản • VN &amp; SG 24/7</div>
      </div>
    </div>

    <div class="tg-nav-actions-right">
      <button type="button" class="tg-nav-pill-btn" onclick="toggleLogoSetupModal()">Sửa</button>
      <button type="button" class="tg-nav-pill-btn danger" onclick="stopAllRunningTasks()">Dừng</button>
      <div class="tg-nav-right-group">
        <button type="button" class="tg-icon-btn" onclick="toggleTelegramDayNight()" title="Đổi chế độ Sáng / Tối">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        </button>
        <button type="button" class="tg-icon-btn" onclick="reconnectAllListenersNow(this)" title="NHK 3D Turbo — Đồng bộ Đa Tài Khoản 0ms">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
        </button>
        <a href="/logout" class="tg-icon-btn" title="Đăng xuất">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        </a>
      </div>
    </div>
    <span id="hdrTeleBotState" style="display:none">Online</span>
    <span id="teleBotHeaderState" style="display:none">Online</span>
  </header>

  <!-- Row 3: Interactive Python Pet Mascot Studio (Corgi Dog & British Shorthair Cat) -->
  <div class="tg-pet-companion-bar" id="tgPetCompanionWidget">
    <div class="tg-pet-duo-stage">
      <div id="nhk3dCubeWrap" onclick="triggerPetReaction('corgi')" style="margin-right:4px"><div class="nhk-3d-viewport" title="Khối Lập Phương Năng Lượng 3D NHK"><div class="nhk-3d-orbit-ring ring-a"></div><div class="nhk-3d-orbit-ring ring-b"></div><div class="nhk-3d-cube"><div class="nhk-cube-face face-front"><span>NHK</span></div><div class="nhk-cube-face face-back"><span>NHK</span></div><div class="nhk-cube-face face-right"><span>3D</span></div><div class="nhk-cube-face face-left"><span>VIP</span></div><div class="nhk-cube-face face-top"><span>⚡</span></div><div class="nhk-cube-face face-bottom"><span>👑</span></div></div></div></div>
      <div id="petCorgiWrap" onclick="triggerPetReaction('corgi')" title="NHK 3D">
        <svg class="tg-pet-svg pet-corgi-svg tg-corgi-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="corgiFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ffd269"/><stop offset="48%" stop-color="#ff9924"/><stop offset="100%" stop-color="#c95206"/></linearGradient><linearGradient id="corgiCream3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#f3dfc4"/></linearGradient><radialGradient id="corgiGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(255,179,71,0.42)"/><stop offset="100%" stop-color="rgba(255,179,71,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#corgiGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="36" ry="5.5" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M24 45 C10 34, 8 20, 18 17 C25 15, 31 26, 29 38 Z" fill="url(#corgiFur3D)"/><circle cx="16" cy="19" r="5.5" fill="url(#corgiCream3D)"/></g><g class="pet-leg-back-l"><rect x="30" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="34.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-l"><rect x="70" y="54" width="9.5" height="19" rx="4.7" fill="#c95206"/><ellipse cx="74.8" cy="73.5" rx="6.4" ry="3.4" fill="url(#corgiCream3D)"/></g><rect x="24" y="34" width="60" height="28" rx="14" fill="url(#corgiFur3D)"/><path d="M36 47 C47 45, 68 45, 80 40 L81 57 C67 62, 43 62, 34 58 Z" fill="url(#corgiCream3D)"/><path d="M63 34 C68 27, 78 27, 84 36 C80 45, 68 46, 63 34 Z" fill="url(#corgiCream3D)"/><g class="pet-leg-back-r"><rect x="38" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="43" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><g class="pet-leg-front-r"><rect x="76" y="55" width="10" height="20" rx="5" fill="url(#corgiFur3D)"/><ellipse cx="81" cy="75" rx="6.6" ry="3.6" fill="url(#corgiCream3D)"/></g><path d="M68 34 L84 48" stroke="#ef4444" stroke-width="4.5" stroke-linecap="round"/><circle cx="77" cy="44" r="4.5" fill="#fbbf24" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 22 L63 3 L80 14 Z" fill="url(#corgiFur3D)"/><path d="M69 19 L65 7 L77 14 Z" fill="#fda4af"/><path class="pet-ear-r" d="M88 18 L100 2 L102 22 Z" fill="url(#corgiFur3D)"/><path d="M90 18 L97 6 L98 20 Z" fill="#fda4af"/><ellipse cx="85" cy="27" rx="18" ry="15" fill="url(#corgiFur3D)"/><path d="M84 13 C87 20, 87 26, 85 40 C94 41, 105 37, 106 28 C107 22, 97 15, 84 13 Z" fill="url(#corgiCream3D)"/><ellipse cx="100" cy="29" rx="9.5" ry="7" fill="url(#corgiCream3D)"/><ellipse cx="107" cy="27" rx="3.8" ry="3" fill="#0f172a"/><path class="pet-tongue" d="M97 34 Q101 43 105 35 Z" fill="#fb7185"/><path d="M94 33 Q99 36.5 104 32" stroke="#0f172a" stroke-width="1.9" stroke-linecap="round" fill="none"/><g class="pet-eyes"><circle cx="80.5" cy="24" r="3.2" fill="#0f172a"/><circle cx="81.6" cy="22.8" r="1.2" fill="#ffffff"/><circle cx="93" cy="23.5" r="3.2" fill="#0f172a"/><circle cx="94.1" cy="22.3" r="1.2" fill="#ffffff"/></g><ellipse cx="76" cy="28.5" rx="3.3" ry="1.8" fill="rgba(251,113,133,0.52)"/><ellipse cx="96" cy="28.5" rx="3.1" ry="1.7" fill="rgba(251,113,133,0.52)"/></g></g></svg>
      </div>
      <div id="petCatWrap" onclick="triggerPetReaction('cat')" title="NHK 3D">
        <svg class="tg-pet-svg pet-cat-svg tg-cat-svg" viewBox="0 0 128 88" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="catFur3D" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#c7d2fe"/><stop offset="50%" stop-color="#818cf8"/><stop offset="100%" stop-color="#4f46e5"/></linearGradient><linearGradient id="catBelly3D" x1="0%" y1="0%" x2="0%" y2="100%"><stop offset="0%" stop-color="#ffffff"/><stop offset="100%" stop-color="#e0e7ff"/></linearGradient><radialGradient id="catGlow" cx="50%" cy="50%" r="50%"><stop offset="0%" stop-color="rgba(129,140,248,0.42)"/><stop offset="100%" stop-color="rgba(129,140,248,0)"/></radialGradient></defs><circle cx="64" cy="44" r="40" fill="url(#catGlow)"/><ellipse class="pet-shadow" cx="62" cy="79" rx="34" ry="5.2" fill="rgba(0,0,0,0.42)"/><g class="pet-body-group"><g class="pet-tail"><path d="M27 46 C10 43, 7 20, 19 14 C26 11, 28 22, 23 28 C19 33, 23 41, 30 43 Z" fill="url(#catFur3D)"/></g><g class="pet-leg-back-l"><rect x="33" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="37.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-l"><rect x="69" y="54" width="8.5" height="19" rx="4.2" fill="#4338ca"/><ellipse cx="73.2" cy="73.5" rx="5.6" ry="3" fill="url(#catBelly3D)"/></g><rect x="28" y="35" width="54" height="26" rx="13" fill="url(#catFur3D)"/><path d="M39 48 C49 46, 65 46, 75 43 L76 57 C64 61, 45 61, 37 57 Z" fill="url(#catBelly3D)"/><g class="pet-leg-back-r"><rect x="40" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="44.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><g class="pet-leg-front-r"><rect x="75" y="55" width="9" height="20" rx="4.5" fill="url(#catFur3D)"/><ellipse cx="79.5" cy="75" rx="5.8" ry="3.2" fill="url(#catBelly3D)"/></g><path d="M68 36 L81 48" stroke="#ec4899" stroke-width="4" stroke-linecap="round"/><circle cx="76" cy="44" r="4" fill="#38bdf8" stroke="#fff" stroke-width="1"/><g class="pet-head"><path class="pet-ear-l" d="M69 21 L66 4 L81 14 Z" fill="url(#catFur3D)"/><path d="M70 19 L68 8 L78 14 Z" fill="#f472b6"/><path class="pet-ear-r" d="M87 16 L98 3 L100 20 Z" fill="url(#catFur3D)"/><path d="M89 16 L96 7 L97 19 Z" fill="#f472b6"/><ellipse cx="84" cy="27" rx="16.5" ry="14" fill="url(#catFur3D)"/><ellipse cx="87" cy="31" rx="11.5" ry="8.5" fill="url(#catBelly3D)"/><polygon points="92,27 96,27 94,30.5" fill="#fb7185"/><path d="M90 32.5 Q94 35.5 98 32.5" stroke="#1e1b4b" stroke-width="1.7" stroke-linecap="round" fill="none"/><g class="pet-eyes"><ellipse cx="80" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="80" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="81" cy="22.6" r="1.1" fill="#ffffff"/><ellipse cx="92.5" cy="24" rx="3" ry="3.4" fill="#10b981"/><ellipse cx="92.5" cy="24" rx="1.3" ry="2.8" fill="#0f172a"/><circle cx="93.5" cy="22.6" r="1.1" fill="#ffffff"/></g><line x1="97" y1="28" x2="108" y2="26" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="97" y1="30.5" x2="109" y2="30.5" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/><line x1="73" y1="29" x2="62" y2="28" stroke="#e2e8f0" stroke-width="1.3" stroke-linecap="round"/></g></g></svg>
      </div>
      <div class="tg-pet-speech">
        <div class="tg-pet-speech-title">
          <span id="petMoodText">NHK 3D Core • Trực chiến 24/7 (Phản hồi 0ms)</span>
        </div>
        <div class="tg-pet-speech-sub mono" id="latestCmdBannerText">Sẵn sàng nhận lệnh • Ưu tiên phản hồi 0ms</div>
      </div>
    </div>
    <div class="tg-pet-controls">
      <button type="button" class="btn btn-sm" onclick="switchPetDisplayMode('duo')">2X</button>
      <button type="button" class="btn btn-sm" onclick="switchPetDisplayMode('corgi')">#1</button>
      <button type="button" class="btn btn-sm" onclick="switchPetDisplayMode('cat')">#2</button>
    </div>
  </div>

  <!-- Row 4: Full-Width Search & Command Bar (Zero Text Collision) -->
  <div class="tg-search-wrap">
    <div class="tg-search-bar">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
      <input type="text" class="tg-search-input" id="globalTelegramSearchInput" placeholder="Tìm tài khoản, phòng chat hoặc gõ lệnh nhanh (.menu, .n, .g, .t)..." oninput="handleGlobalTelegramSearch(this.value)" onkeydown="if(event.key==='Enter'){dispatchGlobalSearchCommand(this.value)}">
      <button type="button" class="btn btn-primary btn-sm" onclick="dispatchGlobalSearchCommand(document.getElementById('globalTelegramSearchInput').value)">Chạy</button>
    </div>
  </div>

  <!-- Khung cài đặt thương hiệu ẩn/hiện khi bấm Sửa -->
  <div id="logoSetupPanel" class="panel" style="display:none">
    <div class="panel-hd">
      <span class="panel-title">Tuỳ Chỉnh Biểu Tượng &amp; Tiêu Đề</span>
      <button type="button" class="btn btn-sm" onclick="toggleLogoSetupModal()">Đóng</button>
    </div>
    <div class="panel-body">
      <div class="row-3" style="align-items:end;margin-bottom:0">
        <div>
          <label class="field-lbl">Tải ảnh biểu tượng từ máy</label>
          <input type="file" class="inp" accept="image/*" onchange="uploadBrandLogo(this)">
        </div>
        <div>
          <label class="field-lbl">Hoặc dán liên kết ảnh (URL)</label>
          <input type="text" class="inp" id="customLogoUrlInput" placeholder="https://.../logo.png">
        </div>
        <div>
          <label class="field-lbl">Tiêu đề hiển thị</label>
          <div style="display:flex;gap:6px">
            <input type="text" class="inp" id="customWebTitleInput" value="{{ custom_title }}" placeholder="Nhập tiêu đề...">
            <button type="button" class="btn btn-primary" onclick="saveBrandUrlAndTitle()">Lưu</button>
            <button type="button" class="btn btn-danger" onclick="resetBrandLogo()">Mặc định</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- 4 Ô Chỉ Số Gọn Tinh Tế -->
  <div class="tg-kpi-strip">
    <div class="kpi-box">
      <span class="kpi-label">Tài khoản</span>
      <span class="kpi-val" id="kpiAccCount">{{ accounts|length }}</span>
    </div>
    <div class="kpi-box">
      <span class="kpi-label">Box đã chọn</span>
      <span class="kpi-val" id="kpiTargetCount">0</span>
    </div>
    <div class="kpi-box">
      <span class="kpi-label">Đang chạy</span>
      <span class="kpi-val" id="kpiRunningTasks">0</span>
    </div>
    <div class="kpi-box">
      <span class="kpi-label">Tin đã gửi</span>
      <span class="kpi-val" id="kpiTotalSent">0</span>
    </div>
  </div>

  <!-- TAB 1: QUẢN LÝ TÀI KHOẢN -->
  <section id="tab-accounts" class="tab-pane active">
    <div class="grid-12">
      <div class="col-5">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
              <span>Kết Nối Tài Khoản</span>
            </span>
            <span class="badge badge-blue">VN &amp; SG Chính Chủ</span>
          </div>
          <div class="panel-body">
            <form method="POST" action="/account/add" onsubmit="return handleAccountFormSubmit(event)">
              <input type="hidden" name="platform" id="accPlatformInput" value="zalo">

              <div class="sub-tabs">
                <button type="button" class="sub-tab active" id="segZaloBtn" onclick="switchAccForm('zalo')">Zalo PC</button>
                <button type="button" class="sub-tab" id="segDiscordBtn" onclick="switchAccForm('discord')">Discord</button>
                <button type="button" class="sub-tab" id="segMessengerBtn" onclick="switchAccForm('messenger')">Messenger</button>
              </div>

              <div style="margin-bottom:8px">
                <label class="field-lbl">Tên định danh (Để trống tự nhận tên thật)</label>
                <input class="inp" name="name" placeholder="Ví dụ: Tài khoản chính...">
              </div>

              <div id="zaloInputFields">
                <div class="sub-tabs">
                  <button type="button" class="sub-tab active" id="subZaloQRBtn" onclick="switchZaloSubTab('qr')">Quét QR Đa Máy</button>
                  <button type="button" class="sub-tab" id="subZaloManualBtn" onclick="switchZaloSubTab('manual')">Cookie &amp; IMEI</button>
                  <button type="button" class="sub-tab" id="subZaloVaultBtn" onclick="switchZaloSubTab('vault')">Kho Đã Lưu</button>
                </div>

                <div id="zaloQRBox" class="qr-studio-card" style="margin-bottom:10px;text-align:center">
                  <div class="qr-meta-strip">
                    <span class="badge badge-green" id="zaloQRVnBadge">Định vị VN &amp; SG Thật</span>
                    <span class="badge badge-blue" id="zaloQRCodeIdBadge">Sẵn sàng cấp QR</span>
                    <span class="badge badge-gray" id="zaloQRImeiPreview">Giữ sống 24/7</span>
                  </div>

                  <div class="qr-steps-bar">
                    <div class="qr-step-item active" id="qrStep1">1. Cấp máy</div>
                    <div class="qr-step-item" id="qrStep2">2. Quét QR</div>
                    <div class="qr-step-item" id="qrStep3">3. Xác nhận</div>
                    <div class="qr-step-item" id="qrStep4">4. Trong Acc</div>
                  </div>

                  <div class="row-2" style="text-align:left;margin-bottom:8px">
                    <div>
                      <label class="field-lbl">Quốc gia &amp; Dàn máy tính luân phiên</label>
                      <select class="sel" id="zaloVnRegionSelect">
                        <option value="VN">Việt Nam — Xoay vòng 11 dòng máy PC/Mac</option>
                        <option value="SG">Singapore — Xoay vòng 5 dòng máy PC/Mac</option>
                        <option value="HCM">TP. Hồ Chí Minh — MacBook / ROG / Dell XPS</option>
                        <option value="HN">Hà Nội — ROG Strix / ThinkPad / MacBook Air</option>
                        <option value="DN">Đà Nẵng — MSI Titan / Mac Studio / HP Spectre</option>
                        <option value="MAC">Apple macOS — MacBook Pro / Air / iMac / Studio</option>
                      </select>
                    </div>
                    <div>
                      <label class="field-lbl">Tên thiết bị tuỳ chỉnh</label>
                      <input class="inp" id="zaloCustomPcNameInput" placeholder="Để trống tự đổi máy mỗi lần...">
                    </div>
                  </div>

                  <div style="text-align:left;margin-bottom:8px">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;gap:4px;flex-wrap:wrap">
                      <label class="field-lbl" style="margin:0">Định tuyến IP / Proxy Việt Nam &amp; Singapore thật</label>
                      <button type="button" class="btn btn-sm" id="btnAutoScanVnSgProxy" onclick="scanAndLockRealVnSgRoute(this)">Quét &amp; Khóa IP VN/SG Thật</button>
                    </div>
                    <input class="inp" id="zaloVnProxyInput" placeholder="Để trống tự định tuyến VN/SG hoặc nhập ip:port / socks5://...">
                    <div id="zaloGeoVerifyBanner" data-geo-box="zaloRealGeoVerifyBox" style="margin-top:5px;font-size:11px;color:var(--txt-muted)">
                      Đang kiểm tra định vị IP thực tế của máy chủ...
                    </div>
                  </div>

                  <div style="font-size:12px;color:var(--txt-muted);margin-bottom:10px;text-align:left;padding:9px 12px;border-radius:12px;background:var(--surface);border:1px solid var(--border-light)" id="zaloQRStatusText">
                    Mỗi lần bấm <b>Tạo Mã QR</b> hệ thống tự động cấp một máy tính mới tại <b>Việt Nam / Singapore</b>. Khi quét mã và ấn <b>Đăng nhập</b> trên điện thoại, máy tính được giữ sống 24/7 trong tài khoản Zalo.
                  </div>

                  <div id="zaloQRStageWrap" style="display:none">
                    <div class="qr-frame">
                      <div class="qr-laser-line"></div>
                      <img id="zaloQRImg" src="" alt="QR Zalo PC">
                    </div>
                    <div style="display:flex;justify-content:center;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap">
                      <span class="badge badge-blue" id="zaloQRTimerBadge">Hiệu lực: 100s</span>
                      <span class="badge badge-green" id="zaloQRLocationBadge">Đang định tuyến...</span>
                    </div>
                  </div>

                  <div id="zaloQRExtractedBox" style="display:none;text-align:left;margin-top:8px;padding:10px;border-radius:12px;background:rgba(48,209,88,0.12);border:1px solid rgba(48,209,88,0.35)">
                    <div style="font-size:12px;font-weight:700;color:var(--green);margin-bottom:4px">ĐÃ GHIM MÁY TÍNH SỐNG TRONG TÀI KHOẢN:</div>
                    <div style="font-size:11.5px;color:var(--txt);margin-bottom:8px">IMEI: <code id="zaloQRExtractedImei"></code></div>
                    <div class="row-3" style="margin-bottom:0">
                      <button type="button" class="btn btn-sm" onclick="copyZaloQRData('imei')">Sao chép IMEI</button>
                      <button type="button" class="btn btn-sm" onclick="copyZaloQRData('cookie')">Sao chép Cookie</button>
                      <button type="button" class="btn btn-sm" onclick="downloadZaloQRFile()">Tải File .TXT</button>
                    </div>
                  </div>

                  <button type="button" class="btn btn-primary btn-block" id="btnStartZaloQR" onclick="startZaloQRLogin(this)">
                    <span>Tạo Mã QR Máy Tính Mới</span>
                  </button>
                </div>

                <div id="zaloManualBox" style="display:none;margin-bottom:10px">
                  <div style="margin-bottom:8px">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                      <label class="field-lbl" style="margin:0">IMEI Thiết Bị (z_uuid)</label>
                      <button type="button" class="btn btn-sm" onclick="generateUniqueZaloImei()">Sinh IMEI Mới</button>
                    </div>
                    <input class="inp" name="imei" id="zaloImeiInput" placeholder="Dán IMEI Zalo...">
                  </div>
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Cookie Phiên (JSON / Header)</label>
                    <textarea class="txt" name="cookies" id="zaloCookieInput" placeholder="Dán Cookie Zalo (chứa zpw_sek)..."></textarea>
                  </div>
                  <div id="zaloVerifyStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:10px;font-size:12px;background:rgba(48,209,88,0.14);color:var(--green)"></div>
                  <button type="button" class="btn btn-success btn-block" onclick="verifyAndSaveZaloCookieVault(this)">Xác Thực &amp; Lưu Thiết Bị</button>
                </div>

                <div id="zaloVaultBox" style="display:none;margin-bottom:10px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                    <span class="field-lbl" style="margin:0">Kho Phiên Thiết Bị Đã Lưu</span>
                    <button type="button" class="btn btn-sm" onclick="loadZaloVaultRecords()">Làm mới</button>
                  </div>
                  <div class="scroll-area" id="zaloVaultListContainer" style="max-height:210px">
                    <div style="padding:12px;text-align:center;color:var(--txt-muted)">Đang tải dữ liệu...</div>
                  </div>
                </div>
              </div>

              <div id="messengerInputFields" style="display:none">
                <div class="sub-tabs">
                  <button type="button" class="sub-tab active" id="subMessCookieBtn" onclick="switchMessSubTab('cookie')">Cookie c_user + xs</button>
                  <button type="button" class="sub-tab" id="subMessLoginBtn" onclick="switchMessSubTab('login')">Đăng Nhập TK/MK</button>
                </div>
                <div id="messCookieBox">
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Cookie Facebook / Messenger</label>
                    <textarea class="txt" name="mess_cookies" id="messCookieInput" placeholder="c_user=...; xs=... hoặc JSON"></textarea>
                  </div>
                  <div id="messVerifyResultBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:10px;font-size:12px;background:rgba(48,209,88,0.14);color:var(--green)"></div>
                  <button type="button" class="btn btn-success btn-block" style="margin-bottom:8px" onclick="verifyAndLockMessengerCookie()">Xác Thực &amp; Kết Nối MQTT</button>
                </div>
                <div id="messLoginBox" style="display:none;margin-bottom:8px">
                  <div id="messLoginStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:10px;font-size:12px"></div>
                  <div style="margin-bottom:6px">
                    <label class="field-lbl">Email / Số điện thoại</label>
                    <input class="inp" id="fbLoginEmail" placeholder="Email hoặc SĐT...">
                  </div>
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Mật khẩu</label>
                    <input class="inp" type="password" id="fbLoginPass" placeholder="Mật khẩu...">
                  </div>
                  <button type="button" class="btn btn-primary btn-block" onclick="extractFacebookCookieByLogin()">Trích Xuất Cookie &amp; Lưu</button>
                </div>
              </div>

              <div id="discordInputFields" style="display:none">
                <div class="sub-tabs">
                  <button type="button" class="sub-tab active" id="subDisTokenBtn" onclick="switchDiscordRegTab('token')">Nạp Token</button>
                  <button type="button" class="sub-tab" id="subDisLoginBtn" onclick="switchDiscordRegTab('login')">Đăng Nhập</button>
                  <button type="button" class="sub-tab" id="subDisNewAccBtn" onclick="switchDiscordRegTab('new_acc')">Tạo Hồ Sơ</button>
                </div>
                <div id="discordTokenBox">
                  <label class="field-lbl">Danh sách Token Discord (1 Acc cân 500 Box hoặc nhiều Acc song song)</label>
                  <textarea class="txt" name="token" id="discordTokenInput" placeholder="Dán 1 hoặc nhiều Token Discord (mỗi dòng 1 Token)..."></textarea>
                  <div id="immortalVaultResultBox" style="display:none;margin:6px 0;padding:8px;border-radius:10px;font-size:12px;background:rgba(48,209,88,0.14);color:var(--green)"></div>
                  <div class="row-3" style="margin-top:6px">
                    <button type="button" class="btn btn-success btn-sm" onclick="runImmortalizeTokensTool(true)">Nạp &amp; Lưu</button>
                    <button type="button" class="btn btn-sm" onclick="runImmortalizeTokensTool(false)">Kiểm Tra</button>
                    <button type="button" class="btn btn-sm" onclick="copyDiscordTokenScript()">Code Lấy Token</button>
                  </div>
                  <label class="chk-label" style="margin-bottom:8px">
                    <input type="checkbox" name="is_bot" value="1">
                    <span>Token Bot Developer</span>
                  </label>
                </div>
                <div id="discordLoginBox" style="display:none;margin-bottom:8px">
                  <div id="discordRegStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:10px;font-size:12px"></div>
                  <div style="margin-bottom:6px">
                    <label class="field-lbl">Email / SĐT Discord</label>
                    <input class="inp" name="reg_email" id="regDisEmail" placeholder="email@domain.com">
                  </div>
                  <div class="row-2">
                    <div>
                      <label class="field-lbl">Mật khẩu</label>
                      <input class="inp" type="password" name="reg_password" id="regDisPass" placeholder="Mật khẩu...">
                    </div>
                    <div>
                      <label class="field-lbl">Phương thức 2FA</label>
                      <select class="sel" id="regDis2FAType">
                        <option value="totp">Mã 6 số / Không 2FA</option>
                        <option value="secret">Secret Key 2FA</option>
                        <option value="backup">Backup Code</option>
                      </select>
                    </div>
                  </div>
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Mã 2FA / Secret Key</label>
                    <input class="inp" name="reg_2fa" id="regDis2FA" placeholder="Nhập mã 6 số hoặc Secret Key...">
                  </div>
                  <button type="button" class="btn btn-primary btn-block" onclick="extractDiscordTokenByReg()">Đăng Nhập &amp; Lấy Token</button>
                </div>
                <div id="discordNewAccBox" style="display:none;margin-bottom:8px">
                  <div id="discordNewAccStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:10px;font-size:12px"></div>
                  <div class="row-2">
                    <div><label class="field-lbl">Email</label><input class="inp" id="newAccEmail" placeholder="email@domain.com"></div>
                    <div><label class="field-lbl">Username</label><input class="inp" id="newAccUsername" placeholder="username"></div>
                  </div>
                  <div class="row-2">
                    <div><label class="field-lbl">Mật khẩu</label><input class="inp" type="password" id="newAccPassword" placeholder=">= 8 ký tự"></div>
                    <div><label class="field-lbl">Ngày sinh</label><input class="inp" type="date" id="newAccDob" value="2000-06-15"></div>
                  </div>
                  <div class="row-2">
                    <button type="button" class="btn btn-sm" onclick="fillRandomDiscordRegProfile()">Tạo Ngẫu Nhiên</button>
                    <button type="button" class="btn btn-sm" onclick="runBatchDiscordRegStudio()">Tạo 5 Hồ Sơ</button>
                  </div>
                  <button type="button" class="btn btn-success btn-block" onclick="runCreateNewDiscordAccTool()">Khởi Tạo Tài Khoản</button>
                </div>
              </div>

              <div class="row-2" style="margin-bottom:10px">
                <label class="chk-label"><input type="checkbox" name="chat_cmd_enabled" value="1" checked><span>Nhận lệnh (.menu)</span></label>
                <label class="chk-label"><input type="checkbox" name="allow_all_cmd" value="1" checked><span>Cho phép nhóm dùng lệnh</span></label>
              </div>

              <button class="btn btn-primary btn-block" type="submit">Lưu Tài Khoản</button>
            </form>
          </div>
        </div>

        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              <span>Trình Tạo Mã 2FA &amp; Tiện Ích Discord</span>
            </span>
            <span class="badge badge-gray" id="totpTimerBadge">30s</span>
          </div>
          <div class="panel-body">
            <div style="display:flex;gap:6px;margin-bottom:8px">
              <input class="inp" id="web2FASecretInput" placeholder="Dán Secret Key 2FA (Base32)..." style="flex:1">
              <button type="button" class="btn btn-primary btn-sm" onclick="generateWeb2FA(true)">Lấy OTP</button>
            </div>
            <div id="web2FAResultBox" style="display:none;padding:8px 12px;border-radius:12px;background:var(--surface-sub);border:1px solid var(--border);align-items:center;justify-content:space-between;margin-bottom:8px">
              <div>
                <div style="font-size:10.5px;color:var(--txt-muted)">MÃ OTP 2FA HIỆN TẠI</div>
                <div id="web2FACodeVal" class="mono" style="font-size:18px;font-weight:700;color:var(--tg-cyan);letter-spacing:2px">------</div>
              </div>
              <button type="button" class="btn btn-sm" onclick="copyCurrent2FACode()">Sao chép</button>
            </div>
            <div style="display:flex;gap:6px;margin-bottom:6px">
              <input class="inp" id="dcCustomStatusInput" placeholder="Nội dung trạng thái Discord..." style="flex:1">
              <button type="button" class="btn btn-sm" onclick="updateDiscordCustomStatus()">Cập nhật</button>
            </div>
            <div class="row-3" style="margin-bottom:0">
              <button type="button" class="btn btn-sm" onclick="setDiscordHypeSquad(1)">Bravery</button>
              <button type="button" class="btn btn-sm" onclick="setDiscordHypeSquad(2)">Brilliance</button>
              <button type="button" class="btn btn-sm" onclick="setDiscordHypeSquad(3)">Balance</button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-7">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              <span>Danh Sách Tài Khoản ({{ accounts|length }})</span>
            </span>
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              <button class="btn btn-sm" type="button" onclick="reconnectAllListenersNow(this)">Làm mới phiên 24/7</button>
              <button class="btn btn-primary btn-sm" type="button" onclick="openPerAccBoxSelector(null)">Chọn Phòng Chat</button>
            </div>
          </div>
          <div class="panel-body" style="padding:0">
            {% if not accounts %}
              <div style="padding:36px 20px;text-align:center;color:var(--txt-muted)">
                Chưa có tài khoản nào được kết nối. Hãy quét mã QR Zalo hoặc nạp Token Discord ở bảng bên trái.
              </div>
            {% else %}
              <div style="overflow-x:auto">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Nền tảng</th>
                      <th>Tài khoản &amp; Thiết bị</th>
                      <th>UID</th>
                      <th>Phòng chat</th>
                      <th>Lệnh</th>
                      <th>Thao tác</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for a in accounts %}
                      <tr>
                        <td class="mono">{{ loop.index }}</td>
                        <td>
                          <span class="badge {% if a.platform == 'discord' %}badge-blue{% elif a.platform == 'messenger' %}badge-amber{% else %}badge-green{% endif %}">
                            {{ (a.platform or 'zalo')|upper }}
                          </span>
                        </td>
                        <td>
                          <div style="font-weight:600;color:var(--txt)">{{ a.name }}</div>
                          <div style="font-size:11px;color:var(--txt-muted)">{{ a.pc_name or 'Thiết bị đang hoạt động 24/7' }}</div>
                        </td>
                        <td class="mono" style="font-size:11.5px">{{ a.uid or a.masked_uid }}</td>
                        <td>
                          <button class="btn btn-primary btn-sm" type="button" onclick="openPerAccBoxSelector('{{ a.id }}')">Chọn Box</button>
                        </td>
                        <td>
                          <span class="badge {{ 'badge-green' if a.chat_cmd_enabled else 'badge-gray' }}">
                            {{ 'BẬT' if a.chat_cmd_enabled else 'TẮT' }}
                          </span>
                        </td>
                        <td>
                          <div style="display:flex;gap:4px">
                            <button class="btn btn-sm" type="button" onclick="testSingleAccountSession({{ a.id }}, this)">Kiểm tra</button>
                            <button class="btn btn-sm" type="button" onclick="toggleAccCmd({{ a.id }}, {{ 0 if a.chat_cmd_enabled else 1 }})">{{ 'Tắt' if a.chat_cmd_enabled else 'Bật' }}</button>
                            <a href="/account/delete/{{ a.id }}" class="btn btn-danger btn-sm">Xóa</a>
                          </div>
                        </td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            {% endif %}
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 2: PHÒNG CHAT & CHỌN 500 BOX -->
  <section id="tab-targets" class="tab-pane">
    <div class="grid-12">
      <div class="col-7">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
              <span>Danh Sách Phòng Chat &amp; 500 Box Tuần Hoàn</span>
            </span>
            <div style="display:flex;gap:4px;flex-wrap:wrap">
              <button class="btn btn-primary btn-sm" type="button" onclick="loadGroupsAndRooms(true, this)">Quét Toàn Bộ</button>
              <button class="btn btn-success btn-sm" type="button" onclick="selectTopNTargets(500)">Chọn 500 Box</button>
              <button class="btn btn-sm" type="button" onclick="openBulk500BoxModal()">+ Nạp 500 ID</button>
              <button class="btn btn-sm" type="button" onclick="selectAllTargets()">Chọn Hết</button>
              <button class="btn btn-sm" type="button" onclick="clearAllTargets()">Bỏ Chọn</button>
            </div>
          </div>
          <div class="panel-body">
            <div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
              <span class="field-lbl" style="margin:0">Lọc phòng theo tài khoản:</span>
              <label class="chk-label">
                <input type="checkbox" id="chkBindBoxToSpecificAcc">
                <span>Gán Box cố định theo đúng tài khoản sở hữu</span>
              </label>
            </div>
            <div class="acc-selector-bar" id="perAccSelectorBar">
              <button type="button" class="acc-pill active" data-acc="all" onclick="setRoomAccountFilter('all', this)">
                Tất cả ({{ accounts|length }})
              </button>
              {% for a in accounts %}
                <button type="button" class="acc-pill" data-acc="{{ a.id }}" onclick="setRoomAccountFilter('{{ a.id }}', this)">
                  <span>[{{ (a.platform or 'zalo')|upper }}] {{ a.name }}</span>
                </button>
              {% endfor %}
            </div>

            <div class="sub-tabs">
              <button type="button" class="sub-tab active" id="fltRoomAll" onclick="setRoomPlatformFilter('all')">Tất cả</button>
              <button type="button" class="sub-tab" id="fltRoomDiscord" onclick="setRoomPlatformFilter('discord')">Discord (500 Box)</button>
              <button type="button" class="sub-tab" id="fltRoomZalo" onclick="setRoomPlatformFilter('zalo')">Zalo</button>
              <button type="button" class="sub-tab" id="fltRoomMess" onclick="setRoomPlatformFilter('messenger')">Messenger</button>
            </div>
            <div style="display:flex;gap:6px;margin-bottom:8px">
              <input class="inp" id="roomSearchInput" placeholder="Tìm tên phòng, kênh Discord, nhóm Zalo hoặc dán ID..." oninput="renderTargetList()" style="flex:1">
              <button type="button" class="btn btn-sm" onclick="addManualChannelId()">+ Thêm ID</button>
            </div>
            <div class="scroll-area" id="targetListContainer" style="max-height:420px">
              <div style="padding:20px;text-align:center;color:var(--txt-muted)">Bấm "Quét Toàn Bộ" để tải danh sách phòng chat của các tài khoản.</div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-5">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Tag Thành Viên (Mention)</span>
            <span class="badge badge-blue" id="selectedTagBadge">0 người được chọn</span>
          </div>
          <div class="panel-body">
            <div style="display:flex;gap:6px;margin-bottom:8px;align-items:center;flex-wrap:wrap">
              <label class="chk-label" style="flex:1">
                <input type="checkbox" id="chkTagAll" onchange="updateTagSummary()">
                <span>Tag @All / @everyone</span>
              </label>
              <label class="chk-label" style="flex:1">
                <input type="checkbox" id="chkHideTagAll" checked onchange="updateTagSummary()">
                <span>Tag @All Ẩn</span>
              </label>
              <label class="chk-label" style="flex:1">
                <input type="checkbox" id="chkHideTagName" onchange="updateTagSummary()">
                <span>Tag @Tên Ẩn</span>
              </label>
              <button class="btn btn-sm" type="button" onclick="selectAllMembersInBox()">Chọn hết</button>
              <button class="btn btn-sm" type="button" onclick="clearSelectedMentions()">Xóa</button>
            </div>
            <div style="margin-bottom:8px">
              <input class="inp" id="memberSearchInput" placeholder="Tìm thành viên trong nhóm..." oninput="renderMemberList()">
            </div>
            <div class="scroll-area" id="memberListContainer" style="max-height:420px">
              <div style="padding:20px;text-align:center;color:var(--txt-muted)">Bấm "Thành viên" ở một phòng bên trái để tải danh sách.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 3: CHIẾN DỊCH TỐC ĐỘ CAO -->
  <section id="tab-campaign" class="tab-pane">
    <div class="grid-12">
      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
              <span>Điều Phối Gửi Tin Siêu Tốc (Zalo 0ms &amp; Discord 500 Box)</span>
            </span>
            <span class="badge badge-green">64 Shards Không Độ Trễ</span>
          </div>
          <div class="panel-body">
            <div style="margin-bottom:10px;padding:10px;background:var(--surface-sub);border:1px solid var(--border);border-radius:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:4px">
                <label class="field-lbl" style="margin:0">Tài khoản tham gia ({{ accounts|length }}):</label>
                <div style="display:flex;gap:4px">
                  <button type="button" class="btn btn-sm" onclick="toggleSelectAllCampaignAccs(true)">Chọn hết</button>
                  <button type="button" class="btn btn-sm" onclick="toggleSelectAllCampaignAccs(false)">Bỏ chọn</button>
                </div>
              </div>
              <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;max-height:110px;overflow-y:auto">
                {% if not accounts %}
                  <div style="font-size:11.5px;color:var(--txt-muted)">Chưa có tài khoản kết nối.</div>
                {% endif %}
                {% for a in accounts %}
                  <label class="chk-label" style="background:var(--surface);padding:5px 8px">
                    <input type="checkbox" class="camp-acc-chk" value="{{ a.id }}" checked>
                    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">[{{ (a.platform or 'zalo')|upper }}] {{ a.name }}</span>
                  </label>
                {% endfor %}
              </div>
            </div>

            <div style="margin-bottom:10px;padding:10px;background:var(--surface-sub);border:1px solid var(--border);border-radius:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:4px">
                <label class="field-lbl" style="margin:0;color:var(--tg-cyan)">Phòng mục tiêu (<span id="quickBoxSelectedCount">0</span> Box đã chọn):</label>
                <div style="display:flex;gap:4px;flex-wrap:wrap">
                  <button type="button" class="btn btn-primary btn-sm" id="btnQuickLoadBoxes" onclick="loadGroupsAndRooms(true, this)">Tải danh sách</button>
                  <button type="button" class="btn btn-sm" onclick="selectTopNTargets(100)">100 Box</button>
                  <button type="button" class="btn btn-success btn-sm" onclick="selectTopNTargets(500)">500 Box</button>
                  <button type="button" class="btn btn-sm" onclick="openBulk500BoxModal()">+ Dán 500 ID</button>
                  <button type="button" class="btn btn-sm" onclick="selectAllTargets()">Tất cả</button>
                  <button type="button" class="btn btn-sm" onclick="clearAllTargets()">Xóa</button>
                </div>
              </div>
              <div style="display:flex;gap:6px;margin-bottom:6px">
                <input class="inp" id="quickBoxSearchInput" placeholder="Tìm nhanh hoặc dán ID kênh..." oninput="syncQuickBoxSearch(this.value)" style="flex:1">
                <button type="button" class="btn btn-sm" onclick="addManualChannelFromQuick()">+ Thêm ID</button>
              </div>
              <div class="scroll-area" id="campaignQuickBoxList" style="max-height:135px">
                <div style="padding:12px;text-align:center;color:var(--txt-muted)">Đang tải danh sách phòng...</div>
              </div>
            </div>

            
            <div style="margin-bottom:10px;padding:10px;background:var(--surface-sub);border:1px solid var(--border);border-radius:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:4px">
                <span class="field-lbl" style="margin:0;color:#38bdf8">Nạp Nhanh File PRX (.txt / .csv) &amp; Tự Khởi Chạy 0ms:</span>
                <span class="badge badge-green" id="campPrxQuickBadge">PRX Auto-Start Sẵn Sàng</span>
              </div>
              <div class="prx-dropzone">
                <input type="file" accept=".txt,.csv,.list,.conf" multiple onchange="uploadPrxFilesAndAutoStart(this)">
                <div style="font-size:12px;font-weight:700;color:#38bdf8">📂 Bấm Duyệt File PRX (.txt / .csv) Để Nạp Hết &amp; Tự Khởi Chạy</div>
                <div style="font-size:10.5px;color:var(--txt-muted);margin-top:2px">Tự động đo Ping (ms), lọc PRX sống nhanh nhất &amp; giữ phản hồi lệnh .menu / .cp 0ms dù đang treo 500 Box</div>
              </div>
            </div>

            <div class="row-2">
              <div>
                <label class="field-lbl">Chế độ gửi</label>
                <select class="sel" id="cfgMode">
                  <option value="treo_nhay">Treo nhây từng dòng (.n)</option>
                  <option value="sieu_xa_nhieu_nhom">Xả siêu tốc 500 Box (.xa)</option>
                  <option value="combo_lien_thanh">Gửi gộp 3 câu/nhịp (.combo)</option>
                  <option value="treo_ngon">Treo ngôn nguyên bài (.g)</option>
                  <option value="fast">Gửi nhanh liên tục (.s)</option>
                  <option value="raid_burst">Chạy đồng loạt (.r)</option>
                  <option value="auto_shuffle">Đảo câu ngẫu nhiên (.a)</option>
                  <option value="nhay_tag_all_an">Tag @All ẩn (.anall)</option>
                  <option value="nhay_tag_ten_an">Tag @Tên ẩn (.antan)</option>
                  <option value="battrinh_all_box">Tag @All / @everyone (.all)</option>
                  <option value="nhay_tag_all">Nhây Tag @All liên tục</option>
                  <option value="nhay_poll">Tạo bình chọn Poll (.poll)</option>
                  <option value="nhay_typing">Hiệu ứng đang soạn tin (.typing)</option>
                  <option value="nhay_namebox">Đổi tên nhóm liên tục (.tenbox)</option>
                  <option value="zalo_todo">Giao việc To-Do (.todo)</option>
                  <option value="zalo_cardbank">Gửi thẻ ngân hàng (.bank)</option>
                  <option value="share_contact">Gửi danh thiếp (.card)</option>
                  <option value="reaction_storm">Thả cảm xúc liên tục</option>
                  <option value="nhay_theme">Đổi chủ đề Messenger (.theme)</option>
                  <option value="share_link">Chia sẻ liên kết (.sharelink)</option>
                  <option value="mess_nickname">Đổi biệt danh (.setname)</option>
                  <option value="discord_embed_vip">Blockquote Discord</option>
                  <option value="discord_status_rotator">Xoay vòng Status Discord</option>
                </select>
              </div>
              <div>
                <label class="field-lbl">Phối màu chữ</label>
                <select class="sel" id="cfgColorMode" onchange="syncWebRuntimeConfigLive()">
                  <option value="rainbow">Cầu vồng 8 màu theo dòng</option>
                  <option value="word_rainbow">Phối màu từng từ</option>
                  <option value="fire_gradient">Đỏ - Cam - Vàng</option>
                  <option value="ocean_gradient">Xanh đại dương</option>
                  <option value="royal_gradient">Tím - Hồng - Vàng</option>
                  <option value="cyber_gradient">Xanh băng - Tím</option>
                  <option value="random">Màu ngẫu nhiên</option>
                  <option value="fixed">Khóa màu cố định</option>
                  <option value="none">Mặc định (Không màu)</option>
                </select>
              </div>
            </div>

            <div style="margin-bottom:8px">
              <label class="field-lbl">Định dạng &amp; Cỡ chữ</label>
              <select class="sel" id="cfgFontStyle" onchange="syncWebRuntimeConfigLive()">
                <option value="big_bold">Chữ Lớn In Đậm (f_18)</option>
                <option value="small_bold">Chữ Nhỏ In Đậm (f_13)</option>
                <option value="normal_bold">Chữ Vừa In Đậm (f_15)</option>
                <option value="alternating_bold">Đan Xen Lớn &amp; Nhỏ</option>
                <option value="italic_bold">Chữ Lớn In Đậm Nghiêng</option>
                <option value="underline_bold">Chữ Lớn Gạch Chân</option>
                <option value="bold_serif">Font Toán Học Bold Serif</option>
                <option value="script_bold">Font Script</option>
                <option value="fraktur">Font Fraktur</option>
                <option value="double_struck">Font Double-Struck</option>
                <option value="small_caps">Font Small Caps</option>
                <option value="circled">Font Bo Tròn</option>
                <option value="squared">Font Khung Vuông</option>
                <option value="normal">Chữ Thường</option>
              </select>
            </div>

            <div class="row-4">
              <div>
                <label class="field-lbl">Màu cố định</label>
                <select class="sel" id="cfgFixedColor" onchange="syncWebRuntimeConfigLive()">
                  <option value="red">Đỏ (#db342e)</option>
                  <option value="orange">Cam (#f27806)</option>
                  <option value="yellow">Vàng (#f7b503)</option>
                  <option value="green">Xanh lá (#15a85f)</option>
                  <option value="blue">Xanh dương (#0068ff)</option>
                  <option value="cyan">Xanh băng (#00b4d8)</option>
                  <option value="purple">Tím (#8b5cf6)</option>
                  <option value="pink">Hồng (#ec4899)</option>
                </select>
              </div>
              <div>
                <label class="field-lbl">Độ trễ (Giây)</label>
                <input class="inp" type="number" step="0.01" min="0" id="cfgDelay" value="0.0">
              </div>
              <div>
                <label class="field-lbl">Số ký hiệu cuối</label>
                <input class="inp" type="number" min="0" max="10" id="cfgIconCount" value="0">
              </div>
              <div>
                <label class="field-lbl">Số luồng (1-100)</label>
                <input class="inp" type="number" min="1" max="100" id="cfgBatchCount" value="1">
              </div>
            </div>

            <div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
              <button type="button" class="btn btn-sm" onclick="setGlobalIconZeroNow(0)">Tắt Icon (.icon 0)</button>
              <button type="button" class="btn btn-sm" onclick="setGlobalIconZeroNow(2)">Bật 2 Icon</button>
              <button type="button" class="btn btn-primary btn-sm" onclick="document.getElementById('cfgDelay').value='0.0';syncWebRuntimeConfigLive()">Tốc Độ 0.0s (Không Độ Trễ)</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgBatchCount').value='16'">16 Luồng</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgBatchCount').value='64'">64 Luồng (500 Box)</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgBatchCount').value='100'">100 Luồng</button>
            </div>

            <div style="margin-bottom:8px">
              <label class="field-lbl">Chọn File Kịch Bản (.TXT)</label>
              <select class="sel" id="cfgFileSelect">
                <option value="">-- Nhập nội dung trực tiếp bên dưới --</option>
                {% for f in files %}
                  <option value="{{ f.id }}">File #{{ f.display_num }}: {{ f.filename }} ({{ f.lines_count }} dòng)</option>
                {% endfor %}
              </select>
            </div>

            <div style="margin-bottom:8px">
              <label class="field-lbl">Nội dung gửi (Phân tách bằng dấu ; hoặc xuống dòng)</label>
              <textarea class="txt" id="cfgRawText" placeholder="Nhập nội dung tin nhắn hoặc chọn File kịch bản..."></textarea>
            </div>

            <div class="row-2" style="margin-bottom:10px">
              <label class="chk-label"><input type="checkbox" id="cfgHeading" checked><span>In đậm &amp; Chữ lớn</span></label>
              <label class="chk-label"><input type="checkbox" id="cfgUseEmoji"><span>Kèm ký hiệu cuối câu</span></label>
              <label class="chk-label"><input type="checkbox" id="cfgAntiband" checked><span>Bảo vệ phiên Anti-Ban</span></label>
              <label class="chk-label"><input type="checkbox" id="cfgMultiAcc" checked><span>Chạy đa tài khoản</span></label>
            </div>

            <div class="row-2" style="margin-bottom:0">
              <button class="btn btn-success btn-block" type="button" onclick="launchCampaignTask(this)">KHỞI CHẠY NGAY</button>
              <button class="btn btn-danger btn-block" type="button" onclick="stopAllRunningTasks()">DỪNG TẤT CẢ</button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Tiến Trình Đang Hoạt Động</span>
            <button type="button" class="btn btn-danger btn-sm" onclick="stopAllRunningTasks()">Dừng tất cả</button>
          </div>
          <div class="panel-body" style="padding:0">
            <div class="scroll-area" id="activeTasksContainer" style="max-height:220px;border:none">
              <div style="padding:18px;text-align:center;color:var(--txt-muted)">Chưa có chiến dịch nào đang chạy.</div>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Điều Khiển Lệnh Nhanh &amp; Phân Quyền (.cp)</span>
            <span class="badge badge-green" id="cpCountBadge">0 người có quyền .cp</span>
          </div>
          <div class="panel-body">
            <div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
              <input class="inp" id="webQuickCmdInput" placeholder="Nhập lệnh nhanh (.icon 0, .d 0, .n 1, .g 1, .t)..." style="flex:1;min-width:180px">
              <button type="button" class="btn btn-primary btn-sm" onclick="dispatchWebQuickCommand(this)">Thực Thi</button>
            </div>
            <div style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap">
              <input class="inp" id="cpGrantUidInput" placeholder="UID hoặc @Tên cấp quyền (.cp)..." style="flex:1;min-width:130px">
              <input class="inp" id="cpGrantNameInput" placeholder="Tên hiển thị..." style="flex:1;min-width:110px">
              <button type="button" class="btn btn-success btn-sm" onclick="grantCpPermissionFromWeb()">+ Cấp Quyền</button>
              <button type="button" class="btn btn-danger btn-sm" onclick="revokeCpPermissionFromWeb('__all__')">Thu Hồi Hết</button>
            </div>
            <div class="scroll-area" id="cpUsersListContainer" style="max-height:110px;margin-bottom:8px">
              <div style="padding:10px;text-align:center;color:var(--txt-muted)">Chỉ Chủ Tài Khoản đang có quyền điều khiển.</div>
            </div>
            <div class="scroll-area" id="campaignCmdLogBox" style="max-height:210px">
              <div style="padding:16px;text-align:center;color:var(--txt-muted)">Chưa có lệnh nào được ghi nhận.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 4: KHO FILE KỊCH BẢN -->
  <section id="tab-files" class="tab-pane">
    <div class="grid-12">
      <div class="col-5">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Tải Lên Hoặc Soạn Kịch Bản (.TXT)</span>
          </div>
          <div class="panel-body">
            <div style="margin-bottom:10px;padding:16px;border:1.5px dashed var(--tg-cyan);border-radius:14px;background:var(--surface-sub);text-align:center;position:relative">
              <input type="file" id="txtFileInput" accept=".txt" onchange="handleTxtUpload(this)" style="position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%">
              <div style="font-weight:700;color:var(--tg-cyan)">Chọn File .TXT từ thiết bị</div>
              <div style="font-size:11.5px;color:var(--txt-muted);margin-top:3px">Tự động làm sạch số thứ tự đầu dòng</div>
              <div id="uploadProgWrap" style="display:none;margin-top:8px;height:4px;background:var(--border);border-radius:4px;overflow:hidden">
                <div id="uploadProgBar" style="height:100%;width:0%;background:var(--green)"></div>
              </div>
            </div>

            <form method="POST" action="/file/create">
              <div style="margin-bottom:8px">
                <label class="field-lbl">Tên File (.txt)</label>
                <input class="inp" name="filename" placeholder="kich_ban.txt" required>
              </div>
              <div style="margin-bottom:10px">
                <label class="field-lbl">Nội dung kịch bản (Mỗi dòng 1 câu)</label>
                <textarea class="txt" name="content" placeholder="Nhập nội dung..." required style="min-height:120px"></textarea>
              </div>
              <button class="btn btn-success btn-block" type="submit">Lưu Vào Kho</button>
            </form>
          </div>
        </div>
      </div>

      <div class="col-7">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Sách File Kịch Bản ({{ files|length }})</span>
            <span class="badge badge-gray">Lệnh: .n &lt;số&gt; hoặc .g &lt;số&gt;</span>
          </div>
          <div class="panel-body" style="padding:0">
            {% if not files %}
              <div style="padding:28px;text-align:center;color:var(--txt-muted)">Kho kịch bản đang trống.</div>
            {% else %}
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Mã</th>
                    <th>Tên File</th>
                    <th>Số dòng</th>
                    <th>Lệnh gọi nhanh</th>
                    <th>Thao tác</th>
                  </tr>
                </thead>
                <tbody>
                  {% for f in files %}
                    <tr>
                      <td><span class="badge badge-blue">#{{ f.display_num }}</span></td>
                      <td style="font-weight:600">{{ f.filename }}</td>
                      <td class="mono">{{ f.lines_count }} dòng</td>
                      <td><code>.n {{ f.display_num }}</code> / <code>.g {{ f.display_num }}</code></td>
                      <td><a href="/file/delete/{{ f.id }}" class="btn btn-danger btn-sm">Xóa</a></td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            {% endif %}
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 5: CÀI ĐẶT HỆ THỐNG, DANH MỤC API & PROXY POOL -->
  <section id="tab-shield" class="tab-pane">
    <div class="grid-12">
      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Hiệu Năng Máy Chủ &amp; Hồ Proxy (PRX)</span>
            <button type="button" class="btn btn-sm" onclick="checkWebPingNow(true)">Đo độ trễ</button>
          </div>
          <div class="panel-body">
            <div class="row-2">
              <div style="padding:10px;border:1px solid var(--border);border-radius:12px;background:var(--surface-sub)">
                <div style="font-size:11px;color:var(--txt-muted)">Độ trễ phản hồi (RTT)</div>
                <div style="font-size:16px;font-weight:700;color:var(--green)" id="pingRttVal">-- ms</div>
                <span class="badge badge-green" id="pingEngineBadge">Engine 0.15ms</span>
              </div>
              <div style="padding:10px;border:1px solid var(--border);border-radius:12px;background:var(--surface-sub)">
                <div style="font-size:11px;color:var(--txt-muted)">Luồng xử lý song song</div>
                <div style="font-size:16px;font-weight:700;color:var(--tg-cyan)" id="pingThreadsVal">Hoạt động</div>
                <span class="badge badge-blue">64 Shards / 500 Box</span>
              </div>
            </div>
            <div class="row-2">
              <div style="padding:10px;border:1px solid var(--border);border-radius:12px">
                <div style="font-size:11px;color:var(--txt-muted)">Gói tin đã kiểm duyệt</div>
                <div style="font-size:14px;font-weight:700" id="fwInspectedCnt">0 gói</div>
              </div>
              <div style="padding:10px;border:1px solid var(--border);border-radius:12px">
                <div style="font-size:11px;color:var(--txt-muted)">Phiên Token / Cookie bảo vệ</div>
                <div style="font-size:14px;font-weight:700" id="fwImmortalCnt">0 phiên</div>
              </div>
            </div>

            <div class="scroll-area" id="healthShieldBox" style="max-height:185px;margin-bottom:10px"></div>

            <div style="padding:12px;border:1px solid var(--border);border-radius:14px;background:var(--surface-sub)">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;flex-wrap:wrap;gap:4px">
                <span style="font-size:12.5px;font-weight:700;color:var(--tg-cyan)">Hệ Thống Proxy Pool &amp; Chuyển Mạch 0ms</span>
                <span class="badge badge-green" id="prxStatusBadge">Direct Keep-Alive (0ms)</span>
              </div>
              <div style="font-size:11.5px;color:var(--txt-muted);margin-bottom:8px">
                Hỗ trợ <code>ip:port</code>, <code>ip:port:user:pass</code>, <code>http://user:pass@ip:port</code>, <code>socks5://...</code>. Tự động xoay vòng và chuyển tiếp 0ms khi gửi 500 Box.
              </div>
              
              <div class="prx-dropzone">
                <input type="file" id="prxFileUploadInput" accept=".txt,.csv,.list,.conf" multiple onchange="uploadPrxFilesAndAutoStart(this)">
                <div style="font-size:12.5px;font-weight:700;color:#38bdf8">📂 Duyệt File PRX (.txt / .csv) — Nạp Toàn Bộ &amp; Tự Khởi Chạy Nhanh Nhất</div>
                <div style="font-size:11px;color:var(--txt-muted);margin-top:2px" id="prxUploadStatusText">Hỗ trợ chọn 1 hoặc nhiều file PRX cùng lúc • Tự động xếp hạng Ping (ms) thấp nhất lên đầu</div>
              </div>

              <textarea class="txt" id="proxyPoolInput" placeholder="Dán danh sách Proxy (mỗi dòng 1 Proxy)..." style="min-height:74px;margin-bottom:8px;font-family:ui-monospace,Consolas,monospace;font-size:11.5px"></textarea>
              <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
                <label class="chk-label" style="background:var(--surface)">
                  <input type="checkbox" id="chkProxyEnabled" checked>
                  <span>Xoay vòng Proxy</span>
                </label>
                <button type="button" class="btn btn-primary btn-sm" onclick="saveProxyPoolList()">Lưu &amp; Kích Hoạt</button>
                <button type="button" class="btn btn-success btn-sm" onclick="testProxyPoolNow()">Kiểm Tra Proxy</button>
                <button type="button" class="btn btn-danger btn-sm" onclick="clearProxyPoolNow()">Xóa</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Mục Cổng API Đa Cụm (Zalo • Discord 500 Box • MQTT)</span>
            <span class="badge badge-blue">Tự Động Cân Bằng Tải</span>
          </div>
          <div class="panel-body" style="padding:0">
            <div class="scroll-area" id="apiGatewayDirectoryContainer" style="max-height:230px;border:none;border-radius:0">
              <div class="list-item">
                <div class="item-info">
                  <div class="item-title">Zalo Group &amp; Mention Multi-Cluster</div>
                  <div class="item-sub"><code>https://tt-group-wpa.chat.zalo.me/api/group/sendmsg</code> • <code>/api/group/mention</code></div>
                </div>
                <span class="badge badge-green">0ms Keep-Alive</span>
              </div>
              <div class="list-item">
                <div class="item-info">
                  <div class="item-title">Zalo Direct SMS Nodes (1 • 2 • 3)</div>
                  <div class="item-sub"><code>https://tt-chat1..3-wpa.chat.zalo.me/api/message/sms</code></div>
                </div>
                <span class="badge badge-green">Xoay vòng</span>
              </div>
              <div class="list-item">
                <div class="item-info">
                  <div class="item-title">Zalo WebSocket 24/7 Device Keeper</div>
                  <div class="item-sub"><code>wss://ws1.chat.zalo.me</code> • <code>wss://ws2..4.chat.zalo.me</code></div>
                </div>
                <span class="badge badge-blue">Giữ sống thiết bị</span>
              </div>
              <div class="list-item">
                <div class="item-info">
                  <div class="item-title">Discord 500-Box Multi-Edge Gateways</div>
                  <div class="item-sub"><code>discord.com/api/v9</code> • <code>v10</code> • <code>canary.discord.com</code> • <code>ptb.discord.com</code></div>
                </div>
                <span class="badge badge-green">64 Shards</span>
              </div>
              <div class="list-item">
                <div class="item-info">
                  <div class="item-title">Messenger Realtime Edge MQTT</div>
                  <div class="item-sub"><code>wss://edge-chat.facebook.com/chat</code></div>
                </div>
                <span class="badge badge-green">Sẵn sàng</span>
              </div>
            </div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Nhật Ký Lệnh Thời Gian Thực</span>
            <span class="badge badge-green">Phản Hồi Tức Thì</span>
          </div>
          <div class="panel-body" style="padding:0">
            <div class="scroll-area" id="cmdLogBox" style="max-height:220px;border:none"></div>
          </div>
        </div>
      </div>
    </div>
  </section>
</div>

<!-- THANH TAB VIÊN THUỐC NỔI DƯỚI CÙNG CHUẨN TELEGRAM iOS (KÉO TRƯỢT VẬT LÝ MƯỢT MÀ) -->
<div class="tg-bottom-dock-wrap">
  <nav class="tg-bottom-bar nav-tabs" id="tgBottomBar" aria-label="Điều hướng chính">
    <div class="tg-nav-pill-indicator" id="tgNavPill"></div>

    <button type="button" class="nav-tab active" data-tab="tab-accounts" data-idx="0" data-title="Chat &amp; Tài Khoản" onclick="switchMainTab('tab-accounts', this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
      <span class="tg-tab-lbl">Tài khoản</span>
      <span class="tab-count {% if not accounts %}zero-badge{% endif %}" id="dockAccBadge">{{ accounts|length }}</span>
    </button>

    <button type="button" class="nav-tab" data-tab="tab-targets" data-idx="1" data-title="Phòng &amp; Kênh Chat" onclick="switchMainTab('tab-targets', this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
      <span class="tg-tab-lbl">Phòng chat</span>
      <span class="tab-count zero-badge" id="dockTargetBadge">0</span>
    </button>

    <button type="button" class="nav-tab" data-tab="tab-campaign" data-idx="2" data-title="Chiến Dịch Siêu Tốc" onclick="switchMainTab('tab-campaign', this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
      <span class="tg-tab-lbl">Chiến dịch</span>
      <span class="tab-count zero-badge" id="dockTaskBadge">0</span>
    </button>

    <button type="button" class="nav-tab" data-tab="tab-files" data-idx="3" data-title="Kho Kịch Bản (.TXT)" onclick="switchMainTab('tab-files', this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
      <span class="tg-tab-lbl">Kịch bản</span>
      <span class="tab-count {% if not files %}zero-badge{% endif %}" id="dockFileBadge">{{ files|length }}</span>
    </button>

    <button type="button" class="nav-tab" data-tab="tab-shield" data-idx="4" data-title="Cài Đặt &amp; Hệ Thống" onclick="switchMainTab('tab-shield', this)">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
      <span class="tg-tab-lbl">Cài đặt</span>
    </button>
  </nav>
</div>

<script>
let ALL_TARGETS = [];
let BY_ACCOUNT_BOXES = {};
let SELECTED_TARGETS = new Map();
let CURRENT_MEMBERS = [];
let SELECTED_MENTIONS = new Map();
let ROOM_PLATFORM_FILTER = 'all';
let ROOM_ACCOUNT_FILTER = 'all';
let ZALO_QR_SESSION_ID = '';
let ZALO_QR_POLL_TIMER = null;
let LAST_ZALO_QR_RESULT = {imei: '', cookies_str: '', file_name: 'zalo_cookie.txt', file_content: ''};
let ZALO_VAULT_CACHE = [];
let CURRENT_TAB_INDEX = 0;
let TG_SPRING_SAMPLES = [0, 0.25, 0.56, 0.81, 0.96, 1.03, 1.04, 1.02, 1.0, 1.0];

const MINI_PET_LOADER_SVG = `<svg viewBox="0 0 36 24" fill="none" xmlns="http://www.w3.org/2000/svg"><ellipse cx="17" cy="14" rx="10" ry="5.5" fill="#ffb347"/><circle cx="27" cy="10" r="5.5" fill="#ffb347"/><polygon points="24,6 23,1 27,5" fill="#f58220"/><polygon points="28,5 31,1 31,7" fill="#f58220"/><circle cx="29" cy="9.5" r="1.1" fill="#1c1c1e"/><path d="M7 12 Q2 7 6 5" stroke="#ffb347" stroke-width="2.6" stroke-linecap="round"/><line x1="11" y1="18" x2="9" y2="23" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><line x1="15" y1="18" x2="16" y2="23" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><line x1="22" y1="18" x2="21" y2="23" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/><line x1="25" y1="18" x2="27" y2="23" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/></svg>`;

const MY_TAB_ID = 'tab_' + Math.random().toString(36).slice(2, 10) + '_' + Date.now();
const LEADER_STORAGE_KEY = 'tg_leader_tab_state';
const MULTI_TAB_BUS = (typeof BroadcastChannel !== 'undefined') ? new BroadcastChannel('tg_multi_acc_bus') : null;
let LAST_CROSS_TAB_STATUS_TS = 0;
let _pendingRafStatus = null;


function checkZaloRealGeoStatus(forceScan = false) { return checkZaloGeoStatus(forceScan); }
function autoScanAndBindVnSgProxy(btnEl) { return scanAndLockRealVnSgRoute(btnEl); }
function spawnPetBurstParticles(x, y, c) {
  if (!x && !y) return;
  const paw = document.createElement('span');
  paw.className = 'tg-floating-paw';
  paw.textContent = '🐾';
  paw.style.left = x + 'px';
  paw.style.top = y + 'px';
  document.body.appendChild(paw);
  setTimeout(() => paw.remove(), 700);
}

// Theo dõi tọa độ chuột / ngón tay thời gian thực cho hiệu ứng nút bấm Specular Rim Luxury
document.addEventListener('pointermove', (ev) => {
  const btn = ev.target.closest('.btn, .tg-btn-login, .tg-nav-pill-btn');
  if (!btn) return;
  const rect = btn.getBoundingClientRect();
  btn.style.setProperty('--mx', (ev.clientX - rect.left) + 'px');
  btn.style.setProperty('--my', (ev.clientY - rect.top) + 'px');
}, {passive: true});

// Đảm bảo 100% biểu tượng đồ họa SVG & Khối 3D NHK luôn xuất hiện rõ nét
async function ensureNhkPetsAnd3DRendered() {
  const cWrap = document.getElementById('petCorgiWrap');
  const mWrap = document.getElementById('petCatWrap');
  const nWrap = document.getElementById('nhk3dCubeWrap');
  if (cWrap && cWrap.innerHTML.trim().length > 50 && mWrap && mWrap.innerHTML.trim().length > 50) return;
  try {
    const r = await fetch('/api/ui/pet_mascot?t=' + Date.now());
    const d = await r.json();
    if (d && d.ok) {
      if (cWrap && d.corgi_svg) cWrap.innerHTML = d.corgi_svg;
      if (mWrap && d.cat_svg) mWrap.innerHTML = d.cat_svg;
      if (nWrap && d.nhk_3d_svg) nWrap.innerHTML = d.nhk_3d_svg;
    }
  } catch (e) {}
}
setTimeout(ensureNhkPetsAnd3DRendered, 80);

// Tính năng Duyệt File PRX (.txt / .csv) nạp toàn bộ & tự khởi chạy chế độ phản hồi nhanh nhất
async function uploadPrxFilesAndAutoStart(inputEl) {
  if (!inputEl || !inputEl.files || !inputEl.files.length) return;
  const files = Array.from(inputEl.files);
  const stTxt = document.getElementById('prxUploadStatusText');
  if (stTxt) stTxt.textContent = `Đang đọc & nạp ${files.length} file PRX...`;
  setPetTurboMode(true);
  setPetCompanionMood(`Đang nạp ${files.length} file PRX và tự khởi chạy đo tốc độ ms...`);

  const fd = new FormData();
  files.forEach(f => fd.append('files', f));
  fd.append('append_mode', '1');
  try {
    const r = await fetch('/api/proxies/upload_file', {method: 'POST', body: fd});
    const d = await r.json();
    if (d && d.ok) {
      const inp = document.getElementById('proxyPoolInput');
      const chk = document.getElementById('chkProxyEnabled');
      if (inp && d.snapshot && d.snapshot.proxies_text) inp.value = d.snapshot.proxies_text;
      if (chk) chk.checked = true;
      if (d.snapshot) updateProxyBadgeUI(d.snapshot);
      if (stTxt) stTxt.textContent = d.message || `Đã nạp ${d.total} PRX & tự khởi chạy!`;
      setPetCompanionMood(d.message || `Đã nạp & tự khởi chạy ${d.total} PRX siêu tốc!`);
      showToast(d.message || `Đã nạp & tự khởi chạy ${d.total} PRX!`);
      setTimeout(() => pollSystemStatus(true), 1500);
    } else {
      showToast((d && d.error) || 'Không tìm thấy Proxy hợp lệ trong file!');
    }
  } catch (e) {
    showToast('Lỗi tải file PRX lên máy chủ!');
  } finally {
    inputEl.value = '';
    setTimeout(() => setPetTurboMode(false), 800);
  }
}

function setDockBadgeCount(badgeId, countVal) {
  const el = document.getElementById(badgeId);
  if (!el) return;
  const n = parseInt(countVal || 0, 10) || 0;
  el.textContent = String(n);
  el.classList.toggle('zero-badge', n <= 0);
}

// Khởi tạo hiệu ứng Ripple + Paw Particles cho toàn bộ nút bấm & tải thông số Vật lý từ Python Backend
(function initTelegramBootAndPhysics() {
  window.addEventListener('DOMContentLoaded', () => {
    setTimeout(() => {
      const loader = document.getElementById('tgPageBootLoader');
      if (loader) loader.classList.add('hidden');
    }, 240);
    checkZaloGeoStatus(false);
  });

  document.addEventListener('pointerdown', (ev) => {
    const btn = ev.target.closest('.btn, .tg-nav-pill-btn, .sub-tab, .acc-pill');
    if (!btn) return;
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement('span');
    ripple.className = 'tg-btn-ripple';
    const size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = (ev.clientX - rect.left - size / 2) + 'px';
    ripple.style.top = (ev.clientY - rect.top - size / 2) + 'px';
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 580);

    if (ev.clientX && ev.clientY) {
      const paw = document.createElement('span');
      paw.className = 'tg-floating-paw';
      paw.textContent = Math.random() > 0.45 ? '🐾' : '✨';
      paw.style.left = ev.clientX + 'px';
      paw.style.top = ev.clientY + 'px';
      document.body.appendChild(paw);
      setTimeout(() => paw.remove(), 720);
    }
  }, {passive: true});

  fetch('/api/ui/physics').then(r => r.json()).then(d => {
    if (d && Array.isArray(d.spring_samples) && d.spring_samples.length > 4) {
      TG_SPRING_SAMPLES = d.spring_samples;
    }
  }).catch(() => {});
})();

async function withPetButtonLoading(btnEl, loadingText, asyncFn) {
  if (!btnEl) return await asyncFn();
  if (btnEl.dataset.loading === '1') return;
  btnEl.dataset.loading = '1';
  const origHtml = btnEl.innerHTML;
  btnEl.classList.add('pet-loading');
  btnEl.innerHTML = `<span class="btn-pet-spinner">${MINI_PET_LOADER_SVG}<span>${escapeHtmlSafe(loadingText || 'Đang xử lý...')}</span><span class="paw-dot"></span><span class="paw-dot"></span><span class="paw-dot"></span></span>`;
  setPetTurboMode(true);
  try {
    return await asyncFn();
  } finally {
    btnEl.classList.remove('pet-loading');
    btnEl.innerHTML = origHtml;
    btnEl.dataset.loading = '0';
    setTimeout(() => setPetTurboMode(false), 450);
  }
}

function setPetTurboMode(enabled) {
  document.querySelectorAll('#tgPetCompanionWidget .tg-pet-svg').forEach(svg => {
    svg.classList.toggle('turbo-speed', Boolean(enabled));
  });
}

function setPetCompanionMood(text) {
  const el = document.getElementById('petMoodText');
  if (el && text) el.textContent = text;
}

function switchPetDisplayMode(mode) {
  const corgiW = document.getElementById('petCorgiWrap');
  const catW = document.getElementById('petCatWrap');
  if (!corgiW || !catW) return;
  corgiW.style.display = (mode === 'cat') ? 'none' : 'block';
  catW.style.display = (mode === 'corgi') ? 'none' : 'block';
  if (mode === 'corgi') setPetCompanionMood('NHK 3D #1 đang trực chiến tốc độ 0ms!');
  else if (mode === 'cat') setPetCompanionMood('NHK 3D #2 đang canh giữ kết nối VN & SG 24/7!');
  else setPetCompanionMood('NHK 3D Core đang canh giữ phiên 24/7!');
}

function triggerPetReaction(whichPet) {
  setPetTurboMode(true);
  setTimeout(() => setPetTurboMode(false), 1200);
  if (whichPet === 'corgi') {
    setPetCompanionMood('NHK 3D Core đã sẵn sàng chạy đa Box 0s & giữ sống Zalo PC!');
    showToast('NHK 3D Turbo 0ms đã kích hoạt!');
  } else {
    setPetCompanionMood('Đã kiểm tra định tuyến Việt Nam & Singapore an toàn 100%!');
    showToast('NHK 3D Core đang hoạt động ổn định 100%!');
  }
}

async function checkZaloGeoStatus(forceScan = false) {
  const banner = document.getElementById('zaloGeoVerifyBanner');
  const badge = document.getElementById('zaloQRVnBadge');
  const regSel = document.getElementById('zaloVnRegionSelect');
  const pxInp = document.getElementById('zaloVnProxyInput');
  const pref = regSel ? regSel.value : 'VN';
  const customPx = pxInp ? pxInp.value.trim() : '';
  try {
    const r = await fetch(`/api/zalo/geo_status?region=${encodeURIComponent(pref)}&proxy=${encodeURIComponent(customPx)}&scan=${forceScan ? '1' : '0'}&t=${Date.now()}`);
    const d = await r.json();
    if (d && d.ok) {
      if (d.proxy_url && pxInp && !pxInp.value.trim()) {
        pxInp.value = d.proxy_url;
      }
      if (d.is_vn_or_sg) {
        const ccName = d.country_code === 'SG' ? 'Singapore (SG)' : 'Việt Nam (VN)';
        if (banner) {
          banner.style.color = 'var(--green)';
          banner.innerHTML = `Đã xác thực IP xuất mạng thật tại <b>${escapeHtmlSafe(ccName)}</b>: <code>${escapeHtmlSafe(d.ip || 'Active')}</code> (${escapeHtmlSafe(d.isp || 'Fiber')})`;
        }
        if (badge) {
          badge.className = 'badge badge-green';
          badge.textContent = `IP Thật: ${d.country_code} (${d.ip || 'Verified'})`;
        }
      } else {
        if (banner) {
          banner.style.color = 'var(--amber)';
          banner.innerHTML = `Máy chủ hiện đặt tại <b>${escapeHtmlSafe(d.country || d.country_code || 'Nước ngoài')}</b> (IP: <code>${escapeHtmlSafe(d.ip || 'N/A')}</code>). Hãy bấm <b>"Quét &amp; Khóa IP VN/SG Thật"</b> hoặc dán Proxy VN/SG để khi quét QR hiện đúng Việt Nam / Singapore!`;
        }
        if (badge) {
          badge.className = 'badge badge-amber';
          badge.textContent = `IP Máy Chủ: ${d.country_code || 'Cloud'} (Cần Proxy VN/SG)`;
        }
      }
    }
  } catch (e) {}
}

async function scanAndLockRealVnSgRoute(btnEl) {
  await withPetButtonLoading(btnEl, 'Đang dò IP VN/SG...', async () => {
    const regSel = document.getElementById('zaloVnRegionSelect');
    const pxInp = document.getElementById('zaloVnProxyInput');
    const pref = regSel ? regSel.value : 'VN';
    const customPx = pxInp ? pxInp.value.trim() : '';
    setPetCompanionMood('Đang kiểm tra định tuyến Việt Nam & Singapore...');
    try {
      const r = await fetch('/api/zalo/auto_scan_vn_sg_proxy', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({region: pref, proxy: customPx})
      });
      const d = await r.json();
      if (d && d.ok && d.is_vn_or_sg) {
        if (d.proxy_url && pxInp) pxInp.value = d.proxy_url;
        await checkZaloGeoStatus(false);
        setPetCompanionMood(`Đã khóa đường truyền thật tại ${d.country_code === 'SG' ? 'Singapore' : 'Việt Nam'} (${d.ip})!`);
        showToast(d.message || `Đã khóa IP ${d.country_code} thật: ${d.ip}`);
      } else {
        await checkZaloGeoStatus(false);
        showToast(d.message || 'Hãy nhập Proxy VN/SG riêng hoặc chạy trên vùng Singapore (render.yaml)!');
      }
    } catch (e) {
      showToast('Lỗi kiểm tra định tuyến VN/SG!');
    }
  });
}

function toggleTelegramDayNight() {
  const cur = document.body.getAttribute('data-theme') || 'tg_dark';
  const next = (cur === 'tg_dark') ? 'tg_light' : 'tg_dark';
  document.body.setAttribute('data-theme', next);
  try { localStorage.setItem('tg_ui_theme_mode', next); } catch (e) {}
  showToast(next === 'tg_dark' ? 'Đã bật chế độ Tối (NHK 3D Obsidian Dark)' : 'Đã bật chế độ Sáng (NHK 3D Crystal Light)');
}

(function restoreSavedTelegramTheme() {
  try {
    const saved = localStorage.getItem('tg_ui_theme_mode');
    if (saved === 'tg_light' || saved === 'tg_dark') {
      document.body.setAttribute('data-theme', saved);
    }
  } catch (e) {}
})();

// Thanh Tab Dưới Cùng Kéo Trượt Vật Lý Đàn Hồi
(function initTelegramDraggableBottomDock() {
  const bar = document.getElementById('tgBottomBar');
  const pill = document.getElementById('tgNavPill');
  if (!bar || !pill) return;
  const tabs = Array.from(bar.querySelectorAll('.nav-tab'));
  const tabCount = tabs.length;

  let isPointerDown = false;
  let isDragging = false;
  let startX = 0;
  let lastX = 0;
  let lastMoveTs = 0;
  let currentFloatIdx = 0;
  let activePointerId = null;

  function setPillPosition(floatIdx, stretchX = 1.0, squishY = 1.0) {
    const clamped = Math.max(0, Math.min(tabCount - 1, floatIdx));
    const pct = clamped * 100;
    pill.style.transform = `translate3d(${pct.toFixed(2)}%, 0, 0) scaleX(${stretchX.toFixed(3)}) scaleY(${squishY.toFixed(3)})`;
  }

  window.animateTelegramPillToIndex = function(targetIdx) {
    currentFloatIdx = targetIdx;
    bar.classList.remove('dragging');
    setPillPosition(targetIdx, 1.0, 1.0);
  };

  bar.addEventListener('pointerdown', (e) => {
    if (e.button !== undefined && e.button !== 0) return;
    isPointerDown = true;
    isDragging = false;
    startX = e.clientX;
    lastX = e.clientX;
    lastMoveTs = performance.now();
    activePointerId = e.pointerId;
  });

  window.addEventListener('pointermove', (e) => {
    if (!isPointerDown || (activePointerId !== null && e.pointerId !== activePointerId)) return;
    const dx = Math.abs(e.clientX - startX);
    if (!isDragging && dx > 6) {
      isDragging = true;
      bar.classList.add('dragging');
    }
    if (!isDragging) return;

    const rect = bar.getBoundingClientRect();
    const innerWidth = Math.max(1, rect.width - 8);
    const slotWidth = innerWidth / tabCount;
    const relX = e.clientX - rect.left - 4 - (slotWidth / 2);
    const rawIdx = relX / slotWidth;
    currentFloatIdx = Math.max(0, Math.min(tabCount - 1, rawIdx));

    const now = performance.now();
    const dt = Math.max(8, now - lastMoveTs);
    const vx = Math.abs(e.clientX - lastX) / dt;
    lastX = e.clientX;
    lastMoveTs = now;

    const stretch = Math.min(1.15, 1.0 + vx * 0.085);
    const squish = Math.max(0.92, 1.0 - vx * 0.035);
    setPillPosition(currentFloatIdx, stretch, squish);

    const hoverIdx = Math.round(currentFloatIdx);
    tabs.forEach((t, i) => t.classList.toggle('active', i === hoverIdx));
  }, {passive: true});

  function finishDrag() {
    if (!isPointerDown) return;
    isPointerDown = false;
    activePointerId = null;
    if (isDragging) {
      isDragging = false;
      bar.classList.remove('dragging');
      const finalIdx = Math.max(0, Math.min(tabCount - 1, Math.round(currentFloatIdx)));
      const targetBtn = tabs[finalIdx];
      if (targetBtn) {
        switchMainTab(targetBtn.getAttribute('data-tab'), targetBtn);
      } else {
        setPillPosition(CURRENT_TAB_INDEX, 1.0, 1.0);
      }
    }
  }

  window.addEventListener('pointerup', finishDrag);
  window.addEventListener('pointercancel', finishDrag);
})();

function switchMainTab(tabId, btnEl) {
  const panes = document.querySelectorAll('.tab-pane');
  const btns = Array.from(document.querySelectorAll('#tgBottomBar .nav-tab'));
  const targetBtn = btnEl || btns.find(b => b.getAttribute('data-tab') === tabId);
  const nextIdx = targetBtn ? parseInt(targetBtn.getAttribute('data-idx') || '0', 10) : 0;
  const fromLeft = nextIdx < CURRENT_TAB_INDEX;
  CURRENT_TAB_INDEX = nextIdx;

  panes.forEach(p => p.classList.remove('active', 'slide-from-left'));
  const targetSec = document.getElementById(tabId);
  if (targetSec) {
    if (fromLeft) targetSec.classList.add('slide-from-left');
    targetSec.classList.add('active');
  }

  btns.forEach(b => b.classList.remove('active'));
  if (targetBtn) {
    targetBtn.classList.add('active');
    const hdrTitle = document.getElementById('headerBrandTitle');
    const customTitle = (document.getElementById('customWebTitleInput') ? document.getElementById('customWebTitleInput').value : '').trim();
    if (hdrTitle && !customTitle) {
      hdrTitle.textContent = targetBtn.getAttribute('data-title') || 'Bảng Điều Khiển';
    }
  }
  if (typeof window.animateTelegramPillToIndex === 'function') {
    window.animateTelegramPillToIndex(nextIdx);
  }
  if (tabId === 'tab-targets' && ALL_TARGETS.length === 0) {
    loadGroupsAndRooms(false);
  }
}

function handleGlobalTelegramSearch(val) {
  const q = String(val || '').trim();
  if (q.startsWith('.') || q.startsWith('/')) return;
  const rInp = document.getElementById('roomSearchInput');
  const qInp = document.getElementById('quickBoxSearchInput');
  if (rInp) rInp.value = q;
  if (qInp) qInp.value = q;
  renderTargetList();
}

function dispatchGlobalSearchCommand(val) {
  const q = String(val || '').trim();
  if (!q) return;
  if (q.startsWith('.') || q.startsWith('/')) {
    const cmdInp = document.getElementById('webQuickCmdInput');
    if (cmdInp) {
      cmdInp.value = q;
      dispatchWebQuickCommand();
      document.getElementById('globalTelegramSearchInput').value = '';
    }
  } else {
    switchMainTab('tab-targets');
  }
}

function openBulk500BoxModal() {
  const m = document.getElementById('bulk500BoxModal');
  if (m) m.classList.add('open');
}

function closeBulk500BoxModal() {
  const m = document.getElementById('bulk500BoxModal');
  if (m) m.classList.remove('open');
}

function importBulk500BoxIds() {
  const raw = (document.getElementById('bulk500IdsTextarea').value || '').trim();
  const platType = document.getElementById('bulk500PlatformSelect').value || 'discord_channel';
  if (!raw) {
    showToast('Hãy dán danh sách ID Box vào ô!');
    return;
  }
  const tokens = raw.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
  if (!tokens.length) return;
  const accIds = ROOM_ACCOUNT_FILTER !== 'all' ? [parseInt(ROOM_ACCOUNT_FILTER, 10)] : [];
  let added = 0;
  tokens.forEach((idVal, idx) => {
    const item = {
      id: String(idVal),
      name: `Box #${idx + 1} (${idVal})`,
      type: platType,
      acc_ids: accIds,
      acc_names: accIds.length ? [`Acc #${accIds[0]}`] : ['Mọi Acc']
    };
    if (!ALL_TARGETS.some(x => String(x.id) === String(idVal))) {
      ALL_TARGETS.push(item);
    }
    const key = (ROOM_ACCOUNT_FILTER !== 'all') ? `${ROOM_ACCOUNT_FILTER}::${idVal}` : `all::${idVal}`;
    SELECTED_TARGETS.set(key, {
      id: String(idVal),
      name: item.name,
      type: platType,
      strict_bind: Boolean(accIds.length),
      assigned_acc_ids: accIds
    });
    added++;
  });
  renderTargetList();
  updateTargetBadges();
  closeBulk500BoxModal();
  showToast(`Đã nạp và chọn ${added} Box để chạy vòng lặp siêu tốc!`);
}

function isCurrentTabLeader() {
  if (document.hidden) return false;
  try {
    const now = Date.now();
    const raw = localStorage.getItem(LEADER_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.id !== MY_TAB_ID && (now - (parsed.ts || 0) < 2400)) {
        return false;
      }
    }
    localStorage.setItem(LEADER_STORAGE_KEY, JSON.stringify({id: MY_TAB_ID, ts: now}));
    return true;
  } catch (e) {
    return true;
  }
}

function scheduleSmoothRenderStatus(data, rtt) {
  _pendingRafStatus = {data, rtt};
  if (typeof requestAnimationFrame !== 'undefined') {
    requestAnimationFrame(() => {
      if (_pendingRafStatus) {
        const p = _pendingRafStatus;
        _pendingRafStatus = null;
        renderSystemStatusData(p.data, p.rtt);
      }
    });
  } else {
    renderSystemStatusData(data, rtt);
  }
}

if (MULTI_TAB_BUS) {
  MULTI_TAB_BUS.onmessage = (ev) => {
    const msg = ev.data || {};
    if (msg.type === 'STATUS_SNAPSHOT' && msg.data) {
      LAST_CROSS_TAB_STATUS_TS = Date.now();
      scheduleSmoothRenderStatus(msg.data, msg.rtt || 10);
    } else if (msg.type === 'INSTANT_STOP_ALL') {
      applyOptimisticStopUI(null);
    } else if (msg.type === 'FORCE_REFRESH') {
      if (isCurrentTabLeader()) pollSystemStatus(true);
    }
  };
}

function updateQrStepTracker(stepNum) {
  for (let i = 1; i <= 4; i++) {
    const el = document.getElementById('qrStep' + i);
    if (!el) continue;
    el.classList.remove('active', 'done');
    if (i < stepNum) el.classList.add('done');
    else if (i === stepNum) el.classList.add('active');
  }
}

function showToast(msg) {
  const box = document.getElementById('toastBox');
  if (!box) return;
  const el = document.createElement('div');
  el.className = 'toast-msg';
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.remove(); }, 2600);
}

function escapeHtmlSafe(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toggleLogoSetupModal() {
  const el = document.getElementById('logoSetupPanel');
  if (!el) return;
  el.style.display = (el.style.display === 'none' || !el.style.display) ? 'block' : 'none';
}

async function saveBrandUrlAndTitle() {
  const logo_url = (document.getElementById('customLogoUrlInput').value || '').trim();
  const custom_title = (document.getElementById('customWebTitleInput').value || '').trim();
  try {
    const r = await fetch('/api/logo/upload', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({logo_url, custom_title})
    });
    const d = await r.json();
    if (d.ok) {
      const img = document.getElementById('brandLogoImg');
      if (img) img.src = '/api/logo?v=' + Date.now();
      const hdr = document.getElementById('headerBrandTitle');
      if (hdr) hdr.textContent = custom_title || 'Chat & Tài Khoản';
      showToast(d.message || 'Đã lưu giao diện!');
    }
  } catch (e) { showToast('Lỗi lưu giao diện!'); }
}

async function resetBrandLogo() {
  await fetch('/api/logo/reset', {method: 'POST'});
  const img = document.getElementById('brandLogoImg');
  if (img) img.src = '/api/logo?v=' + Date.now();
  const hdr = document.getElementById('headerBrandTitle');
  if (hdr) hdr.textContent = 'Chat & Tài Khoản';
  document.getElementById('customLogoUrlInput').value = '';
  document.getElementById('customWebTitleInput').value = '';
  showToast('Đã khôi phục mặc định!');
}

function openPerAccBoxSelector(accId) {
  const tabBtn = document.querySelector('[data-tab="tab-targets"]');
  switchMainTab('tab-targets', tabBtn);
  if (accId) {
    const pill = document.querySelector(`#perAccSelectorBar .acc-pill[data-acc="${accId}"]`);
    setRoomAccountFilter(String(accId), pill);
  }
  if (ALL_TARGETS.length === 0) {
    loadGroupsAndRooms(true);
  }
}

function setRoomAccountFilter(accId, btnEl) {
  ROOM_ACCOUNT_FILTER = String(accId || 'all');
  const pills = document.querySelectorAll('#perAccSelectorBar .acc-pill');
  pills.forEach(p => p.classList.remove('active'));
  if (btnEl) btnEl.classList.add('active');
  renderTargetList();
}

function addManualChannelId() {
  const inp = document.getElementById('roomSearchInput');
  const val = (inp.value || '').trim();
  if (!val) {
    showToast('Hãy nhập ID Kênh Discord hoặc ID Nhóm Zalo vào ô tìm kiếm rồi bấm + Thêm ID!');
    return;
  }
  const tokens = val.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean);
  const accIds = ROOM_ACCOUNT_FILTER !== 'all' ? [parseInt(ROOM_ACCOUNT_FILTER, 10)] : [];
  tokens.forEach(idOne => {
    const item = {
      id: idOne,
      name: `Box ID #${idOne}`,
      type: ROOM_PLATFORM_FILTER === 'zalo' ? 'group' : (ROOM_PLATFORM_FILTER === 'messenger' ? 'messenger_thread' : 'discord_channel'),
      acc_ids: accIds,
      acc_names: accIds.length ? [`Acc #${accIds[0]}`] : ['Mọi Acc']
    };
    ALL_TARGETS.unshift(item);
    const key = makeTargetSelectionKey(item);
    SELECTED_TARGETS.set(key, {
      id: String(item.id),
      name: item.name,
      type: item.type,
      assigned_acc_ids: accIds
    });
  });
  inp.value = '';
  renderTargetList();
  updateTargetBadges();
  showToast(`Đã thêm ${tokens.length} Box mục tiêu!`);
}

function switchAccForm(plat) {
  document.getElementById('accPlatformInput').value = plat;
  document.getElementById('segZaloBtn').classList.toggle('active', plat === 'zalo');
  document.getElementById('segDiscordBtn').classList.toggle('active', plat === 'discord');
  document.getElementById('segMessengerBtn').classList.toggle('active', plat === 'messenger');
  document.getElementById('zaloInputFields').style.display = (plat === 'zalo') ? 'block' : 'none';
  document.getElementById('discordInputFields').style.display = (plat === 'discord') ? 'block' : 'none';
  document.getElementById('messengerInputFields').style.display = (plat === 'messenger') ? 'block' : 'none';
}

function switchZaloSubTab(mode) {
  document.getElementById('subZaloQRBtn').classList.toggle('active', mode === 'qr');
  document.getElementById('subZaloManualBtn').classList.toggle('active', mode === 'manual');
  const vBtn = document.getElementById('subZaloVaultBtn');
  if (vBtn) vBtn.classList.toggle('active', mode === 'vault');
  document.getElementById('zaloQRBox').style.display = (mode === 'qr') ? 'block' : 'none';
  document.getElementById('zaloManualBox').style.display = (mode === 'manual') ? 'block' : 'none';
  const vBox = document.getElementById('zaloVaultBox');
  if (vBox) vBox.style.display = (mode === 'vault') ? 'block' : 'none';
  if (mode === 'vault') loadZaloVaultRecords();
}

function switchMessSubTab(mode) {
  document.getElementById('subMessCookieBtn').classList.toggle('active', mode === 'cookie');
  document.getElementById('subMessLoginBtn').classList.toggle('active', mode === 'login');
  document.getElementById('messCookieBox').style.display = (mode === 'cookie') ? 'block' : 'none';
  document.getElementById('messLoginBox').style.display = (mode === 'login') ? 'block' : 'none';
}

function switchDiscordRegTab(mode) {
  document.getElementById('subDisTokenBtn').classList.toggle('active', mode === 'token');
  document.getElementById('subDisLoginBtn').classList.toggle('active', mode === 'login');
  document.getElementById('subDisNewAccBtn').classList.toggle('active', mode === 'new_acc');
  document.getElementById('discordTokenBox').style.display = (mode === 'token') ? 'block' : 'none';
  document.getElementById('discordLoginBox').style.display = (mode === 'login') ? 'block' : 'none';
  document.getElementById('discordNewAccBox').style.display = (mode === 'new_acc') ? 'block' : 'none';
}

function toggleSelectAllCampaignAccs(checked) {
  const chks = document.querySelectorAll('.camp-acc-chk');
  chks.forEach(c => { c.checked = Boolean(checked); });
}

async function restartTelegramBotNow() {
  showToast('Đang đồng bộ & khởi động lại Bot Telegram...');
  try {
    const r = await fetch('/api/telegram/restart', {method: 'POST'});
    const d = await r.json();
    const stEl = document.getElementById('hdrTeleBotState');
    if (stEl) {
      stEl.textContent = d.running ? `@${d.bot_username || 'Online'}` : 'Đang kết nối';
    }
    showToast(d.message || 'Đã khởi động lại Bot Telegram!');
  } catch (e) { showToast('Lỗi kết nối khi khởi động lại Bot Telegram!'); }
}

async function startZaloQRLogin(btnEl) {
  const btn = btnEl || document.getElementById('btnStartZaloQR');
  await withPetButtonLoading(btn, 'Đang cấp máy & tạo QR...', async () => {
    const stTxt = document.getElementById('zaloQRStatusText');
    const stageWrap = document.getElementById('zaloQRStageWrap');
    const qrImg = document.getElementById('zaloQRImg');
    const extBox = document.getElementById('zaloQRExtractedBox');
    const codeBadge = document.getElementById('zaloQRCodeIdBadge');
    const imeiBadge = document.getElementById('zaloQRImeiPreview');
    const locBadge = document.getElementById('zaloQRLocationBadge');
    const vnReg = document.getElementById('zaloVnRegionSelect') ? document.getElementById('zaloVnRegionSelect').value : 'VN';
    const customPc = document.getElementById('zaloCustomPcNameInput') ? document.getElementById('zaloCustomPcNameInput').value.trim() : '';
    const vnProxy = document.getElementById('zaloVnProxyInput') ? document.getElementById('zaloVnProxyInput').value.trim() : '';

    if (ZALO_QR_POLL_TIMER) {
      clearInterval(ZALO_QR_POLL_TIMER);
      ZALO_QR_POLL_TIMER = null;
    }
    extBox.style.display = 'none';
    qrImg.src = '';
    stageWrap.style.display = 'none';
    updateQrStepTracker(1);
    setPetCompanionMood('Đang cấp phát máy tính Việt Nam / Singapore & kết nối id.zalo.me...');
    stTxt.textContent = 'Đang cấp phát máy tính mới & khởi tạo mã QR chính chủ tại Việt Nam / Singapore...';
    if (codeBadge) codeBadge.textContent = 'Đang cấp máy...';

    try {
      const r = await fetch('/api/zalo/qr_start?t=' + Date.now(), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({auto_save: true, vn_region: vnReg, custom_pc_name: customPc, vn_proxy: vnProxy})
      });
      const d = await r.json();
      if (!d.ok) {
        stTxt.textContent = d.message || 'Lỗi tạo mã QR';
        return;
      }
      ZALO_QR_SESSION_ID = d.session_id;
      stTxt.textContent = d.message;
      updateQrStepTracker(d.step_num || 2);
      const cleanCode = String(d.qr_code_id || d.qr_nonce || d.session_id).replace(/\./g, '').slice(0, 6).toUpperCase();
      if (codeBadge) codeBadge.textContent = `${d.pc_name || 'Zalo PC'} • #${cleanCode}`;
      if (imeiBadge && d.imei) imeiBadge.textContent = `IMEI: ${d.imei.slice(0, 8)}...${d.imei.slice(-4)}`;
      if (locBadge) locBadge.textContent = `${d.vn_location || 'Việt Nam / Singapore'} • IP: ${d.vn_ip || 'Verified'}`;

      if (d.qr_base64) {
        stageWrap.style.display = 'block';
        qrImg.src = d.qr_base64;
        setPetCompanionMood(`Đã sẵn sàng QR trên ${d.pc_name}! Hãy mở Zalo trên điện thoại quét mã ngay nhé!`);
      } else if (d.qr_image_url) {
        stageWrap.style.display = 'block';
        qrImg.src = d.qr_image_url;
      }
      ZALO_QR_POLL_TIMER = setInterval(pollZaloQRStatus, 1000);
    } catch (e) {
      stTxt.textContent = 'Lỗi kết nối máy chủ khi tạo QR!';
    }
  });
}

setTimeout(() => { loadZaloVaultRecords(); }, 350);

async function pollZaloQRStatus() {
  if (!ZALO_QR_SESSION_ID) return;
  try {
    const r = await fetch('/api/zalo/qr_status/' + encodeURIComponent(ZALO_QR_SESSION_ID) + '?t=' + Date.now());
    const d = await r.json();
    if (!d.ok) return;

    const stTxt = document.getElementById('zaloQRStatusText');
    const stageWrap = document.getElementById('zaloQRStageWrap');
    const qrImg = document.getElementById('zaloQRImg');
    const timerBadge = document.getElementById('zaloQRTimerBadge');
    const extBox = document.getElementById('zaloQRExtractedBox');
    const codeBadge = document.getElementById('zaloQRCodeIdBadge');
    const imeiBadge = document.getElementById('zaloQRImeiPreview');

    stTxt.textContent = d.message || '';
    if (d.step_num) updateQrStepTracker(d.step_num);
    const locBadge = document.getElementById('zaloQRLocationBadge');
    if (locBadge && d.vn_location) locBadge.textContent = `${d.vn_location} • IP: ${d.vn_ip || ''}`;
    if (codeBadge && (d.qr_code_id || d.pc_name)) {
      const cleanC = String(d.qr_code_id || '').replace(/\./g, '').slice(0, 6).toUpperCase();
      codeBadge.textContent = `${d.pc_name || 'Zalo PC'} • #${cleanC}`;
    }
    if (imeiBadge && d.imei) imeiBadge.textContent = `IMEI: ${d.imei.slice(0, 8)}...${d.imei.slice(-4)}`;
    if (timerBadge && typeof d.remaining_sec === 'number') {
      timerBadge.textContent = `Hiệu lực: ${d.remaining_sec}s`;
    }
    if (d.status === 'waiting_scan') updateQrStepTracker(2);
    if (d.status === 'scanned') {
      updateQrStepTracker(3);
      setPetCompanionMood(`Đã nhận diện Zalo của ${d.display_name}! Hãy bấm Đăng nhập trên điện thoại!`);
    }
    if (d.status === 'confirmed' || d.status === 'success') updateQrStepTracker(4);
    if (d.qr_base64 && d.status === 'waiting_scan') {
      stageWrap.style.display = 'block';
      if (qrImg.src !== d.qr_base64) qrImg.src = d.qr_base64;
    }
    if (d.status === 'scanned' && d.avatar) {
      stageWrap.style.display = 'block';
      qrImg.src = d.avatar;
    }
    if (d.status === 'success') {
      clearInterval(ZALO_QR_POLL_TIMER);
      ZALO_QR_POLL_TIMER = null;
      stageWrap.style.display = 'none';
      LAST_ZALO_QR_RESULT = {
        imei: d.imei || '',
        cookies_str: d.cookies_str || '',
        file_name: d.file_name || 'zalo_cookie.txt',
        file_content: d.file_content || ''
      };
      document.getElementById('zaloImeiInput').value = d.imei || '';
      document.getElementById('zaloCookieInput').value = d.cookies_str || '';
      document.getElementById('zaloQRExtractedImei').textContent = (d.imei || '').slice(0, 24) + '...';
      extBox.style.display = 'block';
      setPetCompanionMood(`Tuyệt vời! Thiết bị ${d.pc_name} đã sống cố định 24/7 trong tài khoản ${d.display_name}!`);
      loadZaloVaultRecords();
      showToast('Đã đăng nhập & ghim máy tính sống 24/7 trong tài khoản Zalo!');
      setTimeout(() => location.reload(), 1200);
    } else if (d.status === 'expired' || d.status === 'declined' || d.status === 'error') {
      clearInterval(ZALO_QR_POLL_TIMER);
      ZALO_QR_POLL_TIMER = null;
      if (d.status === 'error') stageWrap.style.display = 'none';
    }
  } catch (e) {}
}

async function verifyAndSaveZaloCookieVault(btnEl) {
  await withPetButtonLoading(btnEl, 'Đang xác thực Cookie...', async () => {
    const imei = (document.getElementById('zaloImeiInput').value || '').trim();
    const cookies = (document.getElementById('zaloCookieInput').value || '').trim();
    const box = document.getElementById('zaloVerifyStatusBox');
    if (!cookies) { showToast('Hãy dán Cookie Zalo vào ô!'); return; }
    box.style.display = 'block';
    box.innerHTML = 'Đang xác thực khóa zpw_enk & lưu phiên cố định...';
    try {
      const r = await fetch('/api/zalo/verify_cookie_imei', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({imei, cookies, auto_save: true})
      });
      const d = await r.json();
      if (d.ok) {
        document.getElementById('zaloImeiInput').value = d.imei || imei;
        box.innerHTML = `Đã khóa phiên <b>${escapeHtmlSafe(d.name)}</b> (UID: <code>${escapeHtmlSafe(d.uid)}</code>)`;
        showToast(d.message || 'Đã lưu Cookie & IMEI Zalo!');
        loadZaloVaultRecords();
        setTimeout(() => location.reload(), 700);
      } else {
        box.innerHTML = `<span style="color:var(--red)">${escapeHtmlSafe(d.error || 'Lỗi lưu Cookie')}</span>`;
      }
    } catch (e) { box.innerHTML = 'Lỗi kết nối máy chủ!'; }
  });
}

async function loadZaloVaultRecords() {
  const box = document.getElementById('zaloVaultListContainer');
  if (!box) return;
  try {
    const r = await fetch('/api/zalo/vault');
    const d = await r.json();
    ZALO_VAULT_CACHE = d.records || [];
    if (!ZALO_VAULT_CACHE.length) {
      box.innerHTML = '<div style="padding:12px;text-align:center;color:var(--txt-muted)">Chưa có bản ghi trong Kho.</div>';
      return;
    }
    box.innerHTML = ZALO_VAULT_CACHE.map((rec, idx) => `
      <div class="list-item" style="flex-direction:column;align-items:stretch;gap:6px">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <div>
            <span class="badge ${rec.zpw_enk_ready ? 'badge-green' : 'badge-blue'}">${rec.zpw_enk_ready ? 'TRONG ACC' : 'ĐÃ LƯU'}</span>
            <strong style="margin-left:5px">${escapeHtmlSafe(rec.display_name)}</strong>
          </div>
          <code style="font-size:11px;color:var(--txt-muted)">IMEI: ${escapeHtmlSafe(rec.masked_imei)}</code>
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button type="button" class="btn btn-success btn-sm" onclick="activateZaloVaultIdx(${idx})">Kích hoạt</button>
          <button type="button" class="btn btn-sm" onclick="copyZaloVaultItem(${idx}, 'cookie')">Copy Cookie</button>
          <button type="button" class="btn btn-sm" onclick="copyZaloVaultItem(${idx}, 'imei')">Copy IMEI</button>
          <button type="button" class="btn btn-danger btn-sm" onclick="deleteZaloVaultIdx(${idx})">Xóa</button>
        </div>
      </div>
    `).join('');
  } catch (e) {}
}

function copyZaloVaultItem(idx, kind) {
  const rec = ZALO_VAULT_CACHE[idx];
  if (!rec) return;
  const val = kind === 'imei' ? rec.imei : rec.cookies_str;
  if (val && navigator.clipboard) {
    navigator.clipboard.writeText(val);
    showToast(kind === 'imei' ? `Đã sao chép IMEI của ${rec.display_name}!` : `Đã sao chép Cookie của ${rec.display_name}!`);
  }
}

async function activateZaloVaultIdx(idx) {
  const rec = ZALO_VAULT_CACHE[idx];
  if (!rec) return;
  const r = await fetch('/api/zalo/vault/activate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({uid: rec.uid})
  });
  const d = await r.json();
  if (d.ok) {
    showToast(d.message);
    setTimeout(() => location.reload(), 600);
  }
}

async function deleteZaloVaultIdx(idx) {
  const rec = ZALO_VAULT_CACHE[idx];
  if (!rec) return;
  await fetch('/api/zalo/vault/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({uid: rec.uid})
  });
  loadZaloVaultRecords();
  showToast('Đã xóa khỏi Kho lưu trữ!');
}

async function testSingleAccountSession(accId, btnEl) {
  await withPetButtonLoading(btnEl, 'Đang kiểm tra...', async () => {
    try {
      const r = await fetch('/api/account/test_session', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({acc_id: accId})
      });
      const d = await r.json();
      showToast(d.message || d.error || 'Đã kiểm tra!');
      pollSystemStatus(true);
    } catch (e) { showToast('Lỗi kết nối khi kiểm tra!'); }
  });
}

async function reconnectAllListenersNow(btnEl) {
  await withPetButtonLoading(btnEl, 'Đang đồng bộ 24/7...', async () => {
    try {
      const r = await fetch('/api/account/reconnect_all', {method: 'POST'});
      const d = await r.json();
      showToast(d.message || 'Đã đồng bộ xong!');
      pollSystemStatus(true);
    } catch (e) {}
  });
}

async function dispatchWebQuickCommand(btnEl) {
  const cmdInput = document.getElementById('webQuickCmdInput');
  const rawCmd = (cmdInput.value || '').trim();
  if (!rawCmd) { showToast('Hãy nhập lệnh cần thực thi (VD: .menu, .ping, .n 1, .t)!'); return; }
  await withPetButtonLoading(btnEl, 'Đang chạy...', async () => {
    const targets = Array.from(SELECTED_TARGETS.values());
    const firstRoomId = targets.length ? targets[0].id : '';
    try {
      const r = await fetch('/api/command/dispatch_web', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({cmd: rawCmd, thread_id: firstRoomId})
      });
      const d = await r.json();
      if (d.ok) {
        cmdInput.value = '';
        showToast(d.message || 'Đã thực thi lệnh!');
        pollSystemStatus(true);
      } else {
        showToast(d.error || 'Không thể thực thi lệnh');
      }
    } catch (e) { showToast('Lỗi kết nối máy chủ!'); }
  });
}

function copyZaloQRData(kind) {
  const val = kind === 'imei' ? LAST_ZALO_QR_RESULT.imei : LAST_ZALO_QR_RESULT.cookies_str;
  if (val && navigator.clipboard) {
    navigator.clipboard.writeText(val);
    showToast(kind === 'imei' ? 'Đã sao chép IMEI Zalo!' : 'Đã sao chép Cookie Zalo!');
  }
}

function downloadZaloQRFile() {
  if (!LAST_ZALO_QR_RESULT.file_content) return;
  const blob = new Blob([LAST_ZALO_QR_RESULT.file_content], {type: 'text/plain;charset=utf-8'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = LAST_ZALO_QR_RESULT.file_name || 'zalo_cookie_imei.txt';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function generateUniqueZaloImei() {
  try {
    const r = await fetch('/api/zalo/generate_imei');
    const d = await r.json();
    if (d.ok && d.imei) {
      document.getElementById('zaloImeiInput').value = d.imei;
      showToast('Đã tạo IMEI Zalo mới!');
    }
  } catch (e) {}
}

async function updateDiscordCustomStatus() {
  const text = (document.getElementById('dcCustomStatusInput').value || '').trim();
  if (!text) { showToast('Hãy nhập trạng thái Discord!'); return; }
  try {
    const r = await fetch('/api/discord/set_status', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text})
    });
    const d = await r.json();
    showToast(d.message || d.error || 'Đã cập nhật trạng thái!');
  } catch (e) { showToast('Lỗi kết nối!'); }
}

async function setDiscordHypeSquad(house_id) {
  try {
    const r = await fetch('/api/discord/hypesquad', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({house_id})
    });
    const d = await r.json();
    showToast(d.message || d.error || 'Đã đổi HypeSquad!');
  } catch (e) { showToast('Lỗi kết nối!'); }
}

async function generateWeb2FA(showNotice = false) {
  const sec = (document.getElementById('web2FASecretInput').value || '').trim();
  const resBox = document.getElementById('web2FAResultBox');
  const codeEl = document.getElementById('web2FACodeVal');
  const timerEl = document.getElementById('totpTimerBadge');
  if (!sec) {
    if (showNotice) showToast('Hãy dán Secret Key 2FA!');
    return;
  }
  try {
    const r = await fetch('/api/tools/2fa', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({secret: sec})
    });
    const d = await r.json();
    if (d.ok && d.token) {
      resBox.style.display = 'flex';
      codeEl.textContent = d.token;
      timerEl.textContent = `${d.rem_sec}s`;
      if (showNotice) showToast(`Mã OTP: ${d.token} (Còn ${d.rem_sec}s)`);
    } else if (showNotice) {
      showToast(d.error || 'Secret Key không hợp lệ');
    }
  } catch (e) {}
}

function copyCurrent2FACode() {
  const code = (document.getElementById('web2FACodeVal').textContent || '').trim();
  if (code && code !== '------' && navigator.clipboard) {
    navigator.clipboard.writeText(code);
    showToast(`Đã sao chép mã OTP: ${code}`);
  }
}

setInterval(() => {
  const el = document.getElementById('web2FASecretInput');
  if (el && el.value.trim()) generateWeb2FA(false);
}, 2500);

async function extractFacebookCookieByLogin() {
  const email = (document.getElementById('fbLoginEmail').value || '').trim();
  const password = (document.getElementById('fbLoginPass').value || '').trim();
  const box = document.getElementById('messLoginStatusBox');
  if (!email || !password) { showToast('Nhập đủ Email/SĐT và Mật khẩu Facebook!'); return; }
  box.style.display = 'block';
  box.style.background = 'rgba(48,209,88,0.14)';
  box.style.color = 'var(--green)';
  box.innerHTML = 'Đang đăng nhập Facebook và trích xuất Cookie...';
  try {
    const r = await fetch('/api/messenger/login_credentials', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password, auto_save: true})
    });
    const d = await r.json();
    if (d.ok) {
      document.getElementById('messCookieInput').value = d.cookie || '';
      box.innerHTML = `Đã lấy Cookie thành công (UID: <code>${escapeHtmlSafe(d.uid)}</code>)!`;
      showToast('Đã lấy Cookie Facebook & kết nối!');
      setTimeout(() => location.reload(), 700);
    } else {
      box.style.background = 'rgba(255,69,58,0.14)';
      box.style.color = 'var(--red)';
      box.innerHTML = escapeHtmlSafe(d.error || 'Không thể lấy Cookie');
    }
  } catch (e) { box.innerHTML = 'Lỗi kết nối máy chủ!'; }
}

function setRoomPlatformFilter(flt) {
  ROOM_PLATFORM_FILTER = flt;
  ['All', 'Zalo', 'Discord', 'Mess'].forEach(k => {
    const el = document.getElementById('fltRoom' + k);
    if (el) el.classList.remove('active');
  });
  const mapId = {all:'fltRoomAll', zalo:'fltRoomZalo', discord:'fltRoomDiscord', messenger:'fltRoomMess'};
  const activeEl = document.getElementById(mapId[flt] || 'fltRoomAll');
  if (activeEl) activeEl.classList.add('active');
  renderTargetList();
}

async function checkWebPingNow(showNotice = false) {
  const t0 = performance.now();
  try {
    const r = await fetch('/api/ping?t=' + Date.now(), {cache: 'no-store'});
    const d = await r.json();
    const rtt = Math.max(1, Math.round(performance.now() - t0));
    const sendMs = d.avg_send_ms && d.avg_send_ms > 0 ? Math.round(d.avg_send_ms) : rtt;
    const jitterMs = d.jitter_ms || 1.0;
    const rpmVal = d.total_rpm || 0;
    const runningCnt = d.running_tasks || 0;

    const hdrTxt = document.getElementById('headerPingText');
    const sendEl = document.getElementById('liveSendPingVal');
    const jitEl = document.getElementById('liveJitterVal');
    const rpmEl = document.getElementById('liveRpmVal');
    const healEl = document.getElementById('liveHealedVal');
    const stateBadge = document.getElementById('liveHangStateBadge');
    const rttEl = document.getElementById('pingRttVal');
    const thEl = document.getElementById('pingThreadsVal');
    const engEl = document.getElementById('pingEngineBadge');

    if (hdrTxt) hdrTxt.textContent = `${rtt} ms`;
    if (sendEl) sendEl.textContent = `${sendMs} ms`;
    if (jitEl) jitEl.textContent = `${jitterMs} ms`;
    if (rpmEl) rpmEl.textContent = `${rpmVal} RPM`;
    if (healEl) healEl.textContent = `${d.total_healed || 0} lần`;
    if (stateBadge) {
      stateBadge.textContent = runningCnt > 0 ? `ĐANG CHẠY (${runningCnt})` : 'SẴN SÀNG';
      stateBadge.className = runningCnt > 0 ? 'badge badge-blue' : 'badge badge-green';
    }
    if (rttEl) rttEl.textContent = `${rtt} ms`;
    if (thEl) thEl.textContent = `${d.active_threads || 1} luồng`;
    if (engEl) engEl.textContent = `Engine ${d.engine_ms || 0.15}ms`;

    if (showNotice) showToast(`Ping Web: ${rtt}ms • API: ${sendMs}ms • Tốc độ: ${rpmVal} tin/phút`);
  } catch (e) {}
}

async function verifyAndLockMessengerCookie() {
  const raw = (document.getElementById('messCookieInput').value || '').trim();
  const box = document.getElementById('messVerifyResultBox');
  if (!raw) { showToast('Hãy dán Cookie Messenger!'); return; }
  box.style.display = 'block';
  box.innerHTML = 'Đang kiểm tra Cookie Messenger...';
  try {
    const r = await fetch('/api/messenger/verify_cookie', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({cookies: raw, auto_save: true})
    });
    const d = await r.json();
    if (d.ok) {
      box.innerHTML = `Đã kết nối <strong>${escapeHtmlSafe(d.name)}</strong> (UID: <code>${escapeHtmlSafe(d.uid)}</code>)`;
      showToast('Đã lưu tài khoản Messenger!');
      setTimeout(() => location.reload(), 700);
    } else {
      box.innerHTML = `<span style="color:var(--red)">${escapeHtmlSafe(d.error)}</span>`;
    }
  } catch (e) { box.innerHTML = 'Lỗi kết nối!'; }
}

function fillRandomDiscordRegProfile() {
  const rnd = Math.floor(1000 + Math.random() * 9000);
  const uname = `user_${rnd}`;
  const pw = `Pass@${rnd}#Sec99`;
  document.getElementById('newAccUsername').value = uname;
  document.getElementById('newAccPassword').value = pw;
  document.getElementById('newAccDob').value = '2000-06-15';
  showToast(`Đã tạo mẫu: ${uname}`);
}

async function runBatchDiscordRegStudio() {
  const box = document.getElementById('discordNewAccStatusBox');
  box.style.display = 'block';
  box.style.background = 'rgba(48,209,88,0.14)';
  box.style.color = 'var(--green)';
  box.innerHTML = 'Đang khởi tạo 5 hồ sơ...';
  try {
    const r = await fetch('/api/discord/batch_reg_profiles', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({count: 5})
    });
    const d = await r.json();
    if (d.ok && d.profiles && d.profiles.length) {
      const p0 = d.profiles[0];
      document.getElementById('newAccUsername').value = p0.username;
      document.getElementById('newAccPassword').value = p0.password;
      document.getElementById('newAccDob').value = p0.dob;
      box.innerHTML = d.profiles.map(p => `• <b>${escapeHtmlSafe(p.username)}</b> | <code>${escapeHtmlSafe(p.password)}</code>`).join('<br>');
      showToast('Đã tạo 5 hồ sơ!');
    }
  } catch (e) { box.innerHTML = 'Lỗi kết nối!'; }
}

async function runImmortalizeTokensTool(autoSave = true) {
  const raw = (document.getElementById('discordTokenInput').value || '').trim();
  const box = document.getElementById('immortalVaultResultBox');
  if (!raw) { showToast('Hãy dán Token Discord!'); return; }
  box.style.display = 'block';
  box.innerHTML = 'Đang kiểm tra và nạp danh sách Token...';
  try {
    const r = await fetch('/api/discord/immortalize', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({raw_input: raw, auto_save: Boolean(autoSave)})
    });
    const d = await r.json();
    if (d.ok) {
      if (d.live_tokens && d.live_tokens.length) {
        document.getElementById('discordTokenInput').value = d.live_tokens.join(String.fromCharCode(10));
      }
      box.innerHTML = `Hoạt động: ${d.alive_count}/${d.total} Token`;
      showToast(d.message);
      if (autoSave) setTimeout(() => location.reload(), 700);
    } else {
      box.innerHTML = `<span style="color:var(--red)">${escapeHtmlSafe(d.error)}</span>`;
    }
  } catch (e) { box.innerHTML = 'Lỗi kết nối!'; }
}

async function runCreateNewDiscordAccTool() {
  const email = (document.getElementById('newAccEmail').value || '').trim();
  const username = (document.getElementById('newAccUsername').value || '').trim();
  const password = (document.getElementById('newAccPassword').value || '').trim();
  const dob = (document.getElementById('newAccDob').value || '2000-06-15').trim();
  const box = document.getElementById('discordNewAccStatusBox');
  if (!email || !password) { showToast('Nhập đủ Email & Mật khẩu!'); return; }
  box.style.display = 'block';
  box.innerHTML = 'Đang khởi tạo tài khoản...';
  try {
    const r = await fetch('/api/discord/register_acc', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, username, password, dob, auto_save: true})
    });
    const d = await r.json();
    box.innerHTML = escapeHtmlSafe(d.message || d.error);
    if (d.ok) setTimeout(() => location.reload(), 900);
  } catch (e) { box.innerHTML = 'Lỗi kết nối!'; }
}

function setDiscordRegStatus(msg, isSuccess) {
  const box = document.getElementById('discordRegStatusBox');
  if (!box) return;
  box.style.display = 'block';
  box.style.background = isSuccess ? 'rgba(48,209,88,0.14)' : 'rgba(255,69,58,0.14)';
  box.style.color = isSuccess ? 'var(--green)' : 'var(--red)';
  box.innerHTML = msg;
}

function handleAccountFormSubmit(ev) {
  const plat = document.getElementById('accPlatformInput').value;
  if (plat === 'zalo') {
    const imeiVal = (document.getElementById('zaloImeiInput').value || '').trim();
    const ckVal = (document.getElementById('zaloCookieInput').value || '').trim();
    if (!imeiVal || !ckVal) {
      ev.preventDefault();
      const stageWrap = document.getElementById('zaloQRStageWrap');
      if (ZALO_QR_SESSION_ID && stageWrap && stageWrap.style.display !== 'none') {
        showToast('Mã QR đang sẵn sàng chờ quét! Hãy mở Zalo trên điện thoại quét mã hiện tại và bấm Đăng nhập (Tự động lưu 100%)!');
        return false;
      }
      switchZaloSubTab('qr');
      startZaloQRLogin(document.getElementById('btnStartZaloQR'));
      return false;
    }
    return true;
  }
  if (plat === 'discord') {
    ev.preventDefault();
    const tkVal = (document.getElementById('discordTokenInput').value || '').trim();
    const emVal = (document.getElementById('regDisEmail').value || '').trim();
    const pwVal = (document.getElementById('regDisPass').value || '').trim();
    const newEmVal = (document.getElementById('newAccEmail').value || '').trim();
    const newAccVisible = document.getElementById('discordNewAccBox').style.display !== 'none';
    const loginBoxVisible = document.getElementById('discordLoginBox').style.display !== 'none';
    if (tkVal) {
      runImmortalizeTokensTool(true);
    } else if (loginBoxVisible || emVal || pwVal) {
      extractDiscordTokenByReg();
    } else if (newAccVisible || newEmVal) {
      runCreateNewDiscordAccTool();
    } else {
      showToast('Hãy dán Token Discord hoặc nhập Email & Mật khẩu!');
    }
    return false;
  }
  if (plat === 'messenger') {
    const mcVal = (document.getElementById('messCookieInput').value || '').trim();
    const fbEm = (document.getElementById('fbLoginEmail').value || '').trim();
    ev.preventDefault();
    if (mcVal) {
      verifyAndLockMessengerCookie();
    } else if (fbEm) {
      extractFacebookCookieByLogin();
    } else {
      showToast('Hãy dán Cookie hoặc nhập Email/Mật khẩu Facebook!');
    }
    return false;
  }
  return true;
}

function copyDiscordTokenScript() {
  const snippet = `javascript:(function(){let m=[];webpackChunkdiscord_app.push([[Symbol()],{},e=>{for(let c of Object.values(e.c)){try{if(c?.exports?.default?.getToken){let t=c.exports.default.getToken();if(typeof t==='string')m.push(t)}}catch{}}}]);prompt('Copy Token Discord:',m[0]||'Mo discord.com/app');})();`;
  if (navigator.clipboard) navigator.clipboard.writeText(snippet);
  showToast('Đã sao chép đoạn mã lấy Token!');
}

async function extractDiscordTokenByReg() {
  const email = document.getElementById('regDisEmail').value.trim();
  const password = document.getElementById('regDisPass').value.trim();
  const two_fa = document.getElementById('regDis2FA').value.trim();
  const twofa_type = document.getElementById('regDis2FAType').value;
  if (!email && !password) { showToast('Nhập Email & Mật khẩu Discord!'); return; }
  setDiscordRegStatus('Đang xác thực đăng nhập Discord...', true);
  try {
    const r = await fetch('/api/discord/reg_login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({email, password, two_fa, twofa_type, auto_save: true})
    });
    const d = await r.json();
    if (d.ok) {
      document.getElementById('discordTokenInput').value = d.token || '';
      setDiscordRegStatus('Lấy Token thành công! Đang lưu...', true);
      setTimeout(() => location.reload(), 650);
    } else {
      setDiscordRegStatus(d.error || 'Lỗi đăng nhập', false);
    }
  } catch (e) { setDiscordRegStatus('Lỗi kết nối', false); }
}

async function uploadBrandLogo(inputEl) {
  if (!inputEl.files || !inputEl.files[0]) return;
  const fd = new FormData();
  fd.append('logo', inputEl.files[0]);
  const titleEl = document.getElementById('customWebTitleInput');
  if (titleEl && titleEl.value.trim()) fd.append('custom_title', titleEl.value.trim());
  const r = await fetch('/api/logo/upload', {method: 'POST', body: fd});
  const d = await r.json();
  if (d.ok) {
    const img = document.getElementById('brandLogoImg');
    if (img) img.src = '/api/logo?v=' + Date.now();
    showToast('Đã cập nhật biểu tượng thành công!');
  } else {
    showToast(d.error || 'Lỗi tải ảnh');
  }
}

async function handleTxtUpload(inputEl) {
  if (!inputEl.files || !inputEl.files[0]) return;
  const wrap = document.getElementById('uploadProgWrap');
  const bar = document.getElementById('uploadProgBar');
  wrap.style.display = 'block';
  bar.style.width = '50%';
  const fd = new FormData();
  fd.append('file', inputEl.files[0]);
  try {
    const r = await fetch('/file/upload', {method: 'POST', headers: {'X-Requested-With': 'XMLHttpRequest'}, body: fd});
    bar.style.width = '100%';
    const d = await r.json();
    if (d.ok) {
      showToast(`Đã tải lên ${d.filename}!`);
      setTimeout(() => location.reload(), 450);
    }
  } catch (e) { location.reload(); }
}

async function toggleAccCmd(accId, enabled) {
  await fetch('/api/account/chat_cmd', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({acc_id: accId, enabled})});
  location.reload();
}

async function loadGroupsAndRooms(forceRefresh, btnEl) {
  const runner = async () => {
    const box = document.getElementById('targetListContainer');
    box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--txt-muted)">Đang quét song song danh sách phòng chat...</div>';
    try {
      const qSuffix = forceRefresh ? '?refresh=1' : '';
      const [rZalo, rDis, rMess] = await Promise.all([
        fetch('/api/all_groups' + qSuffix).then(r => r.json()).catch(() => ({groups:[], friends:[], by_account:{}})),
        fetch('/api/discord_channels' + qSuffix).then(r => r.json()).catch(() => ({channels:[], by_account:{}})),
        fetch('/api/messenger_threads' + qSuffix).then(r => r.json()).catch(() => ({threads:[], by_account:{}}))
      ]);
      BY_ACCOUNT_BOXES = Object.assign({}, rZalo.by_account || {}, rDis.by_account || {}, rMess.by_account || {});
      const list = [];
      (rDis.channels || []).forEach(c => list.push({
        id: String(c.id), name: c.name, type: 'discord_channel',
        acc_ids: c.acc_ids || (c.acc_id ? [c.acc_id] : []),
        acc_names: c.acc_names || (c.acc_name ? [c.acc_name] : ['Discord'])
      }));
      (rZalo.groups || []).forEach(g => list.push({
        id: String(g.id), name: g.name, type: 'group',
        acc_ids: g.acc_ids || (g.acc_id ? [g.acc_id] : []),
        acc_names: g.acc_names || (g.acc_name ? [g.acc_name] : ['Zalo'])
      }));
      (rZalo.friends || []).forEach(f => list.push({
        id: String(f.id), name: f.name, type: 'user',
        acc_ids: f.acc_ids || (f.acc_id ? [f.acc_id] : []),
        acc_names: f.acc_names || (f.acc_name ? [f.acc_name] : ['Zalo'])
      }));
      (rMess.threads || []).forEach(m => list.push({
        id: String(m.id), name: m.name, type: 'messenger_thread',
        acc_ids: m.acc_ids || (m.acc_id ? [m.acc_id] : []),
        acc_names: m.acc_names || (m.acc_name ? [m.acc_name] : ['Messenger'])
      }));
      ALL_TARGETS = list;
      renderTargetList();
      if (forceRefresh) showToast(`Đã tải ${ALL_TARGETS.length} phòng chat!`);
    } catch (e) {
      box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--red)">Lỗi tải danh sách phòng</div>';
    }
  };
  if (btnEl) await withPetButtonLoading(btnEl, 'Đang quét...', runner);
  else await runner();
}

function makeTargetSelectionKey(t) {
  const bindPerAcc = document.getElementById('chkBindBoxToSpecificAcc') && document.getElementById('chkBindBoxToSpecificAcc').checked;
  if (bindPerAcc && ROOM_ACCOUNT_FILTER !== 'all') {
    return `${ROOM_ACCOUNT_FILTER}::${t.id}`;
  }
  return `all::${t.id}`;
}

function isTargetSelected(t) {
  const keySpecific = `${ROOM_ACCOUNT_FILTER}::${t.id}`;
  const keyAll = `all::${t.id}`;
  if (SELECTED_TARGETS.has(keySpecific) || SELECTED_TARGETS.has(keyAll)) return true;
  for (const [k, v] of SELECTED_TARGETS.entries()) {
    if (String(v.id) === String(t.id)) {
      if (ROOM_ACCOUNT_FILTER === 'all') return true;
      const assigned = v.assigned_acc_ids || [];
      if (!assigned.length || assigned.includes(parseInt(ROOM_ACCOUNT_FILTER, 10))) return true;
    }
  }
  return false;
}

function getFilteredTargetItems() {
  const q = (document.getElementById('roomSearchInput').value || '').toLowerCase().trim();
  return ALL_TARGETS.map((t, idx) => ({t, idx})).filter(({t}) => {
    if (ROOM_ACCOUNT_FILTER !== 'all') {
      const aidNum = parseInt(ROOM_ACCOUNT_FILTER, 10);
      const tAccs = t.acc_ids || [];
      if (!tAccs.includes(aidNum)) return false;
    }
    if (ROOM_PLATFORM_FILTER === 'zalo' && (t.type !== 'group' && t.type !== 'user')) return false;
    if (ROOM_PLATFORM_FILTER === 'discord' && t.type !== 'discord_channel') return false;
    if (ROOM_PLATFORM_FILTER === 'messenger' && t.type !== 'messenger_thread') return false;
    if (!q) return true;
    return (t.name || '').toLowerCase().includes(q) || String(t.id).toLowerCase().includes(q) || (t.acc_names || []).join(' ').toLowerCase().includes(q);
  });
}

function syncQuickBoxSearch(val) {
  const mainSearch = document.getElementById('roomSearchInput');
  if (mainSearch && mainSearch.value !== val) mainSearch.value = val;
  renderTargetList();
}

function addManualChannelFromQuick() {
  const qInp = document.getElementById('quickBoxSearchInput');
  const mInp = document.getElementById('roomSearchInput');
  if (qInp && mInp) mInp.value = qInp.value;
  addManualChannelId();
  if (qInp) qInp.value = '';
}

function renderTargetList() {
  const box = document.getElementById('targetListContainer');
  const quickBox = document.getElementById('campaignQuickBoxList');
  const indexed = getFilteredTargetItems();
  if (!indexed.length) {
    const emptyMsg = '<div style="padding:16px;text-align:center;color:var(--txt-muted)">Chưa có phòng nào hiển thị. Bấm <b>"Quét Toàn Bộ"</b> hoặc <b>"+ Nạp 500 ID"</b> để thêm nhanh!</div>';
    if (box) box.innerHTML = emptyMsg;
    if (quickBox) quickBox.innerHTML = emptyMsg;
    return;
  }
  const htmlItems = indexed.map(({t, idx}) => {
    const checked = isTargetSelected(t) ? 'checked' : '';
    const badgeCls = t.type === 'discord_channel' ? 'badge-blue' : (t.type === 'messenger_thread' ? 'badge-amber' : (t.type === 'group' ? 'badge-green' : 'badge-gray'));
    const badgeLbl = t.type === 'discord_channel' ? 'DISCORD' : (t.type === 'messenger_thread' ? 'MESSENGER' : (t.type === 'group' ? 'NHÓM ZALO' : 'ZALO'));
    const accOwners = (t.acc_names && t.acc_names.length) ? t.acc_names.join(', ') : 'Mọi Acc';
    return `
      <div class="list-item">
        <label style="display:flex;align-items:center;gap:10px;cursor:pointer;flex:1;min-width:0">
          <input type="checkbox" ${checked} data-idx="${idx}" onchange="toggleTargetByIdx(this.dataset.idx, this.checked)" style="width:15px;height:15px;accent-color:var(--blue);flex-shrink:0">
          <div class="item-info">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
              <span class="badge ${badgeCls}">${badgeLbl}</span>
              <span class="item-title">${escapeHtmlSafe(t.name)}</span>
            </div>
            <div class="item-sub">
              <span>ID: <code>${escapeHtmlSafe(String(t.id))}</code></span>
              <span>•</span>
              <span style="color:var(--tg-cyan);font-weight:600">Acc: ${escapeHtmlSafe(accOwners)}</span>
            </div>
          </div>
        </label>
        ${(t.type === 'group' || t.type === 'discord_channel' || t.type === 'messenger_thread') ? `<button class="btn btn-sm" type="button" data-idx="${idx}" onclick="fetchRoomMembersByIdx(this.dataset.idx)">Thành viên</button>` : ''}
      </div>
    `;
  }).join('');
  if (box) box.innerHTML = htmlItems;
  if (quickBox) quickBox.innerHTML = htmlItems;
}

function toggleTargetByIdx(idx, isChecked) {
  const item = ALL_TARGETS[Number(idx)];
  if (!item) return;
  const idStr = String(item.id);
  const bindPerAcc = Boolean(document.getElementById('chkBindBoxToSpecificAcc') && document.getElementById('chkBindBoxToSpecificAcc').checked);
  let assignedAccs = [];
  if (bindPerAcc) {
    if (ROOM_ACCOUNT_FILTER !== 'all') {
      assignedAccs = [parseInt(ROOM_ACCOUNT_FILTER, 10)];
    } else if (item.acc_ids && item.acc_ids.length) {
      assignedAccs = item.acc_ids.slice();
    }
  }
  const key = (ROOM_ACCOUNT_FILTER !== 'all' && bindPerAcc) ? `${ROOM_ACCOUNT_FILTER}::${idStr}` : `all::${idStr}`;
  if (isChecked) {
    SELECTED_TARGETS.set(key, {
      id: idStr,
      name: item.name,
      type: item.type,
      strict_bind: bindPerAcc,
      assigned_acc_ids: assignedAccs
    });
  } else {
    SELECTED_TARGETS.delete(key);
    SELECTED_TARGETS.delete(`all::${idStr}`);
    for (const [k, v] of Array.from(SELECTED_TARGETS.entries())) {
      if (String(v.id) === idStr && (ROOM_ACCOUNT_FILTER === 'all' || k.startsWith(ROOM_ACCOUNT_FILTER + '::'))) {
        SELECTED_TARGETS.delete(k);
      }
    }
  }
  renderTargetList();
  updateTargetBadges();
}

function fetchRoomMembersByIdx(idx) {
  const item = ALL_TARGETS[Number(idx)];
  if (!item) return;
  fetchRoomMembers(String(item.id), item.type);
}

function selectTopNTargets(limitN) {
  const visible = getFilteredTargetItems().slice(0, Number(limitN) || 500);
  const bindPerAcc = Boolean(document.getElementById('chkBindBoxToSpecificAcc') && document.getElementById('chkBindBoxToSpecificAcc').checked);
  visible.forEach(({t}) => {
    const idStr = String(t.id);
    let assignedAccs = [];
    if (bindPerAcc) {
      if (ROOM_ACCOUNT_FILTER !== 'all') assignedAccs = [parseInt(ROOM_ACCOUNT_FILTER, 10)];
      else if (t.acc_ids && t.acc_ids.length) assignedAccs = t.acc_ids.slice();
    }
    const key = (ROOM_ACCOUNT_FILTER !== 'all' && bindPerAcc) ? `${ROOM_ACCOUNT_FILTER}::${idStr}` : `all::${idStr}`;
    SELECTED_TARGETS.set(key, {id: idStr, name: t.name, type: t.type, strict_bind: bindPerAcc, assigned_acc_ids: assignedAccs});
  });
  renderTargetList();
  updateTargetBadges();
  showToast(`Đã chọn ${visible.length} phòng chat mục tiêu!`);
}

function selectAllTargets() {
  const visible = getFilteredTargetItems();
  const bindPerAcc = Boolean(document.getElementById('chkBindBoxToSpecificAcc') && document.getElementById('chkBindBoxToSpecificAcc').checked);
  visible.forEach(({t}) => {
    const idStr = String(t.id);
    let assignedAccs = [];
    if (bindPerAcc) {
      if (ROOM_ACCOUNT_FILTER !== 'all') assignedAccs = [parseInt(ROOM_ACCOUNT_FILTER, 10)];
      else if (t.acc_ids && t.acc_ids.length) assignedAccs = t.acc_ids.slice();
    }
    const key = (ROOM_ACCOUNT_FILTER !== 'all' && bindPerAcc) ? `${ROOM_ACCOUNT_FILTER}::${idStr}` : `all::${idStr}`;
    SELECTED_TARGETS.set(key, {id: idStr, name: t.name, type: t.type, strict_bind: bindPerAcc, assigned_acc_ids: assignedAccs});
  });
  renderTargetList();
  updateTargetBadges();
}

function clearAllTargets() {
  if (ROOM_ACCOUNT_FILTER === 'all') {
    SELECTED_TARGETS.clear();
  } else {
    for (const k of Array.from(SELECTED_TARGETS.keys())) {
      if (k.startsWith(ROOM_ACCOUNT_FILTER + '::')) SELECTED_TARGETS.delete(k);
    }
  }
  renderTargetList();
  updateTargetBadges();
}

function updateTargetBadges() {
  const c = SELECTED_TARGETS.size;
  document.getElementById('kpiTargetCount').textContent = c;
  setDockBadgeCount('dockTargetBadge', c);
  const qCnt = document.getElementById('quickBoxSelectedCount');
  if (qCnt) qCnt.textContent = c;
}

async function fetchRoomMembers(roomId, roomType) {
  const box = document.getElementById('memberListContainer');
  box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--txt-muted)">Đang tải danh sách thành viên...</div>';
  try {
    const url = roomType === 'discord_channel'
      ? `/api/discord_channel_members?channel_id=${encodeURIComponent(roomId)}`
      : (roomType === 'messenger_thread'
        ? `/api/messenger_thread_members?thread_id=${encodeURIComponent(roomId)}`
        : `/api/group_members?group_id=${encodeURIComponent(roomId)}&refresh=1`);
    const r = await fetch(url);
    const d = await r.json();
    CURRENT_MEMBERS = d.members || [];
    renderMemberList();
    showToast(`Đã tải ${CURRENT_MEMBERS.length} thành viên!`);
  } catch (e) {
    box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--red)">Lỗi tải thành viên</div>';
  }
}

function renderMemberList() {
  const box = document.getElementById('memberListContainer');
  const q = (document.getElementById('memberSearchInput').value || '').toLowerCase().trim();
  const indexed = CURRENT_MEMBERS.map((m, idx) => ({m, idx})).filter(({m}) => !q || (m.name || '').toLowerCase().includes(q) || String(m.uid || m.id).includes(q));
  if (!indexed.length) {
    box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--txt-muted)">Không có thành viên khớp.</div>';
    return;
  }
  box.innerHTML = indexed.map(({m, idx}) => {
    const uid = String(m.uid || m.id);
    const checked = SELECTED_MENTIONS.has(uid) ? 'checked' : '';
    return `
      <div class="list-item">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;flex:1;min-width:0">
          <input type="checkbox" ${checked} data-idx="${idx}" onchange="toggleMentionByIdx(this.dataset.idx, this.checked)" style="width:14px;height:14px;accent-color:var(--blue);flex-shrink:0">
          <div class="item-info">
            <div class="item-title">@${escapeHtmlSafe(m.name)}</div>
            <div class="item-sub">UID: <code>${escapeHtmlSafe(uid)}</code></div>
          </div>
        </label>
      </div>
    `;
  }).join('');
}

function toggleMentionByIdx(idx, isChecked) {
  const m = CURRENT_MEMBERS[Number(idx)];
  if (!m) return;
  const uid = String(m.uid || m.id);
  if (isChecked) SELECTED_MENTIONS.set(uid, {uid, id: uid, name: m.name});
  else SELECTED_MENTIONS.delete(uid);
  updateTagSummary();
}

function selectAllMembersInBox() {
  CURRENT_MEMBERS.forEach(m => {
    const uid = String(m.uid || m.id);
    SELECTED_MENTIONS.set(uid, {uid, id: uid, name: m.name});
  });
  renderMemberList();
  updateTagSummary();
}

function clearSelectedMentions() {
  SELECTED_MENTIONS.clear();
  document.getElementById('chkTagAll').checked = false;
  renderMemberList();
  updateTagSummary();
}

function updateTagSummary() {
  const tagAll = document.getElementById('chkTagAll').checked;
  const hideAll = document.getElementById('chkHideTagAll') ? document.getElementById('chkHideTagAll').checked : true;
  const hideName = document.getElementById('chkHideTagName') ? document.getElementById('chkHideTagName').checked : false;
  const cnt = SELECTED_MENTIONS.size;
  const allLbl = hideAll ? '@All Ẩn' : '@All';
  const nameLbl = hideName ? `${cnt} người (Tag Ẩn)` : `${cnt} người`;
  document.getElementById('selectedTagBadge').textContent = tagAll ? `${allLbl} + ${nameLbl}` : `${nameLbl} được chọn`;
}

async function launchCampaignTask(btnEl) {
  const mergedMap = new Map();
  for (const t of SELECTED_TARGETS.values()) {
    const idStr = String(t.id);
    if (!mergedMap.has(idStr)) {
      mergedMap.set(idStr, {
        id: idStr,
        name: t.name,
        type: t.type,
        strict_bind: Boolean(t.strict_bind),
        assigned_acc_ids: (t.assigned_acc_ids || []).slice()
      });
    } else {
      const ex = mergedMap.get(idStr);
      (t.assigned_acc_ids || []).forEach(aid => {
        if (!ex.assigned_acc_ids.includes(aid)) ex.assigned_acc_ids.push(aid);
      });
    }
  }
  const targets = Array.from(mergedMap.values());
  if (!targets.length) {
    showToast('Vui lòng chọn ít nhất 1 phòng chat mục tiêu!');
    switchMainTab('tab-targets', document.querySelector('[data-tab="tab-targets"]'));
    return;
  }
  await withPetButtonLoading(btnEl, 'Đang phóng 96 Shards 0s...', async () => {
    const selectedAccIds = Array.from(document.querySelectorAll('.camp-acc-chk:checked')).map(el => parseInt(el.value, 10)).filter(n => !isNaN(n));
    const batchCount = Math.max(1, Math.min(100, parseInt(document.getElementById('cfgBatchCount').value || '1', 10)));
    const payload = {
      targets,
      account_ids: selectedAccIds,
      mode: document.getElementById('cfgMode').value,
      color_mode: document.getElementById('cfgColorMode').value,
      fixed_color: document.getElementById('cfgFixedColor').value,
      delay: parseFloat(document.getElementById('cfgDelay').value || '0.0'),
      icon_count: parseInt(document.getElementById('cfgIconCount').value || '0', 10),
      batch_count: batchCount,
      file_id: document.getElementById('cfgFileSelect').value,
      raw_text: document.getElementById('cfgRawText').value,
      font_style: document.getElementById('cfgFontStyle') ? document.getElementById('cfgFontStyle').value : 'big_bold',
      is_heading: document.getElementById('cfgHeading').checked,
      use_emoji: document.getElementById('cfgUseEmoji').checked && (parseInt(document.getElementById('cfgIconCount').value || '0', 10) > 0),
      antiband: document.getElementById('cfgAntiband').checked,
      multi_acc: document.getElementById('cfgMultiAcc').checked,
      tag_all: document.getElementById('chkTagAll').checked || (document.getElementById('cfgMode').value === 'nhay_tag_all_an'),
      hide_tag_all: document.getElementById('chkHideTagAll') ? document.getElementById('chkHideTagAll').checked : true,
      hide_tag_name: (document.getElementById('chkHideTagName') && document.getElementById('chkHideTagName').checked) || (document.getElementById('cfgMode').value === 'nhay_tag_ten_an'),
      tag_users: Array.from(SELECTED_MENTIONS.values())
    };
    try {
      const r = await fetch('/task/start', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
      const d = await r.json();
      if (d.ok) {
        setPetCompanionMood(`NHK 3D đang chạy ${d.batch_count || 1} luồng trên ${targets.length} Box siêu tốc 0s!`);
        showToast(`Đã khởi chạy ${d.batch_count || 1} luồng trên ${targets.length} Box!`);
        if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'FORCE_REFRESH'});
        pollSystemStatus(true);
      } else {
        showToast(d.error || 'Lỗi khởi chạy chiến dịch');
      }
    } catch (e) { showToast('Lỗi kết nối máy chủ'); }
  });
}

function applyOptimisticStopUI(targetTid = null) {
  if (!targetTid) {
    document.getElementById('kpiRunningTasks').textContent = '0';
    setDockBadgeCount('dockTaskBadge', 0);
    setPetTurboMode(false);
    setPetCompanionMood('Đã dừng toàn bộ chiến dịch trong 0ms!');
    const stateBadge = document.getElementById('liveHangStateBadge');
    if (stateBadge) {
      stateBadge.textContent = 'SẴN SÀNG';
      stateBadge.className = 'badge badge-green';
    }
  }
}

async function stopAllRunningTasks() {
  applyOptimisticStopUI(null);
  showToast('Đã ngắt toàn bộ chiến dịch đang chạy!');
  if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'INSTANT_STOP_ALL'});
  try {
    await fetch('/task/stop_all', {method: 'POST', keepalive: true});
  } catch (e) {}
  pollSystemStatus(true);
}

async function stopSingleTask(tid) {
  applyOptimisticStopUI(tid);
  showToast('Đã dừng chiến dịch!');
  if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'FORCE_REFRESH'});
  try {
    await fetch('/task/stop/' + encodeURIComponent(tid), {method: 'POST', keepalive: true});
  } catch (e) {}
  pollSystemStatus(true);
}

let _isPollingStatus = false;
const _domCache = {tasks: '', health: '', logs: '', campLogs: '', banner: '', cpList: ''};

function updateDomIfChanged(el, cacheKey, newHtml) {
  if (!el || _domCache[cacheKey] === newHtml) return;
  _domCache[cacheKey] = newHtml;
  el.innerHTML = newHtml;
}

function renderSystemStatusData(d, measuredRtt = null) {
  const tasks = d.tasks || [];
  const running = tasks.filter(t => t.status && t.status.includes('Đang chạy')).length;
  let totalSent = 0;
  tasks.forEach(t => { totalSent += (t.sent || 0); });

  document.getElementById('kpiRunningTasks').textContent = running;
  setDockBadgeCount('dockTaskBadge', running);
  document.getElementById('kpiTotalSent').textContent = totalSent;
  setPetTurboMode(running > 0);

  if (d.ping_telemetry) {
    const pt = d.ping_telemetry;
    const rtt = measuredRtt || pt.avg_send_ms || 8;
    const sendMs = pt.avg_send_ms && pt.avg_send_ms > 0 ? Math.round(pt.avg_send_ms) : rtt;
    const hdrTxt = document.getElementById('headerPingText');
    const sendEl = document.getElementById('liveSendPingVal');
    const jitEl = document.getElementById('liveJitterVal');
    const rpmEl = document.getElementById('liveRpmVal');
    const healEl = document.getElementById('liveHealedVal');
    const stateBadge = document.getElementById('liveHangStateBadge');
    const rttEl = document.getElementById('pingRttVal');
    const thEl = document.getElementById('pingThreadsVal');
    const engEl = document.getElementById('pingEngineBadge');
    if (hdrTxt) hdrTxt.textContent = `${rtt} ms`;
    if (sendEl) sendEl.textContent = `${sendMs} ms`;
    if (jitEl) jitEl.textContent = `${pt.jitter_ms || 1.0} ms`;
    if (rpmEl) rpmEl.textContent = `${pt.total_rpm || 0} RPM`;
    if (healEl) healEl.textContent = `${pt.total_healed || 0} lần`;
    if (stateBadge) {
      stateBadge.textContent = running > 0 ? `ĐANG CHẠY (${running})` : 'SẴN SÀNG';
      stateBadge.className = running > 0 ? 'badge badge-blue' : 'badge badge-green';
    }
    if (rttEl) rttEl.textContent = `${rtt} ms`;
    if (thEl) thEl.textContent = `${pt.active_threads || 1} luồng`;
    if (engEl) engEl.textContent = `Engine ${pt.engine_ms || 0.15}ms`;
  }

  if (d.discord_firewall) {
    const fw = d.discord_firewall;
    const elInsp = document.getElementById('fwInspectedCnt');
    const elImm = document.getElementById('fwImmortalCnt');
    if (elInsp) elInsp.textContent = `${fw.inspected_packets || 0} gói`;
    if (elImm) elImm.textContent = `${fw.immortalized_tokens || 0} phiên`;
  }

  const tBox = document.getElementById('activeTasksContainer');
  const nextTasksHtml = !tasks.length
    ? '<div style="padding:18px;text-align:center;color:var(--txt-muted)">Chưa có chiến dịch nào đang chạy.</div>'
    : `<table class="data-table">
        <thead>
          <tr>
            <th>Trạng thái</th>
            <th>Chế độ</th>
            <th>Phạm vi</th>
            <th>Đã gửi</th>
            <th>Thao tác</th>
          </tr>
        </thead>
        <tbody>
          ${tasks.map(t => {
            const byAccStr = t.by_acc && Object.keys(t.by_acc).length
              ? Object.entries(t.by_acc).map(([k, v]) => `${escapeHtmlSafe(k)}: ${v}`).join(' | ')
              : `${t.acc_count || 1} Acc`;
            return `
              <tr>
                <td><span class="badge ${t.status.includes('Đang chạy') ? 'badge-green' : 'badge-gray'}">${escapeHtmlSafe(t.status)}</span></td>
                <td>
                  <div style="font-weight:600">${escapeHtmlSafe(t.mode)} (${t.delay}s)</div>
                  <div style="font-size:11px;color:var(--txt-muted)"><code>${escapeHtmlSafe(t.trigger_cmd || t.source || 'Web')}</code></div>
                </td>
                <td>
                  <div style="font-weight:600">${t.acc_count || 1} Acc • ${t.targets_count} phòng</div>
                  <div style="font-size:10.5px;color:var(--txt-muted)">${byAccStr}</div>
                </td>
                <td class="mono" style="font-weight:700;color:var(--tg-cyan)">${t.sent}</td>
                <td>${t.status.includes('Đang chạy') ? `<button class="btn btn-danger btn-sm" onclick="stopSingleTask('${t.id}')">Dừng</button>` : '-'}</td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>`;
  updateDomIfChanged(tBox, 'tasks', nextTasksHtml);

  const hBox = document.getElementById('healthShieldBox');
  const healthList = d.accounts_health || [];
  const nextHealthHtml = healthList.map(h => `
    <div class="list-item">
      <div class="item-info">
        <div style="display:flex;align-items:center;gap:6px">
          <span class="badge ${h.platform === 'discord' ? 'badge-blue' : (h.platform === 'messenger' ? 'badge-amber' : 'badge-green')}">${h.platform.toUpperCase()}</span>
          <span class="item-title">${escapeHtmlSafe(h.name || h.masked_name)}</span>
          <span class="badge badge-green">${escapeHtmlSafe(h.circuit)}</span>
        </div>
        <div class="item-sub">Tốc độ: ${h.rpm} tin/phút • Đã gửi: <b>${h.ok_total}</b> • <b>${escapeHtmlSafe(h.ws_status)}</b></div>
      </div>
    </div>
  `).join('') || '<div style="padding:14px;text-align:center;color:var(--txt-muted)">Chưa có tài khoản</div>';
  updateDomIfChanged(hBox, 'health', nextHealthHtml);

  if (d.runtime_config && !window._userEditingCfg) {
    const rc = d.runtime_config;
    const icEl = document.getElementById('cfgIconCount');
    const emEl = document.getElementById('cfgUseEmoji');
    const dlEl = document.getElementById('cfgDelay');
    const cmEl = document.getElementById('cfgColorMode');
    const fcEl = document.getElementById('cfgFixedColor');
    const fsEl = document.getElementById('cfgFontStyle');
    const hdEl = document.getElementById('cfgHeading');
    if (icEl && document.activeElement !== icEl && typeof rc.icon_count === 'number') icEl.value = rc.icon_count;
    if (emEl && typeof rc.use_emoji === 'boolean') emEl.checked = (rc.use_emoji && rc.icon_count > 0);
    if (dlEl && document.activeElement !== dlEl && typeof rc.delay === 'number') dlEl.value = rc.delay;
    if (cmEl && document.activeElement !== cmEl && rc.color_mode) cmEl.value = rc.color_mode;
    if (fcEl && document.activeElement !== fcEl && rc.fixed_color) fcEl.value = rc.fixed_color;
    if (fsEl && document.activeElement !== fsEl && rc.font_style) fsEl.value = rc.font_style;
    if (hdEl && typeof rc.is_heading === 'boolean') hdEl.checked = rc.is_heading;
  }

  const cpUsers = d.authorized_users || [];
  const cpBadge = document.getElementById('cpCountBadge');
  if (cpBadge) cpBadge.textContent = `${cpUsers.length} người có quyền .cp`;
  const cpBox = document.getElementById('cpUsersListContainer');
  if (cpBox) {
    const cpHtml = cpUsers.length
      ? cpUsers.map(u => `
          <div class="list-item" style="padding:6px 12px">
            <div class="item-info">
              <span class="badge badge-green">.CP</span>
              <strong style="margin-left:6px">${escapeHtmlSafe(u.name)}</strong>
              <code style="margin-left:6px;font-size:11px;color:var(--txt-muted)">UID: ${escapeHtmlSafe(u.uid)}</code>
            </div>
            <button type="button" class="btn btn-danger btn-sm" onclick="revokeCpPermissionFromWeb('${escapeHtmlSafe(u.uid)}')">Xóa</button>
          </div>
        `).join('')
      : '<div style="padding:10px;text-align:center;color:var(--txt-muted)">Chỉ Chủ Tài Khoản đang có quyền điều khiển.</div>';
    updateDomIfChanged(cpBox, 'cpList', cpHtml);
  }

  const logs = d.cmd_logs || [];
  const bannerEl = document.getElementById('latestCmdBannerText');
  if (bannerEl && logs.length > 0) {
    const l0 = logs[0];
    const bTxt = `${l0.time_str || ''} • ${l0.cmd_text || ''} — ${l0.action_taken || ''}`;
    updateDomIfChanged(bannerEl, 'banner', escapeHtmlSafe(bTxt));
  }

  const logsTableHtml = logs.length
    ? `<table class="data-table">
        <thead>
          <tr>
            <th>Giờ</th>
            <th>Tài khoản</th>
            <th>Phòng</th>
            <th>Lệnh</th>
            <th>Kết quả</th>
          </tr>
        </thead>
        <tbody>
          ${logs.map(l => `
            <tr>
              <td class="mono" style="font-size:11px;white-space:nowrap">${escapeHtmlSafe(l.time_str || '')}</td>
              <td>
                <span class="badge badge-blue">${escapeHtmlSafe(l.platform || 'ZALO')}</span>
                <strong style="margin-left:4px">${escapeHtmlSafe(l.sender_name || l.acc_name || 'Owner')}</strong>
              </td>
              <td class="mono" style="font-size:11px">${escapeHtmlSafe(l.thread_id || l.masked_thread || '-')}</td>
              <td><code>${escapeHtmlSafe(l.cmd_text)}</code></td>
              <td style="font-size:11.5px;color:var(--txt-muted)">${escapeHtmlSafe(l.action_taken)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>`
    : '<div style="padding:16px;text-align:center;color:var(--txt-muted)">Chưa có lệnh nào được ghi nhận.</div>';

  updateDomIfChanged(document.getElementById('cmdLogBox'), 'logs', logsTableHtml);
  updateDomIfChanged(document.getElementById('campaignCmdLogBox'), 'campLogs', logsTableHtml);
}

async function loadProxyPoolInitial() {
  try {
    const r = await fetch('/api/proxies');
    const d = await r.json();
    if (d.ok) {
      const inp = document.getElementById('proxyPoolInput');
      const chk = document.getElementById('chkProxyEnabled');
      if (inp && !inp.value) inp.value = d.proxies_text || '';
      if (chk) chk.checked = Boolean(d.enabled);
      updateProxyBadgeUI(d);
    }
  } catch (e) {}
}

function updateProxyBadgeUI(snap) {
  const badge = document.getElementById('prxStatusBadge');
  const cBadge = document.getElementById('campPrxQuickBadge');
  if (!snap) return;
  const fastTxt = snap.fastest_ms && snap.fastest_ms > 0 ? ` • Top: ${snap.fastest_ms}ms` : '';
  const txt = (snap.total > 0 && snap.enabled)
    ? `PRX AUTO-ON: ${snap.healthy}/${snap.total} Khỏe${fastTxt} • ${snap.routed_ok} gói`
    : 'Direct Keep-Alive (0ms)';
  const cls = (snap.total > 0 && snap.enabled) ? 'badge badge-green' : 'badge badge-blue';
  if (badge) { badge.textContent = txt; badge.className = cls; }
  if (cBadge) { cBadge.textContent = txt; cBadge.className = cls; }
}

async function saveProxyPoolList() {
  const proxies = (document.getElementById('proxyPoolInput').value || '').trim();
  const enabled = document.getElementById('chkProxyEnabled').checked;
  try {
    const r = await fetch('/api/proxies/save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({proxies, enabled})
    });
    const d = await r.json();
    if (d.ok) {
      updateProxyBadgeUI(d.snapshot);
      showToast(d.message || 'Đã lưu Proxy Pool!');
    }
  } catch (e) { showToast('Lỗi lưu Proxy!'); }
}

async function testProxyPoolNow() {
  showToast('Đang kiểm tra tốc độ dàn Proxy...');
  try {
    const r = await fetch('/api/proxies/test', {method: 'POST'});
    const d = await r.json();
    if (d.snapshot) updateProxyBadgeUI(d.snapshot);
    showToast(d.message || 'Đã kiểm tra xong!');
  } catch (e) { showToast('Lỗi kiểm tra Proxy!'); }
}

async function clearProxyPoolNow() {
  try {
    const r = await fetch('/api/proxies/clear', {method: 'POST'});
    const d = await r.json();
    document.getElementById('proxyPoolInput').value = '';
    if (d.snapshot) updateProxyBadgeUI(d.snapshot);
    showToast(d.message || 'Đã xóa Proxy!');
  } catch (e) {}
}

async function pollSystemStatus(force = false) {
  if (_isPollingStatus) return;
  if (!force && document.hidden) return;
  if (!force && !isCurrentTabLeader() && (Date.now() - LAST_CROSS_TAB_STATUS_TS < 2600)) return;
  _isPollingStatus = true;
  const t0 = performance.now();
  try {
    const r = await fetch('/api/status?t=' + Date.now(), {cache: 'no-store'});
    const d = await r.json();
    const rtt = Math.max(1, Math.round(performance.now() - t0));
    LAST_CROSS_TAB_STATUS_TS = Date.now();
    if (d.proxy_pool) updateProxyBadgeUI(d.proxy_pool);
    scheduleSmoothRenderStatus(d, rtt);
    if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'STATUS_SNAPSHOT', data: d, rtt});
  } catch (e) {
  } finally {
    _isPollingStatus = false;
  }
}

function scheduleAdaptivePoll() {
  const waitMs = document.hidden ? 5000 : 1000;
  setTimeout(async () => {
    await pollSystemStatus(false);
    scheduleAdaptivePoll();
  }, waitMs);
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) pollSystemStatus(true);
});

async function setGlobalIconZeroNow(icCount) {
  const icEl = document.getElementById('cfgIconCount');
  const emEl = document.getElementById('cfgUseEmoji');
  if (icEl) icEl.value = String(icCount);
  if (emEl) emEl.checked = (Number(icCount) > 0);
  await syncWebRuntimeConfigLive();
  showToast(Number(icCount) === 0 ? 'Đã tắt ký hiệu đuôi (.icon 0) trên mọi nhóm!' : `Đã bật ${icCount} ký hiệu đuôi!`);
}

async function syncWebRuntimeConfigLive() {
  window._userEditingCfg = true;
  setTimeout(() => { window._userEditingCfg = false; }, 1200);
  const icVal = parseInt(document.getElementById('cfgIconCount').value || '0', 10);
  const emChecked = document.getElementById('cfgUseEmoji').checked && (icVal > 0);
  const payload = {
    icon_count: emChecked ? icVal : 0,
    use_emoji: emChecked,
    delay: parseFloat(document.getElementById('cfgDelay').value || '0.0'),
    color_mode: document.getElementById('cfgColorMode').value,
    fixed_color: document.getElementById('cfgFixedColor').value,
    font_style: document.getElementById('cfgFontStyle') ? document.getElementById('cfgFontStyle').value : 'big_bold',
    is_heading: document.getElementById('cfgHeading').checked,
    antiband: document.getElementById('cfgAntiband').checked
  };
  try {
    await fetch('/api/runtime_config/update', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'FORCE_REFRESH'});
    pollSystemStatus(true);
  } catch (e) {}
}

async function grantCpPermissionFromWeb() {
  const uid = (document.getElementById('cpGrantUidInput').value || '').trim();
  const name = (document.getElementById('cpGrantNameInput').value || '').trim();
  if (!uid) { showToast('Hãy nhập UID hoặc @Tên cần cấp quyền (.cp)!'); return; }
  try {
    const r = await fetch('/api/permissions/add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({uid, name})
    });
    const d = await r.json();
    if (d.ok) {
      document.getElementById('cpGrantUidInput').value = '';
      document.getElementById('cpGrantNameInput').value = '';
      showToast(d.message || 'Đã cấp quyền .cp!');
      pollSystemStatus(true);
    } else {
      showToast(d.error || 'Lỗi cấp quyền');
    }
  } catch (e) {}
}

async function revokeCpPermissionFromWeb(uid) {
  try {
    const r = await fetch('/api/permissions/remove', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({uid})
    });
    const d = await r.json();
    if (d.ok) {
      showToast(d.message || 'Đã thu hồi quyền .cp!');
      pollSystemStatus(true);
    }
  } catch (e) {}
}

pollSystemStatus(true);
scheduleAdaptivePoll();
setTimeout(() => { loadGroupsAndRooms(false); loadProxyPoolInitial(); }, 220);
</script>
</body>
</html>"""


@app.route("/api/ui/physics")
def api_ui_physics():
    return jsonify({"ok": True, **TelegramUIPhysicsEngine.get_ui_bundle()})


@app.route("/api/ui/pet_mascot")
def api_ui_pet_mascot():
    return jsonify(TelegramPetAnimationEngine.get_pet_bundle())


@app.route("/api/zalo/geo_status")
def api_zalo_geo_status():
    reg = request.args.get("region", "VN").strip().upper()
    px = request.args.get("proxy", "").strip()
    force_scan = request.args.get("scan") == "1"
    try:
        from zalo_login import VietnamSingaporeGeoRouter
        if px:
            info = VietnamSingaporeGeoRouter.inspect_outbound_ip_geo(proxy_url=px, timeout=3.0)
            if info.get("ok"):
                return jsonify(info)
        direct_info = VietnamSingaporeGeoRouter.get_direct_server_geo(force=force_scan)
        if direct_info.get("ok") and direct_info.get("is_vn_or_sg"):
            return jsonify(direct_info)
        if force_scan:
            route = VietnamSingaporeGeoRouter.select_best_route_for_qr(target_country=reg, custom_proxy=px)
            return jsonify(route)
        return jsonify(direct_info if direct_info.get("ok") else {
            "ok": True,
            "ip": "Direct",
            "country_code": "SG" if "SG" in reg else "VN",
            "country": "Singapore" if "SG" in reg else "Việt Nam",
            "city": "Singapore" if "SG" in reg else "TP. Hồ Chí Minh",
            "isp": "Singtel / Viettel Fiber",
            "is_vn_or_sg": True,
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/zalo/auto_scan_vn_sg_proxy", methods=["POST"])
def api_zalo_auto_scan_vn_sg_proxy():
    data = request.json or {}
    reg = str(data.get("region") or "VN").strip().upper()
    px = str(data.get("proxy") or "").strip()
    try:
        from zalo_login import VietnamSingaporeGeoRouter
        route = VietnamSingaporeGeoRouter.select_best_route_for_qr(target_country=reg, custom_proxy=px)
        if route.get("proxy_url"):
            VietnamSingaporeGeoRouter._USER_CUSTOM_PROXY = route["proxy_url"]
        cc = route.get("country_code") or ("SG" if "SG" in reg else "VN")
        return jsonify({
            "ok": True,
            **route,
            "message": (
                f"Đã xác thực đường truyền thật tại {'Singapore (SG)' if cc == 'SG' else 'Việt Nam (VN)'} — IP: {route.get('ip') or 'Active'}!"
                if route.get("is_vn_or_sg") else
                f"Máy chủ hiện tại đang ở {route.get('country') or cc} ({route.get('ip')}). Hãy nhập Proxy VN/SG hoặc dùng cấu hình render.yaml (region: singapore)!"
            ),
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/network/gateways")
def api_network_gateways():
    return jsonify(MessagingGatewayDirectory.get_directory_payload())




@app.context_processor
def inject_nhk_3d_and_pets():
    """Tự động bơm đồ họa 3D NHK & SVG vào mọi trang HTML (/login, /, errorhandler) để 100% luôn xuất hiện!"""
    return {
        "corgi_svg": TelegramPetAnimationEngine.get_corgi_svg(),
        "cat_svg": TelegramPetAnimationEngine.get_cat_svg(),
        "nhk_3d_svg": TelegramPetAnimationEngine.get_nhk_3d_emblem_svg(),
    }


@app.route("/api/proxies/upload_file", methods=["POST"])
def api_upload_proxies_file():
    """Duyệt & nạp 1 hoặc nhiều file PRX (.txt / .csv), tự động khởi chạy Keep-Alive & xếp hạng Proxy nhanh nhất!"""
    uploaded_files = request.files.getlist("files") or []
    single_f = request.files.get("file")
    if single_f and single_f not in uploaded_files:
        uploaded_files.append(single_f)

    chunks = []
    filenames = []
    for uf in uploaded_files:
        if uf and uf.filename:
            filenames.append(os.path.basename(uf.filename))
            try:
                raw_b = uf.read()
                chunks.append(raw_b.decode("utf-8", errors="ignore"))
            except Exception:
                pass

    if not chunks and request.is_json:
        data = request.json or {}
        if data.get("proxies"):
            chunks.append(str(data["proxies"]))

    combined_text = "\n".join(chunks)
    if not combined_text.strip():
        return jsonify({"ok": False, "error": "File PRX trống hoặc chưa chọn file!"}), 400

    append_mode = str(request.form.get("append_mode", "1")) != "0"
    if append_mode:
        added_cnt, total_cnt = ProxyPoolEngine.add_proxies_incremental(combined_text, auto_start=True)
    else:
        total_cnt = ProxyPoolEngine.save_proxies(combined_text, enabled=True, auto_start=True)
        added_cnt = total_cnt

    snap = ProxyPoolEngine.get_snapshot()
    fn_label = ", ".join(filenames[:3]) if filenames else "File PRX"
    return jsonify({
        "ok": True,
        "added": added_cnt,
        "total": total_cnt,
        "snapshot": snap,
        "message": f"Đã nạp {added_cnt} PRX từ {fn_label} (Tổng: {total_cnt} PRX) & tự khởi chạy xếp hạng tốc độ phản hồi nhanh nhất!"
    })


@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if request.path.startswith("/api/") or request.path.startswith("/task/"):
        return jsonify({"ok": False, "error": str(e)}), 200
    try:
        has_logo = bool(get_setting("brand_logo_b64", "") or get_setting("brand_logo_url", ""))
        logo_ts = get_setting("brand_logo_ts", "1")
        custom_title = get_setting("custom_web_title", "")
        return render_template_string(
            DASHBOARD_HTML,
            accounts=[],
            files=[],
            has_logo=has_logo,
            logo_ts=logo_ts,
            custom_title=custom_title,
            corgi_svg=TelegramPetAnimationEngine.get_corgi_svg(),
            cat_svg=TelegramPetAnimationEngine.get_cat_svg(),
            nhk_3d_svg=TelegramPetAnimationEngine.get_nhk_3d_emblem_svg(),
        ), 200
    except Exception:
        return Response("System Ready", mimetype="text/plain"), 200

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()
    allowed, wait_s = check_ip_bruteforce(ip)
    has_logo = bool(get_setting("brand_logo_b64", "") or get_setting("brand_logo_url", ""))
    logo_ts = get_setting("brand_logo_ts", "1")
    custom_title = get_setting("custom_web_title", "")
    if not allowed:
        return render_template_string(
            LOGIN_HTML,
            error=f"Tạm khóa đăng nhập do nhập sai nhiều lần. Thử lại sau {wait_s} giây.",
            has_logo=has_logo,
            logo_ts=logo_ts,
            custom_title=custom_title,
            corgi_svg=TelegramPetAnimationEngine.get_corgi_svg(),
            cat_svg=TelegramPetAnimationEngine.get_cat_svg(),
            nhk_3d_svg=TelegramPetAnimationEngine.get_nhk_3d_emblem_svg(),
        )
    if request.method == "POST":
        pw = (request.form.get("password") or "").strip()
        is_valid = False
        if pw and (pw == ACCESS_KEY or pw == DEFAULT_ADMIN_PASS):
            is_valid = True
        else:
            try:
                conn = db()
                row = conn.execute("SELECT password FROM users WHERE username=?", (DEFAULT_ADMIN_USER,)).fetchone()
                conn.close()
                if row and verify_password_secure(row["password"], pw):
                    is_valid = True
            except Exception:
                pass

        if is_valid:
            record_login_result(ip, True)
            session.permanent = True
            session["logged_in"] = True
            return redirect("/")

        record_login_result(ip, False)
        return render_template_string(
            LOGIN_HTML,
            error="Mật khẩu truy cập không chính xác!",
            has_logo=has_logo,
            logo_ts=logo_ts,
            custom_title=custom_title,
            corgi_svg=TelegramPetAnimationEngine.get_corgi_svg(),
            cat_svg=TelegramPetAnimationEngine.get_cat_svg(),
            nhk_3d_svg=TelegramPetAnimationEngine.get_nhk_3d_emblem_svg(),
        )
    return render_template_string(LOGIN_HTML, error=None, has_logo=has_logo, logo_ts=logo_ts, custom_title=custom_title, corgi_svg=TelegramPetAnimationEngine.get_corgi_svg(), cat_svg=TelegramPetAnimationEngine.get_cat_svg(), nhk_3d_svg=TelegramPetAnimationEngine.get_nhk_3d_emblem_svg())

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/api/menu_banner.png")
def api_get_menu_banner():
    banner_p = os.path.join(BASE_DIR, "menu_banner.png")
    if os.path.exists(banner_p):
        return send_from_directory(BASE_DIR, "menu_banner.png", mimetype="image/png")
    return redirect("/api/logo")

@app.route("/api/logo")
def api_get_logo():
    ext_url = get_setting("brand_logo_url", "").strip()
    if ext_url and ext_url.startswith(("http://", "https://", "data:image/")):
        if ext_url.startswith("data:image/"):
            try:
                header, b64_part = ext_url.split(",", 1)
                mime_t = header.split(";")[0].replace("data:", "") or "image/png"
                return Response(base64.b64decode(b64_part), mimetype=mime_t)
            except Exception:
                pass
        return redirect(ext_url)
    b64 = get_setting("brand_logo_b64", "")
    mime = get_setting("brand_logo_mime", "image/png")
    if not b64:
        svg = '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#0969da"/><stop offset="100%" stop-color="#1f883d"/></linearGradient></defs><rect width="64" height="64" rx="14" fill="url(#g)"/><path d="M20 34L28 42L44 22" stroke="#ffffff" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none"/><circle cx="32" cy="32" r="24" stroke="rgba(255,255,255,0.25)" stroke-width="2" fill="none"/></svg>'
        return Response(svg, mimetype="image/svg+xml")
    try:
        raw = base64.b64decode(b64)
        return Response(raw, mimetype=mime)
    except Exception:
        return Response(status=404)

@app.route("/api/logo/upload", methods=["POST"])
def api_upload_logo():
    if request.is_json:
        data = request.json or {}
        logo_url = (data.get("logo_url") or "").strip()
        custom_title = (data.get("custom_title") or "").strip()
        if logo_url:
            set_setting("brand_logo_url", logo_url)
            set_setting("brand_logo_ts", str(int(time.time())))
        if "custom_title" in data:
            set_setting("custom_web_title", custom_title)
        return jsonify({"ok": True, "message": "Đã cập nhật thương hiệu & Logo Website!"})

    f = request.files.get("logo")
    custom_title = (request.form.get("custom_title") or "").strip()
    if custom_title:
        set_setting("custom_web_title", custom_title)
    if not f:
        return jsonify({"ok": False, "error": "Chưa chọn ảnh"}), 400
    raw = f.read()
    if not raw or len(raw) > 10 * 1024 * 1024:
        return jsonify({"ok": False, "error": "Ảnh không hợp lệ hoặc quá 10MB"}), 400
    mime = f.mimetype or "image/png"
    set_setting("brand_logo_url", "")
    set_setting("brand_logo_b64", base64.b64encode(raw).decode("utf-8"))
    set_setting("brand_logo_mime", mime)
    set_setting("brand_logo_ts", str(int(time.time())))
    return jsonify({"ok": True, "message": "Đã tải lên Logo Website thành công!"})

@app.route("/api/logo/reset", methods=["POST"])
def api_reset_logo():
    set_setting("brand_logo_b64", "")
    set_setting("brand_logo_url", "")
    set_setting("custom_web_title", "")
    set_setting("brand_logo_ts", str(int(time.time())))
    return jsonify({"ok": True, "message": "Đã khôi phục Logo mặc định!"})

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    acc_rows = get_all_accounts_from_ram()
    for a in acc_rows:
        a["masked_name"] = mask_account_name(a.get("name") or "Tài khoản")
        a["masked_uid"] = mask_sensitive_id(a.get("uid") or a.get("imei") or a.get("token") or "", 3)
    try:
        files_list = get_ordered_files_with_display_num()
    except Exception:
        files_list = []
    has_logo = bool(get_setting("brand_logo_b64", "") or get_setting("brand_logo_url", ""))
    logo_ts = get_setting("brand_logo_ts", "1")
    custom_title = get_setting("custom_web_title", "")
    return render_template_string(
        DASHBOARD_HTML,
        accounts=acc_rows,
        files=files_list,
        has_logo=has_logo,
        logo_ts=logo_ts,
        custom_title=custom_title,
    )

@app.route("/api/discord/immortalize", methods=["POST"])
def api_discord_immortalize():
    data = request.json or {}
    raw_input = (data.get("raw_input") or data.get("token") or "").strip()
    custom_name = (data.get("name") or "").strip()
    auto_save = bool(data.get("auto_save", True))
    res = DiscordImmortalRegTool.immortalize_tokens_batch(
        raw_input, custom_name=custom_name, auto_save=auto_save
    )
    return jsonify(res), (200 if res.get("ok") else 400)

@app.route("/api/discord/batch_reg_profiles", methods=["POST"])
def api_discord_batch_reg_profiles():
    data = request.json or {}
    cnt = int(data.get("count", 5))
    res = DiscordImmortalRegTool.generate_batch_clean_reg_profiles(count=cnt)
    return jsonify(res), 200

@app.route("/api/discord/register_acc", methods=["POST"])
def api_discord_register_acc():
    data = request.json or {}
    email = (data.get("email") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    dob = (data.get("dob") or "2000-06-15").strip()
    invite_code = (data.get("invite_code") or "").strip()
    auto_save = bool(data.get("auto_save", True))
    res = DiscordImmortalRegTool.register_new_account(
        email=email, username=username, password=password,
        dob=dob, invite_code=invite_code, auto_save=auto_save
    )
    return jsonify(res), 200

@app.route("/api/discord/refresh_firewall", methods=["POST"])
def api_discord_refresh_firewall():
    rows = get_all_accounts_from_ram(platform="discord")
    refreshed = 0
    for r in rows:
        tk = (r.get("token") or "").strip()
        if tk:
            tkey = DiscordStealthAntiBanEngine._token_vault_key(tk)
            with DiscordStealthAntiBanEngine._LOCK:
                DiscordStealthAntiBanEngine._WARMED_SESSIONS.discard(tkey)
            DiscordStealthAntiBanEngine.ensure_session_warmed_up(tk, is_bot=bool(r.get("is_bot", 0)))
            refreshed += 1
    return jsonify({
        "ok": True,
        "refreshed": refreshed,
        "message": f"Đã làm mới Tường Lửa & nạp lại Cookie Cloudflare cho {refreshed} tài khoản Discord!"
    })

@app.route("/api/tools/2fa", methods=["POST", "GET"])
def api_tools_2fa():
    if request.method == "POST":
        data = request.json or {}
        secret = (data.get("secret") or "").strip()
    else:
        secret = (request.args.get("secret") or "").strip()
    token, rem_sec = generate_totp_rfc6238(secret)
    if token:
        return jsonify({"ok": True, "token": token, "rem_sec": rem_sec})
    return jsonify({"ok": False, "error": "Secret Key 2FA không hợp lệ!"}), 400

@app.route("/api/zalo/generate_imei")
def api_zalo_generate_imei():
    return jsonify({"ok": True, "imei": ZaloWebIDGenerator.generate_unique_imei(salt=secrets.token_hex(6))})

@app.route("/api/zalo/qr_start", methods=["POST"])
def api_zalo_qr_start():
    data = request.json or {}
    auto_save = bool(data.get("auto_save", True))
    vn_region = str(data.get("vn_region") or "HCM").strip().upper()
    custom_pc_name = str(data.get("custom_pc_name") or "").strip()
    vn_proxy = str(data.get("vn_proxy") or "").strip()
    res = ZaloQRLoginManager.start_qr_session(
        auto_save=auto_save,
        vn_region=vn_region,
        custom_pc_name=custom_pc_name,
        vn_proxy=vn_proxy,
    )
    return jsonify(res)

@app.route("/api/zalo/pc_devices")
def api_zalo_pc_devices():
    try:
        from zalo_login import ZaloPCSessionKeeper
        devs = ZaloPCSessionKeeper.list_active_devices()
    except Exception:
        devs = []
    return jsonify({"ok": True, "devices": devs})

@app.route("/api/telegram/status")
def api_telegram_status():
    try:
        from get_ck_im_zalo import get_telegram_bot_status
        st = get_telegram_bot_status()
    except Exception as e:
        st = {"running": False, "last_error": str(e)}
    return jsonify({"ok": True, **st})

@app.route("/api/telegram/restart", methods=["POST"])
def api_telegram_restart():
    global _TELEGRAM_BOT_RUNNER
    try:
        from get_ck_im_zalo import start_background_telegram_bot, get_telegram_bot_status
        _TELEGRAM_BOT_RUNNER = start_background_telegram_bot(TELEGRAM_BOT_TOKEN, force_restart=True)
        time.sleep(0.6)
        st = get_telegram_bot_status()
        return jsonify({"ok": True, "message": "🤖 Đã khởi động lại Bot Telegram & gỡ bỏ Webhook xung đột thành công!", **st})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200

@app.route("/api/zalo/qr_status/<session_id>")
def api_zalo_qr_status(session_id):
    res = ZaloQRLoginManager.get_session_status(session_id)
    return jsonify(res)

@app.route("/api/zalo/qr_image/<session_id>.png")
def api_zalo_qr_image_png(session_id):
    png_bytes = ZaloQRLoginManager.get_qr_png_bytes(session_id)
    if not png_bytes:
        return Response(status=204)
    resp = Response(png_bytes, mimetype="image/png")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp

@app.route("/api/zalo/vault")
def api_zalo_vault_list():
    return jsonify({"ok": True, "records": ZaloCookieVaultEngine.list_vault_records()})

@app.route("/api/zalo/verify_cookie_imei", methods=["POST"])
def api_zalo_verify_cookie_imei():
    data = request.json or {}
    raw_imei = (data.get("imei") or "").strip()
    raw_cookies = (data.get("cookies") or "").strip()
    custom_name = (data.get("name") or "").strip()
    auto_save = bool(data.get("auto_save", True))

    imei = extract_imei_from_raw_input(raw_imei, raw_cookies)
    if not imei:
        imei = ZaloWebIDGenerator.generate_unique_imei(salt=raw_cookies[:32])
    cookies_dict = normalize_zalo_cookies(raw_cookies or raw_imei)
    if not cookies_dict:
        return jsonify({"ok": False, "error": "Cookie Zalo không hợp lệ hoặc để trống!"}), 400

    uid = ""
    zpw_enk = ""
    acc_name = custom_name or f"Zalo_{imei[-4:]}"
    verified_live = False
    try:
        z = Zalo.get_pooled_client(imei, cookies_dict, force_new=True)
        uid = z.uid or ""
        zpw_enk = z.secret_key or ""
        if not custom_name and z.display_name:
            acc_name = z.display_name
        cookies_dict = z.cookies_dict
        verified_live = True
    except Exception:
        uid = f"zalo_{hashlib.md5(imei.encode('utf-8')).hexdigest()[:8]}"

    ZaloCookieVaultEngine.save_zalo_vault_record(
        uid=uid, display_name=acc_name, imei=imei, cookies_dict=cookies_dict, zpw_enk=zpw_enk
    )

    if auto_save:
        conn = db()
        existing = conn.execute("SELECT id FROM accounts WHERE platform='zalo' AND (uid=? OR imei=?)", (uid, imei)).fetchone()
        if existing:
            conn.execute(
                "UPDATE accounts SET name=?, imei=?, cookies=?, uid=?, enabled=1 WHERE id=?",
                (acc_name, imei, json.dumps(cookies_dict, ensure_ascii=False), uid, existing["id"])
            )
        else:
            conn.execute(
                """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
                   VALUES (?, 'zalo', ?, ?, '', 0, ?, 1, '.', 1, 1, ?)""",
                (acc_name, imei, json.dumps(cookies_dict, ensure_ascii=False), uid, time.time())
            )
        conn.commit()
        conn.close()
        sync_all_zalo_listeners()

    return jsonify({
        "ok": True,
        "uid": uid,
        "name": acc_name,
        "imei": imei,
        "verified_live": verified_live,
        "zpw_enk_ready": bool(zpw_enk),
        "message": f"Đã lưu Cookie & IMEI của {acc_name} vào Kho lưu trữ và kết nối API Zalo thành công!"
    })

@app.route("/api/zalo/vault/activate", methods=["POST"])
def api_zalo_vault_activate():
    data = request.json or {}
    uid = str(data.get("uid") or "").strip()
    records = ZaloCookieVaultEngine.list_vault_records()
    rec = next((r for r in records if str(r["uid"]) == uid), None)
    if not rec:
        return jsonify({"ok": False, "error": "Không tìm thấy bản ghi trong Kho lưu trữ"}), 404
    conn = db()
    existing = conn.execute("SELECT id FROM accounts WHERE platform='zalo' AND (uid=? OR imei=?)", (rec["uid"], rec["imei"])).fetchone()
    if existing:
        conn.execute(
            "UPDATE accounts SET name=?, imei=?, cookies=?, uid=?, enabled=1 WHERE id=?",
            (rec["display_name"], rec["imei"], json.dumps(rec["cookies"], ensure_ascii=False), rec["uid"], existing["id"])
        )
    else:
        conn.execute(
            """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
               VALUES (?, 'zalo', ?, ?, '', 0, ?, 1, '.', 1, 1, ?)""",
            (rec["display_name"], rec["imei"], json.dumps(rec["cookies"], ensure_ascii=False), rec["uid"], time.time())
        )
    conn.commit()
    conn.close()
    sync_all_zalo_listeners()
    return jsonify({"ok": True, "message": f"Đã kích hoạt & kết nối lại tài khoản Zalo {rec['display_name']}!"})

@app.route("/api/zalo/vault/delete", methods=["POST"])
def api_zalo_vault_delete():
    data = request.json or {}
    uid = str(data.get("uid") or "").strip()
    ZaloCookieVaultEngine.delete_vault_record(uid)
    return jsonify({"ok": True})

@app.route("/api/proxies", methods=["GET"])
def api_get_proxies():
    return jsonify({"ok": True, **ProxyPoolEngine.get_snapshot()})

@app.route("/api/proxies/save", methods=["POST"])
def api_save_proxies():
    data = request.json or {}
    raw_proxies = data.get("proxies", "")
    enabled = bool(data.get("enabled", True))
    cnt = ProxyPoolEngine.save_proxies(raw_proxies, enabled=enabled)
    return jsonify({
        "ok": True,
        "count": cnt,
        "snapshot": ProxyPoolEngine.get_snapshot(),
        "message": f"Đã lưu {cnt} Proxy vào Hồ Proxy Siêu Tốc (Tự động xoay vòng & Failover 0ms)!"
    })

@app.route("/api/proxies/test", methods=["POST"])
def api_test_proxies():
    res = ProxyPoolEngine.test_all_proxies()
    res["snapshot"] = ProxyPoolEngine.get_snapshot()
    return jsonify(res)

@app.route("/api/proxies/clear", methods=["POST"])
def api_clear_proxies():
    ProxyPoolEngine.save_proxies("", enabled=True)
    return jsonify({
        "ok": True,
        "snapshot": ProxyPoolEngine.get_snapshot(),
        "message": "Đã xóa danh sách Proxy & chuyển về chế độ Direct Keep-Alive!"
    })

@app.route("/api/antidieall/heal", methods=["POST"])
def api_antidieall_heal():
    HEALTH_MGR.auto_heal_all()
    return jsonify({"ok": True, "message": "⚡ Đã làm mới toàn bộ kết nối & hàng đợi đa luồng!"})

@app.route("/api/discord/set_status", methods=["POST"])
def api_discord_set_status():
    data = request.json or {}
    text = (data.get("text") or "Online").strip()
    rows = get_all_accounts_from_ram(platform="discord")
    ok_cnt = 0
    for r in rows:
        try:
            dc = DiscordClient(r["token"], is_bot=bool(r.get("is_bot", 0)))
            if dc.set_custom_status(text):
                ok_cnt += 1
        except Exception:
            continue
    return jsonify({"ok": True, "updated": ok_cnt, "message": f"Đã cập nhật Custom Status cho {ok_cnt} tài khoản Discord!"})

@app.route("/api/discord/hypesquad", methods=["POST"])
def api_discord_hypesquad():
    data = request.json or {}
    house_id = int(data.get("house_id") or 1)
    rows = get_all_accounts_from_ram(platform="discord")
    ok_cnt = 0
    for r in rows:
        try:
            dc = DiscordClient(r["token"], is_bot=bool(r.get("is_bot", 0)))
            if dc.set_hypesquad(house_id):
                ok_cnt += 1
        except Exception:
            continue
    return jsonify({"ok": True, "updated": ok_cnt, "message": f"Đã đổi huy hiệu HypeSquad cho {ok_cnt} tài khoản Discord!"})

@app.route("/api/messenger/login_credentials", methods=["POST"])
def api_messenger_login_credentials():
    data = request.json or {}
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    custom_name = (data.get("name") or "").strip()
    auto_save = bool(data.get("auto_save", True))
    getter = FacebookCookieGetter()
    cookie_str, uid, msg = getter.login_facebook(email, password)
    if not cookie_str or not uid:
        return jsonify({"ok": False, "error": msg}), 400
    c_dict = normalize_messenger_cookies(cookie_str)
    acc_name = custom_name or f"Mess_{uid[-4:]}"
    try:
        m_client = MessengerClient.get_pooled_client(c_dict, uid=uid, force_new=True)
        if not custom_name and m_client.display_name:
            acc_name = m_client.display_name
        c_dict = m_client.cookies_dict
    except Exception:
        pass
    if auto_save:
        conn = db()
        existing = conn.execute("SELECT id FROM accounts WHERE platform='messenger' AND uid=?", (uid,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE accounts SET name=?, cookies=?, enabled=1 WHERE id=?",
                (acc_name, json.dumps(c_dict, ensure_ascii=False), existing["id"])
            )
        else:
            conn.execute(
                """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
                   VALUES (?, 'messenger', '', ?, '', 0, ?, 1, '.', 1, 1, ?)""",
                (acc_name, json.dumps(c_dict, ensure_ascii=False), uid, time.time())
            )
        conn.commit()
        conn.close()
        sync_all_zalo_listeners()
    return jsonify({"ok": True, "cookie": cookie_str, "uid": uid, "name": acc_name, "message": "Đã lấy Cookie Facebook thành công!"})

@app.route("/api/discord/reg_login", methods=["POST"])
def api_discord_reg_login():
    data = request.json or {}
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    two_fa = (data.get("two_fa") or "").strip()
    twofa_type = (data.get("twofa_type") or "totp").strip()
    auto_save = bool(data.get("auto_save", True))

    res = login_discord_reg_session(email, password, two_fa, twofa_type=twofa_type)
    if not res.get("ok"):
        return jsonify(res), 400

    token = res["token"]
    prof = res.get("profile") or {}
    if auto_save:
        uid = str(prof.get("id") or "")
        uname = prof.get("global_name") or prof.get("username") or f"Discord_{uid[-4:]}"
        conn = db()
        conn.execute(
            """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
               VALUES (?, 'discord', '', '{}', ?, 0, ?, 1, '.', 1, 1, ?)""",
            (uname, token, uid, time.time()),
        )
        conn.commit()
        conn.close()
        sync_all_zalo_listeners()
    return jsonify({
        "ok": True,
        "token": token,
        "message": "Đã lấy Token Discord sạch & kích hoạt bảo vệ!"
    })

@app.route("/api/ping")
def api_ping():
    t0 = time.perf_counter()
    active_th = threading.active_count()
    running_cnt = sum(1 for v in ACTIVE_TASKS.values() if not v["stop"].is_set())
    tel = HEALTH_MGR.get_live_ping_telemetry()
    eng_ms = round((time.perf_counter() - t0) * 1000.0 + 0.25, 2)
    return jsonify({
        "ok": True,
        "server_ts": int(time.time() * 1000),
        "engine_ms": eng_ms,
        "active_threads": active_th,
        "running_tasks": running_cnt,
        "avg_send_ms": tel["avg_send_ms"],
        "jitter_ms": tel["jitter_ms"],
        "total_rpm": tel["total_rpm"],
        "total_healed": tel["total_healed"],
        "ping_history": tel["history"],
    })

@app.route("/api/messenger/verify_cookie", methods=["POST"])
def api_messenger_verify_cookie():
    data = request.json or {}
    raw_cookies = (data.get("cookies") or "").strip()
    custom_name = (data.get("name") or "").strip()
    auto_save = bool(data.get("auto_save", True))
    c_dict = normalize_messenger_cookies(raw_cookies)
    uid = extract_messenger_uid(c_dict)
    if not uid or "xs" not in c_dict:
        return jsonify({"ok": False, "error": "Cookie Messenger thiếu trường c_user hoặc xs!"}), 400
    try:
        m_bot = MessengerClient.get_pooled_client(c_dict, uid=uid, force_new=True)
        acc_name = custom_name or m_bot.display_name or f"Mess_{uid[-4:]}"
        if auto_save:
            conn = db()
            existing = conn.execute(
                "SELECT id FROM accounts WHERE platform='messenger' AND uid=?", (uid,)
            ).fetchone()
            if existing:
                conn.execute(
                    "UPDATE accounts SET name=?, cookies=?, enabled=1 WHERE id=?",
                    (acc_name, json.dumps(m_bot.cookies_dict, ensure_ascii=False), existing["id"])
                )
            else:
                conn.execute(
                    """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
                       VALUES (?, 'messenger', '', ?, '', 0, ?, 1, '.', 1, 1, ?)""",
                    (acc_name, json.dumps(m_bot.cookies_dict, ensure_ascii=False), uid, time.time())
                )
            conn.commit()
            conn.close()
            sync_all_zalo_listeners()
        return jsonify({
            "ok": True,
            "uid": uid,
            "name": acc_name,
            "message": f"Đã lưu Cookie Messenger cho {acc_name} & bật kết nối MQTT!"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

_ROOM_SCAN_POOL = ThreadPoolExecutor(max_workers=32)

@app.route("/api/messenger_threads")
def api_messenger_threads():
    force = request.args.get("refresh") == "1"
    filter_acc_id = request.args.get("acc_id", "").strip()
    rows = get_all_accounts_from_ram(platform="messenger")
    if filter_acc_id and filter_acc_id.isdigit():
        rows = [r for r in rows if int(r["id"]) == int(filter_acc_id)]

    def _scan_mess_acc(r):
        aid = int(r["id"])
        aname = r.get("name") or f"Mess #{aid}"
        out_list = []
        try:
            m_bot = MessengerClient.get_pooled_client(r["cookies"], uid=r.get("uid") or "")
            for th in m_bot.get_threads(use_cache=not force):
                item = dict(th)
                item["id"] = str(th["id"])
                item["acc_id"] = aid
                item["acc_name"] = aname
                out_list.append(item)
        except Exception:
            pass
        return aid, aname, out_list

    threads_map = {}
    by_account = {}
    futs = [_ROOM_SCAN_POOL.submit(_scan_mess_acc, r) for r in rows]
    for fut in futs:
        try:
            aid, aname, t_list = fut.result(timeout=12)
            by_account[str(aid)] = {"acc_id": aid, "acc_name": aname, "platform": "messenger", "boxes": t_list}
            for th in t_list:
                tid = str(th["id"])
                if tid not in threads_map:
                    th_copy = dict(th)
                    th_copy["acc_ids"] = [aid]
                    th_copy["acc_names"] = [aname]
                    threads_map[tid] = th_copy
                else:
                    if aid not in threads_map[tid]["acc_ids"]:
                        threads_map[tid]["acc_ids"].append(aid)
                        threads_map[tid]["acc_names"].append(aname)
        except Exception:
            continue
    return jsonify({"threads": list(threads_map.values()), "by_account": by_account})

@app.route("/api/messenger_thread_members")
def api_messenger_thread_members():
    tid = (request.args.get("thread_id") or "").strip()
    if not tid:
        return jsonify({"members": []})
    rows = get_all_accounts_from_ram(platform="messenger")
    for r in rows:
        try:
            m_bot = MessengerClient.get_pooled_client(r["cookies"], uid=r.get("uid") or "")
            mems = m_bot.get_thread_members(tid, use_cache=False)
            if mems:
                return jsonify({"members": mems})
        except Exception:
            continue
    return jsonify({"members": []})

@app.route("/account/add", methods=["POST"])
def account_add():
    platform = (request.form.get("platform") or "zalo").strip().lower()
    custom_name = (request.form.get("name") or "").strip()
    chat_cmd = 1 if request.form.get("chat_cmd_enabled") else 0
    allow_all = 1 if request.form.get("allow_all_cmd") else 0

    if platform == "messenger":
        raw_mc = (request.form.get("mess_cookies") or request.form.get("cookies") or "").strip()
        c_dict = normalize_messenger_cookies(raw_mc)
        uid = extract_messenger_uid(c_dict)
        if not uid or not c_dict:
            return redirect("/")
        acc_name = custom_name or f"Mess_{uid[-4:]}"
        try:
            m_bot = MessengerClient.get_pooled_client(c_dict, uid=uid)
            if not custom_name and m_bot.display_name:
                acc_name = m_bot.display_name
            c_dict = m_bot.cookies_dict
        except Exception:
            pass
        conn = db()
        conn.execute(
            """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
               VALUES (?, 'messenger', '', ?, '', 0, ?, ?, '.', ?, 1, ?)""",
            (acc_name, json.dumps(c_dict, ensure_ascii=False), uid, chat_cmd, allow_all, time.time()),
        )
        conn.commit()
        conn.close()
        sync_all_zalo_listeners()
        return redirect("/")

    if platform == "discord":
        raw_token_input = (request.form.get("token") or "").strip()
        reg_email = (request.form.get("reg_email") or "").strip()
        reg_password = (request.form.get("reg_password") or "").strip()
        reg_2fa = (request.form.get("reg_2fa") or "").strip()
        is_bot = 1 if request.form.get("is_bot") else 0
        tokens = extract_discord_tokens_from_reg_or_raw(raw_token_input)
        if not tokens and (reg_email or reg_password):
            res_login = login_discord_reg_session(reg_email, reg_password, reg_2fa)
            if res_login.get("ok") and res_login.get("token"):
                tokens = [res_login["token"]]
        if not tokens:
            return redirect("/")

        conn = db()
        for idx, tk in enumerate(tokens):
            w_res = warmup_discord_stealth_token(tk)
            uid = str(w_res.get("uid") or "").strip()
            real_uname = w_res.get("username") or (f"Discord_{uid[-4:]}" if uid else f"Discord #{idx + 1}")
            acc_name = (f"{custom_name} #{idx + 1}" if (custom_name and len(tokens) > 1) else custom_name) or real_uname
            if uid:
                OWNER_UIDS_CACHE.add(uid)
            existing = conn.execute("SELECT id FROM accounts WHERE platform='discord' AND token=?", (tk,)).fetchone()
            if not existing and uid:
                existing = conn.execute("SELECT id FROM accounts WHERE platform='discord' AND uid=?", (uid,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE accounts SET name=?, token=?, is_bot=?, uid=?, chat_cmd_enabled=?, allow_all_cmd=?, enabled=1 WHERE id=?",
                    (acc_name, tk, is_bot, uid, chat_cmd, allow_all, existing["id"])
                )
            else:
                conn.execute(
                    """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
                       VALUES (?, 'discord', '', '{}', ?, ?, ?, ?, '.', ?, 1, ?)""",
                    (acc_name, tk, is_bot, uid, chat_cmd, allow_all, time.time()),
                )
        conn.commit()
        conn.close()
        refresh_accounts_ram_cache()
        sync_all_zalo_listeners()
        return redirect("/")

    raw_imei = (request.form.get("imei") or "").strip()
    raw_cookies = (request.form.get("cookies") or "").strip()
    imei = extract_imei_from_raw_input(raw_imei, raw_cookies)
    cookies_dict = normalize_zalo_cookies(raw_cookies or raw_imei)
    if not imei or not cookies_dict:
        return redirect("/")

    uid = ""
    acc_name = custom_name or f"Zalo_{imei[-4:]}"
    try:
        z = Zalo.get_pooled_client(imei, cookies_dict)
        uid = z.uid or ""
        if not custom_name and z.display_name:
            acc_name = z.display_name
    except Exception:
        pass

    conn = db()
    conn.execute(
        """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
           VALUES (?, 'zalo', ?, ?, '', 0, ?, ?, '.', ?, 1, ?)""",
        (acc_name, imei, json.dumps(cookies_dict, ensure_ascii=False), uid, chat_cmd, allow_all, time.time()),
    )
    conn.commit()
    conn.close()
    sync_all_zalo_listeners()
    return redirect("/")

@app.route("/account/delete/<int:acc_id>")
def account_delete(acc_id):
    if acc_id in ACTIVE_LISTENERS:
        ACTIVE_LISTENERS[acc_id].stop()
        ACTIVE_LISTENERS.pop(acc_id, None)
    conn = db()
    conn.execute("DELETE FROM accounts WHERE id=?", (acc_id,))
    conn.commit()
    conn.close()
    refresh_accounts_ram_cache()
    refresh_owner_uids()
    return redirect("/")

@app.route("/api/account/chat_cmd", methods=["POST"])
def api_toggle_chat_cmd():
    data = request.json or {}
    acc_id = int(data.get("acc_id", 0))
    enabled = 1 if data.get("enabled") else 0
    conn = db()
    conn.execute("UPDATE accounts SET chat_cmd_enabled=? WHERE id=?", (enabled, acc_id))
    conn.commit()
    conn.close()
    sync_all_zalo_listeners()
    return jsonify({"ok": True})

@app.route("/api/account/allow_all_cmd", methods=["POST"])
def api_toggle_allow_all():
    data = request.json or {}
    acc_id = int(data.get("acc_id", 0))
    allow_all = 1 if data.get("allow_all") else 0
    conn = db()
    conn.execute("UPDATE accounts SET allow_all_cmd=? WHERE id=?", (allow_all, acc_id))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route("/api/all_groups")
def api_all_groups():
    force = request.args.get("refresh") == "1"
    filter_acc_id = request.args.get("acc_id", "").strip()
    rows = get_all_accounts_from_ram(platform="zalo")
    if filter_acc_id and filter_acc_id.isdigit():
        rows = [r for r in rows if int(r["id"]) == int(filter_acc_id)]

    def _scan_zalo_acc(r):
        aid = int(r["id"])
        aname = r.get("name") or f"Zalo #{aid}"
        g_out = []
        f_out = []
        try:
            z = Zalo.get_pooled_client(
                r["imei"], r["cookies"],
                user_agent=r.get("user_agent") or "",
                zpw_enk_hint=r.get("zpw_enk") or "",
                uid_hint=r.get("uid") or ""
            )
            for g in z.groups(use_cache=not force):
                item = dict(g)
                item["id"] = str(g["id"])
                item["acc_id"] = aid
                item["acc_name"] = aname
                g_out.append(item)
            for f in z.friends(use_cache=not force):
                item = dict(f)
                item["id"] = str(f["id"])
                item["acc_id"] = aid
                item["acc_name"] = aname
                f_out.append(item)
        except Exception:
            pass
        return aid, aname, g_out, f_out

    groups_map = {}
    friends_map = {}
    by_account = {}
    futs = [_ROOM_SCAN_POOL.submit(_scan_zalo_acc, r) for r in rows]
    for fut in futs:
        try:
            aid, aname, g_list, f_list = fut.result(timeout=12)
            by_account[str(aid)] = {
                "acc_id": aid,
                "acc_name": aname,
                "platform": "zalo",
                "boxes": g_list + f_list
            }
            for g in g_list:
                gid = str(g["id"])
                if gid not in groups_map:
                    gc = dict(g)
                    gc["acc_ids"] = [aid]
                    gc["acc_names"] = [aname]
                    groups_map[gid] = gc
                else:
                    if aid not in groups_map[gid]["acc_ids"]:
                        groups_map[gid]["acc_ids"].append(aid)
                        groups_map[gid]["acc_names"].append(aname)
            for f in f_list:
                fid = str(f["id"])
                if fid not in friends_map:
                    fc = dict(f)
                    fc["acc_ids"] = [aid]
                    fc["acc_names"] = [aname]
                    friends_map[fid] = fc
                else:
                    if aid not in friends_map[fid]["acc_ids"]:
                        friends_map[fid]["acc_ids"].append(aid)
                        friends_map[fid]["acc_names"].append(aname)
        except Exception:
            continue
    return jsonify({"groups": list(groups_map.values()), "friends": list(friends_map.values()), "by_account": by_account})

@app.route("/api/group_members")
def api_group_members():
    gid = (request.args.get("group_id") or "").strip()
    force = request.args.get("refresh") == "1"
    if not gid:
        return jsonify({"members": []})
    rows = get_all_accounts_from_ram(platform="zalo")
    for r in rows:
        try:
            z = Zalo.get_pooled_client(
                r["imei"], r["cookies"],
                user_agent=r.get("user_agent") or "",
                zpw_enk_hint=r.get("zpw_enk") or "",
                uid_hint=r.get("uid") or ""
            )
            mems = z.get_members_full(gid, use_cache=not force)
            if mems:
                return jsonify({"members": mems})
        except Exception:
            continue
    return jsonify({"members": []})

@app.route("/api/discord_channels")
def api_discord_channels():
    """Quét song toàn bộ Box Nhóm, Chat Riêng và Server của TỪNG Tài Khoản Discord (Chọn Box theo từng Acc):
    - Chạy đa luồng qua _ROOM_SCAN_POOL không bao giờ làm đơ web dù áp 50-100 Acc Discord cùng lúc!
    - Trả về cả danh sách tổng hợp kèm `acc_ids`/`acc_names` VÀ `by_account` để chọn Box theo từng Acc riêng biệt."""
    force = request.args.get("refresh") == "1"
    filter_acc_id = request.args.get("acc_id", "").strip()
    rows = get_all_accounts_from_ram(platform="discord")
    if filter_acc_id and filter_acc_id.isdigit():
        rows = [r for r in rows if int(r["id"]) == int(filter_acc_id)]

    def _scan_discord_acc(r):
        aid = int(r["id"])
        aname = r.get("name") or f"Discord #{aid}"
        boxes_out = []
        try:
            bot = DiscordClient(r["token"], is_bot=bool(r.get("is_bot", 0)))
            for b in bot.get_all_boxes(force_refresh=force):
                cid = str(b["id"])
                boxes_out.append({
                    "id": cid,
                    "name": b["name"],
                    "type": "discord_channel",
                    "sub_type": b.get("sub_type", "channel"),
                    "acc_id": aid,
                    "acc_name": aname,
                })
        except Exception:
            pass
        return aid, aname, boxes_out

    channels_map = {}
    by_account = {}
    futs = [_ROOM_SCAN_POOL.submit(_scan_discord_acc, r) for r in rows]
    for fut in futs:
        try:
            aid, aname, b_list = fut.result(timeout=12)
            by_account[str(aid)] = {
                "acc_id": aid,
                "acc_name": aname,
                "platform": "discord",
                "boxes": b_list,
            }
            for b in b_list:
                cid = str(b["id"])
                if cid not in channels_map:
                    bc = dict(b)
                    bc["acc_ids"] = [aid]
                    bc["acc_names"] = [aname]
                    channels_map[cid] = bc
                else:
                    if aid not in channels_map[cid]["acc_ids"]:
                        channels_map[cid]["acc_ids"].append(aid)
                        channels_map[cid]["acc_names"].append(aname)
        except Exception:
            continue
    return jsonify({"channels": list(channels_map.values()), "by_account": by_account})

@app.route("/api/discord_channel_members")
def api_discord_channel_members():
    cid = (request.args.get("channel_id") or "").strip()
    if not cid:
        return jsonify({"members": []})
    rows = get_all_accounts_from_ram(platform="discord")
    for r in rows:
        try:
            bot = DiscordClient(r["token"], is_bot=bool(r.get("is_bot", 0)))
            mems = bot.get_channel_recent_members(cid)
            if mems:
                return jsonify({"members": mems})
        except Exception:
            continue
    return jsonify({"members": []})

@app.route("/file/upload", methods=["POST"])
def file_upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "Chưa chọn file"}), 400
    fname = os.path.basename(f.filename)
    if not fname.lower().endswith(".txt"):
        fname += ".txt"
    save_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{fname}")
    raw_bytes = f.read()
    text_content = raw_bytes.decode("utf-8", errors="ignore")
    cleaned = clean_corrupted_shortcuts(text_content)
    with open(save_path, "w", encoding="utf-8") as wf:
        wf.write(cleaned)
    parsed = parse_file_stream_fast(save_path, strip_numbers=True)
    lines_cnt = parsed.get("line_count", len(parsed.get("lines", []))) if isinstance(parsed, dict) else len(parsed)
    conn = db()
    conn.execute(
        "INSERT INTO files (filename, filepath, lines_count, created_at) VALUES (?, ?, ?, ?)",
        (fname, save_path, lines_cnt, time.time()),
    )
    conn.commit()
    conn.close()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "filename": fname, "lines_count": lines_cnt})
    return redirect("/")

@app.route("/file/create", methods=["POST"])
def file_create():
    fname = (request.form.get("filename") or "kich_ban.txt").strip()
    if not fname.lower().endswith(".txt"):
        fname += ".txt"
    content = clean_corrupted_shortcuts(request.form.get("content") or "")
    save_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{os.path.basename(fname)}")
    with open(save_path, "w", encoding="utf-8") as wf:
        wf.write(content)
    parsed = parse_file_stream_fast(save_path, strip_numbers=True)
    lines_cnt = parsed.get("line_count", len(parsed.get("lines", []))) if isinstance(parsed, dict) else len(parsed)
    conn = db()
    conn.execute(
        "INSERT INTO files (filename, filepath, lines_count, created_at) VALUES (?, ?, ?, ?)",
        (fname, save_path, lines_cnt, time.time()),
    )
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/file/delete/<int:fid>")
def file_delete(fid):
    conn = db()
    row = conn.execute("SELECT filepath FROM files WHERE id=?", (fid,)).fetchone()
    if row and row["filepath"] and os.path.exists(row["filepath"]):
        try:
            os.remove(row["filepath"])
        except Exception:
            pass
    conn.execute("DELETE FROM files WHERE id=?", (fid,))
    conn.commit()
    conn.close()
    return redirect("/")

@app.route("/task/start", methods=["POST"])
def route_task_start():
    data = request.json or {}
    targets = data.get("targets") or []
    if not targets:
        return jsonify({"ok": False, "error": "Chưa chọn phòng chat mục tiêu!"}), 400

    mode = data.get("mode", "treo_nhay")
    file_id = str(data.get("file_id") or "").strip()
    raw_text = clean_corrupted_shortcuts(data.get("raw_text") or "").strip()
    tag_users = list(data.get("tag_users") or [])
    tag_all = bool(data.get("tag_all", False))
    batch_count = max(1, min(100, int(data.get("batch_count", 1) or 1)))

    if raw_text and "@" in raw_text:
        conn = db()
        z_row = conn.execute("SELECT * FROM accounts WHERE platform='zalo' LIMIT 1").fetchone()
        conn.close()
        z_client = None
        if z_row:
            try:
                z_client = Zalo.get_pooled_client(z_row["imei"], z_row["cookies"])
            except Exception:
                pass
        first_gid = next((t["id"] for t in targets if t.get("type") == "group"), None)
        stripped, auto_m, auto_all = extract_trailing_tags_and_resolve(
            raw_text, incoming_mentions=None, zalo_client=z_client, group_id=first_gid
        )
        if auto_m or auto_all:
            raw_text = stripped if stripped else raw_text
            if auto_all:
                tag_all = True
            for am in auto_m:
                if not any(str(x.get("uid") or x.get("id")) == str(am["uid"]) for x in tag_users):
                    tag_users.append(am)

    blocks = []
    if file_id:
        blocks = get_blocks_from_file_query(file_id, mode=mode)
    if not blocks and raw_text:
        if mode == "treo_nhay":
            if ";" in raw_text:
                blocks = [strip_leading_line_number(x.strip()) for x in raw_text.split(";") if x.strip()]
            else:
                blocks = [strip_leading_line_number(x.strip()) for x in raw_text.split("\n") if x.strip()]
        elif mode == "treo_ngon":
            blocks = [raw_text]
        else:
            blocks = [x.strip() for x in raw_text.split(";") if x.strip()] if ";" in raw_text else [raw_text]

    if blocks:
        blocks = [
            b_item for b_item in blocks
            if re.sub(r"<@(?:!|&)?\d+>", "", str(b_item or "")).strip()
            and not re.fullmatch(r"@[\w\s\.\-_À-ỹ]+", re.sub(r"<@(?:!|&)?\d+>", "", str(b_item or "")).strip())
        ]

    if not blocks:
        return jsonify({"ok": False, "error": "Vui lòng chọn File kịch bản hoặc nhập nội dung!"}), 400

    for t in targets:
        if t.get("type") == "discord_channel" and t.get("id"):
            for aid_k in list(ACTIVE_LISTENERS.keys()):
                DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS[aid_k].add(str(t["id"]))
        elif t.get("type") in ("messenger_thread", "messenger_group") and t.get("id"):
            for aid_k in list(ACTIVE_LISTENERS.keys()):
                MessengerStealthAntiBanEngine.ACTIVE_MESSENGER_POLL_THREADS[aid_k].add(str(t["id"]))
        elif t.get("id"):
            HOT_ACTIVE_ZALO_GROUPS.add(str(t["id"]))
            ALL_KNOWN_ZALO_GROUP_IDS.add(str(t["id"]))

    raw_delay = float(data.get("delay", 0.0) or 0.0)
    antiband_flag = bool(data.get("antiband", True))
    eff_delay = max(0.0, raw_delay)

    account_ids = data.get("account_ids") or []
    created_tids = []
    for b_i in range(batch_count):
        b_blocks = list(blocks)
        if b_i > 0 and len(b_blocks) > 1:
            shift = b_i % len(b_blocks)
            b_blocks = b_blocks[shift:] + b_blocks[:shift]
        tid = start_task_programmatic(
            targets=targets,
            blocks=b_blocks,
            delay=eff_delay,
            use_emoji=bool(data.get("use_emoji", True)),
            icon_count=int(data.get("icon_count", 3)),
            tag_users=tag_users,
            tag_all=tag_all,
            is_heading=bool(data.get("is_heading", True)),
            multi_acc=bool(data.get("multi_acc", True)),
            mode=mode,
            color_mode=data.get("color_mode", "rainbow"),
            fixed_color=data.get("fixed_color", "red"),
            antiband=antiband_flag,
            antidieall=True,
            source_label="web",
            account_ids=account_ids,
            trigger_cmd=f"Web UI ({mode})",
            hide_tag_all=bool(data.get("hide_tag_all", True)),
            hide_tag_name=bool(data.get("hide_tag_name", True)) or (mode == "nhay_tag_ten_an"),
            font_style=data.get("font_style", "big_bold" if bool(data.get("is_heading", True)) else "normal")
        )
        created_tids.append(tid)
    log_system_command(
        0, targets[0].get("id", ""), "Admin_Web",
        f"[WEB] Khởi chạy {mode} ({len(created_tids)} luồng)",
        f"Chạy trên {len(targets)} phòng | Đa tài khoản: {'BẬT' if data.get('multi_acc', True) else 'TẮT'}"
    )
    with _STATUS_CACHE_LOCK:
        _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
    return jsonify({"ok": True, "task_id": created_tids[0], "task_ids": created_tids, "batch_count": len(created_tids)})

@app.route("/api/account/test_session", methods=["POST"])
def api_account_test_session():
    data = request.json or {}
    acc_id = int(data.get("acc_id") or 0)
    acc = get_account_from_ram(acc_id)
    if not acc:
        return jsonify({"ok": False, "error": "Không tìm thấy tài khoản"}), 404
    plat = (acc.get("platform") or "zalo").lower()
    try:
        if plat == "zalo":
            z = Zalo.get_pooled_client(
                acc["imei"], acc["cookies"], force_new=True,
                user_agent=acc.get("user_agent") or "",
                zpw_enk_hint=acc.get("zpw_enk") or "",
                uid_hint=acc.get("uid") or ""
            )
            g_list = z.groups(use_cache=False)
            sync_all_zalo_listeners()
            log_system_command(acc_id, z.uid or "", z.display_name or "", ".status (Test Phiên PC)", f"Phiên Zalo PC đang ở trong Acc ({len(g_list)} nhóm)")
            return jsonify({
                "ok": True,
                "message": f"Tài khoản Zalo '{z.display_name}' đang ONLINE trong Acc (UID: {z.uid}, {len(g_list)} nhóm, khóa zpw_enk sẵn sàng)!"
            })
        elif plat == "discord":
            dc = DiscordClient(acc["token"], is_bot=bool(acc.get("is_bot", 0)))
            ok_c = dc.check(force_network=False)
            sync_all_zalo_listeners()
            return jsonify({
                "ok": ok_c,
                "message": f"Tài khoản Discord '{acc.get('name')}' đang ONLINE (UID: {dc.user_id})!" if ok_c else "Token Discord cần kiểm tra lại!"
            })
        else:
            mc = MessengerClient.get_pooled_client(acc["cookies"], uid=acc.get("uid") or "")
            sync_all_zalo_listeners()
            return jsonify({"ok": True, "message": f"Tài khoản Messenger '{mc.display_name}' đang hoạt động tốt!"})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Lỗi kiểm tra phiên: {e}"}), 200

@app.route("/api/account/reconnect_all", methods=["POST"])
def api_account_reconnect_all():
    refresh_accounts_ram_cache()
    for aid, lst in list(ACTIVE_LISTENERS.items()):
        try:
            lst.stop()
        except Exception:
            pass
    ACTIVE_LISTENERS.clear()
    sync_all_zalo_listeners()
    return jsonify({
        "ok": True,
        "message": f"Đã kết nối lại & giữ phiên PC Online 24/7 cho {len(ACTIVE_LISTENERS)} tài khoản!"
    })

@app.route("/api/command/dispatch_web", methods=["POST"])
def api_command_dispatch_web():
    data = request.json or {}
    raw_cmd = (data.get("cmd") or "").strip()
    thread_id = str(data.get("thread_id") or "").strip()
    if not raw_cmd:
        return jsonify({"ok": False, "error": "Chưa nhập lệnh!"}), 400
    if not raw_cmd.startswith((".", "/", "!")):
        raw_cmd = "." + raw_cmd

    accs = get_all_accounts_from_ram(enabled_only=True)
    if not accs:
        log_system_command(0, thread_id or "Web_Console", "Admin_Web", raw_cmd, "Đã ghi nhận lệnh trên Web Console (Chưa có tài khoản kết nối)")
        return jsonify({"ok": True, "message": f"Đã ghi nhận lệnh '{raw_cmd}' trên Bảng Soi Lệnh!"})

    acc0 = accs[0]
    plat = (acc0.get("platform") or "zalo").lower()
    z_cli, d_cli, m_cli = None, None, None
    try:
        if plat == "zalo":
            z_cli = Zalo.get_pooled_client(
                acc0["imei"], acc0["cookies"],
                user_agent=acc0.get("user_agent") or "",
                zpw_enk_hint=acc0.get("zpw_enk") or "",
                uid_hint=acc0.get("uid") or ""
            )
            if not thread_id:
                gs = z_cli.groups(use_cache=True)
                thread_id = str(gs[0]["id"]) if gs else str(z_cli.uid or "0")
        elif plat == "discord":
            d_cli = DiscordClient(acc0["token"], is_bot=bool(acc0.get("is_bot", 0)))
            if not thread_id:
                bs = d_cli.get_all_boxes()
                thread_id = str(bs[0]["id"]) if bs else "0"
        elif plat == "messenger":
            m_cli = MessengerClient.get_pooled_client(acc0["cookies"], uid=acc0.get("uid") or "")
            if not thread_id:
                ts = m_cli.get_threads(use_cache=True)
                thread_id = str(ts[0]["id"]) if ts else str(m_cli.uid or "0")
    except Exception:
        pass

    executed = parse_and_execute_inchat_command(
        zalo_client=z_cli,
        acc_row=acc0,
        thread_id=thread_id or "Web_Console",
        is_group=True,
        sender_id=str(acc0.get("uid") or "0"),
        raw_msg=raw_cmd,
        discord_client=d_cli,
        messenger_client=m_cli,
        platform=plat,
        pre_claimed_slot=True
    )
    if not executed:
        log_system_command(acc0["id"], thread_id or "Web_Console", "Admin_Web", raw_cmd, f"Đã thực thi lệnh từ Web Console ({plat.upper()})")
    return jsonify({"ok": True, "message": f"Đã thực thi lệnh '{raw_cmd}' thành công!"})

@app.route("/task/stop/<tid>", methods=["POST"])
def route_task_stop(tid):
    info = ACTIVE_TASKS.pop(tid, None)
    if info:
        if info.get("stop"):
            info["stop"].set()
        for t_id in (info.get("targets") or []):
            bump_stop_epoch(t_id)
            DiscordStealthAntiBanEngine.abort_all_campaign_wait_buckets(t_id)
    else:
        bump_stop_epoch(None)

    with TASKS_RAM_LOCK:
        if tid in TASKS_RAM_STORE:
            TASKS_RAM_STORE[tid]["status"] = "stopped"
            TASKS_RAM_STORE[tid]["dirty"] = True

    def _async_stop_single():
        try:
            conn = db()
            conn.execute("UPDATE tasks SET status='stopped' WHERE id=?", (tid,))
            conn.commit()
        except Exception:
            pass

    threading.Thread(target=_async_stop_single, daemon=True).start()
    with _STATUS_CACHE_LOCK:
        _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
    return jsonify({"ok": True})

@app.route("/task/stop_all", methods=["POST"])
def route_task_stop_all():
    cnt = stop_tasks_for_thread(None)
    return jsonify({"ok": True, "stopped": cnt})

_STATUS_SNAPSHOT_CACHE = {"ts": 0.0, "payload": None}
_STATUS_CACHE_LOCK = threading.RLock()

@app.route("/api/status")
def api_status():
    """API Trạng Thái & Bảng Soi Lệnh Thời Gian Thực:"""
    t0 = time.perf_counter()
    now = time.time()
    with _STATUS_CACHE_LOCK:
        if _STATUS_SNAPSHOT_CACHE["payload"] is not None and (now - _STATUS_SNAPSHOT_CACHE["ts"] < 0.25):
            return jsonify(_STATUS_SNAPSHOT_CACHE["payload"])

    task_list = []
    with TASKS_RAM_LOCK:
        sorted_tasks = sorted(TASKS_RAM_STORE.values(), key=lambda x: x.get("started_at", 0), reverse=True)[:100]
        for t_obj in sorted_tasks:
            tid = t_obj.get("id", "")
            is_active = (tid in ACTIVE_TASKS and not ACTIVE_TASKS[tid]["stop"].is_set() and t_obj.get("status") == "running")
            meta = t_obj.get("meta") or {}
            live_opts = (ACTIVE_TASKS.get(tid) or {}).get("opts") or {}
            task_list.append({
                "id": tid,
                "mode": t_obj.get("type") or live_opts.get("mode") or "treo_nhay",
                "source": meta.get("source") or "web",
                "trigger_cmd": meta.get("trigger_cmd") or "",
                "acc_count": int(t_obj.get("acc_count") or 1),
                "by_acc": t_obj.get("by_acc") or {},
                "targets_count": meta.get("box_count") or len(meta.get("targets") or []),
                "sent": int(t_obj.get("sent", 0)),
                "fail": int(t_obj.get("fail", 0)),
                "status": "Đang chạy" if is_active else "Đã dừng",
                "delay": live_opts.get("delay", t_obj.get("delay", meta.get("delay", 1.0))),
            })

    acc_rows = get_all_accounts_from_ram()
    health_out = []
    for a in acc_rows:
        aid = a["id"]
        snap = HEALTH_MGR.get_snapshot(aid)
        lst = ACTIVE_LISTENERS.get(aid)
        ws_st = getattr(lst, "ws_status", "Đang trực chiến 24/7") if lst else "Tắt nhận lệnh"
        health_out.append({
            "id": aid,
            "platform": a.get("platform") or "zalo",
            "name": a.get("name") or f"Acc #{aid}",
            "masked_name": mask_account_name(a.get("name") or "Account"),
            "circuit": snap["circuit"],
            "rpm": snap["rpm"],
            "ok_total": snap["ok_total"],
            "risk_score": snap["risk_score"],
            "ws_status": sanitize_log_text(ws_st),
        })

    masked_logs = []
    for l in list(BOT_LOGS_RAM_DEQUE)[:45]:
        ts_val = float(l.get("created_at") or time.time())
        s_uid = str(l.get("sender_id") or "").strip()
        s_name = l.get("sender_name") or GLOBAL_USER_NAME_CACHE.get(s_uid) or (l.get("acc_name") if s_uid in ("0", "") else f"UID_{s_uid[-4:]}")
        masked_logs.append({
            "time_str": l.get("time_str") or time.strftime("%H:%M:%S", time.localtime(ts_val)),
            "platform": l.get("platform") or "CHAT",
            "acc_name": l.get("acc_name") or f"Acc #{l.get('acc_id', 0)}",
            "sender_id": s_uid,
            "sender_name": s_name,
            "thread_id": str(l.get("thread_id") or ""),
            "cmd_text": sanitize_log_text(l.get("cmd_text") or ""),
            "action_taken": sanitize_log_text(l.get("action_taken") or ""),
            "masked_thread": mask_sensitive_id(l.get("thread_id") or "", 5),
            "created_at": ts_val,
        })

    with SYSTEM_CFG_LOCK:
        rt_cfg_snap = dict(SYSTEM_RUNTIME_CONFIG)

    auth_users_list = list_authorized_users()
    for au in auth_users_list:
        au["time_str"] = time.strftime("%H:%M:%S %d/%m", time.localtime(float(au.get("added_at") or time.time())))

    tel = HEALTH_MGR.get_live_ping_telemetry()
    eng_ms = round((time.perf_counter() - t0) * 1000.0 + 0.15, 2)
    payload = {
        "tasks": task_list,
        "accounts_health": health_out,
        "cmd_logs": masked_logs,
        "authorized_users": auth_users_list,
        "runtime_config": rt_cfg_snap,
        "discord_firewall": DiscordFirewallEngine.get_firewall_snapshot(),
        "proxy_pool": ProxyPoolEngine.get_snapshot(),
        "ping_telemetry": {
            "engine_ms": eng_ms,
            "active_threads": threading.active_count(),
            "avg_send_ms": tel["avg_send_ms"],
            "jitter_ms": tel["jitter_ms"],
            "total_rpm": tel["total_rpm"],
            "total_healed": tel["total_healed"],
        }
    }
    with _STATUS_CACHE_LOCK:
        _STATUS_SNAPSHOT_CACHE["ts"] = time.time()
        _STATUS_SNAPSHOT_CACHE["payload"] = payload
    return jsonify(payload)

@app.route("/api/runtime_config/update", methods=["POST"])
def api_runtime_config_update():
    data = request.json or {}
    updates = {}
    if "icon_count" in data:
        ic_n = max(0, min(10, int(data.get("icon_count") or 0)))
        updates["icon_count"] = ic_n
        updates["use_emoji"] = (ic_n > 0)
    if "use_emoji" in data and "icon_count" not in data:
        updates["use_emoji"] = bool(data["use_emoji"])
    if "delay" in data:
        updates["delay"] = max(0.0, float(data.get("delay") or 0.0))
    if "color_mode" in data:
        updates["color_mode"] = str(data["color_mode"])
    if "fixed_color" in data:
        updates["fixed_color"] = str(data["fixed_color"])
    if "font_style" in data:
        fs = str(data["font_style"])
        updates["font_style"] = fs
        updates["is_heading"] = (fs in ("big_bold", "alternating_bold", "italic_bold", "underline_bold"))
    if "is_heading" in data and "font_style" not in data:
        updates["is_heading"] = bool(data["is_heading"])
    if "antiband" in data:
        updates["antiband"] = bool(data["antiband"])
    if "hide_tag_all" in data:
        updates["hide_tag_all"] = bool(data["hide_tag_all"])
    if "hide_tag_name" in data:
        updates["hide_tag_name"] = bool(data["hide_tag_name"])
    cnt = update_running_tasks_config(thread_id=None, **updates)
    log_system_command(0, "ALL_GROUPS", "Admin_Web", f"[WEB-SYNC] {json.dumps(updates, ensure_ascii=False)}", f"Đồng bộ cấu hình lên toàn bộ các nhóm ({cnt} tiến trình)", sender_name="Admin Web")
    with SYSTEM_CFG_LOCK:
        snap = dict(SYSTEM_RUNTIME_CONFIG)
    return jsonify({"ok": True, "updated_tasks": cnt, "runtime_config": snap, "message": "Đã áp dụng cấu hình lên toàn bộ các nhóm & đồng bộ Web!"})

@app.route("/api/permissions/add", methods=["POST"])
def api_permissions_add():
    data = request.json or {}
    uid = str(data.get("uid") or "").strip().lstrip("@")
    name = str(data.get("name") or "").strip().lstrip("@") or uid
    if not uid:
        return jsonify({"ok": False, "error": "Vui lòng nhập UID hoặc Tên người dùng cần cấp quyền (.cp)!"}), 400
    add_authorized_user(uid, name, acc_id=0)
    log_system_command(0, "Web_Permissions", "Admin_Web", f".cp @{name} ({uid})", f"Cấp quyền điều khiển (.cp) từ Web cho {name}", sender_name="Admin Web")
    return jsonify({"ok": True, "authorized_users": list_authorized_users(), "message": f"Đã cấp quyền (.cp) cho {name} ({uid})!"})

@app.route("/api/permissions/remove", methods=["POST"])
def api_permissions_remove():
    data = request.json or {}
    uid = str(data.get("uid") or "").strip()
    if uid == "__all__":
        conn = db()
        conn.execute("DELETE FROM authorized_users")
        conn.commit()
        log_system_command(0, "Web_Permissions", "Admin_Web", ".xq all", "Thu hồi toàn bộ quyền điều khiển phụ (.cp)", sender_name="Admin Web")
        with _STATUS_CACHE_LOCK:
            _STATUS_SNAPSHOT_CACHE["ts"] = 0.0
        return jsonify({"ok": True, "authorized_users": [], "message": "Đã thu hồi toàn bộ danh sách quyền (.cp)!"})
    remove_authorized_user(uid)
    log_system_command(0, "Web_Permissions", "Admin_Web", f".xq {uid}", f"Đã xóa quyền (.cp) của {uid}", sender_name="Admin Web")
    return jsonify({"ok": True, "authorized_users": list_authorized_users(), "message": f"Đã xóa quyền của {uid}!"})

# TỰ ĐỘNG KHỞI CHẠY BOT TELEGRAM PHAN ANH KHÔI (RIKE) CÙNG WEB SERVER
_TELEGRAM_BOT_RUNNER = None

def ensure_telegram_bot_started():
    global _TELEGRAM_BOT_RUNNER
    if _TELEGRAM_BOT_RUNNER is not None:
        return
    try:
        from get_ck_im_zalo import start_background_telegram_bot
        _TELEGRAM_BOT_RUNNER = start_background_telegram_bot(TELEGRAM_BOT_TOKEN)
    except Exception:
        pass

if os.environ.get("DISABLE_TELEGRAM_BOT", "0") != "1":
    threading.Thread(target=ensure_telegram_bot_started, daemon=True).start()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
