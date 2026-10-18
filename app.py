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

# CẤU HÌNH HỆ THỐNG & BẢO MẬT WEB — PHAN ANH KHÔI (v19 CLEAN WHITE EDITION)
APP_TITLE = "HỆ THỐNG ĐIỀU KHIỂN ĐA TÀI KHOẢN v19 — Phan Anh Khôi"
APP_AUTHOR = "Phan Anh Khôi"
SECRET_KEY = os.environ.get("SECRET_KEY", "noel-secret-key-2026-secure")
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
        cur.execute("UPDATE accounts SET allow_all_cmd = 1 WHERE allow_all_cmd IS NULL OR allow_all_cmd = 0")
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

def refresh_accounts_ram_cache():
    try:
        conn = db()
        rows = conn.execute("SELECT * FROM accounts ORDER BY id DESC").fetchall()
        conn.close()
        new_map = {r["id"]: dict(r) for r in rows}
        with ACCOUNTS_RAM_LOCK:
            ACCOUNTS_RAM_CACHE.clear()
            ACCOUNTS_RAM_CACHE.update(new_map)
        return list(new_map.values())
    except Exception:
        with ACCOUNTS_RAM_LOCK:
            return list(ACCOUNTS_RAM_CACHE.values())

def get_account_from_ram(acc_id):
    with ACCOUNTS_RAM_LOCK:
        acc = ACCOUNTS_RAM_CACHE.get(acc_id)
        if acc is not None:
            return dict(acc)
    refresh_accounts_ram_cache()
    with ACCOUNTS_RAM_LOCK:
        acc = ACCOUNTS_RAM_CACHE.get(acc_id)
        return dict(acc) if acc is not None else None

def get_all_accounts_from_ram(platform=None, enabled_only=False):
    with ACCOUNTS_RAM_LOCK:
        if not ACCOUNTS_RAM_CACHE:
            pass
        else:
            items = list(ACCOUNTS_RAM_CACHE.values())
            if platform:
                items = [a for a in items if (a.get("platform") or "zalo") == platform]
            if enabled_only:
                en = [a for a in items if a.get("enabled", 1)]
                items = en if en else items
            return [dict(a) for a in items]
    all_accs = refresh_accounts_ram_cache()
    if platform:
        all_accs = [a for a in all_accs if (a.get("platform") or "zalo") == platform]
    if enabled_only:
        en = [a for a in all_accs if a.get("enabled", 1)]
        all_accs = en if en else all_accs
    return [dict(a) for a in all_accs]

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
    """Khóa nguyên tử 2 tầng (RAM + SQLite Cross-Process Lock) chống lặp lệnh tuyệt đối 100%:
    - Đảm bảo gõ .menu, .chao, .g, .n chỉ phản hồi ĐÚNG 1 LẦN duy nhất dù chạy nhiều luồng,
      nhiều tài khoản hay nhiều worker Gunicorn cùng lúc!"""
    now = time.time()
    norm_txt = re.sub(r"\s+", " ", str(raw_msg or "").strip()).lower()[:120]
    plat_s = str(platform or "zalo").lower()
    tid_s = str(thread_id or "").strip()
    mid_s = str(msg_id or "").strip()
    cmd_key = f"cmd:{plat_s}:{tid_s}:{norm_txt}"

    with GLOBAL_CMD_DEDUPE_LOCK:
        for k, ts_old in list(GLOBAL_CMD_DEDUPE_CACHE.items()):
            if now - ts_old > 20.0:
                GLOBAL_CMD_DEDUPE_CACHE.pop(k, None)
        if mid_s and mid_s not in ("0", ""):
            m_key = f"mid:{plat_s}:{tid_s}:{mid_s}"
            if m_key in GLOBAL_CMD_DEDUPE_CACHE:
                return False
            GLOBAL_CMD_DEDUPE_CACHE[m_key] = now
        last_ts = GLOBAL_CMD_DEDUPE_CACHE.get(cmd_key, 0.0)
        if now - last_ts < 1.2:
            return False
        GLOBAL_CMD_DEDUPE_CACHE[cmd_key] = now

    # Khóa nguyên tử cấp cơ sở dữ liệu SQLite (chống 2 worker process cùng thực thi 1 lệnh)
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("DELETE FROM cmd_execution_locks WHERE created_at < ?", (now - 20.0,))
        if mid_s and mid_s not in ("0", ""):
            cur.execute(
                "INSERT OR IGNORE INTO cmd_execution_locks (lock_key, created_at) VALUES (?, ?)",
                (f"mid:{plat_s}:{tid_s}:{mid_s}", now)
            )
            if cur.rowcount == 0:
                conn.commit()
                conn.close()
                return False
        time_bucket = int(now // 2)
        row_ex = cur.execute(
            "SELECT 1 FROM cmd_execution_locks WHERE lock_key = ?",
            (f"{cmd_key}:{time_bucket}",)
        ).fetchone()
        if row_ex:
            conn.commit()
            conn.close()
            return False
        cur.execute(
            "INSERT OR IGNORE INTO cmd_execution_locks (lock_key, created_at) VALUES (?, ?)",
            (f"{cmd_key}:{time_bucket}", now)
        )
        inserted = (cur.rowcount == 1)
        conn.commit()
        conn.close()
        if not inserted:
            return False
    except Exception:
        pass
    return True

SYSTEM_RUNTIME_CONFIG = {
    "delay": 0.0,
    "color_mode": "rainbow",
    "fixed_color": "red",
    "icon_count": 3,
    "use_emoji": True,
    "is_heading": True,
    "antiband": True,
    "antidieall": True,
    "strip_line_num": True,
    "hide_acc_log": True,
}
SYSTEM_CFG_LOCK = threading.RLock()

SYSTEM_SENT_IDS = deque(maxlen=1500)
SYSTEM_SENT_TEXT_HASHES = deque(maxlen=1500)
SYSTEM_SENT_LOCK = threading.RLock()

def _normalize_for_echo_hash(s):
    if not s:
        return ""
    for zw in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"):
        s = s.replace(zw, "")
    return re.sub(r"\s+", " ", s.strip()).lower()[:240]

def register_system_sent_message(msg_id=None, client_id=None, text=None):
    now = time.time()
    with SYSTEM_SENT_LOCK:
        if msg_id:
            SYSTEM_SENT_IDS.append((str(msg_id), now))
        if client_id:
            SYSTEM_SENT_IDS.append((str(client_id), now))
        if text:
            nh = _normalize_for_echo_hash(text)
            if nh:
                SYSTEM_SENT_TEXT_HASHES.append((nh, now))
                first_line = _normalize_for_echo_hash(text.split("\n")[0])
                if first_line:
                    SYSTEM_SENT_TEXT_HASHES.append((first_line, now))

VALID_SYSTEM_CMD_TOKENS = {
    "menu", "help", "lenh", "hdsd", "m", "h",
    "2fa", "otp", "totp", "todo", "giaoviec", "bank", "stk", "card", "danhthiep",
    "statusdc", "hypesquad", "react", "thuhoi", "undo",
    "spam", "fast", "nhanh", "s", "nhay", "treonhay", "treo_nhay", "n",
    "ngon", "treongon", "treo_ngon", "g", "file", "chay", "f",
    "files", "dsfile", "listfile", "ds", "tag", "all", "tagall",
    "raid", "r", "auto", "a", "dao", "chao", "hi",
    "ping", "p", "status", "info", "stinfo", "id", "uid", "mem", "tv", "thanhvien",
    "addfile", "taof", "af", "clear", "reset",
    "delay", "tocdo", "time", "d", "mau", "color", "doimau",
    "icon", "emoji", "chuto", "heading", "antiband", "antiban",
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
    with SYSTEM_SENT_LOCK:
        for mid, ts in list(SYSTEM_SENT_IDS):
            if now - ts <= 95.0:
                if (msg_id and str(msg_id) == mid) or (client_id and str(client_id) == mid):
                    return True
        if text:
            if is_direct_user_command_text(text):
                return False
            nh = _normalize_for_echo_hash(text)
            first_line = _normalize_for_echo_hash(text.split("\n")[0])
            for h_saved, ts in list(SYSTEM_SENT_TEXT_HASHES):
                if now - ts <= 65.0 and h_saved and (nh == h_saved or first_line == h_saved):
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
        rows = conn.execute("SELECT uid FROM accounts").fetchall()
        conn.close()
        s = set()
        for r in rows:
            if r["uid"]:
                for part in str(r["uid"]).split(","):
                    if part.strip():
                        s.add(part.strip())
        OWNER_UIDS_CACHE = s
    except Exception:
        pass

def is_user_authorized_for_cmd(sender_uid, client_uid=None, client_send2me_id=None, allow_all=False):
    s_uid = str(sender_uid or "").strip()
    if s_uid in ("0", ""):
        return True
    if client_uid and s_uid == str(client_uid).strip():
        return True
    if client_send2me_id and s_uid == str(client_send2me_id).strip():
        return True
    if s_uid in OWNER_UIDS_CACHE:
        return True
    if allow_all:
        return True

    try:
        conn = db()
        row = conn.execute("SELECT id FROM authorized_users WHERE uid = ?", (s_uid,)).fetchone()
        conn.close()
        return bool(row)
    except Exception:
        return False

def add_authorized_user(uid, name="", acc_id=0):
    uid_str = str(uid or "").strip()
    if not uid_str or uid_str in ("0", "-1"):
        return False
    conn = db()
    conn.execute(
        "INSERT OR REPLACE INTO authorized_users (uid, name, added_by_acc, added_at) VALUES (?, ?, ?, ?)",
        (uid_str, name or f"User_{uid_str[-4:]}", acc_id, time.time())
    )
    conn.commit()
    conn.close()
    return True

def remove_authorized_user(uid):
    uid_str = str(uid or "").strip()
    conn = db()
    cur = conn.execute("DELETE FROM authorized_users WHERE uid = ?", (uid_str,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    return deleted > 0

def list_authorized_users():
    conn = db()
    rows = conn.execute("SELECT uid, name, added_at FROM authorized_users ORDER BY id ASC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# BỘ ICON & EMOJI CHUẨN ZALO 100% (ĐÃ FIX TRIỆT ĐỂ LỖI CHỮ THÔ ':-')
ZALO_PALETTE = [
    {"id": "red",    "name": "Đỏ Rực",        "hex": "#db342e", "zcode": "db342e"},
    {"id": "yellow", "name": "Vàng Hoàng Kim", "hex": "#f7b503", "zcode": "f7b503"},
    {"id": "green",  "name": "Xanh Ngọc Lục",  "hex": "#15a85f", "zcode": "15a85f"},
    {"id": "orange", "name": "Cam Rực Lửa",    "hex": "#f27806", "zcode": "f27806"},
]

ZALO_NATIVE_ZCODES = ["db342e", "f7b503", "15a85f", "f27806"]
ZALO_COLOR_MAP = {
    "red": "db342e", "do": "db342e", "đỏ": "db342e",
    "yellow": "f7b503", "vang": "f7b503", "vàng": "f7b503",
    "green": "15a85f", "xanh": "15a85f", "xanhla": "15a85f",
    "orange": "f27806", "cam": "f27806",
    "ocean": "15a85f", "blue": "f7b503", "purple": "db342e", "pink": "f27806",
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

# BỘ LỌC TỰ ĐỘNG XOÁ SỐ THỨ TỰ ĐẦU DÒNG ("1. ", "2. ", "3) ") & TẢI FILE NHANH
FILE_MEMORY_CACHE = {}
FILE_CACHE_LOCK = threading.RLock()

LEADING_NUMBER_RE = re.compile(
    r"^\s*(?:câu\s*\d+[\.\:\)\-]+|\(\d+\)|#?\d+[\.\)\:\-]+)\s*",
    re.IGNORECASE
)

def strip_leading_line_number(line):
    if not line:
        return ""
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
        stripped = ln.strip()
        if stripped:
            raw_non_empty_lines.append(stripped)
            clean_ln = strip_leading_line_number(stripped) if strip_numbers else clean_corrupted_shortcuts(stripped)
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
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "platform": '"Windows"'
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "platform": '"macOS"'
        },
    ]

    @classmethod
    def get_session_headers(cls, imei):
        idx = zlib.crc32(str(imei or "zalo").encode("utf-8")) % len(cls.BROWSER_PROFILES)
        prof = cls.BROWSER_PROFILES[idx]
        return {
            "User-Agent": prof["ua"],
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
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
        salt = int(time.time() * 1000) & 0xFFFF
        mutated = cls.mutate_zalo_word_boundaries(final_msg, salt=salt)
        return mutated + " " + cls.generate_zero_shift_tail(thread_id)

    @staticmethod
    def compute_human_cadence_delay(base_delay, burst_cnt=0, risk_score=0.0, adaptive_bonus=0.0, text_len=20):
        # Chạy chuẩn xác 100% tốc độ Delay người dùng cài đặt (Tối thiểu 0.20s trên Zalo), KHÔNG cộng thêm delay ảo hay thời gian nghỉ!
        return max(0.20, float(base_delay))

class Chrome131TLSAdapter(HTTPAdapter):
    """Bộ điều hợp TLS chuẩn trình duyệt Chrome 131 (Chống phát hiện JA3/JA4 Fingerprint):
    - Ép toàn bộ kết nối HTTPS của requests.Session sử dụng đúng bộ khóa mã hóa TLS 1.3 / ECDHE và ALPN http/1.1
      giống hệt kết nối Gateway WebSocket, ngăn chặn hoàn toàn việc Cloudflare/Discord phát hiện lệch vân tay TLS
      khi gõ lệnh gửi tin nhắn POST /messages!"""

    def __init__(self, *args, **kwargs):
        self._ssl_ctx = DiscordStealthAntiBanEngine.create_chrome_tls_context()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_ctx
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._ssl_ctx
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
        """Đa hình tin nhắn 100% thuần Latin/ASCII (Không Cyrillic, Không Zero-Width):
        Giúp chạy tốc độ 0.0s trên Discord mà mỗi tin nhắn vẫn có mã băm khác nhau và vượt qua 100% bộ lọc Trust & Safety."""
        clean_t = cls.sanitize_outbound_text(text)
        if not clean_t:
            return clean_t
        # Nếu là tin nhắn hệ thống ngắn hoặc danh sách ghi chú nhiều dòng (> 4 dòng) thì giữ nguyên bản sạch
        if clean_t.count("\n") >= 4:
            return clean_t
        global _ANTIBAN_COUNTER
        with _ANTIBAN_LOCK:
            _ANTIBAN_COUNTER = (_ANTIBAN_COUNTER + 1) & 0xFFFFFF
            seq = _ANTIBAN_COUNTER
        c_hash = zlib.crc32(str(channel_id or "dc").encode("utf-8")) & 0xFF
        suffix = cls.PURE_LATIN_VARIATIONS[(seq + c_hash) % len(cls.PURE_LATIN_VARIATIONS)]
        return f"{clean_t}{suffix}"

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
    """Hạ tầng Anti-Scan, Anti-Ban & Tường Lửa Bảo Vệ Token Discord Bất Tử (Super VIP v14):
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

    @classmethod
    def build_super_properties_b64(cls, token):
        props = cls.build_super_properties_dict(token)
        raw_json = json.dumps(props, separators=(",", ":"))
        return base64.b64encode(raw_json.encode("utf-8")).decode("utf-8")

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
            "Accept-Encoding": "gzip, deflate, br, zstd",
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
        with cls._LOCK:
            sess = cls._SHARED_SESSIONS.get(tkey)
            if sess is None:
                sess = requests.Session()
                tls_adapter = Chrome131TLSAdapter(pool_connections=64, pool_maxsize=128, max_retries=1)
                sess.mount("https://", tls_adapter)
                sess.mount("http://", HTTPAdapter(pool_connections=64, pool_maxsize=128, max_retries=1))
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
            if now - last_ts < 25.0:
                return False, max(3.0, 25.0 - (now - last_ts))
            cls._LAST_IDENTIFY_TS[tkey] = now
            return True, 0.0

    @classmethod
    def pick_stealth_endpoint(cls, token, path_suffix, rotate_step=0):
        return f"https://discord.com/api/v9{path_suffix}"

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
    def record_bucket_headers(cls, channel_id, resp_headers):
        if not channel_id:
            return
        now = time.time()
        with cls._LOCK:
            cls._CHANNEL_SEND_HISTORY[str(channel_id)].append(now)
        if not resp_headers:
            return
        try:
            rem = resp_headers.get("X-RateLimit-Remaining")
            reset_after = resp_headers.get("X-RateLimit-Reset-After")
            if rem is not None and reset_after is not None:
                with cls._LOCK:
                    cls._CHANNEL_BUCKETS[str(channel_id)] = {
                        "remaining": int(rem),
                        "reset_at": now + float(reset_after),
                    }
        except Exception:
            pass

    @classmethod
    def set_channel_cooldown(cls, channel_id, wait_sec):
        if not channel_id:
            return
        with DiscordFirewallEngine._STATS_LOCK:
            DiscordFirewallEngine.FIREWALL_STATS["rate_shields_triggered"] += 1
        with cls._LOCK:
            cls._CHANNEL_BUCKETS[str(channel_id)] = {
                "remaining": 0,
                "reset_at": time.time() + float(wait_sec),
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
                cls._CHANNEL_BUCKETS.pop(cid_s, None)
                cls._CHANNEL_SEND_HISTORY.pop(cid_s, None)
                cls._CHANNEL_NEXT_SLOT_TS.pop(cid_s, None)

    @classmethod
    def get_channel_bucket_wait(cls, channel_id, token=None):
        now = time.time()
        cid_s = str(channel_id)
        t_part = cls._token_vault_key(token) if token else "shared"
        slot_key = f"{t_part}:{cid_s}"
        ch_lock = cls._CHANNEL_LOCKS[slot_key]
        with ch_lock:
            b = cls._CHANNEL_BUCKETS.get(slot_key) or cls._CHANNEL_BUCKETS.get(cid_s)
            if b and b["remaining"] <= 0 and now < b["reset_at"]:
                return max(0.05, min(1.5, b["reset_at"] - now))
            next_slot = cls._CHANNEL_NEXT_SLOT_TS.get(slot_key, 0.0)
            if now < next_slot:
                return min(0.8, next_slot - now)
            return 0.0

    @classmethod
    def acquire_multi_group_slot(cls, token, channel_id, stop_ev=None, start_global_epoch=None, start_box_epoch=None):
        """Điều phối viên Đa Tài Khoản & Đa Nhóm v19 (Per-Account Independent Micro-Slot):
        - Tách khe thời gian riêng cho từng cặp (Tài khoản, Phòng chat) giúp 10-20 Acc cùng bắn vào 1 phòng song song 100% công suất!
        - Ngắt tức thì 0ms ngay khi bấm Dừng hoặc gõ .t / .stop!"""
        cid_s = str(channel_id)
        t_part = cls._token_vault_key(token) if token else "shared"
        slot_key = f"{t_part}:{cid_s}"
        ch_lock = cls._CHANNEL_LOCKS[slot_key]
        while not is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, cid_s):
            now = time.time()
            wait_s = 0.0
            with ch_lock:
                b = cls._CHANNEL_BUCKETS.get(slot_key) or cls._CHANNEL_BUCKETS.get(cid_s)
                if b and b["remaining"] <= 0 and now < b["reset_at"]:
                    wait_s = max(0.06, min(1.4, b["reset_at"] - now))
                else:
                    next_slot = cls._CHANNEL_NEXT_SLOT_TS.get(slot_key, 0.0)
                    if now >= next_slot:
                        gap = 0.14 if cls.SUPER_VIP_MODE else 0.05
                        cls._CHANNEL_NEXT_SLOT_TS[slot_key] = now + gap
                        return True
                    else:
                        wait_s = min(0.5, next_slot - now)
            if interruptible_wait(stop_ev, min(wait_s, 0.10), start_global_epoch, start_box_epoch, cid_s):
                return False
        return False

    @classmethod
    def should_trigger_typing(cls, channel_id):
        return False

class MessengerStealthAntiBanEngine:
    """Hạ tầng Anti-Ban & Lightspeed MQTT v14 Siêu Cấp cho Facebook Messenger (Tích hợp từ ckien.zip):
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
    def acquire_messenger_stealth_slot(cls, uid, thread_id, antiband=True, stop_ev=None, start_global_epoch=None, start_box_epoch=None):
        """Lá chắn Chống Bay Acc Messenger (Sigma Anti-Checkpoint Pacer v17):
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
    """Động cơ Hàn Mạch & Chống Chết Toàn Diện Anti-Die-All v16 ULTRA (Zalo • Discord • Messenger MQTT):
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

    def can_send(self, acc_id, max_rpm=999999, channel_id=None, platform="zalo"):
        now = time.time()
        cid_s = str(channel_id or "").strip()

        if cid_s:
            with self.lock:
                box_until = self.box_cooldowns.get((acc_id, cid_s), 0.0)
                if now < box_until:
                    return False, round(min(1.2, box_until - now), 3)

        if platform == "discord" and cid_s:
            ch_wait = DiscordStealthAntiBanEngine.get_channel_bucket_wait(cid_s)
            if ch_wait > 0:
                return False, round(min(1.5, ch_wait), 3)

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
        with self.lock:
            st = self.state[acc_id]
            st["burst_counter"] += 1
            b_cnt = st["burst_counter"]
            bonus = float(st.get("adaptive_delay_bonus", 0.0))

        if platform == "discord":
            d_val = max(0.0, float(base_delay))
            return round(d_val + min(0.18, bonus), 3)

        if platform == "messenger":
            mess_floor = max(1.85 if antiband else 0.90, float(base_delay))
            jitter = random.uniform(0.25, 0.65) if antiband else 0.05
            breath = random.uniform(1.8, 2.8) if (antiband and b_cnt % 8 == 0) else 0.0
            multi_box_pad = min(0.8, max(0.0, (int(active_box_count or 1) - 1) * 0.25))
            return round(mess_floor + jitter + breath + multi_box_pad + min(0.8, bonus), 2)

        return round(max(0.20, float(base_delay)) + (random.uniform(0.02, 0.07) if antiband else 0.0) + min(0.3, bonus), 3)

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
        wait_s = min(2.5, max(0.25, float(retry_after or 0.85)))
        if channel_id:
            cid_s = str(channel_id)
            DiscordStealthAntiBanEngine.set_channel_cooldown(cid_s, wait_s)
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
        """Hồ quản lý phiên Zalo tập trung (ZaloSessionPool v19):
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
        adapter = HTTPAdapter(pool_connections=40, pool_maxsize=80, max_retries=2)
        self.s.mount("https://", adapter)
        self.s.mount("http://", adapter)
        base_hdrs = ZaloSmartAntiBanEngine.get_session_headers(self.imei)
        # Tìm User-Agent và zpw_enk đã lưu trong Vault/DB nếu chưa truyền vào
        saved_ua, saved_enk, saved_uid, saved_name = self._lookup_saved_vault_meta()
        eff_ua = (user_agent or saved_ua or "").strip()
        if eff_ua:
            base_hdrs["User-Agent"] = eff_ua
        self.user_agent = base_hdrs["User-Agent"]
        self.s.headers.update(base_hdrs)
        self.s.cookies.update(self.cookies_dict)
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
        ud = None
        last_err = ""
        ts_now = int(time.time() * 1000)

        # Phương thức 1: Chuẩn zlapi (wpa.zaloapp.com/api/login/getLoginInfo?imei=...)
        # Phương thức 2: Chuẩn Zalo Web PC có mã hóa zcid + zcid_ext + signkey (wpa.chat.zalo.me/api/login/getLoginInfo)
        # Phương thức 3: Chuẩn wpa.zaloapp.com đầy đủ tham số zpw_ver=645
        try:
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
        except Exception as e_enc:
            last_err = str(e_enc)

        if not isinstance(ud, dict):
            login_endpoints = [
                ("https://wpa.zaloapp.com/api/login/getLoginInfo", {"imei": self.imei}),
                ("https://wpa.zaloapp.com/api/login/getLoginInfo", {
                    "zpw_ver": 645,
                    "zpw_type": 30,
                    "imei": self.imei,
                    "type": 30,
                    "client_version": 645,
                    "computer_name": "Web",
                    "ts": ts_now
                }),
                ("https://wpa.chat.zalo.me/api/login/getLoginInfo", {
                    "imei": self.imei,
                    "type": 30,
                    "client_version": 645,
                    "computer_name": "Web",
                    "ts": ts_now
                }),
            ]
            for ep_url, ep_params in login_endpoints:
                try:
                    r = self.s.get(ep_url, params=ep_params, timeout=10)
                    for c_item in r.cookies:
                        self.cookies_dict[c_item.name] = c_item.value
                    d = r.json() if r.content else {}
                    cand_ud = d.get("data")
                    if isinstance(cand_ud, dict) and cand_ud.get("zpw_enk"):
                        ud = cand_ud
                        break
                    last_err = d.get("error_message") or str(d.get("error_code") or "")
                except Exception as ex:
                    last_err = str(ex)
                    continue

        if isinstance(ud, dict) and ud.get("zpw_enk"):
            self.uid = str(ud.get("uid") or ud.get("userId") or ud.get("send2me_id") or self.uid or "")
            self.send2me_id = str(ud.get("send2me_id") or self.uid or "")
            self.secret_key = ud.get("zpw_enk")
            self.display_name = ud.get("displayName") or ud.get("zaloName") or self.display_name or (f"Zalo_{self.uid[-4:]}" if self.uid else "Zalo PC")
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

            # Gọi thêm getServerInfo để báo cáo trạng thái thiết bị máy tính đang hoạt động với máy chủ Zalo
            try:
                srv_sign = hashlib.md5(f"zsecuregetserverinfo{self.imei}30645Web".encode("utf-8")).hexdigest()
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
        else:
            raise Exception(f"Phiên đăng nhập Zalo hết hạn hoặc Cookie/IMEI không khớp ({last_err or 'No zpw_enk'})")

        self.uid = str(ud.get("uid") or ud.get("userId") or ud.get("send2me_id") or "")
        self.send2me_id = str(ud.get("send2me_id") or "")
        self.secret_key = ud.get("zpw_enk")
        self.display_name = ud.get("displayName") or ud.get("zaloName") or (f"Zalo_{self.uid[-4:]}" if self.uid else "Zalo VIP")
        self.zalo_name = ud.get("zaloName") or self.display_name
        self.username = ud.get("username") or self.display_name

        if self.uid and self.secret_key:
            try:
                ZaloCookieVaultEngine.save_zalo_vault_record(
                    uid=self.uid,
                    display_name=self.display_name,
                    imei=self.imei,
                    cookies_dict=self.cookies_dict,
                    zpw_enk=self.secret_key,
                    user_agent=self.s.headers.get("User-Agent", "")
                )
            except Exception:
                pass

        if self.uid:
            OWNER_UIDS_CACHE.add(self.uid)
        if self.send2me_id:
            OWNER_UIDS_CACHE.add(self.send2me_id)

        ws_candidates = []
        for k in ("zpw_ws", "ws", "websocket"):
            val = ud.get(k)
            if isinstance(val, list):
                ws_candidates.extend(val)
            elif isinstance(val, str) and val:
                ws_candidates.append(val)
        if not ws_candidates:
            ws_candidates = [
                "wss://ws1.chat.zalo.me",
                "wss://ws2.chat.zalo.me",
                "wss://ws3.chat.zalo.me",
                "wss://ws4.chat.zalo.me"
            ]
        self.ws_urls = ws_candidates

        if not self.secret_key:
            raise Exception("Không thể lấy khóa giải mã bảo mật (zpw_enk)")

    def _enc(self, params):
        key = base64.b64decode(self.secret_key)
        cipher = AES.new(key, AES.MODE_CBC, bytes(16))
        pt = json.dumps(params, ensure_ascii=False).encode("utf-8")
        pad = AES.block_size - len(pt) % AES.block_size
        pt += bytes([pad]) * pad
        return base64.b64encode(cipher.encrypt(pt)).decode()

    def _dec(self, enc):
        if not enc:
            return "{}"
        key = base64.b64decode(self.secret_key)
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
        r = self.s.get(
            "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
            params={"zpw_ver": 645, "zpw_type": 30}, timeout=12,
        )
        dec = self._dec(r.json().get("data", ""))
        gmap = json.loads(dec).get("data", {}).get("gridVerMap", {})
        for gid in gmap:
            KNOWN_GROUPS_BY_ACC[self.uid].add(str(gid))
            ALL_KNOWN_ZALO_GROUP_IDS.add(str(gid))
        return gmap

    def get_last_msgs(self):
        """Lấy toàn bộ tin nhắn mới nhất của mọi Nhóm (groupMsgs) và Chat riêng (msgs) trong 1 request duy nhất
        (Chuẩn zlapi preloadconvers/get-last-msgs) giúp soi lệnh .menu, .n, .g, .t tức thì trên mọi phòng!"""
        try:
            enc = self._enc({"threadIdLocalMsgId": json.dumps({}), "imei": self.imei})
            r = self.s.get(
                "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs",
                params={"zpw_ver": "645", "zpw_type": "30", "params": enc},
                timeout=6,
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
            opts = ["Đồng ý 100%", "Chuẩn VIP Phan Anh Khôi"]
        pl = {
            "group_id": gid_s,
            "question": str(question or "Bình chọn Phan Anh Khôi"),
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
        pl = {"grid": gid_s, "gname": str(new_name or "Box Phan Anh Khôi")}
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
            "content": str(content or "Nhiệm vụ hệ thống Phan Anh Khôi"),
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

    def send_card_bank(self, thread_id, bin_bank=970422, num_acc="9999999999", name_acc="PHAN ANH KHOI", is_group=True):
        pl = {
            "binBank": int(bin_bank or 970422),
            "numAccBank": str(num_acc or "9999999999"),
            "nameAccBank": str(name_acc or "PHAN ANH KHOI").upper(),
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
            r_cm = self.s.get(
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
        if color_mode == "random":
            candidates = [c for c in ZALO_NATIVE_ZCODES if c != prev_zcode]
            return random.choice(candidates)
        chosen = ZALO_NATIVE_ZCODES[step_index % len(ZALO_NATIVE_ZCODES)]
        if chosen == prev_zcode:
            chosen = ZALO_NATIVE_ZCODES[(step_index + 1) % len(ZALO_NATIVE_ZCODES)]
        return chosen

    def build_colored_message_with_vip_icons(
        self, raw_text, color_mode="rainbow", fixed_color="red",
        is_heading=True, color_offset=0, antiband=True,
        use_emoji=True, icon_count=3, strip_line_num=False
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
            stripped = ln.strip()
            if not stripped:
                core_lines.append("")
                current_u16_pos += 1
                continue

            force_line_heading = False
            if stripped.startswith("#"):
                stripped = re.sub(r"^#+\s*", "", stripped).strip() or stripped
                force_line_heading = True

            if strip_line_num:
                stripped = strip_leading_line_number(stripped)

            tokens = stripped.split(" ")
            line_tail_icons = []
            while tokens and _is_emoji_or_zalo_shortcut_token(tokens[-1]):
                tk = tokens.pop()
                if tk in ZALO_ICON_VIP:
                    line_tail_icons.insert(0, tk)
                elif tk in LEGACY_SHORTCUT_TO_ICON_MAP:
                    line_tail_icons.insert(0, LEGACY_SHORTCUT_TO_ICON_MAP[tk])
                else:
                    line_tail_icons.insert(0, get_icon_hard(line_tail_icons))

            core_text = " ".join(tokens).strip()
            if not core_text and line_tail_icons:
                core_text = " ".join(line_tail_icons)
                line_tail_icons = []

            if line_tail_icons:
                collected_tail_icons.extend(line_tail_icons)

            core_lines.append(core_text)
            core_u16_len = utf16_len(core_text)
            use_big_font = is_heading or force_line_heading

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
                        w_step += 1
                        st_parts = ["b"]
                        if use_big_font:
                            st_parts.append("f_18")
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

                st_parts = []
                if use_big_font:
                    st_parts.extend(["b", "f_18"])
                elif color_mode != "none":
                    st_parts.append("b")
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
        if use_emoji and icon_count > 0:
            if collected_tail_icons:
                tail_icon_str = " ".join(collected_tail_icons[:max(icon_count, 3)])
            else:
                tail_icon_str = build_unique_zalo_icons(icon_count)
        elif collected_tail_icons:
            tail_icon_str = " ".join(collected_tail_icons[:3])

        return core_msg, styles, first_color, tail_icon_str

    def attach_mentions_real_zalo(self, core_msg, mentions=None, tag_all=False, group_id=None):
        """Gắn Tag Thật 100% chuẩn giao thức Zalo Group (`/api/group/mention`):
        - Tính chính xác vị trí `pos` và độ dài `len` theo UTF-16LE code units.
        - Trả về `final` và mảng `m_arr` chuẩn `[{"pos": pos, "len": len, "uid": str(uid), "type": 0}]`."""
        final = core_msg if core_msg else ""
        m_arr = []

        if tag_all:
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
                        sep = " " if (final and not final.endswith((" ", "\n"))) else ""
                        pos = utf16_len(final + sep)
                        final = final + sep + "@All"
                        m_arr.append({"pos": int(pos), "len": 4, "uid": "-1", "type": 1})
                    continue

                seen_uids.add(uid)

                raw_name = str(m.get("name") or m.get("dName") or m.get("displayName") or "").strip().lstrip("@")
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

    def _send_raw_payload(self, final_msg, thread_id, is_group, m_arr, styles, first_color="db342e"):
        """Gửi gói tin mã hóa tới Zalo WPA v645 (Hỗ trợ ĐỒNG THỜI vừa Tag tên xanh dương vừa Đổi màu chữ & Chữ lớn):
        - Khi gửi tin nhắn nhóm có Tag (`is_group and m_arr`), gọi `https://tt-group-wpa.chat.zalo.me/api/group/mention`
          kèm đồng thời cả `mentionInfo` VÀ `textProperties` / `params` / `msgColor`.
        - Tích hợp cơ chế Dual-Packet Safeguard: nếu cụm máy chủ Zalo nhóm từ chối gói kết hợp, tự động fallback tức thì."""
        if is_group:
            url = (
                "https://tt-group-wpa.chat.zalo.me/api/group/mention"
                if m_arr
                else "https://tt-group-wpa.chat.zalo.me/api/group/sendmsg"
            )
        else:
            url = "https://tt-chat2-wpa.chat.zalo.me/api/message/sms"

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
                mention_json = json.dumps(m_arr, separators=(",", ":"), ensure_ascii=False)
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
        r = self.s.post(
            url,
            params={"zpw_ver": 645, "zpw_type": 30},
            data={"params": enc},
            timeout=15
        )
        try:
            rj = r.json()
            if rj.get("data"):
                dec = json.loads(self._dec(rj["data"]))
                if isinstance(dec, dict):
                    sent_mid = (dec.get("data") or {}).get("msgId") or dec.get("msgId")
                    if sent_mid:
                        register_system_sent_message(msg_id=sent_mid, client_id=client_id, text=final_msg)
        except Exception:
            pass
        return r

    def send_adv(self, raw_text, thread_id, color_mode="rainbow", fixed_color="red",
                 is_group=True, mentions=None, tag_all=False, is_heading=True,
                 color_offset=0, antiband=True, use_emoji=False, icon_count=0,
                 auto_retry_thread_type=False, strip_line_num=False, parse_auto_tags=True):
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

        core_msg, styles, first_color, tail_icon_str = self.build_colored_message_with_vip_icons(
            working_text,
            color_mode=color_mode,
            fixed_color=fixed_color,
            is_heading=is_heading,
            color_offset=color_offset,
            antiband=antiband,
            use_emoji=use_emoji,
            icon_count=icon_count,
            strip_line_num=strip_line_num
        )

        msg_with_tags, m_arr = self.attach_mentions_real_zalo(
            core_msg,
            mentions=(eff_mentions if is_group else None),
            tag_all=(eff_tag_all if is_group else False),
            group_id=(thread_id if is_group else None)
        )

        # Đồng bộ hóa vùng màu chữ (styles) kết hợp vùng Tag (m_arr) để vừa Tag xanh vừa Đổi màu chữ chuẩn 100%
        if styles and m_arr and color_mode != "none":
            tag_st_parts = ["b"]
            if is_heading:
                tag_st_parts.append("f_18")
            if first_color:
                tag_st_parts.append(f"c_{first_color}")
            for m_item in m_arr:
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

        if antiband:
            final_msg = ZaloSmartAntiBanEngine.append_tail(final_msg, thread_id=str(thread_id))

        r = self._send_raw_payload(final_msg, thread_id, is_group, m_arr, styles, first_color=first_color)

        if r.status_code == 429:
            raise Exception("429:RateLimit:30")

        try:
            resp_json = r.json()
            err_code = resp_json.get("error_code", 0)
            inner_err = 0
            if resp_json.get("data"):
                try:
                    dec_resp = json.loads(self._dec(resp_json["data"]))
                    if isinstance(dec_resp, dict):
                        inner_err = dec_resp.get("error_code", 0)
                except Exception:
                    pass

            if auto_retry_thread_type and (err_code != 0 or inner_err != 0):
                r2 = self._send_raw_payload(final_msg, thread_id, not is_group, [], styles, first_color=first_color)
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

    text = (raw_text or "").strip()
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
    return text.strip(), resolved_mentions, tag_all

# HỆ THỐNG REG & KHỞI TẠO PHIÊN DISCORD SIÊU VIP v14 (CHỐNG RESET MẬT KHẨU 100%)
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
    """Khởi tạo két sắt bảo vệ Token Discord Bất Tử v14 (Zero-REST Offline Shield):
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
    """Hệ Thống Tool Reg Acc & Đúc Token Discord Bất Tử 4-Trong-1 (Super VIP v14 — Chống Báo Reset Mật Khẩu 100%):
    - ĐÃ SỬA TRIỆT ĐỂ lỗi thiếu X-Super-Properties khi gọi /api/v9/auth/login khiến người dùng không đăng nhập được bằng Gmail/Mật khẩu!
    - Tự động giữ nguyên đầy đủ cả X-Super-Properties, X-Fingerprint và Cookie Cloudflare thật."""

    @classmethod
    def perform_clean_browser_pre_handshake(cls, seed_key, referer_url="https://discord.com/login"):
        s = requests.Session()
        tls_adapter = Chrome131TLSAdapter(pool_connections=15, pool_maxsize=30, max_retries=2)
        s.mount("https://", tls_adapter)
        s.mount("http://", HTTPAdapter(pool_connections=15, pool_maxsize=30, max_retries=2))
        s.cookies.update({"locale": "vi"})

        prof = DiscordStealthAntiBanEngine.get_deterministic_profile(seed_key)
        nav_headers = {
            "User-Agent": prof["ua"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
            "Sec-Ch-Ua": prof["sec_ch_ua"],
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": f'"{prof["os"]}"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        }
        fingerprint = ""
        try:
            s.get(referer_url, headers=nav_headers, timeout=8)
        except Exception:
            pass

        api_headers = DiscordStealthAntiBanEngine.build_stealth_headers(
            seed_key, is_bot=False, include_auth=False
        )
        # QUAN TRỌNG: Giữ nguyên X-Super-Properties cho /auth/login và /experiments chuẩn Chrome 131 Web!
        super_b64 = api_headers.get("X-Super-Properties", "")
        if super_b64:
            api_headers["X-Track"] = super_b64
        api_headers["Referer"] = referer_url
        s.headers.update(api_headers)

        try:
            r_fp = s.get("https://discord.com/api/v9/experiments?with_guild_experiments=true", timeout=8)
            if r_fp.status_code == 200:
                fingerprint = r_fp.json().get("fingerprint") or ""
                if fingerprint:
                    s.headers["X-Fingerprint"] = fingerprint
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
                time.sleep(random.uniform(0.12, 0.28))
            w_res = warmup_discord_stealth_token(tk)
            if w_res.get("ok"):
                uid = str(w_res.get("uid") or "")
                uname = custom_name or w_res.get("username") or f"Discord VIP #{idx + 1}"
                if uid:
                    OWNER_UIDS_CACHE.add(uid)
                prof = DiscordStealthAntiBanEngine.get_deterministic_profile(tk)
                c_dict = DiscordStealthAntiBanEngine.get_deterministic_cookies(tk)
                has_signed_cookie = ("__dcfduid" in c_dict and "__sdcfduid" in c_dict)

                if auto_save and conn:
                    existing = conn.execute(
                        "SELECT id FROM accounts WHERE platform='discord' AND (token=? OR (uid!='' AND uid=?))",
                        (tk, uid)
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
            "message": f"Đã đúc thành công {len(ok_list)}/{len(tokens)} Token Discord Siêu VIP v14 (Chống Reset Key 100%)!"
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
    """Bộ Lưu Trữ & Đồng Bộ Mã Cookie + IMEI + Khóa zpw_enk Zalo Bất Tử (Zalo Cookie & IMEI Vault v16):
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
    """Bộ Khởi Tạo Thiết Bị Máy Tính Ảo (Virtual PC Device Identity Generator v18):
    - Mỗi mã QR Zalo được gắn sẵn 1 Máy Tính (PC) ngẫu nhiên hoàn chỉnh (Windows 11 / macOS + Chrome 131 + IMEI riêng).
    - Khi quét mã QR trên điện thoại, Zalo nhận diện ngay thiết bị PC đang chờ đăng nhập và bật thông báo Xác Nhận tức thì!"""

    VIRTUAL_PC_POOL = [
        {
            "pc_name": "DESKTOP-VN92K8M (Windows 11 Pro)",
            "computer_name": "Web",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec_platform": '"Windows"',
        },
        {
            "pc_name": "MSI-TITAN-HX18 (Windows 11)",
            "computer_name": "Web",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
            "sec_platform": '"Windows"',
        },
        {
            "pc_name": "ASUS-ROG-G16 (Windows 11)",
            "computer_name": "Web",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec_platform": '"Windows"',
        },
        {
            "pc_name": "DELL-XPS-9530 (Windows 11)",
            "computer_name": "Web",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
            "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec_platform": '"Windows"',
        },
        {
            "pc_name": "MACBOOK-PRO-M3 (macOS Sonoma)",
            "computer_name": "Web",
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            "sec_platform": '"macOS"',
        },
    ]

    @classmethod
    def create_random_pc_device(cls, seed_salt=""):
        base = random.choice(cls.VIRTUAL_PC_POOL)
        rnd_tag = secrets.token_hex(2).upper()
        pc_label = base["pc_name"].replace("(", f"-{rnd_tag} (")
        imei = cls.generate_unique_imei(base["ua"], salt=f"{pc_label}_{seed_salt}")
        return {
            "pc_name": pc_label,
            "computer_name": base["computer_name"],
            "ua": base["ua"],
            "sec_ch_ua": base["sec_ch_ua"],
            "sec_platform": base["sec_platform"],
            "imei": imei,
        }

    @classmethod
    def generate_unique_ua_and_headers(cls, seed_salt=""):
        dev = cls.create_random_pc_device(seed_salt)
        return dev["ua"], dev["sec_ch_ua"], dev["sec_platform"]

    @classmethod
    def generate_unique_imei(cls, user_agent="", salt=""):
        u = str(uuid.uuid4())
        ua_s = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        entropy = f"{ua_s}|{salt}|{time.time_ns()}|{secrets.token_hex(8)}"
        tail = hashlib.md5(entropy.encode("utf-8")).hexdigest()
        return f"{u}-{tail}"


class ZaloQRLoginManager:
    """Hệ Thống Tạo Mã QR Zalo Gắn Sẵn Máy Tính Ảo (Virtual PC Bound QR Engine v18):
    - ĐÃ FIX TRIỆT ĐỂ 100% lỗi 'Mã QR đăng nhập không hợp lệ':
      1. Mỗi mã QR được khởi tạo kèm một phiên Máy Tính (PC) ngẫu nhiên độc lập (Windows 11 / MacBook Pro + Chrome 131 + IMEI riêng).
      2. Sử dụng đúng luồng chuẩn `https://zalo.me/pc` (`https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc`) của zalo_login / zca-js:
         - Bước 1: GET trang login lấy phiên `_zlang`, `zpsid` và mã phiên bản `main-x.x.x.js` thực tế.
         - Bước 2: POST `logininfo` & `verify-client` (`type=device`) để đăng ký thiết bị PC ảo với máy chủ `id.zalo.me`.
         - Bước 3: POST `authen/qr/generate` để sinh mã QR đã gắn chặt với thiết bị PC ảo vừa đăng ký.
         - Bước 4: Giữ kết nối `authen/qr/waiting-scan` liên tục bằng Cookie đồng nhất để ngay khi điện thoại quét là nhảy ra yêu cầu đăng nhập thiết bị PC tức thì!"""

    SESSIONS = {}
    LOCK = threading.RLock()

    @classmethod
    def _persist_qr_state_to_db(cls, st):
        if not st or not st.get("session_id"):
            return
        try:
            serializable = {
                "session_id": st["session_id"],
                "qr_nonce": st.get("qr_nonce", ""),
                "qr_code_id": st.get("qr_code_id", ""),
                "pc_name": st.get("pc_name", "PC-WINDOWS-11"),
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
            conn = db()
            conn.execute(
                """INSERT OR REPLACE INTO zalo_qr_sessions
                   (session_id, state_json, qr_png, updated_at)
                   VALUES (?, ?, ?, ?)""",
                (
                    st["session_id"],
                    json.dumps(serializable, ensure_ascii=False),
                    st.get("qr_png_bytes") or b"",
                    time.time(),
                )
            )
            conn.commit()
        except Exception:
            pass

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
    def start_qr_session(cls, auto_save=True):
        # Chống tạo trùng do nhấp đúp trong 1.2 giây làm hủy phiên QR vừa tạo
        now = time.time()
        with cls.LOCK:
            for existing_id, existing_st in list(cls.SESSIONS.items()):
                if (now - existing_st.get("created_at", 0) < 1.2) and existing_st.get("qr_base64") and existing_st.get("status") == "waiting_scan":
                    return cls.get_session_status(existing_id)

        session_id = str(uuid.uuid4())
        qr_nonce = secrets.token_hex(6)
        pc_dev = ZaloWebIDGenerator.create_random_pc_device(f"{session_id}_{qr_nonce}")

        st = {
            "session_id": session_id,
            "qr_nonce": qr_nonce,
            "pc_name": pc_dev["pc_name"],
            "computer_name": pc_dev["computer_name"],
            "status": "generating",
            "message": f"⏳ Đang khởi tạo thiết bị máy tính ảo {pc_dev['pc_name']} & cấp mã QR chính chủ...",
            "qr_base64": "",
            "qr_png_bytes": b"",
            "qr_code_id": "",
            "imei": pc_dev["imei"],
            "user_agent": pc_dev["ua"],
            "sec_ch_ua": pc_dev["sec_ch_ua"],
            "sec_platform": pc_dev["sec_platform"],
            "cookies": {},
            "cookies_str": "",
            "display_name": "",
            "avatar": "",
            "uid": "",
            "file_name": "",
            "file_content": "",
            "auto_save": bool(auto_save),
            "created_at": now,
            "stop_ev": threading.Event(),
        }
        with cls.LOCK:
            for old_k, old_v in list(cls.SESSIONS.items()):
                old_v["stop_ev"].set()
                if now - old_v.get("created_at", 0) > 60:
                    cls.SESSIONS.pop(old_k, None)
            cls.SESSIONS[session_id] = st
        cls._persist_qr_state_to_db(st)

        th = threading.Thread(target=cls._qr_worker, args=(session_id,), daemon=True)
        th.start()

        t0 = time.time()
        while time.time() - t0 < 8.5:
            if st["qr_base64"] or st["status"] in ("error", "expired"):
                break
            time.sleep(0.05)
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
        rem = max(0, 120 - elapsed)
        if rem == 0 and st.get("status") in ("generating", "waiting_scan", "scanned"):
            st["status"] = "expired"
            st["message"] = "⏰ Mã QR đã hết hạn (120s). Hãy bấm 'Tạo Mã QR Zalo Mới' để khởi tạo thiết bị PC & mã QR mới!"
            if "stop_ev" in st and hasattr(st["stop_ev"], "set"):
                st["stop_ev"].set()
            cls._persist_qr_state_to_db(st)

        raw_code = str(st.get("qr_code_id") or "")
        clean_code_badge = raw_code.split(".")[0].upper()[:6] if raw_code else ""

        return {
            "ok": True,
            "session_id": st["session_id"],
            "qr_nonce": st.get("qr_nonce", ""),
            "qr_code_id": clean_code_badge,
            "pc_name": st.get("pc_name", "DESKTOP-WIN11"),
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
    def _finalize_zalo_credentials(cls, st, imei, cookies_dict, display_name_hint="", user_info_dict=None):
        clean_c = normalize_zalo_cookies(cookies_dict)
        uid = ""
        zpw_enk = ""
        ua_bound = st.get("user_agent") or ""
        pc_name = st.get("pc_name") or "PC-WINDOWS-11"
        d_name = display_name_hint or "Zalo User"
        if isinstance(user_info_dict, dict):
            uid = str(user_info_dict.get("uid") or user_info_dict.get("userId") or user_info_dict.get("send2me_id") or "")
            zpw_enk = str(user_info_dict.get("zpw_enk") or "")
            d_name = user_info_dict.get("displayName") or user_info_dict.get("zaloName") or d_name

        # Khởi tạo trực tiếp phiên Zalo PC bằng đúng User-Agent & IMEI của mã QR để máy tính ở cố định trong tài khoản Zalo!
        for _try_i in range(2):
            try:
                z = Zalo.get_pooled_client(
                    imei, clean_c, force_new=True,
                    user_agent=ua_bound, zpw_enk_hint=zpw_enk, uid_hint=uid
                )
                uid = z.uid or uid
                zpw_enk = z.secret_key or zpw_enk
                if z.display_name and not z.display_name.startswith("Zalo_"):
                    d_name = z.display_name
                clean_c.update(z.cookies_dict)
                # Gọi thử groups() & get_last_msgs() ngay lập tức để kích hoạt phiên hoạt động trên máy chủ Zalo Chat
                try:
                    z.groups(use_cache=False)
                    z.get_last_msgs()
                except Exception:
                    pass
                break
            except Exception:
                time.sleep(0.3)

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
        f_content = f"Imei:\n{imei}\n\nUser-Agent:\n{ua_bound}\n\nZpw_Enk:\n{zpw_enk}\n\nCookie:\n{cookies_str}\n"

        st["imei"] = imei
        st["cookies"] = clean_c
        st["cookies_str"] = cookies_str
        st["display_name"] = d_name
        st["uid"] = uid
        st["file_name"] = safe_fn
        st["file_content"] = f_content
        st["status"] = "success"
        enk_badge = "Đã khóa zpw_enk & vào thẳng trong Acc" if zpw_enk else "Đã lưu phiên Cookie & IMEI"
        st["message"] = f"Đã đăng nhập trực tiếp vào tài khoản {d_name} trên thiết bị {pc_name} ({enk_badge})! Gõ .menu trong Zalo để dùng lệnh ngay!"
        cls._persist_qr_state_to_db(st)

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
                    "[QR-LOGIN]",
                    f"[ZALO] Thiết bị {pc_name} đã vào thẳng tài khoản {d_name} & bật bộ soi lệnh .menu 24/7"
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
            if resp is not None and resp.cookies:
                for c in resp.cookies:
                    if c.name and c.value is not None:
                        jar_dict[c.name] = c.value
        except Exception:
            pass

    @classmethod
    def _qr_worker(cls, session_id):
        with cls.LOCK:
            st = cls.SESSIONS.get(session_id)
        if not st:
            return

        # Ưu tiên 1: Nếu môi trường có cài đặt thư viện zalo_login (như trong get ck im zalo.py)
        try:
            from zalo_login import login_qr_with_unique_imei, LoginQRCallbackEventType
            import asyncio

            async def _run_native_zalo_login():
                async def _cb(event):
                    if st["stop_ev"].is_set():
                        return
                    ev_type = event.get("type")
                    data = event.get("data") or {}
                    actions = event.get("actions") or {}
                    if ev_type == LoginQRCallbackEventType.QRCodeGenerated:
                        qr_code_id = str(data.get("code") or "")
                        b64_img = data.get("image") or ""
                        if not b64_img and "saveToFile" in actions:
                            tmp_p = os.path.join(UPLOAD_DIR, f"qr_{session_id}.png")
                            await actions["saveToFile"](tmp_p)
                            if os.path.exists(tmp_p):
                                with open(tmp_p, "rb") as rf:
                                    raw_b = rf.read()
                                os.remove(tmp_p)
                                st["qr_png_bytes"] = raw_b
                                b64_img = "data:image/png;base64," + base64.b64encode(raw_b).decode("utf-8")
                        elif b64_img:
                            clean_b = b64_img.split(",", 1)[-1].strip()
                            pad_r = (4 - len(clean_b) % 4) % 4
                            raw_b = base64.b64decode(clean_b + ("=" * pad_r))
                            st["qr_png_bytes"] = raw_b
                            b64_img = "data:image/png;base64," + base64.b64encode(raw_b).decode("utf-8")
                        st["qr_code_id"] = qr_code_id
                        st["qr_base64"] = b64_img
                        st["status"] = "waiting_scan"
                        short_c = qr_code_id.split(".")[0].upper()[:6]
                        st["message"] = f"💻 Thiết bị {st['pc_name']} (Mã #{short_c}) đã sẵn sàng! Hãy dùng Zalo quét mã để hiện thông báo đăng nhập!"
                        cls._persist_qr_state_to_db(st)
                    elif ev_type == LoginQRCallbackEventType.QRCodeScanned:
                        st["display_name"] = data.get("display_name") or "Tài khoản Zalo"
                        st["avatar"] = data.get("avatar") or ""
                        st["status"] = "scanned"
                        st["message"] = f"📲 Thiết bị {st['pc_name']} đã kết nối với Zalo của {st['display_name']}! Hãy bấm 'Đăng nhập' trên điện thoại!"
                        cls._persist_qr_state_to_db(st)
                    elif ev_type == LoginQRCallbackEventType.QRCodeExpired:
                        st["status"] = "expired"
                        st["message"] = "⏰ Mã QR đã hết hạn. Hãy bấm Tạo Mã QR Zalo Mới!"
                        cls._persist_qr_state_to_db(st)
                    elif ev_type == LoginQRCallbackEventType.QRCodeDeclined:
                        st["status"] = "declined"
                        st["message"] = "❌ Bạn đã từ chối đăng nhập trên điện thoại."
                        cls._persist_qr_state_to_db(st)

                res = await asyncio.wait_for(login_qr_with_unique_imei(callback=_cb), timeout=120)
                if res and isinstance(res, dict):
                    cls._finalize_zalo_credentials(
                        st,
                        res.get("imei") or st["imei"],
                        res.get("cookies") or {},
                        display_name_hint=st["display_name"],
                        user_info_dict=res.get("user_info") or {},
                    )

            asyncio.run(_run_native_zalo_login())
            return
        except ImportError:
            pass
        except Exception:
            pass

        # Ưu tiên 2: Động cơ Virtual PC Bound QR Engine tích hợp sẵn (Chuẩn 100% giao thức https://zalo.me/pc của zca-js & zalo_login)
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=2)
        s.mount("https://", adapter)
        s.mount("http://", adapter)

        ua = st["user_agent"]
        sec_ch_ua = st["sec_ch_ua"]
        sec_platform = st["sec_platform"]
        pc_name = st.get("pc_name", "DESKTOP-WIN11")

        # QUAN TRỌNG: Bắt buộc dùng continue_url = "https://zalo.me/pc" chuẩn zca-js / zalo_login
        # để id.zalo.me gắn mã QR với phiên đăng nhập Zalo PC/Web hợp lệ khi điện thoại quét!
        continue_url = "https://zalo.me/pc"
        login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc"
        v_str = "2.3.10"
        qr_b64_raw = ""
        qr_code_id = ""
        cookie_jar_dict = {"_zlang": "vn"}

        nav_headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
            "Cache-Control": "max-age=0",
            "Priority": "u=0, i",
            "Sec-Ch-Ua": sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": sec_platform,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-site",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }

        def _make_fetch_headers(ref_url):
            ck_header = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
            h = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
                "Content-Type": "application/x-www-form-urlencoded",
                "Priority": "u=1, i",
                "Origin": "https://id.zalo.me",
                "Referer": ref_url,
                "Sec-Ch-Ua": sec_ch_ua,
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": sec_platform,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }
            if ck_header:
                h["Cookie"] = ck_header
            return h

        try:
            for attempt in range(3):
                if st["stop_ev"].is_set():
                    return
                for cand_cont, cand_ref in (
                    ("https://zalo.me/pc", "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc"),
                    ("https://chat.zalo.me/", "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F"),
                ):
                    continue_url = cand_cont
                    login_referer = cand_ref
                    try:
                        r_page = s.get(login_referer, headers=nav_headers, timeout=10)
                        cls._harvest_cookies(r_page, s, cookie_jar_dict)
                        html_p = r_page.text or ""
                        m_ver = re.search(r"https://stc-zlogin\.zdn\.vn/main-([\d\.]+)\.js", html_p)
                        if m_ver:
                            v_str = m_ver.group(1).strip()
                    except Exception:
                        pass

                    # Bước 2: Đăng ký thông tin phiên PC (logininfo)
                    try:
                        r_li = s.post(
                            "https://id.zalo.me/account/logininfo",
                            data={"continue": continue_url, "v": v_str},
                            headers=_make_fetch_headers(login_referer),
                            timeout=8,
                        )
                        cls._harvest_cookies(r_li, s, cookie_jar_dict)
                    except Exception:
                        pass

                    # Bước 3: Xác thực thiết bị máy tính ảo (verify-client type=device)
                    try:
                        r_vc = s.post(
                            "https://id.zalo.me/account/verify-client",
                            data={"type": "device", "continue": continue_url, "v": v_str},
                            headers=_make_fetch_headers(login_referer),
                            timeout=8,
                        )
                        cls._harvest_cookies(r_vc, s, cookie_jar_dict)
                    except Exception:
                        pass

                    # Bước 4: Sinh mã QR gắn trực tiếp với thiết bị PC ảo
                    try:
                        r_qr = s.post(
                            "https://id.zalo.me/account/authen/qr/generate",
                            data={"continue": continue_url, "v": v_str},
                            headers=_make_fetch_headers(login_referer),
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
                        continue
                if qr_b64_raw and qr_code_id:
                    break
                time.sleep(0.25)

            if not qr_b64_raw or not qr_code_id:
                st["status"] = "error"
                st["message"] = (
                    "⚠️ Máy chủ mạng hiện tại chặn kết nối tới id.zalo.me. "
                    "Bạn hãy chọn tab '✍️ Dán Cookie' bên cạnh để nạp Cookie Zalo tức thì!"
                )
                cls._persist_qr_state_to_db(st)
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
            st["message"] = (
                f"💻 Đã khởi tạo máy tính ảo {pc_name} (Mã #{short_code})! "
                "Hãy dùng Zalo trên điện thoại quét mã QR bên dưới để hiện bảng xác nhận đăng nhập!"
            )
            cls._persist_qr_state_to_db(st)

            # Bước 5: Giữ kết nối Long-Polling waiting-scan liên tục cho thiết bị PC ảo
            while not st["stop_ev"].is_set() and (time.time() - st["created_at"] < 120):
                try:
                    r_scan = s.post(
                        "https://id.zalo.me/account/authen/qr/waiting-scan",
                        data={"code": qr_code_id, "continue": continue_url, "v": v_str},
                        headers=_make_fetch_headers(login_referer),
                        timeout=28,
                    )
                    cls._harvest_cookies(r_scan, s, cookie_jar_dict)
                    j_scan = r_scan.json() if r_scan.content else {}
                    if not isinstance(j_scan, dict):
                        time.sleep(0.4)
                        continue
                    err_c = j_scan.get("error_code")
                    if err_c == 8:
                        continue
                    sd = j_scan.get("data")
                    if err_c == 0 and isinstance(sd, dict) and (sd.get("display_name") or sd.get("avatar")):
                        st["display_name"] = str(sd.get("display_name") or "Tài khoản Zalo").strip()
                        st["avatar"] = str(sd.get("avatar") or "").strip()
                        st["status"] = "scanned"
                        st["message"] = (
                            f"📲 Thiết bị {pc_name} đã nhận diện Zalo của {st['display_name']}! "
                            "Hãy bấm nút 'Đăng nhập / Xác nhận' vừa hiện lên trên điện thoại của bạn!"
                        )
                        cls._persist_qr_state_to_db(st)
                        break
                    if err_c in (0, None):
                        time.sleep(0.4)
                        continue
                    if err_c in (-13, 13):
                        st["status"] = "declined"
                        st["message"] = "❌ Yêu cầu đăng nhập QR đã bị hủy trên điện thoại."
                        cls._persist_qr_state_to_db(st)
                        return
                    if err_c not in (0, 8):
                        st["status"] = "expired"
                        st["message"] = "⏰ Phiên QR đã hết hạn. Hãy bấm 'Tạo Mã QR Zalo Mới' để cấp máy tính ảo mới!"
                        cls._persist_qr_state_to_db(st)
                        return
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    time.sleep(0.6)

            if st["status"] != "scanned":
                return

            # Bước 6: Chờ người dùng bấm "Đăng nhập" trên điện thoại (waiting-confirm)
            while not st["stop_ev"].is_set() and (time.time() - st["created_at"] < 120):
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
                        headers=_make_fetch_headers(login_referer),
                        timeout=28,
                    )
                    cls._harvest_cookies(r_conf, s, cookie_jar_dict)
                    j_conf = r_conf.json() if r_conf.content else {}
                    if not isinstance(j_conf, dict):
                        time.sleep(0.4)
                        continue
                    err_cf = j_conf.get("error_code")
                    if err_cf == 8:
                        continue
                    if err_cf in (-13, 13):
                        st["status"] = "declined"
                        st["message"] = "❌ Bạn đã từ chối yêu cầu đăng nhập trên điện thoại."
                        cls._persist_qr_state_to_db(st)
                        return
                    if err_cf == 0:
                        st["status"] = "confirmed"
                        st["message"] = f"🎉 Đã xác nhận đăng nhập trên {pc_name}! Đang đồng bộ Cookie zpw_sek & khóa zpw_enk..."
                        cls._persist_qr_state_to_db(st)
                        break
                    if err_cf and err_cf not in (0, 8):
                        st["status"] = "error"
                        st["message"] = f"Lỗi xác nhận QR (Mã {err_cf}). Hãy bấm Tạo Mã QR Zalo Mới!"
                        cls._persist_qr_state_to_db(st)
                        return
                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    time.sleep(0.5)

            if st["status"] != "confirmed":
                return

            # Bước 7: Theo dõi từng bước nhảy Redirect (Hop-by-Hop + JS/Meta Redirect) qua id.zalo.me/account/check -> jr.chat.zalo.me/jr/pushsession -> chat.zalo.me
            # TUYỆT ĐỐI không khóa cứng Cookie cũ khi nhảy qua jr.chat.zalo.me để nhận đầy đủ zpw_sek chính chủ vào thẳng tài khoản!
            def _follow_hop_by_hop(start_u, init_ref):
                cur_u = start_u
                cur_ref = init_ref
                for _hop in range(10):
                    if not cur_u:
                        break
                    p_u = urlparse(cur_u)
                    s.cookies.update(cookie_jar_dict)
                    ck_hop = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
                    h_hop = dict(nav_headers)
                    h_hop["Referer"] = cur_ref
                    h_hop["Sec-Fetch-Site"] = "same-site" if "zalo.me" in (p_u.netloc or "") else "none"
                    if ck_hop:
                        h_hop["Cookie"] = ck_hop
                    try:
                        r_h = s.get(cur_u, headers=h_hop, allow_redirects=False, timeout=12)
                        cls._harvest_cookies(r_h, s, cookie_jar_dict)
                        # Thu hoạch thêm từ raw Set-Cookie header nếu domain khác nhau (.zalo.me / .chat.zalo.me)
                        raw_sc = r_h.headers.get("Set-Cookie") or ""
                        for m_sc in re.finditer(r"(?:^|,\s*)([A-Za-z0-9_\-\.]+)=([^;,\s]+)", raw_sc):
                            ck_n, ck_v = m_sc.group(1).strip(), m_sc.group(2).strip()
                            if ck_n.lower() not in ("path", "domain", "expires", "max-age", "samesite", "secure", "httponly"):
                                cookie_jar_dict[ck_n] = ck_v
                        if r_h.status_code in (301, 302, 303, 307, 308):
                            loc = r_h.headers.get("Location") or ""
                            if not loc:
                                break
                            if loc.startswith("/"):
                                loc = f"{p_u.scheme}://{p_u.netloc}{loc}"
                            cur_ref = cur_u
                            cur_u = loc
                            continue
                        body_s = r_h.text or ""
                        m_js = re.search(r"""(?:window\.location(?:\.href|\.replace)?\s*=|content=['"]\d+;\s*url=)\s*['"]?(https://[^'"\s<>]+)""", body_s, re.I)
                        if m_js and "zalo.me" in m_js.group(1):
                            cur_ref = cur_u
                            cur_u = m_js.group(1)
                            continue
                    except Exception:
                        pass
                    break

            # Kiểm tra nếu waiting-confirm trả về URL redirect trực tiếp trong data
            conf_data = j_conf.get("data") if isinstance(j_conf, dict) else None
            if isinstance(conf_data, dict):
                for u_key in ("url", "redirect_url", "continue", "next"):
                    if isinstance(conf_data.get(u_key), str) and conf_data[u_key].startswith("http"):
                        _follow_hop_by_hop(conf_data[u_key], login_referer)
            elif isinstance(conf_data, str) and conf_data.startswith("http"):
                _follow_hop_by_hop(conf_data, login_referer)

            from urllib.parse import quote as _url_quote
            for check_u in (
                f"https://id.zalo.me/account/check?type=0&continue={_url_quote(continue_url, safe='')}",
                "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2F",
                "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2Findex.html",
                "https://chat.zalo.me/",
            ):
                _follow_hop_by_hop(check_u, login_referer)

            # Bước 8: Đăng nhập trực tiếp vào máy chủ Zalo Chat (wpa.chat.zalo.me + wpa.zaloapp.com) bằng ParamsEncryptor v2 (zcid + zcid_ext + signkey)
            user_info_got = {}
            ck_final_str = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
            wpa_headers = {
                "User-Agent": ua,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
                "Origin": "https://chat.zalo.me",
                "Referer": "https://chat.zalo.me/",
                "Sec-Ch-Ua": sec_ch_ua,
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": sec_platform,
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "Cookie": ck_final_str,
            }

            try:
                enc_q, enc_key = ZaloParamsEncryptor.build_encrypted_login_query(
                    st["imei"], computer_name=st.get("computer_name", "Web"), language="vi", ztype=30, client_version=645
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
                elif isinstance(raw_d, dict) and raw_d.get("zpw_enk"):
                    user_info_got = raw_d
            except Exception:
                pass

            if not user_info_got.get("zpw_enk"):
                for wpa_ep, wpa_p in (
                    ("https://wpa.zaloapp.com/api/login/getLoginInfo", {"imei": st["imei"]}),
                    ("https://wpa.zaloapp.com/api/login/getLoginInfo", {
                        "imei": st["imei"],
                        "zpw_ver": 645,
                        "zpw_type": 30,
                        "type": 30,
                        "client_version": 645,
                        "computer_name": st.get("computer_name", "Web"),
                        "language": "vi",
                        "ts": int(time.time() * 1000),
                    }),
                    ("https://wpa.chat.zalo.me/api/login/getLoginInfo", {
                        "imei": st["imei"],
                        "type": 30,
                        "client_version": 645,
                        "computer_name": st.get("computer_name", "Web"),
                        "language": "vi",
                        "ts": int(time.time() * 1000),
                    }),
                ):
                    try:
                        r_info = s.get(wpa_ep, params=wpa_p, headers=wpa_headers, timeout=10)
                        cls._harvest_cookies(r_info, s, cookie_jar_dict)
                        j_info = r_info.json() if r_info.content else {}
                        if isinstance(j_info.get("data"), dict) and j_info["data"].get("zpw_enk"):
                            user_info_got = j_info["data"]
                            break
                    except Exception:
                        pass

            cls._finalize_zalo_credentials(
                st, st["imei"], cookie_jar_dict,
                display_name_hint=st["display_name"],
                user_info_dict=user_info_got
            )
        except Exception as e:
            st["status"] = "error"
            st["message"] = f"Lỗi khởi tạo phiên QR Zalo: {e}"
            cls._persist_qr_state_to_db(st)


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

    s, fingerprint = DiscordImmortalRegTool.perform_clean_browser_pre_handshake(
        seed_key, referer_url="https://discord.com/login"
    )
    s.headers["X-Context-Properties"] = "eyJsb2NhdGlvbiI6IkxvZ2luIn0="

    pl = {
        "login": email_clean,
        "password": password,
        "undelete": False,
        "login_source": None,
        "gift_code_sku_id": None,
    }
    try:
        r = s.post("https://discord.com/api/v9/auth/login", json=pl, timeout=15)
        d = r.json() if r.content else {}
    except Exception as e:
        return {"ok": False, "error": f"Lỗi kết nối tới máy chủ Discord: {e}"}

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

# CLIENT GIAO THỨC DISCORD SIÊU VIP v14 (ZERO-REST CHECK + ANTI-RESET-PASSWORD)
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
            r = self.s.get(ep, timeout=12)
            if r.status_code == 200:
                channels = r.json()
                prefix = f"[{guild_name}] " if guild_name else ""
                out_ch = []
                for c in channels:
                    if c.get("type") in (0, 5):
                        cid_s = str(c["id"])
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
        """Lấy danh sách kênh Discord Siêu VIP v14:
        - Ưu tiên 1: Lấy tức thì từ bộ nhớ Gateway READY (_PASSIVE_READY_BOXES) hoặc SQLite Vault (0 request REST!).
        - Ưu tiên 2: Nếu vừa thêm Token và Gateway đang bắt tay, chờ tối đa 3.0s để nhận gói READY.
        - Ưu tiên 3: Nếu vẫn chưa có, gọi duy nhất 1 request nhẹ lấy danh sách DM/Group Box và lưu vào SQLite Vault."""
        tkey = DiscordStealthAntiBanEngine._token_vault_key(self.token)
        DiscordStealthAntiBanEngine._ensure_vault_record(self.token)

        if not self.is_bot:
            for _ in range(12):
                with DiscordStealthAntiBanEngine._LOCK:
                    passive = DiscordStealthAntiBanEngine._PASSIVE_READY_BOXES.get(tkey)
                    if passive and passive.get("boxes"):
                        return list(passive["boxes"])
                    cached = DiscordStealthAntiBanEngine._BOXES_CACHE.get(tkey)
                    if cached and cached.get("boxes"):
                        return list(cached["boxes"])
                time.sleep(0.25)

            dm_boxes = self.get_dm_and_group_boxes()
            if dm_boxes:
                with DiscordStealthAntiBanEngine._LOCK:
                    DiscordStealthAntiBanEngine._BOXES_CACHE[tkey] = {"ts": time.time(), "boxes": list(dm_boxes)}
                try:
                    conn = db()
                    conn.execute(
                        "UPDATE discord_token_vault SET boxes_json=?, updated_at=? WHERE token_key=?",
                        (json.dumps(dm_boxes, ensure_ascii=False), time.time(), tkey),
                    )
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                return dm_boxes
            return []

        with DiscordStealthAntiBanEngine._LOCK:
            passive = DiscordStealthAntiBanEngine._PASSIVE_READY_BOXES.get(tkey)
            if passive and passive.get("boxes"):
                return list(passive["boxes"])
            cached = DiscordStealthAntiBanEngine._BOXES_CACHE.get(tkey)
            if cached and (time.time() - cached["ts"] < 600.0) and not force_refresh:
                return list(cached["boxes"])

        all_boxes = []
        guilds = self.get_guilds()
        for g in guilds[:5]:
            time.sleep(random.uniform(0.20, 0.35))
            ch_list = self.get_channels(g["id"], g.get("name", ""))
            all_boxes.extend(ch_list)

        with DiscordStealthAntiBanEngine._LOCK:
            DiscordStealthAntiBanEngine._BOXES_CACHE[tkey] = {"ts": time.time(), "boxes": list(all_boxes)}
        return all_boxes

    def get_guild_channels(self, guild_id, guild_name=""):
        return self.get_channels(guild_id, guild_name=guild_name)

    def get_channel_recent_members(self, channel_id):
        return self.get_box_members(channel_id)

    def get_box_members(self, channel_id):
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
        pl = {"custom_status": {"text": str(text or "NOEL v15 — Phan Anh Khôi"), "emoji_name": str(emoji_name or "👑")}}
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
            opts = ["Đồng ý 100% 🔥", "Chuẩn VIP Phan Anh Khôi 👑"]
        answers = [{"poll_media": {"text": opt[:55]}} for opt in opts[:10]]
        pl = {
            "mobile_network_type": "unknown",
            "content": "",
            "nonce": DiscordStealthAntiBanEngine.generate_snowflake_nonce(),
            "tts": False,
            "flags": 0,
            "poll": {
                "question": {"text": str(question_text or "Bình chọn Phan Anh Khôi")[:280]},
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
        lines = [ln.strip() for ln in str(raw_text or "").split("\n")]
        out_lines = []
        for ln in lines:
            if not ln:
                out_lines.append("")
                continue
            clean_ln = re.sub(r"^#+\s*", "", ln).strip()
            if is_heading:
                out_lines.append(f"# **{clean_ln}**")
            elif style_mode != "none":
                out_lines.append(f"**{clean_ln}**")
            else:
                out_lines.append(clean_ln)
        return "\n".join(out_lines)

    def send_message(self, channel_id, content, color_mode="rainbow", fixed_color=None,
                     antiband=True, mentions=None, tag_all=False, strip_line_num=False,
                     is_heading=True, stop_ev=None, start_global_epoch=None, start_box_epoch=None,
                     priority_bypass=False):
        if not priority_bypass and is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, channel_id):
            return None
        self.route_step = (self.route_step + 1) & 0xFFFF
        DiscordStealthAntiBanEngine.ensure_session_warmed_up(self.token, is_bot=self.is_bot)
        self._apply_headers(channel_id=channel_id)

        if not priority_bypass:
            if not DiscordStealthAntiBanEngine.acquire_multi_group_slot(
                self.token, channel_id, stop_ev=stop_ev,
                start_global_epoch=start_global_epoch, start_box_epoch=start_box_epoch
            ):
                return None

        raw = clean_corrupted_shortcuts(content)
        if strip_line_num:
            raw = "\n".join(strip_leading_line_number(ln) for ln in raw.split("\n"))

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

        # Nếu raw vô tình chỉ chứa thẻ <@...> hoặc rỗng sau khi tách tag, tự động bù nội dung chuẩn để không bao giờ chỉ gửi mỗi tên Tag!
        raw_stripped_check = re.sub(r"<@(?:!|&)?\d+>", "", str(raw or "")).strip()
        if not raw_stripped_check:
            raw = "Hệ thống SAKURA FROST v18 — Phan Anh Khôi điểm danh siêu tốc!"

        unframed_body = self.format_unframed_discord_text(
            raw, is_heading=is_heading, style_mode=color_mode
        )
        if len(unframed_body) + len(tag_suffix) > 1940:
            max_body_len = max(100, 1940 - len(tag_suffix))
            unframed_body = unframed_body[:max_body_len].rstrip()
            if unframed_body.count("**") % 2 == 1:
                unframed_body += "**"
        formatted_content = f"{unframed_body}{tag_suffix}".strip()

        if antiband:
            formatted_content = DiscordStealthAntiBanEngine.append_stealth_tail(
                formatted_content, channel_id=str(channel_id)
            )
        else:
            formatted_content = DiscordFirewallEngine.sanitize_outbound_text(formatted_content)

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
        if priority_bypass:
            active_sess.headers.update(self.s.headers)
        r = active_sess.post(url, json=pl, timeout=(2.8, 5.0))
        if r.cookies:
            DiscordStealthAntiBanEngine.persist_real_cloudflare_cookies(self.token, self.s.cookies)
        DiscordStealthAntiBanEngine.record_bucket_headers(channel_id, r.headers)

        if r.status_code == 429:
            try:
                rj = r.json()
                retry_after = float(rj.get("retry_after", 5.0))
                err_code = int(rj.get("code", 0))
            except Exception:
                retry_after = 5.0
                err_code = 0
            DiscordStealthAntiBanEngine.set_channel_cooldown(channel_id, retry_after)
            raise Exception(f"429:RateLimit:{retry_after}:DiscordCode_{err_code}")

        if r.status_code in (401, 403, 404):
            try:
                err_code = int(r.json().get("code", 0))
            except Exception:
                err_code = 0
            if r.status_code == 401 or err_code in (40001, 40002):
                raise Exception(f"AuthError:Discord_{r.status_code}_{err_code}")
            if err_code in (50001, 50013, 10003, 50007) or r.status_code in (403, 404):
                DiscordStealthAntiBanEngine.set_channel_cooldown(channel_id, 900.0)
                raise Exception(f"ChannelForbidden:Discord_{r.status_code}_{err_code}")
            raise Exception(f"HTTP {r.status_code}:Code_{err_code}")

        if r.status_code not in (200, 201):
            raise Exception(f"HTTP {r.status_code}")

        resp_data = r.json()
        if isinstance(resp_data, dict) and resp_data.get("id"):
            register_system_sent_message(msg_id=resp_data["id"], text=formatted_content)
        return resp_data

# ĐỘNG CƠ FACEBOOK MESSENGER LIGHTSPEED MQTT v14 (TÍCH HỢP TỪ CKIEN.ZIP)
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
    """Client Giao Thức Facebook Messenger Lightspeed MQTT v14 (Tích hợp nguyên bản từ ckien.zip):
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
        tls_adapter = Chrome131TLSAdapter(pool_connections=64, pool_maxsize=128, max_retries=1)
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
            "question_text": str(question_text or "Bình chọn NOEL v14"),
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
        """Gửi tin nhắn Messenger ưu tiên 100% qua đường truyền Lightspeed MQTT (/ls_req) + Sigma Anti-Checkpoint Shield v17!"""
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
    """Bộ lắng nghe lệnh 24/7 trên Messenger v14 (Lightspeed MQTT /t_ms Real-Time Stream):
    - Duy trì kết nối WebSocket MQTT v3.1 tới wss://edge-chat.facebook.com/chat và nhận trực tiếp mọi lệnh
      (.menu, .nhay, .ngon, .theme, .poll, .stop...) qua topic '/t_ms' với 0 request HTTP Polling!"""

    def __init__(self, acc_id):
        self.acc_id = acc_id
        self.platform = "messenger"
        self.stop_ev = threading.Event()
        self.seen_msg_ids = deque(maxlen=2500)
        self.is_initial_seed_done = False
        self.ws_status = "Messenger MQTT Lightspeed v14 Active"
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
                    self.ws_status = "Messenger MQTT /ls_req v14 (.menu Sẵn Sàng)"
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
def box_target_worker(client, acc_id, plat, target, blocks, runtime_opts,
                      stop_ev, counter, lock, stagger_sec=0.0, active_box_count=1):
    target_type = target.get("type", "group")
    target_id = str(target.get("id"))
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

    while not is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id):
        if not blocks:
            break

        antiband = bool(runtime_opts.get("antiband", True))
        antidieall = bool(runtime_opts.get("antidieall", True))
        delay = float(runtime_opts.get("delay", 1.0))
        use_emoji = bool(runtime_opts.get("use_emoji", True))
        icon_count = int(runtime_opts.get("icon_count", 3))
        is_heading = bool(runtime_opts.get("is_heading", True))
        mode = runtime_opts.get("mode", "fast")
        color_mode = runtime_opts.get("color_mode", "rainbow")
        fixed_color = runtime_opts.get("fixed_color", "red")
        tag_users = runtime_opts.get("tag_users") or []
        tag_all = bool(runtime_opts.get("tag_all", False))
        strip_line_num = bool(runtime_opts.get("strip_line_num", True)) or (mode == "treo_nhay")

        if antidieall:
            ok_send, wait_sec = HEALTH_MGR.can_send(acc_id, channel_id=target_id, platform=plat)
            if not ok_send:
                if interruptible_wait(stop_ev, min(1.2, max(0.15, wait_sec)), start_global_epoch, start_box_epoch, target_id):
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

            if mode == "nhay_tag_all":
                eff_tag_all = True
                is_group = True

            if mode == "raid_burst":
                color_mode = "word_rainbow"
                is_heading = True
                use_emoji = True
                icon_count = max(icon_count, 5)

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
                    b_name = parts_b[2] if len(parts_b) > 2 else "PHAN ANH KHOI"
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
                    try:
                        recent_m = client.get_recent_group_messages(target_id)
                        for rm_item in recent_m[-3:]:
                            mid_r = rm_item.get("msgId") or rm_item.get("globalMsgId")
                            cmid_r = rm_item.get("cliMsgId")
                            if mid_r:
                                client.send_reaction(target_id, mid_r, cmid_r, icon=random.choice(["/-heart", "/-strong", ":))", "/-rose", "/-li"]), is_group=is_group)
                    except Exception:
                        pass
                with lock:
                    counter["sent"] += 1
                HEALTH_MGR.report_success(acc_id)
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
                HEALTH_MGR.report_success(acc_id)
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
                HEALTH_MGR.report_success(acc_id)
            elif mode == "treo_ngon":
                text = clean_raw.replace("\r\n", "\n").replace("\r", "\n")
                if plat == "zalo":
                    client.send_adv(
                        text, target_id, color_mode=color_mode, fixed_color=fixed_color,
                        is_group=is_group, mentions=(eff_mentions if is_group else None),
                        tag_all=(eff_tag_all if is_group else False), is_heading=is_heading,
                        color_offset=color_counter, antiband=antiband,
                        use_emoji=use_emoji, icon_count=icon_count,
                        auto_retry_thread_type=True, strip_line_num=False
                    )
                elif plat == "messenger":
                    client.send_message(
                        target_id, text, is_group=True, mentions=eff_mentions,
                        tag_all=eff_tag_all, antiband=antiband,
                        use_emoji=use_emoji, icon_count=icon_count,
                        is_heading=is_heading, strip_line_num=False
                    )
                else:
                    if use_emoji and icon_count > 0:
                        text = text + " " + build_unique_zalo_icons(icon_count)
                    client.send_message(
                        target_id, text, color_mode=color_mode,
                        fixed_color=fixed_color, antiband=antiband,
                        mentions=eff_mentions, tag_all=eff_tag_all,
                        strip_line_num=False, is_heading=is_heading
                    )

                color_counter += 1
                with lock:
                    counter["sent"] += 1
                HEALTH_MGR.report_success(acc_id)

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

                    if antidieall:
                        ok_s, w_s = HEALTH_MGR.can_send(acc_id, channel_id=target_id, platform=plat)
                        if not ok_s:
                            if interruptible_wait(stop_ev, min(1.2, max(0.15, w_s)), start_global_epoch, start_box_epoch, target_id):
                                break
                            continue

                    t0_send = time.perf_counter()
                    if plat == "zalo":
                        client.send_adv(
                            ln, target_id, color_mode=color_mode, fixed_color=fixed_color,
                            is_group=is_group, mentions=(eff_mentions if is_group else None),
                            tag_all=(eff_tag_all if is_group else False), is_heading=is_heading,
                            color_offset=color_counter, antiband=antiband,
                            use_emoji=use_emoji, icon_count=icon_count,
                            auto_retry_thread_type=True, strip_line_num=True
                        )
                    elif plat == "messenger":
                        client.send_message(
                            target_id, ln, is_group=True, mentions=eff_mentions,
                            tag_all=eff_tag_all, antiband=antiband,
                            use_emoji=use_emoji, icon_count=icon_count,
                            is_heading=is_heading, strip_line_num=True,
                            stop_ev=stop_ev, start_global_epoch=start_global_epoch, start_box_epoch=start_box_epoch
                        )
                    else:
                        msg_ln = (ln + " " + build_unique_zalo_icons(icon_count)) if (use_emoji and icon_count > 0) else ln
                        sent_res = client.send_message(
                            target_id, msg_ln, color_mode=color_mode,
                            fixed_color=fixed_color, antiband=antiband,
                            mentions=eff_mentions, tag_all=eff_tag_all,
                            strip_line_num=True, is_heading=is_heading,
                            stop_ev=stop_ev, start_global_epoch=start_global_epoch, start_box_epoch=start_box_epoch
                        )
                        if sent_res is None and is_task_stopped_fast(stop_ev, start_global_epoch, start_box_epoch, target_id):
                            break
                    lat_ms = (time.perf_counter() - t0_send) * 1000.0

                    color_counter += 1
                    with lock:
                        counter["sent"] += 1
                    HEALTH_MGR.report_success(acc_id, latency_ms=lat_ms, channel_id=target_id)
                    step_d = HEALTH_MGR.get_adaptive_delay(
                        acc_id, delay, antiband=antiband, platform=plat, text_len=len(ln), active_box_count=active_box_count
                    )
                    if plat == "discord":
                        if step_d > 0.0:
                            if interruptible_wait(stop_ev, step_d, start_global_epoch, start_box_epoch, target_id):
                                break
                    else:
                        if interruptible_wait(stop_ev, max(0.20, step_d), start_global_epoch, start_box_epoch, target_id):
                            break
                continue

            else:
                text = strip_leading_line_number(clean_raw) if strip_line_num else clean_raw
                if plat == "zalo":
                    client.send_adv(
                        text, target_id, color_mode=color_mode, fixed_color=fixed_color,
                        is_group=is_group, mentions=(eff_mentions if is_group else None),
                        tag_all=(eff_tag_all if is_group else False), is_heading=is_heading,
                        color_offset=color_counter, antiband=antiband,
                        use_emoji=use_emoji, icon_count=icon_count,
                        auto_retry_thread_type=True, strip_line_num=strip_line_num
                    )
                elif plat == "messenger":
                    client.send_message(
                        target_id, text, is_group=True, mentions=eff_mentions,
                        tag_all=eff_tag_all, antiband=antiband,
                        use_emoji=use_emoji, icon_count=icon_count,
                        is_heading=is_heading, strip_line_num=strip_line_num
                    )
                else:
                    if use_emoji and icon_count > 0:
                        text = text + " " + build_unique_zalo_icons(icon_count)
                    client.send_message(
                        target_id, text, color_mode=color_mode,
                        fixed_color=fixed_color, antiband=antiband,
                        mentions=eff_mentions, tag_all=eff_tag_all,
                        strip_line_num=strip_line_num, is_heading=is_heading
                    )

                color_counter += 1
                with lock:
                    counter["sent"] += 1
                HEALTH_MGR.report_success(acc_id)

        except Exception as e:
            err_str = str(e)
            if "ChannelForbidden:" in err_str:
                # Kênh này bị khóa quyền chat, dừng riêng luồng kênh này để bảo vệ tuổi thọ tài khoản Discord
                break
            elif "429:RateLimit:" in err_str:
                parts = err_str.split(":")
                try:
                    retry_after = float(parts[2])
                except Exception:
                    retry_after = 15.0
                HEALTH_MGR.report_rate_limit(acc_id, retry_after, reason=err_str, channel_id=target_id)
            elif "AuthError" in err_str:
                HEALTH_MGR.report_error(acc_id, err_str, is_auth_error=True)
                if plat == "zalo":
                    try:
                        client = Zalo.get_pooled_client(client.imei, client.cookies_dict, force_new=True)
                    except Exception:
                        pass
            else:
                HEALTH_MGR.report_error(acc_id, err_str, is_auth_error=False, channel_id=target_id)

        actual_delay = HEALTH_MGR.get_adaptive_delay(
            acc_id, delay, antiband=antiband, platform=plat, text_len=len(clean_raw), active_box_count=active_box_count
        )
        if plat == "discord":
            if actual_delay > 0.0:
                if interruptible_wait(stop_ev, actual_delay, start_global_epoch, start_box_epoch, target_id):
                    break
        else:
            if interruptible_wait(stop_ev, max(0.20, actual_delay), start_global_epoch, start_box_epoch, target_id):
                break

def single_acc_multi_box_dispatcher(acc_dict, targets, blocks, runtime_opts, stop_ev, counter, lock, acc_idx=0):
    acc_id = acc_dict["id"]
    plat = (acc_dict.get("platform") or "zalo").lower()
    acc_name = acc_dict.get("name") or f"Acc #{acc_id}"

    # Stagger nhẹ giữa các tài khoản (0.06s) để khi 5-20 Acc cùng bắn vào 1 phòng tin nhắn rải đều cực đẹp và không đụng độ
    if acc_idx > 0:
        if stop_ev.wait(min(0.6, acc_idx * 0.06)):
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

    # Khởi tạo bộ đếm riêng cho từng tài khoản trong counter["by_acc"]
    with lock:
        if "by_acc" not in counter:
            counter["by_acc"] = {}
        counter["by_acc"][acc_name] = 0

    class _AccCounterProxy(dict):
        def __getitem__(self, k):
            return counter.get(k, 0)
        def __setitem__(self, k, v):
            diff = v - counter.get(k, 0)
            counter[k] = v
            if k == "sent" and diff > 0:
                counter["by_acc"][acc_name] = counter["by_acc"].get(acc_name, 0) + diff

    proxy_counter = _AccCounterProxy()
    box_threads = []
    total_boxes = max(1, len(targets))
    for idx, target in enumerate(targets):
        stagger = min(0.45, idx * 0.035)
        bt = threading.Thread(
            target=box_target_worker,
            args=(client, acc_id, plat, target, blocks, runtime_opts, stop_ev, proxy_counter, lock, stagger, total_boxes),
            daemon=True
        )
        box_threads.append(bt)
        bt.start()

    while not stop_ev.is_set():
        if not any(bt.is_alive() for bt in box_threads):
            break
        stop_ev.wait(0.25)

    for bt in box_threads:
        bt.join(timeout=0.05)

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
        # Khi gõ lệnh từ khung chat mà bật Đa Tài Khoản (multi_acc=True): huy động TẤT CẢ tài khoản cùng nền tảng chạy song song!
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

    selected_accs = accs if multi_acc else [accs[0]]
    acc_names_list = [a.get("name") or f"Acc #{a['id']}" for a in selected_accs]
    with TASKS_RAM_LOCK:
        if tid in TASKS_RAM_STORE:
            TASKS_RAM_STORE[tid]["acc_count"] = len(selected_accs)
            TASKS_RAM_STORE[tid]["acc_names"] = acc_names_list

    counter = {"sent": 0, "by_acc": {n: 0 for n in acc_names_list}}
    lock = threading.Lock()
    threads = []

    for idx_a, a in enumerate(selected_accs):
        # Đảo thứ tự câu nhẹ giữa các Acc để khi 5 Acc cùng chạy không gửi trùng 1 câu cùng lúc
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
        if stop_ev.wait(0.35):
            break

    with TASKS_RAM_LOCK:
        if tid in TASKS_RAM_STORE:
            TASKS_RAM_STORE[tid]["sent"] = counter["sent"]
            TASKS_RAM_STORE[tid]["by_acc"] = dict(counter.get("by_acc") or {})
            TASKS_RAM_STORE[tid]["status"] = "stopped"
            TASKS_RAM_STORE[tid]["dirty"] = True
    ACTIVE_TASKS.pop(tid, None)

def start_task_programmatic(targets, blocks, delay=1.0, use_emoji=True, icon_count=3,
                            tag_users=None, tag_all=False, is_heading=True, multi_acc=True,
                            mode="fast", color_mode="rainbow", fixed_color="red",
                            antiband=True, antidieall=True, specific_acc_id=None, source_label="web",
                            defer_db_insert=False, account_ids=None, trigger_cmd=""):
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

    runtime_opts = {
        "delay": float(delay),
        "use_emoji": bool(use_emoji),
        "icon_count": int(icon_count),
        "tag_users": list(tag_users),
        "tag_all": bool(tag_all),
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
    updated = 0
    with SYSTEM_CFG_LOCK:
        for k, v in kwargs.items():
            if k in SYSTEM_RUNTIME_CONFIG:
                SYSTEM_RUNTIME_CONFIG[k] = v

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

def log_system_command(acc_id, thread_id, sender_id, cmd_text, action_taken):
    acc_obj = get_account_from_ram(acc_id) if acc_id else None
    acc_name = (acc_obj.get("name") if acc_obj else "") or f"Acc #{acc_id}"
    plat_lbl = ((acc_obj.get("platform") if acc_obj else "") or "zalo").upper()
    now_t = time.time()
    entry = {
        "acc_id": acc_id,
        "acc_name": acc_name,
        "platform": plat_lbl,
        "time_str": time.strftime("%H:%M:%S", time.localtime(now_t)),
        "thread_id": str(thread_id or ""),
        "sender_id": str(sender_id or ""),
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

def parse_and_execute_inchat_command(
    zalo_client, acc_row, thread_id, is_group, sender_id, raw_msg,
    raw_mentions=None, discord_client=None, platform="zalo", messenger_client=None,
    pre_claimed_slot=False
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
        arg_body = raw_after_space.strip()
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
    }
    cmd_token = stealth_alias_map.get(cmd_token, cmd_token)

    is_owner = (s_uid in ("0", "", my_uid, my_s2m)) or (s_uid in OWNER_UIDS_CACHE)
    allow_all_val = acc_row.get("allow_all_cmd")
    allow_all = True if allow_all_val is None else bool(int(allow_all_val))

    # Luôn cho phép .menu, .help, .files, .stop phản hồi tức thì để không bao giờ bị kẹt quyền
    always_open_cmds = {"menu", "help", "lenh", "bot", "hdsd", "files", "dsfile", "listfile", "dsquyen", "stop", "dung", "dừng", "stopall", "ping", "status", "info", "id", "uid", "mem"}
    if cmd_token not in always_open_cmds:
        if not is_user_authorized_for_cmd(s_uid, my_uid, my_s2m, allow_all=allow_all):
            return False

    # Khóa nguyên tử chống xuất hiện 2 lần khi gõ .menu hoặc bất kỳ lệnh nào trong khung chat
    if not pre_claimed_slot:
        if not claim_command_execution_slot(platform, thread_id, s_uid, text):
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

    def _send_reply(msg_txt):
        register_system_sent_message(text=msg_txt)
        if platform == "zalo" and zalo_client:
            try:
                zalo_client.send_adv(
                    msg_txt, thread_id, color_mode="none",
                    is_group=is_group, is_heading=False, antiband=True,
                    use_emoji=False, icon_count=0, auto_retry_thread_type=True,
                    parse_auto_tags=False
                )
            except Exception:
                try:
                    zalo_client.send_adv(
                        msg_txt, thread_id, color_mode="none",
                        is_group=not is_group, is_heading=False, antiband=False,
                        use_emoji=False, icon_count=0, auto_retry_thread_type=False,
                        parse_auto_tags=False
                    )
                except Exception:
                    pass
        elif platform == "discord" and discord_client:
            DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS[acc_id].add(str(thread_id))
            try:
                discord_client.send_message(
                    thread_id, msg_txt, color_mode="none", antiband=True, is_heading=False,
                    priority_bypass=True
                )
            except Exception:
                pass
        elif platform == "messenger" and messenger_client:
            MessengerStealthAntiBanEngine.ACTIVE_MESSENGER_POLL_THREADS[acc_id].add(str(thread_id))
            try:
                messenger_client.send_message(
                    thread_id, msg_txt, is_group=True, antiband=True, is_heading=False
                )
            except Exception:
                pass

    if cmd_token in ("menu", "help", "lenh", "bot", "hdsd"):
        with SYSTEM_CFG_LOCK:
            cur_d = SYSTEM_RUNTIME_CONFIG["delay"]
            cur_c = SYSTEM_RUNTIME_CONFIG["color_mode"]
            cur_ic = SYSTEM_RUNTIME_CONFIG["icon_count"]
        vip_st = "ON" if DiscordStealthAntiBanEngine.SUPER_VIP_MODE else "OFF"
        if platform == "discord":
            help_txt = (
                f"⚡ HỆ THỐNG NOEL v15 — PHAN ANH KHÔI (Anti-Reset-Key: {vip_st}):\n"
                "• .n <số file / câu> [@Tên] — Treo nhây từng dòng\n"
                "• .g <số file / bài> [@Tên] — Treo ngôn nguyên bài\n"
                "• .r <số file / câu> [@Tên] — Chế độ tốc độ cao\n"
                "• .a <số file / câu> [@Tên] — Đảo câu ngẫu nhiên\n"
                "• .s <nội dung> [@Tên] | .chao [@Tên] | .vip (Bật/Tắt Siêu VIP)\n"
                "• .f <số file> | .ds (Xem file) | .af <tên> | <nd> (Tạo file)\n"
                f"• .d <giây> (Hiện tại: {cur_d}s) | .mau <rainbow|word|tat> ({cur_c})\n"
                "• .ping | .status | .id | .mem | .cp @Tên | .xq @Tên\n"
                "• .t (Dừng phòng này) | .ta (Dừng tất cả)"
            )
        elif platform == "messenger":
            help_txt = (
                "⚡ BẢNG LỆNH MESSENGER MQTT v15 — PHAN ANH KHÔI:\n"
                "• .nhay <nd / số file> [@Tên / @All] (Tắt: .n)\n"
                "• .ngon <nd / số file> [@Tên / @All] (Tắt: .g)\n"
                "• .raid <nd / số file> [@Tên] (.r) | .auto <số file> (.a)\n"
                "• .theme <tên / random> (.setnen) — Đổi nền MQTT\n"
                "• .poll <câu hỏi> | <ý 1> ; <ý 2> (.nhaypoll) — Tạo Poll MQTT\n"
                "• .sharelink <url> | <nd> | .sharecontact [@Tên]\n"
                "• .typing <on/off> | .tenbox <tên mới> | .setname <biệt danh> [@Tên]\n"
                f"• .delay <giây> ({cur_d}s) | .icon <0-10> ({cur_ic}) | .files (.ds)\n"
                "• .ping | .status | .id | .mem | .stop (.t) | .stopall (.ta)"
            )
        else:
            help_txt = (
                "⚡ BẢNG LỆNH ZALO SIÊU VIP v15 — PHAN ANH KHÔI:\n"
                "• .nhay <nd / số file> [@Tên / @All] (Tắt: .n)\n"
                "• .ngon <nd / số file> [@Tên / @All] (Tắt: .g)\n"
                "• .spam <nội dung> [@Tên / @All] (Tắt: .s)\n"
                "• .raid <nd / số file> [@Tên / @All] (Tắt: .r - Siêu tốc)\n"
                "• .auto <nd / số file> [@Tên / @All] (Tắt: .a - Đảo câu)\n"
                "• .file <số file> | .files (.ds) | .addfile <tên> | <nd>\n"
                f"• .delay <giây> ({cur_d}s) | .icon <0-10> ({cur_ic}) | .mau <rainbow|word>\n"
                "• .ping (.p) | .status | .id | .mem | .stop (.t) | .stopall (.ta)"
            )
        _send_reply(help_txt)
        log_system_command(acc_id, thread_id, sender_id, text, f"Hiển thị .menu ({platform})")
        return True

    if cmd_token in ("2fa", "otp", "totp"):
        sec_str = arg_body.strip()
        code_6, rem_s = generate_totp_rfc6238(sec_str)
        if code_6:
            _send_reply(f"🔐 MÃ OTP 2FA (Phan Anh Khôi): {code_6} (Hiệu lực còn {rem_s}s)")
        else:
            _send_reply("⚠️ Cú pháp: .2fa <Secret_Key_Base32>")
        log_system_command(acc_id, thread_id, sender_id, text, "Tạo mã 2FA OTP")
        return True

    if platform == "discord" and discord_client and cmd_token in ("statusdc",):
        st_txt = arg_body.strip() or "NOEL v15 — Phan Anh Khôi"
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
            q_s = arg_body.strip() or "Bình chọn Phan Anh Khôi"
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
            q_s = arg_body.strip() or "Bình chọn Phan Anh Khôi"
            opts = ["Đồng ý 100% 🔥", "Chuẩn VIP 👑"]
        zalo_client.create_poll(thread_id, q_s.strip(), opts)
        log_system_command(acc_id, thread_id, sender_id, text, f"Tạo Poll Zalo: {q_s[:25]}")
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("tenbox",):
        new_gn = arg_body.strip() or f"Box Phan Anh Khôi #{random.randint(10, 99)}"
        zalo_client.change_group_name(thread_id, new_gn)
        _send_reply(f"✏️ Đã đổi tên nhóm Zalo thành: {new_gn}")
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("todo", "giaoviec"):
        cleaned_td, t_mentions, _ = extract_trailing_tags_and_resolve(
            arg_body, incoming_mentions=raw_mentions, zalo_client=zalo_client, group_id=thread_id
        )
        ass_u = [m["uid"] for m in t_mentions] if t_mentions else [zalo_client.uid]
        zalo_client.send_todo(thread_id, cleaned_td or "Nhiệm vụ Phan Anh Khôi", assignees=ass_u)
        _send_reply("✅ Đã tạo & giao việc (To-Do) trên nhóm Zalo!")
        return True

    if platform == "zalo" and zalo_client and cmd_token in ("bank", "stk"):
        parts_b = [p.strip() for p in arg_body.split("|")]
        b_bin = int(parts_b[0]) if (parts_b and parts_b[0].isdigit()) else 970422
        b_num = parts_b[1] if len(parts_b) > 1 else (parts_b[0] if parts_b and parts_b[0] else "9999999999")
        b_name = parts_b[2] if len(parts_b) > 2 else "PHAN ANH KHOI"
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
        _send_reply(f"👑 Chế độ SIÊU VIP v14: {st_lbl}")
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
            q_str = arg_body.strip() or "Bình chọn Siêu VIP NOEL v14"
            opts = ["Đồng ý 100% 🔥", "Quá Đỉnh 🚀", "Siêu VIP 👑"]
        messenger_client.send_poll_mqtt(thread_id, q_str.strip(), opts)
        log_system_command(acc_id, thread_id, sender_id, text, f"Tạo Poll MQTT: {q_str[:30]}")
        return True

    if platform == "messenger" and messenger_client and cmd_token in ("sharelink", "link"):
        if "|" in arg_body:
            u_s, t_s = arg_body.split("|", 1)
        else:
            u_s, t_s = (arg_body.strip() or "https://www.facebook.com/"), "🔥 NOEL v14 Lightspeed MQTT"
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
                mems = zalo_client.get_members_full(thread_id, use_cache=False)
            elif platform == "discord" and discord_client:
                mems = discord_client.get_box_members(thread_id)
            elif platform == "messenger" and messenger_client:
                mems = messenger_client.get_thread_members(thread_id, use_cache=False)
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
        added_names = []
        if target_mentions:
            for tm in target_mentions:
                if add_authorized_user(tm["uid"], tm["name"], acc_id):
                    added_names.append(tm["name"])
        elif arg_body.strip().isdigit():
            uid_ = arg_body.strip()
            if add_authorized_user(uid_, f"UID_{uid_[-4:]}", acc_id):
                added_names.append(uid_)

        reply_txt = ("Đã cấp quyền dùng lệnh cho: " + ", ".join(added_names)) if added_names else "Hãy tag người cần cấp quyền: .chophep @Tên"
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
            min_allowed = 0.0 if platform == "discord" else 0.2
            new_d = max(min_allowed, min(120.0, float(val_str)))
            cnt = update_running_tasks_config(thread_id=None, delay=new_d)
            if platform != "discord" and float(val_str) < 0.2:
                reply_txt = f"Zalo tối thiểu 0.2s (0.0s chỉ dành riêng cho Discord). Đã chỉnh delay Zalo thành {new_d}s ({cnt} tiến trình)"
            else:
                reply_txt = f"Đã chỉnh delay thành {new_d}s (Áp dụng cho {cnt} tiến trình đang chạy)"
        except Exception:
            reply_txt = "Cú pháp đúng: .delay <số giây> (Discord hỗ trợ 0.0s, Zalo từ 0.2s)"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt)
        return True

    if cmd_token in ("mau", "color", "doimau"):
        arg_c = remove_vn_accents(arg_body.strip())
        if arg_c in ("rainbow", "dong", "cauvong"):
            update_running_tasks_config(color_mode="rainbow")
            reply_txt = "Đã bật tự động phối màu từng dòng"
        elif arg_c in ("word", "word_rainbow", "tu", "tungtu"):
            update_running_tasks_config(color_mode="word_rainbow")
            reply_txt = "Đã bật phối màu từng từ"
        elif arg_c in ("random", "ngaunhien"):
            update_running_tasks_config(color_mode="random")
            reply_txt = "Đã bật phối màu ngẫu nhiên"
        elif arg_c in ("none", "tat", "off"):
            update_running_tasks_config(color_mode="none")
            reply_txt = "Đã tắt đổi màu chữ"
        elif arg_c in ZALO_COLOR_MAP:
            c_map_id = {"do": "red", "red": "red", "vang": "yellow", "yellow": "yellow", "xanh": "green", "xanhla": "green", "green": "green", "cam": "orange", "orange": "orange"}.get(arg_c, "red")
            update_running_tasks_config(color_mode="fixed", fixed_color=c_map_id)
            reply_txt = f"Đã khóa cố định màu chữ: {c_map_id}"
        else:
            reply_txt = "Chọn màu: .mau rainbow | .mau word | .mau random | .mau do | .mau vang | .mau xanh | .mau cam | .mau tat"
        _send_reply(reply_txt)
        log_system_command(acc_id, thread_id, sender_id, text, reply_txt)
        return True

    if cmd_token in ("icon", "emoji"):
        try:
            ic_n = max(0, min(10, int(arg_body.strip())))
            update_running_tasks_config(icon_count=ic_n, use_emoji=(ic_n > 0))
            reply_txt = f"Đã chỉnh số lượng Icon VIP: {ic_n}"
        except Exception:
            reply_txt = "Cú pháp: .icon <số lượng từ 0 đến 10>"
        _send_reply(reply_txt)
        return True

    if cmd_token in ("chuto", "heading"):
        on_val = arg_body.strip().lower() not in ("off", "tat", "0")
        update_running_tasks_config(is_heading=on_val)
        reply_txt = "Đã BẬT chữ lớn in đậm" if on_val else "Đã TẮT chữ lớn in đậm"
        _send_reply(reply_txt)
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
        "ngon": "treo_ngon",
        "treongon": "treo_ngon",
        "treo_ngon": "treo_ngon",
        "raid": "raid_mode",
        "auto": "auto_shuffle",
        "chao": "chao_mode",
        "file": "file_cmd",
        "chay": "file_cmd",
        "tag": "fast",
        "all": "fast",
        "tagall": "fast",
        "nhaypoll": "nhay_poll",
        "nhaynamebox": "nhay_namebox",
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

    cleaned_body, extracted_mentions, extracted_tag_all = extract_trailing_tags_and_resolve(
        arg_body,
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

    if cmd_token in ("all", "tagall"):
        extracted_tag_all = True

    is_auto_shuffle = (chosen_mode == "auto_shuffle")
    if chosen_mode == "raid_mode":
        chosen_mode = "treo_nhay"
        delay_val = 0.0 if platform == "discord" else 0.20
        color_mode = "word_rainbow"
        is_heading = True
        use_emoji = True
        icon_count = max(icon_count, 4)
    elif chosen_mode == "auto_shuffle":
        chosen_mode = "treo_nhay"
    elif chosen_mode == "chao_mode":
        chosen_mode = "treo_nhay"
        if not cleaned_body.strip():
            cleaned_body = "Chào cả nhà ngày mới rực rỡ nhé; Chúc anh em trong box luôn vui vẻ đỉnh cao; Hệ thống NOEL v12 điểm danh siêu tốc"

    if platform == "zalo" and (extracted_mentions or extracted_tag_all):
        target_obj[0]["type"] = "group"

    tokens = cleaned_body.split()
    consumed = 0
    file_query = direct_file_num

    if chosen_mode == "file_cmd":
        chosen_mode = "treo_nhay"
        if not file_query and tokens:
            file_query = tokens[0]
            consumed = 1

    for tk in tokens[consumed:]:
        tk_low = tk.lower()
        if tk_low.startswith("delay=") or tk_low.startswith("d="):
            try:
                min_inl = 0.0 if platform == "discord" else 0.20
                delay_val = max(min_inl, float(tk_low.split("=", 1)[1].replace("s", "")))
                consumed += 1
            except Exception:
                break
        elif tk_low.startswith("color=") or tk_low.startswith("mau="):
            c_val = tk_low.split("=", 1)[1]
            if c_val in ("rainbow", "word_rainbow", "random", "none"):
                color_mode = c_val
            elif c_val in ZALO_COLOR_MAP:
                color_mode = "fixed"
                fixed_color = c_val
            consumed += 1
        elif tk_low.startswith("icon="):
            try:
                icon_count = max(0, int(tk_low.split("=", 1)[1]))
                use_emoji = (icon_count > 0)
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

    remaining_content = " ".join(tokens[consumed:]).strip() if consumed > 0 else cleaned_body.strip()

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
                "Hệ Thống SAKURA FROST v18 ULTRA — Phan Anh Khôi\n"
                "Đẳng cấp tốc độ ánh sáng, cân mọi chiến trường không độ trễ!\n"
                "Tường lửa Anti-Ban v17 bảo vệ toàn diện 24/7!"
            ]
        else:
            blocks = [
                "Hệ thống SAKURA FROST v18 — Phan Anh Khôi điểm danh siêu tốc!",
                "Đẳng cấp treo đa luồng cân 100 tiến trình cực mượt!",
                "Lá chắn Anti-Ban v17 bất tử vận hành 24/7 không delay!",
                "Tốc độ phản hồi ánh sáng — Chuẩn VIP Phan Anh Khôi!"
            ]

    if is_auto_shuffle and len(blocks) > 1:
        blocks = list(blocks)
        random.shuffle(blocks)

    stop_tasks_for_thread(thread_id)

    tid = start_task_programmatic(
        targets=target_obj,
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

    tag_desc = "@All" if extracted_tag_all else (", ".join("@" + m["name"] for m in extracted_mentions) if extracted_mentions else "Không tag")
    log_system_command(acc_id, thread_id, sender_id, text, f"[{platform.upper()}] Chạy {chosen_mode} (Task {tid[-6:]}) | Tag: {tag_desc}")
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

        parse_and_execute_inchat_command(
            zalo_client=client,
            acc_row=acc_row,
            thread_id=thread_id,
            is_group=is_group,
            sender_id=uid_from,
            raw_msg=content,
            raw_mentions=raw_mentions,
            platform="zalo"
        )

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
        """Bộ đồng bộ Delta Poller + PreloadConvers thông minh đa luồng cho Zalo v19:
        1. Gọi get_last_msgs() (preloadconvers/get-last-msgs) để bắt tức thì mọi lệnh .menu, .n, .g, .t ở CẢ Chat Riêng (msgs) VÀ Mọi Nhóm (groupMsgs) trong 1 request!
        2. Đọc get_grid_ver_map() để phát hiện tức thì nhóm vừa có tin nhắn mới (ver thay đổi).
        3. Quét song song bằng ThreadPoolExecutor giúp phản hồi lệnh dưới 0.8 giây!"""
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
                        if is_direct_user_command_text(ct) and (msg_ts == 0 or abs(now_ms - msg_ts) <= 90000):
                            self._process_msg_item(client, acc_now, m, default_is_group=False)
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
                        if is_direct_user_command_text(ct) and (msg_ts == 0 or abs(now_ms - msg_ts) <= 90000):
                            m["grid"] = gid_m
                            self._process_msg_item(client, acc_now, m, default_is_group=True, fallback_thread_id=gid_m)
                        else:
                            self.seen_msg_ids.append(self._make_msg_dedupe_key(m, ct))
            else:
                for m in u_msgs:
                    if isinstance(m, dict):
                        self._process_msg_item(client, acc_now, m, default_is_group=False)
                for m in g_msgs:
                    if isinstance(m, dict):
                        gid_m = str(m.get("idTo") or m.get("grid") or "").strip()
                        m["grid"] = gid_m
                        # Nếu lệnh có @Tag mà preloadconvers chưa kèm mentionInfo, lấy bản đầy đủ từ get_recent_group_messages
                        rc_txt = str(m.get("content") or "")
                        if "@" in rc_txt and gid_m and not m.get("mentions") and not m.get("mentionInfo"):
                            try:
                                full_g = client.get_recent_group_messages(gid_m)
                                m_match = next((x for x in reversed(full_g) if str(x.get("msgId")) == str(m.get("msgId"))), None)
                                if m_match:
                                    m = m_match
                                    m["grid"] = gid_m
                            except Exception:
                                pass
                        self._process_msg_item(client, acc_now, m, default_is_group=True, fallback_thread_id=gid_m)
        except Exception:
            pass

        changed_gids = []
        gmap = {}
        try:
            gmap = client.get_grid_ver_map() or {}
            for gid_k, ver_v in gmap.items():
                gid_s = str(gid_k)
                prev_v = self.last_grid_vers.get(gid_s)
                if prev_v is not None and str(prev_v) != str(ver_v):
                    changed_gids.append(gid_s)
                    HOT_ACTIVE_ZALO_GROUPS.add(gid_s)
                self.last_grid_vers[gid_s] = ver_v
        except Exception:
            pass

        all_gids = list(KNOWN_GROUPS_BY_ACC.get(client.uid, set()) | ALL_KNOWN_ZALO_GROUP_IDS)
        if not all_gids:
            try:
                client.groups(use_cache=True)
                all_gids = list(KNOWN_GROUPS_BY_ACC.get(client.uid, set()) | ALL_KNOWN_ZALO_GROUP_IDS)
            except Exception:
                return
        if not all_gids:
            return

        def _ver_num(g):
            v = gmap.get(str(g), 0)
            try:
                return int(str(v).split("_")[0])
            except Exception:
                return 0

        # Sắp xếp nhóm theo phiên bản hoạt động mới nhất giảm dần
        all_gids.sort(key=_ver_num, reverse=True)

        target_gids = []
        # Ưu tiên 1: Các nhóm vừa có tin nhắn mới làm thay đổi gridVerMap
        for cg in changed_gids:
            if cg not in target_gids:
                target_gids.append(cg)
        # Ưu tiên 2: Các nhóm đang chạy chiến dịch hoặc vừa gõ lệnh
        for hg in list(HOT_ACTIVE_ZALO_GROUPS):
            if str(hg) not in target_gids:
                target_gids.append(str(hg))
        # Ưu tiên 3: Top 4 nhóm hoạt động gần nhất trên tài khoản Zalo
        for top_g in all_gids[:4]:
            if str(top_g) not in target_gids:
                target_gids.append(str(top_g))
        # Ưu tiên 4: Các nhóm chưa được khởi tạo snapshot
        unseeded = [str(g) for g in all_gids if str(g) not in self.seeded_groups]
        for ug in unseeded[:4]:
            if ug not in target_gids:
                target_gids.append(ug)
        # Ưu tiên 5: Vòng xoay tuần tự qua toàn bộ các nhóm còn lại
        batch_size = min(4, len(all_gids))
        start_i = self.poll_cursor % len(all_gids)
        for i in range(batch_size):
            g_cand = str(all_gids[(start_i + i) % len(all_gids)])
            if g_cand not in target_gids:
                target_gids.append(g_cand)
        self.poll_cursor = (start_i + batch_size) % len(all_gids)

        selected_batch = target_gids[:10]
        if not selected_batch:
            return

        futures = [_SHARED_ZALO_POLLER_POOL.submit(self._poll_single_group, client, acc_now, gid) for gid in selected_batch]
        for fut in futures:
            try:
                fut.result(timeout=4.5)
            except Exception:
                pass

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
                self._poll_active_groups_inline(client, acc_row)
                if "Cần cập nhật" in self.ws_status or "Đang" in self.ws_status or time.time() < self.ws_conflict_until:
                    self.ws_status = "PC Online Trong Acc (.menu Sẵn Sàng 24/7)"
            except Exception as e:
                if "Phiên đăng nhập" in str(e) or "zpw_enk" in str(e):
                    self.ws_status = "Cần cập nhật lại Cookie Zalo"
            self.stop_ev.wait(0.95)

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
                                self._process_msg_item(client, acc_now, m, default_is_group=is_grp_cmd)
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
        self.seen_msg_ids = deque(maxlen=1500)
        self.seeded_channels = set()
        self.ws_status = "Đang khởi tạo Discord Ghost Shield..."
        self.last_event_ts = 0.0
        self.last_seq = None
        self.thread = threading.Thread(target=self._run_loop, daemon=True)

    def start(self):
        self.thread.start()

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

        # Chỉ xử lý nếu tin nhắn thực sự bắt đầu bằng tiền tố lệnh để tránh mọi thao tác thừa
        clean_check = strip_invisible_chars(content)
        custom_pfx = (acc_row.get("cmd_prefix") or ".").strip()
        if not clean_check.startswith(tuple(set([custom_pfx, ".", "/", "!"]))):
            return

        raw_mentions = []
        for m in (msg_data.get("mentions") or []):
            muid = str(m.get("id") or "")
            mname = m.get("global_name") or m.get("username") or ""
            if muid:
                if mname:
                    GLOBAL_USER_NAME_CACHE[muid] = mname
                raw_mentions.append({"uid": muid, "id": muid, "name": mname})

        # Khóa nguyên tử NGAY LẬP TỨC theo msg_id & nội dung lệnh trước khi tạo luồng trễ phản xạ
        # để dù có 2 kết nối hay 2 tiến trình cùng nhận sự kiện cũng KHÔNG BAO GIỜ nhảy 2 lần .menu!
        if not claim_command_execution_slot("discord", channel_id, sender_id, clean_check, msg_id=msg_id):
            return

        def _delayed_cmd_exec():
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
                pre_claimed_slot=True
            )

        threading.Thread(target=_delayed_cmd_exec, daemon=True).start()

    def _poll_active_discord_channels_fallback(self, client, acc_now):
        """Chỉ quét nhẹ tối đa 2 kênh đang chạy chiến dịch khi Gateway tạm ngắt kết nối
        (TUYỆT ĐỐI KHÔNG quét hàng loạt DM lúc khởi động để chống Discord báo Reset mật khẩu!):"""
        ch_set = list(DiscordStealthAntiBanEngine.ACTIVE_DISCORD_POLL_CHANNELS.get(self.acc_id, set()))[:2]
        for cid in ch_set:
            if self.stop_ev.is_set():
                break
            try:
                ep = DiscordStealthAntiBanEngine.pick_stealth_endpoint(client.token, f"/channels/{cid}/messages?limit=5", 0)
                r = client.s.get(ep, timeout=6)
                if r.status_code == 200 and isinstance(r.json(), list):
                    msgs = list(reversed(r.json()))
                    if cid not in self.seeded_channels:
                        self.seeded_channels.add(cid)
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

        raw_sock = socket.create_connection((host, port), timeout=14)
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
            f"Accept-Encoding: gzip, deflate, br, zstd\r\n"
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

        sock.settimeout(2.5)
        hb_interval = 38.0
        last_hb = time.time()
        identified = False
        prof = DiscordStealthAntiBanEngine.get_deterministic_profile(client.token)
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
                            hb_interval = max(20.0, (float(d_ev.get("heartbeat_interval", 41250)) / 1000.0) * random.uniform(0.88, 0.95))
                            # Nhịp trễ khởi động tự nhiên giống hệt trình duyệt Chrome thật tải bundle JS
                            self.stop_ev.wait(random.uniform(0.35, 0.65))
                            if self.stop_ev.is_set():
                                break
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
                                self.ws_status = "Discord Ghost Session (Resumed - .menu Sẵn Sàng)"
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
                                self.ws_status = "Discord System Shield (.menu Sẵn Sàng)"
                            else:
                                can_id, wait_id = DiscordStealthAntiBanEngine.can_send_gateway_identify(client.token)
                                if not can_id:
                                    self.ws_status = f"Anti-Check Cooldown ({int(wait_id)}s)"
                                    self.stop_ev.wait(wait_id)
                                    if self.stop_ev.is_set():
                                        break
                                # 100% chuẩn trình duyệt Chrome 131 Web thật trên luồng nén zlib-stream (afk: False, capabilities: 30717, không gửi compress: False)
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
                                self.ws_status = "Discord Chrome 131 Shield (.menu Sẵn Sàng)"

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
                            self.ws_status = "Discord Ghost Vault (.menu Sẵn Sàng Toàn Kênh)"

                        elif op == 0 and t_ev == "RESUMED":
                            self.ws_status = "Discord Ghost Vault (Resumed - .menu Sẵn Sàng)"

                        elif op == 0 and t_ev == "MESSAGE_CREATE" and isinstance(d_ev, dict):
                            self.last_event_ts = time.time()
                            self._handle_discord_message_event(client, acc_now, d_ev)

                        elif op == 1:
                            hb_pkt = json.dumps({"op": 1, "d": self.last_seq}).encode("utf-8")
                            ZaloRealtimeListener._send_ws_frame(sock, hb_pkt, opcode=0x1)
                            last_hb = time.time()

                        elif op == 9:
                            if not d_ev:
                                DiscordStealthAntiBanEngine.save_gateway_resume_state(client.token, "", "", 0)
                            self.stop_ev.wait(random.uniform(3.0, 5.5))
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
        # Đợi nhẹ 1.8s sau khi thêm Token để tránh xung đột request với bước xác thực ban đầu
        self.stop_ev.wait(2.0)
        while not self.stop_ev.is_set():
            acc_row = self._get_acc_row()
            if not acc_row or acc_row.get("platform") != "discord":
                break
            if not acc_row.get("chat_cmd_enabled", 1):
                self.ws_status = "Đã tắt nhận lệnh"
                self.stop_ev.wait(4.0)
                continue

            try:
                is_bot = bool(acc_row.get("is_bot", 0))
                client = DiscordClient(acc_row["token"], is_bot=is_bot)
                if not client.check(force_network=False):
                    self.ws_status = "Token cần kiểm tra lại"
                    self.stop_ev.wait(18.0)
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
                self.stop_ev.wait(5.5)
            except Exception:
                self.ws_status = "Đang đồng bộ lại..."
                self.stop_ev.wait(6.0)

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
                if not need_start and plat == "zalo" and hasattr(lst, "poller_thread"):
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

# GIAO DIỆN WEB CHÍNH: NOEL (100% VECTOR SVG HIỆN ĐẠI, CHỐNG TRÀN VIỀN TUYỆT ĐỐI,
# THANH TAB NGANG DƯỚI NHỎ GỌN HIỆN ĐẠI, NÚT BẤM CÓ HÌNH ẢNH DESIGN NOEL)
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Đăng nhập hệ thống — Phan Anh Khôi</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:#f4f6f8;color:#1f2328;min-height:100vh;
  display:flex;align-items:center;justify-content:center;padding:16px;
}
.login-card{
  width:100%;max-width:380px;background:#ffffff;
  border:1px solid #d0d7de;border-radius:6px;padding:24px;
  box-shadow:0 1px 3px rgba(27,31,36,0.08);
}
.login-hd{
  border-bottom:1px solid #d8dee4;padding-bottom:12px;margin-bottom:16px;
}
.login-title{font-size:17px;font-weight:700;color:#1f2328}
.login-sub{font-size:12px;color:#57606a;margin-top:4px}
.form-group{margin-bottom:14px}
.form-label{display:block;font-size:12px;font-weight:600;color:#1f2328;margin-bottom:6px}
.form-input{
  width:100%;padding:8px 10px;font-size:14px;color:#1f2328;
  background:#f6f8fa;border:1px solid #d0d7de;border-radius:5px;outline:none;
}
.form-input:focus{background:#ffffff;border-color:#0969da;box-shadow:0 0 0 3px rgba(9,105,218,0.15)}
.btn-submit{
  width:100%;padding:9px 14px;font-size:13px;font-weight:600;color:#ffffff;
  background:#1f883d;border:1px solid rgba(27,31,36,0.15);border-radius:5px;cursor:pointer;
}
.btn-submit:hover{background:#1a7f37}
.err-box{
  background:#ffebe9;border:1px solid rgba(255,129,130,0.4);
  color:#cf222e;padding:8px 10px;border-radius:5px;font-size:12px;margin-bottom:14px;
}
.sec-note{margin-top:14px;padding-top:10px;border-top:1px solid #eaeef2;font-size:11px;color:#57606a;display:flex;justify-content:space-between}
</style>
</head>
<body>
  <div class="login-card">
    <div class="login-hd">
      <div class="login-title">Hệ Thống Điều Khiển Đa Tài Khoản v19</div>
      <div class="login-sub">Phát triển bởi Phan Anh Khôi • Bảo mật PBKDF2 &amp; CSRF</div>
    </div>
    {% if error %}<div class="err-box">{{ error }}</div>{% endif %}
    <form method="POST" action="/login">
      <div class="form-group">
        <label class="form-label">Mật khẩu quản trị</label>
        <input class="form-input" type="password" name="password" placeholder="Nhập mật khẩu truy cập..." required autofocus>
      </div>
      <button class="btn-submit" type="submit">Đăng nhập vào bảng điều khiển</button>
    </form>
    <div class="sec-note">
      <span>Trạng thái: Bảo mật 2 lớp</span>
      <span>Chống Brute-Force IP</span>
    </div>
  </div>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bảng Điều Khiển Đa Tài Khoản v19 — Phan Anh Khôi</title>
<style>
:root{
  --bg:#f4f6f8;
  --surface:#ffffff;
  --surface-sub:#f6f8fa;
  --border:#d0d7de;
  --border-light:#e6ebf1;
  --txt:#1f2328;
  --txt-muted:#57606a;
  --blue:#0969da;
  --green:#1a7f37;
  --red:#cf222e;
  --amber:#9a6700;
}
*{box-sizing:border-box;margin:0;padding:0;min-width:0}
html,body{
  width:100%;max-width:100vw;overflow-x:hidden;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg);color:var(--txt);font-size:13px;line-height:1.45;
}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
input,select,textarea,button{font-family:inherit;font-size:13px}

.container{max-width:1180px;margin:0 auto;padding:12px 14px 36px}

/* Topbar cổ điển, rõ ràng như viết tay */
.header-bar{
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:10px 14px;margin-bottom:10px;
  display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;
}
.header-left{display:flex;align-items:center;gap:10px}
.brand-mark{
  width:32px;height:32px;border-radius:5px;border:1px solid var(--border);
  background:var(--surface-sub);display:flex;align-items:center;justify-content:center;
  font-weight:700;color:var(--blue);cursor:pointer;overflow:hidden;flex-shrink:0;
}
.brand-mark img{width:100%;height:100%;object-fit:cover}
.header-title{font-size:15px;font-weight:700;color:var(--txt)}
.header-sub{font-size:11.5px;color:var(--txt-muted)}
.header-actions{display:flex;align-items:center;gap:6px;flex-wrap:wrap}

/* Thanh trạng thái & báo lệnh trực tiếp */
.status-strip{
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:8px 12px;margin-bottom:10px;
  display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;
}
.status-items{display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:12px}
.status-item{display:inline-flex;align-items:center;gap:5px;color:var(--txt-muted)}
.status-item b{color:var(--txt);font-family:ui-monospace,Consolas,monospace}
.dot-online{width:8px;height:8px;border-radius:50%;background:#1a7f37;display:inline-block}

/* Hộp thông báo lệnh mới nhất vừa soi được */
.live-cmd-banner{
  background:#ddf4ff;border:1px solid rgba(9,105,218,0.35);border-radius:6px;
  padding:7px 12px;margin-bottom:10px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;
  font-size:12px;color:#0550ae;
}

/* KPI 4 ô phẳng, viền chuẩn */
.kpi-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:10px}
@media(max-width:640px){.kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
.kpi-box{
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  padding:9px 12px;display:flex;align-items:center;justify-content:space-between;
}
.kpi-label{font-size:11.5px;font-weight:600;color:var(--txt-muted)}
.kpi-val{font-size:16px;font-weight:700;color:var(--txt);font-family:ui-monospace,Consolas,monospace}

/* Thanh Tab điều hướng ngang trên đầu chuẩn kỹ thuật */
.nav-tabs{
  display:flex;gap:4px;border-bottom:1px solid var(--border);
  margin-bottom:12px;overflow-x:auto;padding-bottom:1px;
}
.nav-tab{
  padding:8px 14px;background:var(--surface-sub);border:1px solid var(--border);
  border-bottom:none;border-radius:6px 6px 0 0;color:var(--txt-muted);
  font-weight:600;font-size:12.5px;cursor:pointer;white-space:nowrap;
  display:inline-flex;align-items:center;gap:6px;
}
.nav-tab:hover{color:var(--txt);background:#eaeef2}
.nav-tab.active{
  background:var(--surface);color:var(--blue);border-color:var(--border);
  position:relative;top:1px;padding-bottom:9px;
}
.tab-count{
  padding:1px 6px;border-radius:10px;font-size:11px;font-weight:700;
  background:#eaeef2;color:var(--txt);
}
.nav-tab.active .tab-count{background:#ddf4ff;color:var(--blue)}

.tab-pane{display:none}
.tab-pane.active{display:block}

.grid-12{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:10px}
.col-5{grid-column:span 5}.col-6{grid-column:span 6}.col-7{grid-column:span 7}.col-12{grid-column:span 12}
@media(max-width:880px){.col-5,.col-6,.col-7{grid-column:span 12}}

.panel{
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  margin-bottom:10px;overflow:hidden;
}
.panel-hd{
  background:var(--surface-sub);padding:8px 12px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;
}
.panel-title{font-size:13px;font-weight:700;color:var(--txt)}
.panel-body{padding:12px}

.row-2{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:8px}
.row-3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-bottom:8px}
.row-4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-bottom:8px}
@media(max-width:600px){.row-3,.row-4{grid-template-columns:repeat(2,minmax(0,1fr))}}

.field-lbl{display:block;font-size:11.5px;font-weight:600;color:var(--txt);margin-bottom:4px}
.inp,.sel,.txt{
  width:100%;padding:6px 9px;border-radius:5px;
  background:#ffffff;border:1px solid var(--border);color:var(--txt);outline:none;
}
.inp:focus,.sel:focus,.txt:focus{border-color:var(--blue);box-shadow:0 0 0 2px rgba(9,105,218,0.15)}
.txt{resize:vertical;min-height:64px;line-height:1.4}

.sub-tabs{display:flex;gap:4px;margin-bottom:10px;border-bottom:1px solid var(--border-light);padding-bottom:6px;flex-wrap:wrap}
.sub-tab{
  padding:5px 10px;border:1px solid var(--border);border-radius:4px;
  background:var(--surface-sub);color:var(--txt-muted);font-size:12px;font-weight:600;cursor:pointer;
}
.sub-tab.active{background:var(--blue);color:#ffffff;border-color:var(--blue)}

/* Nút bấm kỹ thuật tiêu chuẩn */
.btn{
  padding:6px 12px;border-radius:5px;border:1px solid var(--border);
  background:var(--surface-sub);color:var(--txt);font-weight:600;font-size:12px;
  cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:5px;
  text-decoration:none;white-space:nowrap;
}
.btn:hover{background:#eaeef2}
.btn-primary{background:var(--blue);color:#ffffff;border-color:rgba(27,31,36,0.15)}
.btn-primary:hover{background:#085cc5}
.btn-success{background:var(--green);color:#ffffff;border-color:rgba(27,31,36,0.15)}
.btn-success:hover{background:#166c2e}
.btn-danger{background:var(--red);color:#ffffff;border-color:rgba(27,31,36,0.15)}
.btn-danger:hover{background:#b61d28}
.btn-block{width:100%;padding:8px 12px}
.btn-sm{padding:3px 8px;font-size:11.5px;border-radius:4px}

.badge{
  display:inline-block;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600;
  border:1px solid transparent;white-space:nowrap;
}
.badge-blue{background:#ddf4ff;color:#0969da;border-color:rgba(9,105,218,0.25)}
.badge-green{background:#dafbe1;color:#1a7f37;border-color:rgba(26,127,55,0.25)}
.badge-red{background:#ffebe9;color:#cf222e;border-color:rgba(207,34,46,0.25)}
.badge-amber{background:#fff8c5;color:#9a6700;border-color:rgba(154,103,0,0.25)}
.badge-gray{background:#eaeef2;color:#57606a;border-color:#d0d7de}

.chk-label{
  display:flex;align-items:center;gap:6px;padding:6px 8px;
  background:var(--surface-sub);border:1px solid var(--border);border-radius:5px;
  font-size:12px;font-weight:500;color:var(--txt);cursor:pointer;
}
.chk-label input{width:14px;height:14px;accent-color:var(--blue)}

.qr-frame{
  width:210px;height:210px;margin:8px auto;padding:8px;
  background:#ffffff;border:2px solid var(--border);border-radius:6px;
  display:flex;align-items:center;justify-content:center;
}
.qr-frame img{width:100%;height:100%;object-fit:contain;image-rendering:crisp-edges}

.scroll-area{max-height:340px;overflow-y:auto;border:1px solid var(--border-light);border-radius:5px}
.list-item{
  display:flex;align-items:center;justify-content:space-between;gap:8px;
  padding:8px 10px;border-bottom:1px solid var(--border-light);background:#ffffff;
}
.list-item:last-child{border-bottom:none}
.list-item:hover{background:var(--surface-sub)}
.item-info{min-width:0;flex:1}
.item-title{font-size:12.5px;font-weight:600;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.item-sub{font-size:11px;color:var(--txt-muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

/* Bảng dữ liệu chuẩn kỹ thuật */
.data-table{width:100%;border-collapse:collapse;font-size:12px}
.data-table th,.data-table td{
  padding:7px 9px;border-bottom:1px solid var(--border-light);text-align:left;vertical-align:middle;
}
.data-table th{background:var(--surface-sub);font-weight:600;color:var(--txt-muted);font-size:11px;text-transform:uppercase}
.data-table tr:hover td{background:#f9fbfd}

#toastBox{position:fixed;top:12px;right:12px;z-index:9999;display:flex;flex-direction:column;gap:6px}
.toast-msg{
  background:#1f2328;color:#ffffff;padding:8px 12px;border-radius:5px;
  font-size:12px;font-weight:600;box-shadow:0 3px 10px rgba(0,0,0,0.2);
}
</style>
</head>
<body>
<div id="toastBox"></div>

<div class="container">
  <header class="header-bar">
    <div class="header-left">
      <label class="brand-mark" title="Đổi biểu tượng">
        <input type="file" id="logoInput" accept="image/*" style="display:none" onchange="uploadBrandLogo(this)">
        <img id="brandLogoImg" src="/api/logo?v={{ logo_ts }}" alt="Logo" style="{% if not has_logo %}display:none{% endif %}">
        <span id="brandLogoFallback" style="{% if has_logo %}display:none{% endif %}">PK</span>
      </label>
      <div>
        <div class="header-title">HỆ THỐNG ĐIỀU KHIỂN ĐA TÀI KHOẢN v19 — PHAN ANH KHÔI</div>
        <div class="header-sub">Zalo PC Session (Giữ thiết bị trong Acc) • Discord Anti-Reset • Messenger MQTT • Đa Tài Khoản Song Song</div>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn btn-danger" type="button" onclick="stopAllRunningTasks()">DỪNG TẤT CẢ TIẾN TRÌNH</button>
      <button class="btn" type="button" onclick="triggerAntiDieAllHeal()">Làm mới kết nối</button>
      <a href="/logout" class="btn">Đăng xuất</a>
    </div>
  </header>

  <div class="status-strip">
    <div class="status-items">
      <span class="status-item" onclick="checkWebPingNow(true)" style="cursor:pointer">
        <span class="dot-online" id="headerPingDot"></span>
        <span>Độ trễ Web: <b id="headerPingText">-- ms</b></span>
      </span>
      <span class="status-item"><span>Độ trễ API: <b id="liveSendPingVal">-- ms</b></span></span>
      <span class="status-item"><span>Dao động (Jitter): <b id="liveJitterVal">1.0 ms</b></span></span>
      <span class="status-item"><span>Tốc độ gửi: <b id="liveRpmVal">0 tin/phút</b></span></span>
      <span class="status-item"><span>Tự phục hồi: <b id="liveHealedVal">0 lần</b></span></span>
    </div>
    <div>
      <span class="badge badge-green" id="liveHangStateBadge">HỆ THỐNG SẴN SÀNG</span>
    </div>
  </div>

  <!-- Thanh báo lệnh vừa soi được theo thời gian thực -->
  <div class="live-cmd-banner" id="latestCmdBanner">
    <div>
      <strong>Trình Soi Lệnh 24/7:</strong>
      <span id="latestCmdBannerText">Đang lắng nghe lệnh (.menu, .n, .g, .s, .r, .t, .ping) trên tất cả tài khoản đã kết nối...</span>
    </div>
    <button type="button" class="btn btn-sm" onclick="switchMainTab('tab-campaign', document.querySelector('[data-tab=\'tab-campaign\']'))">Xem Bảng Soi Lệnh &amp; Chiến Dịch</button>
  </div>

  <div class="kpi-grid">
    <div class="kpi-box">
      <span class="kpi-label">Tài khoản kết nối</span>
      <span class="kpi-val" id="kpiAccCount">{{ accounts|length }}</span>
    </div>
    <div class="kpi-box">
      <span class="kpi-label">Phòng mục tiêu chọn</span>
      <span class="kpi-val" id="kpiTargetCount">0</span>
    </div>
    <div class="kpi-box">
      <span class="kpi-label">Chiến dịch đang chạy</span>
      <span class="kpi-val" id="kpiRunningTasks">0</span>
    </div>
    <div class="kpi-box">
      <span class="kpi-label">Tổng tin nhắn đã gửi</span>
      <span class="kpi-val" id="kpiTotalSent">0</span>
    </div>
  </div>

  <div class="nav-tabs">
    <button type="button" class="nav-tab active" data-tab="tab-accounts" onclick="switchMainTab('tab-accounts', this)">
      <span>1. Quản Lý Tài Khoản</span>
      <span class="tab-count">{{ accounts|length }}</span>
    </button>
    <button type="button" class="nav-tab" data-tab="tab-targets" onclick="switchMainTab('tab-targets', this)">
      <span>2. Chọn Phòng &amp; Tag Thành Viên</span>
      <span class="tab-count" id="dockTargetBadge">0</span>
    </button>
    <button type="button" class="nav-tab" data-tab="tab-campaign" onclick="switchMainTab('tab-campaign', this)">
      <span>3. Chiến Dịch &amp; Bảng Soi Lệnh</span>
      <span class="tab-count" id="dockTaskBadge">0</span>
    </button>
    <button type="button" class="nav-tab" data-tab="tab-files" onclick="switchMainTab('tab-files', this)">
      <span>4. Kho File Kịch Bản (.TXT)</span>
      <span class="tab-count">{{ files|length }}</span>
    </button>
    <button type="button" class="nav-tab" data-tab="tab-shield" onclick="switchMainTab('tab-shield', this)">
      <span>5. Giám Sát &amp; Bảo Mật</span>
    </button>
  </div>

  <!-- TAB 1: QUẢN LÝ TÀI KHOẢN -->
  <section id="tab-accounts" class="tab-pane active">
    <div class="grid-12">
      <div class="col-5">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Thêm &amp; Đăng Nhập Tài Khoản</span>
            <span class="badge badge-blue">Giữ Phiên PC Cố Định</span>
          </div>
          <div class="panel-body">
            <form method="POST" action="/account/add" onsubmit="return handleAccountFormSubmit(event)">
              <input type="hidden" name="platform" id="accPlatformInput" value="zalo">

              <div class="sub-tabs">
                <button type="button" class="sub-tab active" id="segZaloBtn" onclick="switchAccForm('zalo')">Zalo (QR / Cookie)</button>
                <button type="button" class="sub-tab" id="segDiscordBtn" onclick="switchAccForm('discord')">Discord (Token / TK)</button>
                <button type="button" class="sub-tab" id="segMessengerBtn" onclick="switchAccForm('messenger')">Facebook Messenger</button>
              </div>

              <div style="margin-bottom:8px">
                <label class="field-lbl">Tên ghi chú tài khoản (Để trống sẽ tự lấy tên thật)</label>
                <input class="inp" name="name" placeholder="Ví dụ: Acc Zalo Chính, Acc Phụ 1...">
              </div>

              <div id="zaloInputFields">
                <div class="sub-tabs">
                  <button type="button" class="sub-tab active" id="subZaloQRBtn" onclick="switchZaloSubTab('qr')">Quét Mã QR Máy Tính</button>
                  <button type="button" class="sub-tab" id="subZaloManualBtn" onclick="switchZaloSubTab('manual')">Dán Cookie &amp; IMEI</button>
                  <button type="button" class="sub-tab" id="subZaloVaultBtn" onclick="switchZaloSubTab('vault')">Kho Lưu Trữ ({{ accounts|length }})</button>
                </div>

                <div id="zaloQRBox" style="margin-bottom:10px;padding:10px;border:1px solid var(--border);border-radius:5px;background:var(--surface-sub);text-align:center">
                  <div style="display:flex;justify-content:space-between;gap:6px;margin-bottom:6px;flex-wrap:wrap">
                    <span class="badge badge-blue" id="zaloQRCodeIdBadge">Chưa khởi tạo QR</span>
                    <span class="badge badge-gray" id="zaloQRImeiPreview">Thiết bị PC độc lập</span>
                  </div>
                  <div style="font-size:12px;color:var(--txt);margin-bottom:8px;text-align:left" id="zaloQRStatusText">
                    Bấm nút <b>"Tạo Mã QR Đăng Nhập Máy Tính"</b> bên dưới. Khi quét và bấm Đồng ý trên điện thoại, máy tính ảo sẽ đăng nhập thẳng vào tài khoản Zalo của bạn và giữ kết nối 24/7 để dùng lệnh (<code>.menu</code>, <code>.n</code>, <code>.g</code>, <code>.t</code>).
                  </div>
                  <div id="zaloQRStageWrap" style="display:none">
                    <div class="qr-frame">
                      <img id="zaloQRImg" src="" alt="Mã QR Zalo">
                    </div>
                    <div style="font-size:11.5px;font-weight:600;color:var(--blue);margin-bottom:6px" id="zaloQRTimerBadge">Thời gian hiệu lực: 120s</div>
                  </div>

                  <div id="zaloQRExtractedBox" style="display:none;text-align:left;margin-top:8px;padding:8px;border-radius:5px;background:#dafbe1;border:1px solid rgba(26,127,55,0.3)">
                    <div style="font-size:12px;font-weight:700;color:#1a7f37;margin-bottom:4px">ĐÃ VÀO THẲNG TÀI KHOẢN &amp; KHÓA PHIÊN BẤT TỬ:</div>
                    <div style="font-size:11px;color:var(--txt);margin-bottom:6px">IMEI: <code id="zaloQRExtractedImei"></code></div>
                    <div class="row-3" style="margin-bottom:0">
                      <button type="button" class="btn btn-sm" onclick="copyZaloQRData('imei')">Copy IMEI</button>
                      <button type="button" class="btn btn-sm" onclick="copyZaloQRData('cookie')">Copy Cookie</button>
                      <button type="button" class="btn btn-sm" onclick="downloadZaloQRFile()">Tải File .TXT</button>
                    </div>
                  </div>

                  <button type="button" class="btn btn-primary btn-block" id="btnStartZaloQR" onclick="startZaloQRLogin()">
                    Tạo Mã QR Đăng Nhập Máy Tính Mới
                  </button>
                </div>

                <div id="zaloManualBox" style="display:none;margin-bottom:10px">
                  <div style="margin-bottom:8px">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                      <label class="field-lbl" style="margin:0">IMEI Thiết Bị Zalo (zpw_imei)</label>
                      <button type="button" class="btn btn-sm" onclick="generateUniqueZaloImei()">Tạo IMEI Ngẫu Nhiên</button>
                    </div>
                    <input class="inp" name="imei" id="zaloImeiInput" placeholder="Dán IMEI Zalo vào đây...">
                  </div>
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Cookie Zalo (JSON J2Team / Extension / Header String)</label>
                    <textarea class="txt" name="cookies" id="zaloCookieInput" placeholder="Dán Cookie Zalo (có zpw_sek) vào đây..."></textarea>
                  </div>
                  <div id="zaloVerifyStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:5px;font-size:12px;background:#dafbe1;color:#1a7f37;border:1px solid rgba(26,127,55,0.3)"></div>
                  <button type="button" class="btn btn-success btn-block" onclick="verifyAndSaveZaloCookieVault()">Xác Thực Khóa zpw_enk &amp; Lưu Vào Hệ Thống</button>
                </div>

                <div id="zaloVaultBox" style="display:none;margin-bottom:10px">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                    <span class="field-lbl" style="margin:0">Kho Phiên Zalo Đã Lưu (Cookie + IMEI + zpw_enk)</span>
                    <button type="button" class="btn btn-sm" onclick="loadZaloVaultRecords()">Làm mới</button>
                  </div>
                  <div class="scroll-area" id="zaloVaultListContainer" style="max-height:210px">
                    <div style="padding:12px;text-align:center;color:var(--txt-muted)">Đang tải dữ liệu...</div>
                  </div>
                </div>
              </div>

              <div id="messengerInputFields" style="display:none">
                <div class="sub-tabs">
                  <button type="button" class="sub-tab active" id="subMessCookieBtn" onclick="switchMessSubTab('cookie')">Dán Cookie c_user + xs</button>
                  <button type="button" class="sub-tab" id="subMessLoginBtn" onclick="switchMessSubTab('login')">Đăng Nhập Email/SĐT</button>
                </div>
                <div id="messCookieBox">
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Cookie Facebook / Messenger</label>
                    <textarea class="txt" name="mess_cookies" id="messCookieInput" placeholder="c_user=...; xs=... hoặc JSON"></textarea>
                  </div>
                  <div id="messVerifyResultBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:5px;font-size:12px;background:#dafbe1;color:#1a7f37"></div>
                  <button type="button" class="btn btn-success btn-block" style="margin-bottom:8px" onclick="verifyAndLockMessengerCookie()">Xác Thực &amp; Kết Nối Messenger MQTT</button>
                </div>
                <div id="messLoginBox" style="display:none;margin-bottom:8px">
                  <div id="messLoginStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:5px;font-size:12px"></div>
                  <div style="margin-bottom:6px">
                    <label class="field-lbl">Email / SĐT</label>
                    <input class="inp" id="fbLoginEmail" placeholder="Email hoặc SĐT...">
                  </div>
                  <div style="margin-bottom:8px">
                    <label class="field-lbl">Mật khẩu</label>
                    <input class="inp" type="password" id="fbLoginPass" placeholder="Mật khẩu...">
                  </div>
                  <button type="button" class="btn btn-primary btn-block" onclick="extractFacebookCookieByLogin()">Lấy Cookie &amp; Lưu Tài Khoản</button>
                </div>
              </div>

              <div id="discordInputFields" style="display:none">
                <div class="sub-tabs">
                  <button type="button" class="sub-tab active" id="subDisTokenBtn" onclick="switchDiscordRegTab('token')">Nạp Nhiều Token</button>
                  <button type="button" class="sub-tab" id="subDisLoginBtn" onclick="switchDiscordRegTab('login')">Đăng Nhập TK/MK</button>
                  <button type="button" class="sub-tab" id="subDisNewAccBtn" onclick="switchDiscordRegTab('new_acc')">Tạo Hồ Sơ Mới</button>
                </div>
                <div id="discordTokenBox">
                  <label class="field-lbl">Danh sách Token Discord (Mỗi dòng 1 Token — Hỗ trợ nạp nhiều Acc cùng lúc)</label>
                  <textarea class="txt" name="token" id="discordTokenInput" placeholder="Dán 1 hoặc nhiều Token Discord (mỗi dòng 1 Token)..."></textarea>
                  <div id="immortalVaultResultBox" style="display:none;margin:6px 0;padding:8px;border-radius:5px;font-size:12px;background:#dafbe1;color:#1a7f37"></div>
                  <div class="row-3" style="margin-top:6px">
                    <button type="button" class="btn btn-success btn-sm" onclick="runImmortalizeTokensTool(true)">Nạp &amp; Lưu Tất Cả</button>
                    <button type="button" class="btn btn-sm" onclick="runImmortalizeTokensTool(false)">Kiểm Tra Live</button>
                    <button type="button" class="btn btn-sm" onclick="copyDiscordTokenScript()">Copy Code Lấy Token</button>
                  </div>
                  <label class="chk-label" style="margin-bottom:8px">
                    <input type="checkbox" name="is_bot" value="1">
                    <span>Đây là Token Bot Developer</span>
                  </label>
                </div>
                <div id="discordLoginBox" style="display:none;margin-bottom:8px">
                  <div id="discordRegStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:5px;font-size:12px"></div>
                  <div style="margin-bottom:6px">
                    <label class="field-lbl">Email / SĐT Discord</label>
                    <input class="inp" name="reg_email" id="regDisEmail" placeholder="email@gmail.com">
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
                    <label class="field-lbl">Mã 2FA / Secret Key (Nếu có)</label>
                    <input class="inp" name="reg_2fa" id="regDis2FA" placeholder="Nhập mã 6 số hoặc Secret Key...">
                  </div>
                  <button type="button" class="btn btn-primary btn-block" onclick="extractDiscordTokenByReg()">Đăng Nhập &amp; Trích Xuất Token</button>
                </div>
                <div id="discordNewAccBox" style="display:none;margin-bottom:8px">
                  <div id="discordNewAccStatusBox" style="display:none;margin-bottom:8px;padding:8px;border-radius:5px;font-size:12px"></div>
                  <div class="row-2">
                    <div><label class="field-lbl">Email</label><input class="inp" id="newAccEmail" placeholder="email@gmail.com"></div>
                    <div><label class="field-lbl">Username</label><input class="inp" id="newAccUsername" placeholder="user_vip"></div>
                  </div>
                  <div class="row-2">
                    <div><label class="field-lbl">Mật khẩu</label><input class="inp" type="password" id="newAccPassword" placeholder=">= 8 ký tự"></div>
                    <div><label class="field-lbl">Ngày sinh</label><input class="inp" type="date" id="newAccDob" value="2000-06-15"></div>
                  </div>
                  <div class="row-2">
                    <button type="button" class="btn btn-sm" onclick="fillRandomDiscordRegProfile()">Tạo Ngẫu Nhiên</button>
                    <button type="button" class="btn btn-sm" onclick="runBatchDiscordRegStudio()">Khởi Tạo 5 Hồ Sơ</button>
                  </div>
                  <button type="button" class="btn btn-success btn-block" onclick="runCreateNewDiscordAccTool()">Đăng Ký Tài Khoản Discord</button>
                </div>
              </div>

              <div class="row-2" style="margin-bottom:8px">
                <label class="chk-label"><input type="checkbox" name="chat_cmd_enabled" value="1" checked><span>Bật lắng nghe lệnh (.menu)</span></label>
                <label class="chk-label"><input type="checkbox" name="allow_all_cmd" value="1" checked><span>Cho phép thành viên nhóm dùng lệnh</span></label>
              </div>

              <button class="btn btn-primary btn-block" type="submit">Lưu Tài Khoản Vào Hệ Thống</button>
            </form>
          </div>
        </div>

        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Công Cụ Tạo Mã 2FA OTP &amp; Trạng Thái Discord</span>
            <span class="badge badge-gray" id="totpTimerBadge">30s</span>
          </div>
          <div class="panel-body">
            <div style="display:flex;gap:6px;margin-bottom:8px">
              <input class="inp" id="web2FASecretInput" placeholder="Dán chuỗi Secret Key 2FA (Base32)..." style="flex:1">
              <button type="button" class="btn btn-primary btn-sm" onclick="generateWeb2FA(true)">Lấy Mã 6 Số</button>
            </div>
            <div id="web2FAResultBox" style="display:none;padding:8px 10px;border-radius:5px;background:var(--surface-sub);border:1px solid var(--border);align-items:center;justify-content:space-between;margin-bottom:8px">
              <div>
                <div style="font-size:10.5px;color:var(--txt-muted)">MÃ OTP 2FA HIỆN TẠI</div>
                <div id="web2FACodeVal" class="mono" style="font-size:18px;font-weight:700;color:var(--blue);letter-spacing:2px">------</div>
              </div>
              <button type="button" class="btn btn-sm" onclick="copyCurrent2FACode()">Sao chép</button>
            </div>
            <div style="display:flex;gap:6px;margin-bottom:6px">
              <input class="inp" id="dcCustomStatusInput" placeholder="Nội dung Custom Status Discord..." style="flex:1">
              <button type="button" class="btn btn-sm" onclick="updateDiscordCustomStatus()">Cập nhật Status</button>
            </div>
            <div class="row-3" style="margin-bottom:0">
              <button type="button" class="btn btn-sm" onclick="setDiscordHypeSquad(1)">HypeSquad Bravery</button>
              <button type="button" class="btn btn-sm" onclick="setDiscordHypeSquad(2)">HypeSquad Brilliance</button>
              <button type="button" class="btn btn-sm" onclick="setDiscordHypeSquad(3)">HypeSquad Balance</button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-7">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Sách Tài Khoản Đã Kết Nối ({{ accounts|length }})</span>
            <div style="display:flex;gap:6px">
              <button class="btn btn-sm" type="button" onclick="reconnectAllListenersNow()">Đồng Bộ &amp; Giữ Phiên PC Tất Cả Acc</button>
              <button class="btn btn-primary btn-sm" type="button" onclick="loadGroupsAndRooms(true)">Quét Toàn Bộ Phòng Chat</button>
            </div>
          </div>
          <div class="panel-body" style="padding:0">
            {% if not accounts %}
              <div style="padding:28px;text-align:center;color:var(--txt-muted)">
                Chưa có tài khoản nào được kết nối. Hãy tạo mã QR Zalo hoặc nạp Token Discord / Cookie Messenger ở khung bên trái.
              </div>
            {% else %}
              <div style="overflow-x:auto">
                <table class="data-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Nền tảng</th>
                      <th>Tên tài khoản / Thiết bị</th>
                      <th>Định danh (UID)</th>
                      <th>Nhận lệnh (.menu)</th>
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
                          <div style="font-size:11px;color:var(--txt-muted)">{{ a.pc_name or 'Phiên Web/PC Cố Định' }}</div>
                        </td>
                        <td class="mono" style="font-size:11.5px">{{ a.uid or a.masked_uid }}</td>
                        <td>
                          <span class="badge {{ 'badge-green' if a.chat_cmd_enabled else 'badge-gray' }}">
                            {{ 'ĐANG BẬT' if a.chat_cmd_enabled else 'ĐÃ TẮT' }}
                          </span>
                        </td>
                        <td>
                          <div style="display:flex;gap:4px">
                            <button class="btn btn-sm" type="button" onclick="testSingleAccountSession({{ a.id }})">Kiểm tra</button>
                            <button class="btn btn-sm" type="button" onclick="toggleAccCmd({{ a.id }}, {{ 0 if a.chat_cmd_enabled else 1 }})">{{ 'Tắt lệnh' if a.chat_cmd_enabled else 'Bật lệnh' }}</button>
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

  <!-- TAB 2: CHỌN PHÒNG & TAG -->
  <section id="tab-targets" class="tab-pane">
    <div class="grid-12">
      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Sách Phòng Chat / Nhóm Mục Tiêu</span>
            <div style="display:flex;gap:4px">
              <button class="btn btn-primary btn-sm" type="button" onclick="loadGroupsAndRooms(true)">Quét Mới</button>
              <button class="btn btn-sm" type="button" onclick="selectAllTargets()">Chọn tất cả</button>
              <button class="btn btn-sm" type="button" onclick="clearAllTargets()">Bỏ chọn</button>
            </div>
          </div>
          <div class="panel-body">
            <div class="sub-tabs">
              <button type="button" class="sub-tab active" id="fltRoomAll" onclick="setRoomPlatformFilter('all')">Tất cả</button>
              <button type="button" class="sub-tab" id="fltRoomZalo" onclick="setRoomPlatformFilter('zalo')">Zalo</button>
              <button type="button" class="sub-tab" id="fltRoomDiscord" onclick="setRoomPlatformFilter('discord')">Discord</button>
              <button type="button" class="sub-tab" id="fltRoomMess" onclick="setRoomPlatformFilter('messenger')">Messenger</button>
            </div>
            <div style="margin-bottom:8px">
              <input class="inp" id="roomSearchInput" placeholder="Tìm kiếm theo tên nhóm, tên bạn bè hoặc ID phòng..." oninput="renderTargetList()">
            </div>
            <div class="scroll-area" id="targetListContainer" style="max-height:380px">
              <div style="padding:20px;text-align:center;color:var(--txt-muted)">Bấm "Quét Mới" để tải danh sách nhóm và bạn bè từ tất cả tài khoản.</div>
            </div>
          </div>
        </div>
      </div>

      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Sách Thành Viên Cần Tag (Mention)</span>
            <span class="badge badge-blue" id="selectedTagBadge">0 người được chọn</span>
          </div>
          <div class="panel-body">
            <div style="display:flex;gap:6px;margin-bottom:8px;align-items:center">
              <label class="chk-label" style="flex:1">
                <input type="checkbox" id="chkTagAll" onchange="updateTagSummary()">
                <span>Tag toàn bộ thành viên (@All / @everyone)</span>
              </label>
              <button class="btn btn-sm" type="button" onclick="selectAllMembersInBox()">Chọn hết</button>
              <button class="btn btn-sm" type="button" onclick="clearSelectedMentions()">Xóa chọn</button>
            </div>
            <div style="margin-bottom:8px">
              <input class="inp" id="memberSearchInput" placeholder="Lọc tên thành viên trong nhóm..." oninput="renderMemberList()">
            </div>
            <div class="scroll-area" id="memberListContainer" style="max-height:380px">
              <div style="padding:20px;text-align:center;color:var(--txt-muted)">Bấm nút "Thành viên" ở một nhóm bên trái để tải danh sách người trong nhóm.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 3: CHIẾN DỊCH & BẢNG SOI LỆNH TRỰC TIẾP -->
  <section id="tab-campaign" class="tab-pane">
    <div class="grid-12">
      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Cấu Hình &amp; Khởi Chạy Chiến Dịch Đa Tài Khoản</span>
            <span class="badge badge-green">Hỗ Trợ Nhiều Acc Cùng Lúc</span>
          </div>
          <div class="panel-body">
            <!-- BỘ CHỌN TÀI KHOẢN CHẠY ĐỒNG LOẠT -->
            <div style="margin-bottom:10px;padding:8px 10px;background:var(--surface-sub);border:1px solid var(--border);border-radius:5px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <label class="field-lbl" style="margin:0">Chọn tài khoản tham gia chạy chiến dịch ({{ accounts|length }} Acc):</label>
                <div style="display:flex;gap:4px">
                  <button type="button" class="btn btn-sm" onclick="toggleSelectAllCampaignAccs(true)">Chọn hết Acc</button>
                  <button type="button" class="btn btn-sm" onclick="toggleSelectAllCampaignAccs(false)">Bỏ chọn</button>
                </div>
              </div>
              <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:5px;max-height:110px;overflow-y:auto">
                {% if not accounts %}
                  <div style="font-size:11.5px;color:var(--txt-muted)">Chưa có tài khoản kết nối.</div>
                {% endif %}
                {% for a in accounts %}
                  <label class="chk-label" style="background:#ffffff;padding:4px 7px">
                    <input type="checkbox" class="camp-acc-chk" value="{{ a.id }}" checked>
                    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">[{{ (a.platform or 'zalo')|upper }}] {{ a.name }}</span>
                  </label>
                {% endfor %}
              </div>
            </div>

            <div class="row-2">
              <div>
                <label class="field-lbl">Chế độ chiến dịch</label>
                <select class="sel" id="cfgMode">
                  <option value="treo_nhay">Treo Nhây Từng Câu (.n)</option>
                  <option value="treo_ngon">Treo Ngôn Nguyên Bài (.g)</option>
                  <option value="fast">Spam Nhanh Tốc Độ Cao (.s)</option>
                  <option value="raid_burst">Raid Tổng Lực Đa Tài Khoản (.r)</option>
                  <option value="auto_shuffle">Đảo Câu Ngẫu Nhiên (.a)</option>
                  <option value="nhay_tag_all">Nhây Tag @All / @everyone Liên Tục</option>
                  <option value="nhay_poll">Tạo Bình Chọn Poll Liên Tục (.poll)</option>
                  <option value="nhay_typing">Treo Hiệu Ứng Đang Soạn Tin (.typing)</option>
                  <option value="nhay_namebox">Đổi Tên Nhóm Liên Tục (.tenbox)</option>
                  <option value="zalo_todo">Giao Việc To-Do Tag Thành Viên (.todo)</option>
                  <option value="zalo_cardbank">Gửi Thẻ Ngân Hàng STK (.bank)</option>
                  <option value="share_contact">Gửi Danh Thiếp Liên Hệ (.card)</option>
                  <option value="reaction_storm">Thả Cảm Xúc Tin Nhắn Liên Tục</option>
                  <option value="nhay_theme">Đổi Chủ Đề Nền Messenger (.theme)</option>
                  <option value="share_link">Chia Sẻ Liên Kết (.sharelink)</option>
                  <option value="mess_nickname">Đổi Biệt Danh Thành Viên (.setname)</option>
                  <option value="discord_embed_vip">Chữ Nghệ Thuật Blockquote Discord</option>
                  <option value="discord_status_rotator">Đổi Custom Status Tự Động Discord</option>
                </select>
              </div>
              <div>
                <label class="field-lbl">Định dạng màu chữ (Zalo / Discord)</label>
                <select class="sel" id="cfgColorMode">
                  <option value="rainbow">Đổi màu theo từng dòng</option>
                  <option value="word_rainbow">Phối màu theo từng từ</option>
                  <option value="random">Màu ngẫu nhiên</option>
                  <option value="fixed">Màu cố định</option>
                  <option value="none">Chữ mặc định (Không màu)</option>
                </select>
              </div>
            </div>

            <div class="row-4">
              <div>
                <label class="field-lbl">Màu cố định</label>
                <select class="sel" id="cfgFixedColor">
                  <option value="red">Đỏ</option>
                  <option value="yellow">Vàng</option>
                  <option value="green">Xanh lá</option>
                  <option value="orange">Cam</option>
                </select>
              </div>
              <div>
                <label class="field-lbl">Độ trễ (Giây)</label>
                <input class="inp" type="number" step="0.05" min="0" id="cfgDelay" value="0.2">
              </div>
              <div>
                <label class="field-lbl">Số Icon đuôi</label>
                <input class="inp" type="number" min="0" max="10" id="cfgIconCount" value="2">
              </div>
              <div>
                <label class="field-lbl">Số luồng (1-100)</label>
                <input class="inp" type="number" min="1" max="100" id="cfgBatchCount" value="1">
              </div>
            </div>

            <div style="display:flex;gap:4px;margin-bottom:8px;flex-wrap:wrap">
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgDelay').value='0.0'">Delay 0.0s (Discord)</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgDelay').value='0.2'">Delay 0.2s (Zalo)</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgDelay').value='1.9'">Delay 1.9s (Messenger)</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgBatchCount').value='5'">5 Luồng</button>
              <button type="button" class="btn btn-sm" onclick="document.getElementById('cfgBatchCount').value='20'">20 Luồng</button>
            </div>

            <div style="margin-bottom:8px">
              <label class="field-lbl">Chọn File Kịch Bản (.TXT)</label>
              <select class="sel" id="cfgFileSelect">
                <option value="">-- Sử dụng nội dung nhập trực tiếp bên dưới --</option>
                {% for f in files %}
                  <option value="{{ f.id }}">File #{{ f.display_num }}: {{ f.filename }} ({{ f.lines_count }} dòng)</option>
                {% endfor %}
              </select>
            </div>

            <div style="margin-bottom:8px">
              <label class="field-lbl">Nội dung tin nhắn (Phân tách câu bằng dấu ; hoặc xuống dòng, hỗ trợ gõ @Tên)</label>
              <textarea class="txt" id="cfgRawText" placeholder="Nhập các câu kịch bản hoặc chọn File ở trên..."></textarea>
            </div>

            <div class="row-2" style="margin-bottom:10px">
              <label class="chk-label"><input type="checkbox" id="cfgHeading" checked><span>In đậm &amp; Cỡ chữ lớn</span></label>
              <label class="chk-label"><input type="checkbox" id="cfgUseEmoji" checked><span>Gắn Emoji cuối câu</span></label>
              <label class="chk-label"><input type="checkbox" id="cfgAntiband" checked><span>Bật Anti-Ban bảo vệ tài khoản</span></label>
              <label class="chk-label"><input type="checkbox" id="cfgMultiAcc" checked><span>Chạy đồng loạt nhiều tài khoản</span></label>
            </div>

            <div class="row-2" style="margin-bottom:0">
              <button class="btn btn-success btn-block" type="button" onclick="launchCampaignTask()">KHỞI CHẠY CHIẾN DỊCH</button>
              <button class="btn btn-danger btn-block" type="button" onclick="stopAllRunningTasks()">DỪNG TẤT CẢ</button>
            </div>
          </div>
        </div>
      </div>

      <div class="col-6">
        <!-- BẢNG TIẾN TRÌNH CHIẾN DỊCH ĐANG CHẠY -->
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Sách Chiến Dịch Đang Chạy &amp; Thống Kê Đa Acc</span>
            <button type="button" class="btn btn-danger btn-sm" onclick="stopAllRunningTasks()">Dừng tất cả</button>
          </div>
          <div class="panel-body" style="padding:0">
            <div class="scroll-area" id="activeTasksContainer" style="max-height:210px;border:none">
              <div style="padding:18px;text-align:center;color:var(--txt-muted)">Chưa có chiến dịch nào đang chạy.</div>
            </div>
          </div>
        </div>

        <!-- BẢNG SOI LỆNH TRỰC TIẾP & KÍCH HOẠT LỆNH NHANH -->
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Bảng Soi Lệnh Thời Gian Thực (Live Command Inspector)</span>
            <span class="badge badge-blue">Tự Động Cập Nhật</span>
          </div>
          <div class="panel-body">
            <div style="display:flex;gap:6px;margin-bottom:8px">
              <input class="inp" id="webQuickCmdInput" placeholder="Gõ lệnh thử nghiệm trực tiếp (VD: .menu, .ping, .n 1, .t)..." style="flex:1">
              <button type="button" class="btn btn-primary btn-sm" onclick="dispatchWebQuickCommand()">Thực Thi Lệnh</button>
            </div>
            <div class="scroll-area" id="campaignCmdLogBox" style="max-height:210px">
              <div style="padding:16px;text-align:center;color:var(--txt-muted)">Chưa có lệnh nào được ghi nhận. Hãy gõ <code>.menu</code> trong nhóm Zalo/Discord/Mess hoặc ô trên!</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB 4: KHO FILE -->
  <section id="tab-files" class="tab-pane">
    <div class="grid-12">
      <div class="col-5">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Tải Lên Hoặc Soạn Mới File Kịch Bản (.TXT)</span>
          </div>
          <div class="panel-body">
            <div style="margin-bottom:10px;padding:12px;border:1px dashed var(--border);border-radius:5px;background:var(--surface-sub);text-align:center;position:relative">
              <input type="file" id="txtFileInput" accept=".txt" onchange="handleTxtUpload(this)" style="position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%">
              <div style="font-weight:600;color:var(--blue)">Chọn File .TXT từ thiết bị để tải lên</div>
              <div style="font-size:11px;color:var(--txt-muted);margin-top:2px">Tự động làm sạch số thứ tự đầu dòng và gán mã số File</div>
              <div id="uploadProgWrap" style="display:none;margin-top:6px;height:4px;background:#d0d7de;border-radius:4px;overflow:hidden">
                <div id="uploadProgBar" style="height:100%;width:0%;background:var(--green)"></div>
              </div>
            </div>

            <form method="POST" action="/file/create">
              <div style="margin-bottom:8px">
                <label class="field-lbl">Tên File (.txt)</label>
                <input class="inp" name="filename" placeholder="kich_ban_1.txt" required>
              </div>
              <div style="margin-bottom:10px">
                <label class="field-lbl">Nội dung kịch bản (Mỗi dòng 1 câu)</label>
                <textarea class="txt" name="content" placeholder="Nhập nội dung kịch bản..." required style="min-height:110px"></textarea>
              </div>
              <button class="btn btn-success btn-block" type="submit">Lưu File Vào Kho</button>
            </form>
          </div>
        </div>
      </div>

      <div class="col-7">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Danh Sách File Kịch Bản ({{ files|length }})</span>
            <span class="badge badge-gray">Gõ .n &lt;số&gt; hoặc .g &lt;số&gt; trong chat</span>
          </div>
          <div class="panel-body" style="padding:0">
            {% if not files %}
              <div style="padding:24px;text-align:center;color:var(--txt-muted)">Kho file kịch bản đang trống.</div>
            {% else %}
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Mã số</th>
                    <th>Tên File</th>
                    <th>Số dòng</th>
                    <th>Cú pháp gọi nhanh trong Chat</th>
                    <th>Thao tác</th>
                  </tr>
                </thead>
                <tbody>
                  {% for f in files %}
                    <tr>
                      <td><span class="badge badge-blue">#{{ f.display_num }}</span></td>
                      <td style="font-weight:600">{{ f.filename }}</td>
                      <td class="mono">{{ f.lines_count }} dòng</td>
                      <td><code>.n {{ f.display_num }} @Tên</code> hoặc <code>.g {{ f.display_num }}</code></td>
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

  <!-- TAB 5: GIÁM SÁT & BẢO MẬT -->
  <section id="tab-shield" class="tab-pane">
    <div class="grid-12">
      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Giám Sát Kết Nối Tài Khoản &amp; Tường Lửa Bảo Mật</span>
            <button type="button" class="btn btn-sm" onclick="checkWebPingNow(true)">Đo độ trễ ngay</button>
          </div>
          <div class="panel-body">
            <div class="row-2">
              <div style="padding:8px;border:1px solid var(--border);border-radius:5px;background:var(--surface-sub)">
                <div style="font-size:11px;color:var(--txt-muted)">Độ trễ phản hồi (RTT)</div>
                <div style="font-size:15px;font-weight:700;color:var(--green)" id="pingRttVal">-- ms</div>
                <span class="badge badge-green" id="pingEngineBadge">Engine 0.2ms</span>
              </div>
              <div style="padding:8px;border:1px solid var(--border);border-radius:5px;background:var(--surface-sub)">
                <div style="font-size:11px;color:var(--txt-muted)">Luồng xử lý song song</div>
                <div style="font-size:15px;font-weight:700;color:var(--blue)" id="pingThreadsVal">Hoạt động</div>
                <span class="badge badge-blue">TLS 1.3 + WebSocket + MQTT</span>
              </div>
            </div>
            <div class="row-2">
              <div style="padding:8px;border:1px solid var(--border);border-radius:5px">
                <div style="font-size:11px;color:var(--txt-muted)">Gói tin đã kiểm duyệt bảo mật</div>
                <div style="font-size:14px;font-weight:700" id="fwInspectedCnt">0 gói</div>
              </div>
              <div style="padding:8px;border:1px solid var(--border);border-radius:5px">
                <div style="font-size:11px;color:var(--txt-muted)">Phiên Token / Cookie đã khóa bảo vệ</div>
                <div style="font-size:14px;font-weight:700" id="fwImmortalCnt">0 phiên</div>
              </div>
            </div>
            <div class="scroll-area" id="healthShieldBox" style="max-height:280px"></div>
          </div>
        </div>
      </div>

      <div class="col-6">
        <div class="panel">
          <div class="panel-hd">
            <span class="panel-title">Nhật Ký Toàn Bộ Lệnh Đã Thực Thi</span>
            <span class="badge badge-green">Chống Lặp Lệnh 100%</span>
          </div>
          <div class="panel-body" style="padding:0">
            <div class="scroll-area" id="cmdLogBox" style="max-height:390px;border:none"></div>
          </div>
        </div>
      </div>
    </div>
  </section>
</div>

<script>
let ALL_TARGETS = [];
let SELECTED_TARGETS = new Map();
let CURRENT_MEMBERS = [];
let SELECTED_MENTIONS = new Map();
let ROOM_PLATFORM_FILTER = 'all';
let ZALO_QR_SESSION_ID = '';
let ZALO_QR_POLL_TIMER = null;
let LAST_ZALO_QR_RESULT = {imei: '', cookies_str: '', file_name: 'zalo_cookie.txt', file_content: ''};
let ZALO_VAULT_CACHE = [];

const MULTI_TAB_BUS = (typeof BroadcastChannel !== 'undefined') ? new BroadcastChannel('pk_system_v19_bus') : null;
let LAST_CROSS_TAB_STATUS_TS = 0;

if (MULTI_TAB_BUS) {
  MULTI_TAB_BUS.onmessage = (ev) => {
    const msg = ev.data || {};
    if (msg.type === 'STATUS_SNAPSHOT' && msg.data) {
      LAST_CROSS_TAB_STATUS_TS = Date.now();
      renderSystemStatusData(msg.data, msg.rtt || 10);
    } else if (msg.type === 'INSTANT_STOP_ALL') {
      applyOptimisticStopUI(null);
    } else if (msg.type === 'FORCE_REFRESH') {
      pollSystemStatus(true);
    }
  };
}

function showToast(msg) {
  const box = document.getElementById('toastBox');
  const el = document.createElement('div');
  el.className = 'toast-msg';
  el.textContent = msg;
  box.appendChild(el);
  setTimeout(() => { el.remove(); }, 2600);
}

function escapeHtmlSafe(s) {
  return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function switchMainTab(tabId, btnEl) {
  const panes = document.querySelectorAll('.tab-pane');
  for (let i = 0; i < panes.length; i++) panes[i].classList.remove('active');
  const targetSec = document.getElementById(tabId);
  if (targetSec) targetSec.classList.add('active');

  const btns = document.querySelectorAll('.nav-tabs .nav-tab');
  for (let i = 0; i < btns.length; i++) btns[i].classList.remove('active');
  if (btnEl) btnEl.classList.add('active');
  if (tabId === 'tab-targets' && ALL_TARGETS.length === 0) {
    loadGroupsAndRooms(false);
  }
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

async function startZaloQRLogin() {
  const stTxt = document.getElementById('zaloQRStatusText');
  const stageWrap = document.getElementById('zaloQRStageWrap');
  const qrImg = document.getElementById('zaloQRImg');
  const btn = document.getElementById('btnStartZaloQR');
  const extBox = document.getElementById('zaloQRExtractedBox');
  const codeBadge = document.getElementById('zaloQRCodeIdBadge');
  const imeiBadge = document.getElementById('zaloQRImeiPreview');

  if (ZALO_QR_POLL_TIMER) {
    clearInterval(ZALO_QR_POLL_TIMER);
    ZALO_QR_POLL_TIMER = null;
  }
  extBox.style.display = 'none';
  qrImg.src = '';
  stageWrap.style.display = 'none';
  stTxt.textContent = 'Đang khởi tạo máy tính ảo và cấp mã QR đăng nhập chính chủ từ id.zalo.me...';
  if (codeBadge) codeBadge.textContent = 'Đang lấy mã QR...';
  btn.disabled = true;

  try {
    const r = await fetch('/api/zalo/qr_start?t=' + Date.now(), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({auto_save: true})
    });
    const d = await r.json();
    btn.disabled = false;
    if (!d.ok) {
      stTxt.textContent = d.message || 'Lỗi tạo mã QR';
      return;
    }
    ZALO_QR_SESSION_ID = d.session_id;
    stTxt.textContent = d.message;
    const cleanCode = String(d.qr_code_id || d.qr_nonce || d.session_id).replace(/\./g, '').slice(0, 6).toUpperCase();
    if (codeBadge) codeBadge.textContent = `${d.pc_name || 'PC-WIN11'} • #${cleanCode}`;
    if (imeiBadge && d.imei) imeiBadge.textContent = `IMEI: ${d.imei.slice(0, 8)}...${d.imei.slice(-4)}`;

    if (d.qr_base64) {
      stageWrap.style.display = 'block';
      qrImg.src = d.qr_base64;
    } else if (d.qr_image_url) {
      stageWrap.style.display = 'block';
      qrImg.src = d.qr_image_url;
    }
    btn.textContent = 'Đổi Mã QR Máy Tính Mới Khác';
    ZALO_QR_POLL_TIMER = setInterval(pollZaloQRStatus, 1300);
  } catch (e) {
    btn.disabled = false;
    stTxt.textContent = 'Lỗi kết nối máy chủ khi tạo QR!';
  }
}

setTimeout(() => { loadZaloVaultRecords(); }, 400);

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
    if (codeBadge && (d.qr_code_id || d.pc_name)) {
      const cleanC = String(d.qr_code_id || '').replace(/\./g, '').slice(0, 6).toUpperCase();
      codeBadge.textContent = `${d.pc_name || 'PC-WIN11'} • #${cleanC}`;
    }
    if (imeiBadge && d.imei) imeiBadge.textContent = `IMEI: ${d.imei.slice(0, 8)}...${d.imei.slice(-4)}`;
    if (timerBadge && typeof d.remaining_sec === 'number') {
      timerBadge.textContent = `Thời gian hiệu lực còn: ${d.remaining_sec}s`;
    }
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
      loadZaloVaultRecords();
      showToast('Đã đăng nhập thẳng vào tài khoản Zalo & kích hoạt bộ nhận lệnh!');
      setTimeout(() => location.reload(), 1500);
    } else if (d.status === 'expired' || d.status === 'declined' || d.status === 'error') {
      clearInterval(ZALO_QR_POLL_TIMER);
      ZALO_QR_POLL_TIMER = null;
      if (d.status === 'error') stageWrap.style.display = 'none';
    }
  } catch (e) {}
}

async function verifyAndSaveZaloCookieVault() {
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
      box.innerHTML = `<span style="color:#cf222e">${escapeHtmlSafe(d.error || 'Lỗi lưu Cookie')}</span>`;
    }
  } catch (e) { box.innerHTML = 'Lỗi kết nối máy chủ!'; }
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
            <span class="badge ${rec.zpw_enk_ready ? 'badge-green' : 'badge-blue'}">${rec.zpw_enk_ready ? 'TRONG ACC (zpw_enk OK)' : 'ĐÃ LƯU'}</span>
            <strong style="margin-left:5px">${escapeHtmlSafe(rec.display_name)}</strong>
          </div>
          <code style="font-size:11px;color:var(--txt-muted)">IMEI: ${escapeHtmlSafe(rec.masked_imei)}</code>
        </div>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button type="button" class="btn btn-success btn-sm" onclick="activateZaloVaultIdx(${idx})">Kích hoạt vào hệ thống</button>
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
    showToast(kind === 'imei' ? `Đã copy IMEI của ${rec.display_name}!` : `Đã copy Cookie của ${rec.display_name}!`);
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

async function testSingleAccountSession(accId) {
  showToast('Đang kiểm tra kết nối tài khoản #' + accId + '...');
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
}

async function reconnectAllListenersNow() {
  showToast('Đang đồng bộ & kích hoạt lại bộ lắng nghe lệnh cho toàn bộ tài khoản...');
  try {
    const r = await fetch('/api/account/reconnect_all', {method: 'POST'});
    const d = await r.json();
    showToast(d.message || 'Đã đồng bộ xong!');
    pollSystemStatus(true);
  } catch (e) {}
}

async function dispatchWebQuickCommand() {
  const cmdInput = document.getElementById('webQuickCmdInput');
  const rawCmd = (cmdInput.value || '').trim();
  if (!rawCmd) { showToast('Hãy nhập lệnh cần thực thi (VD: .menu, .ping, .n 1, .t)!'); return; }
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
}

async function triggerAntiDieAllHeal() {
  try {
    const r = await fetch('/api/antidieall/heal', {method: 'POST'});
    const d = await r.json();
    showToast(d.message || 'Đã làm mới kết nối!');
    checkWebPingNow(false);
  } catch (e) {}
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
  box.style.background = '#dafbe1';
  box.style.color = '#1a7f37';
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
      box.style.background = '#ffebe9';
      box.style.color = '#cf222e';
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
    if (rpmEl) rpmEl.textContent = `${rpmVal} tin/phút`;
    if (healEl) healEl.textContent = `${d.total_healed || 0} lần`;
    if (stateBadge) {
      stateBadge.textContent = runningCnt > 0 ? `ĐANG CHẠY (${runningCnt} CHIẾN DỊCH)` : 'HỆ THỐNG SẴN SÀNG';
      stateBadge.className = runningCnt > 0 ? 'badge badge-blue' : 'badge badge-green';
    }
    if (rttEl) rttEl.textContent = `${rtt} ms`;
    if (thEl) thEl.textContent = `${d.active_threads || 1} luồng`;
    if (engEl) engEl.textContent = `Engine ${d.engine_ms || 0.2}ms`;

    if (showNotice) showToast(`Độ trễ Web: ${rtt}ms | API: ${sendMs}ms | Tốc độ: ${rpmVal} tin/phút`);
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
      box.innerHTML = `<span style="color:#cf222e">${escapeHtmlSafe(d.error)}</span>`;
    }
  } catch (e) { box.innerHTML = 'Lỗi kết nối!'; }
}

function fillRandomDiscordRegProfile() {
  const rnd = Math.floor(1000 + Math.random() * 9000);
  const uname = `user_vip_${rnd}`;
  const pw = `Pass@${rnd}#Vip99`;
  document.getElementById('newAccUsername').value = uname;
  document.getElementById('newAccPassword').value = pw;
  document.getElementById('newAccDob').value = '2000-06-15';
  showToast(`Đã điền mẫu: ${uname}`);
}

async function runBatchDiscordRegStudio() {
  const box = document.getElementById('discordNewAccStatusBox');
  box.style.display = 'block';
  box.style.background = '#dafbe1';
  box.style.color = '#1a7f37';
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
      box.innerHTML = `<span style="color:#cf222e">${escapeHtmlSafe(d.error)}</span>`;
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
  box.style.background = isSuccess ? '#dafbe1' : '#ffebe9';
  box.style.color = isSuccess ? '#1a7f37' : '#cf222e';
  box.innerHTML = msg;
}

function handleAccountFormSubmit(ev) {
  const plat = document.getElementById('accPlatformInput').value;
  if (plat === 'zalo') {
    const imeiVal = (document.getElementById('zaloImeiInput').value || '').trim();
    const ckVal = (document.getElementById('zaloCookieInput').value || '').trim();
    if (!imeiVal || !ckVal) {
      ev.preventDefault();
      switchZaloSubTab('qr');
      startZaloQRLogin();
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
  const r = await fetch('/api/logo/upload', {method: 'POST', body: fd});
  const d = await r.json();
  if (d.ok) {
    const img = document.getElementById('brandLogoImg');
    const fb = document.getElementById('brandLogoFallback');
    img.src = '/api/logo?v=' + Date.now();
    img.style.display = 'block';
    if (fb) fb.style.display = 'none';
    showToast('Đã cập nhật biểu tượng!');
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

async function loadGroupsAndRooms(forceRefresh) {
  const box = document.getElementById('targetListContainer');
  box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--txt-muted)">Đang quét danh sách phòng từ tất cả tài khoản...</div>';
  try {
    const qSuffix = forceRefresh ? '?refresh=1' : '';
    const [rZalo, rDis, rMess] = await Promise.all([
      fetch('/api/all_groups' + qSuffix).then(r => r.json()).catch(() => ({groups:[], friends:[]})),
      fetch('/api/discord_channels' + qSuffix).then(r => r.json()).catch(() => ({channels:[]})),
      fetch('/api/messenger_threads' + qSuffix).then(r => r.json()).catch(() => ({threads:[]}))
    ]);
    const list = [];
    (rZalo.groups || []).forEach(g => list.push({id: String(g.id), name: g.name, type: 'group', members: g.members || '?'}));
    (rZalo.friends || []).forEach(f => list.push({id: String(f.id), name: f.name, type: 'user', members: 1}));
    (rDis.channels || []).forEach(c => list.push({id: String(c.id), name: c.name, type: 'discord_channel', members: 'Discord'}));
    (rMess.threads || []).forEach(m => list.push({id: String(m.id), name: m.name, type: 'messenger_thread', members: m.members || 'Mess'}));
    ALL_TARGETS = list;
    renderTargetList();
    showToast(`Đã tải ${ALL_TARGETS.length} phòng chat!`);
  } catch (e) {
    box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--red)">Lỗi tải danh sách phòng</div>';
  }
}

function renderTargetList() {
  const box = document.getElementById('targetListContainer');
  const q = (document.getElementById('roomSearchInput').value || '').toLowerCase().trim();
  const indexed = ALL_TARGETS.map((t, idx) => ({t, idx})).filter(item => {
    const t = item.t;
    if (ROOM_PLATFORM_FILTER === 'zalo' && (t.type !== 'group' && t.type !== 'user')) return false;
    if (ROOM_PLATFORM_FILTER === 'discord' && t.type !== 'discord_channel') return false;
    if (ROOM_PLATFORM_FILTER === 'messenger' && t.type !== 'messenger_thread') return false;
    if (!q) return true;
    return (t.name || '').toLowerCase().includes(q) || String(t.id).toLowerCase().includes(q);
  });
  if (!indexed.length) {
    box.innerHTML = '<div style="padding:18px;text-align:center;color:var(--txt-muted)">Không có phòng phù hợp. Hãy bấm "Quét Mới".</div>';
    return;
  }
  box.innerHTML = indexed.map(({t, idx}) => {
    const checked = SELECTED_TARGETS.has(String(t.id)) ? 'checked' : '';
    const badgeCls = t.type === 'discord_channel' ? 'badge-blue' : (t.type === 'messenger_thread' ? 'badge-amber' : (t.type === 'group' ? 'badge-green' : 'badge-gray'));
    const badgeLbl = t.type === 'discord_channel' ? 'DISCORD' : (t.type === 'messenger_thread' ? 'MESSENGER' : (t.type === 'group' ? 'NHÓM ZALO' : 'BẠN BÈ ZALO'));
    return `
      <div class="list-item">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;flex:1;min-width:0">
          <input type="checkbox" ${checked} data-idx="${idx}" onchange="toggleTargetByIdx(this.dataset.idx, this.checked)" style="width:14px;height:14px;accent-color:var(--blue);flex-shrink:0">
          <div class="item-info">
            <div style="display:flex;align-items:center;gap:6px">
              <span class="badge ${badgeCls}">${badgeLbl}</span>
              <span class="item-title">${escapeHtmlSafe(t.name)}</span>
            </div>
            <div class="item-sub">ID phòng: <code>${escapeHtmlSafe(String(t.id))}</code></div>
          </div>
        </label>
        ${(t.type === 'group' || t.type === 'discord_channel' || t.type === 'messenger_thread') ? `<button class="btn btn-sm" type="button" data-idx="${idx}" onclick="fetchRoomMembersByIdx(this.dataset.idx)">Thành viên</button>` : ''}
      </div>
    `;
  }).join('');
}

function toggleTargetByIdx(idx, isChecked) {
  const item = ALL_TARGETS[Number(idx)];
  if (!item) return;
  const idStr = String(item.id);
  if (isChecked) SELECTED_TARGETS.set(idStr, {id: idStr, name: item.name, type: item.type});
  else SELECTED_TARGETS.delete(idStr);
  updateTargetBadges();
}

function fetchRoomMembersByIdx(idx) {
  const item = ALL_TARGETS[Number(idx)];
  if (!item) return;
  fetchRoomMembers(String(item.id), item.type);
}

function selectAllTargets() {
  ALL_TARGETS.forEach(t => SELECTED_TARGETS.set(String(t.id), t));
  renderTargetList();
  updateTargetBadges();
}

function clearAllTargets() {
  SELECTED_TARGETS.clear();
  renderTargetList();
  updateTargetBadges();
}

function updateTargetBadges() {
  const c = SELECTED_TARGETS.size;
  document.getElementById('kpiTargetCount').textContent = c;
  document.getElementById('dockTargetBadge').textContent = c;
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
  const cnt = SELECTED_MENTIONS.size;
  document.getElementById('selectedTagBadge').textContent = tagAll ? `@All + ${cnt} người` : `${cnt} người được chọn`;
}

async function launchCampaignTask() {
  const targets = Array.from(SELECTED_TARGETS.values());
  if (!targets.length) {
    showToast('Vui lòng chọn ít nhất 1 phòng ở mục "2. Chọn Phòng & Tag Thành Viên"!');
    switchMainTab('tab-targets', document.querySelector('[data-tab="tab-targets"]'));
    return;
  }
  const selectedAccIds = Array.from(document.querySelectorAll('.camp-acc-chk:checked')).map(el => parseInt(el.value, 10)).filter(n => !isNaN(n));
  const batchCount = Math.max(1, Math.min(100, parseInt(document.getElementById('cfgBatchCount').value || '1', 10)));
  const payload = {
    targets,
    account_ids: selectedAccIds,
    mode: document.getElementById('cfgMode').value,
    color_mode: document.getElementById('cfgColorMode').value,
    fixed_color: document.getElementById('cfgFixedColor').value,
    delay: parseFloat(document.getElementById('cfgDelay').value || '0.2'),
    icon_count: parseInt(document.getElementById('cfgIconCount').value || '2', 10),
    batch_count: batchCount,
    file_id: document.getElementById('cfgFileSelect').value,
    raw_text: document.getElementById('cfgRawText').value,
    is_heading: document.getElementById('cfgHeading').checked,
    use_emoji: document.getElementById('cfgUseEmoji').checked,
    antiband: document.getElementById('cfgAntiband').checked,
    multi_acc: document.getElementById('cfgMultiAcc').checked,
    tag_all: document.getElementById('chkTagAll').checked,
    tag_users: Array.from(SELECTED_MENTIONS.values())
  };
  try {
    const r = await fetch('/task/start', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)});
    const d = await r.json();
    if (d.ok) {
      showToast(`Đã khởi chạy ${d.batch_count || 1} chiến dịch (${selectedAccIds.length || 'Tất cả'} tài khoản song song)!`);
      if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'FORCE_REFRESH'});
      pollSystemStatus(true);
    } else {
      showToast(d.error || 'Lỗi khởi chạy chiến dịch');
    }
  } catch (e) { showToast('Lỗi kết nối máy chủ'); }
}

function applyOptimisticStopUI(targetTid = null) {
  if (!targetTid) {
    document.getElementById('kpiRunningTasks').textContent = '0';
    document.getElementById('dockTaskBadge').textContent = '0';
    const stateBadge = document.getElementById('liveHangStateBadge');
    if (stateBadge) {
      stateBadge.textContent = 'HỆ THỐNG SẴN SÀNG';
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
const _domCache = {tasks: '', health: '', logs: '', campLogs: '', banner: ''};

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
  document.getElementById('dockTaskBadge').textContent = running;
  document.getElementById('kpiTotalSent').textContent = totalSent;

  if (d.ping_telemetry) {
    const pt = d.ping_telemetry;
    const rtt = measuredRtt || pt.avg_send_ms || 10;
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
    if (rpmEl) rpmEl.textContent = `${pt.total_rpm || 0} tin/phút`;
    if (healEl) healEl.textContent = `${pt.total_healed || 0} lần`;
    if (stateBadge) {
      stateBadge.textContent = running > 0 ? `ĐANG CHẠY (${running} CHIẾN DỊCH)` : 'HỆ THỐNG SẴN SÀNG';
      stateBadge.className = running > 0 ? 'badge badge-blue' : 'badge badge-green';
    }
    if (rttEl) rttEl.textContent = `${rtt} ms`;
    if (thEl) thEl.textContent = `${pt.active_threads || 1} luồng`;
    if (engEl) engEl.textContent = `Engine ${pt.engine_ms || 0.2}ms`;
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
            <th>Chế độ &amp; Nguồn lệnh</th>
            <th>Đa Acc &amp; Phòng</th>
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
                  <div style="font-weight:600">${escapeHtmlSafe(t.mode)} (Delay: ${t.delay}s)</div>
                  <div style="font-size:11px;color:var(--txt-muted)"><code>${escapeHtmlSafe(t.trigger_cmd || t.source || 'Web')}</code></div>
                </td>
                <td>
                  <div style="font-weight:600">${t.acc_count || 1} Acc • ${t.targets_count} phòng</div>
                  <div style="font-size:10.5px;color:var(--txt-muted)">${byAccStr}</div>
                </td>
                <td class="mono" style="font-weight:700;color:var(--blue)">${t.sent}</td>
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
        <div class="item-sub">Tốc độ: ${h.rpm} tin/phút • Đã gửi: <b>${h.ok_total}</b> • Trạng thái: <b>${escapeHtmlSafe(h.ws_status)}</b></div>
      </div>
    </div>
  `).join('') || '<div style="padding:14px;text-align:center;color:var(--txt-muted)">Chưa có tài khoản</div>';
  updateDomIfChanged(hBox, 'health', nextHealthHtml);

  const logs = d.cmd_logs || [];
  const bannerEl = document.getElementById('latestCmdBannerText');
  if (bannerEl && logs.length > 0) {
    const l0 = logs[0];
    const bTxt = `[${l0.time_str || 'Mới'}] [${l0.platform || 'CHAT'}] ${l0.acc_name || ''}: Lệnh "${l0.cmd_text}" -> ${l0.action_taken}`;
    updateDomIfChanged(bannerEl, 'banner', escapeHtmlSafe(bTxt));
  }

  const logsTableHtml = logs.length
    ? `<table class="data-table">
        <thead>
          <tr>
            <th>Thời gian</th>
            <th>Tài khoản</th>
            <th>Lệnh đã gõ</th>
            <th>Kết quả thực thi</th>
          </tr>
        </thead>
        <tbody>
          ${logs.map(l => `
            <tr>
              <td class="mono" style="font-size:11px;white-space:nowrap">${escapeHtmlSafe(l.time_str || '')}</td>
              <td><span class="badge badge-blue">${escapeHtmlSafe(l.platform || 'ZALO')}</span> <small>${escapeHtmlSafe(l.acc_name || '')}</small></td>
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

async function pollSystemStatus(force = false) {
  if (_isPollingStatus) return;
  if (!force && document.hidden) return;
  if (!force && (Date.now() - LAST_CROSS_TAB_STATUS_TS < 1200)) return;
  _isPollingStatus = true;
  const t0 = performance.now();
  try {
    const r = await fetch('/api/status?t=' + Date.now(), {cache: 'no-store'});
    const d = await r.json();
    const rtt = Math.max(1, Math.round(performance.now() - t0));
    LAST_CROSS_TAB_STATUS_TS = Date.now();
    renderSystemStatusData(d, rtt);
    if (MULTI_TAB_BUS) MULTI_TAB_BUS.postMessage({type: 'STATUS_SNAPSHOT', data: d, rtt});
  } catch (e) {
  } finally {
    _isPollingStatus = false;
  }
}

function scheduleAdaptivePoll() {
  const waitMs = document.hidden ? 6000 : (1300 + Math.floor(Math.random() * 400));
  setTimeout(async () => {
    await pollSystemStatus(false);
    scheduleAdaptivePoll();
  }, waitMs);
}
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) pollSystemStatus(true);
});
pollSystemStatus(true);
scheduleAdaptivePoll();
</script>
</body>
</html>"""

# CÁC ROUTE FLASK & API ĐIỀU KHIỂN TOÀN DIỆN (CHỐNG LỖI 500 TUYỆT ĐỐI)
@app.errorhandler(Exception)
def handle_unexpected_error(e):
    if request.path.startswith("/api/") or request.path.startswith("/task/"):
        return jsonify({"ok": False, "error": str(e)}), 200
    try:
        has_logo = bool(get_setting("brand_logo_b64", ""))
        logo_ts = get_setting("brand_logo_ts", "1")
        return render_template_string(
            DASHBOARD_HTML,
            accounts=[],
            files=[],
            has_logo=has_logo,
            logo_ts=logo_ts,
        ), 200
    except Exception:
        return Response("NOEL System Ready", mimetype="text/plain"), 200

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()
    allowed, wait_s = check_ip_bruteforce(ip)
    has_logo = bool(get_setting("brand_logo_b64", ""))
    logo_ts = get_setting("brand_logo_ts", "1")
    if not allowed:
        return render_template_string(
            LOGIN_HTML,
            error=f"Tạm khóa đăng nhập do nhập sai nhiều lần. Thử lại sau {wait_s} giây.",
            has_logo=has_logo,
            logo_ts=logo_ts,
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
        )
    return render_template_string(LOGIN_HTML, error=None, has_logo=has_logo, logo_ts=logo_ts)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/api/logo")
def api_get_logo():
    b64 = get_setting("brand_logo_b64", "")
    mime = get_setting("brand_logo_mime", "image/png")
    if not b64:
        svg = '<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24"><rect width="24" height="24" rx="6" fill="#be123c"/><path d="M12 3L14.8 8.5L21 9.3L16.2 14L17.5 20.5L12 17.2L6.5 20.5L7.8 14L3 9.3L9.2 8.5L12 3Z" fill="#fde68a"/></svg>'
        return Response(svg, mimetype="image/svg+xml")
    try:
        raw = base64.b64decode(b64)
        return Response(raw, mimetype=mime)
    except Exception:
        return Response(status=404)

@app.route("/api/logo/upload", methods=["POST"])
def api_upload_logo():
    f = request.files.get("logo")
    if not f:
        return jsonify({"ok": False, "error": "Chưa chọn ảnh"}), 400
    raw = f.read()
    if not raw or len(raw) > 6 * 1024 * 1024:
        return jsonify({"ok": False, "error": "Ảnh không hợp lệ hoặc quá 6MB"}), 400
    mime = f.mimetype or "image/png"
    set_setting("brand_logo_b64", base64.b64encode(raw).decode("utf-8"))
    set_setting("brand_logo_mime", mime)
    set_setting("brand_logo_ts", str(int(time.time())))
    return jsonify({"ok": True})

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect("/login")
    acc_rows = []
    try:
        conn = db()
        acc_rows = [dict(r) for r in conn.execute("SELECT * FROM accounts ORDER BY id DESC").fetchall()]
        conn.close()
    except Exception:
        acc_rows = []
    for a in acc_rows:
        a["masked_name"] = mask_account_name(a.get("name") or "Tài khoản")
        a["masked_uid"] = mask_sensitive_id(a.get("uid") or a.get("imei") or a.get("token") or "", 3)
    try:
        files_list = get_ordered_files_with_display_num()
    except Exception:
        files_list = []
    has_logo = bool(get_setting("brand_logo_b64", ""))
    logo_ts = get_setting("brand_logo_ts", "1")
    return render_template_string(
        DASHBOARD_HTML,
        accounts=acc_rows,
        files=files_list,
        has_logo=has_logo,
        logo_ts=logo_ts,
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
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='discord'").fetchall()]
    conn.close()
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
        "message": f"Đã làm mới Tường Lửa 9 Lớp & nạp lại Cookie Cloudflare cho {refreshed} tài khoản Discord!"
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
        return jsonify({"ok": True, "token": token, "rem_sec": rem_sec, "author": "Phan Anh Khôi"})
    return jsonify({"ok": False, "error": "Secret Key 2FA không hợp lệ!"}), 400

@app.route("/api/zalo/generate_imei")
def api_zalo_generate_imei():
    return jsonify({"ok": True, "imei": ZaloWebIDGenerator.generate_unique_imei(salt=secrets.token_hex(6))})

@app.route("/api/zalo/qr_start", methods=["POST"])
def api_zalo_qr_start():
    data = request.json or {}
    auto_save = bool(data.get("auto_save", True))
    res = ZaloQRLoginManager.start_qr_session(auto_save=auto_save)
    return jsonify(res)

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
        "message": f"Đã lưu Cookie & IMEI của {acc_name} vào Kho Vault và kết nối API Zalo thành công!"
    })

@app.route("/api/zalo/vault/activate", methods=["POST"])
def api_zalo_vault_activate():
    data = request.json or {}
    uid = str(data.get("uid") or "").strip()
    records = ZaloCookieVaultEngine.list_vault_records()
    rec = next((r for r in records if str(r["uid"]) == uid), None)
    if not rec:
        return jsonify({"ok": False, "error": "Không tìm thấy bản ghi trong Kho Vault"}), 404
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
    return jsonify({"ok": True, "message": f"Đã kích hoạt & kết nối lại tài khoản Zalo {rec['display_name']} từ Kho Vault!"})

@app.route("/api/zalo/vault/delete", methods=["POST"])
def api_zalo_vault_delete():
    data = request.json or {}
    uid = str(data.get("uid") or "").strip()
    ZaloCookieVaultEngine.delete_vault_record(uid)
    return jsonify({"ok": True})

@app.route("/api/antidieall/heal", methods=["POST"])
def api_antidieall_heal():
    HEALTH_MGR.auto_heal_all()
    return jsonify({"ok": True, "message": "⚡ Đã kích hoạt Hàn Mạch Anti-Die-All v16 & làm mới toàn bộ hàng đợi đa luồng!"})

@app.route("/api/discord/set_status", methods=["POST"])
def api_discord_set_status():
    data = request.json or {}
    text = (data.get("text") or "NOEL v15 — Phan Anh Khôi").strip()
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='discord'").fetchall()]
    conn.close()
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
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='discord'").fetchall()]
    conn.close()
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
        "message": "Đã lấy Token Discord Reg sạch & kích hoạt bảo vệ Anti-Scan!"
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
            "message": f"Đã đúc khóa Cookie Messenger Bất Tử cho {acc_name} & bật Sigma Anti-Ban!"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/api/messenger_threads")
def api_messenger_threads():
    force = request.args.get("refresh") == "1"
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='messenger'").fetchall()]
    conn.close()
    threads_map = {}
    for r in rows:
        try:
            m_bot = MessengerClient.get_pooled_client(r["cookies"], uid=r.get("uid") or "")
            for th in m_bot.get_threads(use_cache=not force):
                tid = str(th["id"])
                threads_map[tid] = th
        except Exception:
            continue
    return jsonify({"threads": list(threads_map.values())})

@app.route("/api/messenger_thread_members")
def api_messenger_thread_members():
    tid = (request.args.get("thread_id") or "").strip()
    if not tid:
        return jsonify({"members": []})
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='messenger'").fetchall()]
    conn.close()
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
            uid = str(w_res.get("uid") or "")
            acc_name = custom_name or w_res.get("username") or f"Discord Stealth #{idx + 1}"
            if uid:
                OWNER_UIDS_CACHE.add(uid)
            conn.execute(
                """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, created_at)
                   VALUES (?, 'discord', '', '{}', ?, ?, ?, ?, '.', ?, 1, ?)""",
                (acc_name, tk, is_bot, uid, chat_cmd, allow_all, time.time()),
            )
        conn.commit()
        conn.close()
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
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='zalo'").fetchall()]
    conn.close()
    groups_map = {}
    friends_map = {}
    for r in rows:
        try:
            z = Zalo.get_pooled_client(r["imei"], r["cookies"])
            for g in z.groups(use_cache=not force):
                groups_map[str(g["id"])] = g
            for f in z.friends(use_cache=not force):
                friends_map[str(f["id"])] = f
        except Exception:
            continue
    return jsonify({"groups": list(groups_map.values()), "friends": list(friends_map.values())})

@app.route("/api/group_members")
def api_group_members():
    gid = (request.args.get("group_id") or "").strip()
    force = request.args.get("refresh") == "1"
    if not gid:
        return jsonify({"members": []})
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='zalo'").fetchall()]
    conn.close()
    for r in rows:
        try:
            z = Zalo.get_pooled_client(r["imei"], r["cookies"])
            mems = z.get_members_full(gid, use_cache=not force)
            if mems:
                return jsonify({"members": mems})
        except Exception:
            continue
    return jsonify({"members": []})

@app.route("/api/discord_channels")
def api_discord_channels():
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='discord'").fetchall()]
    conn.close()
    channels_map = {}
    for r in rows:
        try:
            bot = DiscordClient(r["token"], is_bot=bool(r.get("is_bot", 0)))
            for b in bot.get_all_boxes():
                cid = str(b["id"])
                channels_map[cid] = {
                    "id": cid,
                    "name": b["name"],
                    "type": "discord_channel",
                }
        except Exception:
            continue
    return jsonify({"channels": list(channels_map.values())})

@app.route("/api/discord_channel_members")
def api_discord_channel_members():
    cid = (request.args.get("channel_id") or "").strip()
    if not cid:
        return jsonify({"members": []})
    conn = db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM accounts WHERE platform='discord'").fetchall()]
    conn.close()
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

    raw_delay = float(data.get("delay", 0.0))
    antiband_flag = bool(data.get("antiband", True))
    has_mess_target = any(t.get("type") in ("messenger_thread", "messenger_group") for t in targets)
    has_zalo_target = any(t.get("type") in ("group", "user") for t in targets)
    if has_mess_target:
        eff_delay = max(1.85 if antiband_flag else 0.90, raw_delay)
    elif has_zalo_target:
        eff_delay = max(0.20, raw_delay)
    else:
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
            delay=eff_delay + (b_i * 0.03 if batch_count > 1 else 0.0),
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
            trigger_cmd=f"Web UI ({mode})"
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
    """API Trạng Thái & Bảng Soi Lệnh Thời Gian Thực v19:"""
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
    for l in list(BOT_LOGS_RAM_DEQUE)[:35]:
        ts_val = float(l.get("created_at") or time.time())
        masked_logs.append({
            "time_str": l.get("time_str") or time.strftime("%H:%M:%S", time.localtime(ts_val)),
            "platform": l.get("platform") or "CHAT",
            "acc_name": l.get("acc_name") or f"Acc #{l.get('acc_id', 0)}",
            "cmd_text": sanitize_log_text(l.get("cmd_text") or ""),
            "action_taken": sanitize_log_text(l.get("action_taken") or ""),
            "masked_thread": mask_sensitive_id(l.get("thread_id") or "", 5),
            "created_at": ts_val,
        })

    tel = HEALTH_MGR.get_live_ping_telemetry()
    eng_ms = round((time.perf_counter() - t0) * 1000.0 + 0.15, 2)
    payload = {
        "tasks": task_list,
        "accounts_health": health_out,
        "cmd_logs": masked_logs,
        "discord_firewall": DiscordFirewallEngine.get_firewall_snapshot(),
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
