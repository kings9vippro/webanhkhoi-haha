"""
zalo_login.py — Module Đăng Nhập QR Máy Tính Zalo Chính Chủ & Khóa Phiên Trong Tài Khoản (v26)
Tác giả: Phan Anh Khôi (Rike)
Tính năng cốt lõi:
1. Tạo mã QR Máy Tính Zalo chính chủ từ `id.zalo.me` (`continue=https://zalo.me/pc`).
2. Sau khi người dùng quét mã QR và bấm "Đồng ý / Đăng nhập" trên điện thoại:
   - Đi theo từng bước Redirect (`allow_redirects=False`) thu hoạch trọn vẹn Cookie `zpw_sek`.
   - Khởi tạo phiên Máy Tính (`computer_name="Web"`, `client_version=645`, `type=30`) qua `getServerInfo` và `getLoginInfo` (AES-CBC `ZaloPCParamsEncryptor` v2).
   - BẮT BUỘC KIỂM TRA XÁC THỰC (`verify_zalo_pc_device_logged_in_account`):
     + Phải giải mã thành công khóa `zpw_enk` và `uid` thật.
     + Phải gọi thử nghiệm thành công API nội bộ (`getlg/v4` hoặc `getServerInfo`) chứng minh thiết bị Máy Tính của mã QR đó ĐÃ NẰM TRONG TÀI KHOẢN ZALO của người dùng!
     + Nếu thiết bị Máy Tính KHÔNG nằm trong tài khoản Zalo (hoặc thiếu `zpw_enk` / `zpw_sek`), TUYỆT ĐỐI KHÔNG TRẢ VỀ Cookie và IMEI ảo/die!
3. Tự động khởi chạy luồng `ZaloPCSessionKeeper` (WebSocket `wss://ws1.chat.zalo.me` + nhịp tim Keep-Alive 24/7) để giữ chặt máy tính ở trong mục "Thiết bị đang đăng nhập" của tài khoản Zalo, không bao giờ tự chạy đi đâu hay tự thoát!
"""

import os
import re
import ssl
import time
import uuid
import json
import base64
import socket
import struct
import hashlib
import secrets
import inspect
import asyncio
import threading
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

        class AES:
            MODE_CBC = 2
            block_size = 16

            @staticmethod
            def new(key, mode, iv=None):
                iv_b = iv if iv is not None else bytes(16)
                class _CBCWrap:
                    def __init__(self, k, i):
                        self._c = _Cipher(_alg.AES(k), _modes.CBC(i))
                    def encrypt(self, data):
                        enc = self._c.encryptor()
                        return enc.update(data) + enc.finalize()
                    def decrypt(self, data):
                        dec = self._c.decryptor()
                        return dec.update(data) + dec.finalize()
                return _CBCWrap(key, iv_b)


class LoginQRCallbackEventType:
    QRCodeGenerated = "QRCodeGenerated"
    QRCodeExpired = "QRCodeExpired"
    QRCodeScanned = "QRCodeScanned"
    QRCodeDeclined = "QRCodeDeclined"
    GotLoginInfo = "GotLoginInfo"


class ZaloPCParamsEncryptor:
    """Bộ mã hóa tham số đăng nhập Zalo PC/Web chuẩn giao thức zca-js v2 (client_version=645, type=30)."""
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


class ZaloPCSessionKeeper:
    """Bộ Giữ Phiên Máy Tính Zalo Cố Định 24/7 Trong Tài Khoản:
    - Duy trì kết nối WebSocket (`wss://ws1.chat.zalo.me`) và nhịp tim HTTP `getServerInfo` định kỳ
      để máy tính của mã QR luôn nằm trong mục 'Thiết bị đang đăng nhập' trên điện thoại Zalo,
      không bao giờ bị văng hay làm die Cookie/IMEI!"""

    _ACTIVE_KEEPERS = {}
    _LOCK = threading.RLock()

    @classmethod
    def start_keeper(cls, uid, imei, cookies_dict, user_agent, zpw_enk="", ws_urls=None):
        key = str(uid or imei).strip()
        if not key:
            return
        with cls._LOCK:
            old = cls._ACTIVE_KEEPERS.get(key)
            if old and old.get("stop_ev"):
                old["stop_ev"].set()
            stop_ev = threading.Event()
            st = {
                "uid": str(uid or ""),
                "imei": str(imei),
                "cookies": dict(cookies_dict or {}),
                "ua": user_agent,
                "zpw_enk": str(zpw_enk or ""),
                "ws_urls": list(ws_urls or ["wss://ws1.chat.zalo.me", "wss://ws2.chat.zalo.me"]),
                "stop_ev": stop_ev,
                "started_at": time.time(),
            }
            cls._ACTIVE_KEEPERS[key] = st
            th = threading.Thread(target=cls._keeper_loop, args=(st,), daemon=True)
            th.start()

    @staticmethod
    def _send_ws_ping(sock, payload_bytes, opcode=0x2):
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
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload_bytes))
        sock.sendall(bytes(header) + masked)

    @classmethod
    def _keeper_loop(cls, st):
        stop_ev = st["stop_ev"]
        imei = st["imei"]
        ua = st["ua"]
        cookies = st["cookies"]
        ws_urls = st["ws_urls"]
        s = requests.Session()
        s.cookies.update(cookies)
        s.headers.update({
            "User-Agent": ua,
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
        })
        ws_idx = 0
        last_http_hb = 0.0

        while not stop_ev.is_set():
            now = time.time()
            if now - last_http_hb >= 120.0:
                last_http_hb = now
                try:
                    srv_sign = hashlib.md5(f"zsecuregetserverinfo645Web{imei}30".encode("utf-8")).hexdigest()
                    s.get(
                        "https://wpa.chat.zalo.me/api/login/getServerInfo",
                        params={"imei": imei, "type": 30, "client_version": 645, "computer_name": "Web", "signkey": srv_sign},
                        timeout=6,
                    )
                except Exception:
                    pass

            ws_url = ws_urls[ws_idx % len(ws_urls)]
            ws_idx += 1
            if "zpw_ver=" not in ws_url:
                sep = "&" if "?" in ws_url else "?"
                ws_url = f"{ws_url}{sep}zpw_ver=645&zpw_type=30&t={int(time.time() * 1000)}"

            sock = None
            try:
                parsed = urlparse(ws_url)
                host = parsed.hostname or "ws1.chat.zalo.me"
                port = parsed.port or 443
                path = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
                raw_sock = socket.create_connection((host, port), timeout=10)
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(raw_sock, server_hostname=host)
                ws_key = base64.b64encode(os.urandom(16)).decode()
                ck_str = "; ".join(f"{k}={v}" for k, v in cookies.items() if k and v is not None)
                hs = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"Origin: https://chat.zalo.me\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Cookie: {ck_str}\r\n\r\n"
                )
                sock.sendall(hs.encode("utf-8"))
                resp_b = sock.recv(1024)
                if b"101" in resp_b:
                    sock.settimeout(20.0)
                    while not stop_ev.is_set():
                        hb_pkt = struct.pack("<BHB", 1, 2, 1) + json.dumps({"eventId": int(time.time() * 1000)}).encode("utf-8")
                        cls._send_ws_ping(sock, hb_pkt, opcode=0x2)
                        if stop_ev.wait(18.0):
                            break
                        if time.time() - last_http_hb >= 120.0:
                            last_http_hb = time.time()
                            try:
                                srv_sign = hashlib.md5(f"zsecuregetserverinfo645Web{imei}30".encode("utf-8")).hexdigest()
                                s.get(
                                    "https://wpa.chat.zalo.me/api/login/getServerInfo",
                                    params={"imei": imei, "type": 30, "client_version": 645, "computer_name": "Web", "signkey": srv_sign},
                                    timeout=6,
                                )
                            except Exception:
                                pass
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
            stop_ev.wait(5.0)


def verify_zalo_pc_device_logged_in_account(imei, cookies_dict, user_agent, zpw_enk=""):
    """Kiểm tra nghiêm ngặt xem máy tính của mã QR đã thực sự đăng nhập và nằm trong tài khoản Zalo chưa:
    - Bắt buộc có `zpw_sek` trong Cookie và `zpw_enk` hợp lệ.
    - Bắt buộc gọi thành công API nhóm (`getlg/v4`) hoặc giải mã được dữ liệu tài khoản bằng khóa `zpw_enk`.
    - Nếu máy tính không nằm trong tài khoản, trả về `(False, reason)` để hệ thống KHÔNG trả về Cookie/IMEI chết!"""
    if not imei or not isinstance(cookies_dict, dict):
        return False, "Thiếu thông tin IMEI hoặc Cookie phiên."
    if not cookies_dict.get("zpw_sek"):
        return False, "Máy tính chưa được cấp chứng chỉ phiên zpw_sek trong tài khoản Zalo."
    if not zpw_enk:
        return False, "Máy tính chưa kích hoạt được khóa phiên zpw_enk trong tài khoản Zalo."

    try:
        ck_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items() if k and v is not None)
        hdrs = {
            "User-Agent": user_agent,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
            "Cookie": ck_str,
        }
        r = requests.get(
            "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
            params={"zpw_ver": 645, "zpw_type": 30},
            headers=hdrs,
            timeout=8,
        )
        rj = r.json() if r.content else {}
        if rj.get("error_code") == 0 and rj.get("data"):
            key_b = base64.b64decode(zpw_enk)
            cipher = AES.new(key_b, AES.MODE_CBC, bytes(16))
            raw = base64.b64decode(unquote(rj["data"]) if "%" in rj["data"] else rj["data"])
            dec = cipher.decrypt(raw)
            pad_len = dec[-1]
            if 1 <= pad_len <= 16:
                dec = dec[:-pad_len]
            parsed = json.loads(dec.decode("utf-8", errors="ignore"))
            if isinstance(parsed, dict):
                return True, "Thiết bị máy tính đã nằm cố định trong tài khoản Zalo!"
    except Exception as e:
        return False, f"Không xác thực được phiên máy tính trong tài khoản: {e}"

    return False, "Máy tính chưa vào được bên trong tài khoản Zalo."


def generate_unique_zalo_pc_imei(user_agent="", salt=""):
    u = str(uuid.uuid4())
    ua_s = f"{user_agent}_{salt}_{time.time_ns()}_{secrets.token_hex(4)}"
    tail = hashlib.md5(ua_s.encode("utf-8")).hexdigest()
    return f"{u}-{tail}"


def _harvest_cookies(resp, session_obj, jar_dict):
    try:
        if session_obj and session_obj.cookies:
            for c in session_obj.cookies:
                if c.name and c.value is not None:
                    jar_dict[c.name] = c.value
        if resp is not None:
            if getattr(resp, "history", None):
                for h_resp in resp.history:
                    _harvest_cookies(h_resp, None, jar_dict)
            if resp.cookies:
                for c in resp.cookies:
                    if c.name and c.value is not None:
                        jar_dict[c.name] = c.value
            sc_hdr = resp.headers.get("Set-Cookie") or ""
            for m_sc in re.finditer(
                r"(?:^|;\s*|\,\s*)(zpw_sek|zpsid|zpsidleg|zpw_sua|__zi|__zi-legacy|_zlang|app\.event\.zalo\.me)=([^;,\s]+)",
                sc_hdr
            ):
                jar_dict[m_sc.group(1)] = m_sc.group(2)
    except Exception:
        pass


def _execute_qr_login_sync(emit_event_fn, qr_callback=None, timeout=120, custom_pc_name=None):
    """Thực thi luồng tạo QR, đăng nhập thẳng thiết bị Máy Tính vào trong tài khoản Zalo và xác thực nghiêm ngặt."""
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    sec_ch_ua = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
    sec_platform = '"Windows"'
    rnd_tag = secrets.token_hex(2).upper()
    pc_name = custom_pc_name or f"ZALO-PC-RIKE-{rnd_tag} (Windows 11 Pro)"
    imei = generate_unique_zalo_pc_imei(ua, salt=pc_name)

    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=2)
    s.mount("https://", adapter)
    s.mount("http://", adapter)

    continue_url = "https://zalo.me/pc"
    login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fzalo.me%2Fpc"
    v_str = "2.3.10"
    cookie_jar_dict = {"_zlang": "vn"}
    s.cookies.set("_zlang", "vn", domain=".zalo.me")

    nav_headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
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
            "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
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

    qr_b64_raw = ""
    qr_code_id = ""
    start_ts = time.time()

    for _attempt in range(3):
        try:
            r_page = s.get(login_referer, headers=nav_headers, timeout=10, allow_redirects=True)
            _harvest_cookies(r_page, s, cookie_jar_dict)
            m_ver = re.search(r"https://stc-zlogin\.zdn\.vn/main-([\d\.]+)\.js", r_page.text or "")
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
            _harvest_cookies(r_li, s, cookie_jar_dict)
        except Exception:
            pass

        try:
            r_vc = s.post(
                "https://id.zalo.me/account/verify-client",
                data={"type": "device", "continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=8,
            )
            _harvest_cookies(r_vc, s, cookie_jar_dict)
        except Exception:
            pass

        try:
            r_qr = s.post(
                "https://id.zalo.me/account/authen/qr/generate",
                data={"continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=10,
            )
            _harvest_cookies(r_qr, s, cookie_jar_dict)
            j_qr = r_qr.json() if r_qr.content else {}
            qr_data = j_qr.get("data") or {}
            if isinstance(qr_data, dict):
                qr_b64_raw = qr_data.get("image") or qr_data.get("qr_image") or ""
                qr_code_id = qr_data.get("code") or qr_data.get("qr_id") or ""
            if qr_b64_raw and qr_code_id:
                break
        except Exception:
            pass
        time.sleep(0.25)

    if not qr_b64_raw or not qr_code_id:
        return None

    clean_b64 = qr_b64_raw.split(",", 1)[-1].strip()
    pad_r = (4 - len(clean_b64) % 4) % 4
    raw_png = base64.b64decode(clean_b64 + ("=" * pad_r))
    qr_data_uri = "data:image/png;base64," + base64.b64encode(raw_png).decode("utf-8")

    if qr_callback:
        try:
            qr_callback(qr_data_uri)
        except Exception:
            pass

    async def _save_to_file_async(filepath):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "wb") as wf:
            wf.write(raw_png)
        return filepath

    emit_event_fn({
        "type": LoginQRCallbackEventType.QRCodeGenerated,
        "data": {"code": qr_code_id, "image": qr_data_uri, "imei": imei, "pc_name": pc_name},
        "actions": {"saveToFile": _save_to_file_async},
    })

    display_name = "Zalo User"
    avatar = ""
    scanned_ok = False

    while time.time() - start_ts < timeout:
        try:
            r_scan = s.post(
                "https://id.zalo.me/account/authen/qr/waiting-scan",
                data={"code": qr_code_id, "continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=25,
            )
            _harvest_cookies(r_scan, s, cookie_jar_dict)
            j_scan = r_scan.json() if r_scan.content else {}
            if not isinstance(j_scan, dict):
                time.sleep(0.35)
                continue
            err_c = j_scan.get("error_code")
            if err_c == 8:
                continue
            sd = j_scan.get("data")
            if err_c == 0 and isinstance(sd, dict) and (sd.get("display_name") or sd.get("avatar")):
                display_name = str(sd.get("display_name") or "Người dùng").strip()
                avatar = str(sd.get("avatar") or "").strip()
                scanned_ok = True
                emit_event_fn({
                    "type": LoginQRCallbackEventType.QRCodeScanned,
                    "data": {"display_name": display_name, "avatar": avatar, "code": qr_code_id},
                })
                break
            if err_c in (-13, 13):
                emit_event_fn({"type": LoginQRCallbackEventType.QRCodeDeclined, "data": {}})
                return None
            if err_c not in (0, 8, None):
                emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
                return None
        except requests.exceptions.Timeout:
            continue
        except Exception:
            time.sleep(0.35)

    if not scanned_ok:
        emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
        return None

    confirmed_ok = False
    j_conf = {}
    while time.time() - start_ts < timeout:
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
                timeout=25,
            )
            _harvest_cookies(r_conf, s, cookie_jar_dict)
            j_conf = r_conf.json() if r_conf.content else {}
            if not isinstance(j_conf, dict):
                time.sleep(0.35)
                continue
            err_cf = j_conf.get("error_code")
            if err_cf == 8:
                continue
            if err_cf in (-13, 13):
                emit_event_fn({"type": LoginQRCallbackEventType.QRCodeDeclined, "data": {}})
                return None
            if err_cf == 0:
                confirmed_ok = True
                break
            if err_cf and err_cf not in (0, 8):
                emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
                return None
        except requests.exceptions.Timeout:
            continue
        except Exception:
            time.sleep(0.35)

    if not confirmed_ok:
        emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
        return None

    # Bước 7: Nhận chứng chỉ zpw_sek qua từng chặng Redirect (không làm rớt cookie zpw_sek)
    cookie_jar_dict["z_uuid"] = imei

    def _follow_redirect_hops(start_url, initial_ref):
        cur_u = start_url
        cur_ref = initial_ref
        for _hop in range(10):
            if not cur_u:
                break
            p_u = urlparse(cur_u)
            ck_hop = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
            h_hop = dict(nav_headers)
            h_hop["Referer"] = cur_ref
            if ck_hop:
                h_hop["Cookie"] = ck_hop
            try:
                r_h = s.get(cur_u, headers=h_hop, allow_redirects=False, timeout=10)
                _harvest_cookies(r_h, s, cookie_jar_dict)
                if r_h.status_code in (301, 302, 303, 307, 308):
                    loc = r_h.headers.get("Location") or ""
                    if not loc:
                        break
                    if loc.startswith("/"):
                        loc = f"{p_u.scheme}://{p_u.netloc}{loc}"
                    cur_ref = cur_u
                    cur_u = loc
                    continue
            except Exception:
                pass
            break

    conf_data = j_conf.get("data") if isinstance(j_conf, dict) else None
    redirect_target = ""
    if isinstance(conf_data, dict):
        for u_key in ("url", "redirect_url", "continue", "next"):
            if isinstance(conf_data.get(u_key), str) and conf_data[u_key].startswith("http"):
                redirect_target = conf_data[u_key]
                break
    elif isinstance(conf_data, str) and conf_data.startswith("http"):
        redirect_target = conf_data

    if redirect_target:
        _follow_redirect_hops(redirect_target, login_referer)
    if not cookie_jar_dict.get("zpw_sek"):
        _follow_redirect_hops(
            "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2Findex.html",
            login_referer
        )

    # Bước 8: Đăng ký thiết bị Máy Tính vào trong tài khoản Zalo (`wpa.chat.zalo.me`)
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
        srv_sign = hashlib.md5(f"zsecuregetserverinfo645Web{imei}30".encode("utf-8")).hexdigest()
        r_srv = s.get(
            "https://wpa.chat.zalo.me/api/login/getServerInfo",
            params={
                "imei": imei,
                "type": 30,
                "client_version": 645,
                "computer_name": "Web",
                "signkey": srv_sign,
            },
            headers=wpa_headers,
            timeout=8,
        )
        _harvest_cookies(r_srv, s, cookie_jar_dict)
    except Exception:
        pass

    for zt_try in (30, 24):
        if user_info_got.get("zpw_enk"):
            break
        try:
            ck_final_str = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
            wpa_headers["Cookie"] = ck_final_str
            enc_q, enc_key = ZaloPCParamsEncryptor.build_encrypted_login_query(
                imei, computer_name="Web", language="vi", ztype=zt_try, client_version=645
            )
            r_enc_login = s.get(
                "https://wpa.chat.zalo.me/api/login/getLoginInfo",
                params=enc_q,
                headers=wpa_headers,
                timeout=10,
            )
            _harvest_cookies(r_enc_login, s, cookie_jar_dict)
            j_enc = r_enc_login.json() if r_enc_login.content else {}
            raw_d = j_enc.get("data")
            if isinstance(raw_d, str) and raw_d:
                dec_info = ZaloPCParamsEncryptor.decrypt_login_data(raw_d, enc_key)
                if isinstance(dec_info, dict) and dec_info.get("zpw_enk"):
                    user_info_got = dec_info
            elif isinstance(raw_d, dict) and raw_d.get("zpw_enk"):
                user_info_got = raw_d
        except Exception:
            pass

    uid = str(user_info_got.get("uid") or user_info_got.get("userId") or user_info_got.get("send2me_id") or "")
    zpw_enk = str(user_info_got.get("zpw_enk") or "")

    # BẮT BUỘC KIỂM TRA: Máy tính của QR đó PHẢI nằm trong tài khoản Zalo thì mới trả về Cookie & IMEI!
    verified_in_acc, verify_msg = verify_zalo_pc_device_logged_in_account(
        imei=imei, cookies_dict=cookie_jar_dict, user_agent=ua, zpw_enk=zpw_enk
    )
    if not verified_in_acc or not zpw_enk or not uid:
        emit_event_fn({
            "type": LoginQRCallbackEventType.QRCodeDeclined,
            "data": {"error": verify_msg or "Thiết bị máy tính chưa vào được trong tài khoản Zalo!"},
        })
        return None

    ws_list = []
    for k_ws in ("zpw_ws", "ws", "websocket"):
        v_ws = user_info_got.get(k_ws)
        if isinstance(v_ws, list):
            ws_list.extend(v_ws)
        elif isinstance(v_ws, str) and v_ws:
            ws_list.append(v_ws)

    # Khởi chạy bộ giữ phiên máy tính cố định 24/7 trong tài khoản Zalo (không chạy đi đâu hết!)
    ZaloPCSessionKeeper.start_keeper(
        uid=uid, imei=imei, cookies_dict=cookie_jar_dict,
        user_agent=ua, zpw_enk=zpw_enk, ws_urls=ws_list
    )

    pf = user_info_got.get("profile") if isinstance(user_info_got.get("profile"), dict) else {}
    final_name = (
        user_info_got.get("displayName")
        or user_info_got.get("zaloName")
        or pf.get("displayName")
        or display_name
    )
    phone_num = str(user_info_got.get("phoneNumber") or pf.get("phoneNumber") or "N/A")

    user_info_out = dict(user_info_got)
    user_info_out.setdefault("uid", uid)
    user_info_out.setdefault("displayName", final_name)
    user_info_out.setdefault("phoneNumber", phone_num)
    user_info_out.setdefault("zpw_enk", zpw_enk)
    user_info_out["verified_in_account"] = True
    user_info_out["pc_name"] = pc_name

    result_payload = {
        "cookies": cookie_jar_dict,
        "imei": imei,
        "user_agent": ua,
        "zpw_enk": zpw_enk,
        "uid": uid,
        "display_name": final_name,
        "pc_name": pc_name,
        "verified_in_account": True,
        "user_info": user_info_out,
    }

    emit_event_fn({
        "type": LoginQRCallbackEventType.GotLoginInfo,
        "data": result_payload,
    })
    return result_payload


async def _login_qr_async_runner(callback=None, qr_callback=None, timeout=120, custom_pc_name=None):
    loop = asyncio.get_running_loop()

    def _emit_from_thread(ev):
        if not callback:
            return
        try:
            if inspect.iscoroutinefunction(callback):
                fut = asyncio.run_coroutine_threadsafe(callback(ev), loop)
                fut.result(timeout=15)
            else:
                res = callback(ev)
                if inspect.isawaitable(res):
                    fut = asyncio.run_coroutine_threadsafe(res, loop)
                    fut.result(timeout=15)
        except Exception:
            pass

    return await asyncio.to_thread(
        _execute_qr_login_sync, _emit_from_thread, qr_callback, timeout, custom_pc_name
    )


def login_qr_with_unique_imei(callback=None, qr_callback=None, timeout=120, custom_pc_name=None):
    """Hàm đa năng tương thích cả 2 chế độ:
    - Chế độ Async (`await login_qr_with_unique_imei(callback=callback)` trong Bot Telegram `get_ck_im_zalo.py`)
    - Chế độ Sync (`login_qr_with_unique_imei(qr_callback=...)` trong Web Control Panel `app.py`)"""
    try:
        asyncio.get_running_loop()
        is_in_async_loop = True
    except RuntimeError:
        is_in_async_loop = False

    if is_in_async_loop or (callback is not None and inspect.iscoroutinefunction(callback)):
        return _login_qr_async_runner(
            callback=callback, qr_callback=qr_callback, timeout=timeout, custom_pc_name=custom_pc_name
        )

    def _emit_sync(ev):
        if not callback:
            return
        try:
            res = callback(ev)
            if inspect.isawaitable(res):
                asyncio.run(res)
        except Exception:
            pass

    return _execute_qr_login_sync(
        _emit_sync, qr_callback=qr_callback, timeout=timeout, custom_pc_name=custom_pc_name
    )
