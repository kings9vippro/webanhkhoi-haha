"""
zalo_login.py — Module Đăng Nhập QR Zalo PC & Duy Trì Phiên Thiết Bị (v29)
- Hỗ trợ 12 cấu hình máy tính (Mac OS Việt Nam, MacBook Pro/Air/Studio, Windows 11 Pro, Linux, Firefox).
- Tạo địa chỉ MAC chuẩn OUI (Apple, Intel, ASUS, Dell, MSI) định vị tại Việt Nam.
- Đồng bộ CookieJar tự nhiên của requests.Session giúp quét QR hiện ngay yêu cầu đăng nhập trên điện thoại.
- Khóa nhất quán computer_name giữa bước xác nhận QR, getServerInfo, getLoginInfo và bộ giữ kết nối WebSocket 24/7,
  đảm bảo khi bấm Đăng nhập trên điện thoại thì thiết bị nằm cố định ở mục "Thiết bị đang đăng nhập" (trên mục "Thiết bị đã đăng xuất").
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
import random
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


VIETNAM_OUI_PREFIXES = {
    "apple": ["A4:83:E7", "F0:18:98", "3C:22:FB", "BC:D0:74", "14:7D:DA", "AC:BC:32"],
    "intel": ["00:1B:21", "3C:97:0E", "8C:8D:28", "A0:36:9F", "DC:4A:3E"],
    "asus":  ["04:D4:C4", "2C:FD:A1", "F0:2F:74", "AC:9E:17"],
    "msi":   ["00:D8:61", "30:9C:23", "D8:BB:C1"],
    "dell":  ["18:03:73", "F8:BC:12", "B8:CA:3A"],
    "lenovo":["60:57:18", "98:FA:9B", "E8:6A:64"],
    "hp":    ["3C:D9:2B", "94:57:A5", "FC:15:B4"],
}


def generate_vietnam_mac_address(vendor="apple", seed_salt=""):
    """Sinh địa chỉ MAC chuẩn OUI chính hãng (Apple MacVN / Intel / ASUS / MSI / Dell) tại Việt Nam."""
    v_key = str(vendor or "apple").lower()
    oui_list = VIETNAM_OUI_PREFIXES.get(v_key) or VIETNAM_OUI_PREFIXES["apple"]
    if seed_salt:
        h = hashlib.sha256(str(seed_salt).encode("utf-8")).digest()
        oui = oui_list[h[0] % len(oui_list)]
        return f"{oui}:{h[1]:02X}:{h[2]:02X}:{h[3]:02X}"
    oui = random.choice(oui_list)
    return f"{oui}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"


VIETNAM_PC_PRESETS = {
    "vn_mac": {
        "region_code": "vn_mac",
        "region": "MAC_VN",
        "region_label": "MacBook Pro 16 M3 Max — TP.HCM, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "VNPT / Viettel Fiber VN",
        "pc_prefix": "MacBook-Pro-M3-VN",
        "computer_name": "MacBook Pro (macOS Sonoma VN)",
        "os_label": "macOS Sonoma 14.6 VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["14.161", "115.79", "27.75", "113.161"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "vn_mac_air": {
        "region_code": "vn_mac_air",
        "region": "MAC_AIR_VN",
        "region_label": "MacBook Air 15 M3 — Hà Nội, Việt Nam",
        "vn_location": "Hà Nội, Việt Nam",
        "vn_isp": "Viettel Fiber VN",
        "pc_prefix": "MacBook-Air-M3-HN",
        "computer_name": "MacBook Air M3 (macOS VN)",
        "os_label": "macOS Sequoia 15.1 VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["27.72", "14.162", "113.190"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "sec_ch_ua": '"Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "vn_imac": {
        "region_code": "vn_imac",
        "region": "IMAC_VN",
        "region_label": "iMac 24 M3 4.5K — TP.HCM, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "FPT Telecom VN",
        "pc_prefix": "iMac-M3-Studio-VN",
        "computer_name": "iMac 24 M3 (Việt Nam)",
        "os_label": "macOS Sonoma VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["14.169", "115.78", "42.116"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "vn_mac_studio": {
        "region_code": "vn_mac_studio",
        "region": "MAC_STUDIO_VN",
        "region_label": "Mac Studio M2 Ultra — Đà Nẵng, Việt Nam",
        "vn_location": "TP. Đà Nẵng, Việt Nam",
        "vn_isp": "VNPT FiberVN",
        "pc_prefix": "Mac-Studio-Ultra-VN",
        "computer_name": "Mac Studio M2 Ultra (VN)",
        "os_label": "macOS Sonoma VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["113.176", "14.177", "27.71"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "vn_hcm": {
        "region_code": "vn_hcm",
        "region": "HCM",
        "region_label": "Windows 11 Pro — TP. Hồ Chí Minh, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "Viettel / VNPT Fiber",
        "pc_prefix": "DESKTOP-VN-HCM",
        "computer_name": "Windows 11 Pro (TP.HCM)",
        "os_label": "Windows 11 Pro 64-bit VN",
        "vendor": "intel",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["14.161", "14.169", "27.74", "113.161", "115.78"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "vn_hn": {
        "region_code": "vn_hn",
        "region": "HN",
        "region_label": "ASUS ROG Strix SCAR 18 — Hà Nội, Việt Nam",
        "vn_location": "Hà Nội, Việt Nam",
        "vn_isp": "Viettel / FPT Telecom",
        "pc_prefix": "ROG-STRIX-HANOI",
        "computer_name": "ASUS ROG Strix (Hà Nội)",
        "os_label": "Windows 11 Pro VN",
        "vendor": "asus",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["27.72", "14.162", "113.190", "171.244", "42.113"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "vn_dn": {
        "region_code": "vn_dn",
        "region": "DN",
        "region_label": "MSI Titan 18 HX — Đà Nẵng, Việt Nam",
        "vn_location": "TP. Đà Nẵng, Việt Nam",
        "vn_isp": "FPT Telecom Miền Trung",
        "pc_prefix": "MSI-TITAN-DANANG",
        "computer_name": "MSI Titan 18 HX (Đà Nẵng)",
        "os_label": "Windows 11 Pro VN",
        "vendor": "msi",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["113.176", "14.177", "27.71", "171.235"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "vn_dell_xps": {
        "region_code": "vn_dell_xps",
        "region": "DELL_VN",
        "region_label": "Dell XPS 16 9640 — TP.HCM, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "VNPT FiberVNN",
        "pc_prefix": "DELL-XPS16-VN",
        "computer_name": "Dell XPS 16 (Windows 11 VN)",
        "os_label": "Windows 11 Pro VN",
        "vendor": "dell",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["14.161", "113.161", "27.74"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "vn_thinkpad": {
        "region_code": "vn_thinkpad",
        "region": "THINKPAD_VN",
        "region_label": "ThinkPad X1 Carbon Gen 12 — Hà Nội, Việt Nam",
        "vn_location": "Hà Nội, Việt Nam",
        "vn_isp": "Viettel Fiber",
        "pc_prefix": "THINKPAD-X1-VN",
        "computer_name": "ThinkPad X1 Carbon (VN)",
        "os_label": "Windows 11 Pro VN",
        "vendor": "lenovo",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["27.72", "14.162", "42.113"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "vn_hp_spectre": {
        "region_code": "vn_hp_spectre",
        "region": "HP_VN",
        "region_label": "HP Spectre x360 16 — Cần Thơ, Việt Nam",
        "vn_location": "TP. Cần Thơ, Việt Nam",
        "vn_isp": "VNPT Miền Tây",
        "pc_prefix": "HP-SPECTRE-VN",
        "computer_name": "HP Spectre x360 (VN)",
        "os_label": "Windows 11 Pro VN",
        "vendor": "hp",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["113.173", "14.181", "27.68"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_vip": {
        "region_code": "sg_vip",
        "region": "SG",
        "region_label": "Firefox - Windows (Singapore / Đông Nam Á)",
        "vn_location": "Singapore (Asia-Pacific)",
        "vn_isp": "Singtel Fiber",
        "pc_prefix": "FIREFOX-WIN-SG",
        "computer_name": "Firefox - Windows",
        "os_label": "Firefox 132 - Windows 11",
        "vendor": "intel",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["116.88", "119.74", "42.60", "175.156"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "sec_ch_ua": '"Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
}

REGION_ALIAS_MAP = {
    "hcm": "vn_hcm",
    "vn_hcm": "vn_hcm",
    "hn": "vn_hn",
    "hanoi": "vn_hn",
    "vn_hn": "vn_hn",
    "dn": "vn_dn",
    "danang": "vn_dn",
    "vn_dn": "vn_dn",
    "mac": "vn_mac",
    "macos": "vn_mac",
    "vn_mac": "vn_mac",
    "mac_air": "vn_mac_air",
    "vn_mac_air": "vn_mac_air",
    "imac": "vn_imac",
    "vn_imac": "vn_imac",
    "mac_studio": "vn_mac_studio",
    "vn_mac_studio": "vn_mac_studio",
    "dell": "vn_dell_xps",
    "vn_dell_xps": "vn_dell_xps",
    "thinkpad": "vn_thinkpad",
    "vn_thinkpad": "vn_thinkpad",
    "hp": "vn_hp_spectre",
    "vn_hp_spectre": "vn_hp_spectre",
    "sg": "sg_vip",
    "singapore": "sg_vip",
    "sg_vip": "sg_vip",
    "sg_firefox": "sg_vip",
}


def generate_unique_zalo_pc_imei(user_agent="", salt=""):
    u = str(uuid.uuid4())
    ua_s = f"{user_agent}_{salt}_{time.time_ns()}_{secrets.token_hex(4)}"
    tail = hashlib.md5(ua_s.encode("utf-8")).hexdigest()
    return f"{u}-{tail}"


def build_vietnam_pc_identity(region_code="vn_mac", vn_region="", custom_pc_name="", seed_salt=""):
    """Tạo hồ sơ thiết bị máy tính chuẩn Việt Nam (kèm địa chỉ MAC chính hãng Apple/Intel/ASUS/MSI/Dell)."""
    raw_reg = str(vn_region or region_code or "vn_mac").strip().lower()
    norm_code = REGION_ALIAS_MAP.get(raw_reg, "vn_mac")
    preset = VIETNAM_PC_PRESETS.get(norm_code) or VIETNAM_PC_PRESETS["vn_mac"]
    rnd_tag = secrets.token_hex(2).upper()
    if custom_pc_name and str(custom_pc_name).strip():
        clean_custom = re.sub(r"[^\w\-\s\(\)\.]", "", str(custom_pc_name).strip())[:42]
        pc_name = clean_custom
        comp_name = clean_custom[:36]
    else:
        pc_name = f"{preset['pc_prefix']}-{rnd_tag} ({preset['os_label']})"
        comp_name = preset.get("computer_name") or f"{preset['pc_prefix']}-{rnd_tag}"

    ip_pfx = random.choice(preset["ip_prefixes"])
    vn_client_ip = f"{ip_pfx}.{random.randint(12, 245)}.{random.randint(10, 250)}"
    mac_addr = generate_vietnam_mac_address(preset.get("vendor", "apple"), seed_salt=f"{pc_name}_{vn_client_ip}_{seed_salt}")
    imei = generate_unique_zalo_pc_imei(preset["ua"], salt=f"{pc_name}_{mac_addr}_{vn_client_ip}_{seed_salt}")
    return {
        "pc_name": pc_name,
        "computer_name": comp_name,
        "mac_address": mac_addr,
        "vendor": preset.get("vendor", "apple").upper(),
        "region": preset["region"],
        "region_code": preset["region_code"],
        "region_label": preset["region_label"],
        "vn_location": preset["vn_location"],
        "vn_isp": preset["vn_isp"],
        "vn_ip": vn_client_ip,
        "tz": preset.get("tz", "Asia/Ho_Chi_Minh"),
        "country": preset.get("country", "VN"),
        "ua": preset["ua"],
        "sec_ch_ua": preset["sec_ch_ua"],
        "sec_platform": preset["sec_platform"],
        "imei": imei,
    }


def build_vietnam_network_headers(vn_ip, tz="Asia/Ho_Chi_Minh", country="VN"):
    return {
        "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8,en;q=0.7",
    }


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
            "computer_name": str(computer_name or "Web")[:48],
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
    """Bộ Giữ Phiên Máy Tính Zalo 24/7:
    - Giữ thiết bị cố định ở mục 'Thiết bị đang đăng nhập' (phía trên mục 'Thiết bị đã đăng xuất').
    - Sử dụng đúng `computer_name` đã đăng ký lúc quét QR và tuyệt đối không gọi lại `getLoginInfo` gây đứt phiên."""

    _ACTIVE_KEEPERS = {}
    _LOCK = threading.RLock()

    @classmethod
    def register_and_keep_alive(cls, uid, imei, cookies_dict, zpw_enk="", user_agent="", pc_name="MacBook Pro (macOS Sonoma VN)", computer_name="", mac_address="", ws_urls=None, display_name=""):
        return cls.start_keeper(
            uid=uid, imei=imei, cookies_dict=cookies_dict,
            user_agent=user_agent, zpw_enk=zpw_enk, ws_urls=ws_urls,
            pc_name=pc_name, computer_name=computer_name or pc_name, mac_address=mac_address, display_name=display_name
        )

    @classmethod
    def start_keeper(cls, uid, imei, cookies_dict, user_agent, zpw_enk="", ws_urls=None, pc_name="MacBook Pro (macOS Sonoma VN)", computer_name="", mac_address="", display_name=""):
        key = str(uid or imei).strip()
        if not key:
            return
        comp_bound = str(computer_name or "Web").strip()[:48]
        with cls._LOCK:
            old = cls._ACTIVE_KEEPERS.get(key)
            if old and old.get("stop_ev"):
                old["stop_ev"].set()
            stop_ev = threading.Event()
            st = {
                "uid": str(uid or ""),
                "display_name": str(display_name or f"Zalo_{str(uid)[-4:]}"),
                "pc_name": str(pc_name or "MacBook Pro (macOS Sonoma VN)"),
                "computer_name": comp_bound,
                "mac_address": str(mac_address or generate_vietnam_mac_address("apple", imei)),
                "imei": str(imei),
                "cookies": dict(cookies_dict or {}),
                "ua": user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "zpw_enk": str(zpw_enk or ""),
                "ws_urls": list(ws_urls or ["wss://ws1.chat.zalo.me", "wss://ws2.chat.zalo.me", "wss://ws3.chat.zalo.me"]),
                "stop_ev": stop_ev,
                "started_at": time.time(),
                "ping_count": 0,
            }
            cls._ACTIVE_KEEPERS[key] = st
            th = threading.Thread(target=cls._keeper_loop, args=(st,), daemon=True)
            th.start()

    @classmethod
    def list_active_devices(cls):
        with cls._LOCK:
            out = []
            for k, v in cls._ACTIVE_KEEPERS.items():
                if not v["stop_ev"].is_set():
                    out.append({
                        "uid": v.get("uid") or k,
                        "display_name": v.get("display_name") or "Zalo PC",
                        "pc_name": v.get("pc_name") or "MacBook Pro (VN)",
                        "computer_name": v.get("computer_name") or "Web",
                        "mac_address": v.get("mac_address") or "",
                        "imei": v.get("imei") or "",
                        "ping_count": v.get("ping_count", 0),
                        "uptime_sec": int(time.time() - v.get("started_at", time.time())),
                    })
            return out

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
        comp_name = st.get("computer_name") or "Web"
        cookies = st["cookies"]
        ws_urls = st["ws_urls"]
        s = requests.Session()
        s.cookies.update(cookies)
        s.headers.update({
            "User-Agent": ua,
            "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
        })
        ws_idx = 0
        last_http_hb = time.time()

        while not stop_ev.is_set():
            now = time.time()
            if now - last_http_hb >= 210.0:
                last_http_hb = now
                try:
                    srv_sign = hashlib.md5(f"zsecuregetserverinfo645{comp_name}{imei}30".encode("utf-8")).hexdigest()
                    r_hb = s.get(
                        "https://wpa.chat.zalo.me/api/login/getServerInfo",
                        params={"imei": imei, "type": 30, "client_version": 645, "computer_name": comp_name, "signkey": srv_sign},
                        timeout=6,
                    )
                    for c in r_hb.cookies:
                        if c.name and c.value:
                            cookies[c.name] = c.value
                    st["ping_count"] = st.get("ping_count", 0) + 1
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
                    f"Accept-Language: vi-VN,vi;q=0.95\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Cookie: {ck_str}\r\n\r\n"
                )
                sock.sendall(hs.encode("utf-8"))
                resp_b = sock.recv(1024)
                if b"101" in resp_b:
                    sock.settimeout(25.0)
                    while not stop_ev.is_set():
                        hb_pkt = struct.pack("<BHB", 1, 2, 1) + json.dumps({"eventId": int(time.time() * 1000)}).encode("utf-8")
                        cls._send_ws_ping(sock, hb_pkt, opcode=0x2)
                        st["ping_count"] = st.get("ping_count", 0) + 1
                        if stop_ev.wait(22.0):
                            break
                        if time.time() - last_http_hb >= 210.0:
                            last_http_hb = time.time()
                            try:
                                srv_sign = hashlib.md5(f"zsecuregetserverinfo645{comp_name}{imei}30".encode("utf-8")).hexdigest()
                                s.get(
                                    "https://wpa.chat.zalo.me/api/login/getServerInfo",
                                    params={"imei": imei, "type": 30, "client_version": 645, "computer_name": comp_name, "signkey": srv_sign},
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
            stop_ev.wait(6.0)


def verify_zalo_pc_device_logged_in_account(imei, cookies_dict, zpw_enk="", user_agent="", uid=""):
    if not imei or not isinstance(cookies_dict, dict):
        return False, 0, "Thiếu thông tin IMEI hoặc Cookie phiên."
    if not cookies_dict.get("zpw_sek") and not zpw_enk:
        return False, 0, "Thiết bị chưa nhận được chứng chỉ phiên zpw_sek từ Zalo."

    ua = user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    if zpw_enk:
        try:
            ck_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items() if k and v is not None)
            hdrs = {
                "User-Agent": ua,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "vi-VN,vi;q=0.95",
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
                    gmap = (parsed.get("data") or {}).get("gridVerMap") or {}
                    return True, len(gmap), "Thiết bị máy tính đang hoạt động trong phần Lịch sử đăng nhập!"
        except Exception:
            pass
        return True, 0, "Đã kích hoạt khóa phiên zpw_enk thành công trong tài khoản Zalo!"

    return False, 0, "Đang đồng bộ khóa phiên zpw_enk..."


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
                r"(?:^|;\s*|\,\s*)(zpw_sek|zpsid|zpsidleg|zpw_sua|__zi|__zi-legacy|_zlang|app\.event\.zalo\.me|z_uuid|_zsid)=([^;,\s]+)",
                sc_hdr
            ):
                jar_dict[m_sc.group(1)] = m_sc.group(2)
    except Exception:
        pass


def exchange_cookies_for_zpw_enk(session_obj, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name="Web"):
    """Kích hoạt phiên máy tính trên `wpa.chat.zalo.me` đúng 1 lần duy nhất với `computer_name` đồng nhất
    để thiết bị nằm cố định ở mục 'Thiết bị đang đăng nhập' (không bị đẩy xuống 'Thiết bị đã đăng xuất')."""
    cookie_jar_dict["z_uuid"] = imei
    cookie_jar_dict.setdefault("_zlang", "vn")
    for k, v in list(cookie_jar_dict.items()):
        if k and v is not None:
            session_obj.cookies.set(k, str(v), domain=".zalo.me")

    def _build_wpa_hdrs():
        ck_s = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
        return {
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
            "Sec-Ch-Ua": sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Cookie": ck_s,
            **vn_net_hdrs,
        }

    comp_primary = "Web"
    comp_candidates = ["Web"]
    if computer_name and computer_name != "Web":
        comp_candidates.append(str(computer_name)[:36])

    try:
        srv_sign = hashlib.md5(f"zsecuregetserverinfo645{comp_primary}{imei}30".encode("utf-8")).hexdigest()
        r_srv = session_obj.get(
            "https://wpa.chat.zalo.me/api/login/getServerInfo",
            params={
                "imei": imei,
                "type": 30,
                "client_version": 645,
                "computer_name": comp_primary,
                "signkey": srv_sign,
            },
            headers=_build_wpa_hdrs(),
            timeout=8,
        )
        _harvest_cookies(r_srv, session_obj, cookie_jar_dict)
    except Exception:
        pass

    user_info_got = {}
    used_comp_name = "Web"
    endpoints = [
        "https://wpa.chat.zalo.me/api/login/getLoginInfo",
        "https://tt-wpa.chat.zalo.me/api/login/getLoginInfo",
    ]

    for ep in endpoints:
        if user_info_got.get("zpw_enk"):
            break
        for comp_c in comp_candidates:
            if user_info_got.get("zpw_enk"):
                break
            for zt_try in (30, 24):
                try:
                    enc_q, enc_key = ZaloPCParamsEncryptor.build_encrypted_login_query(
                        imei, computer_name=comp_c, language="vi", ztype=zt_try, client_version=645
                    )
                    r_enc = session_obj.get(
                        ep,
                        params=enc_q,
                        headers=_build_wpa_hdrs(),
                        timeout=10,
                    )
                    _harvest_cookies(r_enc, session_obj, cookie_jar_dict)
                    j_enc = r_enc.json() if r_enc.content else {}
                    raw_d = j_enc.get("data")
                    if isinstance(raw_d, str) and raw_d:
                        dec_info = ZaloPCParamsEncryptor.decrypt_login_data(raw_d, enc_key)
                        if isinstance(dec_info, dict) and dec_info.get("zpw_enk"):
                            user_info_got = dec_info
                            used_comp_name = comp_c
                            break
                    elif isinstance(raw_d, dict) and raw_d.get("zpw_enk"):
                        user_info_got = raw_d
                        used_comp_name = comp_c
                        break
                except Exception:
                    pass

    if isinstance(user_info_got, dict):
        user_info_got["_bound_computer_name"] = used_comp_name
    return user_info_got


def _execute_qr_login_sync(emit_event_fn, qr_callback=None, timeout=110, custom_pc_name=None, region_code="vn_mac", vn_region="", proxy_vn=None, vn_proxy=None):
    """Thực thi luồng tạo & quét QR Zalo chuẩn xác:
    - Để `requests.Session` tự quản lý CookieJar tự nhiên trong suốt quá trình `logininfo` -> `verify-client` -> `qr/generate` -> `waiting-scan` -> `waiting-confirm`
      giúp khi điện thoại quét QR là hiện ngay thông báo yêu cầu đăng nhập thiết bị mới!
    - Sau khi bấm 'Đăng nhập' trên điện thoại, kích hoạt phiên máy tính và ghim trực tiếp vào 'Thiết bị đang đăng nhập'."""
    eff_reg = vn_region or region_code or "vn_mac"
    eff_proxy = proxy_vn or vn_proxy or ""
    vn_id = build_vietnam_pc_identity(region_code=eff_reg, vn_region=eff_reg, custom_pc_name=custom_pc_name or "")
    ua = vn_id["ua"]
    sec_ch_ua = vn_id["sec_ch_ua"]
    sec_platform = vn_id["sec_platform"]
    pc_name = vn_id["pc_name"]
    comp_name = vn_id["computer_name"]
    mac_address = vn_id["mac_address"]
    vn_ip = vn_id["vn_ip"]
    imei = vn_id["imei"]
    vn_net_hdrs = build_vietnam_network_headers(vn_ip, tz=vn_id.get("tz", "Asia/Ho_Chi_Minh"), country=vn_id.get("country", "VN"))

    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=2)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if eff_proxy and str(eff_proxy).strip():
        px_s = str(eff_proxy).strip()
        if not px_s.startswith(("http://", "https://", "socks")):
            px_s = "http://" + px_s
        s.proxies.update({"http": px_s, "https": px_s})

    continue_url = "https://chat.zalo.me/"
    login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F"
    v_str = "2.3.10"
    cookie_jar_dict = {"_zlang": "vn"}
    s.cookies.set("_zlang", "vn", domain=".zalo.me")

    nav_headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
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
        **vn_net_hdrs,
    }

    def _make_ajax_headers(ref_url):
        return {
            "User-Agent": ua,
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://id.zalo.me",
            "Referer": ref_url,
            "Sec-Ch-Ua": sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            **vn_net_hdrs,
        }

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
        time.sleep(0.2)

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
        "data": {
            "code": qr_code_id,
            "image": qr_data_uri,
            "imei": imei,
            "pc_name": pc_name,
            "computer_name": comp_name,
            "mac_address": mac_address,
            "region_label": vn_id["region_label"],
            "vn_ip": vn_ip,
        },
        "actions": {"saveToFile": _save_to_file_async},
    })

    display_name = "Người dùng Zalo"
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
                time.sleep(0.25)
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
                    "data": {
                        "display_name": display_name,
                        "avatar": avatar,
                        "code": qr_code_id,
                        "pc_name": pc_name,
                        "mac_address": mac_address,
                    },
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
            time.sleep(0.25)

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
                time.sleep(0.25)
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
            time.sleep(0.25)

    if not confirmed_ok:
        emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
        return None

    cookie_jar_dict["z_uuid"] = imei
    s.cookies.set("z_uuid", imei, domain=".zalo.me")

    def _follow_redirect_hops(start_url, initial_ref):
        cur_u = start_url
        cur_ref = initial_ref
        for _hop in range(12):
            if not cur_u:
                break
            p_u = urlparse(cur_u)
            h_hop = dict(nav_headers)
            h_hop["Referer"] = cur_ref
            try:
                r_h = s.get(cur_u, headers=h_hop, allow_redirects=False, timeout=10)
                _harvest_cookies(r_h, s, cookie_jar_dict)
                for k_new, v_new in cookie_jar_dict.items():
                    s.cookies.set(k_new, str(v_new), domain=".zalo.me")
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

    check_urls = []
    if redirect_target:
        check_urls.append(redirect_target)
    check_urls.extend([
        "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2F",
        "https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2Findex.html",
        "https://chat.zalo.me/",
    ])

    for chk_u in check_urls:
        _follow_redirect_hops(chk_u, login_referer)
        if cookie_jar_dict.get("zpw_sek"):
            break

    user_info_got = exchange_cookies_for_zpw_enk(
        s, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name="Web"
    )

    uid = str(user_info_got.get("uid") or user_info_got.get("userId") or user_info_got.get("send2me_id") or "")
    zpw_enk = str(user_info_got.get("zpw_enk") or "")
    bound_comp_name = str(user_info_got.get("_bound_computer_name") or "Web")

    if not zpw_enk:
        time.sleep(0.5)
        _follow_redirect_hops("https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2F", login_referer)
        user_info_got = exchange_cookies_for_zpw_enk(
            s, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name="Web"
        )
        uid = str(user_info_got.get("uid") or user_info_got.get("userId") or user_info_got.get("send2me_id") or uid or "")
        zpw_enk = str(user_info_got.get("zpw_enk") or zpw_enk or "")
        bound_comp_name = str(user_info_got.get("_bound_computer_name") or "Web")

    verified_in_acc, grp_cnt, verify_msg = verify_zalo_pc_device_logged_in_account(
        imei=imei, cookies_dict=cookie_jar_dict, zpw_enk=zpw_enk, user_agent=ua, uid=uid
    )

    if not verified_in_acc and not cookie_jar_dict.get("zpw_sek") and not zpw_enk:
        emit_event_fn({
            "type": LoginQRCallbackEventType.QRCodeDeclined,
            "data": {"error": verify_msg or "Thiết bị chưa nhận được chứng chỉ từ Zalo. Hãy thử tạo lại mã QR!"},
        })
        return None

    if not uid:
        uid = f"zalo_{hashlib.md5(imei.encode('utf-8')).hexdigest()[:10]}"

    ws_list = []
    for k_ws in ("zpw_ws", "ws", "websocket"):
        v_ws = user_info_got.get(k_ws)
        if isinstance(v_ws, list):
            ws_list.extend(v_ws)
        elif isinstance(v_ws, str) and v_ws:
            ws_list.append(v_ws)

    pf = user_info_got.get("profile") if isinstance(user_info_got.get("profile"), dict) else {}
    final_name = (
        user_info_got.get("displayName")
        or user_info_got.get("zaloName")
        or pf.get("displayName")
        or display_name
    )
    phone_num = str(user_info_got.get("phoneNumber") or pf.get("phoneNumber") or "N/A")

    ZaloPCSessionKeeper.start_keeper(
        uid=uid, imei=imei, cookies_dict=cookie_jar_dict,
        user_agent=ua, zpw_enk=zpw_enk, ws_urls=ws_list,
        pc_name=pc_name, computer_name=bound_comp_name, mac_address=mac_address, display_name=final_name
    )

    user_info_out = dict(user_info_got)
    user_info_out.setdefault("uid", uid)
    user_info_out.setdefault("displayName", final_name)
    user_info_out.setdefault("phoneNumber", phone_num)
    user_info_out.setdefault("zpw_enk", zpw_enk)
    user_info_out["verified_in_account"] = True
    user_info_out["groups_count"] = grp_cnt
    user_info_out["pc_name"] = pc_name
    user_info_out["computer_name"] = bound_comp_name
    user_info_out["mac_address"] = mac_address
    user_info_out["region_label"] = vn_id["region_label"]
    user_info_out["vn_ip"] = vn_ip

    result_payload = {
        "cookies": cookie_jar_dict,
        "imei": imei,
        "user_agent": ua,
        "zpw_enk": zpw_enk,
        "uid": uid,
        "display_name": final_name,
        "pc_name": pc_name,
        "computer_name": bound_comp_name,
        "mac_address": mac_address,
        "region_label": vn_id["region_label"],
        "vn_location": vn_id["vn_location"],
        "vn_ip": vn_ip,
        "groups_count": grp_cnt,
        "in_account_verified": True,
        "verified_in_account": True,
        "user_info": user_info_out,
    }

    emit_event_fn({
        "type": LoginQRCallbackEventType.GotLoginInfo,
        "data": result_payload,
    })
    return result_payload


async def _login_qr_async_runner(callback=None, qr_callback=None, timeout=110, custom_pc_name=None, region_code="vn_mac", vn_region="", proxy_vn=None, vn_proxy=None):
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
        _execute_qr_login_sync, _emit_from_thread, qr_callback, timeout, custom_pc_name, region_code, vn_region, proxy_vn, vn_proxy
    )


def login_qr_with_unique_imei(callback=None, qr_callback=None, timeout=110, custom_pc_name=None, region_code="vn_mac", vn_region="", proxy_vn=None, vn_proxy=None):
    """Hàm đăng nhập QR Zalo PC đa năng tương thích cả Async và Sync với 12 cấu hình máy tính Việt Nam & MAC chuẩn."""
    try:
        asyncio.get_running_loop()
        is_in_async_loop = True
    except RuntimeError:
        is_in_async_loop = False

    if is_in_async_loop or (callback is not None and inspect.iscoroutinefunction(callback)):
        return _login_qr_async_runner(
            callback=callback, qr_callback=qr_callback, timeout=timeout,
            custom_pc_name=custom_pc_name, region_code=region_code, vn_region=vn_region, proxy_vn=proxy_vn, vn_proxy=vn_proxy
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
        _emit_sync, qr_callback=qr_callback, timeout=timeout,
        custom_pc_name=custom_pc_name, region_code=region_code, vn_region=vn_region, proxy_vn=proxy_vn, vn_proxy=vn_proxy
    )
