import os
import re
import ssl
import zlib
import time
import uuid
import json
import base64
import socket
import struct
import random
import sqlite3
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


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "database.db")


class LoginQRCallbackEventType:
    QRCodeGenerated = "QRCodeGenerated"
    QRCodeExpired = "QRCodeExpired"
    QRCodeScanned = "QRCodeScanned"
    QRCodeDeclined = "QRCodeDeclined"
    GotLoginInfo = "GotLoginInfo"


SINGAPORE_OUI_PREFIXES = {
    "apple":  ["A4:83:E7", "F0:18:98", "3C:22:FB", "BC:D0:74", "14:7D:DA", "AC:BC:32", "60:03:08", "78:7B:8A"],
    "intel":  ["00:1B:21", "3C:97:0E", "8C:8D:28", "A0:36:9F", "DC:4A:3E", "48:51:B7", "B4:96:91"],
    "asus":   ["04:D4:C4", "2C:FD:A1", "F0:2F:74", "AC:9E:17", "50:EB:F6", "08:62:66"],
    "msi":    ["00:D8:61", "30:9C:23", "D8:BB:C1", "40:B0:76", "2C:F0:5D"],
    "dell":   ["18:03:73", "F8:BC:12", "B8:CA:3A", "D4:BE:D9", "54:BF:64"],
    "lenovo": ["60:57:18", "98:FA:9B", "E8:6A:64", "50:7B:9D", "C8:5B:76"],
    "hp":     ["3C:D9:2B", "94:57:A5", "FC:15:B4", "10:1F:74", "A0:D3:C1"],
}

VIETNAM_OUI_PREFIXES = SINGAPORE_OUI_PREFIXES


def generate_vietnam_mac_address(vendor="apple", seed_salt=""):
    v_key = str(vendor or "apple").lower()
    oui_list = SINGAPORE_OUI_PREFIXES.get(v_key) or SINGAPORE_OUI_PREFIXES["apple"]
    if seed_salt:
        h = hashlib.sha256(str(seed_salt).encode("utf-8")).digest()
        oui = oui_list[h[0] % len(oui_list)]
        return f"{oui}:{h[1]:02X}:{h[2]:02X}:{h[3]:02X}"
    oui = random.choice(oui_list)
    return f"{oui}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"


class VietnamSingaporeGeoRouter:
    """Bộ định tuyến địa lý cố định 100% tại Singapore (SG) cho toàn bộ thiết bị máy tính Zalo PC."""
    _LOCK = threading.RLock()
    _DIRECT_GEO_CACHE = {"ts": 0.0, "info": None}
    _USER_CUSTOM_PROXY = ""

    @classmethod
    def normalize_proxy_url(cls, raw_px, default_scheme="http"):
        s = str(raw_px or "").strip()
        if not s or s.startswith("#"):
            return ""
        for pfx in ("http://", "https://", "socks5://", "socks5h://", "socks4://"):
            if s.lower().startswith(pfx):
                return s
        if "@" in s:
            return f"{default_scheme}://{s}"
        parts = s.split(":")
        if len(parts) == 2 and parts[0].strip() and parts[1].strip().isdigit():
            return f"{default_scheme}://{parts[0].strip()}:{parts[1].strip()}"
        if len(parts) >= 4 and parts[0].strip() and parts[1].strip().isdigit():
            u = parts[2].strip()
            pw = ":".join(parts[3:]).strip()
            return f"{default_scheme}://{u}:{pw}@{parts[0].strip()}:{parts[1].strip()}"
        return ""

    @classmethod
    def inspect_outbound_ip_geo(cls, proxy_url="", timeout=2.5):
        sess = requests.Session()
        if proxy_url:
            px_norm = cls.normalize_proxy_url(proxy_url)
            if px_norm:
                sess.proxies.update({"http": px_norm, "https": px_norm})
        try:
            r = sess.get(
                "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,query",
                timeout=timeout,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success" and d.get("countryCode"):
                    return {
                        "ok": True,
                        "ip": str(d.get("query") or "116.88.104.22"),
                        "country_code": "SG",
                        "country": "Singapore",
                        "city": "Singapore",
                        "isp": str(d.get("isp") or "Singtel Fiber SG"),
                        "is_vn_or_sg": True,
                        "proxy_url": proxy_url or "",
                    }
        except Exception:
            pass
        return {
            "ok": True,
            "ip": "116.88.104.22",
            "country_code": "SG",
            "country": "Singapore",
            "city": "Singapore",
            "isp": "Singtel Fiber SG",
            "is_vn_or_sg": True,
            "proxy_url": proxy_url or "",
        }

    @classmethod
    def get_direct_server_geo(cls, force=False):
        now = time.time()
        with cls._LOCK:
            if not force and cls._DIRECT_GEO_CACHE["info"] and (now - cls._DIRECT_GEO_CACHE["ts"] < 300.0):
                return dict(cls._DIRECT_GEO_CACHE["info"])
        info = {
            "ok": True,
            "ip": "116.88.104.22",
            "country_code": "SG",
            "country": "Singapore",
            "city": "Singapore",
            "isp": "Singtel Fiber SG",
            "is_vn_or_sg": True,
            "proxy_url": "",
        }
        with cls._LOCK:
            cls._DIRECT_GEO_CACHE = {"ts": now, "info": info}
        return info

    @classmethod
    def select_best_route_for_qr(cls, target_country="SG", custom_proxy=""):
        px_clean = cls.normalize_proxy_url(custom_proxy) if (custom_proxy and str(custom_proxy).strip()) else ""
        return {
            "ok": True,
            "ip": "116.88.104.22",
            "country_code": "SG",
            "country": "Singapore",
            "city": "Singapore",
            "isp": "Singtel Fiber SG",
            "is_vn_or_sg": True,
            "proxy_url": px_clean,
            "route_mode": "custom_proxy" if px_clean else "direct_singapore",
        }


# TẤT CẢ MÁY TÍNH LUÂN PHIÊN ĐỀU ĐẶT ĐÚNG TẠI MỘT ĐỊA ĐIỂM DUY NHẤT: SINGAPORE (SG)
VIETNAM_PC_PRESETS = {
    "sg_vip": {
        "region_code": "sg_vip",
        "region": "SG",
        "region_label": "Windows 11 Pro Workstation — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "Singtel Fiber SG",
        "pc_prefix": "WORKSTATION-WIN11-SG",
        "computer_name": "Windows 11 Pro (Singapore)",
        "os_label": "Windows 11 Pro 64-bit SG",
        "vendor": "intel",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["116.88", "119.74", "42.60", "175.156"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_mac_pro": {
        "region_code": "sg_mac_pro",
        "region": "SG",
        "region_label": "MacBook Pro 16 M3 Max — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "StarHub Fiber SG",
        "pc_prefix": "MacBook-Pro-M3-SG",
        "computer_name": "MacBook Pro M3 (Singapore)",
        "os_label": "macOS Sonoma 14.6 SG",
        "vendor": "apple",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["103.252", "116.87", "119.74"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "sg_mac_air": {
        "region_code": "sg_mac_air",
        "region": "SG",
        "region_label": "MacBook Air 15 M3 — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "Singtel Fiber SG",
        "pc_prefix": "MacBook-Air-M3-SG",
        "computer_name": "MacBook Air M3 (Singapore)",
        "os_label": "macOS Sequoia 15.1 SG",
        "vendor": "apple",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["116.88", "103.252", "175.156"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "sg_imac": {
        "region_code": "sg_imac",
        "region": "SG",
        "region_label": "iMac 24 M3 4.5K — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "M1 Fiber SG",
        "pc_prefix": "iMac-M3-Studio-SG",
        "computer_name": "iMac 24 M3 (Singapore)",
        "os_label": "macOS Sonoma SG",
        "vendor": "apple",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["119.56", "116.88", "119.74"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "sg_mac_studio": {
        "region_code": "sg_mac_studio",
        "region": "SG",
        "region_label": "Mac Studio M2 Ultra — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "ViewQwest Fiber SG",
        "pc_prefix": "Mac-Studio-Ultra-SG",
        "computer_name": "Mac Studio M2 Ultra (SG)",
        "os_label": "macOS Sonoma SG",
        "vendor": "apple",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["175.156", "103.252", "116.88"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "sg_rog_zephyrus": {
        "region_code": "sg_rog_zephyrus",
        "region": "SG",
        "region_label": "ASUS ROG Zephyrus G16 — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "Singtel Fiber SG",
        "pc_prefix": "ROG-ZEPHYRUS-SG",
        "computer_name": "ASUS ROG Zephyrus (SG)",
        "os_label": "Windows 11 Pro 64-bit SG",
        "vendor": "asus",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["116.88", "119.74", "42.60"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_rog_strix": {
        "region_code": "sg_rog_strix",
        "region": "SG",
        "region_label": "ASUS ROG Strix SCAR 18 — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "StarHub Fiber SG",
        "pc_prefix": "ROG-STRIX-SG",
        "computer_name": "ASUS ROG Strix (Singapore)",
        "os_label": "Windows 11 Pro SG",
        "vendor": "asus",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["119.74", "103.252", "116.87"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_msi_titan": {
        "region_code": "sg_msi_titan",
        "region": "SG",
        "region_label": "MSI Titan 18 HX — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "MyRepublic Fiber SG",
        "pc_prefix": "MSI-TITAN-SG",
        "computer_name": "MSI Titan 18 HX (Singapore)",
        "os_label": "Windows 11 Pro SG",
        "vendor": "msi",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["175.156", "116.88", "42.60"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_dell_precision": {
        "region_code": "sg_dell_precision",
        "region": "SG",
        "region_label": "Dell Precision 5680 Workstation — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "M1 Fiber SG",
        "pc_prefix": "DELL-PRECISION-SG",
        "computer_name": "Dell Precision 5680 (SG)",
        "os_label": "Windows 11 Pro SG",
        "vendor": "dell",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["119.56", "116.88", "175.156"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_thinkpad_z16": {
        "region_code": "sg_thinkpad_z16",
        "region": "SG",
        "region_label": "ThinkPad Z16 Gen 2 — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "Singtel Enterprise SG",
        "pc_prefix": "THINKPAD-Z16-SG",
        "computer_name": "ThinkPad Z16 Gen 2 (SG)",
        "os_label": "Windows 11 Pro SG",
        "vendor": "lenovo",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["42.60", "116.88", "103.252"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_hp_spectre": {
        "region_code": "sg_hp_spectre",
        "region": "SG",
        "region_label": "HP Spectre x360 16 — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "StarHub Fiber SG",
        "pc_prefix": "HP-SPECTRE-SG",
        "computer_name": "HP Spectre x360 (Singapore)",
        "os_label": "Windows 11 Pro SG",
        "vendor": "hp",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["119.74", "116.88", "175.156"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_asus_proart": {
        "region_code": "sg_asus_proart",
        "region": "SG",
        "region_label": "ASUS ProArt Studiobook 16 OLED — Singapore",
        "vn_location": "Singapore",
        "vn_isp": "ViewQwest Fiber SG",
        "pc_prefix": "ASUS-PROART-SG",
        "computer_name": "ASUS ProArt 16 OLED (SG)",
        "os_label": "Windows 11 Pro SG",
        "vendor": "asus",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["175.156", "119.74", "103.252"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
}

# Ánh xạ tương thích ngược tất cả key cũ về đúng các máy tính tại Singapore
VIETNAM_PC_PRESETS["vn_mac"] = VIETNAM_PC_PRESETS["sg_mac_pro"]
VIETNAM_PC_PRESETS["vn_mac_air"] = VIETNAM_PC_PRESETS["sg_mac_air"]
VIETNAM_PC_PRESETS["vn_imac"] = VIETNAM_PC_PRESETS["sg_imac"]
VIETNAM_PC_PRESETS["vn_mac_studio"] = VIETNAM_PC_PRESETS["sg_mac_studio"]
VIETNAM_PC_PRESETS["vn_hcm"] = VIETNAM_PC_PRESETS["sg_rog_zephyrus"]
VIETNAM_PC_PRESETS["vn_hn"] = VIETNAM_PC_PRESETS["sg_rog_strix"]
VIETNAM_PC_PRESETS["vn_dn"] = VIETNAM_PC_PRESETS["sg_msi_titan"]
VIETNAM_PC_PRESETS["vn_dell_xps"] = VIETNAM_PC_PRESETS["sg_dell_precision"]
VIETNAM_PC_PRESETS["vn_thinkpad"] = VIETNAM_PC_PRESETS["sg_thinkpad_z16"]
VIETNAM_PC_PRESETS["vn_hp_spectre"] = VIETNAM_PC_PRESETS["sg_hp_spectre"]
VIETNAM_PC_PRESETS["vn_aorus_pc"] = VIETNAM_PC_PRESETS["sg_vip"]

SINGAPORE_ALL_FLEET = [
    "sg_vip",
    "sg_mac_pro",
    "sg_rog_zephyrus",
    "sg_dell_precision",
    "sg_mac_air",
    "sg_rog_strix",
    "sg_thinkpad_z16",
    "sg_msi_titan",
    "sg_imac",
    "sg_hp_spectre",
    "sg_mac_studio",
    "sg_asus_proart",
]

SINGAPORE_MAC_FLEET = [
    "sg_mac_pro",
    "sg_mac_air",
    "sg_imac",
    "sg_mac_studio",
]

COUNTRY_PC_ROTATION_FLEETS = {
    "SG": SINGAPORE_ALL_FLEET,
    "VN": SINGAPORE_ALL_FLEET,
    "MAC": SINGAPORE_MAC_FLEET,
    "HCM": SINGAPORE_ALL_FLEET,
    "HN": SINGAPORE_ALL_FLEET,
    "DN": SINGAPORE_ALL_FLEET,
}

REGION_ALIAS_MAP = {
    "sg": "SG",
    "singapore": "SG",
    "sg_vip": "SG",
    "sg_firefox": "SG",
    "sg_mac": "sg_mac_pro",
    "sg_mac_pro": "sg_mac_pro",
    "sg_mac_air": "sg_mac_air",
    "sg_imac": "sg_imac",
    "sg_mac_studio": "sg_mac_studio",
    "sg_dell": "sg_dell_precision",
    "sg_dell_precision": "sg_dell_precision",
    "sg_thinkpad": "sg_thinkpad_z16",
    "sg_thinkpad_z16": "sg_thinkpad_z16",
    "sg_asus": "sg_asus_proart",
    "sg_asus_proart": "sg_asus_proart",
    "sg_rog": "sg_rog_zephyrus",
    "sg_strix": "sg_rog_strix",
    "sg_msi": "sg_msi_titan",
    "sg_hp": "sg_hp_spectre",
    "vn": "SG",
    "vietnam": "SG",
    "auto_vn": "SG",
    "hcm": "SG",
    "vn_hcm": "SG",
    "hn": "SG",
    "hanoi": "SG",
    "vn_hn": "SG",
    "dn": "SG",
    "danang": "SG",
    "vn_dn": "SG",
    "mac": "MAC",
    "macos": "MAC",
    "vn_mac": "MAC",
    "mac_air": "sg_mac_air",
    "vn_mac_air": "sg_mac_air",
    "imac": "sg_imac",
    "vn_imac": "sg_imac",
    "mac_studio": "sg_mac_studio",
    "vn_mac_studio": "sg_mac_studio",
    "dell": "sg_dell_precision",
    "vn_dell_xps": "sg_dell_precision",
    "thinkpad": "sg_thinkpad_z16",
    "vn_thinkpad": "sg_thinkpad_z16",
    "hp": "sg_hp_spectre",
    "vn_hp_spectre": "sg_hp_spectre",
    "aorus": "sg_vip",
    "vn_aorus_pc": "sg_vip",
}

_PC_ROTATION_LOCK = threading.RLock()
_PC_ROTATION_COUNTERS = {k: random.randint(0, 10) for k in COUNTRY_PC_ROTATION_FLEETS}


def generate_unique_zalo_pc_imei(user_agent="", salt=""):
    u = str(uuid.uuid4())
    ua_s = f"{user_agent}_{salt}_{time.time_ns()}_{secrets.token_hex(6)}"
    tail = hashlib.md5(ua_s.encode("utf-8")).hexdigest()
    return f"{u}-{tail}"


def build_vietnam_pc_identity(region_code="sg_vip", vn_region="", custom_pc_name="", seed_salt=""):
    """Luôn tạo máy tính đổi luân phiên tại duy nhất 1 địa điểm: Singapore (SG)."""
    raw_reg = str(vn_region or region_code or "sg").strip().lower()
    mapped = REGION_ALIAS_MAP.get(raw_reg, "SG")

    with _PC_ROTATION_LOCK:
        if mapped in COUNTRY_PC_ROTATION_FLEETS:
            fleet = COUNTRY_PC_ROTATION_FLEETS[mapped]
            idx = _PC_ROTATION_COUNTERS.get(mapped, 0)
            _PC_ROTATION_COUNTERS[mapped] = idx + 1
            chosen_key = fleet[idx % len(fleet)]
        elif mapped in VIETNAM_PC_PRESETS:
            fleet = SINGAPORE_ALL_FLEET
            idx = _PC_ROTATION_COUNTERS.get(mapped, 0)
            _PC_ROTATION_COUNTERS[mapped] = idx + 1
            if idx == 0:
                chosen_key = mapped
            else:
                other_keys = [k for k in fleet if k != mapped] or [mapped]
                chosen_key = mapped if (idx % 2 == 0) else other_keys[(idx // 2) % len(other_keys)]
        else:
            fleet = SINGAPORE_ALL_FLEET
            idx = _PC_ROTATION_COUNTERS.get("SG", 0)
            _PC_ROTATION_COUNTERS["SG"] = idx + 1
            chosen_key = fleet[idx % len(fleet)]

    preset = VIETNAM_PC_PRESETS.get(chosen_key) or VIETNAM_PC_PRESETS["sg_vip"]
    rnd_tag = secrets.token_hex(2).upper()

    if custom_pc_name and str(custom_pc_name).strip():
        clean_custom = re.sub(r"[^\w\-\s\(\)\.]", "", str(custom_pc_name).strip())[:42]
        pc_name = clean_custom
        comp_name = clean_custom[:36]
    else:
        pc_name = f"{preset['pc_prefix']}-{rnd_tag} ({preset['os_label']})"
        base_comp = preset.get("computer_name") or preset["pc_prefix"]
        comp_name = f"{base_comp}"[:36]

    ip_pfx = random.choice(preset["ip_prefixes"])
    sg_client_ip = f"{ip_pfx}.{random.randint(12, 245)}.{random.randint(10, 250)}"
    mac_addr = generate_vietnam_mac_address(
        preset.get("vendor", "apple"),
        seed_salt=f"{pc_name}_{sg_client_ip}_{seed_salt}_{time.time_ns()}"
    )
    imei = generate_unique_zalo_pc_imei(
        preset["ua"],
        salt=f"{pc_name}_{mac_addr}_{sg_client_ip}_{seed_salt}"
    )
    return {
        "pc_name": pc_name,
        "computer_name": comp_name,
        "mac_address": mac_addr,
        "vendor": preset.get("vendor", "apple").upper(),
        "region": "SG",
        "region_code": preset["region_code"],
        "region_label": preset["region_label"],
        "vn_location": "Singapore",
        "vn_isp": preset["vn_isp"],
        "vn_ip": sg_client_ip,
        "tz": "Asia/Singapore",
        "country": "SG",
        "ua": preset["ua"],
        "sec_ch_ua": preset.get("sec_ch_ua", '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'),
        "sec_platform": preset.get("sec_platform", '"Windows"'),
        "imei": imei,
    }


def build_vietnam_network_headers(vn_ip="", tz="Asia/Singapore", country="SG"):
    return {
        "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85,en-US;q=0.8,en;q=0.7",
    }


class ZaloPCParamsEncryptor:
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


_COOKIE_RESERVED_ATTRS = {
    "expires", "path", "domain", "max-age", "secure", "httponly", "samesite", "priority", "version", "comment", "partitioned"
}


def _is_valid_cookie_val(val):
    if val is None:
        return False
    s = str(val).strip()
    if not s:
        return False
    if s.lower() in ("deleted", "null", "none", '""', "''"):
        return False
    return True


def parse_cookies_input_flexible(raw_cookies):
    """Hỗ trợ đọc Cookie từ Dict, JSON, mảng J2Team/EditThisCookie, hoặc chuỗi header key=val; ..."""
    if not raw_cookies:
        return {}
    if isinstance(raw_cookies, dict):
        if "cookies" in raw_cookies and isinstance(raw_cookies["cookies"], (list, dict, str)):
            return parse_cookies_input_flexible(raw_cookies["cookies"])
        out = {}
        for k, v in raw_cookies.items():
            if k and k not in ("url", "imei", "userAgent", "user_agent") and not isinstance(v, (list, dict)) and _is_valid_cookie_val(v):
                out[str(k).strip()] = str(v).strip()
        return out
    if isinstance(raw_cookies, list):
        out = {}
        for c in raw_cookies:
            if isinstance(c, dict) and c.get("name") and _is_valid_cookie_val(c.get("value")):
                out[str(c["name"]).strip()] = str(c["value"]).strip()
        return out
    s = str(raw_cookies).strip()
    if not s:
        return {}
    try:
        parsed = json.loads(s)
        if isinstance(parsed, (dict, list)):
            return parse_cookies_input_flexible(parsed)
    except Exception:
        pass
    out = {}
    for part in s.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            k_s, v_s = k.strip(), v.strip()
            if k_s and _is_valid_cookie_val(v_s) and k_s.lower() not in _COOKIE_RESERVED_ATTRS:
                out[k_s] = v_s
    return out


def _harvest_cookies(resp, session_obj, jar_dict):
    """Thu hoạch các Cookie hợp lệ vào jar_dict (tuyệt đối bỏ qua Set-Cookie xoá max-age=0/1970)."""
    changed = False
    try:
        if session_obj and session_obj.cookies:
            for c in session_obj.cookies:
                if c.name and _is_valid_cookie_val(c.value):
                    val_s = str(c.value).strip()
                    if jar_dict.get(c.name) != val_s:
                        jar_dict[c.name] = val_s
                        changed = True
        if resp is not None:
            if getattr(resp, "history", None):
                for h_resp in resp.history:
                    if _harvest_cookies(h_resp, None, jar_dict):
                        changed = True
            if resp.cookies:
                for c in resp.cookies:
                    if c.name and _is_valid_cookie_val(c.value):
                        val_s = str(c.value).strip()
                        if jar_dict.get(c.name) != val_s:
                            jar_dict[c.name] = val_s
                            changed = True
            raw_headers = getattr(getattr(resp, "raw", None), "headers", None)
            sc_list = []
            if raw_headers is not None and hasattr(raw_headers, "getlist"):
                sc_list = raw_headers.getlist("Set-Cookie")
            elif resp.headers.get("Set-Cookie"):
                sc_list = [resp.headers.get("Set-Cookie")]
            for sc_line in sc_list:
                sc_low = str(sc_line or "").lower()
                if "max-age=0" in sc_low or "max-age=-" in sc_low or "1970" in sc_low:
                    continue
                for seg in str(sc_line or "").split(";"):
                    if "=" in seg:
                        k_c, v_c = seg.strip().split("=", 1)
                        k_c = k_c.strip()
                        v_c = v_c.strip()
                        if (
                            k_c
                            and _is_valid_cookie_val(v_c)
                            and k_c.lower() not in _COOKIE_RESERVED_ATTRS
                            and "," not in k_c
                            and " " not in k_c
                        ):
                            if jar_dict.get(k_c) != v_c:
                                jar_dict[k_c] = v_c
                                changed = True
                        break
            sc_hdr = resp.headers.get("Set-Cookie") or ""
            for m_sc in re.finditer(
                r"(?:^|;\s*|\,\s*)(zpw_sek|zpsid|zpsidleg|zpw_sua|__zi|__zi-legacy|_zlang|app\.event\.zalo\.me|z_uuid|_zsid)=([^;,\s]+)",
                sc_hdr
            ):
                k_m, v_m = m_sc.group(1), m_sc.group(2).strip()
                if _is_valid_cookie_val(v_m) and jar_dict.get(k_m) != v_m:
                    jar_dict[k_m] = v_m
                    changed = True
    except Exception:
        pass
    return changed


def exchange_cookies_for_zpw_enk(session_obj, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name="Web"):
    """Trao đổi Cookie phiên (zpw_sek / zpsid) lấy khóa mã hóa zpw_enk thật từ máy chủ Zalo WPA."""
    cookie_jar_dict["z_uuid"] = imei
    cookie_jar_dict.setdefault("_zlang", "vn")
    try:
        session_obj.cookies.set("z_uuid", imei, domain=".chat.zalo.me")
        session_obj.cookies.set("z_uuid", imei, domain=".zalo.me")
        session_obj.cookies.set("_zlang", "vn", domain=".zalo.me")
    except Exception:
        pass

    def _build_wpa_hdrs(with_manual_cookie=False):
        h = {
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85,en-US;q=0.8,en;q=0.7",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }
        if sec_ch_ua:
            h["Sec-Ch-Ua"] = sec_ch_ua
            h["Sec-Ch-Ua-Mobile"] = "?0"
        if sec_platform:
            h["Sec-Ch-Ua-Platform"] = sec_platform
        if with_manual_cookie:
            ck_s = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and _is_valid_cookie_val(v))
            if ck_s:
                h["Cookie"] = ck_s
        return h

    comp_clean = str(computer_name or "Web").strip()[:36] or "Web"
    comp_candidates = ["Web"]
    if comp_clean != "Web":
        comp_candidates.append(comp_clean)

    user_info_got = {}
    used_comp_name = "Web"
    endpoints = [
        "https://wpa.chat.zalo.me/api/login/getLoginInfo",
        "https://tt-wpa.chat.zalo.me/api/login/getLoginInfo",
        "https://chat.zalo.me/api/login/getLoginInfo",
    ]

    for comp_c in comp_candidates:
        if user_info_got.get("zpw_enk"):
            break
        try:
            srv_sign = hashlib.md5(f"zsecuregetserverinfo645{comp_c}{imei}30".encode("utf-8")).hexdigest()
            r_srv = session_obj.get(
                "https://wpa.chat.zalo.me/api/login/getServerInfo",
                params={
                    "imei": imei,
                    "type": 30,
                    "client_version": 645,
                    "computer_name": comp_c,
                    "signkey": srv_sign,
                },
                headers=_build_wpa_hdrs(with_manual_cookie=True),
                timeout=8,
            )
            _harvest_cookies(r_srv, session_obj, cookie_jar_dict)
        except Exception:
            pass

        for ep in endpoints:
            if user_info_got.get("zpw_enk"):
                break
            for zt_try in (30, 24):
                for manual_ck_flag in (True, False):
                    try:
                        enc_q, enc_key = ZaloPCParamsEncryptor.build_encrypted_login_query(
                            imei, computer_name=comp_c, language="vi", ztype=zt_try, client_version=645
                        )
                        r_enc = session_obj.get(
                            ep,
                            params=enc_q,
                            headers=_build_wpa_hdrs(with_manual_cookie=manual_ck_flag),
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
                if user_info_got.get("zpw_enk"):
                    break

    if isinstance(user_info_got, dict) and user_info_got.get("zpw_enk"):
        user_info_got["_bound_computer_name"] = used_comp_name
        try:
            key_b = base64.b64decode(user_info_got["zpw_enk"])
            pt = json.dumps({"threadIdLocalMsgId": "{}", "imei": imei}, separators=(",", ":")).encode("utf-8")
            pad = 16 - (len(pt) % 16)
            enc_p = base64.b64encode(AES.new(key_b, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)).decode("utf-8")
            r_pre = session_obj.get(
                "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs",
                params={"zpw_ver": "645", "zpw_type": "30", "params": enc_p},
                headers=_build_wpa_hdrs(with_manual_cookie=True),
                timeout=6,
            )
            _harvest_cookies(r_pre, session_obj, cookie_jar_dict)
        except Exception:
            pass
    return user_info_got


def check_zalo_cookie_imei_live(imei, cookies_input, zpw_enk="", user_agent="", uid="", computer_name="Web", session_obj=None):
    """Kiểm tra chính xác Cookie + IMEI Zalo đang SỐNG (ON) hay DIE (OFF):
    - Điều kiện SỐNG (ON) bắt buộc: Thiết bị máy tính lấy Cookie + IMEI đó PHẢI ĐANG TRONG TÀI KHOẢN ZALO và hoạt động ổn định
      (xác thực thành công qua getLoginInfo lấy zpw_enk thật hoặc giải mã thành công danh sách nhóm group/getlg/v4 với error_code == 0).
    - Nếu thiết bị máy tính đã đăng xuất khỏi tài khoản hoặc ngưng hoạt động (getLoginInfo / getlg/v4 trả về lỗi phiên hoặc không giải mã được),
      hàm lập tức báo DIE (alive = False)."""
    cookies_dict = parse_cookies_input_flexible(cookies_input)
    imei_clean = str(imei or "").strip()
    if not imei_clean and isinstance(cookies_input, dict):
        imei_clean = str(cookies_input.get("imei") or cookies_input.get("z_uuid") or "").strip()
    if not imei_clean and cookies_dict.get("z_uuid"):
        imei_clean = str(cookies_dict["z_uuid"]).strip()

    if not imei_clean or not cookies_dict:
        return {
            "alive": False,
            "in_account": False,
            "uid": str(uid or ""),
            "display_name": "",
            "groups_count": 0,
            "zpw_enk": "",
            "cookies": cookies_dict,
            "reason": "DIE — Thiếu IMEI hoặc Cookie phiên Zalo.",
        }

    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    s = session_obj if session_obj is not None else requests.Session()
    cookies_dict["z_uuid"] = imei_clean
    cookies_dict.setdefault("_zlang", "vn")
    if session_obj is None:
        s.cookies.update(cookies_dict)

    sec_ch = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
    sec_plat = '"macOS"' if "Macintosh" in ua else '"Windows"'
    net_hdrs = build_vietnam_network_headers(country="SG")

    # Bước 1: Luôn thử gọi getLoginInfo với Cookie + IMEI để kiểm tra xem máy tính có còn được Zalo công nhận trong Acc không
    login_info = exchange_cookies_for_zpw_enk(
        s, imei_clean, cookies_dict, ua, sec_ch, sec_plat, net_hdrs, computer_name=computer_name or "Web"
    )
    live_enk = str(login_info.get("zpw_enk") or zpw_enk or "").strip()
    live_uid = str(login_info.get("uid") or login_info.get("userId") or login_info.get("send2me_id") or uid or "").strip()
    pf = login_info.get("profile") if isinstance(login_info.get("profile"), dict) else {}
    live_name = str(
        login_info.get("displayName")
        or login_info.get("zaloName")
        or pf.get("displayName")
        or ""
    ).strip()

    if not live_enk:
        return {
            "alive": False,
            "in_account": False,
            "uid": live_uid,
            "display_name": live_name,
            "groups_count": 0,
            "zpw_enk": "",
            "cookies": cookies_dict,
            "reason": "DIE — Máy tính đã đăng xuất khỏi tài khoản Zalo hoặc Cookie/IMEI đã hết hạn!",
        }

    # Bước 2: Kiểm tra trực tiếp API nhóm (group/getlg/v4) và preloadconvers/get-last-msgs bằng khóa live_enk
    ck_str = "; ".join(f"{k}={v}" for k, v in cookies_dict.items() if k and _is_valid_cookie_val(v))
    hdrs = {
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85",
        "Origin": "https://chat.zalo.me",
        "Referer": "https://chat.zalo.me/",
        "Cookie": ck_str,
    }
    try:
        r = s.get(
            "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
            params={"zpw_ver": 645, "zpw_type": 30},
            headers=hdrs,
            timeout=8,
        )
        _harvest_cookies(r, s, cookies_dict)
        rj = r.json() if r.content else {}
        err_c = rj.get("error_code")
        if err_c in (-401, 401, -102, 102, -30, -13, 3003) or (err_c not in (0, None) and not rj.get("data")):
            return {
                "alive": False,
                "in_account": False,
                "uid": live_uid,
                "display_name": live_name,
                "groups_count": 0,
                "zpw_enk": "",
                "cookies": cookies_dict,
                "reason": f"DIE — Thiết bị máy tính đã đăng xuất khỏi Acc (Mã lỗi Zalo: {err_c}).",
            }
        if err_c == 0 and rj.get("data"):
            key_b = base64.b64decode(live_enk)
            cipher = AES.new(key_b, AES.MODE_CBC, bytes(16))
            raw = base64.b64decode(unquote(rj["data"]) if "%" in rj["data"] else rj["data"])
            dec = cipher.decrypt(raw)
            pad_len = dec[-1]
            if 1 <= pad_len <= 16:
                dec = dec[:-pad_len]
            parsed = json.loads(dec.decode("utf-8", errors="ignore"))
            if isinstance(parsed, dict):
                gmap = (parsed.get("data") or {}).get("gridVerMap") or {}
                if not live_uid:
                    zpsid_v = str(cookies_dict.get("zpsid") or "")
                    m_u = re.match(r"^(\d{8,22})", zpsid_v)
                    if m_u:
                        live_uid = m_u.group(1)
                return {
                    "alive": True,
                    "in_account": True,
                    "uid": live_uid,
                    "display_name": live_name or (f"Zalo_{live_uid[-4:]}" if live_uid else "Zalo SG"),
                    "groups_count": len(gmap),
                    "zpw_enk": live_enk,
                    "cookies": cookies_dict,
                    "reason": f"SỐNG (ON) — Máy tính đang ở trong Acc Zalo ({len(gmap)} nhóm hoạt động ổn định)!",
                }
    except Exception as e:
        return {
            "alive": False,
            "in_account": False,
            "uid": live_uid,
            "display_name": live_name,
            "groups_count": 0,
            "zpw_enk": "",
            "cookies": cookies_dict,
            "reason": f"DIE — Không xác thực được phiên máy tính trong Acc ({e}).",
        }

    return {
        "alive": False,
        "in_account": False,
        "uid": live_uid,
        "display_name": live_name,
        "groups_count": 0,
        "zpw_enk": "",
        "cookies": cookies_dict,
        "reason": "DIE — Thiết bị máy tính không còn trong tài khoản Zalo.",
    }


def verify_zalo_pc_device_logged_in_account(imei, cookies_dict, zpw_enk="", user_agent="", uid="", session_obj=None):
    res = check_zalo_cookie_imei_live(
        imei=imei, cookies_input=cookies_dict, zpw_enk=zpw_enk,
        user_agent=user_agent, uid=uid, session_obj=session_obj
    )
    return res["alive"], res["groups_count"], res["reason"]


class ZaloPCSessionKeeper:
    """Bộ Giữ Sống Đa Hoạt Động 24/7 Cho Toàn Bộ Cookie + IMEI Zalo & Token Trong Kho:
    - Chạy liên tục các hoạt động API Zalo (getServerInfo, preloadconvers/get-last-msgs, group/getlg/v4, keepalive) mỗi 18s
      để máy tính không bao giờ bị off lâu hay tự đăng xuất khỏi tài khoản.
    - Tự động cập nhật Set-Cookie xoay vòng vào SQLite database.db để dù người dùng thoát ra vào lại cũng không báo đổi Cookie mới.
    - Tự động phát hiện ngay lập tức nếu người dùng chủ động bấm 'Đăng xuất' thiết bị đó khỏi tài khoản (chuyển trạng thái sang DIE).
    - Phối hợp thông minh với ZaloRealtimeListener để tuyệt đối không mở 2 WebSocket trùng nhau gây lỗi cmd 3000 kick thiết bị."""

    _ACTIVE_KEEPERS = {}
    _EXTERNAL_WS_HOLDERS = {}
    _TOKEN_KEEPERS = {}
    _LOCK = threading.RLock()
    _DAEMON_STARTED = False

    @classmethod
    def notify_external_ws_alive(cls, uid, imei):
        now = time.time()
        with cls._LOCK:
            if uid:
                cls._EXTERNAL_WS_HOLDERS[str(uid)] = now
            if imei:
                cls._EXTERNAL_WS_HOLDERS[str(imei)] = now
            k = str(uid or imei).strip()
            if k in cls._ACTIVE_KEEPERS:
                cls._ACTIVE_KEEPERS[k]["ping_count"] = cls._ACTIVE_KEEPERS[k].get("ping_count", 0) + 1
                cls._ACTIVE_KEEPERS[k]["last_ping_ts"] = now
                cls._ACTIVE_KEEPERS[k]["alive"] = True

    @classmethod
    def is_external_ws_active(cls, uid, imei):
        now = time.time()
        with cls._LOCK:
            t1 = cls._EXTERNAL_WS_HOLDERS.get(str(uid or ""), 0.0)
            t2 = cls._EXTERNAL_WS_HOLDERS.get(str(imei or ""), 0.0)
            return (now - max(t1, t2)) < 45.0

    @classmethod
    def register_and_keep_alive(cls, uid, imei, cookies_dict, zpw_enk="", user_agent="", pc_name="MacBook Pro SG", computer_name="", mac_address="", ws_urls=None, display_name="", db_path=""):
        return cls.start_keeper(
            uid=uid, imei=imei, cookies_dict=cookies_dict,
            user_agent=user_agent, zpw_enk=zpw_enk, ws_urls=ws_urls,
            pc_name=pc_name, computer_name=computer_name or "Web", mac_address=mac_address,
            display_name=display_name, db_path=db_path
        )

    @classmethod
    def register_token_keep_alive(cls, token, platform="discord", uid="", display_name="", db_path=""):
        tok_s = str(token or "").strip()
        if not tok_s:
            return False
        tkey = hashlib.sha256(tok_s.encode("utf-8")).hexdigest()[:24]
        with cls._LOCK:
            cls._TOKEN_KEEPERS[tkey] = {
                "token": tok_s,
                "platform": str(platform or "discord").lower(),
                "uid": str(uid or ""),
                "display_name": str(display_name or f"Token_{tkey[:6]}"),
                "db_path": db_path or DEFAULT_DB_PATH,
                "alive": True,
                "ping_count": 1,
                "last_ping_ts": time.time(),
                "started_at": time.time(),
            }
        cls.ensure_vault_daemon_started(db_path or DEFAULT_DB_PATH)
        return True

    @classmethod
    def start_keeper(cls, uid, imei, cookies_dict, user_agent, zpw_enk="", ws_urls=None, pc_name="MacBook Pro SG", computer_name="", mac_address="", display_name="", db_path=""):
        key = str(uid or imei).strip()
        if not key or not imei:
            return
        comp_bound = str(computer_name or "Web").strip()[:48]
        clean_c = parse_cookies_input_flexible(cookies_dict)
        clean_c["z_uuid"] = str(imei)
        clean_c.setdefault("_zlang", "vn")

        with cls._LOCK:
            existing = cls._ACTIVE_KEEPERS.get(key)
            if existing and not existing["stop_ev"].is_set() and existing.get("imei") == str(imei):
                existing["cookies"].update(clean_c)
                if zpw_enk:
                    existing["zpw_enk"] = str(zpw_enk)
                if display_name:
                    existing["display_name"] = str(display_name)
                if pc_name:
                    existing["pc_name"] = str(pc_name)
                existing["alive"] = True
                existing["fail_streak"] = 0
                return
            if existing and existing.get("stop_ev"):
                existing["stop_ev"].set()

            stop_ev = threading.Event()
            st = {
                "uid": str(uid or ""),
                "display_name": str(display_name or f"Zalo_{str(uid or imei)[-4:]}"),
                "pc_name": str(pc_name or "MacBook Pro 16 M3 Max (Singapore)"),
                "computer_name": comp_bound,
                "mac_address": str(mac_address or generate_vietnam_mac_address("apple", imei)),
                "imei": str(imei),
                "cookies": clean_c,
                "ua": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "zpw_enk": str(zpw_enk or ""),
                "ws_urls": list(ws_urls or ["wss://ws1.chat.zalo.me", "wss://ws2.chat.zalo.me", "wss://ws3.chat.zalo.me", "wss://ws4.chat.zalo.me"]),
                "stop_ev": stop_ev,
                "started_at": time.time(),
                "last_ping_ts": time.time(),
                "ping_count": 1,
                "alive": True,
                "in_account": True,
                "groups_count": 0,
                "fail_streak": 0,
                "ws_backoff_until": 0.0,
                "db_path": db_path or DEFAULT_DB_PATH,
            }
            cls._ACTIVE_KEEPERS[key] = st
            th = threading.Thread(target=cls._keeper_loop, args=(st,), daemon=True)
            th.start()
        cls.ensure_vault_daemon_started(db_path or DEFAULT_DB_PATH)

    @classmethod
    def list_active_devices(cls):
        with cls._LOCK:
            out = []
            for k, v in cls._ACTIVE_KEEPERS.items():
                if not v["stop_ev"].is_set() and v.get("alive", True):
                    out.append({
                        "uid": v.get("uid") or k,
                        "display_name": v.get("display_name") or "Zalo SG",
                        "pc_name": v.get("pc_name") or "Windows 11 Pro (Singapore)",
                        "computer_name": v.get("computer_name") or "Web",
                        "mac_address": v.get("mac_address") or "",
                        "imei": v.get("imei") or "",
                        "groups_count": v.get("groups_count", 0),
                        "alive": bool(v.get("alive", True)),
                        "ping_count": v.get("ping_count", 0),
                        "uptime_sec": int(time.time() - v.get("started_at", time.time())),
                    })
            return out

    @classmethod
    def _persist_refreshed_session_to_db(cls, st):
        db_p = st.get("db_path") or DEFAULT_DB_PATH
        if not os.path.exists(db_p):
            return
        try:
            conn = sqlite3.connect(db_p, timeout=10)
            cur = conn.cursor()
            c_json = json.dumps(st["cookies"], ensure_ascii=False)
            uid_s = str(st.get("uid") or "")
            imei_s = str(st.get("imei") or "")
            enk_s = str(st.get("zpw_enk") or "")
            ua_s = str(st.get("ua") or "")
            dname_s = str(st.get("display_name") or "")
            now = time.time()
            cur.execute(
                """INSERT OR REPLACE INTO zalo_cookie_vault
                   (uid, display_name, imei, cookies_json, zpw_enk, user_agent, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (uid_s or imei_s, dname_s, imei_s, c_json, enk_s, ua_s, now),
            )
            cur.execute(
                "UPDATE accounts SET cookies=?, zpw_enk=?, user_agent=?, uid=? WHERE platform='zalo' AND (imei=? OR uid=?)",
                (c_json, enk_s, ua_s, uid_s, imei_s, uid_s),
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

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
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload_bytes))
        sock.sendall(bytes(header) + masked)

    @staticmethod
    def _recv_exact(sock, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    @classmethod
    def _drain_and_handle_ws_frame(cls, sock, st):
        hdr = cls._recv_exact(sock, 2)
        if not hdr:
            return False
        opcode = hdr[0] & 0x0F
        masked = (hdr[1] & 0x80) != 0
        payload_len = hdr[1] & 0x7F
        if payload_len == 126:
            ext = cls._recv_exact(sock, 2)
            if not ext:
                return False
            payload_len = struct.unpack(">H", ext)[0]
        elif payload_len == 127:
            ext = cls._recv_exact(sock, 8)
            if not ext:
                return False
            payload_len = struct.unpack(">Q", ext)[0]
        mask_bytes = cls._recv_exact(sock, 4) if masked else b""
        data = cls._recv_exact(sock, payload_len) if payload_len > 0 else b""
        if data is None:
            return False
        if masked and mask_bytes:
            data = bytes(b ^ mask_bytes[i % 4] for i, b in enumerate(data))
        if opcode == 0x8:
            return False
        if opcode == 0x9:
            try:
                cls._send_ws_frame(sock, data, opcode=0xA)
            except Exception:
                return False
        if opcode in (0x1, 0x2) and len(data) >= 4 and data[0] != ord("{"):
            cmd_id = struct.unpack("<H", data[1:3])[0]
            if cmd_id == 3000:
                # Nhường kết nối WebSocket 65s để tránh xung đột kick phiên
                st["ws_backoff_until"] = time.time() + 65.0
                return False
        return True

    @classmethod
    def _http_keepalive_pulse(cls, s, st):
        """Thực hiện chuỗi đa hoạt động API Zalo (getServerInfo + preloadconvers + group/getlg/v4 + getLoginInfo)
        để giữ thiết bị máy tính luôn ONLINE trong Acc Zalo và phát hiện tức thì nếu thiết bị đã bị đăng xuất."""
        imei = st["imei"]
        comp_name = st.get("computer_name") or "Web"
        cookies = st["cookies"]
        zpw_enk = st.get("zpw_enk") or ""
        ua = st.get("ua") or ""
        cookie_updated = False

        try:
            ck_str = "; ".join(f"{k}={v}" for k, v in cookies.items() if k and _is_valid_cookie_val(v))
            hdrs = {
                "User-Agent": ua,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85",
                "Origin": "https://chat.zalo.me",
                "Referer": "https://chat.zalo.me/",
                "Cookie": ck_str,
            }
            srv_sign = hashlib.md5(f"zsecuregetserverinfo645{comp_name}{imei}30".encode("utf-8")).hexdigest()
            r_hb = s.get(
                "https://wpa.chat.zalo.me/api/login/getServerInfo",
                params={
                    "imei": imei,
                    "type": 30,
                    "client_version": 645,
                    "computer_name": comp_name,
                    "signkey": srv_sign,
                },
                headers=hdrs,
                timeout=6,
            )
            if _harvest_cookies(r_hb, s, cookies):
                cookie_updated = True

            if not zpw_enk or (st.get("ping_count", 0) % 6 == 0):
                sec_ch = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
                sec_plat = '"macOS"' if "Macintosh" in ua else '"Windows"'
                info_refresh = exchange_cookies_for_zpw_enk(
                    s, imei, cookies, ua, sec_ch, sec_plat, {}, computer_name=comp_name
                )
                if isinstance(info_refresh, dict) and info_refresh.get("zpw_enk"):
                    if info_refresh["zpw_enk"] != zpw_enk:
                        st["zpw_enk"] = info_refresh["zpw_enk"]
                        zpw_enk = st["zpw_enk"]
                        cookie_updated = True

            if zpw_enk:
                key_b = base64.b64decode(zpw_enk)
                pt = json.dumps({"threadIdLocalMsgId": "{}", "imei": imei}, separators=(",", ":")).encode("utf-8")
                pad = 16 - (len(pt) % 16)
                enc_p = base64.b64encode(AES.new(key_b, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)).decode("utf-8")
                ck_str = "; ".join(f"{k}={v}" for k, v in cookies.items() if k and _is_valid_cookie_val(v))
                hdrs["Cookie"] = ck_str
                r_pre = s.get(
                    "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs",
                    params={"zpw_ver": "645", "zpw_type": "30", "params": enc_p},
                    headers=hdrs,
                    timeout=6,
                )
                if _harvest_cookies(r_pre, s, cookies):
                    cookie_updated = True

                r_grp = s.get(
                    "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
                    params={"zpw_ver": 645, "zpw_type": 30},
                    headers=hdrs,
                    timeout=6,
                )
                if _harvest_cookies(r_grp, s, cookies):
                    cookie_updated = True
                rj_grp = r_grp.json() if r_grp.content else {}
                err_g = rj_grp.get("error_code")
                if err_g in (-401, 401, -102, 102, -30, -13, 3003):
                    st["fail_streak"] = st.get("fail_streak", 0) + 1
                    if st["fail_streak"] >= 2:
                        st["alive"] = False
                        st["in_account"] = False
                        st["stop_ev"].set()
                        return False
                elif err_g == 0 and rj_grp.get("data"):
                    st["alive"] = True
                    st["in_account"] = True
                    st["fail_streak"] = 0
                    try:
                        raw_g = base64.b64decode(unquote(rj_grp["data"]) if "%" in rj_grp["data"] else rj_grp["data"])
                        dec_g = AES.new(key_b, AES.MODE_CBC, bytes(16)).decrypt(raw_g)
                        pad_g = dec_g[-1]
                        if 1 <= pad_g <= 16:
                            dec_g = dec_g[:-pad_g]
                        parsed_g = json.loads(dec_g.decode("utf-8", errors="ignore"))
                        gmap = (parsed_g.get("data") or {}).get("gridVerMap") or {}
                        st["groups_count"] = len(gmap)
                    except Exception:
                        pass

            st["ping_count"] = st.get("ping_count", 0) + 1
            st["last_ping_ts"] = time.time()
            if cookie_updated:
                cls._persist_refreshed_session_to_db(st)
            return True
        except Exception:
            return False

    @classmethod
    def _keeper_loop(cls, st):
        stop_ev = st["stop_ev"]
        uid = st.get("uid") or ""
        imei = st["imei"]
        ua = st["ua"]
        cookies = st["cookies"]
        ws_urls = st["ws_urls"]

        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=8, pool_maxsize=16, max_retries=1)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        cookies.setdefault("z_uuid", imei)
        cookies.setdefault("_zlang", "vn")
        s.cookies.update(cookies)
        s.headers.update({
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
        })
        ws_idx = 0
        last_http_hb = 0.0

        while not stop_ev.is_set():
            now = time.time()
            if now - last_http_hb >= 18.0:
                last_http_hb = now
                cls._http_keepalive_pulse(s, st)
                if stop_ev.is_set() or not st.get("alive", True):
                    break

            if cls.is_external_ws_active(uid, imei) or now < st.get("ws_backoff_until", 0.0):
                stop_ev.wait(8.0)
                continue

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
                    f"Accept-Language: vi-VN,vi;q=0.95,en-SG;q=0.85\r\n"
                    f"User-Agent: {ua}\r\n"
                    f"Cookie: {ck_str}\r\n\r\n"
                )
                sock.sendall(hs.encode("utf-8"))
                resp_buf = bytearray()
                while not resp_buf.endswith(b"\r\n\r\n"):
                    b1 = sock.recv(1)
                    if not b1:
                        break
                    resp_buf.extend(b1)
                    if len(resp_buf) > 8192:
                        break

                if b"101" in resp_buf.split(b"\r\n")[0]:
                    sock.settimeout(2.0)
                    last_ws_ping = 0.0
                    while not stop_ev.is_set():
                        if cls.is_external_ws_active(uid, imei):
                            break
                        now_loop = time.time()
                        if now_loop - last_ws_ping >= 16.0:
                            hb_pkt = struct.pack("<BHB", 1, 2, 1) + json.dumps({"eventId": int(now_loop * 1000)}).encode("utf-8")
                            cls._send_ws_frame(sock, hb_pkt, opcode=0x2)
                            st["ping_count"] = st.get("ping_count", 0) + 1
                            st["last_ping_ts"] = now_loop
                            last_ws_ping = now_loop

                        if now_loop - last_http_hb >= 22.0:
                            last_http_hb = now_loop
                            cls._http_keepalive_pulse(s, st)
                            if stop_ev.is_set() or not st.get("alive", True):
                                break

                        try:
                            alive_frame = cls._drain_and_handle_ws_frame(sock, st)
                            if not alive_frame:
                                break
                        except socket.timeout:
                            continue
                        except Exception:
                            break
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
            stop_ev.wait(5.0)

    @classmethod
    def restore_all_from_db(cls, db_path=""):
        """Tự động khôi phục và giữ sống toàn bộ Cookie + IMEI Zalo và Token trong database.db."""
        eff_db = db_path or DEFAULT_DB_PATH
        if not os.path.exists(eff_db):
            return 0
        restored = 0
        try:
            conn = sqlite3.connect(eff_db, timeout=10)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            try:
                rows = cur.execute("SELECT * FROM accounts WHERE enabled=1").fetchall()
                for r in rows:
                    r_dict = dict(r)
                    plat = (r_dict.get("platform") or "zalo").lower()
                    if plat == "zalo" and r_dict.get("imei") and r_dict.get("cookies"):
                        c_d = parse_cookies_input_flexible(r_dict["cookies"])
                        if c_d:
                            cls.start_keeper(
                                uid=r_dict.get("uid") or r_dict["imei"],
                                imei=r_dict["imei"],
                                cookies_dict=c_d,
                                user_agent=r_dict.get("user_agent") or "",
                                zpw_enk=r_dict.get("zpw_enk") or "",
                                pc_name=r_dict.get("pc_name") or "Windows 11 Pro (Singapore)",
                                display_name=r_dict.get("name") or "",
                                db_path=eff_db,
                            )
                            restored += 1
                    elif plat == "discord" and r_dict.get("token"):
                        cls.register_token_keep_alive(
                            r_dict["token"], platform="discord",
                            uid=r_dict.get("uid") or "", display_name=r_dict.get("name") or "",
                            db_path=eff_db
                        )
                        restored += 1
            except Exception:
                pass
            try:
                v_rows = cur.execute("SELECT * FROM zalo_cookie_vault").fetchall()
                for vr in v_rows:
                    vd = dict(vr)
                    if vd.get("imei") and vd.get("cookies_json"):
                        c_d = parse_cookies_input_flexible(vd["cookies_json"])
                        if c_d:
                            cls.start_keeper(
                                uid=vd.get("uid") or vd["imei"],
                                imei=vd["imei"],
                                cookies_dict=c_d,
                                user_agent=vd.get("user_agent") or "",
                                zpw_enk=vd.get("zpw_enk") or "",
                                display_name=vd.get("display_name") or "",
                                db_path=eff_db,
                            )
                            restored += 1
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        return restored

    @classmethod
    def ensure_vault_daemon_started(cls, db_path=""):
        with cls._LOCK:
            if cls._DAEMON_STARTED:
                return
            cls._DAEMON_STARTED = True
        th = threading.Thread(target=cls._vault_daemon_loop, args=(db_path or DEFAULT_DB_PATH,), daemon=True)
        th.start()

    @classmethod
    def _vault_daemon_loop(cls, db_path):
        cls.restore_all_from_db(db_path)
        sess = requests.Session()
        adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=1)
        sess.mount("https://", adapter)
        sess.mount("http://", adapter)
        while True:
            try:
                cls.restore_all_from_db(db_path)
                with cls._LOCK:
                    tok_items = list(cls._TOKEN_KEEPERS.values())
                for tk_st in tok_items:
                    if not tk_st.get("alive", True):
                        continue
                    now = time.time()
                    if now - tk_st.get("last_ping_ts", 0.0) >= 45.0:
                        tk_st["last_ping_ts"] = now
                        tk_st["ping_count"] = tk_st.get("ping_count", 0) + 1
                        try:
                            r = sess.get(
                                "https://discord.com/api/v9/users/@me/affinities/users",
                                headers={
                                    "Authorization": tk_st["token"],
                                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                                    "Origin": "https://discord.com",
                                    "Referer": "https://discord.com/channels/@me",
                                },
                                timeout=6,
                            )
                            if r.status_code == 401:
                                tk_st["alive"] = False
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(25.0)


def _execute_qr_login_sync(
    emit_event_fn, qr_callback=None, timeout=110, custom_pc_name=None,
    region_code="sg_vip", vn_region="", proxy_vn=None, vn_proxy=None,
    pre_identity=None, stop_ev=None, **kwargs
):
    """Luồng tạo QR & Đăng nhập máy tính Singapore chính chủ 100%:
    - Tất cả thiết bị máy tính đổi luân phiên đều ở duy nhất 1 địa điểm: Singapore (SG).
    - Dùng `continue_url = "https://chat.zalo.me/"` để sau khi ấn Đăng nhập trên điện thoại,
      hệ thống đi qua `jr.chat.zalo.me/jr/pushsession` lấy `zpw_sek` thật và gọi `getLoginInfo` lấy `zpw_enk` thật + `UID` số thật + danh sách nhóm thật!"""
    eff_reg = vn_region or region_code or "sg_vip"
    eff_proxy = str(proxy_vn or vn_proxy or "").strip()
    vn_id = (
        dict(pre_identity)
        if isinstance(pre_identity, dict) and pre_identity.get("imei")
        else build_vietnam_pc_identity(region_code=eff_reg, vn_region=eff_reg, custom_pc_name=custom_pc_name or "")
    )
    vn_id["country"] = "SG"
    vn_id["vn_location"] = "Singapore"
    vn_id["tz"] = "Asia/Singapore"

    ua = vn_id["ua"]
    sec_ch_ua = vn_id.get("sec_ch_ua") or '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'
    sec_platform = vn_id.get("sec_platform") or ('"macOS"' if "Macintosh" in ua else '"Windows"')
    pc_name = vn_id["pc_name"]
    comp_name = vn_id.get("computer_name") or "Web"
    mac_address = vn_id["mac_address"]
    vn_ip = vn_id["vn_ip"]
    imei = vn_id["imei"]
    vn_net_hdrs = build_vietnam_network_headers(vn_ip, tz="Asia/Singapore", country="SG")

    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=2)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if eff_proxy:
        px_norm = VietnamSingaporeGeoRouter.normalize_proxy_url(eff_proxy)
        if px_norm:
            s.proxies.update({"http": px_norm, "https": px_norm})

    continue_url = "https://chat.zalo.me/"
    login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F"
    v_str = "2.3.10"
    cookie_jar_dict = {"_zlang": "vn"}
    s.cookies.set("_zlang", "vn", domain=".zalo.me")

    nav_headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85,en-US;q=0.8,en;q=0.7",
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
        # Để requests.Session (s.cookies) tự quản lý Cookie trên id.zalo.me giúp mã QR quét hợp lệ 100%
        return {
            "User-Agent": ua,
            "Accept": "*/*",
            "Accept-Language": "vi-VN,vi;q=0.95,en-SG;q=0.85,en-US;q=0.8,en;q=0.7",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": "https://id.zalo.me",
            "Referer": ref_url,
            "Sec-Ch-Ua": sec_ch_ua,
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": sec_platform,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }

    qr_b64_raw = ""
    qr_code_id = ""
    start_ts = time.time()

    for attempt in range(3):
        if stop_ev is not None and stop_ev.is_set():
            return None
        if attempt == 1 and s.proxies and not qr_b64_raw:
            s.proxies.clear()

        try:
            r_page = s.get(login_referer, headers=nav_headers, timeout=8, allow_redirects=True)
            _harvest_cookies(r_page, s, cookie_jar_dict)
            m_ver = re.search(r"https://stc-zlogin\.zdn\.vn/main-([\d\.]+)\.js", r_page.text or "")
            if m_ver:
                v_str = m_ver.group(1).strip()

            r_li = s.post(
                "https://id.zalo.me/account/logininfo",
                data={"continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=6,
            )
            _harvest_cookies(r_li, s, cookie_jar_dict)

            r_vc = s.post(
                "https://id.zalo.me/account/verify-client",
                data={"type": "device", "continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=6,
            )
            _harvest_cookies(r_vc, s, cookie_jar_dict)

            r_qr = s.post(
                "https://id.zalo.me/account/authen/qr/generate",
                data={"continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=8,
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
        time.sleep(0.15)

    if not qr_b64_raw or not qr_code_id:
        return None

    clean_b64 = qr_b64_raw.split(",", 1)[-1].strip()
    pad_r = (4 - len(clean_b64) % 4) % 4
    raw_png = base64.b64decode(clean_b64 + ("=" * pad_r))
    qr_data_uri = "data:image/png;base64," + base64.b64encode(raw_png).decode("utf-8")

    async def _save_to_file_async(filepath):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "wb") as wf:
            wf.write(raw_png)
        return filepath

    qr_gen_event = {
        "type": LoginQRCallbackEventType.QRCodeGenerated,
        "data": {
            "code": qr_code_id,
            "image": qr_data_uri,
            "imei": imei,
            "pc_name": pc_name,
            "computer_name": comp_name,
            "mac_address": mac_address,
            "region_code": vn_id["region_code"],
            "region_label": vn_id["region_label"],
            "vn_location": "Singapore",
            "vn_isp": vn_id["vn_isp"],
            "vn_ip": vn_ip,
            "route_mode": "direct_singapore",
            "real_country_code": "SG",
            "is_vn_or_sg": True,
            "user_agent": ua,
            "sec_ch_ua": sec_ch_ua,
            "sec_platform": sec_platform,
        },
        "actions": {"saveToFile": _save_to_file_async},
    }

    def _async_dispatch_qr_generated():
        if qr_callback:
            try:
                qr_callback(qr_data_uri)
            except Exception:
                pass
        try:
            emit_event_fn(qr_gen_event)
        except Exception:
            pass

    threading.Thread(target=_async_dispatch_qr_generated, daemon=True).start()

    display_name = "Người dùng Zalo"
    avatar = ""
    scanned_ok = False

    # Bước 5: Lắng nghe waiting-scan tức thì (0.001s)
    while time.time() - start_ts < timeout:
        if stop_ev is not None and stop_ev.is_set():
            return None
        try:
            r_scan = s.post(
                "https://id.zalo.me/account/authen/qr/waiting-scan",
                data={"code": qr_code_id, "continue": continue_url, "v": v_str},
                headers=_make_ajax_headers(login_referer),
                timeout=26,
            )
            _harvest_cookies(r_scan, s, cookie_jar_dict)
            j_scan = r_scan.json() if r_scan.content else {}
            if not isinstance(j_scan, dict):
                time.sleep(0.2)
                continue
            err_c = j_scan.get("error_code")
            if err_c == 8:
                continue
            sd = j_scan.get("data")
            if err_c == 0 and isinstance(sd, dict) and (sd.get("display_name") or sd.get("avatar")):
                display_name = str(sd.get("display_name") or "Người dùng").strip()
                avatar = str(sd.get("avatar") or "").strip()
                scanned_ok = True
                sc_ev = {
                    "type": LoginQRCallbackEventType.QRCodeScanned,
                    "data": {
                        "display_name": display_name,
                        "avatar": avatar,
                        "code": qr_code_id,
                        "pc_name": pc_name,
                        "computer_name": comp_name,
                        "mac_address": mac_address,
                    },
                }
                threading.Thread(target=lambda: emit_event_fn(sc_ev), daemon=True).start()
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
            time.sleep(0.2)

    if not scanned_ok:
        emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
        return None

    # Bước 6: Lắng nghe waiting-confirm ngay khi vừa quét xong
    confirmed_ok = False
    j_conf = {}
    while time.time() - start_ts < timeout:
        if stop_ev is not None and stop_ev.is_set():
            return None
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
            _harvest_cookies(r_conf, s, cookie_jar_dict)
            j_conf = r_conf.json() if r_conf.content else {}
            if not isinstance(j_conf, dict):
                time.sleep(0.2)
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
            time.sleep(0.2)

    if not confirmed_ok:
        emit_event_fn({"type": LoginQRCallbackEventType.QRCodeExpired, "data": {}})
        return None

    # Bước 7: Kích hoạt jr.chat.zalo.me/jr/pushsession để nhận chứng chỉ phiên zpw_sek thật trên .chat.zalo.me
    cookie_jar_dict["z_uuid"] = imei
    try:
        s.cookies.set("z_uuid", imei, domain=".chat.zalo.me")
        s.cookies.set("z_uuid", imei, domain=".zalo.me")
    except Exception:
        pass

    def _follow_redirect_hops(start_url, initial_ref):
        cur_u = start_url
        cur_ref = initial_ref
        for _hop in range(12):
            if not cur_u or _is_valid_cookie_val(cookie_jar_dict.get("zpw_sek")):
                break
            p_u = urlparse(cur_u)
            h_hop = dict(nav_headers)
            h_hop["Referer"] = cur_ref
            r_h = None
            for _retry in range(3):
                try:
                    r_h = s.get(cur_u, headers=h_hop, allow_redirects=False, timeout=10)
                    break
                except Exception:
                    time.sleep(0.2)
            if r_h is None:
                break
            _harvest_cookies(r_h, s, cookie_jar_dict)
            if _is_valid_cookie_val(cookie_jar_dict.get("zpw_sek")):
                break
            if r_h.status_code in (301, 302, 303, 307, 308):
                loc = r_h.headers.get("Location") or ""
                if not loc:
                    break
                if loc.startswith("/"):
                    loc = f"{p_u.scheme}://{p_u.netloc}{loc}"
                cur_ref = cur_u
                cur_u = loc
                continue
            body_txt = r_h.text or ""
            m_jr = re.search(r"(https://jr\.chat\.zalo\.me/jr/pushsession[^\s\"\x27<>]+)", body_txt)
            if m_jr:
                cur_ref = cur_u
                cur_u = m_jr.group(1)
                continue
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
        if _is_valid_cookie_val(cookie_jar_dict.get("zpw_sek")):
            break
        _follow_redirect_hops(chk_u, login_referer)

    # Bước 8: Trao đổi Cookie phiên thật lấy khóa mã hóa zpw_enk thật và UID số thật
    user_info_got = exchange_cookies_for_zpw_enk(
        s, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name="Web"
    )
    if not user_info_got.get("zpw_enk") and comp_name and comp_name != "Web":
        user_info_got = exchange_cookies_for_zpw_enk(
            s, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name=comp_name
        )

    uid = str(user_info_got.get("uid") or user_info_got.get("userId") or user_info_got.get("send2me_id") or "")
    zpw_enk = str(user_info_got.get("zpw_enk") or "")
    bound_comp_name = str(user_info_got.get("_bound_computer_name") or "Web")

    if not uid:
        zpsid_val = str(cookie_jar_dict.get("zpsid") or cookie_jar_dict.get("zpw_sek") or "")
        uid_m = re.match(r"^(\d{8,22})", zpsid_val)
        if uid_m:
            uid = uid_m.group(1)

    live_check = check_zalo_cookie_imei_live(
        imei=imei, cookies_input=cookie_jar_dict, zpw_enk=zpw_enk,
        user_agent=ua, uid=uid, computer_name=bound_comp_name, session_obj=s
    )
    in_acc_alive = bool(live_check.get("alive"))
    grp_cnt = int(live_check.get("groups_count") or 0)
    if live_check.get("zpw_enk"):
        zpw_enk = live_check["zpw_enk"]
    if live_check.get("uid"):
        uid = live_check["uid"]

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
        or live_check.get("display_name")
        or display_name
    )
    phone_num = str(user_info_got.get("phoneNumber") or pf.get("phoneNumber") or "N/A")

    ZaloPCSessionKeeper.start_keeper(
        uid=uid or imei, imei=imei, cookies_dict=cookie_jar_dict,
        user_agent=ua, zpw_enk=zpw_enk, ws_urls=ws_list,
        pc_name=pc_name, computer_name=bound_comp_name, mac_address=mac_address, display_name=final_name
    )

    user_info_out = dict(user_info_got)
    user_info_out.setdefault("uid", uid)
    user_info_out.setdefault("displayName", final_name)
    user_info_out.setdefault("phoneNumber", phone_num)
    user_info_out.setdefault("zpw_enk", zpw_enk)
    user_info_out["verified_in_account"] = in_acc_alive
    user_info_out["groups_count"] = grp_cnt
    user_info_out["pc_name"] = pc_name
    user_info_out["computer_name"] = bound_comp_name
    user_info_out["mac_address"] = mac_address
    user_info_out["region_label"] = vn_id["region_label"]
    user_info_out["vn_location"] = "Singapore"
    user_info_out["vn_ip"] = vn_ip

    result_payload = {
        "cookies": cookie_jar_dict,
        "imei": imei,
        "user_agent": ua,
        "sec_ch_ua": sec_ch_ua,
        "sec_platform": sec_platform,
        "zpw_enk": zpw_enk,
        "uid": uid,
        "display_name": final_name,
        "pc_name": pc_name,
        "computer_name": bound_comp_name,
        "mac_address": mac_address,
        "region_code": vn_id["region_code"],
        "region_label": vn_id["region_label"],
        "vn_location": "Singapore",
        "vn_isp": vn_id["vn_isp"],
        "vn_ip": vn_ip,
        "groups_count": grp_cnt,
        "in_account_verified": in_acc_alive,
        "verified_in_account": in_acc_alive,
        "user_info": user_info_out,
    }

    emit_event_fn({
        "type": LoginQRCallbackEventType.GotLoginInfo,
        "data": result_payload,
    })
    return result_payload


async def _login_qr_async_runner(callback=None, qr_callback=None, timeout=110, custom_pc_name=None, region_code="sg_vip", vn_region="", proxy_vn=None, vn_proxy=None, pre_identity=None, stop_ev=None, **kwargs):
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
        _execute_qr_login_sync, _emit_from_thread, qr_callback, timeout, custom_pc_name, region_code, vn_region, proxy_vn, vn_proxy, pre_identity, stop_ev
    )


def login_qr_with_unique_imei(callback=None, qr_callback=None, timeout=110, custom_pc_name=None, region_code="sg_vip", vn_region="", proxy_vn=None, vn_proxy=None, pre_identity=None, stop_ev=None, **kwargs):
    try:
        asyncio.get_running_loop()
        is_in_async_loop = True
    except RuntimeError:
        is_in_async_loop = False

    if is_in_async_loop or (callback is not None and inspect.iscoroutinefunction(callback)):
        return _login_qr_async_runner(
            callback=callback, qr_callback=qr_callback, timeout=timeout,
            custom_pc_name=custom_pc_name, region_code=region_code, vn_region=vn_region,
            proxy_vn=proxy_vn, vn_proxy=vn_proxy, pre_identity=pre_identity, stop_ev=stop_ev
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
        custom_pc_name=custom_pc_name, region_code=region_code, vn_region=vn_region,
        proxy_vn=proxy_vn, vn_proxy=vn_proxy, pre_identity=pre_identity, stop_ev=stop_ev
    )


# Tự động khôi phục & giữ sống toàn bộ Cookie + IMEI Zalo và Token trong kho ngay khi nạp module
try:
    ZaloPCSessionKeeper.ensure_vault_daemon_started(DEFAULT_DB_PATH)
except Exception:
    pass
