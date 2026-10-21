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
import hashlib
import secrets
import inspect
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    "apple": ["A4:83:E7", "F0:18:98", "3C:22:FB", "BC:D0:74", "14:7D:DA", "AC:BC:32", "60:03:08", "78:7B:8A"],
    "intel": ["00:1B:21", "3C:97:0E", "8C:8D:28", "A0:36:9F", "DC:4A:3E", "48:51:B7", "B4:96:91"],
    "asus":  ["04:D4:C4", "2C:FD:A1", "F0:2F:74", "AC:9E:17", "50:EB:F6", "08:62:66"],
    "msi":   ["00:D8:61", "30:9C:23", "D8:BB:C1", "40:B0:76", "2C:F0:5D"],
    "dell":  ["18:03:73", "F8:BC:12", "B8:CA:3A", "D4:BE:D9", "54:BF:64"],
    "lenovo":["60:57:18", "98:FA:9B", "E8:6A:64", "50:7B:9D", "C8:5B:76"],
    "hp":    ["3C:D9:2B", "94:57:A5", "FC:15:B4", "10:1F:74", "A0:D3:C1"],
}


def generate_vietnam_mac_address(vendor="apple", seed_salt=""):
    v_key = str(vendor or "apple").lower()
    oui_list = VIETNAM_OUI_PREFIXES.get(v_key) or VIETNAM_OUI_PREFIXES["apple"]
    if seed_salt:
        h = hashlib.sha256(str(seed_salt).encode("utf-8")).digest()
        oui = oui_list[h[0] % len(oui_list)]
        return f"{oui}:{h[1]:02X}:{h[2]:02X}:{h[3]:02X}"
    oui = random.choice(oui_list)
    return f"{oui}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"


class VietnamSingaporeGeoRouter:
    """Bộ Định Tuyến & Xác Thực Địa Lý Thực Tế Việt Nam (VN) & Singapore (SG):
    - Kiểm tra địa chỉ IP xuất mạng thật của phiên kết nối (qua ip-api.com, ipwho.is, ipinfo.io).
    - Tuyệt đối không ghi nhãn giả: nếu máy chủ gốc đang ở Mỹ/Châu Âu (như Render US), tự động quét & bắc cầu qua
      Proxy Việt Nam (VN) hoặc Singapore (SG) sống thật để khi quét QR trên điện thoại Zalo hiển thị đúng Việt Nam / Singapore."""

    _LOCK = threading.RLock()
    _DIRECT_GEO_CACHE = {"ts": 0.0, "info": None}
    _VERIFIED_PROXIES = {"VN": [], "SG": [], "ANY": []}
    _LAST_HARVEST_TS = 0.0
    _USER_CUSTOM_PROXY = ""

    LIVE_PROXY_SOURCES_VN_SG = [
        ("VN", "http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=3000&country=VN&ssl=yes&anonymity=all"),
        ("SG", "http", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=3000&country=SG&ssl=yes&anonymity=all"),
        ("VN", "socks5", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=3000&country=VN"),
        ("SG", "socks5", "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=3000&country=SG"),
        ("VN", "http", "https://www.proxy-list.download/api/v1/get?type=https&country=VN"),
        ("SG", "http", "https://www.proxy-list.download/api/v1/get?type=https&country=SG"),
        ("VN", "http", "https://www.proxy-list.download/api/v1/get?type=http&country=VN"),
        ("SG", "http", "https://www.proxy-list.download/api/v1/get?type=http&country=SG"),
        ("VN", "socks5", "https://www.proxy-list.download/api/v1/get?type=socks5&country=VN"),
        ("SG", "socks5", "https://www.proxy-list.download/api/v1/get?type=socks5&country=SG"),
        ("SG", "json_geonode", "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&country=SG"),
        ("VN", "json_geonode", "https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&country=VN"),
    ]

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
    def inspect_outbound_ip_geo(cls, proxy_url="", timeout=3.2):
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
                    cc = str(d.get("countryCode") or "").upper()
                    return {
                        "ok": True,
                        "ip": str(d.get("query") or ""),
                        "country_code": cc,
                        "country": str(d.get("country") or cc),
                        "city": str(d.get("city") or d.get("regionName") or ""),
                        "isp": str(d.get("isp") or ""),
                        "is_vn_or_sg": cc in ("VN", "SG"),
                        "proxy_url": proxy_url or "",
                    }
        except Exception:
            pass

        try:
            r2 = sess.get("https://ipwho.is/", timeout=timeout)
            if r2.status_code == 200:
                d2 = r2.json()
                if d2.get("success") is not False and d2.get("country_code"):
                    cc = str(d2.get("country_code") or "").upper()
                    conn_info = d2.get("connection") if isinstance(d2.get("connection"), dict) else {}
                    return {
                        "ok": True,
                        "ip": str(d2.get("ip") or ""),
                        "country_code": cc,
                        "country": str(d2.get("country") or cc),
                        "city": str(d2.get("city") or d2.get("region") or ""),
                        "isp": str(conn_info.get("isp") or conn_info.get("org") or ""),
                        "is_vn_or_sg": cc in ("VN", "SG"),
                        "proxy_url": proxy_url or "",
                    }
        except Exception:
            pass

        try:
            r3 = sess.get("https://ipinfo.io/json", timeout=timeout)
            if r3.status_code == 200:
                d3 = r3.json()
                cc = str(d3.get("country") or "").upper()
                if cc:
                    return {
                        "ok": True,
                        "ip": str(d3.get("ip") or ""),
                        "country_code": cc,
                        "country": "Vietnam" if cc == "VN" else ("Singapore" if cc == "SG" else cc),
                        "city": str(d3.get("city") or d3.get("region") or ""),
                        "isp": str(d3.get("org") or ""),
                        "is_vn_or_sg": cc in ("VN", "SG"),
                        "proxy_url": proxy_url or "",
                    }
        except Exception:
            pass

        return {
            "ok": False,
            "ip": "",
            "country_code": "",
            "country": "",
            "city": "",
            "isp": "",
            "is_vn_or_sg": False,
            "proxy_url": proxy_url or "",
        }

    @classmethod
    def get_direct_server_geo(cls, force=False):
        now = time.time()
        with cls._LOCK:
            if not force and cls._DIRECT_GEO_CACHE["info"] and (now - cls._DIRECT_GEO_CACHE["ts"] < 300.0):
                return dict(cls._DIRECT_GEO_CACHE["info"])
        info = cls.inspect_outbound_ip_geo(proxy_url="", timeout=2.8)
        with cls._LOCK:
            if info.get("ok"):
                cls._DIRECT_GEO_CACHE = {"ts": now, "info": info}
        return info

    @classmethod
    def verify_proxy_for_zalo_qr(cls, proxy_url, timeout=2.8):
        px_norm = cls.normalize_proxy_url(proxy_url)
        if not px_norm:
            return None
        geo = cls.inspect_outbound_ip_geo(proxy_url=px_norm, timeout=timeout)
        if not geo.get("ok") or geo.get("country_code") not in ("VN", "SG"):
            return None
        try:
            s = requests.Session()
            s.proxies.update({"http": px_norm, "https": px_norm})
            r = s.get(
                "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F",
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                    "Accept-Language": "vi-VN,vi;q=0.95",
                },
                timeout=timeout,
            )
            if r.status_code == 200:
                geo["proxy_url"] = px_norm
                geo["zalo_reachable"] = True
                return geo
        except Exception:
            pass
        return None

    @classmethod
    def harvest_live_vn_sg_proxies(cls, preferred_country="VN", max_wait_sec=4.2):
        now = time.time()
        pref = "SG" if "SG" in str(preferred_country or "").upper() else "VN"
        with cls._LOCK:
            if cls._VERIFIED_PROXIES.get(pref) and (now - cls._LAST_HARVEST_TS < 180.0):
                return list(cls._VERIFIED_PROXIES[pref])

        candidates = []
        seen = set()

        def _fetch_source(src_tuple):
            cc_tag, proto, url = src_tuple
            found_local = []
            try:
                r = requests.get(url, timeout=2.2)
                if r.status_code == 200 and r.text:
                    if proto == "json_geonode":
                        data_list = (r.json() or {}).get("data") or []
                        for item in data_list:
                            ip_s = item.get("ip")
                            port_s = item.get("port")
                            protocols = item.get("protocols") or ["http"]
                            pr = protocols[0] if protocols else "http"
                            if ip_s and port_s:
                                found_local.append((cc_tag, f"{pr}://{ip_s}:{port_s}"))
                    else:
                        for ln in r.text.splitlines():
                            ln_s = ln.strip()
                            if ":" in ln_s and not ln_s.startswith("<"):
                                px_u = cls.normalize_proxy_url(ln_s, default_scheme=proto)
                                if px_u:
                                    found_local.append((cc_tag, px_u))
            except Exception:
                pass
            return found_local

        ordered_sources = sorted(
            cls.LIVE_PROXY_SOURCES_VN_SG,
            key=lambda x: 0 if x[0] == pref else 1
        )
        with ThreadPoolExecutor(max_workers=8) as src_pool:
            for res_list in src_pool.map(_fetch_source, ordered_sources):
                for cc_tag, px_u in res_list:
                    if px_u not in seen:
                        seen.add(px_u)
                        candidates.append((cc_tag, px_u))

        if not candidates:
            return []

        verified_vn = []
        verified_sg = []
        t0 = time.time()
        test_batch = [px_u for _, px_u in candidates[:36]]

        with ThreadPoolExecutor(max_workers=18) as ver_pool:
            fut_map = {ver_pool.submit(cls.verify_proxy_for_zalo_qr, px, 2.3): px for px in test_batch}
            for fut in as_completed(fut_map):
                if time.time() - t0 > max_wait_sec and (verified_vn or verified_sg):
                    break
                try:
                    info = fut.result(timeout=0.1)
                    if info and info.get("zalo_reachable"):
                        if info["country_code"] == "VN":
                            verified_vn.append(info)
                        elif info["country_code"] == "SG":
                            verified_sg.append(info)
                        if (pref == "VN" and len(verified_vn) >= 2) or (pref == "SG" and len(verified_sg) >= 2):
                            break
                except Exception:
                    pass

        with cls._LOCK:
            cls._LAST_HARVEST_TS = time.time()
            if verified_vn:
                cls._VERIFIED_PROXIES["VN"] = verified_vn
            if verified_sg:
                cls._VERIFIED_PROXIES["SG"] = verified_sg
            cls._VERIFIED_PROXIES["ANY"] = verified_vn + verified_sg

        return verified_sg if (pref == "SG" and verified_sg) else (verified_vn or verified_sg)

    @classmethod
    def select_best_route_for_qr(cls, target_country="VN", custom_proxy=""):
        """Chọn đường truyền thực tế tốt nhất cho phiên QR Zalo:
        1. Nếu người dùng nhập Proxy riêng (`custom_proxy`), kiểm tra và dùng ngay.
        2. Nếu máy chủ hiện tại đang có IP thật ở Việt Nam (`VN`) hoặc Singapore (`SG`), dùng kết nối trực tiếp (0ms).
        3. Nếu máy chủ đang đặt ở nước khác (VD: Mỹ), tự động lấy Proxy VN/SG từ hồ Proxy đã xác thực để đảm bảo vị trí quét tại VN/SG."""
        pref = "SG" if "SG" in str(target_country or "").upper() else "VN"

        for px_cand in (custom_proxy, cls._USER_CUSTOM_PROXY):
            if px_cand and str(px_cand).strip():
                px_norm = cls.normalize_proxy_url(px_cand)
                if px_norm:
                    info = cls.inspect_outbound_ip_geo(proxy_url=px_norm, timeout=3.0)
                    if info.get("ok"):
                        info["route_mode"] = "custom_proxy"
                        return info
                    return {
                        "ok": True,
                        "ip": "",
                        "country_code": pref,
                        "country": "Singapore" if pref == "SG" else "Việt Nam",
                        "city": "Singapore" if pref == "SG" else "TP. Hồ Chí Minh",
                        "isp": "Custom Proxy Route",
                        "is_vn_or_sg": True,
                        "proxy_url": px_norm,
                        "route_mode": "custom_proxy",
                    }

        direct_geo = cls.get_direct_server_geo()
        if direct_geo.get("ok") and direct_geo.get("country_code") in ("VN", "SG"):
            direct_geo["route_mode"] = "direct_native_vn_sg"
            direct_geo["proxy_url"] = ""
            return direct_geo

        harvested = cls.harvest_live_vn_sg_proxies(preferred_country=pref, max_wait_sec=3.8)
        if harvested:
            chosen = harvested[0]
            chosen["route_mode"] = "auto_vn_sg_proxy"
            return chosen

        if direct_geo.get("ok"):
            direct_geo["route_mode"] = "direct_non_vn_sg"
            direct_geo["proxy_url"] = ""
            return direct_geo

        return {
            "ok": False,
            "ip": "",
            "country_code": pref,
            "country": "Singapore" if pref == "SG" else "Việt Nam",
            "city": "Singapore" if pref == "SG" else "TP. Hồ Chí Minh",
            "isp": "Singtel Fiber" if pref == "SG" else "Viettel / VNPT Fiber",
            "is_vn_or_sg": True,
            "proxy_url": "",
            "route_mode": "fallback_headers",
        }


VIETNAM_PC_PRESETS = {
    "vn_mac": {
        "region_code": "vn_mac",
        "region": "MAC_VN",
        "region_label": "MacBook Pro 16 M3 Max — TP.HCM, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "VNPT / Viettel Fiber VN",
        "pc_prefix": "MacBook-Pro-M3-VN",
        "computer_name": "MacBook Pro M3 Max",
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
        "computer_name": "MacBook Air M3",
        "os_label": "macOS Sequoia 15.1 VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["27.72", "14.162", "113.190"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "vn_imac": {
        "region_code": "vn_imac",
        "region": "IMAC_VN",
        "region_label": "iMac 24 M3 4.5K — TP.HCM, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "FPT Telecom VN",
        "pc_prefix": "iMac-M3-Studio-VN",
        "computer_name": "iMac 24 M3 Studio",
        "os_label": "macOS Sonoma VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["14.169", "115.78", "42.116"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0",
        "sec_ch_ua": "",
        "sec_platform": "",
    },
    "vn_mac_studio": {
        "region_code": "vn_mac_studio",
        "region": "MAC_STUDIO_VN",
        "region_label": "Mac Studio M2 Ultra — Đà Nẵng, Việt Nam",
        "vn_location": "TP. Đà Nẵng, Việt Nam",
        "vn_isp": "VNPT FiberVN",
        "pc_prefix": "Mac-Studio-Ultra-VN",
        "computer_name": "Mac Studio M2 Ultra",
        "os_label": "macOS Sonoma VN",
        "vendor": "apple",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["113.176", "14.177", "27.71"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "vn_hcm": {
        "region_code": "vn_hcm",
        "region": "HCM",
        "region_label": "ASUS ROG Zephyrus G16 — TP. Hồ Chí Minh, Việt Nam",
        "vn_location": "TP. Hồ Chí Minh, Việt Nam",
        "vn_isp": "Viettel / VNPT Fiber",
        "pc_prefix": "ROG-ZEPHYRUS-HCM",
        "computer_name": "ASUS ROG Zephyrus G16",
        "os_label": "Windows 11 Pro 64-bit VN",
        "vendor": "asus",
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
        "computer_name": "ASUS ROG Strix SCAR 18",
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
        "computer_name": "MSI Titan 18 HX",
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
        "computer_name": "Dell XPS 16 9640",
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
        "computer_name": "ThinkPad X1 Carbon G12",
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
        "computer_name": "HP Spectre x360 16",
        "os_label": "Windows 11 Pro VN",
        "vendor": "hp",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["113.173", "14.181", "27.68"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "vn_aorus_pc": {
        "region_code": "vn_aorus_pc",
        "region": "AORUS_VN",
        "region_label": "AORUS Master RTX 4090 — Hải Phòng, Việt Nam",
        "vn_location": "TP. Hải Phòng, Việt Nam",
        "vn_isp": "FPT / Viettel Fiber",
        "pc_prefix": "AORUS-RTX4090-VN",
        "computer_name": "AORUS Master RTX 4090",
        "os_label": "Windows 11 Pro 64-bit VN",
        "vendor": "intel",
        "tz": "Asia/Ho_Chi_Minh",
        "country": "VN",
        "ip_prefixes": ["14.163", "27.73", "113.160"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_vip": {
        "region_code": "sg_vip",
        "region": "SG",
        "region_label": "Firefox - Windows 11 Pro (Singapore)",
        "vn_location": "Singapore (Marina Bay)",
        "vn_isp": "Singtel Fiber SG",
        "pc_prefix": "FIREFOX-WIN11-SG",
        "computer_name": "Firefox - Windows",
        "os_label": "Firefox 132 - Windows 11",
        "vendor": "intel",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["116.88", "119.74", "42.60", "175.156"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
        "sec_ch_ua": "",
        "sec_platform": "",
    },
    "sg_mac_pro": {
        "region_code": "sg_mac_pro",
        "region": "SG_MAC",
        "region_label": "MacBook Pro 16 M3 Max (Singapore)",
        "vn_location": "Singapore (Orchard)",
        "vn_isp": "StarHub Fiber SG",
        "pc_prefix": "MACBOOK-PRO-SG",
        "computer_name": "MacBook Pro M3 SG",
        "os_label": "macOS Sonoma 14.6 SG",
        "vendor": "apple",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["103.252", "116.87", "119.74"],
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"macOS"',
    },
    "sg_dell_precision": {
        "region_code": "sg_dell_precision",
        "region": "SG_DELL",
        "region_label": "Dell Precision 5680 Workstation (Singapore)",
        "vn_location": "Singapore (Changi Business Park)",
        "vn_isp": "M1 Fiber SG",
        "pc_prefix": "DELL-PRECISION-SG",
        "computer_name": "Dell Precision 5680",
        "os_label": "Windows 11 Pro SG",
        "vendor": "dell",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["119.56", "116.88", "175.156"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "sec_ch_ua": '"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_thinkpad_z16": {
        "region_code": "sg_thinkpad_z16",
        "region": "SG_THINKPAD",
        "region_label": "ThinkPad Z16 Gen 2 (Singapore)",
        "vn_location": "Singapore (Jurong East)",
        "vn_isp": "Singtel Enterprise SG",
        "pc_prefix": "THINKPAD-Z16-SG",
        "computer_name": "ThinkPad Z16 Gen 2",
        "os_label": "Windows 11 Pro SG",
        "vendor": "lenovo",
        "tz": "Asia/Singapore",
        "country": "SG",
        "ip_prefixes": ["42.60", "116.88", "103.252"],
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec_platform": '"Windows"',
    },
    "sg_asus_proart": {
        "region_code": "sg_asus_proart",
        "region": "SG_ASUS",
        "region_label": "ASUS ProArt Studiobook 16 OLED (Singapore)",
        "vn_location": "Singapore (Raffles Place)",
        "vn_isp": "ViewQwest Fiber SG",
        "pc_prefix": "ASUS-PROART-SG",
        "computer_name": "ASUS ProArt 16 OLED",
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

COUNTRY_PC_ROTATION_FLEETS = {
    "VN": [
        "vn_mac",
        "vn_hcm",
        "vn_dell_xps",
        "vn_mac_air",
        "vn_hn",
        "vn_thinkpad",
        "vn_dn",
        "vn_imac",
        "vn_hp_spectre",
        "vn_mac_studio",
        "vn_aorus_pc",
    ],
    "SG": [
        "sg_vip",
        "sg_mac_pro",
        "sg_dell_precision",
        "sg_thinkpad_z16",
        "sg_asus_proart",
    ],
    "MAC": [
        "vn_mac",
        "vn_mac_air",
        "vn_imac",
        "vn_mac_studio",
        "sg_mac_pro",
    ],
    "HCM": [
        "vn_hcm",
        "vn_mac",
        "vn_dell_xps",
        "vn_imac",
        "vn_aorus_pc",
    ],
    "HN": [
        "vn_hn",
        "vn_thinkpad",
        "vn_mac_air",
        "vn_aorus_pc",
    ],
    "DN": [
        "vn_dn",
        "vn_mac_studio",
        "vn_hp_spectre",
        "vn_dell_xps",
    ],
}

REGION_ALIAS_MAP = {
    "vn": "VN",
    "vietnam": "VN",
    "auto_vn": "VN",
    "hcm": "HCM",
    "vn_hcm": "HCM",
    "hn": "HN",
    "hanoi": "HN",
    "vn_hn": "HN",
    "dn": "DN",
    "danang": "DN",
    "vn_dn": "DN",
    "mac": "MAC",
    "macos": "MAC",
    "vn_mac": "MAC",
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
    "aorus": "vn_aorus_pc",
    "vn_aorus_pc": "vn_aorus_pc",
    "sg": "SG",
    "singapore": "SG",
    "sg_vip": "SG",
    "sg_firefox": "SG",
    "sg_mac": "sg_mac_pro",
    "sg_dell": "sg_dell_precision",
    "sg_thinkpad": "sg_thinkpad_z16",
    "sg_asus": "sg_asus_proart",
}

_PC_ROTATION_LOCK = threading.RLock()
_PC_ROTATION_COUNTERS = {k: random.randint(0, 10) for k in COUNTRY_PC_ROTATION_FLEETS}


def generate_unique_zalo_pc_imei(user_agent="", salt=""):
    u = str(uuid.uuid4())
    ua_s = f"{user_agent}_{salt}_{time.time_ns()}_{secrets.token_hex(6)}"
    tail = hashlib.md5(ua_s.encode("utf-8")).hexdigest()
    return f"{u}-{tail}"


def build_vietnam_pc_identity(region_code="vn_mac", vn_region="", custom_pc_name="", seed_salt=""):
    raw_reg = str(vn_region or region_code or "vn").strip().lower()
    mapped = REGION_ALIAS_MAP.get(raw_reg, "VN")

    with _PC_ROTATION_LOCK:
        if mapped in COUNTRY_PC_ROTATION_FLEETS:
            fleet = COUNTRY_PC_ROTATION_FLEETS[mapped]
            idx = _PC_ROTATION_COUNTERS.get(mapped, 0)
            _PC_ROTATION_COUNTERS[mapped] = idx + 1
            chosen_key = fleet[idx % len(fleet)]
        elif mapped in VIETNAM_PC_PRESETS:
            country_bucket = "SG" if mapped.startswith("sg_") else "VN"
            fleet = COUNTRY_PC_ROTATION_FLEETS[country_bucket]
            idx = _PC_ROTATION_COUNTERS.get(mapped, 0)
            _PC_ROTATION_COUNTERS[mapped] = idx + 1
            if idx == 0:
                chosen_key = mapped
            else:
                other_keys = [k for k in fleet if k != mapped] or [mapped]
                chosen_key = mapped if (idx % 2 == 0) else other_keys[(idx // 2) % len(other_keys)]
        else:
            fleet = COUNTRY_PC_ROTATION_FLEETS["VN"]
            idx = _PC_ROTATION_COUNTERS.get("VN", 0)
            _PC_ROTATION_COUNTERS["VN"] = idx + 1
            chosen_key = fleet[idx % len(fleet)]

    preset = VIETNAM_PC_PRESETS.get(chosen_key) or VIETNAM_PC_PRESETS["vn_mac"]
    rnd_tag = secrets.token_hex(2).upper()

    if custom_pc_name and str(custom_pc_name).strip():
        clean_custom = re.sub(r"[^\w\-\s\(\)\.]", "", str(custom_pc_name).strip())[:42]
        pc_name = clean_custom
        comp_name = clean_custom[:36]
    else:
        pc_name = f"{preset['pc_prefix']}-{rnd_tag} ({preset['os_label']})"
        base_comp = preset.get("computer_name") or preset["pc_prefix"]
        comp_name = f"{base_comp} #{rnd_tag}"[:36]

    ip_pfx = random.choice(preset["ip_prefixes"])
    vn_client_ip = f"{ip_pfx}.{random.randint(12, 245)}.{random.randint(10, 250)}"
    mac_addr = generate_vietnam_mac_address(
        preset.get("vendor", "apple"),
        seed_salt=f"{pc_name}_{vn_client_ip}_{seed_salt}_{time.time_ns()}"
    )
    imei = generate_unique_zalo_pc_imei(
        preset["ua"],
        salt=f"{pc_name}_{mac_addr}_{vn_client_ip}_{seed_salt}"
    )
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
        "sec_ch_ua": preset.get("sec_ch_ua", ""),
        "sec_platform": preset.get("sec_platform", ""),
        "imei": imei,
    }


def build_vietnam_network_headers(vn_ip, tz="Asia/Ho_Chi_Minh", country="VN"):
    ip_s = str(vn_ip or "14.161.92.108").strip()
    cc_s = "SG" if str(country or "").upper() == "SG" else "VN"
    lang = "vi-VN,vi;q=0.95,en-SG;q=0.85,en-US;q=0.8,en;q=0.7" if cc_s == "SG" else "vi-VN,vi;q=0.96,en-US;q=0.8,en;q=0.7"
    return {
        "Accept-Language": lang,
        "X-Forwarded-For": ip_s,
        "X-Real-IP": ip_s,
        "CF-Connecting-IP": ip_s,
        "True-Client-IP": ip_s,
        "X-Client-IP": ip_s,
        "CF-IPCountry": cc_s,
        "Forwarded": f"for={ip_s};proto=https",
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


class ZaloPCSessionKeeper:
    _ACTIVE_KEEPERS = {}
    _EXTERNAL_WS_HOLDERS = {}
    _LOCK = threading.RLock()

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

    @classmethod
    def is_external_ws_active(cls, uid, imei):
        now = time.time()
        with cls._LOCK:
            t1 = cls._EXTERNAL_WS_HOLDERS.get(str(uid or ""), 0.0)
            t2 = cls._EXTERNAL_WS_HOLDERS.get(str(imei or ""), 0.0)
            return (now - max(t1, t2)) < 45.0

    @classmethod
    def register_and_keep_alive(cls, uid, imei, cookies_dict, zpw_enk="", user_agent="", pc_name="MacBook Pro", computer_name="", mac_address="", ws_urls=None, display_name=""):
        return cls.start_keeper(
            uid=uid, imei=imei, cookies_dict=cookies_dict,
            user_agent=user_agent, zpw_enk=zpw_enk, ws_urls=ws_urls,
            pc_name=pc_name, computer_name=computer_name or "Web", mac_address=mac_address, display_name=display_name
        )

    @classmethod
    def start_keeper(cls, uid, imei, cookies_dict, user_agent, zpw_enk="", ws_urls=None, pc_name="MacBook Pro", computer_name="", mac_address="", display_name=""):
        key = str(uid or imei).strip()
        if not key:
            return
        comp_bound = str(computer_name or "Web").strip()[:48]
        with cls._LOCK:
            existing = cls._ACTIVE_KEEPERS.get(key)
            if existing and not existing["stop_ev"].is_set() and existing.get("imei") == str(imei):
                existing["cookies"].update(dict(cookies_dict or {}))
                if zpw_enk:
                    existing["zpw_enk"] = str(zpw_enk)
                if display_name:
                    existing["display_name"] = str(display_name)
                if pc_name:
                    existing["pc_name"] = str(pc_name)
                return
            if existing and existing.get("stop_ev"):
                existing["stop_ev"].set()

            stop_ev = threading.Event()
            st = {
                "uid": str(uid or ""),
                "display_name": str(display_name or f"Zalo_{str(uid)[-4:]}"),
                "pc_name": str(pc_name or "MacBook Pro"),
                "computer_name": comp_bound,
                "mac_address": str(mac_address or generate_vietnam_mac_address("apple", imei)),
                "imei": str(imei),
                "cookies": dict(cookies_dict or {}),
                "ua": user_agent or "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "zpw_enk": str(zpw_enk or ""),
                "ws_urls": list(ws_urls or ["wss://ws1.chat.zalo.me", "wss://ws2.chat.zalo.me", "wss://ws3.chat.zalo.me", "wss://ws4.chat.zalo.me"]),
                "stop_ev": stop_ev,
                "started_at": time.time(),
                "last_ping_ts": time.time(),
                "ping_count": 1,
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
                        "pc_name": v.get("pc_name") or "MacBook Pro",
                        "computer_name": v.get("computer_name") or "Web",
                        "mac_address": v.get("mac_address") or "",
                        "imei": v.get("imei") or "",
                        "ping_count": v.get("ping_count", 0),
                        "uptime_sec": int(time.time() - v.get("started_at", time.time())),
                    })
            return out

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
    def _drain_and_handle_ws_frame(cls, sock):
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
        return True

    @classmethod
    def _http_keepalive_pulse(cls, s, st):
        imei = st["imei"]
        comp_name = st.get("computer_name") or "Web"
        cookies = st["cookies"]
        zpw_enk = st.get("zpw_enk") or ""
        try:
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
                timeout=6,
            )
            for c in r_hb.cookies:
                if c.name and c.value:
                    cookies[c.name] = c.value
            if zpw_enk:
                key_b = base64.b64decode(zpw_enk)
                pt = json.dumps({"threadIdLocalMsgId": "{}", "imei": imei}, separators=(",", ":")).encode("utf-8")
                pad = 16 - (len(pt) % 16)
                enc_p = base64.b64encode(AES.new(key_b, AES.MODE_CBC, bytes(16)).encrypt(pt + bytes([pad]) * pad)).decode("utf-8")
                r_pre = s.get(
                    "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs",
                    params={"zpw_ver": "645", "zpw_type": "30", "params": enc_p},
                    timeout=6,
                )
                for c in r_pre.cookies:
                    if c.name and c.value:
                        cookies[c.name] = c.value
            st["ping_count"] = st.get("ping_count", 0) + 1
            st["last_ping_ts"] = time.time()
        except Exception:
            pass

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
            "Accept-Language": "vi-VN,vi;q=0.95,en-US;q=0.8",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
        })
        ws_idx = 0
        last_http_hb = time.time()

        while not stop_ev.is_set():
            now = time.time()
            if now - last_http_hb >= 65.0:
                last_http_hb = now
                cls._http_keepalive_pulse(s, st)

            if cls.is_external_ws_active(uid, imei):
                stop_ev.wait(10.0)
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
                    f"Accept-Language: vi-VN,vi;q=0.95\r\n"
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
                        if now_loop - last_ws_ping >= 18.0:
                            hb_pkt = struct.pack("<BHB", 1, 2, 1) + json.dumps({"eventId": int(now_loop * 1000)}).encode("utf-8")
                            cls._send_ws_frame(sock, hb_pkt, opcode=0x2)
                            st["ping_count"] = st.get("ping_count", 0) + 1
                            st["last_ping_ts"] = now_loop
                            last_ws_ping = now_loop

                        if now_loop - last_http_hb >= 65.0:
                            last_http_hb = now_loop
                            cls._http_keepalive_pulse(s, st)

                        try:
                            alive_frame = cls._drain_and_handle_ws_frame(sock)
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
            stop_ev.wait(4.0)


def verify_zalo_pc_device_logged_in_account(imei, cookies_dict, zpw_enk="", user_agent="", uid="", session_obj=None):
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
            req_fn = session_obj.get if session_obj is not None else requests.get
            r = req_fn(
                "https://tt-group-wpa.chat.zalo.me/api/group/getlg/v4",
                params={"zpw_ver": 645, "zpw_type": 30},
                headers=hdrs,
                timeout=8,
            )
            if session_obj is not None:
                _harvest_cookies(r, session_obj, cookies_dict)
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
                    return True, len(gmap), "Thiết bị máy tính đang hoạt động ổn định trong tài khoản!"
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
    """Kích hoạt phiên máy tính trên wpa.chat.zalo.me và đánh thức luồng hội thoại để ghim thiết bị sống 24/7 trong Acc."""
    cookie_jar_dict["z_uuid"] = imei
    cookie_jar_dict.setdefault("_zlang", "vn")

    def _build_wpa_hdrs():
        ck_s = "; ".join(f"{k}={v}" for k, v in cookie_jar_dict.items() if k and v is not None)
        h = {
            "User-Agent": ua,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://chat.zalo.me",
            "Referer": "https://chat.zalo.me/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Cookie": ck_s,
            **vn_net_hdrs,
        }
        if sec_ch_ua:
            h["Sec-Ch-Ua"] = sec_ch_ua
            h["Sec-Ch-Ua-Mobile"] = "?0"
        if sec_platform:
            h["Sec-Ch-Ua-Platform"] = sec_platform
        return h

    comp_clean = str(computer_name or "Web").strip()[:36] or "Web"
    comp_candidates = ["Web"]
    if comp_clean != "Web":
        comp_candidates.insert(0, comp_clean)

    user_info_got = {}
    used_comp_name = "Web"
    endpoints = [
        "https://wpa.chat.zalo.me/api/login/getLoginInfo",
        "https://tt-wpa.chat.zalo.me/api/login/getLoginInfo",
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
                headers=_build_wpa_hdrs(),
                timeout=8,
            )
            _harvest_cookies(r_srv, session_obj, cookie_jar_dict)
        except Exception:
            pass

        for ep in endpoints:
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
                headers=_build_wpa_hdrs(),
                timeout=6,
            )
            _harvest_cookies(r_pre, session_obj, cookie_jar_dict)
        except Exception:
            pass
    return user_info_got


def _execute_qr_login_sync(
    emit_event_fn, qr_callback=None, timeout=110, custom_pc_name=None,
    region_code="vn_mac", vn_region="", proxy_vn=None, vn_proxy=None,
    pre_identity=None, stop_ev=None, **kwargs
):
    eff_reg = vn_region or region_code or "vn_mac"
    eff_proxy = str(proxy_vn or vn_proxy or "").strip()
    vn_id = (
        dict(pre_identity)
        if isinstance(pre_identity, dict) and pre_identity.get("imei")
        else build_vietnam_pc_identity(region_code=eff_reg, vn_region=eff_reg, custom_pc_name=custom_pc_name or "")
    )
    target_country = vn_id.get("country") or ("SG" if "SG" in str(eff_reg).upper() else "VN")

    route_info = VietnamSingaporeGeoRouter.select_best_route_for_qr(
        target_country=target_country, custom_proxy=eff_proxy
    )
    active_proxy_url = route_info.get("proxy_url") or ""
    if route_info.get("ip") and route_info.get("is_vn_or_sg"):
        vn_id["vn_ip"] = route_info["ip"]
        if route_info.get("isp"):
            vn_id["vn_isp"] = route_info["isp"]
        if route_info.get("country_code") == "SG":
            vn_id["vn_location"] = f"{route_info.get('city') or 'Singapore'}, Singapore (IP Thật)"
        elif route_info.get("country_code") == "VN":
            vn_id["vn_location"] = f"{route_info.get('city') or 'TP.HCM'}, Việt Nam (IP Thật)"

    ua = vn_id["ua"]
    sec_ch_ua = vn_id.get("sec_ch_ua") or ""
    sec_platform = vn_id.get("sec_platform") or ""
    pc_name = vn_id["pc_name"]
    comp_name = vn_id.get("computer_name") or "Web"
    mac_address = vn_id["mac_address"]
    vn_ip = vn_id["vn_ip"]
    imei = vn_id["imei"]
    vn_net_hdrs = build_vietnam_network_headers(
        vn_ip, tz=vn_id.get("tz", "Asia/Ho_Chi_Minh"), country=vn_id.get("country", target_country)
    )

    def _create_qr_http_session(px_url=""):
        sess = requests.Session()
        adapter = HTTPAdapter(pool_connections=16, pool_maxsize=32, max_retries=2)
        sess.mount("https://", adapter)
        sess.mount("http://", adapter)
        if px_url:
            sess.proxies.update({"http": px_url, "https": px_url})
        return sess

    s = _create_qr_http_session(active_proxy_url)

    continue_url = "https://chat.zalo.me/"
    login_referer = "https://id.zalo.me/account?continue=https%3A%2F%2Fchat.zalo.me%2F"
    v_str = "2.3.10"
    cookie_jar_dict = {"_zlang": "vn"}

    def _build_nav_headers():
        h = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            **vn_net_hdrs,
        }
        if sec_ch_ua:
            h["Sec-Ch-Ua"] = sec_ch_ua
            h["Sec-Ch-Ua-Mobile"] = "?0"
        if sec_platform:
            h["Sec-Ch-Ua-Platform"] = sec_platform
        return h

    def _make_ajax_headers(ref_url):
        h = {
            "User-Agent": ua,
            "Accept": "*/*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://id.zalo.me",
            "Referer": ref_url,
            "X-Requested-With": "XMLHttpRequest",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            **vn_net_hdrs,
        }
        if sec_ch_ua:
            h["Sec-Ch-Ua"] = sec_ch_ua
            h["Sec-Ch-Ua-Mobile"] = "?0"
        if sec_platform:
            h["Sec-Ch-Ua-Platform"] = sec_platform
        return h

    nav_headers = _build_nav_headers()
    qr_b64_raw = ""
    qr_code_id = ""
    start_ts = time.time()

    for attempt in range(3):
        if stop_ev is not None and stop_ev.is_set():
            return None
        if attempt == 1 and active_proxy_url and not qr_b64_raw:
            active_proxy_url = ""
            s = _create_qr_http_session("")

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
            "region_code": vn_id["region_code"],
            "region_label": vn_id["region_label"],
            "vn_location": vn_id["vn_location"],
            "vn_isp": vn_id["vn_isp"],
            "vn_ip": vn_ip,
            "route_mode": route_info.get("route_mode", "direct"),
            "real_country_code": route_info.get("country_code", target_country),
            "is_vn_or_sg": bool(route_info.get("is_vn_or_sg", True)),
            "user_agent": ua,
            "sec_ch_ua": sec_ch_ua,
            "sec_platform": sec_platform,
        },
        "actions": {"saveToFile": _save_to_file_async},
    })

    display_name = "Người dùng Zalo"
    avatar = ""
    scanned_ok = False

    while time.time() - start_ts < timeout:
        if stop_ev is not None and stop_ev.is_set():
            return None
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
                        "computer_name": comp_name,
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
    s.cookies.set("z_uuid", imei, domain=".chat.zalo.me")

    def _follow_redirect_clean(start_url, initial_ref):
        if not start_url:
            return
        h_hop = dict(nav_headers)
        h_hop["Referer"] = initial_ref
        try:
            r_h = s.get(start_url, headers=h_hop, allow_redirects=True, timeout=12)
            _harvest_cookies(r_h, s, cookie_jar_dict)
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

    user_info_got = exchange_cookies_for_zpw_enk(
        s, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name=comp_name
    )

    uid = str(user_info_got.get("uid") or user_info_got.get("userId") or user_info_got.get("send2me_id") or "")
    zpw_enk = str(user_info_got.get("zpw_enk") or "")
    bound_comp_name = str(user_info_got.get("_bound_computer_name") or comp_name or "Web")

    if not zpw_enk:
        time.sleep(0.35)
        _follow_redirect_clean("https://id.zalo.me/account/check?type=0&continue=https%3A%2F%2Fchat.zalo.me%2F", login_referer)
        user_info_got = exchange_cookies_for_zpw_enk(
            s, imei, cookie_jar_dict, ua, sec_ch_ua, sec_platform, vn_net_hdrs, computer_name="Web"
        )
        uid = str(user_info_got.get("uid") or user_info_got.get("userId") or user_info_got.get("send2me_id") or uid or "")
        zpw_enk = str(user_info_got.get("zpw_enk") or zpw_enk or "")
        bound_comp_name = str(user_info_got.get("_bound_computer_name") or "Web")

    verified_in_acc, grp_cnt, verify_msg = verify_zalo_pc_device_logged_in_account(
        imei=imei, cookies_dict=cookie_jar_dict, zpw_enk=zpw_enk, user_agent=ua, uid=uid, session_obj=s
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
        "vn_location": vn_id["vn_location"],
        "vn_isp": vn_id["vn_isp"],
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


async def _login_qr_async_runner(callback=None, qr_callback=None, timeout=110, custom_pc_name=None, region_code="vn_mac", vn_region="", proxy_vn=None, vn_proxy=None, pre_identity=None, stop_ev=None, **kwargs):
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


def login_qr_with_unique_imei(callback=None, qr_callback=None, timeout=110, custom_pc_name=None, region_code="vn_mac", vn_region="", proxy_vn=None, vn_proxy=None, pre_identity=None, stop_ev=None, **kwargs):
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
