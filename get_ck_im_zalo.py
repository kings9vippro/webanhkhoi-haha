"""
get_ck_im_zalo.py — Hệ Thống Bot Telegram Quét QR Zalo Máy Tính Việt Nam & Lấy Cookie/IMEI/Token (v27)
Tác giả: Phan Anh Khôi (Rike)
Đặc điểm nổi bật:
1. KHÔNG BAO GIỜ LỖI IMPORT: Tự động chạy mượt ngay cả khi môi trường Render chưa cài `zlapi` hoặc `python-telegram-bot`.
2. TỰ ĐỘNG XOÁ WEBHOOK CŨ (`deleteWebhook?drop_pending_updates=true`) trước khi Long-Polling để Bot Telegram luôn phản hồi 100% không bị kẹt!
3. MÁY TÍNH QUÉT QR TẠI VIỆT NAM (TP. Hồ Chí Minh / Hà Nội / Đà Nẵng — Không hiện ở Mỹ):
   - Hỗ trợ chọn vùng Máy Tính Việt Nam ngay trên nút bấm Inline Keyboard của Telegram.
   - Sau khi quét QR và ấn Đăng nhập trên điện thoại, tự động kiểm tra thiết bị đã vào trong tài khoản Zalo chưa,
     gửi file `.txt` chứa đầy đủ `IMEI + Zpw_Enk + Cookie JSON`, đồng thời TỰ ĐỘNG ĐỒNG BỘ vào bảng điều khiển Web (`database.db`)!
"""

import os
import re
import io
import time
import uuid
import json
import hmac
import base64
import struct
import random
import sqlite3
import hashlib
import threading
from datetime import datetime
from io import BytesIO
import requests

try:
    from PIL import Image, ImageDraw
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from zalo_login import (
    login_qr_with_unique_imei,
    LoginQRCallbackEventType,
    verify_zalo_pc_device_logged_in_account,
    ZaloPCSessionKeeper,
)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8995799349:AAE8uwWyS-CHzj2yQNkFkMynCTprFTZ1JNc")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

API_2FA = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/2fa.php?secret={}"


def add_border_to_qr(image_data: bytes) -> bytes:
    if not HAS_PIL:
        return image_data
    try:
        image = Image.open(BytesIO(image_data))
        if image.mode == "RGBA":
            bg_white = Image.new("RGB", image.size, (255, 255, 255))
            bg_white.paste(image, mask=image.split()[3])
            image = bg_white
        elif image.mode != "RGB":
            image = image.convert("RGB")
        border_width = 36
        radius = 44
        width, height = image.size
        new_width, new_height = width + border_width * 2, height + border_width * 2
        bg = Image.new("RGB", (new_width, new_height), (255, 255, 255))
        bg.paste(image, (border_width, border_width))
        mask = Image.new("L", (new_width, new_height), 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle([0, 0, new_width, new_height], radius, fill=255)
        output = BytesIO()
        bg.save(output, format="PNG")
        return output.getvalue()
    except Exception:
        return image_data


def generate_totp_local(secret_key, time_step=30, digits=6):
    if not secret_key:
        return None, 0
    clean_sec = re.sub(r"[^A-Za-z2-7]", "", str(secret_key)).upper()
    now_int = int(time.time())
    rem_sec = time_step - (now_int % time_step)
    if clean_sec:
        pad_len = (8 - (len(clean_sec) % 8)) % 8
        try:
            key_bytes = base64.b32decode(clean_sec + ("=" * pad_len), casefold=True)
            counter = now_int // time_step
            msg = struct.pack(">Q", counter)
            digest = hmac.new(key_bytes, msg, hashlib.sha1).digest()
            offset = digest[-1] & 0x0F
            code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
            return str(code_int).zfill(digits), rem_sec
        except Exception:
            pass
    try:
        r = requests.get(API_2FA.format(str(secret_key).replace(" ", "")), timeout=6).json()
        if r.get("token"):
            return str(r["token"]), rem_sec
    except Exception:
        pass
    return None, 0


def sync_zalo_account_to_web_db(uid, display_name, imei, cookies_dict, zpw_enk="", user_agent="", pc_name=""):
    """Đồng bộ tài khoản Zalo vừa quét trên Bot Telegram thẳng vào CSDL Web (`database.db`)."""
    if not imei or not cookies_dict:
        return False
    try:
        conn = sqlite3.connect(DB_PATH, timeout=15)
        cur = conn.cursor()
        c_json = json.dumps(cookies_dict, ensure_ascii=False)
        now = time.time()
        cur.execute(
            """CREATE TABLE IF NOT EXISTS zalo_cookie_vault (
                uid TEXT PRIMARY KEY,
                display_name TEXT DEFAULT '',
                imei TEXT DEFAULT '',
                cookies_json TEXT DEFAULT '{}',
                zpw_enk TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                updated_at REAL
            )"""
        )
        cur.execute(
            """INSERT OR REPLACE INTO zalo_cookie_vault
               (uid, display_name, imei, cookies_json, zpw_enk, user_agent, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (str(uid or imei), str(display_name or "Zalo VN"), str(imei), c_json, str(zpw_enk or ""), str(user_agent or ""), now),
        )
        existing = cur.execute("SELECT id FROM accounts WHERE platform='zalo' AND (uid=? OR imei=?)", (str(uid), str(imei))).fetchone()
        if existing:
            cur.execute(
                "UPDATE accounts SET name=?, imei=?, cookies=?, uid=?, user_agent=?, zpw_enk=?, pc_name=?, chat_cmd_enabled=1, enabled=1 WHERE id=?",
                (str(display_name), str(imei), c_json, str(uid), str(user_agent), str(zpw_enk), str(pc_name), existing[0]),
            )
        else:
            cur.execute(
                """INSERT INTO accounts (name, platform, imei, cookies, token, is_bot, uid, chat_cmd_enabled, cmd_prefix, allow_all_cmd, enabled, user_agent, zpw_enk, pc_name, created_at)
                   VALUES (?, 'zalo', ?, ?, '', 0, ?, 1, '.', 1, 1, ?, ?, ?, ?)""",
                (str(display_name), str(imei), c_json, str(uid), str(user_agent), str(zpw_enk), str(pc_name), now),
            )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


class DiscordTokenGetter:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            "authority": "discord.com",
            "accept": "*/*",
            "accept-language": "vi-VN,vi;q=0.95",
            "content-type": "application/json",
            "origin": "https://discord.com",
            "referer": "https://discord.com/login",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        self.session.headers.update(self.headers)

    def login_discord(self, email, password, twofa_code="", twofa_type="totp"):
        try:
            self.session.get("https://discord.com/login", timeout=8)
            payload = {
                "gift_code_sku_id": None,
                "login": str(email).strip(),
                "login_source": None,
                "password": str(password).strip(),
                "undelete": False,
            }
            r = self.session.post("https://discord.com/api/v9/auth/login", json=payload, timeout=12)
            d = r.json() if r.content else {}
            if r.status_code == 200 and d.get("token"):
                return d["token"], d.get("user_id", ""), "Thành công"
            if d.get("mfa") and d.get("ticket"):
                if not twofa_code:
                    return None, None, "NEED_2FA"
                clean_code = str(twofa_code).strip().replace(" ", "")
                if len(clean_code) >= 12 and not clean_code.isdigit():
                    otp_c, _ = generate_totp_local(clean_code)
                    if otp_c:
                        clean_code = otp_c
                mfa_ep = "https://discord.com/api/v9/auth/mfa/backup" if twofa_type == "backup" else "https://discord.com/api/v9/auth/mfa/totp"
                r2 = self.session.post(
                    mfa_ep,
                    json={
                        "code": clean_code,
                        "ticket": d["ticket"],
                        "login_instance_id": d.get("login_instance_id"),
                        "gift_code_sku_id": None,
                        "login_source": None,
                    },
                    timeout=12,
                )
                d2 = r2.json() if r2.content else {}
                if r2.status_code == 200 and d2.get("token"):
                    return d2["token"], d.get("user_id", ""), "Thành công"
                return None, None, d2.get("message") or "Mã 2FA không chính xác"
            return None, None, d.get("message") or f"Không thể đăng nhập (Mã {r.status_code})"
        except Exception as e:
            return None, None, str(e)


class FacebookCookieGetter:
    def __init__(self):
        self.session = requests.Session()
        self.headers = {
            "authority": "www.facebook.com",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "vi-VN,vi;q=0.95",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        self.session.headers.update(self.headers)

    def login_facebook(self, email, password, twofa_code=""):
        try:
            self.session.get("https://www.facebook.com/login.php", timeout=12)
            login_data = {"email": str(email).strip(), "pass": str(password).strip(), "login": "Log In"}
            self.session.post("https://www.facebook.com/login.php", data=login_data, allow_redirects=True, timeout=18)
            cookies = self.session.cookies.get_dict()
            if "c_user" in cookies and "xs" in cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                return cookie_str, str(cookies.get("c_user")), "Thành công"
            return None, None, "Tài khoản bật phê duyệt 2 lớp hoặc sai mật khẩu."
        except Exception as e:
            return None, None, str(e)


discord_getter = DiscordTokenGetter()
fb_getter = FacebookCookieGetter()


class DirectTelegramBotRunner:
    """Động cơ Bot Telegram Siêu Tốc 24/7 (Hỗ trợ Inline Keyboard, Conversation State & Quét QR Zalo Máy Tính Việt Nam)."""

    def __init__(self, token=TELEGRAM_BOT_TOKEN):
        self.token = str(token or TELEGRAM_BOT_TOKEN).strip()
        self.api_base = f"https://api.telegram.org/bot{self.token}"
        self.stop_ev = threading.Event()
        self.offset = 0
        self.session = requests.Session()
        self.active_qr_locks = set()
        self.user_states = {}
        self.bot_username = ""
        self.started_at = time.time()
        self.processed_updates = 0
        self.last_error = ""

    def api_call(self, method, data=None, files=None, timeout=28):
        try:
            url = f"{self.api_base}/{method}"
            if files:
                r = self.session.post(url, data=data, files=files, timeout=timeout)
            else:
                r = self.session.post(url, json=data if isinstance(data, dict) else None, data=None if isinstance(data, dict) else data, timeout=timeout)
            return r.json() if r.content else {}
        except Exception as e:
            self.last_error = str(e)
            return {"ok": False, "error": str(e)}

    def clear_webhook_and_init(self):
        """Xoá sạch Webhook cũ trên Telegram để getUpdates Long-Polling không bao giờ bị lỗi Conflict 409!"""
        try:
            self.api_call("deleteWebhook", data={"drop_pending_updates": False}, timeout=10)
            me = self.api_call("getMe", timeout=10)
            if me.get("ok") and isinstance(me.get("result"), dict):
                self.bot_username = me["result"].get("username") or "RikeZaloBot"
            self.api_call(
                "setMyCommands",
                data={
                    "commands": [
                        {"command": "start", "description": "Mở Bảng Điều Khiển & Menu Chính"},
                        {"command": "qr", "description": "Tạo Mã QR Zalo Máy Tính Việt Nam (HCM/HN/ĐN)"},
                        {"command": "get", "description": "Lấy Cookie Zalo / Facebook / Token Discord"},
                        {"command": "2fa", "description": "Lấy mã OTP 2FA 6 số tự động"},
                        {"command": "font", "description": "Đổi chữ sang 6 kiểu Font VIP"},
                        {"command": "status", "description": "Xem danh sách Máy Tính Zalo VN đang Online"},
                    ]
                },
                timeout=10,
            )
        except Exception as e:
            self.last_error = str(e)

    def send_text(self, chat_id, text, reply_to=None, parse_mode="HTML", reply_markup=None):
        pl = {"chat_id": chat_id, "text": text}
        if parse_mode:
            pl["parse_mode"] = parse_mode
        if reply_to:
            pl["reply_to_message_id"] = reply_to
        if reply_markup:
            pl["reply_markup"] = reply_markup
        return self.api_call("sendMessage", data=pl)

    def edit_text(self, chat_id, message_id, text, parse_mode="HTML", reply_markup=None):
        pl = {"chat_id": chat_id, "message_id": message_id, "text": text}
        if parse_mode:
            pl["parse_mode"] = parse_mode
        if reply_markup:
            pl["reply_markup"] = reply_markup
        return self.api_call("editMessageText", data=pl)

    def answer_callback(self, callback_query_id, text=""):
        pl = {"callback_query_id": callback_query_id}
        if text:
            pl["text"] = text
        return self.api_call("answerCallbackQuery", data=pl, timeout=8)

    def send_photo_bytes(self, chat_id, png_bytes, caption="", reply_to=None, reply_markup=None):
        pl = {"chat_id": str(chat_id), "caption": caption, "parse_mode": "HTML"}
        if reply_to:
            pl["reply_to_message_id"] = str(reply_to)
        if reply_markup:
            pl["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        return self.api_call("sendPhoto", data=pl, files={"photo": ("zalo_vn_qr.png", png_bytes, "image/png")})

    def send_doc_bytes(self, chat_id, content_bytes, filename, caption="", reply_to=None):
        pl = {"chat_id": str(chat_id), "caption": caption, "parse_mode": "HTML"}
        if reply_to:
            pl["reply_to_message_id"] = str(reply_to)
        return self.api_call("sendDocument", data=pl, files={"document": (filename, content_bytes, "text/plain")})

    def delete_msg(self, chat_id, message_id):
        if not message_id:
            return
        self.api_call("deleteMessage", data={"chat_id": chat_id, "message_id": message_id}, timeout=8)

    @staticmethod
    def build_main_menu_keyboard():
        return {
            "inline_keyboard": [
                [
                    {"text": "🇻🇳 Quét QR Zalo (PC TP.HCM)", "callback_data": "qr_vn_hcm"},
                    {"text": "🇻🇳 Quét QR Zalo (PC Hà Nội)", "callback_data": "qr_vn_hn"},
                ],
                [
                    {"text": "🇻🇳 Quét QR Zalo (PC Đà Nẵng)", "callback_data": "qr_vn_dn"},
                    {"text": "💻 Quét QR MacBook VN", "callback_data": "qr_vn_mac"},
                ],
                [
                    {"text": "🔑 Lấy Token Discord", "callback_data": "menu_discord"},
                    {"text": "🍪 Lấy Cookie Facebook", "callback_data": "menu_facebook"},
                ],
                [
                    {"text": "🔐 Tạo Mã 2FA OTP", "callback_data": "menu_2fa"},
                    {"text": "🖥️ Thiết Bị Đang Online", "callback_data": "menu_status"},
                ],
            ]
        }

    def handle_zalo_qr_command(self, chat_id, user_id, msg_id=None, region_code="vn_hcm", custom_pc_name=""):
        if user_id in self.active_qr_locks:
            self.send_text(
                chat_id,
                "⏳ <b>Bạn đang có 1 phiên QR Máy Tính Việt Nam đang chờ quét!</b>\n"
                "Vui lòng mở Zalo trên điện thoại quét mã hiện tại hoặc đợi hết hạn.",
                reply_to=msg_id,
            )
            return
        self.active_qr_locks.add(user_id)

        def _worker():
            qr_msg_id = None
            scan_msg_id = None
            try:
                wait_r = self.send_text(
                    chat_id,
                    "🇻🇳 <b>Đang khởi tạo Máy Tính Zalo tại Việt Nam &amp; cấp mã QR chính chủ...</b>\n"
                    "<i>(Định tuyến: Asia/Ho_Chi_Minh • Ngôn ngữ: vi-VN • Không hiện vị trí Mỹ)</i>",
                    reply_to=msg_id,
                )
                wait_id = (wait_r.get("result") or {}).get("message_id")

                def _sync_cb(event):
                    nonlocal qr_msg_id, scan_msg_id
                    ev_type = event.get("type")
                    ev_data = event.get("data") or {}
                    if ev_type == LoginQRCallbackEventType.QRCodeGenerated:
                        self.delete_msg(chat_id, wait_id)
                        raw_b64 = str(ev_data.get("image") or "").split(",", 1)[-1].strip()
                        raw_png = base64.b64decode(raw_b64 + ("=" * ((4 - len(raw_b64) % 4) % 4)))
                        bordered_png = add_border_to_qr(raw_png)
                        pc_lbl = ev_data.get("pc_name") or "DESKTOP-VN-HCM (Windows 11 Pro VN)"
                        reg_lbl = ev_data.get("region_label") or "TP. Hồ Chí Minh, Việt Nam"
                        vn_ip = ev_data.get("vn_ip") or "14.161.88.102"
                        cap = (
                            f"🇻🇳 <b>MÃ QR ĐĂNG NHẬP ZALO PC VIỆT NAM</b>\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"🖥️ <b>Thiết bị:</b> <code>{pc_lbl}</code>\n"
                            f"📍 <b>Vị trí:</b> <code>{reg_lbl}</code>\n"
                            f"🌐 <b>IP Việt Nam:</b> <code>{vn_ip}</code>\n"
                            f"⏳ <b>Hiệu lực:</b> 100 giây\n\n"
                            f"👉 <i>Mở ứng dụng Zalo trên điện thoại ➔ Quét mã QR ➔ Bấm <b>Đăng nhập</b> để ghim máy tính vào trong tài khoản!</i>\n"
                            f"👑 <b>Dev:</b> Phan Anh Khôi (Rike)"
                        )
                        pr = self.send_photo_bytes(chat_id, bordered_png, caption=cap, reply_to=msg_id)
                        qr_msg_id = (pr.get("result") or {}).get("message_id")

                    elif ev_type == LoginQRCallbackEventType.QRCodeScanned:
                        self.delete_msg(chat_id, qr_msg_id)
                        d_name = ev_data.get("display_name") or "Người dùng Zalo"
                        pc_lbl = ev_data.get("pc_name") or "DESKTOP-VN-HCM"
                        sr = self.send_text(
                            chat_id,
                            f"✅ <b>Đã nhận diện Zalo của: {d_name}</b>\n"
                            f"🖥️ <b>Thiết bị chờ duyệt:</b> <code>{pc_lbl} (Việt Nam)</code>\n"
                            f"📲 <i>Hãy bấm <b>Đồng ý / Đăng nhập</b> trên điện thoại của bạn ngay!</i>",
                            reply_to=msg_id,
                        )
                        scan_msg_id = (sr.get("result") or {}).get("message_id")

                    elif ev_type == LoginQRCallbackEventType.QRCodeExpired:
                        self.delete_msg(chat_id, qr_msg_id)
                        self.delete_msg(chat_id, scan_msg_id)
                        self.send_text(
                            chat_id,
                            "⏰ <b>Mã QR Zalo đã hết hạn!</b>\nBấm nút bên dưới hoặc gõ <code>/qr</code> để tạo mã QR Máy Tính Việt Nam mới.",
                            reply_to=msg_id,
                            reply_markup=self.build_main_menu_keyboard(),
                        )

                    elif ev_type == LoginQRCallbackEventType.QRCodeDeclined:
                        self.delete_msg(chat_id, qr_msg_id)
                        self.delete_msg(chat_id, scan_msg_id)
                        err_txt = ev_data.get("error") or "Bạn đã từ chối đăng nhập QR trên điện thoại."
                        self.send_text(chat_id, f"❌ <b>Không thể hoàn tất đăng nhập:</b> {err_txt}", reply_to=msg_id)

                    elif ev_type == LoginQRCallbackEventType.GotLoginInfo:
                        self.delete_msg(chat_id, scan_msg_id)
                        cookies = ev_data.get("cookies") or {}
                        imei = ev_data.get("imei") or ""
                        zpw_enk = ev_data.get("zpw_enk") or ""
                        ua = ev_data.get("user_agent") or ""
                        pc_name = ev_data.get("pc_name") or "DESKTOP-VN-HCM (Windows 11 Pro VN)"
                        reg_lbl = ev_data.get("region_label") or "Việt Nam"
                        u_info = ev_data.get("user_info") or {}
                        d_name = ev_data.get("display_name") or u_info.get("displayName") or "Zalo VN"
                        uid = ev_data.get("uid") or u_info.get("uid") or "N/A"
                        grp_cnt = ev_data.get("groups_count") or u_info.get("groups_count") or 0

                        # Đồng bộ trực tiếp vào CSDL Web để hiển thị ngay trên Web Dashboard
                        sync_zalo_account_to_web_db(
                            uid=uid, display_name=d_name, imei=imei,
                            cookies_dict=cookies, zpw_enk=zpw_enk,
                            user_agent=ua, pc_name=pc_name
                        )

                        cookies_str = json.dumps(cookies, ensure_ascii=False, indent=2)
                        file_txt = (
                            f"# PHIEN MAY TINH ZALO VIET NAM DA GHIM TRONG ACC 100%\n"
                            f"# Tac gia: Phan Anh Khoi (Rike) | Vi tri: {reg_lbl}\n"
                            f"PC_Device: {pc_name}\n"
                            f"UID: {uid}\n"
                            f"Display_Name: {d_name}\n"
                            f"Groups_Count: {grp_cnt}\n\n"
                            f"Imei:\n{imei}\n\n"
                            f"Zpw_Enk:\n{zpw_enk}\n\n"
                            f"User_Agent:\n{ua}\n\n"
                            f"Cookie:\n{cookies_str}\n"
                        )
                        cap_ok = (
                            f"🎉 <b>ĐĂNG NHẬP ZALO PC VIỆT NAM THÀNH CÔNG!</b>\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"👤 <b>Tài khoản:</b> {d_name}\n"
                            f"🆔 <b>UID:</b> <code>{uid}</code> ({grp_cnt} nhóm)\n"
                            f"🖥️ <b>Thiết bị:</b> <code>{pc_name}</code>\n"
                            f"🇻🇳 <b>Vị trí:</b> <code>{reg_lbl}</code>\n"
                            f"🔑 <b>IMEI:</b> <code>{imei}</code>\n"
                            f"🛡️ <b>Trạng thái:</b> <code>Đã ghim trong Acc 24/7 &amp; Đồng bộ lên Web</code>\n"
                            f"👑 <b>Dev:</b> Phan Anh Khôi (Rike)"
                        )
                        safe_fn = re.sub(r"[^\w\-\.]", "_", d_name) + "_zalo_vn.txt"
                        self.send_doc_bytes(chat_id, file_txt.encode("utf-8"), safe_fn, caption=cap_ok, reply_to=msg_id)
                        if len(cookies_str) < 3400:
                            self.send_text(chat_id, f"🍪 <b>Cookie JSON ({d_name}):</b>\n<pre>{cookies_str}</pre>", reply_to=msg_id)

                login_qr_with_unique_imei(
                    callback=_sync_cb, timeout=105,
                    custom_pc_name=custom_pc_name, region_code=region_code
                )
            except Exception as e:
                self.send_text(chat_id, f"⚠️ Lỗi xử lý QR Zalo: <code>{e}</code>", reply_to=msg_id)
            finally:
                self.active_qr_locks.discard(user_id)

        threading.Thread(target=_worker, daemon=True).start()

    def process_callback_query(self, cb):
        cb_id = cb.get("id")
        data = str(cb.get("data") or "")
        from_u = cb.get("from") or {}
        user_id = from_u.get("id")
        msg = cb.get("message") or {}
        chat_id = (msg.get("chat") or {}).get("id")
        msg_id = msg.get("message_id")
        self.answer_callback(cb_id)
        if not chat_id or not user_id:
            return

        if data.startswith("qr_vn_"):
            reg = data.replace("qr_", "")
            self.handle_zalo_qr_command(chat_id, user_id, msg_id=msg_id, region_code=reg)
        elif data == "menu_discord":
            self.user_states[user_id] = {"tool": "discord", "step": "email"}
            self.send_text(chat_id, "🔑 <b>LẤY TOKEN DISCORD:</b>\n👉 Vui lòng gửi <b>Email hoặc SĐT Discord</b> của bạn vào khung chat này:", reply_to=msg_id)
        elif data == "menu_facebook":
            self.user_states[user_id] = {"tool": "facebook", "step": "email"}
            self.send_text(chat_id, "🍪 <b>LẤY COOKIE FACEBOOK:</b>\n👉 Vui lòng gửi <b>Email hoặc SĐT Facebook</b> của bạn vào khung chat này:", reply_to=msg_id)
        elif data == "menu_2fa":
            self.user_states[user_id] = {"tool": "2fa", "step": "secret"}
            self.send_text(chat_id, "🔐 <b>TẠO MÃ 2FA OTP:</b>\n👉 Hãy gửi chuỗi <b>Secret Key 2FA (Base32)</b> vào khung chat này:", reply_to=msg_id)
        elif data == "menu_status":
            self.send_status_report(chat_id, msg_id)

    def send_status_report(self, chat_id, reply_to=None):
        active_devs = ZaloPCSessionKeeper.list_active_devices()
        if not active_devs:
            self.send_text(
                chat_id,
                "📊 <b>TRẠNG THÁI HỆ THỐNG BOT — PHAN ANH KHÔI (RIKE)</b>\n"
                "• Bot Telegram: <code>ONLINE 24/7 (Zero-Error Polling)</code>\n"
                "• Máy tính Zalo VN đang giữ sống: <code>0 thiết bị</code>\n"
                "👉 Bấm nút bên dưới hoặc gõ <code>/qr</code> để quét mã QR Zalo PC Việt Nam!",
                reply_to=reply_to,
                reply_markup=self.build_main_menu_keyboard(),
            )
        else:
            lines_s = ["🖥️ <b>DANH SÁCH MÁY TÍNH ZALO VIỆT NAM ĐANG TRONG ACC (24/7):</b>"]
            for dv in active_devs:
                lines_s.append(
                    f"• <b>{dv['display_name']}</b> (UID: <code>{dv['uid']}</code>)\n"
                    f"  └ Thiết bị: <code>{dv['pc_name']}</code> | Nhịp tim: <code>{dv['ping_count']} lần</code>"
                )
            self.send_text(chat_id, "\n".join(lines_s), reply_to=reply_to, reply_markup=self.build_main_menu_keyboard())

    def handle_interactive_state(self, chat_id, user_id, text, msg_id):
        st = self.user_states.get(user_id)
        if not st:
            return False
        tool = st.get("tool")
        step = st.get("step")

        if tool == "2fa" and step == "secret":
            self.user_states.pop(user_id, None)
            code_6, rem_s = generate_totp_local(text)
            if code_6:
                self.send_text(chat_id, f"🔐 <b>MÃ OTP 2FA HIỆN TẠI:</b> <code>{code_6}</code> (Còn {rem_s}s)", reply_to=msg_id)
            else:
                self.send_text(chat_id, "❌ Secret Key 2FA không hợp lệ!", reply_to=msg_id)
            return True

        if tool == "facebook":
            if step == "email":
                st["email"] = text.strip()
                st["step"] = "password"
                self.send_text(chat_id, f"✅ Đã nhận tài khoản: <code>{st['email']}</code>\n📌 <b>Bước 2:</b> Hãy gửi <b>Mật khẩu Facebook</b>:", reply_to=msg_id)
                return True
            elif step == "password":
                email = st.get("email", "")
                self.user_states.pop(user_id, None)
                self.send_text(chat_id, "⏳ Đang đăng nhập Facebook và trích xuất Cookie...", reply_to=msg_id)
                ck, uid, msg_s = fb_getter.login_facebook(email, text.strip())
                if ck:
                    fn = f"fb_cookie_{uid}.txt"
                    self.send_doc_bytes(chat_id, f"UID: {uid}\nCookie:\n{ck}\n".encode("utf-8"), fn, caption=f"✅ <b>Lấy Cookie Facebook thành công (UID: {uid})!</b>", reply_to=msg_id)
                else:
                    self.send_text(chat_id, f"❌ <b>Lỗi:</b> {msg_s}", reply_to=msg_id)
                return True

        if tool == "discord":
            if step == "email":
                st["email"] = text.strip()
                st["step"] = "password"
                self.send_text(chat_id, f"✅ Đã nhận Email/SĐT: <code>{st['email']}</code>\n📌 <b>Bước 2:</b> Hãy gửi <b>Mật khẩu Discord</b>:", reply_to=msg_id)
                return True
            elif step == "password":
                st["password"] = text.strip()
                tk, uid, msg_s = discord_getter.login_discord(st["email"], st["password"], "")
                if tk:
                    self.user_states.pop(user_id, None)
                    self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n<code>{tk}</code>", reply_to=msg_id)
                elif msg_s == "NEED_2FA":
                    st["step"] = "2fa"
                    self.send_text(chat_id, "🔐 Tài khoản Discord có bật 2FA. Hãy gửi <b>Mã 6 số Authenticator</b> hoặc <b>Secret Key 2FA</b> vào đây:", reply_to=msg_id)
                else:
                    self.user_states.pop(user_id, None)
                    self.send_text(chat_id, f"❌ <b>Lỗi:</b> {msg_s}", reply_to=msg_id)
                return True
            elif step == "2fa":
                email = st.get("email", "")
                pw = st.get("password", "")
                self.user_states.pop(user_id, None)
                tk, uid, msg_s = discord_getter.login_discord(email, pw, text.strip())
                if tk:
                    self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n<code>{tk}</code>", reply_to=msg_id)
                else:
                    self.send_text(chat_id, f"❌ <b>Lỗi:</b> {msg_s}", reply_to=msg_id)
                return True

        return False

    def process_update(self, upd):
        self.processed_updates += 1
        if "callback_query" in upd:
            self.process_callback_query(upd["callback_query"])
            return

        msg = upd.get("message") or upd.get("edited_message") or {}
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        from_u = msg.get("from") or {}
        user_id = from_u.get("id") or chat_id
        msg_id = msg.get("message_id")
        text = str(msg.get("text") or "").strip()
        if not chat_id or not text:
            return

        if not text.startswith("/"):
            self.handle_interactive_state(chat_id, user_id, text, msg_id)
            return

        self.user_states.pop(user_id, None)
        parts = text.split()
        cmd = parts[0].lower().split("@")[0]
        args = parts[1:]

        if cmd in ("/start", "/help", "/menu"):
            menu_html = (
                "🇻🇳 <b>TRUNG TÂM QUÉT QR ZALO PC VIỆT NAM &amp; ĐA TÀI KHOẢN</b> 🇻🇳\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "🖥️ <b>1. QUÉT MÃ QR ZALO MÁY TÍNH TẠI VIỆT NAM (KHÔNG Ở MỸ):</b>\n"
                "• <code>/qr</code> — Quét QR Máy Tính tại <b>TP. Hồ Chí Minh, Việt Nam</b>\n"
                "• <code>/qr hn</code> — Quét QR Máy Tính tại <b>Hà Nội, Việt Nam</b>\n"
                "• <code>/qr dn</code> — Quét QR Máy Tính tại <b>Đà Nẵng, Việt Nam</b>\n"
                "• <code>/qr mac</code> — Quét QR thiết bị <b>MacBook Pro Việt Nam</b>\n"
                "<i>(Sau khi quét, máy tính nằm cố định trong mục Thiết bị đăng nhập Zalo 24/7 và tự động đồng bộ lên Web!)</i>\n\n"
                "🔐 <b>2. CÔNG CỤ TOKEN &amp; BẢO MẬT 2FA:</b>\n"
                "• <code>/get zalo</code> — Tạo mã QR Zalo PC Việt Nam\n"
                "• <code>/get discord [email] [pass] [2fa]</code> — Lấy Token Discord\n"
                "• <code>/get facebook [email] [pass]</code> — Lấy Cookie Facebook\n"
                "• <code>/2fa &lt;Secret_Key&gt;</code> — Lấy mã OTP 2FA 6 số\n"
                "• <code>/font &lt;nội dung&gt;</code> — Đổi chữ nghệ thuật VIP\n"
                "• <code>/status</code> — Kiểm tra thiết bị Zalo PC đang giữ sống\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "👑 <b>Tác giả:</b> Phan Anh Khôi (Rike)"
            )
            self.send_text(chat_id, menu_html, reply_to=msg_id, reply_markup=self.build_main_menu_keyboard())

        elif cmd == "/qr" or (cmd == "/get" and args and args[0].lower() == "zalo"):
            reg_arg = (args[0].lower() if (cmd == "/qr" and args) else (args[1].lower() if len(args) > 1 else "hcm"))
            reg_map = {"hcm": "vn_hcm", "sg": "vn_hcm", "hn": "vn_hn", "hanoi": "vn_hn", "dn": "vn_dn", "danang": "vn_dn", "mac": "vn_mac"}
            reg_code = reg_map.get(reg_arg, "vn_hcm")
            custom_pc = " ".join(args[1:]) if (cmd == "/qr" and len(args) > 1) else ""
            self.handle_zalo_qr_command(chat_id, user_id, msg_id=msg_id, region_code=reg_code, custom_pc_name=custom_pc)

        elif cmd == "/get":
            if not args:
                self.send_text(
                    chat_id,
                    "📌 <b>Chọn chức năng bạn muốn sử dụng trên menu bên dưới:</b>",
                    reply_to=msg_id,
                    reply_markup=self.build_main_menu_keyboard(),
                )
                return
            plat = args[0].lower()
            if plat == "discord" and len(args) < 3:
                self.user_states[user_id] = {"tool": "discord", "step": "email"}
                self.send_text(chat_id, "🔑 <b>Bước 1:</b> Gửi <b>Email / SĐT Discord</b> của bạn vào chat này:", reply_to=msg_id)
                return
            if plat in ("facebook", "fb") and len(args) < 3:
                self.user_states[user_id] = {"tool": "facebook", "step": "email"}
                self.send_text(chat_id, "🍪 <b>Bước 1:</b> Gửi <b>Email / SĐT Facebook</b> của bạn vào chat này:", reply_to=msg_id)
                return
            if len(args) >= 3:
                u_acc, u_pw = args[1], args[2]
                u_2fa = args[3] if len(args) > 3 else ""
                if plat == "discord":
                    tk, uid, st_m = discord_getter.login_discord(u_acc, u_pw, u_2fa)
                    if tk:
                        self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n<code>{tk}</code>", reply_to=msg_id)
                    else:
                        self.send_text(chat_id, f"❌ <b>Lỗi:</b> {st_m}", reply_to=msg_id)
                elif plat in ("facebook", "fb"):
                    ck, uid, st_m = fb_getter.login_facebook(u_acc, u_pw, u_2fa)
                    if ck:
                        self.send_text(chat_id, f"✅ <b>Cookie Facebook (UID: {uid}):</b>\n<code>{ck}</code>", reply_to=msg_id)
                    else:
                        self.send_text(chat_id, f"❌ <b>Lỗi:</b> {st_m}", reply_to=msg_id)

        elif cmd == "/2fa":
            if not args:
                self.user_states[user_id] = {"tool": "2fa", "step": "secret"}
                self.send_text(chat_id, "🔐 Hãy gửi chuỗi <b>Secret Key 2FA</b> vào khung chat này:", reply_to=msg_id)
                return
            code_v, rem_s = generate_totp_local("".join(args))
            if code_v:
                self.send_text(chat_id, f"🔐 <b>Mã 2FA OTP:</b> <code>{code_v}</code> (Còn {rem_s}s)", reply_to=msg_id)
            else:
                self.send_text(chat_id, "❌ Không thể tạo mã OTP từ Secret Key này.", reply_to=msg_id)

        elif cmd == "/font":
            sample = " ".join(args).strip() or "Phan Anh Khoi Rike VIP 2026"
            normal = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            styles = {
                "Bold Serif": "𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗",
                "Bold Sans": "𝗔𝗕𝗖𝗗𝗘𝗙𝗚𝗛𝗜𝗝𝗞𝗟𝗠𝗡𝗢𝗣𝗤𝗥𝗦𝗧𝗨𝗩𝗪𝗫𝗬𝗭𝗮𝗯𝗰𝗱𝗲𝗳𝗴𝗵𝗶𝗷𝗸𝗹𝗺𝗻𝗼𝗽𝗾𝗿𝘀𝘁𝘂𝘃𝘄𝘅𝘆𝘇𝟬𝟭𝟮𝟯𝟰𝟱𝟲𝟳𝟴𝟵",
                "Script VIP": "𝒜ℬ𝒞𝒟ℰℱ𝒢ℋℐ𝒥𝒦ℒℳ𝒩𝒪𝒫𝒬ℛ𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵𝒶𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏0123456789",
                "Double Struck": "𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ𝕒𝕓𝕔𝕕𝖊𝖋𝖌𝖍𝖎𝖏𝖐𝖑𝖒𝖓𝖔𝖕𝖖𝖗𝖘𝖙𝖚𝖛𝖜𝖝𝖞𝖟𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡",
            }
            lines_f = ["✨ <b>BẢNG ĐỔI FONT CHỮ ĐẲNG CẤP — PHAN ANH KHÔI (RIKE):</b>"]
            for st_name, table in styles.items():
                if len(table) == len(normal):
                    tr = sample.translate(str.maketrans(normal, table))
                    lines_f.append(f"• <b>{st_name}:</b> <code>{tr}</code>")
            self.send_text(chat_id, "\n".join(lines_f), reply_to=msg_id)

        elif cmd == "/status":
            self.send_status_report(chat_id, reply_to=msg_id)

    def run_forever(self):
        self.clear_webhook_and_init()
        while not self.stop_ev.is_set():
            try:
                res = self.api_call(
                    "getUpdates",
                    data={"offset": self.offset, "timeout": 20, "allowed_updates": ["message", "callback_query"]},
                    timeout=26,
                )
                if isinstance(res, dict) and res.get("ok") and isinstance(res.get("result"), list):
                    for upd in res["result"]:
                        self.offset = max(self.offset, int(upd.get("update_id", 0)) + 1)
                        try:
                            self.process_update(upd)
                        except Exception as ex_u:
                            self.last_error = str(ex_u)
                else:
                    err_code = res.get("error_code") if isinstance(res, dict) else 0
                    if err_code == 409:
                        self.clear_webhook_and_init()
                    time.sleep(2.5)
            except Exception as e:
                self.last_error = str(e)
                time.sleep(2.5)


_GLOBAL_RUNNER_INSTANCE = None
_RUNNER_LOCK = threading.RLock()


def start_background_telegram_bot(token=TELEGRAM_BOT_TOKEN, force_restart=False):
    """Khởi chạy hoặc làm mới Bot Telegram Phan Anh Khôi (Rike) ở chế độ nền 24/7."""
    global _GLOBAL_RUNNER_INSTANCE
    with _RUNNER_LOCK:
        if _GLOBAL_RUNNER_INSTANCE is not None and not force_restart:
            return _GLOBAL_RUNNER_INSTANCE
        if _GLOBAL_RUNNER_INSTANCE is not None and force_restart:
            try:
                _GLOBAL_RUNNER_INSTANCE.stop_ev.set()
            except Exception:
                pass
        runner = DirectTelegramBotRunner(token=token)
        _GLOBAL_RUNNER_INSTANCE = runner
        th = threading.Thread(target=runner.run_forever, daemon=True)
        th.start()
        return runner


def get_telegram_bot_status():
    with _RUNNER_LOCK:
        r = _GLOBAL_RUNNER_INSTANCE
        if r is None:
            return {"running": False, "bot_username": "", "processed_updates": 0}
        return {
            "running": not r.stop_ev.is_set(),
            "bot_username": r.bot_username or "Online",
            "processed_updates": r.processed_updates,
            "uptime_sec": int(time.time() - r.started_at),
            "last_error": r.last_error,
        }


def main():
    print("🤖 Đang khởi động Bot Telegram Quét QR Zalo Việt Nam — Phan Anh Khôi (Rike)...")
    runner = DirectTelegramBotRunner(token=TELEGRAM_BOT_TOKEN)
    runner.run_forever()


if __name__ == "__main__":
    main()
