import requests
import urllib.parse
import re
import io
import random
import os
import json
import threading
import asyncio
import time
import uuid
from datetime import datetime
from io import BytesIO
from PIL import Image, ImageDraw

# Thư viện Telegram
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler

# Các lib Zalo
from zlapi import ZaloAPI
from zlapi.models import Message
from zalo_login import login_qr_with_unique_imei, LoginQRCallbackEventType, verify_zalo_pc_device_logged_in_account, ZaloPCSessionKeeper

# ==================== CẤU HÌNH ====================
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "8995799349:AAE8uwWyS-CHzj2yQNkFkMynCTprFTZ1JNc")

# Các API
API_ALL_IN_ONE   = "https://keyherlyswar.x10.mx/Apidocs/download/downallinone.php?url={}"
API_CAPCUT       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfocapcut.php?url={}"
API_TELE_USR     = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfotele.php?username={}"
API_TELE_BOT     = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfochanneltele.php?username={}"
API_GITHUB       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfogithub.php?username={}"
API_INSTAGRAM    = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfoinsta.php?username={}"
API_ROBLOX       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinforoblox.php?username={}"
API_TIKTOK       = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfotiktok.php?username={}"
API_YOUTUBE      = "https://keyherlyswar.x10.mx/Apidocs/get_info/getinfoyt.php?username={}"
API_TIKTOK_VIDEO = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/infovideott.php?url={}"
API_FB_GETID     = "https://scanfb.id.vn/getID.php?linkFB={}"
API_FB_INFO      = "https://scanfb.id.vn/getInfo.php?id={}"
API_FB_AVT       = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/avtfb.php?uid={}"
API_TAROT        = "https://subhatde.id.vn/tarot"
API_2FA          = "https://keyherlyswar.x10.mx/Apidocs/tien_ich/2fa.php?secret={}"
DISCORD_BOT_TOKEN_INFO = "MTM0MzgyNjMxOTI2MzQwMDAyOQ.GtA65z.r5kJEYnX6DocF7SJ5OALDDhZ2u4EjEVHhsO8zc"

# ==================== CLASS ====================
class DiscordTokenGetter:
    def __init__(self):
        self.session = None
        self.create_new_session()
    def create_new_session(self):
        self.session = requests.Session()
        self.headers = {
            "authority": "discord.com", "accept": "*/*", "accept-language": "vi-VN,vi;q=0.9",
            "content-type": "application/json", "origin": "https://discord.com", "referer": "https://discord.com/login",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        self.session.headers.update(self.headers)
    def login_discord(self, email, password, twofa_code, twofa_type="totp"):
        try:
            self.create_new_session()
            self.session.get("https://discord.com/", timeout=10)
            payload = {"gift_code_sku_id": None, "login": email, "login_source": None, "password": password, "undelete": False}
            response = self.session.post("https://discord.com/api/v9/auth/login", headers=self.headers, data=json.dumps(payload), timeout=10)
            response.raise_for_status()
            data = response.json()
            uid = data.get("user_id")
            token = data.get("token")
            if data.get("mfa") and data.get("ticket") and data.get("login_instance_id"):
                if not twofa_code: return None, None, "Yêu cầu 2FA"
                payload2 = {"code": twofa_code, "gift_code_sku_id": None, "login_instance_id": data.get("login_instance_id"), "ticket": data.get("ticket")}
                mfa_endpoint = "https://discord.com/api/v9/auth/mfa/backup" if twofa_type == "backup" else "https://discord.com/api/v9/auth/mfa/totp"
                response2 = self.session.post(mfa_endpoint, headers=self.headers, data=json.dumps(payload2), timeout=10)
                response2.raise_for_status()
                token = response2.json().get("token")
            if token and uid: return token, uid, "Thành công"
            else: return None, None, "Sai email/mật khẩu"
        except Exception as e: return None, None, str(e)
        finally: self.create_new_session()

class FacebookCookieGetter:
    def __init__(self):
        self.session = None
        self.create_new_session()
    def create_new_session(self):
        self.session = requests.Session()
        self.headers = {'authority': 'www.facebook.com', 'accept': 'text/html', 'user-agent': 'Mozilla/5.0'}
        self.session.headers.update(self.headers)
    def extract_value(self, html, field_name):
        match = re.search(f'name="{field_name}" value="([^"]*)"', html)
        return match.group(1) if match else ""
    def login_facebook(self, email, password):
        try:
            self.create_new_session()
            self.session.get('https://www.facebook.com/login.php', headers=self.headers, timeout=30)
            login_data = {'email': email, 'pass': password, 'login': 'Log In'}
            response = self.session.post('https://www.facebook.com/login.php', data=login_data, headers=self.headers, allow_redirects=True, timeout=30)
            cookies = self.session.cookies.get_dict()
            if 'c_user' in cookies:
                cookie_parts = [f"{k}={v}" for k, v in cookies.items()]
                return ';'.join(cookie_parts), cookies.get('c_user'), "Thành công"
            else:
                return None, None, "Sai tài khoản"
        except Exception as e: return None, None, str(e)
        finally: self.create_new_session()

# ==================== HÀM XỬ LÝ ====================
def add_border_to_qr(image_data: bytes) -> bytes:
    try:
        image = Image.open(BytesIO(image_data))
        if image.mode == 'RGBA': image = image.convert('RGB')
        border_width = 40; radius = 80
        width, height = image.size
        new_width, new_height = width + border_width * 2, height + border_width * 2
        bg = Image.new("RGB", (new_width, new_height), (255, 255, 255))
        bg.paste(image, (border_width, border_width))
        mask = Image.new("L", (new_width, new_height), 0)
        draw = ImageDraw.Draw(mask)
        draw.rounded_rectangle([0, 0, new_width, new_height], radius, fill=255)
        output = BytesIO(); bg.save(output, format='PNG'); return output.getvalue()
    except Exception: return image_data

def fmt_date(d_str):
    try:
        return datetime.strptime(d_str[:19], "%Y-%m-%dT%H:%M:%S").strftime("%d/%m/%Y")
    except: return d_str or "Ẩn"

# ==================== BIẾN LƯU TRẠNG THÁI ====================
user_get_states = {}
zalo_storage = {}

# ==================== HÀM XỬ LÝ ZALO ====================
async def handle_zalo_login_tele(update: Update, context: ContextTypes.DEFAULT_TYPE, session_id: str):
    user = update.effective_user
    timeout = 120
    current_qr_path = None

    async def callback(event):
        nonlocal current_qr_path
        event_type = event["type"]
        data = event.get("data")
        actions = event.get("actions", {})

        if event_type == LoginQRCallbackEventType.QRCodeGenerated:
            qr_path = f"cache/qr_zalo_{data.get('code')}_{session_id}.png"
            os.makedirs("cache", exist_ok=True)
            await actions["saveToFile"](qr_path)
            current_qr_path = qr_path
            with open(qr_path, 'rb') as f:
                bordered_data = add_border_to_qr(f.read())
            await update.message.reply_photo(photo=BytesIO(bordered_data), caption="📱 **ĐĂNG NHẬP ZALO**\nQuét mã QR bên dưới bằng Zalo.\n⏰ Mã có hiệu lực trong 2 phút.", parse_mode='Markdown')

        elif event_type == LoginQRCallbackEventType.QRCodeExpired:
            await update.message.reply_text("⏰ QR CODE HẾT HẠN. Dùng lại lệnh `/get zalo`.", parse_mode='Markdown')
            if current_qr_path and os.path.exists(current_qr_path): os.remove(current_qr_path)

        elif event_type == LoginQRCallbackEventType.QRCodeScanned:
            display_name = data.get("display_name", "Người dùng")
            await update.message.reply_text(f"✅ ĐÃ QUÉT QR bởi **{display_name}**. Xác nhận trên điện thoại.", parse_mode='Markdown')
            if current_qr_path and os.path.exists(current_qr_path): os.remove(current_qr_path)

        elif event_type == LoginQRCallbackEventType.QRCodeDeclined:
            await update.message.reply_text("❌ ĐĂNG NHẬP BỊ TỪ CHỐI.")
            if current_qr_path and os.path.exists(current_qr_path): os.remove(current_qr_path)

        elif event_type == LoginQRCallbackEventType.GotLoginInfo:
            await update.message.reply_text("🎉 ĐĂNG NHẬP THÀNH CÔNG! Đang lấy thông tin...")

    try:
        result = await asyncio.wait_for(login_qr_with_unique_imei(callback=callback), timeout=timeout)
        if result:
            cookies = result.get("cookies", {}); imei = result.get("imei", "N/A"); user_info = result.get("user_info", {})
            display_name = user_info.get("displayName", "N/A"); phone = user_info.get("phoneNumber", "N/A")
            cookies_str = json.dumps(cookies, ensure_ascii=False, indent=2)

            filename = f"{re.sub(r'[^\w\.\-]', '_', display_name)}_zalo.txt"
            file_content = f"Imei:\n{imei}\n\nCookie:\n{cookies_str}\n"

            await update.message.reply_document(document=BytesIO(file_content.encode("utf-8")), filename=filename)
        else:
            await update.message.reply_text("❌ LẤY THÔNG TIN THẤT BẠI.")
    except asyncio.TimeoutError:
        await update.message.reply_text("⏰ HẾT THỜI GIAN. Dùng lại lệnh `/get zalo`.")
    finally:
        if current_qr_path and os.path.exists(current_qr_path): os.remove(current_qr_path)

# ==================== CÁC LỆNH GIỮ LẠI ====================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 **Bot By Phan Anh Khôi (Rike)**\n\n"
        "**Các lệnh có sẵn:**\n"
        "• `/2fa [secret]` — 🔐 Tạo mã OTP\n"
        "• `/get zalo` — 📱 Lấy Cookie & IMEI Zalo\n"
        "• `/get facebook` — 🍪 Lấy Cookie Facebook\n"
        "• `/get discord` — 🔑 Lấy Token Discord\n\n"
        "Sử dụng lệnh để bắt đầu!",
        parse_mode='Markdown'
    )

async def cmd_2fa(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ Cú pháp: `/2fa [secret_key]`", parse_mode='Markdown')
        return
    secret = " ".join(context.args)
    try:
        resp = requests.get(API_2FA.format(secret.replace(" ", "")), timeout=10).json()
        token = resp.get("token")
        if token:
            await update.message.reply_text(f"✅ **MÃ OTP:** `{token}`\n*Mã có hiệu lực 30 giây.*", parse_mode='Markdown')
        else:
            await update.message.reply_text("❌ Không nhận được mã OTP!")
    except Exception as e:
        await update.message.reply_text(f"❌ Lỗi: {e}")

async def cmd_get(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if not context.args:
        await update.message.reply_text("❌ Chọn: `/get zalo`, `/get facebook`, hoặc `/get discord`")
        return
    
    platform = context.args[0].lower()
    if platform == 'zalo':
        await update.message.reply_text("📱 Đang tạo mã QR Zalo, vui lòng chờ...")
        session_id = str(uuid.uuid4())
        await handle_zalo_login_tele(update, context, session_id)

    elif platform == 'facebook':
        user_get_states[user_id] = {'tool': 'facebook_cookie', 'step': 'waiting_email'}
        await update.message.reply_text("🍪 **Bước 1:** Gửi Email / SĐT Facebook của bạn vào chat này.", parse_mode='Markdown')

    elif platform == 'discord':
        user_get_states[user_id] = {'tool': 'discord_token', 'step': 'waiting_email'}
        await update.message.reply_text("🔑 **Bước 1:** Gửi Email / SĐT Discord của bạn vào chat này.", parse_mode='Markdown')

    else:
        await update.message.reply_text("❌ Chỉ hỗ trợ: `zalo`, `facebook`, `discord`.")

# ==================== XỬ LÝ TIN NHẮN ====================
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text
    if user_id not in user_get_states:
        return
    
    state = user_get_states[user_id]
    tool = state['tool']
    step = state.get('step')

    if tool == 'facebook_cookie':
        if step == 'waiting_email':
            state['email'] = text
            state['step'] = 'waiting_password'
            await update.message.reply_text(f"✅ Đã nhận Email: `{text}`\n📌 **Bước 2:** Gửi mật khẩu.", parse_mode='Markdown')
        elif step == 'waiting_password':
            del user_get_states[user_id]
            await update.message.reply_text("⏳ Đang xử lý lấy Cookie FB...")
            getter = FacebookCookieGetter()
            cookie, uid, msg = getter.login_facebook(state['email'], text)
            if cookie:
                file_content = f"Cookie:\n{cookie}\n"
                await update.message.reply_document(document=BytesIO(file_content.encode("utf-8")), filename="fb_cookie.txt")
            else:
                await update.message.reply_text(f"❌ Lỗi: {msg}")

    elif tool == 'discord_token':
        if step == 'waiting_email':
            state['email'] = text
            state['step'] = 'waiting_password'
            await update.message.reply_text(f"✅ Đã nhận Email: `{text}`\n📌 **Bước 2:** Gửi mật khẩu.", parse_mode='Markdown')
        elif step == 'waiting_password':
            state['password'] = text
            state['step'] = 'waiting_2fa'
            keyboard = [
                [InlineKeyboardButton("✅ Có 2FA", callback_data='2fa_yes'),
                 InlineKeyboardButton("❌ Không 2FA", callback_data='2fa_no')]
            ]
            await update.message.reply_text("🔐 Tài khoản có bật 2FA không?", reply_markup=InlineKeyboardMarkup(keyboard))
        elif step == 'waiting_2fa_code':
            twofa_code = text.replace(' ', '').replace('-', '')
            if state.get('twofa_type') == 'totp':
                try:
                    import pyotp
                    totp = pyotp.TOTP(twofa_code)
                    twofa_code = totp.now()
                except: pass
            del user_get_states[user_id]
            await update.message.reply_text("⏳ Đang xử lý lấy Token Discord...")
            getter = DiscordTokenGetter()
            token, uid, msg = getter.login_discord(state['email'], state['password'], twofa_code, state.get('twofa_type'))
            if token:
                file_content = f"Token:\n{token}\n"
                await update.message.reply_document(document=BytesIO(file_content.encode("utf-8")), filename="dc_token.txt")
            else:
                await update.message.reply_text(f"❌ Lỗi: {msg}")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    await query.answer()
    if user_id not in user_get_states:
        await query.edit_message_text("❌ Phiên làm việc đã hết hạn.")
        return
    state = user_get_states[user_id]
    if query.data == '2fa_yes':
        state['has_2fa'] = True
        state['step'] = 'waiting_2fa_code'
        state['twofa_type'] = 'totp'
        keyboard = [
            [InlineKeyboardButton("📱 Authenticator", callback_data='2fa_totp'),
             InlineKeyboardButton("🔑 Backup Code", callback_data='2fa_backup')]
        ]
        await query.edit_message_text("📌 Chọn loại 2FA:", reply_markup=InlineKeyboardMarkup(keyboard))
    elif query.data == '2fa_no':
        del user_get_states[user_id]
        await query.edit_message_text("⏳ Đang xử lý không 2FA...")
        getter = DiscordTokenGetter()
        token, uid, msg = getter.login_discord(state['email'], state['password'], "", "")
        if token:
            file_content = f"Token:\n{token}\n"
            await query.message.reply_document(document=BytesIO(file_content.encode("utf-8")), filename="dc_token.txt")
        else:
            await query.message.reply_text(f"❌ Lỗi: {msg}")
    elif query.data == '2fa_totp':
        state['twofa_type'] = 'totp'
        await query.edit_message_text("🔐 Gửi **Secret Key** của Authenticator App vào chat.")
    elif query.data == '2fa_backup':
        state['twofa_type'] = 'backup'
        await query.edit_message_text("🔐 Gửi **Backup Code** vào chat.")

# ==================== CHẠY BOT ====================


# ==============================================================================
# BỘ ĐỘNG CƠ BOT TELEGRAM ĐA NĂNG (HỖ TRỢ CHẠY TRỰC TIẾP & TÍCH HỢP WEB 24/7)
# Tác giả: Phan Anh Khôi (Rike) | Token: 8995799349:AAE8uwWyS-CHzj2yQNkFkMynCTprFTZ1JNc
# ==============================================================================
import threading as _bot_threading

class DirectTelegramBotRunner:
    """Bộ chạy Bot Telegram trực tiếp qua REST Long-Polling (Không phụ thuộc thư viện ngoài):
    - Đảm bảo khởi chạy 100% trong mọi môi trường và thực thi đầy đủ các lệnh:
      /start, /menu, /qr, /get zalo, /get facebook, /get discord, /2fa, /font, /status"""

    def __init__(self, token=TELEGRAM_BOT_TOKEN):
        self.token = str(token or TELEGRAM_BOT_TOKEN).strip()
        self.api_base = f"https://api.telegram.org/bot{self.token}"
        self.stop_ev = _bot_threading.Event()
        self.offset = 0
        self.session = requests.Session()
        self.active_qr_locks = set()

    def api_call(self, method, data=None, files=None, timeout=25):
        try:
            url = f"{self.api_base}/{method}"
            r = self.session.post(url, data=data, files=files, timeout=timeout)
            return r.json() if r.content else {}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def send_text(self, chat_id, text, reply_to=None, parse_mode="HTML"):
        pl = {"chat_id": chat_id, "text": text}
        if parse_mode:
            pl["parse_mode"] = parse_mode
        if reply_to:
            pl["reply_to_message_id"] = reply_to
        return self.api_call("sendMessage", data=pl)

    def send_photo_bytes(self, chat_id, png_bytes, caption="", reply_to=None):
        pl = {"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"}
        if reply_to:
            pl["reply_to_message_id"] = reply_to
        return self.api_call("sendPhoto", data=pl, files={"photo": ("zalo_qr.png", png_bytes, "image/png")})

    def send_doc_bytes(self, chat_id, content_bytes, filename, caption="", reply_to=None):
        pl = {"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"}
        if reply_to:
            pl["reply_to_message_id"] = reply_to
        return self.api_call("sendDocument", data=pl, files={"document": (filename, content_bytes, "text/plain")})

    def delete_msg(self, chat_id, message_id):
        if not message_id:
            return
        self.api_call("deleteMessage", data={"chat_id": chat_id, "message_id": message_id}, timeout=8)

    def handle_zalo_qr_command(self, chat_id, user_id, msg_id):
        if user_id in self.active_qr_locks:
            self.send_text(chat_id, "⏳ Bạn đang có 1 phiên QR Zalo đang chờ quét. Vui lòng quét hoặc đợi hết hạn!", reply_to=msg_id)
            return
        self.active_qr_locks.add(user_id)

        def _worker():
            qr_msg_id = None
            scan_msg_id = None
            try:
                wait_r = self.send_text(
                    chat_id,
                    "🖥️ <b>Đang khởi tạo Máy Tính Zalo PC & lấy mã QR chính chủ...</b>\n"
                    "<i>(Bắt buộc kiểm tra thiết bị vào trong Acc trước khi xuất Cookie & IMEI)</i>",
                    reply_to=msg_id
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
                        pc_lbl = ev_data.get("pc_name") or "DESKTOP-ZALO-PC"
                        cap = (
                            f"📲 <b>MÃ QR ĐĂNG NHẬP ZALO PC CHÍNH CHỦ</b>\n"
                            f"🖥️ <b>Thiết bị:</b> <code>{pc_lbl}</code>\n"
                            f"⏳ <b>Thời hạn:</b> 100 giây\n"
                            f"👉 <i>Mở Zalo trên điện thoại quét mã và bấm <b>Đăng nhập</b> để ghim máy tính vào trong tài khoản!</i>\n"
                            f"👑 <b>Dev:</b> Phan Anh Khôi (Rike)"
                        )
                        pr = self.send_photo_bytes(chat_id, bordered_png, caption=cap, reply_to=msg_id)
                        qr_msg_id = (pr.get("result") or {}).get("message_id")

                    elif ev_type == LoginQRCallbackEventType.QRCodeScanned:
                        self.delete_msg(chat_id, qr_msg_id)
                        d_name = ev_data.get("display_name") or "Người dùng Zalo"
                        sr = self.send_text(
                            chat_id,
                            f"✅ <b>Đã nhận diện tài khoản: {d_name}</b>\n"
                            f"📲 <i>Vui lòng bấm <b>Đồng ý / Đăng nhập</b> trên điện thoại để máy tính vào trong Acc!</i>",
                            reply_to=msg_id
                        )
                        scan_msg_id = (sr.get("result") or {}).get("message_id")

                    elif ev_type == LoginQRCallbackEventType.QRCodeExpired:
                        self.delete_msg(chat_id, qr_msg_id)
                        self.delete_msg(chat_id, scan_msg_id)
                        self.send_text(chat_id, "⏰ <b>Mã QR Zalo đã hết hạn!</b> Gõ <code>/qr</code> hoặc <code>/get zalo</code> để lấy mã mới.", reply_to=msg_id)

                    elif ev_type == LoginQRCallbackEventType.QRCodeDeclined:
                        self.delete_msg(chat_id, qr_msg_id)
                        self.delete_msg(chat_id, scan_msg_id)
                        self.send_text(chat_id, "❌ <b>Bạn đã từ chối đăng nhập QR trên điện thoại!</b>", reply_to=msg_id)

                    elif ev_type == LoginQRCallbackEventType.GotLoginInfo:
                        self.delete_msg(chat_id, scan_msg_id)
                        in_acc = bool(ev_data.get("in_account_verified"))
                        cookies = ev_data.get("cookies") or {}
                        imei = ev_data.get("imei") or ""
                        zpw_enk = ev_data.get("zpw_enk") or ""
                        pc_name = ev_data.get("pc_name") or "DESKTOP-ZALO-PC"
                        if not in_acc:
                            v_res = verify_zalo_pc_device_logged_in_account(imei=imei, cookies_dict=cookies, zpw_enk=zpw_enk)
                            in_acc = bool(v_res.get("ok"))
                        if not in_acc:
                            self.send_text(
                                chat_id,
                                f"❌ <b>LỖI BẢO VỆ PHIÊN:</b> Máy tính <code>{pc_name}</code> chưa nằm trong tài khoản Zalo của bạn!\n"
                                f"👉 Hệ thống KHÔNG xuất Cookie/IMEI để tránh die phiên. Vui lòng thử lại!",
                                reply_to=msg_id
                            )
                            return
                        u_info = ev_data.get("user_info") or {}
                        d_name = ev_data.get("display_name") or u_info.get("displayName") or "Zalo VIP"
                        uid = ev_data.get("uid") or u_info.get("uid") or "N/A"
                        cookies_str = json.dumps(cookies, ensure_ascii=False, indent=2)
                        file_txt = (
                            f"# ĐÃ XÁC THỰC MÁY TÍNH TRONG ACC ZALO 100% — PHAN ANH KHÔI (RIKE)\n"
                            f"PC_Device: {pc_name}\n"
                            f"UID: {uid}\n"
                            f"Display_Name: {d_name}\n\n"
                            f"Imei:\n{imei}\n\n"
                            f"Zpw_Enk:\n{zpw_enk}\n\n"
                            f"Cookie:\n{cookies_str}\n"
                        )
                        cap_ok = (
                            f"✅ <b>ĐĂNG NHẬP ZALO PC THÀNH CÔNG (ĐÃ GHIM TRONG ACC 24/7)</b>\n"
                            f"━━━━━━━━━━━━━━━━━━━━━━\n"
                            f"👤 <b>Tên Zalo:</b> {d_name}\n"
                            f"🆔 <b>UID:</b> <code>{uid}</code>\n"
                            f"🖥️ <b>Thiết bị trong Acc:</b> <code>{pc_name}</code>\n"
                            f"🔑 <b>IMEI:</b> <code>{imei}</code>\n"
                            f"🛡️ <b>Khóa zpw_enk:</b> <code>Đã khóa sống 100%</code>\n"
                            f"👑 <b>Admin:</b> Phan Anh Khôi (Rike)"
                        )
                        safe_fn = re.sub(r"[^\w\-\.]", "_", d_name) + "_zalo_cookie_imei.txt"
                        self.send_doc_bytes(chat_id, file_txt.encode("utf-8"), safe_fn, caption=cap_ok, reply_to=msg_id)
                        if len(cookies_str) < 3500:
                            self.send_text(chat_id, f"🍪 <b>Cookie JSON:</b>\n<pre>{cookies_str}</pre>", reply_to=msg_id)

                login_qr_with_unique_imei(callback=_sync_cb, timeout=100)
            except Exception as e:
                self.send_text(chat_id, f"⚠️ Lỗi xử lý QR Zalo: <code>{e}</code>", reply_to=msg_id)
            finally:
                self.active_qr_locks.discard(user_id)

        _bot_threading.Thread(target=_worker, daemon=True).start()

    def process_update(self, upd):
        msg = upd.get("message") or upd.get("edited_message") or {}
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        from_u = msg.get("from") or {}
        user_id = from_u.get("id") or chat_id
        msg_id = msg.get("message_id")
        text = str(msg.get("text") or "").strip()
        if not chat_id or not text:
            return

        parts = text.split()
        cmd = parts[0].lower().split("@")[0]
        args = parts[1:]

        if cmd in ("/start", "/help", "/menu"):
            menu_html = (
                "🌟 <b>HỆ THỐNG BOT ĐA NĂNG — PHAN ANH KHÔI (RIKE)</b> 🌟\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "📲 <b>1. LẤY COOKIE & IMEI ZALO PC (GHIM TRONG ACC 24/7):</b>\n"
                "• <code>/qr</code> hoặc <code>/get zalo</code> — Tạo mã QR Máy Tính chính chủ, quét xong máy tính nằm cố định trong Acc Zalo không bao giờ die Cookie/IMEI!\n\n"
                "🔐 <b>2. ĐĂNG NHẬP & LẤY TOKEN / COOKIE:</b>\n"
                "• <code>/get discord &lt;email&gt; &lt;pass&gt; [2fa]</code> — Lấy Token Discord\n"
                "• <code>/get facebook &lt;email&gt; &lt;pass&gt; [2fa]</code> — Lấy Cookie Facebook\n"
                "• <code>/2fa &lt;Secret_Key&gt;</code> — Lấy mã OTP 2FA 6 số\n\n"
                "✨ <b>3. ĐỔI FONT CHỮ & TIỆN ÍCH VIP:</b>\n"
                "• <code>/font &lt;nội dung&gt;</code> — Đổi chữ sang 8 kiểu Font Siêu Đẹp Đẳng Cấp\n"
                "• <code>/status</code> — Kiểm tra trạng thái thiết bị Zalo PC đang giữ sống\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "👑 <b>Tác giả:</b> Phan Anh Khôi (Rike)"
            )
            self.send_text(chat_id, menu_html, reply_to=msg_id)

        elif cmd == "/qr" or (cmd == "/get" and args and args[0].lower() == "zalo"):
            self.handle_zalo_qr_command(chat_id, user_id, msg_id)

        elif cmd == "/get":
            if len(args) < 3:
                self.send_text(
                    chat_id,
                    "📌 <b>Hướng dẫn lệnh /get:</b>\n"
                    "• <code>/get zalo</code> (Hoặc <code>/qr</code>)\n"
                    "• <code>/get discord &lt;email&gt; &lt;pass&gt; [2fa]</code>\n"
                    "• <code>/get facebook &lt;email&gt; &lt;pass&gt; [2fa]</code>",
                    reply_to=msg_id
                )
                return
            plat = args[0].lower()
            u_acc, u_pw = args[1], args[2]
            u_2fa = args[3] if len(args) > 3 else ""
            if plat == "discord":
                tk, uid, st_m = discord_getter.login_discord(u_acc, u_pw, u_2fa)
                if tk:
                    self.send_text(chat_id, f"✅ <b>Token Discord (UID: {uid}):</b>\n<code>{tk}</code>\n👑 <b>Dev:</b> Phan Anh Khôi (Rike)", reply_to=msg_id)
                else:
                    self.send_text(chat_id, f"❌ <b>Lỗi:</b> {st_m}", reply_to=msg_id)
            elif plat in ("facebook", "fb"):
                ck, uid, st_m = fb_getter.login_facebook(u_acc, u_pw, u_2fa)
                if ck:
                    self.send_text(chat_id, f"✅ <b>Cookie Facebook (UID: {uid}):</b>\n<code>{ck}</code>\n👑 <b>Dev:</b> Phan Anh Khôi (Rike)", reply_to=msg_id)
                else:
                    self.send_text(chat_id, f"❌ <b>Lỗi:</b> {st_m}", reply_to=msg_id)

        elif cmd == "/2fa":
            if not args:
                self.send_text(chat_id, "⚠️ Cú pháp: <code>/2fa &lt;Secret_Key&gt;</code>", reply_to=msg_id)
                return
            sec = "".join(args)
            try:
                r2 = requests.get(API_2FA.format(sec), timeout=8).json()
                code_v = r2.get("token") or "Lỗi"
                self.send_text(chat_id, f"🔐 <b>Mã 2FA OTP:</b> <code>{code_v}</code>\n👑 <b>Dev:</b> Phan Anh Khôi (Rike)", reply_to=msg_id)
            except Exception as e:
                self.send_text(chat_id, f"⚠️ Lỗi lấy 2FA: {e}", reply_to=msg_id)

        elif cmd == "/font":
            sample = " ".join(args).strip() or "Phan Anh Khoi Rike VIP 2026"
            normal = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            styles = {
                "Bold Serif": "𝐀𝐁𝐂𝐃𝐄𝐅𝐆𝐇𝐈𝐉𝐊𝐋𝐌𝐍𝐎𝐏𝐐𝐑𝐒𝐓𝐔𝐕𝐖𝐗𝐘𝐙𝐚𝐛𝐜𝐝𝐞𝐟𝐠𝐡𝐢𝐣𝐤𝐥𝐦𝐧𝐨𝐩𝐪𝐫𝐬𝐭𝐮𝐯𝐰𝐱𝐲𝐳𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗",
                "Script VIP": "𝒜ℬ𝒞𝒟ℰℱ𝒢ℋℐ𝒥𝒦ℒℳ𝒩𝒪𝒫𝒬ℛ𝒮𝒯𝒰𝒱𝒲𝒳𝒴𝒵𝒶𝒷𝒸𝒹ℯ𝒻ℊ𝒽𝒾𝒿𝓀𝓁𝓂𝓃ℴ𝓅𝓆𝓇𝓈𝓉𝓊𝓋𝓌𝓍𝓎𝓏0123456789",
                "Fraktur": "mathfrak",
                "Double Struck": "𝔸𝔹ℂ𝔻𝔼𝔽𝔾ℍ𝕀𝕁𝕂𝕃𝕄ℕ𝕆ℙℚℝ𝕊𝕋𝕌𝕍𝕎𝕏𝕐ℤ𝕒𝕓𝕔𝕕𝕖𝕗𝕘𝕙𝕚𝕛𝕜𝕝𝕞󠁮𝕠𝕡𝕢𝕣𝕤𝕥𝕦𝕧𝕨𝕩𝕪𝕫𝟘𝟙𝟚𝟛𝟜𝟝𝟞𝟟𝟠𝟡",
            }
            lines_f = [f"✨ <b>BẢNG ĐỔI CHỮ ĐẲNG CẤP — PHAN ANH KHÔI (RIKE):</b>"]
            for st_name, table in styles.items():
                if len(table) == len(normal):
                    tr = sample.translate(str.maketrans(normal, table))
                    lines_f.append(f"• <b>{st_name}:</b> <code>{tr}</code>")
            self.send_text(chat_id, "\n".join(lines_f), reply_to=msg_id)

        elif cmd == "/status":
            active_devs = ZaloPCSessionKeeper.list_active_devices()
            if not active_devs:
                self.send_text(chat_id, "📊 <b>Trạng thái:</b> Hệ thống Bot Phan Anh Khôi (Rike) đang Online 24/7. Chưa có phiên PC nào đang ghim.", reply_to=msg_id)
            else:
                lines_s = ["🖥️ <b>DANH SÁCH MÁY TÍNH ĐANG TRONG ACC ZALO (24/7):</b>"]
                for dv in active_devs:
                    lines_s.append(f"• <b>{dv['display_name']}</b> (UID: <code>{dv['uid']}</code>) — <code>{dv['pc_name']}</code> [Пing: {dv['ping_count']}]")
                self.send_text(chat_id, "\n".join(lines_s), reply_to=msg_id)

    def run_forever(self):
        while not self.stop_ev.is_set():
            try:
                res = self.api_call("getUpdates", data={"offset": self.offset, "timeout": 20}, timeout=25)
                if isinstance(res, dict) and res.get("ok") and isinstance(res.get("result"), list):
                    for upd in res["result"]:
                        self.offset = max(self.offset, int(upd.get("update_id", 0)) + 1)
                        try:
                            self.process_update(upd)
                        except Exception:
                            pass
                else:
                    time.sleep(3.0)
            except Exception:
                time.sleep(3.0)


def start_background_telegram_bot(token=TELEGRAM_BOT_TOKEN):
    """Khởi chạy Bot Telegram Phan Anh Khôi (Rike) ở chế độ nền (Background Daemon Thread)."""
    runner = DirectTelegramBotRunner(token=token)
    th = _bot_threading.Thread(target=runner.run_forever, daemon=True)
    th.start()
    return runner


def main():
    print("🤖 Đang khởi động Bot Telegram Phan Anh Khôi (Rike)...")
    print(f"🔑 Token: {TELEGRAM_BOT_TOKEN[:15]}...")
    try:
        application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("menu", start))
        application.add_handler(CommandHandler("get", handle_get_command))
        application.add_handler(CommandHandler("qr", lambda u, c: login_zalo_qr(u, c)))
        application.add_handler(CommandHandler("download", download_command))
        application.add_handler(CommandHandler("capcut", capcut_command))
        application.add_handler(CommandHandler("github", github_command))
        application.add_handler(CommandHandler("insta", insta_command))
        application.add_handler(CommandHandler("roblox", roblox_command))
        application.add_handler(CommandHandler("tiktok", tiktok_command))
        application.add_handler(CommandHandler("youtube", youtube_command))
        application.add_handler(CommandHandler("infott", infott_command))
        application.add_handler(CommandHandler("fb", fb_command))
        application.add_handler(CommandHandler("avtfb", avtfb_command))
        application.add_handler(CommandHandler("2fa", twofa_command))
        print("✅ Bot Telegram Phan Anh Khôi (Rike) đã sẵn sàng nhận lệnh!")
        application.run_polling(allowed_updates=Update.ALL_TYPES)
    except Exception as e:
        print(f"⚡ Chuyển sang DirectTelegramBotRunner (Long-Polling Engine): {e}")
        runner = DirectTelegramBotRunner(token=TELEGRAM_BOT_TOKEN)
        runner.run_forever()

if __name__ == "__main__":
    main()
