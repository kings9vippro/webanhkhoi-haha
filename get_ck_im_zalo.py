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
from zalo_login import login_qr_with_unique_imei, LoginQRCallbackEventType

# ==================== CẤU HÌNH ====================
TELEGRAM_BOT_TOKEN = "8951562495:AAG4Eamv5eUEG4vjtUWcGeEgub2H2Z-Z6qw"

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
        "🤖 **Bot By Phan Anh Khôi**\n\n"
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
def main():
    app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("2fa", cmd_2fa))
    app.add_handler(CommandHandler("get", cmd_get))
    app.add_handler(CallbackQueryHandler(button_callback))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🤖 Bot Telegram Get Cookie Imei đã chạy!")
    app.run_polling()

if __name__ == "__main__":
    main()
