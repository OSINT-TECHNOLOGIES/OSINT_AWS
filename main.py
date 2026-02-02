import asyncio
import logging
import os
import requests
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, FSInputFile

import database

from modules.identity import (
    social_osint,
    phone_osint,
    email_osint,
    tg_osint
)

from modules.finance import (
    crypto,
    fin_osint
)

from modules.network import (
    domain_osint,
    ip_osint,
    wayback
)

from modules.forensics import (
    qr_reader,
    metadata
)

from modules.tools import (
    ua_decoder
)

try:
    with open("token.txt", "r") as f:
        BOT_TOKEN = f.read().strip()
except FileNotFoundError:
    print("CRITICAL ERROR: token.txt was not found! Create this file in root folder and paste BotFather token here!")
    exit()

logging.basicConfig(level=logging.INFO)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

async def send_large_message(message: types.Message, text: str):
    if len(text) <= 4096:
        await message.answer(text, parse_mode="HTML", disable_web_page_preview=True)
    else:
        parts = []
        while len(text) > 0:
            if len(text) > 4096:
                part = text[:4096]
                last_newline = part.rfind('\n')
                if last_newline != -1:
                    part = text[:last_newline]
                    text = text[last_newline+1:]
                else:
                    text = text[4096:]
                parts.append(part)
            else:
                parts.append(text)
                text = ""

        for p in parts:
            await message.answer(p, parse_mode="HTML", disable_web_page_preview=True)
            await asyncio.sleep(0.3)

def get_welcome_text():
    return (
        "🕵️‍♂️ <b>OSINT AUTOMATED WORKSPACE</b>\n"
        "<i>This is automated self-hosted Telegram OSINT bot</i>\n\n"

        "<b>📂 AVAILABLE MODULES:</b>\n\n"

        "👤 <b>IDENTITY</b>\n"
        "• <b>Phone:</b> Carrier, Region, Messenger links.\n"
        "• <b>Nickname:</b> Deep search across 500+ sites (Maigret).\n"
        "• <b>Email:</b> Breaches, Registrations, Disposable check.\n"
        "• <b>Telegram:</b> Parse chat members, find Admins/Scammers.\n\n"

        "💰 <b>FINANCE</b>\n"
        "• <b>Crypto:</b> USDT/BTC Analysis, Exchange ID, Risk Check.\n"
        "• <b>Monitoring:</b> Real-time tracking of wallet balance.\n"
        "• <b>Cards:</b> BIN lookup (Bank, Country, Type).\n\n"

        "🕸 <b>NETWORK & WEB</b>\n"
        "• <b>Domain:</b> Whois, Subdomains, DNS Forensics.\n"
        "• <b>IP:</b> Geolocation, Provider, VPN detection.\n"
        "• <b>Wayback:</b> View deleted versions of websites.\n\n"

        "📸 <b>FORENSICS (Send file to Bot)</b>\n"
        "• <b>Exif/GPS:</b> Extract location from original photos.\n"
        "• <b>QR/Barcodes:</b> Decode hidden data from images.\n\n"

        "<i>Select a tool from the dashboard below:</i>"
    )


class AppStates(StatesGroup):
    wait_phone = State()
    wait_user = State()
    wait_email = State()
    wait_tg = State()

    wait_crypto = State()
    wait_bin = State()

    wait_domain = State()
    wait_ip = State()
    wait_wayback = State()

    wait_ua = State()

    set_shodan = State()
    set_wigle = State()
    set_tg_id = State()
    set_tg_hash = State()

def main_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📱 PHONE LOOKUP", callback_data="ph"), InlineKeyboardButton(text="👤 USERNAME SEARCH", callback_data="user")],
        [InlineKeyboardButton(text="📧 EMAIL PROBE", callback_data="em"), InlineKeyboardButton(text="✈️ TELEGRAM PARSER", callback_data="tg")],

        [InlineKeyboardButton(text="💰 CRYPTO ANALYZER", callback_data="cr"), InlineKeyboardButton(text="💳 CARD BIN", callback_data="bin")],

        [InlineKeyboardButton(text="🕸 DOMAIN INTEL", callback_data="dom"), InlineKeyboardButton(text="🌍 IP GEOLOCATION", callback_data="ip")],
        [InlineKeyboardButton(text="🕰 WAYBACK MACHINE", callback_data="wb"), InlineKeyboardButton(text="📱 UA DECODER", callback_data="ua")],

        [InlineKeyboardButton(text="⚙️ SETTINGS / API", callback_data="settings"), InlineKeyboardButton(text="🔄 REFRESH MENU", callback_data="cancel")]
    ])

def settings_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Shodan API", callback_data="s_shodan")],
        [InlineKeyboardButton(text="📡 Wigle API", callback_data="s_wigle")],
        [InlineKeyboardButton(text="✈️ TG App ID", callback_data="s_tgid"), InlineKeyboardButton(text="✈️ TG Hash", callback_data="s_tghash")],
        [InlineKeyboardButton(text="🔙 Back to Dashboard", callback_data="cancel")]
    ])

@dp.message(Command("start"))
async def cmd_start(msg: types.Message):
    if not database.get_setting("setup_complete"):
        database.add_admin(msg.from_user.id)
        database.set_setting("setup_complete", "true")
        await msg.answer(f"👑 <b>System Initialized.</b>\nYou are now the Super Admin.\nID: {msg.from_user.id}", parse_mode="HTML")

    if database.is_admin(msg.from_user.id):
        await msg.answer(get_welcome_text(), reply_markup=main_kb(), parse_mode="HTML")
    else:
        await msg.answer("⛔ <b>ACCESS DENIED</b>\nThis station is restricted to authorized personnel only.", parse_mode="HTML")

@dp.callback_query(F.data == "cancel")
async def cb_cancel(cb: types.CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text(get_welcome_text(), reply_markup=main_kb(), parse_mode="HTML")


@dp.callback_query(F.data == "settings")
async def cb_settings(cb: types.CallbackQuery):
    shodan = "✅ Active" if database.get_setting("shodan_key") else "❌ Missing"
    tg = "✅ Active" if database.get_setting("tg_api_id") else "❌ Missing"

    text = (f"⚙️ <b>SYSTEM CONFIGURATION</b>\n\n"
            f"<b>API Status:</b>\n"
            f"• Shodan: {shodan}\n"
            f"• Telegram: {tg}\n\n"
            f"<i>Select a key to update:</i>")
    await cb.message.edit_text(text, reply_markup=settings_kb(), parse_mode="HTML")

@dp.callback_query(F.data == "s_shodan")
async def set_shodan(cb: types.CallbackQuery, state: FSMContext):
    await cb.message.edit_text("🔑 <b>Shodan API</b>\nPlease paste your API Key:", parse_mode="HTML")
    await state.set_state(AppStates.set_shodan)

@dp.message(AppStates.set_shodan)
async def save_shodan(msg: types.Message, state: FSMContext):
    database.set_setting("shodan_key", msg.text.strip())
    await msg.answer("✅ Shodan Key saved.", reply_markup=settings_kb())
    await state.clear()

@dp.callback_query(F.data == "s_tgid")
async def set_tgid(cb: types.CallbackQuery, state: FSMContext):
    await cb.message.edit_text("✈️ <b>Telegram App ID</b>\nEnter the numeric App ID:", parse_mode="HTML")
    await state.set_state(AppStates.set_tg_id)

@dp.message(AppStates.set_tg_id)
async def save_tgid(msg: types.Message, state: FSMContext):
    database.set_setting("tg_api_id", msg.text.strip())
    await msg.answer("✅ App ID saved.", reply_markup=settings_kb())
    await state.clear()

@dp.callback_query(F.data == "s_tghash")
async def set_tghash(cb: types.CallbackQuery, state: FSMContext):
    await cb.message.edit_text("✈️ <b>Telegram API Hash</b>\nEnter the hash string:", parse_mode="HTML")
    await state.set_state(AppStates.set_tg_hash)

@dp.message(AppStates.set_tg_hash)
async def save_tghash(msg: types.Message, state: FSMContext):
    database.set_setting("tg_api_hash", msg.text.strip())
    await msg.answer("✅ API Hash saved.", reply_markup=settings_kb())
    await state.clear()


BUTTONS = {
    "ph": ("📱 <b>PHONE INTELLIGENCE</b>\nEnter target number (e.g. +1555...):", AppStates.wait_phone),
    "user": ("👤 <b>USERNAME SEARCH</b>\nEnter target nickname:", AppStates.wait_user),
    "em": ("📧 <b>EMAIL PROBE</b>\nEnter target address:", AppStates.wait_email),
    "tg": ("✈️ <b>TELEGRAM RECON</b>\nPaste chat link (https://t.me/...) to extract members:", AppStates.wait_tg),
    "cr": ("💰 <b>CRYPTO FORENSICS</b>\nEnter BTC or TRC20 (USDT) address:", AppStates.wait_crypto),
    "bin": ("💳 <b>BANKING</b>\nEnter first 6 digits of the card (BIN):", AppStates.wait_bin),
    "dom": ("🕸 <b>DOMAIN RECON</b>\nEnter website domain:", AppStates.wait_domain),
    "ip": ("🌍 <b>IP INTELLIGENCE</b>\nEnter IPv4 address:", AppStates.wait_ip),
    "wb": ("🕰 <b>WAYBACK MACHINE</b>\nEnter URL to find deleted versions:", AppStates.wait_wayback),
    "ua": ("📱 <b>DEVICE ANALYSIS</b>\nPaste User-Agent string:", AppStates.wait_ua),
}

@dp.callback_query(F.data.in_(BUTTONS.keys()))
async def navigation_handler(cb: types.CallbackQuery, state: FSMContext):
    text, st = BUTTONS[cb.data]
    await cb.message.edit_text(text, parse_mode="HTML")
    await state.set_state(st)


@dp.message(AppStates.wait_phone)
async def p_phone(msg: types.Message, state: FSMContext):
    await msg.answer("🔎 Scanning phone networks...")
    res = phone_osint.check_phone(msg.text.strip())
    await send_large_message(msg, res)
    await msg.answer("✅ Task Complete.", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_user)
async def p_user(msg: types.Message, state: FSMContext):
    wait = await msg.answer("🕵️‍♂️ <b>Launching Maigret...</b>\nScanning 500+ sites. This takes 1-2 minutes.")
    res = await social_osint.check_username(msg.text.strip())
    await wait.delete()
    await send_large_message(msg, res)
    await msg.answer("✅ Task Complete.", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_email)
async def p_email(msg: types.Message, state: FSMContext):
    wait = await msg.answer("⏳ Analyzing email leaks and registrations...")
    res = await email_osint.check_email(msg.text.strip())
    await wait.delete()
    await msg.answer(res, parse_mode="HTML", reply_markup=main_kb(), disable_web_page_preview=True)
    await state.clear()

@dp.message(AppStates.wait_tg)
async def p_tg(msg: types.Message, state: FSMContext):
    wait = await msg.answer("✈️ Connecting to Telegram Network...\nExtracting members list.")
    res = await tg_osint.parse_chat_members(msg.text.strip())
    await wait.delete()
    await send_large_message(msg, res)
    await msg.answer("✅ Task Complete.", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_crypto)
async def p_crypto(msg: types.Message, state: FSMContext):
    wait = await msg.answer("🔍 Querying Blockchain Nodes...")
    addr = msg.text.strip()
    res = crypto.check_crypto(addr)
    await wait.delete()

    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🚨 Add to Live Monitoring", callback_data=f"mon_{addr}")]
    ])
    await msg.answer(res, parse_mode="HTML", reply_markup=kb)
    await msg.answer("Returning to dashboard...", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_bin)
async def p_bin(msg: types.Message, state: FSMContext):
    res = fin_osint.check_bin(msg.text.strip())
    await msg.answer(res, parse_mode="HTML", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_domain)
async def p_domain(msg: types.Message, state: FSMContext):
    wait = await msg.answer("🕸 Scanning DNS and Subdomains...")
    res = domain_osint.check_domain(msg.text.strip())
    await wait.delete()
    await send_large_message(msg, res)
    await msg.answer("✅ Task Complete.", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_ip)
async def p_ip(msg: types.Message, state: FSMContext):
    res = ip_osint.check_ip(msg.text.strip())
    await msg.answer(res, parse_mode="HTML", reply_markup=main_kb(), disable_web_page_preview=True)
    await state.clear()

@dp.message(AppStates.wait_wayback)
async def p_wayback(msg: types.Message, state: FSMContext):
    res = wayback.check_archive(msg.text.strip())
    await msg.answer(res, parse_mode="HTML", reply_markup=main_kb())
    await state.clear()

@dp.message(AppStates.wait_ua)
async def p_ua(msg: types.Message, state: FSMContext):
    res = ua_decoder.parse_ua(msg.text.strip())
    await msg.answer(res, parse_mode="HTML", reply_markup=main_kb())
    await state.clear()

@dp.message(F.photo | F.document)
async def handle_files(msg: types.Message):
    if not database.is_admin(msg.from_user.id): return

    status = await msg.answer("📥 <b>Forensic Analysis</b>\nDownloading and processing file...")

    if msg.document:
        f_id = msg.document.file_id
        fname = msg.document.file_name
    else:
        f_id = msg.photo[-1].file_id
        fname = "image.jpg"

    f = await bot.get_file(f_id)
    path = f"temp_{fname}"
    await bot.download_file(f.file_path, path)

    report = []

    qr = qr_reader.read_qr_code(path)
    if "QR Code" in qr or "Barcode" in qr:
        report.append(qr)

    if msg.document:
        meta = metadata.get_exif_data(path)
        if "GPS" in meta: report.append(meta)

    try: os.remove(path)
    except: pass

    if report:
        final_text = "\n➖➖➖➖➖➖\n".join(report)
    else:
        final_text = "🤷‍♂️ <b>No forensic data found.</b>\nTry sending the photo as a <b>File</b> (Document) to extract GPS metadata."

    await status.delete()
    await send_large_message(msg, final_text)

@dp.message(F.forward_origin)
async def analyze_forward(msg: types.Message):
    if not database.is_admin(msg.from_user.id): return

    origin = msg.forward_origin
    report = ["🕵️‍♂️ <b>Analyzing Forwarded Message:</b>"]

    if origin.type == 'user':
        u = origin.sender_user
        name = f"{u.first_name} {u.last_name or ''}".strip()
        report.append(f"👤 <b>User:</b> {name}")
        report.append(f"🆔 <b>ID:</b> <code>{u.id}</code>")
        if u.username: report.append(f"🔗 @{u.username}")

    elif origin.type == 'channel':
        c = origin.chat
        report.append(f"📢 <b>Channel:</b> {c.title}")
        report.append(f"🆔 <b>ID:</b> <code>{c.id}</code>")
        if c.username: report.append(f"🔗 @{c.username}")

    elif origin.type == 'hidden_user':
        report.append(f"👻 <b>Hidden User:</b> {origin.sender_user_name}")
        report.append("⚠️ ID is hidden by privacy settings.")

    await msg.answer("\n".join(report), parse_mode="HTML")

@dp.callback_query(F.data.startswith("mon_"))
async def cb_monitor_add(cb: types.CallbackQuery):
    addr = cb.data.split("_")[1]
    database.add_to_watchlist(cb.from_user.id, addr, 0.0)
    await cb.answer("✅ Target added to Watchlist.", show_alert=True)

async def crypto_monitor_task():
    while True:
        targets = database.get_watchlist()

        for item in targets:
            record_id, user_id, address, last_bal, t_type = item

            try:
                url = f"https://apilist.tronscan.org/api/account?address={address}"
                res = requests.get(url, timeout=5).json()

                current_bal = 0.0
                for t in res.get('withPriceTokens', []):
                    if t.get('tokenAbbr') == 'USDT':
                        current_bal = float(t.get('balance', 0)) / 1000000

                if current_bal != last_bal:
                    diff = current_bal - last_bal
                    emoji = "fw🤑 INCOMING FUND!" if diff > 0 else "💸 OUTGOING FUND!"
                    msg = (f"🚨 <b>MONITORING ALERT</b>\n"
                           f"{emoji}\n"
                           f"👛: <code>{address}</code>\n"
                           f"Old: {last_bal} $\n"
                           f"New: {current_bal} $\n"
                           f"Diff: {diff:+.2f} $")

                    try:
                        await bot.send_message(user_id, msg, parse_mode="HTML")
                    except: pass

                    database.update_balance(record_id, current_bal)

            except Exception as e:
                logging.error(f"Monitor error for {address}: {e}")

            await asyncio.sleep(2)

        await asyncio.sleep(300)


async def on_startup(bot: Bot):
    admins = database.get_all_admins()
    for uid in admins:
        try:
            await bot.send_message(uid, "🟢 <b>SYSTEM ONLINE</b>\nOSINT AWS is ready.", reply_markup=main_kb(), parse_mode="HTML")
        except: pass

async def main():
    asyncio.create_task(crypto_monitor_task())
    dp.startup.register(on_startup)
    await bot.delete_webhook(drop_pending_updates=True)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
