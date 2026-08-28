import os
import re
import time
import html
import asyncio
import hmac
import hashlib
import logging
import sqlite3
import requests
from datetime import datetime
from collections import OrderedDict
from threading import Thread, Lock
from flask import Flask, request, jsonify

from aiogram import Bot, Dispatcher, F, types
from aiogram.filters import CommandStart, Command, StateFilter
from aiogram.types import (
    LabeledPrice, 
    PreCheckoutQuery, 
    InlineKeyboardMarkup, 
    InlineKeyboardButton,
    ReplyKeyboardMarkup, 
    KeyboardButton, 
    ReplyKeyboardRemove,
    BotCommand,
    BotCommandScopeChat
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from dotenv import load_dotenv

load_dotenv()

# --- Конфигурация ---
TG_BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))  # Ваш Telegram ID
PORT = int(os.getenv("PORT", 5000))
IG_APP_SECRET = os.getenv("IG_APP_SECRET", "")  # App Secret из Meta для проверки подписи вебхука
IG_APP_ID = os.getenv("IG_APP_ID", "")  # App ID из Meta — нужен для автопродления Instagram-токена
GRAPH_API_URL = "https://graph.facebook.com/v19.0"
TOKEN_RENEW_CHECK_INTERVAL = 24 * 3600  # проверяем раз в сутки
TOKEN_RENEW_THRESHOLD = 5 * 86400  # продлеваем, если до истечения осталось меньше 5 дней

# --- Хранилище настроек ---
# Если задан DATABASE_URL — используем внешний Postgres (переживает рестарт/редеплой
# на любом хостинге). Если нет — локальный SQLite-файл по пути DB_PATH (переживает
# рестарт только если хостинг даёт постоянный диск и DB_PATH указывает именно на него).
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL)
DB_PATH = os.getenv("DB_PATH", "bot_settings.db")

if USE_POSTGRES:
    import psycopg2
    import psycopg2.extras
else:
    logging.warning(
        "DATABASE_URL не задан — настройки хранятся в локальном SQLite-файле "
        f"'{DB_PATH}'. Если хостинг пересоздаёт файловую систему при каждом "
        "рестарте/редеплое, все настройки и статистика будут сбрасываться. "
        "Чтобы это исправить — подключите бесплатный Postgres (например Neon.tech "
        "или Supabase) и укажите его адрес в переменной DATABASE_URL."
    )

if not TG_BOT_TOKEN:
    raise ValueError("Укажите BOT_TOKEN в переменных окружения!")

if not ADMIN_ID:
    raise ValueError(
        "Укажите ADMIN_ID в переменных окружения! "
        "Без него любой пользователь Telegram получит доступ к админ-панели."
    )

if not IG_APP_SECRET:
    logging.warning(
        "IG_APP_SECRET не задан — подпись входящих Instagram-вебхуков не проверяется. "
        "Это небезопасно для продакшена: любой, кто узнает URL /webhook, "
        "сможет присылать поддельные события от вашего имени."
    )

if not IG_APP_ID or not IG_APP_SECRET:
    logging.warning(
        "IG_APP_ID и/или IG_APP_SECRET не заданы — автопродление Instagram Access Token "
        "работать не будет, токен придётся обновлять вручную в Meta for Developers."
    )

# --- Защита от повторной обработки одного и того же события Instagram ---
# Meta повторяет доставку вебхука, если не получает 200 OK быстро — без дедупликации
# один и тот же комментарий может вызвать несколько DM/ответов подряд.
_PROCESSED_COMMENTS = OrderedDict()
_PROCESSED_COMMENTS_LOCK = Lock()
_PROCESSED_COMMENTS_MAX = 1000


def _already_processed(comment_id: str) -> bool:
    if not comment_id:
        return False
    with _PROCESSED_COMMENTS_LOCK:
        if comment_id in _PROCESSED_COMMENTS:
            return True
        _PROCESSED_COMMENTS[comment_id] = True
        if len(_PROCESSED_COMMENTS) > _PROCESSED_COMMENTS_MAX:
            _PROCESSED_COMMENTS.popitem(last=False)
        return False


def verify_ig_signature(raw_body: bytes, signature_header: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(IG_APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    received = signature_header.split("sha256=", 1)[-1]
    return hmac.compare_digest(expected, received)


def strip_html(text: str) -> str:
    """Запасной вариант на случай сбоя HTML-разметки — убирает теги, оставляя текст читаемым."""
    return re.sub(r"<[^>]+>", "", text)


def exchange_for_long_lived_token(short_lived_token: str):
    """Обменивает короткоживущий Instagram/Facebook токен на долгоживущий (обычно ~60 дней).
    Возвращает (новый_токен, срок_действия_в_секундах) или None, если обмен не удался."""
    if not IG_APP_ID or not IG_APP_SECRET:
        return None
    try:
        resp = requests.get(
            f"{GRAPH_API_URL}/oauth/access_token",
            params={
                "grant_type": "fb_exchange_token",
                "client_id": IG_APP_ID,
                "client_secret": IG_APP_SECRET,
                "fb_exchange_token": short_lived_token,
            },
            timeout=10,
        )
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        logging.error(f"Ошибка запроса продления Instagram-токена: {e}")
        return None

    if not resp.ok or "access_token" not in data:
        logging.error(f"Не удалось продлить Instagram-токен: {data}")
        return None

    expires_in = data.get("expires_in") or (60 * 86400)
    return data["access_token"], int(expires_in)

logging.basicConfig(level=logging.INFO)
bot = Bot(token=TG_BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
app = Flask(__name__)

# --- База данных настроек (SQLite) ---
def get_db():
    if USE_POSTGRES:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return conn
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                amount INTEGER NOT NULL,
                paid_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
    else:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                first_seen TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS purchases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                paid_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
    default_start_msg = (
        "👋 <b>Добро пожаловать!</b>\n\n"
        "🚀 <b>Курс: Заработок на нейросетях и ИИ</b>\n\n"
        "• 5 готовых схем заработка на нейросетях\n"
        "• База рабочих промптов и связок\n"
        "• Создание контента и автоворонок с нуля\n"
        "• Доступ к закрытому Telegram-каналу и комьюнити\n\n"
        "Нажмите кнопку ниже для безопасной оплаты через ЮKassa:"
    )
    defaults = {
        "verify_token": "0000",
        "page_access_token": "",
        "trigger_word": "КУРС",
        "dm_text": "Привет! 🚀 Твоя ссылка на курс со скидкой 50%:\n👉 https://t.me/YOUR_BOT?start=insta",
        "reply_comment_text": "Ответили вам в Direct! 📥",
        "page_access_token_expires_at": "",
        "course_title": "Курс: Заработок на нейросетях",
        "course_description": "Полный доступ ко всем материалам курса и закрытому сообществу.",
        "course_start_message": default_start_msg,
        "course_photo_id": "",
        "course_price": "299000",
        "payment_token": "",
        "course_link": "https://t.me/+YOUR_INVITE_LINK"
    }
    for k, v in defaults.items():
        if USE_POSTGRES:
            cursor.execute(
                "INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                (k, v)
            )
        else:
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v))
    conn.commit()
    conn.close()

def get_setting(key: str) -> str:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT value FROM settings WHERE key = {'%s' if USE_POSTGRES else '?'}", (key,))
    row = cursor.fetchone()
    conn.close()
    return (row["value"] if row else "") or ""

def set_setting(key: str, value: str):
    conn = get_db()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute(
            "INSERT INTO settings (key, value) VALUES (%s, %s) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            (key, value)
        )
    else:
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()

def record_user(user_id: int):
    conn = get_db()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute("INSERT INTO users (user_id) VALUES (%s) ON CONFLICT (user_id) DO NOTHING", (user_id,))
    else:
        cursor.execute("INSERT OR IGNORE INTO users (user_id) VALUES (?)", (user_id,))
    conn.commit()
    conn.close()

def record_purchase(user_id: int, amount: int):
    conn = get_db()
    cursor = conn.cursor()
    if USE_POSTGRES:
        cursor.execute("INSERT INTO purchases (user_id, amount) VALUES (%s, %s)", (user_id, amount))
    else:
        cursor.execute("INSERT INTO purchases (user_id, amount) VALUES (?, ?)", (user_id, amount))
    conn.commit()
    conn.close()

def get_stats() -> dict:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS c FROM users")
    users_count = cursor.fetchone()["c"]
    cursor.execute("SELECT COUNT(*) AS c, COALESCE(SUM(amount), 0) AS s FROM purchases")
    row = cursor.fetchone()
    conn.close()
    return {
        "users_count": users_count,
        "purchases_count": row["c"],
        "revenue_kopecks": row["s"],
    }

init_db()

# --- FSM Состояния ---
class AdminStates(StatesGroup):
    waiting_for_page_token = State()
    waiting_for_trigger_word = State()
    waiting_for_dm_text = State()
    waiting_for_reply_comment_text = State()
    waiting_for_verify_token = State()
    waiting_for_payment_token = State()
    waiting_for_course_link = State()
    waiting_for_channel_for_autolink = State()
    waiting_for_channel_for_course_post = State()
    waiting_for_course_price = State()
    waiting_for_course_title = State()
    waiting_for_course_start_msg = State()
    waiting_for_course_photo = State()

# --- Постоянная клавиатура снизу (Reply Keyboard) для Админа ---
def get_admin_reply_kb():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📝 Текст приветствия"), KeyboardButton(text="🖼 Фото обложки")],
            [KeyboardButton(text="🏷 Название курса"), KeyboardButton(text="💰 Цена курса")],
            [KeyboardButton(text="🔗 Ссылка на канал"), KeyboardButton(text="🪄 Автоссылка на канал")],
            [KeyboardButton(text="📤 Опубликовать курс в канал"), KeyboardButton(text="💳 Токен ЮKassa")],
            [KeyboardButton(text="🎯 Кодовое слово IG"), KeyboardButton(text="✉️ Текст Direct (IG)")],
            [KeyboardButton(text="💬 Ответ под комментом (IG)"), KeyboardButton(text="🔐 Verify Token (IG)")],
            [KeyboardButton(text="🔑 Instagram Token"), KeyboardButton(text="📋 Текущие настройки")],
            [KeyboardButton(text="📊 Статистика"), KeyboardButton(text="🗑 Удалить фото")],
            [KeyboardButton(text="📖 Инструкция"), KeyboardButton(text="❌ Закрыть панель")]
        ],
        resize_keyboard=True,
        is_persistent=True
    )

def get_cancel_reply_kb():
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="🔙 Отмена")]],
        resize_keyboard=True
    )

# --- Настройка кнопки Меню (Commands) слева снизу ---
async def setup_bot_commands(bot: Bot):
    # Общая команда для обычных пользователей
    await bot.set_my_commands([
        BotCommand(command="start", description="🚀 Главное меню / Оплата")
    ])

    # Персональное меню для Админа (кнопка слева снизу)
    if ADMIN_ID:
        try:
            await bot.set_my_commands(
                [
                    BotCommand(command="admin", description="⚙️ Панель управления"),
                    BotCommand(command="settings", description="📋 Посмотреть настройки"),
                    BotCommand(command="start", description="🚀 Перезапуск / Вид клиента")
                ],
                scope=BotCommandScopeChat(chat_id=ADMIN_ID)
            )
            logging.info(f"Персональное меню команд для ADMIN_ID ({ADMIN_ID}) успешно установлено.")
        except Exception as e:
            logging.error(f"Не удалось установить команды для админа: {e}")

# --- Обработчик отмены ввода ---
@dp.message(F.text == "🔙 Отмена")
async def cancel_handler(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer("Действие отменено.", reply_markup=get_admin_reply_kb())

# --- Клиентский запуск ---
@dp.message(CommandStart())
async def start_handler(message: types.Message):
    record_user(message.from_user.id)
    price = int(get_setting("course_price") or "299000")
    rubles = price // 100
    start_text = get_setting("course_start_message")
    photo_id = get_setting("course_photo_id")

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=f"💳 Купить ({rubles} ₽)", callback_data="buy_course")]
        ]
    )

    if photo_id:
        try:
            await message.answer_photo(
                photo=photo_id,
                caption=start_text,
                reply_markup=kb,
                parse_mode="HTML"
            )
            return
        except Exception as e:
            # Либо не удалось отправить само фото, либо текст приветствия сломал
            # HTML-разметку (незакрытый тег) — пробуем без форматирования,
            # чтобы покупатель в любом случае увидел кнопку оплаты.
            logging.error(f"Не удалось отправить фото с приветствием: {e}")
            try:
                await message.answer_photo(photo=photo_id, caption=strip_html(start_text), reply_markup=kb)
                return
            except Exception as e2:
                logging.error(f"Не удалось отправить фото даже без форматирования: {e2}")

    try:
        await message.answer(
            start_text,
            reply_markup=kb,
            parse_mode="HTML",
            disable_web_page_preview=True
        )
    except Exception as e:
        logging.error(f"Не удалось отправить приветствие с HTML-разметкой: {e}")
        await message.answer(strip_html(start_text), reply_markup=kb, disable_web_page_preview=True)

# --- Команда /admin и /settings из меню слева ---
@dp.message(Command("admin"))
async def admin_command(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        await message.answer("⛔️ Доступ запрещен.")
        return
    try:
        await message.answer(
            "👋 <b>Добро пожаловать, администратор!</b>\n\n"
            "⚙️ Панель управления воронкой открыта — кнопки внизу экрана 👇\n"
            "Также вы можете открывать команды через синюю кнопку «Меню» слева.\n\n"
            "Ниже сразу пришлю инструкцию по настройке — актуальна и при первом запуске, "
            "и как справочник на будущее (её же можно вызвать кнопкой <b>📖 Инструкция</b>).",
            reply_markup=get_admin_reply_kb(),
            parse_mode="HTML"
        )
    except Exception as e:
        logging.error(f"Не удалось отправить приветствие админа с HTML-разметкой: {e}")
        await message.answer(
            "👋 Добро пожаловать, администратор! Панель управления открыта — кнопки внизу.",
            reply_markup=get_admin_reply_kb()
        )
    await send_setup_instructions(message)

@dp.message(Command("settings"))
async def settings_command(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await show_settings_text(message)

# --- Обработчики кнопок нижней клавиатуры ---
@dp.message(F.text == "❌ Закрыть панель")
async def close_admin(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Панель с кнопками скрыта.\n\nЧтобы открыть её снова, нажмите синюю кнопку «Меню» в левом нижнем углу и выберите <b>⚙️ Панель управления</b>.",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode="HTML"
    )

@dp.message(F.text == "📋 Текущие настройки")
async def show_settings_text(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    token = get_setting("page_access_token")
    hidden_token = f"{token[:10]}...{token[-5:]}" if len(token) > 15 else (token or "Не задан")

    expires_at = get_setting("page_access_token_expires_at")
    if not token:
        token_status_line = ""
    elif expires_at:
        try:
            expires_dt = datetime.fromtimestamp(int(expires_at))
            days_left = (int(expires_at) - int(time.time())) // 86400
            token_status_line = f"⏳ <b>Токен истекает:</b> {expires_dt.strftime('%d.%m.%Y')} (~{days_left} дн., продлевается автоматически)\n"
        except (ValueError, OSError):
            token_status_line = ""
    elif IG_APP_ID and IG_APP_SECRET:
        token_status_line = "⏳ <b>Токен истекает:</b> неизвестно — введите токен заново, чтобы включить автопродление\n"
    else:
        token_status_line = "⏳ <b>Токен истекает:</b> автопродление выключено (нет IG_APP_ID/IG_APP_SECRET)\n"

    price = int(get_setting("course_price") or "299000") // 100
    photo_status = "Установлено ✅" if get_setting("course_photo_id") else "Отсутствует (только текст) ❌"

    # Все значения ниже — свободный текст, который вводит админ (или который приходит
    # из Instagram/Meta), поэтому обязательно экранируем перед вставкой в HTML-разметку —
    # иначе случайный символ <, > или & в тексте сломает всё сообщение.
    e = html.escape
    info = (
        "📋 <b>Текущие настройки системы:</b>\n\n"
        f"🏷 <b>Название курса:</b> {e(get_setting('course_title'))}\n"
        f"💰 <b>Цена:</b> {price} ₽\n"
        f"🖼 <b>Фото обложки:</b> {photo_status}\n"
        f"🔗 <b>Ссылка на канал:</b> <code>{e(get_setting('course_link'))}</code>\n\n"
        f"📝 <b>Текст /start:</b>\n---\n{e(get_setting('course_start_message'))}\n---\n\n"
        f"🎯 <b>Кодовое слово IG:</b> <code>{e(get_setting('trigger_word'))}</code>\n"
        f"✉️ <b>Текст в Direct (IG):</b>\n<i>{e(get_setting('dm_text'))}</i>\n\n"
        f"💬 <b>Ответ под комментарием (IG):</b>\n<i>{e(get_setting('reply_comment_text'))}</i>\n\n"
        f"🔐 <b>Verify Token (для настройки вебхука в Meta):</b>\n<code>{e(get_setting('verify_token'))}</code>\n\n"
        f"🔑 <b>Instagram Page Access Token:</b> <code>{e(hidden_token)}</code>\n"
        f"{token_status_line}"
        f"💳 <b>ЮKassa Token:</b> <code>{'Настроен' if get_setting('payment_token') else 'Не настроен'}</code>"
    )
    try:
        await message.answer(info, reply_markup=get_admin_reply_kb(), parse_mode="HTML", disable_web_page_preview=True)
    except Exception as ex:
        logging.error(f"Не удалось отправить настройки с HTML-разметкой: {ex}")
        await message.answer(strip_html(info), reply_markup=get_admin_reply_kb(), disable_web_page_preview=True)

@dp.message(F.text == "📊 Статистика")
async def show_stats(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    stats = get_stats()
    users_count = stats["users_count"]
    purchases_count = stats["purchases_count"]
    revenue = stats["revenue_kopecks"] // 100
    conversion = (purchases_count / users_count * 100) if users_count else 0

    info = (
        "📊 <b>Статистика бота</b>\n\n"
        f"👥 <b>Пользователей всего:</b> {users_count}\n"
        f"💰 <b>Покупок:</b> {purchases_count}\n"
        f"📈 <b>Конверсия в покупку:</b> {conversion:.1f}%\n"
        f"💵 <b>Выручка (через ЮKassa):</b> {revenue} ₽"
    )
    try:
        await message.answer(info, reply_markup=get_admin_reply_kb(), parse_mode="HTML")
    except Exception as e:
        logging.error(f"Не удалось отправить статистику с HTML-разметкой: {e}")
        await message.answer(strip_html(info), reply_markup=get_admin_reply_kb())

@dp.message(F.text == "📖 Инструкция")
async def show_instructions(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    await send_setup_instructions(message)
    await message.answer("Готово 👆", reply_markup=get_admin_reply_kb())

async def send_setup_instructions(message: types.Message):
    verify_token = html.escape(get_setting("verify_token") or "(не задан)")

    part1 = (
        "📖 <b>Инструкция: настройка Instagram (Meta Graph API)</b>\n\n"
        "<b>1. Создайте приложение</b>\n"
        "developers.facebook.com/apps → тип <b>Business</b>.\n\n"
        "<b>2. Добавьте продукт Webhooks</b>\n"
        "В приложении: <b>Добавить продукты → Webhooks → Настроить</b>, объект <b>Instagram</b>.\n\n"
        "<b>3. Укажите в настройках вебхука:</b>\n"
        "• Callback URL: <code>https://ВАШ_ДОМЕН/webhook</code>\n"
        f"• Verify Token: <code>{verify_token}</code>\n"
        "(по умолчанию в боте стоит <code>0000</code> — просто скопируйте текущее значение выше "
        "и вставьте его в Meta один в один; при желании смените его кнопкой "
        "<b>🔐 Verify Token (IG)</b>)\n\n"
        "<b>4. Подпишитесь на поле</b> <code>comments</code>.\n\n"
        "<b>5. App Secret и App ID</b>\n"
        "Settings → Basic → скопируйте <b>App Secret</b> и <b>App ID</b>, укажите их в переменных "
        "окружения хостинга как <code>IG_APP_SECRET</code> и <code>IG_APP_ID</code> (нужны для "
        "проверки подписи вебхуков и автопродления токена)."
    )

    part2 = (
        "<b>6. Получите Page Access Token</b>\n"
        "Через Graph API Explorer, для страницы, привязанной к вашему Instagram, с правами:\n"
        "<code>instagram_basic</code>, <code>instagram_manage_comments</code>, "
        "<code>instagram_manage_messages</code>, <code>pages_show_list</code>, "
        "<code>pages_messaging</code>.\n"
        "Вставьте его кнопкой <b>🔑 Instagram Token</b> — бот сам продлит его и будет "
        "поддерживать актуальным (если заданы <code>IG_APP_ID</code>/<code>IG_APP_SECRET</code>).\n\n"
        "<b>7. Оплата (ЮKassa через Telegram)</b>\n"
        "<code>@BotFather</code> → <code>/mybots</code> → выбрать бота → <b>Payments</b> → выбрать "
        "провайдера ЮKassa (для теста — «ЮKassa (RUB) TEST»). Полученный provider_token вставьте "
        "кнопкой <b>💳 Токен ЮKassa</b>.\n\n"
        "<b>8. Остальные настройки</b> — название и цена курса, ссылка на канал "
        "(<code>https://t.me/...</code>), текст приветствия, кодовое слово и тексты для Instagram — "
        "всё меняется кнопками ниже, без перезапуска бота.\n\n"
        "<b>9. Важно про хранение данных.</b> Если переменная <code>DATABASE_URL</code> не задана, "
        "все настройки хранятся в локальном файле и могут слетать при рестарте хостинга. "
        "Подключите бесплатный Postgres (Neon.tech/Supabase) и укажите его в "
        "<code>DATABASE_URL</code> — подробности в README проекта.\n\n"
        "Текущее состояние всех настроек — кнопка <b>📋 Текущие настройки</b>."
    )

    for text in (part1, part2):
        try:
            await message.answer(text, parse_mode="HTML", disable_web_page_preview=True)
        except Exception as e:
            logging.error(f"Не удалось отправить инструкцию с HTML-разметкой: {e}")
            await message.answer(strip_html(text), disable_web_page_preview=True)

@dp.message(F.text == "📝 Текст приветствия")
async def set_start_msg_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_course_start_msg)
    await message.answer(
        "Отправьте в чат новый <b>текст приветственного сообщения</b> (/start). "
        "Для форматирования используйте HTML-теги: <code>&lt;b&gt;жирный&lt;/b&gt;</code>, "
        "<code>&lt;i&gt;курсив&lt;/i&gt;</code> — обычный текст можно писать как есть.",
        reply_markup=get_cancel_reply_kb(),
        parse_mode="HTML"
    )

@dp.message(F.text == "🖼 Фото обложки")
async def set_photo_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_course_photo)
    await message.answer("📸 <b>Отправьте изображение в этот чат</b> (как обычное фото), и оно станет обложкой:", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

@dp.message(F.text == "🗑 Удалить фото")
async def delete_photo_btn(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return
    set_setting("course_photo_id", "")
    await message.answer("🗑 Фото удалено. Теперь бот будет отправлять только текстовое сообщение.", reply_markup=get_admin_reply_kb())

@dp.message(F.text == "🏷 Название курса")
async def set_title_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_course_title)
    await message.answer("Отправьте <b>название курса/продукта</b>:", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

@dp.message(F.text == "💰 Цена курса")
async def set_price_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_course_price)
    await message.answer("Укажите цену курса в рублях (например: <code>2990</code>):", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

@dp.message(F.text == "🔗 Ссылка на канал")
async def set_link_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_course_link)
    await message.answer("Отправьте <b>ссылку на закрытый канал/материалы</b>:", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

@dp.message(F.text == "🪄 Автоссылка на канал")
async def set_channel_autolink_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_channel_for_autolink)
    await message.answer(
        "Отправьте <b>юзернейм канала</b> (например <code>@my_channel</code>) или его "
        "<b>числовой ID</b> (например <code>-1001234567890</code>) — бот должен уже быть "
        "добавлен в этот канал администратором с правом «Приглашать пользователей по ссылке».\n\n"
        "Если у канала нет юзернейма — узнать числовой ID можно, переслав любое "
        "сообщение из канала боту <code>@userinfobot</code>.",
        reply_markup=get_cancel_reply_kb(),
        parse_mode="HTML"
    )

@dp.message(AdminStates.waiting_for_channel_for_autolink, F.text)
async def process_channel_autolink_input(msg: types.Message, state: FSMContext):
    chat_ref = msg.text.strip()
    await state.clear()
    try:
        invite = await bot.create_chat_invite_link(chat_id=chat_ref, name="Автоворонка — доступ к курсу")
        set_setting("course_link", invite.invite_link)
        await msg.answer(
            f"✅ Ссылка создана автоматически и сохранена как ссылка на курс:\n<code>{html.escape(invite.invite_link)}</code>",
            reply_markup=get_admin_reply_kb(),
            parse_mode="HTML"
        )
    except Exception as e:
        logging.error(f"Не удалось создать ссылку-приглашение для {chat_ref}: {e}")
        await msg.answer(
            "❌ Не удалось создать ссылку. Проверьте:\n"
            "1) бот добавлен в канал именно администратором;\n"
            "2) у бота включено право «Приглашать пользователей по ссылке» (Invite Users via Link);\n"
            "3) юзернейм/ID указан верно, с <code>@</code> или в формате <code>-100...</code>.\n\n"
            f"Текст ошибки от Telegram: <code>{html.escape(str(e))}</code>",
            reply_markup=get_admin_reply_kb(),
            parse_mode="HTML"
        )

def get_course_posts() -> list:
    """Материалы курса «ИИ-Ремесло», разбитые на посты для канала."""
    return [
        (
            "🪶 <b>ИИ-Ремесло</b>\n"
            "Курс: заработок на нейросетях и ИИ\n\n"
            "3 модуля, 9 уроков — без воды. Дальше по порядку пойдут посты с материалами."
        ),
        (
            "<b>Модуль 1 — Карта возможностей</b>\n"
            "Прежде чем выбирать инструмент, стоит понять сам рынок.\n\n"
            "<b>Урок 1.1 — Четыре модели заработка на нейросетях</b>\n"
            "1) Услуги на фрилансе — вы выполняете задачи заказчика с помощью нейросетей быстрее и дешевле.\n"
            "2) Продажа готового контента — генерируете заранее и продаёте многократно.\n"
            "3) Автоматизация под ключ — собираете рабочие связки (боты, воронки) для бизнеса.\n"
            "4) Обучение и консалтинг — учите других тому, что уже освоили сами.\n"
            "Начинать разумнее с 1 и 2 — низкий порог входа, быстрая обратная связь от рынка.\n\n"
            "<b>Урок 1.2 — Инструменты для старта</b>\n"
            "• ChatGPT / Claude — тексты, структура, код\n"
            "• Midjourney — изображения высокого качества\n"
            "• ElevenLabs — синтез и клонирование голоса\n"
            "• CapCut — быстрый монтаж коротких видео\n\n"
            "<b>Урок 1.3 — Как выбрать нишу за вечер</b>\n"
            "Отметьте для себя: делали что-то похожее руками? готовы показывать результат публично? "
            "видите минимум трёх конкурентов, которые на этом зарабатывают? можете показать первый "
            "результат за 1–2 дня? Ниша с наибольшим числом «да» — та, с которой стоит начинать."
        ),
        (
            "<b>Модуль 2 — Ремесло формулировок</b>\n"
            "Промпт-инжиниринг — это навык точно формулировать задачу, и он продаётся так же, "
            "как копирайтинг или дизайн.\n\n"
            "<b>Урок 2.1 — Анатомия рабочего промпта</b>\n"
            "Пять частей: Роль (кем выступает нейросеть) → Контекст (для кого и зачем) → "
            "Задача (что именно сделать) → Формат (в каком виде нужен ответ) → Ограничения "
            "(чего избегать).\n\n"
            "Пример каркаса:\n"
            "<pre>Роль: ты — опытный копирайтер маркетплейсов.\n"
            "Контекст: карточка товара, ниша — детские рюкзаки.\n"
            "Задача: продающее описание из трёх абзацев.\n"
            "Формат: заголовок + абзац о выгодах + список характеристик.\n"
            "Ограничения: без превосходных степеней, без воды.</pre>\n\n"
            "<b>Урок 2.2 — Где брать первые заказы</b>\n"
            "• Kwork — проще всего получить первый заказ и отзыв\n"
            "• FL.ru — заказчики с более крупным бюджетом\n"
            "• Upwork / Fiverr — заказчики из-за рубежа, оплата в валюте\n"
            "Сделайте 3–5 демо-кейсов заранее — портфолио решает.\n\n"
            "<b>Урок 2.3 — Как не продешевить</b>\n"
            "Клиент платит не за минуты работы, а за результат. Ориентируйтесь на цену "
            "альтернативы без ИИ и ставьте на 30–50% ниже, поднимая цену с каждым отзывом."
        ),
        (
            "<b>Модуль 3 — Конвейер контента</b>\n"
            "Вторая модель заработка — не под заказ, а впрок: генерировать контент заранее "
            "и продавать многократно.\n\n"
            "<b>Урок 3.1 — Форматы, которые продаются</b>\n"
            "ИИ-изображения для стоков, digital-продукты (планировщики, шаблоны), "
            "короткие видео для Reels/Shorts пачками, тексты про запас (посты, рассылки).\n\n"
            "<b>Урок 3.2 — От генерации до продажи</b>\n"
            "• Adobe Stock — принимает ИИ-изображения при маркировке по их правилам\n"
            "• Etsy — digital-товары: шаблоны, планировщики, принты\n"
            "• Свой Telegram-канал — прямые продажи без комиссии площадки\n\n"
            "<b>Урок 3.3 — Как поставить на автомат</b>\n"
            "Ручная продажа в директ не масштабируется. Решение — автоворонка: комментарий с "
            "кодовым словом в Instagram → сообщение в Direct → оплата в Telegram → выдача доступа. "
            "Кстати, вы прямо сейчас находитесь внутри именно такой автоворонки — этот бот и есть "
            "рабочий пример."
        ),
        (
            "<b>Итог — набор на первую неделю</b>\n\n"
            "✅ Выбрана ниша по чек-листу из урока 1.3\n"
            "✅ Установлен один текстовый и один визуальный инструмент\n"
            "✅ Собран каркас промпта под свою нишу\n"
            "✅ Заведён профиль на Kwork или FL.ru с 3–5 демо-работами\n"
            "✅ Выбран один формат для контента впрок\n\n"
            "Курс не заканчивается на чтении — возвращайтесь к промптам из урока 2.1 при каждом "
            "новом заказе и адаптируйте их под свою нишу."
        ),
    ]

@dp.message(F.text == "📤 Опубликовать курс в канал")
async def publish_course_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_channel_for_course_post)
    await message.answer(
        "Отправьте <b>юзернейм канала</b> (например <code>@my_channel</code>) или его "
        "<b>числовой ID</b> (например <code>-1001234567890</code>) — бот должен быть добавлен "
        "туда администратором с правом публиковать сообщения. Материалы курса «ИИ-Ремесло» "
        "уйдут туда серией постов.",
        reply_markup=get_cancel_reply_kb(),
        parse_mode="HTML"
    )

@dp.message(AdminStates.waiting_for_channel_for_course_post, F.text)
async def process_publish_course_input(msg: types.Message, state: FSMContext):
    chat_ref = msg.text.strip()
    await state.clear()
    posts = get_course_posts()
    sent, failed = 0, 0
    for text in posts:
        try:
            await bot.send_message(chat_id=chat_ref, text=text, parse_mode="HTML")
        except Exception as e:
            logging.error(f"Не удалось опубликовать пост курса в {chat_ref} с HTML-разметкой: {e}")
            try:
                await bot.send_message(chat_id=chat_ref, text=strip_html(text))
            except Exception as e2:
                logging.error(f"Не удалось опубликовать пост курса в {chat_ref} даже без разметки: {e2}")
                failed += 1
                continue
        sent += 1
        await asyncio.sleep(1)  # не спамим Telegram API постами подряд

    if failed:
        await msg.answer(
            f"⚠️ Опубликовано {sent} из {len(posts)} постов, {failed} не прошли.\n"
            "Проверьте, что бот — админ канала с правом публикации, и что юзернейм/ID верны.",
            reply_markup=get_admin_reply_kb()
        )
    else:
        await msg.answer(
            f"✅ Курс опубликован в канале — {sent} постов отправлено.",
            reply_markup=get_admin_reply_kb()
        )

@dp.message(F.text == "💳 Токен ЮKassa")
async def set_pay_token_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_payment_token)
    await message.answer("Отправьте <b>Payment Token</b> ЮKassa от BotFather:", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

@dp.message(F.text == "🎯 Кодовое слово IG")
async def set_trigger_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_trigger_word)
    await message.answer("Отправьте новое <b>кодовое слово</b> (например: КУРС):", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

@dp.message(F.text == "✉️ Текст Direct (IG)")
async def set_dm_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_dm_text)
    await message.answer(
        "Отправьте новый <b>текст личного сообщения (Direct)</b>, "
        "которое бот пришлёт пользователю Instagram по кодовому слову:",
        reply_markup=get_cancel_reply_kb(),
        parse_mode="HTML"
    )

@dp.message(F.text == "💬 Ответ под комментом (IG)")
async def set_reply_comment_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_reply_comment_text)
    await message.answer(
        "Отправьте новый <b>текст публичного ответа под комментарием</b> в Instagram "
        "(его увидят все, кто зайдёт на пост). Отправьте <code>-</code> (дефис), чтобы бот не отвечал под комментарием вообще:",
        reply_markup=get_cancel_reply_kb(),
        parse_mode="HTML"
    )

@dp.message(F.text == "🔐 Verify Token (IG)")
async def set_verify_token_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_verify_token)
    await message.answer(
        "Отправьте новый <b>Verify Token</b>. Это произвольная строка (пароль), "
        "которую нужно будет один в один указать в настройках вебхука в Meta for Developers:",
        reply_markup=get_cancel_reply_kb(),
        parse_mode="HTML"
    )

@dp.message(F.text == "🔑 Instagram Token")
async def set_ig_token_btn(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_for_page_token)
    await message.answer("Отправьте <b>Instagram Page Access Token</b> от Meta Developers:", reply_markup=get_cancel_reply_kb(), parse_mode="HTML")

# --- Обработка FSM ввода ---
@dp.message(AdminStates.waiting_for_course_photo, F.photo)
async def process_photo_input(msg: types.Message, state: FSMContext):
    file_id = msg.photo[-1].file_id
    set_setting("course_photo_id", file_id)
    await state.clear()
    await msg.answer("✅ Фото обложки успешно обновлено!", reply_markup=get_admin_reply_kb())

@dp.message(AdminStates.waiting_for_course_photo)
async def process_photo_input_wrong_type(msg: types.Message):
    await msg.answer(
        "⚠️ Здесь нужно отправить именно фото (как изображение, не файлом). "
        "Попробуйте ещё раз или нажмите «🔙 Отмена».",
        reply_markup=get_cancel_reply_kb()
    )

@dp.message(AdminStates.waiting_for_course_start_msg, F.text)
async def process_start_msg_input(msg: types.Message, state: FSMContext):
    set_setting("course_start_message", msg.text)
    await state.clear()
    await msg.answer("✅ Текст приветствия <code>/start</code> успешно обновлен!", reply_markup=get_admin_reply_kb(), parse_mode="HTML")

@dp.message(AdminStates.waiting_for_course_title, F.text)
async def process_title_input(msg: types.Message, state: FSMContext):
    title = msg.text.strip()
    set_setting("course_title", title)
    await state.clear()
    await msg.answer(f"✅ Название курса изменено на: <b>{html.escape(title)}</b>", reply_markup=get_admin_reply_kb(), parse_mode="HTML")

@dp.message(AdminStates.waiting_for_page_token, F.text)
async def process_page_token_input(msg: types.Message, state: FSMContext):
    raw_token = msg.text.strip()
    await state.clear()

    result = exchange_for_long_lived_token(raw_token)
    if result:
        long_token, expires_in = result
        set_setting("page_access_token", long_token)
        set_setting("page_access_token_expires_at", str(int(time.time()) + expires_in))
        days = expires_in // 86400
        await msg.answer(
            f"✅ Instagram Access Token сохранён и автоматически продлён "
            f"(действует ещё ~{days} дн.). Дальше бот будет продлевать его сам, "
            f"пока не истечёт полностью.",
            reply_markup=get_admin_reply_kb()
        )
        return

    set_setting("page_access_token", raw_token)
    set_setting("page_access_token_expires_at", "")
    if IG_APP_ID and IG_APP_SECRET:
        await msg.answer(
            "⚠️ Токен сохранён, но автоматически продлить его не удалось (Meta вернула ошибку — "
            "возможно, токен уже недействителен). Автопродление подключится, когда вставите рабочий токен.",
            reply_markup=get_admin_reply_kb()
        )
    else:
        await msg.answer(
            "✅ Instagram Access Token обновлен! ⚠️ Автопродление не работает — не заданы "
            "переменные окружения IG_APP_ID/IG_APP_SECRET, токен придётся обновлять вручную.",
            reply_markup=get_admin_reply_kb()
        )

@dp.message(AdminStates.waiting_for_trigger_word, F.text)
async def process_trigger_input(msg: types.Message, state: FSMContext):
    trigger = msg.text.strip().upper()
    set_setting("trigger_word", trigger)
    await state.clear()
    await msg.answer(f"✅ Кодовое слово изменено на: <b>{html.escape(trigger)}</b>", reply_markup=get_admin_reply_kb(), parse_mode="HTML")

@dp.message(AdminStates.waiting_for_dm_text, F.text)
async def process_dm_input(msg: types.Message, state: FSMContext):
    set_setting("dm_text", msg.text.strip())
    await state.clear()
    await msg.answer("✅ Текст сообщения в Direct (IG) обновлен!", reply_markup=get_admin_reply_kb())

@dp.message(AdminStates.waiting_for_reply_comment_text, F.text)
async def process_reply_comment_input(msg: types.Message, state: FSMContext):
    value = msg.text.strip()
    set_setting("reply_comment_text", "" if value == "-" else value)
    await state.clear()
    if value == "-":
        await msg.answer("✅ Публичный ответ под комментарием отключен (бот будет только отправлять Direct).", reply_markup=get_admin_reply_kb())
    else:
        await msg.answer("✅ Текст ответа под комментарием (IG) обновлен!", reply_markup=get_admin_reply_kb())

@dp.message(AdminStates.waiting_for_verify_token, F.text)
async def process_verify_token_input(msg: types.Message, state: FSMContext):
    set_setting("verify_token", msg.text.strip())
    await state.clear()
    await msg.answer(
        "✅ Verify Token обновлен! Не забудьте указать точно такое же значение "
        "в настройках вебхука вашего приложения в Meta for Developers.",
        reply_markup=get_admin_reply_kb()
    )

@dp.message(AdminStates.waiting_for_payment_token, F.text)
async def process_payment_tok_input(msg: types.Message, state: FSMContext):
    set_setting("payment_token", msg.text.strip())
    await state.clear()
    await msg.answer("✅ Токен ЮKassa сохранен!", reply_markup=get_admin_reply_kb())

@dp.message(AdminStates.waiting_for_course_link, F.text)
async def process_link_input(msg: types.Message, state: FSMContext):
    set_setting("course_link", msg.text.strip())
    await state.clear()
    await msg.answer("✅ Ссылка на канал сохранена!", reply_markup=get_admin_reply_kb())

@dp.message(AdminStates.waiting_for_course_price, F.text)
async def process_price_input(msg: types.Message, state: FSMContext):
    try:
        rubles = int(msg.text.strip())
        set_setting("course_price", str(rubles * 100))
        await state.clear()
        await msg.answer(f"✅ Новая цена установлена: <b>{rubles} ₽</b>", reply_markup=get_admin_reply_kb(), parse_mode="HTML")
    except ValueError:
        await msg.answer("❌ Введите корректное число (только цифры).")

# Если админ в режиме ввода текста прислал что-то другое (фото, стикер, голосовое) —
# раньше это молча портило настройку (сохранялось пустое значение). Теперь просто просим
# прислать текст, ничего не меняя.
@dp.message(StateFilter(
    AdminStates.waiting_for_course_start_msg,
    AdminStates.waiting_for_course_title,
    AdminStates.waiting_for_page_token,
    AdminStates.waiting_for_trigger_word,
    AdminStates.waiting_for_dm_text,
    AdminStates.waiting_for_reply_comment_text,
    AdminStates.waiting_for_verify_token,
    AdminStates.waiting_for_payment_token,
    AdminStates.waiting_for_course_link,
    AdminStates.waiting_for_course_price,
    AdminStates.waiting_for_channel_for_autolink,
    AdminStates.waiting_for_channel_for_course_post,
))
async def process_text_state_wrong_type(msg: types.Message):
    await msg.answer(
        "⚠️ Здесь нужно текстовое сообщение, а не фото/файл/стикер/голосовое. "
        "Отправьте текст ещё раз или нажмите «🔙 Отмена».",
        reply_markup=get_cancel_reply_kb()
    )

# --- Оплата ЮKassa в Telegram ---
@dp.callback_query(F.data == "buy_course")
async def send_invoice(callback: types.CallbackQuery):
    p_token = get_setting("payment_token")
    if not p_token:
        await callback.message.answer("⚠️ Оплата временно недоступна (не настроен платежный токен).")
        await callback.answer()
        return

    price = int(get_setting("course_price") or "299000")
    title = get_setting("course_title") or "Курс по нейросетям"
    desc = get_setting("course_description") or "Доступ к материалам и урокам"

    try:
        await bot.send_invoice(
            chat_id=callback.from_user.id,
            title=title,
            description=desc,
            payload="custom_course_payload",
            provider_token=p_token,
            currency="RUB",
            prices=[LabeledPrice(label=title, amount=price)],
            start_parameter="course-buy"
        )
    except Exception as e:
        logging.error(f"Не удалось создать счет на оплату: {e}")
        await callback.message.answer(
            "⚠️ Не удалось создать счет на оплату. Проверьте платежный токен ЮKassa в настройках "
            "или попробуйте позже."
        )
    await callback.answer()

@dp.pre_checkout_query()
async def process_pre_checkout(pre_checkout_query: PreCheckoutQuery):
    await bot.answer_pre_checkout_query(pre_checkout_query.id, ok=True)

@dp.message(F.successful_payment)
async def successful_payment(message: types.Message):
    record_purchase(message.from_user.id, message.successful_payment.total_amount)
    link = get_setting("course_link")

    # Ссылку в кликабельный HTML-формат <a href="url">текст</a> оборачиваем только если
    # это похоже на настоящий URL — иначе (например, если админ по ошибке ввёл "@username"
    # вместо "https://t.me/username") просто показываем её текстом, чтобы её можно было
    # хотя бы скопировать, а не терять сообщение целиком из-за ошибки разметки.
    if link.startswith("http://") or link.startswith("https://") or link.startswith("tg://"):
        link_line = f'👉 <a href="{html.escape(link, quote=True)}">Перейти к обучению</a>'
    else:
        link_line = f"👉 {html.escape(link)}" if link else "👉 (ссылка не настроена — обратитесь к администратору)"

    text = (
        f"🎉 <b>Оплата прошла успешно!</b>\n\n"
        f"Ваша персональная ссылка на материалы курса:\n{link_line}\n\n"
        f"Приятного изучения!"
    )
    try:
        await message.answer(text, parse_mode="HTML", disable_web_page_preview=True)
    except Exception as e:
        logging.error(f"Не удалось отправить сообщение об оплате с HTML-разметкой: {e}")
        await message.answer(strip_html(text), disable_web_page_preview=True)

# --- Сервер Flask (Вебхук Instagram) ---
@app.route("/", methods=["GET"])
def index():
    return "All-in-One Telegram + Instagram Engine is Live!", 200

@app.route("/webhook", methods=["GET"])
def verify_fb_webhook():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")
    expected_token = get_setting("verify_token")

    if mode == "subscribe" and token == expected_token:
        return challenge, 200
    return "Verification failed", 403

@app.route("/webhook", methods=["POST"])
def fb_webhook_event():
    # Проверка подписи запроса — защищает от поддельных вебхуков от кого угодно,
    # кто узнал публичный URL /webhook.
    if IG_APP_SECRET:
        signature_header = request.headers.get("X-Hub-Signature-256", "")
        if not verify_ig_signature(request.get_data(), signature_header):
            logging.warning("Отклонён webhook-запрос с неверной подписью X-Hub-Signature-256.")
            return "Invalid signature", 403

    data = request.get_json(silent=True) or {}
    if data.get("object") != "instagram":
        return "Not an instagram event", 404

    page_token = get_setting("page_access_token")
    trigger = get_setting("trigger_word").upper()
    dm_message = get_setting("dm_text")
    reply_comment = get_setting("reply_comment_text")

    if not page_token:
        logging.warning("Получено событие Instagram, но page_access_token не настроен — игнорирую.")
        return jsonify({"status": "ok"}), 200

    for entry in data.get("entry", []):
        for change in entry.get("changes", []):
            if change.get("field") != "comments":
                continue

            val = change.get("value", {})
            text = val.get("text", "") or ""
            comment_id = val.get("id")
            user_id = val.get("from", {}).get("id")

            # Защита от повторной обработки одного и того же комментария
            # (Meta может присылать событие повторно, если ответ 200 задержался).
            if _already_processed(comment_id):
                continue

            # Защита от "эха": собственный ответ бота под комментарием тоже приходит
            # как новое событие comments и не должен запускать бота повторно.
            if reply_comment and text.strip() == reply_comment.strip():
                continue

            if not user_id or trigger not in text.upper():
                continue

            try:
                resp = requests.post(
                    f"{GRAPH_API_URL}/me/messages",
                    params={"access_token": page_token},
                    json={"recipient": {"id": user_id}, "message": {"text": dm_message}},
                    timeout=10
                )
                if not resp.ok:
                    logging.error(f"Instagram DM не отправлен: {resp.status_code} {resp.text}")
            except requests.RequestException as e:
                logging.error(f"Ошибка отправки Instagram DM: {e}")

            if reply_comment and comment_id:
                try:
                    resp = requests.post(
                        f"{GRAPH_API_URL}/{comment_id}/replies",
                        params={"access_token": page_token, "message": reply_comment},
                        timeout=10
                    )
                    if not resp.ok:
                        logging.error(f"Ответ на комментарий не отправлен: {resp.status_code} {resp.text}")
                except requests.RequestException as e:
                    logging.error(f"Ошибка ответа на комментарий Instagram: {e}")

    return jsonify({"status": "ok"}), 200

def run_flask():
    app.run(host="0.0.0.0", port=PORT, use_reloader=False, threaded=True)

async def token_renewal_loop():
    """Раз в сутки проверяет срок действия Instagram-токена и продлевает его заранее,
    если до истечения осталось меньше TOKEN_RENEW_THRESHOLD секунд."""
    while True:
        await asyncio.sleep(TOKEN_RENEW_CHECK_INTERVAL)
        try:
            token = get_setting("page_access_token")
            expires_at = get_setting("page_access_token_expires_at")
            if not token or not expires_at or not (IG_APP_ID and IG_APP_SECRET):
                continue

            remaining = int(expires_at) - int(time.time())
            if remaining > TOKEN_RENEW_THRESHOLD:
                continue

            result = exchange_for_long_lived_token(token)
            if result:
                new_token, expires_in = result
                set_setting("page_access_token", new_token)
                set_setting("page_access_token_expires_at", str(int(time.time()) + expires_in))
                logging.info(f"Instagram Access Token автоматически продлён ещё на {expires_in // 86400} дн.")
            else:
                logging.error("Не удалось автоматически продлить Instagram Access Token.")
                try:
                    await bot.send_message(
                        ADMIN_ID,
                        "⚠️ Не удалось автоматически продлить Instagram Access Token — "
                        "похоже, он уже недействителен. Получите новый в Meta for Developers "
                        "и обновите его кнопкой «🔑 Instagram Token» в /admin."
                    )
                except Exception as notify_err:
                    logging.error(f"Не удалось уведомить админа о просроченном токене: {notify_err}")
        except Exception as e:
            logging.error(f"Ошибка в фоновой задаче автопродления Instagram-токена: {e}")

async def main():
    # Настраиваем меню команд слева внизу
    await setup_bot_commands(bot)

    # Запуск Flask сервера в отдельном потоке
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()
    logging.info(f"Flask Webhook Server запущен на порту {PORT}")

    # Фоновая задача автопродления Instagram-токена
    asyncio.create_task(token_renewal_loop())

    # Запуск Telegram бота
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
