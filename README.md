# NOVA Messenger — starter MVP

پیام‌رسان فارسی RTL با طراحی تیره/بنفش، PWA، بک‌اند FastAPI، SQLite، ورود با کد یک‌بارمصرف، چت خصوصی متنی و WebSocket برای دریافت زنده پیام.

## وضعیت نسخه
این یک MVP قابل اجراست، نه محصول آماده انتشار عمومی. در حالت آزمایشی کد ورود در لاگ سرور چاپ می‌شود. پیش از انتشار عمومی، ارسال SMS واقعی، دیتابیس پایدار، محدودیت نرخ مشترک، HTTPS و بررسی امنیتی لازم است. SQLite در فایل‌سیستم موقت میزبان ممکن است با راه‌اندازی مجدد پاک شود.

## اجرای محلی
Python 3.11+:
```bash
pip install -r requirements.txt
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export OTP_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DEV_OTP=true
uvicorn main:app --host 0.0.0.0 --port 8000
```
در اندروید می‌توانی از Termux استفاده کنی و مرورگر را به `http://127.0.0.1:8000` باز کنی. کد آزمایشی را در لاگ سرور پیدا کن.

## استقرار آزمایشی
مخزن را به سرویس میزبانی متصل کن و متغیرهای محیطی را در پنل سرویس تنظیم کن. فایل `render.yaml` فقط پیکربندی آزمایشی است. پلن رایگان ممکن است بخوابد و SQLite محلی تضمین پایداری ندارد؛ برای استفاده واقعی PostgreSQL مدیریت‌شده و backup لازم است.

## پیامک واقعی (Twilio)
متغیرها: `SMS_PROVIDER=twilio`, `DEV_OTP=false`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`. کلیدها را در GitHub قرار نده.

## ویژگی‌های موجود
- درخواست و تأیید کد یک‌بارمصرف با انقضای ۵ دقیقه‌ای و هش HMAC
- JWT، ویرایش نام نمایشی، جست‌وجوی کاربران و فهرست گفتگوها
- پیام متنی خصوصی و WebSocket برای پیام زنده
- رابط واکنش‌گرا و manifest نصب‌شدنی

## پیش از انتشار عمومی
- انتقال SQLite به PostgreSQL و تنظیم backup/restore
- محدودسازی نرخ مشترک با Redis، محدودیت IP و ضدسوءاستفاده برای OTP
- تست امنیتی، سیاست حریم خصوصی، گزارش/مسدودسازی، حذف حساب و لغو نشست
- JWT فعلی در localStorage نگه‌داری می‌شود؛ برای محصول حساس، معماری نشست امن را بررسی کن
- رمزنگاری سرتاسری، تماس صوتی/تصویری، رسانه و Push هنوز پیاده نشده‌اند
- PWA نصب‌شدنی است؛ APK بومی مرحله جداگانه‌ای است

## APIهای اصلی
- `POST /api/auth/request-code` با `{"phone":"+989121234567"}`
- `POST /api/auth/verify` با `{"phone":"+989121234567","code":"123456"}`
- `GET /api/me`, `PATCH /api/me`
- `GET /api/users?q=Ali`
- `GET /api/chats`
- `GET /api/messages/{peer_id}`
- `POST /api/messages` با `{"receiver_id":2,"body":"سلام"}`
- `WS /ws?token=...`
- `GET /health`
