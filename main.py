import os, re, time, hmac, hashlib, secrets, sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import jwt

ROOT = Path(__file__).resolve().parent
DB_PATH = os.getenv("DATABASE_PATH", str(ROOT / "nova.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "")
OTP_SECRET = os.getenv("OTP_SECRET", "")
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "168"))
DEV_OTP = os.getenv("DEV_OTP", "true").lower() == "true"
SMS_PROVIDER = os.getenv("SMS_PROVIDER", "console").lower()
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")
if not JWT_SECRET or len(JWT_SECRET) < 32:
    JWT_SECRET = secrets.token_urlsafe(48)
    print("WARNING: JWT_SECRET is not set/too short. A temporary key was generated; sessions will reset on restart.")
if not OTP_SECRET or len(OTP_SECRET) < 32:
    OTP_SECRET = secrets.token_urlsafe(48)
    print("WARNING: OTP_SECRET is not set/too short. OTPs will not survive restart.")
app = FastAPI(title="NOVA Messenger API", version="0.1.0")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
connections: dict[int, set[WebSocket]] = {}
otp_attempts: dict[str, list[float]] = {}
verify_attempts: dict[str, list[float]] = {}

def db():
    con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con

def init_db():
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT UNIQUE NOT NULL,
          display_name TEXT NOT NULL DEFAULT 'کاربر NOVA',
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS otp_codes(
          phone TEXT PRIMARY KEY, digest TEXT NOT NULL, expires_at INTEGER NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages(
          id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER NOT NULL REFERENCES users(id),
          receiver_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
          created_at TEXT NOT NULL, read_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, id);
        """)
init_db()

def now_iso(): return datetime.now(timezone.utc).isoformat()
def normalize_phone(phone: str) -> str:
    p = re.sub(r"[\s()\-]", "", phone.strip())
    if p.startswith("00"): p = "+" + p[2:]
    if not re.fullmatch(r"\+[1-9]\d{7,14}", p):
        raise HTTPException(400, "شماره را با کد کشور وارد کن؛ مثال: +989121234567")
    return p

def limit(bucket: dict, key: str, maximum: int, window: int):
    now = time.time()
    vals = [t for t in bucket.get(key, []) if now-t < window]
    if len(vals) >= maximum:
        raise HTTPException(429, "تعداد درخواست زیاد است؛ کمی بعد دوباره امتحان کن.")
    vals.append(now); bucket[key] = vals

def otp_digest(phone, code):
    return hmac.new(OTP_SECRET.encode(), f"{phone}:{code}".encode(), hashlib.sha256).hexdigest()

async def send_sms(phone, code):
    if SMS_PROVIDER == "twilio":
        if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER]):
            raise HTTPException(503, "تنظیمات سرویس پیامک کامل نیست.")
        import httpx
        url=f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json"
        async with httpx.AsyncClient(timeout=15) as client:
            r=await client.post(url, auth=(TWILIO_ACCOUNT_SID,TWILIO_AUTH_TOKEN),
                data={"From":TWILIO_FROM_NUMBER,"To":phone,"Body":f"کد ورود NOVA: {code}"})
        if r.status_code >= 300:
            print("SMS provider error:", r.status_code, r.text[:200])
            raise HTTPException(502, "ارسال پیامک ناموفق بود؛ بعداً تلاش کن.")
    elif DEV_OTP:
        print(f"[NOVA DEV OTP] phone={phone} code={code} (development only)")
    else:
        raise HTTPException(503, "سرویس پیامک تنظیم نشده است.")

class RequestOTP(BaseModel):
    phone: str = Field(min_length=8, max_length=24)
class VerifyOTP(BaseModel):
    phone: str
    code: str = Field(min_length=6, max_length=6)
class ProfileUpdate(BaseModel):
    display_name: str = Field(min_length=2, max_length=40)
class SendMessage(BaseModel):
    receiver_id: int
    body: str = Field(min_length=1, max_length=4000)

def current_user(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "ابتدا وارد حساب شو.")
    try:
        payload=jwt.decode(authorization[7:], JWT_SECRET, algorithms=["HS256"])
        uid=int(payload["sub"])
    except Exception:
        raise HTTPException(401, "نشست نامعتبر یا منقضی شده است.")
    with db() as c: row=c.execute("SELECT id,phone,display_name,created_at FROM users WHERE id=?", (uid,)).fetchone()
    if not row: raise HTTPException(401, "حساب پیدا نشد.")
    return dict(row)

@app.get("/")
def home(): return FileResponse(ROOT / "static" / "index.html")
@app.get("/manifest.webmanifest")
def manifest(): return FileResponse(ROOT / "static" / "manifest.webmanifest", media_type="application/manifest+json")
@app.get("/health")
def health(): return {"ok": True, "service":"NOVA"}

@app.post("/api/auth/request-code")
async def request_code(data: RequestOTP):
    phone=normalize_phone(data.phone)
    limit(otp_attempts, phone, 3, 600)
    code=f"{secrets.randbelow(1_000_000):06d}"
    with db() as c:
        c.execute("INSERT INTO otp_codes(phone,digest,expires_at,attempts,created_at) VALUES(?,?,?,?,?) ON CONFLICT(phone) DO UPDATE SET digest=excluded.digest,expires_at=excluded.expires_at,attempts=0,created_at=excluded.created_at",
            (phone, otp_digest(phone,code), int(time.time())+300, 0, int(time.time())))
    await send_sms(phone, code)
    return {"ok":True, "message":"اگر شماره معتبر باشد، کد ورود ارسال می‌شود. کد تا ۵ دقیقه اعتبار دارد."}

@app.post("/api/auth/verify")
def verify(data: VerifyOTP):
    phone=normalize_phone(data.phone)
    limit(verify_attempts, phone, 8, 600)
    with db() as c:
        row=c.execute("SELECT * FROM otp_codes WHERE phone=?", (phone,)).fetchone()
        if not row or int(row["expires_at"]) < int(time.time()) or row["attempts"] >= 5:
            raise HTTPException(400, "کد منقضی شده یا وجود ندارد؛ کد تازه بگیر.")
        expected=otp_digest(phone, data.code)
        if not hmac.compare_digest(expected, row["digest"]):
            c.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE phone=?", (phone,))
            raise HTTPException(400, "کد تأیید اشتباه است.")
        c.execute("DELETE FROM otp_codes WHERE phone=?", (phone,))
        c.execute("INSERT OR IGNORE INTO users(phone,display_name,created_at) VALUES(?,?,?)", (phone,"کاربر NOVA",now_iso()))
        user=c.execute("SELECT id,phone,display_name,created_at FROM users WHERE phone=?", (phone,)).fetchone()
    token=jwt.encode({"sub":str(user["id"]),"exp":datetime.now(timezone.utc)+timedelta(hours=TOKEN_TTL_HOURS)}, JWT_SECRET, algorithm="HS256")
    return {"token":token,"user":dict(user)}

@app.get("/api/me")
def me(user=Depends(current_user)): return {"user":user}

@app.patch("/api/me")
def update_me(data: ProfileUpdate, user=Depends(current_user)):
    name=data.display_name.strip()
    if len(name)<2: raise HTTPException(400,"نام خیلی کوتاه است.")
    with db() as c:
        c.execute("UPDATE users SET display_name=? WHERE id=?", (name,user["id"]))
        row=c.execute("SELECT id,phone,display_name,created_at FROM users WHERE id=?", (user["id"],)).fetchone()
    return {"user":dict(row)}

@app.get("/api/users")
def search_users(q: str="", user=Depends(current_user)):
    q=q.strip()[:50]
    if len(q)<2: return {"users":[]}
    with db() as c:
        rows=c.execute("SELECT id,display_name FROM users WHERE id != ? AND display_name LIKE ? ORDER BY display_name LIMIT 30",
                       (user["id"], f"%{q.replace('%','')}%")).fetchall()
    return {"users":[dict(r) for r in rows]}

@app.get("/api/chats")
def chats(user=Depends(current_user)):
    with db() as c:
        rows=c.execute("""
          SELECT u.id AS user_id,u.display_name,
            m.body AS last_message,m.created_at AS last_at,
            (SELECT COUNT(*) FROM messages x WHERE x.sender_id=u.id AND x.receiver_id=? AND x.read_at IS NULL) AS unread
          FROM users u JOIN (
            SELECT CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END AS peer, MAX(id) AS mid
            FROM messages WHERE sender_id=? OR receiver_id=? GROUP BY peer
          ) p ON p.peer=u.id JOIN messages m ON m.id=p.mid
          WHERE u.id != ? ORDER BY m.id DESC
        """,(user["id"],user["id"],user["id"],user["id"],user["id"])).fetchall()
    return {"chats":[dict(r) for r in rows]}

@app.get("/api/messages/{peer_id}")
def get_messages(peer_id:int, before:int=0, user=Depends(current_user)):
    if peer_id==user["id"]: raise HTTPException(400,"شناسه گفتگو نامعتبر است.")
    with db() as c:
        peer=c.execute("SELECT id FROM users WHERE id=?", (peer_id,)).fetchone()
        if not peer: raise HTTPException(404,"کاربر پیدا نشد.")
        rows=c.execute("""SELECT id,sender_id,receiver_id,body,created_at,read_at FROM messages
          WHERE ((sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)) AND id>?
          ORDER BY id DESC LIMIT 100""",(user["id"],peer_id,peer_id,user["id"],before)).fetchall()
        c.execute("UPDATE messages SET read_at=? WHERE sender_id=? AND receiver_id=? AND read_at IS NULL",(now_iso(),peer_id,user["id"]))
    return {"messages":[dict(r) for r in reversed(rows)]}

@app.post("/api/messages")
async def send_message(data:SendMessage, user=Depends(current_user)):
    body=data.body.strip()
    if not body: raise HTTPException(400,"پیام خالی است.")
    if data.receiver_id==user["id"]: raise HTTPException(400,"نمی‌توانی به خودت پیام بدهی.")
    with db() as c:
        peer=c.execute("SELECT id FROM users WHERE id=?", (data.receiver_id,)).fetchone()
        if not peer: raise HTTPException(404,"گیرنده پیدا نشد؛ باید ابتدا ثبت‌نام کرده باشد.")
        cur=c.execute("INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)",
                      (user["id"],data.receiver_id,body,now_iso()))
        row=c.execute("SELECT id,sender_id,receiver_id,body,created_at,read_at FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()
    msg=dict(row)
    await broadcast(data.receiver_id, {"type":"message","message":msg})
    await broadcast(user["id"], {"type":"message","message":msg})
    return {"message":msg}

async def broadcast(uid, payload):
    dead=[]
    for ws in list(connections.get(uid,set())):
        try: await ws.send_json(payload)
        except Exception: dead.append(ws)
    for ws in dead: connections.get(uid,set()).discard(ws)

@app.websocket("/ws")
async def websocket_endpoint(ws:WebSocket, token:str=""):
    try:
        payload=jwt.decode(token,JWT_SECRET,algorithms=["HS256"])
        uid=int(payload["sub"])
    except Exception:
        await ws.close(code=1008); return
    await ws.accept()
    connections.setdefault(uid,set()).add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        connections.get(uid,set()).discard(ws)
