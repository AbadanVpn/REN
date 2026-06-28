import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

# ❌ بخش CUSTOM_ADDRESSES سراسری حذف شد و به داخل خود ساختار LINKS منتقل شد.

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

# --- هدرها و پیش‌نیازهای برنامه ---
@app.on_event("startup")
async def startup_event():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    asyncio.create_task(keep_alive())
    logger.info(f"REN started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown_event():
    if http_client:
        await http_client.aclose()

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- تابع‌های کمکی سیستم ---
async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token: return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
        except: pass

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None) -> str:
    domain = get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {
                "label": "Default", 
                "limit_bytes": 0, 
                "used_bytes": 0, 
                "max_connections": 0, 
                "created_at": datetime.now().isoformat(), 
                "active": True,
                "addresses": [] # آی‌پی‌های تمیز پیش‌فرض اینباند
            }

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

# --- روت‌های مدیریت نشست و رندر فرانت ---
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return LOGIN_HTML

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return DASHBOARD_HTML

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password") or "")) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

# --- APIهای مدیریت اینباندها (تغییر یافته بر اساس درخواست شما) ---

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name format invalid")
    
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    
    # 📥 دریافت آی‌پی‌های تمیز اختصاصی فرستاده شده از فرانت‌اند برای این اینباند
    raw_addresses = body.get("addresses") or []
    # تمیزکاری آرایه ورودی (حذف فاصله‌ها و رکوردهای خالی)
    clean_addresses = [str(addr).strip() for addr in raw_addresses if str(addr).strip()]

    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, 
            "limit_bytes": limit_bytes, 
            "used_bytes": 0, 
            "max_connections": max_conn, 
            "created_at": datetime.now().isoformat(), 
            "active": True,
            "addresses": clean_addresses # ذخیره اختصاصی داخل خود اینباند
        }
    return {"uuid": uid, "label": label, "ok": True}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "uuid": uid, 
                "label": data["label"], 
                "limit_bytes": data["limit_bytes"], 
                "used_bytes": data["used_bytes"], 
                "max_connections": data.get("max_connections", 0), 
                "active": data["active"], 
                "created_at": data["created_at"], 
                "current_connections": count_connections_for_link(uid), 
                "addresses": data.get("addresses", []), # برگرداندن آی‌پی‌های اختصاصی به فرانت‌اند
                "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}")
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "max_connections" in body:
            LINKS[uid]["max_connections"] = max(0, int(body["max_connections"] or 0))
        # 🔄 امکان آپدیت یا ویرایش آی‌پی‌های اختصاصی از بخش ویرایش اینباند
        if "addresses" in body:
            raw_addresses = body.get("addresses") or []
            LINKS[uid]["addresses"] = [str(addr).strip() for addr in raw_addresses if str(addr).strip()]
            
    return {"ok": True}

# --- خروجی کانفیگ سابسکریپشن بر اساس آی‌پی‌های اختصاصی هر اینباند ---
@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
            
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
        
    # 🎯 خواندن آی‌پی‌های اختصاصی تعریف‌شده برای همین اینباند به جای لیست عمومی قدیم
    addresses = link.get("addresses", [])
    
    sub_links = []
    # لینک اصلی سرور با آدرس دامنه پیش‌فرض
    server_link = generate_vless_link(uid, remark=f"REN-{link['label']}-Server")
    sub_links.append(server_link)
    
    # تولید لینک مجزا برای هر کدام از آی‌پی‌های تمیز اختصاصی این کاربر
    for i, addr in enumerate(addresses):
        remark = f"REN-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
        
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": f"attachment; filename=\"sub_{uid}.txt\"",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire=0"
    }
    return Response(content=encoded, headers=headers)

# ❌ بقیه متد‌های مدیریت آدرس‌های سراسری (مثل `POST /api/addresses` و `DELETE /api/addresses`) به دلیل یکپارچه‌شدن با خود ساختار اینباند حذف شدند.

# --- هسته اصلی WebSocket و پروکسی تانل (بدون تغییر منطق شما) ---
# ... [کدهای تانل VLESS و توابع مربوط به اتصالات مانند قبل باقی مانده‌اند] ...
