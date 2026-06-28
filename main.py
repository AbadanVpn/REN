import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
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

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

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

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

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
                "addresses": []
            }

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded: return forwarded.split(",")[0].strip()
    return websocket.client.host if websocket.client else "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try: await ws.close(code=1000, reason="link deleted")
            except: pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

# --- FastAPI Initialization ---
app = FastAPI(title="REN", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token: SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

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
    
    # تفکیک آدرس‌ها بر اساس خط یا ویرگول در اینباند
    raw_addresses = body.get("addresses") or ""
    if isinstance(raw_addresses, list):
        clean_addresses = [str(a).strip() for a in raw_addresses if str(a).strip()]
    else:
        clean_addresses = [str(a).strip() for a in re.split(r'[\n,]+', str(raw_addresses)) if str(a).strip()]

    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, 
            "limit_bytes": limit_bytes, 
            "used_bytes": 0, 
            "max_connections": max_conn, 
            "created_at": datetime.now().isoformat(), 
            "active": True,
            "addresses": clean_addresses
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
                "addresses": data.get("addresses", []),
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
        if "addresses" in body:
            raw_addresses = body.get("addresses") or ""
            if isinstance(raw_addresses, list):
                LINKS[uid]["addresses"] = [str(a).strip() for a in raw_addresses if str(a).strip()]
            else:
                LINKS[uid]["addresses"] = [str(a).strip() for a in re.split(r'[\n,]+', str(raw_addresses)) if str(a).strip()]
            
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
            
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
        
    addresses = link.get("addresses", [])
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"REN-{link['label']}-Server")
    sub_links.append(server_link)
    
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

# --- Core VLESS Tunneling ---
RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24: raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else: raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def check_quota(uid: str, extra_bytes: int) -> bool:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None: return False
        if not link["active"]: return False
        if link["limit_bytes"] == 0: return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]

async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS: LINKS[uid]["used_bytes"] += n

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size; stats["total_requests"] += 1
            if conn_id in connections: connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            writer.write(data); await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded"); break
            stats["total_bytes"] += size
            if conn_id in connections: connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            max_conn = link_data.get("max_connections", 0)
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                if count_connections_for_link(uuid) >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        size = len(first_chunk)
        stats["total_bytes"] += size; stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            stats["total_bytes"] += p_size
            connections[conn_id]["bytes"] += p_size
            hourly_traffic[datetime.now().strftime("%H:00")] += p_size
            await add_usage(uuid, p_size)
            writer.write(initial_payload); await writer.drain()
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    if not any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values()):
                        remove_ip_from_link(uid, ip)

# --- Full Web UI Templates ---
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>REN Gateway - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; margin: 0; padding: 0; }
        body { background: #0b0f19; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
        .card { background: #111827; border: 1px solid #1f2937; border-radius: 16px; padding: 40px; width: 100%; max-width: 420px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); }
        h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; color: #fff; text-align: center; letter-spacing: -0.5px; }
        p { color: #9ca3af; font-size: 14px; text-align: center; margin-bottom: 32px; }
        .group { margin-bottom: 24px; }
        label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 8px; color: #9ca3af; }
        input { width: 100%; background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 12px 16px; color: #fff; font-size: 15px; outline: none; transition: border 0.2s; }
        input:focus { border-color: #3b82f6; }
        button { width: 100%; background: #3b82f6; color: #fff; border: none; border-radius: 8px; padding: 12px; font-size: 15px; font-weight: 600; cursor: pointer; transition: background 0.2s; margin-top: 8px; }
        button:hover { background: #2563eb; }
        .error { color: #ef4444; font-size: 13px; text-align: center; margin-top: 16px; min-height: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>REN Gateway</h1>
        <p>Sign in to manage your core edge gateway</p>
        <div class="group">
            <label>Admin Password</label>
            <input type="password" id="pw" placeholder="••••••••" onkeydown="if(event.key==='Enter') login()">
        </div>
        <button onclick="login()">Sign In</button>
        <div class="error" id="err"></div>
    </div>
    <script>
        async function login() {
            const p = document.getElementById('pw').value;
            const err = document.getElementById('err');
            err.textContent = '';
            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({password: p})
                });
                const d = await res.json();
                if(res.ok && d.ok) { window.location.href = '/dashboard'; }
                else { err.textContent = d.detail || 'Login failed'; }
            } catch { err.textContent = 'Connection error'; }
        }
        window.onload = async () => {
            const res = await fetch('/api/me');
            const d = await res.json();
            if(d.authenticated) window.location.href = '/dashboard';
        };
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>REN Gateway - Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; font-family: 'Plus Jakarta Sans', sans-serif; margin: 0; padding: 0; }
        body { background: #0b0f19; color: #f3f4f6; padding: 40px 20px; min-height: 100vh; }
        .container { max-width: 1100px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 40px; }
        h1 { font-size: 26px; font-weight: 700; color: #fff; }
        .btn { background: #1f2937; color: #fff; border: 1px solid #374151; border-radius: 8px; padding: 8px 16px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s; text-decoration: none; display: inline-flex; align-items: center; }
        .btn:hover { background: #374151; }
        .btn-primary { background: #3b82f6; border-color: #3b82f6; }
        .btn-primary:hover { background: #2563eb; }
        .btn-danger { background: #ef4444; border-color: #ef4444; }
        .btn-danger:hover { background: #dc2626; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .stat-card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 24px; }
        .stat-label { font-size: 13px; color: #9ca3af; font-weight: 500; margin-bottom: 6px; }
        .stat-val { font-size: 24px; font-weight: 700; color: #fff; }

        .section { background: #111827; border: 1px solid #1f2937; border-radius: 14px; padding: 28px; margin-bottom: 30px; }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
        .section-title { font-size: 18px; font-weight: 600; color: #fff; }

        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; align-items: flex-end; }
        .form-group { display: flex; flex-direction: column; }
        .form-group label { font-size: 12px; font-weight: 500; color: #9ca3af; margin-bottom: 6px; }
        .form-group input, .form-group select { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 10px 14px; color: #fff; font-size: 14px; outline: none; }
        .form-group textarea { background: #1f2937; border: 1px solid #374151; border-radius: 8px; padding: 10px 14px; color: #fff; font-size: 14px; outline: none; resize: vertical; height: 41px; }

        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { font-size: 12px; text-transform: uppercase; color: #9ca3af; font-weight: 600; padding: 12px 16px; border-bottom: 1px solid #1f2937; }
        td { padding: 16px; border-bottom: 1px solid #1f2937; font-size: 14px; color: #e5e7eb; vertical-align: middle; }
        tr:last-child td { border-bottom: none; }
        
        .badge { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 9999px; font-size: 12px; font-weight: 500; }
        .badge-success { background: rgba(16,185,129,0.1); color: #10b981; }
        .badge-muted { background: rgba(156,163,175,0.1); color: #9ca3af; }

        .code-box { background: #1f2937; border: 1px solid #374151; padding: 6px 10px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #3b82f6; max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .actions { display: flex; gap: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>REN Management Console</h1>
            <button class="btn" onclick="logout()">Sign Out</button>
        </header>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-label">Active Connections</div><div class="stat-val" id="st-conn">0</div></div>
            <div class="stat-card"><div class="stat-label">Total Data Forwarded</div><div class="stat-val" id="st-data">0 MB</div></div>
            <div class="stat-card"><div class="stat-label">Total Requests</div><div class="stat-val" id="st-req">0</div></div>
            <div class="stat-card"><div class="stat-label">System Uptime</div><div class="stat-val" id="st-uptime">00:00:00</div></div>
        </div>

        <!-- Add Inbound Form -->
        <div class="section">
            <div class="section-title" style="margin-bottom:20px;">Add New Inbound Link</div>
            <div class="form-row">
                <div class="form-group">
                    <label>Name / Label</label>
                    <input type="text" id="ln-label" placeholder="e.g. User-A">
                </div>
                <div class="form-group">
                    <label>Data Limit</label>
                    <input type="number" id="ln-limit" value="0" min="0">
                </div>
                <div class="form-group">
                    <label>Unit</label>
                    <select id="ln-unit"><option>GB</option><option>MB</option></select>
                </div>
                <div class="form-group">
                    <label>Max Connections (0=unlimited)</label>
                    <input type="number" id="ln-conn" value="0" min="0">
                </div>
                <!-- 🎯 بخش آی‌پی تمیز اختصاصی به ازای هر اینباند اضافه شده در اینجا -->
                <div class="form-group">
                    <label>Clean IPs (Comma / New line separated)</label>
                    <textarea id="ln-ips" placeholder="104.16.0.1, clean.com"></textarea>
                </div>
                <button class="btn btn-primary" onclick="createLink()">Create Inbound</button>
            </div>
        </div>

        <!-- Inbound Links Table -->
        <div class="section" style="padding: 16px 0;">
            <div class="section-header" style="padding: 0 28px 12px 28px;">
                <div class="section-title">Inbound Connections</div>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Label</th>
                            <th>Status</th>
                            <th>Traffic (Used / Limit)</th>
                            <th>Active Conns</th>
                            <th>Clean IPs Count</th>
                            <th>Subscription Config</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="links-tbody"></tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function formatBytes(b) {
            if(b === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(b) / Math.log(k));
            return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        async function req(url, method='GET', body=null) {
            const opt = { method, headers: {} };
            if(body) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
            const res = await fetch(url, opt);
            if(res.status === 401) { window.location.href = '/login'; return null; }
            return res.json();
        }

        async function logout() {
            await fetch('/api/logout', {method: 'POST'});
            window.location.href = '/login';
        }

        async function loadStats() {
            const d = await req('/stats');
            if(!d) return;
            document.getElementById('st-conn').textContent = d.active_connections;
            document.getElementById('st-data').textContent = d.total_traffic_mb >= 1024 ? (d.total_traffic_mb/1024).toFixed(2)+' GB' : d.total_traffic_mb+' MB';
            document.getElementById('st-req').textContent = d.total_requests;
            document.getElementById('st-uptime').textContent = d.uptime;
        }

        async function loadLinks() {
            const d = await req('/api/links');
            if(!d) return;
            const tbody = document.getElementById('links-tbody');
            tbody.innerHTML = '';
            d.links.forEach(l => {
                const limitStr = l.limit_bytes === 0 ? 'Unlimited' : formatBytes(l.limit_bytes);
                const subUrl = window.location.origin + '/sub/' + l.uuid;
                const ipCount = l.addresses ? l.addresses.length : 0;
                
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td style="font-weight:600; color:#fff;">${l.label}</td>
                    <td><span class="badge ${l.active ? 'badge-success':'badge-muted'}">${l.active ? 'Active':'Disabled'}</span></td>
                    <td>${formatBytes(l.used_bytes)} / ${limitStr}</td>
                    <td>${l.current_connections} / ${l.max_connections === 0 ? '∞' : l.max_connections}</td>
                    <td><span class="badge badge-muted">${ipCount} IPs</span></td>
                    <td><div class="code-box" onclick="navigator.clipboard.writeText('${subUrl}'); alert('Copied Link!');" style="cursor:pointer;">${subUrl}</div></td>
                    <td class="actions">
                        <button class="btn" style="padding:4px 10px;" onclick="toggleLink('${l.uuid}', ${!l.active})">${l.active ? 'Disable':'Enable'}</button>
                        <button class="btn btn-danger" style="padding:4px 10px;" onclick="deleteLink('${l.uuid}')">Delete</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function createLink() {
            const label = document.getElementById('ln-label').value;
            const val = parseFloat(document.getElementById('ln-limit').value);
            const unit = document.getElementById('ln-unit').value;
            const conn = parseInt(document.getElementById('ln-conn').value);
            const ips = document.getElementById('ln-ips').value;

            if(!label) return alert('Label is required');
            const res = await req('/api/links', 'POST', {
                label, limit_value: val, limit_unit: unit, max_connections: conn, addresses: ips
            });
            if(res && res.ok) {
                document.getElementById('ln-label').value = '';
                document.getElementById('ln-ips').value = '';
                loadLinks();
            } else if(res) { alert(res.detail || 'Error creating link'); }
        }

        async function toggleLink(uid, state) {
            await req('/api/links/'+uid, 'PATCH', {active: state});
            loadLinks();
        }

        async function deleteLink(uid) {
            if(confirm('Delete inbound?')) {
                await req('/api/links/'+uid, 'DELETE');
                loadLinks();
            }
        }

        window.onload = () => {
            loadStats(); loadLinks();
            setInterval(loadStats, 3000);
            setInterval(loadLinks, 5000);
        };
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], reload=True)
