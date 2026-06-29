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

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

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
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"REN started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None, port: int = 443, security: str = "tls", fingerprint: str = "chrome") -> str:
    domain = get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": security,
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": fingerprint,
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:{port}?{query}#{quote(remark)}"

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
                "label":"پیش‌فرض",
                "limit_bytes":0,
                "used_bytes":0,
                "max_connections":0,
                "addresses":["www.speedtest.net"],
                "created_at":datetime.now().isoformat(),
                "active":True,
                "port":443,
                "security":"tls",
                "fingerprint":"chrome"
            }

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

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
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

@app.get("/")
async def root():
    return {"service": "REN", "version": "1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
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
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
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
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    addresses=[str(a).strip() for a in (body.get("addresses") or []) if str(a).strip()]
    if max_conn < 0:
        max_conn = 0
    # New fields: port, security, fingerprint
    port = int(body.get("port", 443))
    security = body.get("security", "tls")
    fingerprint = body.get("fingerprint", "chrome")
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "max_connections": max_conn,
            "addresses": addresses,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "port": port,
            "security": security,
            "fingerprint": fingerprint
        }
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "max_connections": max_conn,
        "active": True,
        "created_at": LINKS[uid]["created_at"],
        "port": port,
        "security": security,
        "fingerprint": fingerprint,
        "vless_link": generate_vless_link(uid, remark=f"REN-{label}", port=port, security=security, fingerprint=fingerprint)
    }

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
                "addresses":data.get("addresses",[]),
                "active": data["active"],
                "created_at": data["created_at"],
                "current_connections": count_connections_for_link(uid),
                "port": data.get("port", 443),
                "security": data.get("security", "tls"),
                "fingerprint": data.get("fingerprint", "chrome"),
                "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}", port=data.get("port", 443), security=data.get("security", "tls"), fingerprint=data.get("fingerprint", "chrome"))
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
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
        # New fields update
        if "port" in body:
            LINKS[uid]["port"] = int(body["port"])
        if "security" in body:
            LINKS[uid]["security"] = body["security"]
        if "fingerprint" in body:
            LINKS[uid]["fingerprint"] = body["fingerprint"]
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    vless_link = generate_vless_link(
        uid,
        remark=f"REN-{link['label']}",
        port=link.get("port", 443),
        security=link.get("security", "tls"),
        fingerprint=link.get("fingerprint", "chrome")
    )
    used = link["used_bytes"]
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# REN Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: Unlimited
# Port: {link.get('port', 443)}
# Security: {link.get('security', 'tls')}
# Fingerprint: {link.get('fingerprint', 'chrome')}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
        "port": link.get("port", 443),
        "security": link.get("security", "tls"),
        "fingerprint": link.get("fingerprint", "chrome")
    }

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    addresses = list(link.get("addresses") or [])
    sub_links = []
    # Server (main) link
    server_link = generate_vless_link(
        uid,
        remark=f"REN-{link['label']}-Server",
        port=link.get("port", 443),
        security=link.get("security", "tls"),
        fingerprint=link.get("fingerprint", "chrome")
    )
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"REN-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(
            uid,
            remark=remark,
            address=addr,
            port=link.get("port", 443),
            security=link.get("security", "tls"),
            fingerprint=link.get("fingerprint", "chrome")
        )
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={link['used_bytes']}; download=0; total={link['limit_bytes']}; expire=0"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
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
    else:
        raise ValueError(f"unknown address type: {addr_type}")
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
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n

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
            connections[conn_id]["bytes"] += size
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
            connections[conn_id]["bytes"] += size
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
                current = count_connections_for_link(uuid)
                if current >= max_conn:
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
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)

# HTML login and dashboard (same as before, but with modifications in the dashboard HTML)
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl" lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#030712;--surface:rgba(17,24,39,0.85);--surface2:#1f2937;--border:rgba(255,255,255,0.08);--text:rgba(255,255,255,0.95);--text2:rgba(156,163,175,0.8);--text3:rgba(156,163,175,0.4);--primary:#6366f1;--primary-glow:rgba(99,102,241,0.15);--accent:#4f46e5;--error:#ef4444;--error-bg:rgba(239,68,68,0.08);--orb1:rgba(99,102,241,0.15);--orb2:rgba(139,92,246,0.12);--orb3:rgba(6,182,212,0.08)}
html[data-theme="light"]{--bg:#f3f4f6;--surface:rgba(255,255,255,0.9);--surface2:#ffffff;--border:rgba(0,0,0,0.06);--text:rgba(17,24,39,0.92);--text2:rgba(75,85,99,0.8);--text3:rgba(156,163,175,0.6);--primary:#4f46e5;--primary-glow:rgba(79,70,229,0.12);--accent:#4338ca;--error:#dc2626;--error-bg:rgba(220,38,38,0.06);--orb1:rgba(79,70,229,0.1);--orb2:rgba(124,58,237,0.08);--orb3:rgba(8,145,178,0.05)}
body{font-family:'Vazirmatn',Tahoma,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .5s,color .5s;overflow:hidden}

.bg-canvas{position:fixed;inset:0;z-index:0;pointer-events:none}
.orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:0;animation:orbFloat 20s ease-in-out infinite}
.orb-1{width:400px;height:400px;background:var(--orb1);top:-10%;left:-5%;animation-delay:0s}
.orb-2{width:350px;height:350px;background:var(--orb2);bottom:-10%;right:-5%;animation-delay:-7s}
.orb-3{width:250px;height:250px;background:var(--orb3);top:40%;left:60%;animation-delay:-14s}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1);opacity:0.6}25%{transform:translate(60px,-40px) scale(1.1);opacity:0.8}50%{transform:translate(-30px,50px) scale(0.9);opacity:0.5}75%{transform:translate(40px,20px) scale(1.05);opacity:0.7}}

.grid-bg{position:fixed;inset:0;z-index:0;opacity:0.03;background-image:linear-gradient(rgba(255,255,255,0.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.1) 1px,transparent 1px);background-size:60px 60px;pointer-events:none}

.toolbar{position:fixed;top:20px;right:20px;display:flex;gap:6px;z-index:10}
.toolbar button{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:15px;transition:all .3s;backdrop-filter:blur(20px)}
.toolbar button:hover{border-color:var(--primary);color:var(--primary);transform:scale(1.05)}

.login-page{width:100%;max-width:380px;padding:0 20px;position:relative;z-index:1}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:24px;padding:48px 36px 36px;position:relative;overflow:hidden;backdrop-filter:blur(40px);box-shadow:0 8px 40px rgba(0,0,0,0.2),0 0 80px rgba(99,102,241,0.05);animation:cardIn .8s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(30px) scale(0.96)}
@keyframes cardIn{to{opacity:1;transform:translateY(0) scale(1)}}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 3s ease-in-out infinite}
@keyframes shimmer{0%,100%{opacity:0.5;transform:scaleX(0.5)}50%{opacity:1;transform:scaleX(1)}}
.login-card::after{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at var(--mx,50%) var(--my,50%),rgba(99,102,241,0.04) 0%,transparent 50%);pointer-events:none;transition:opacity .3s;opacity:0}
.login-card:hover::after{opacity:1}

.brand{text-align:center;margin-bottom:36px}
.brand svg{margin-bottom:20px;filter:drop-shadow(0 0 20px rgba(99,102,241,0.3));animation:logoPulse 4s ease-in-out infinite}
@keyframes logoPulse{0%,100%{filter:drop-shadow(0 0 20px rgba(99,102,241,0.3));transform:scale(1)}50%{filter:drop-shadow(0 0 30px rgba(99,102,241,0.5));transform:scale(1.02)}}
.brand h1{font-size:22px;font-weight:800;color:var(--text);letter-spacing:-0.03em;animation:fadeUp .6s .2s ease both}
.brand p{font-size:11px;color:var(--text3);margin-top:6px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;animation:fadeUp .6s .3s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

.form-group{margin-bottom:20px;animation:fadeUp .6s .4s ease both}
.form-group label{display:block;font-size:11px;font-weight:700;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em}
.form-group input{width:100%;padding:13px 16px;background:var(--surface2);border:1.5px solid var(--border);border-radius:12px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .3s cubic-bezier(0.4,0,0.2,1)}
.form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow),0 0 20px var(--primary-glow)}
.form-group input::placeholder{color:var(--text3)}

.login-btn{width:100%;padding:13px;background:var(--primary);border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:700;font-family:inherit;cursor:pointer;transition:all .3s cubic-bezier(0.4,0,0.2,1);letter-spacing:0.02em;position:relative;overflow:hidden;animation:fadeUp .6s .5s ease both}
.login-btn::before{content:'';position:absolute;top:50%;left:50%;width:0;height:0;background:rgba(255,255,255,0.2);border-radius:50%;transform:translate(-50%,-50%);transition:width .5s,height .5s}
.login-btn:hover{filter:brightness(1.15);transform:translateY(-2px);box-shadow:0 8px 25px rgba(99,102,241,0.35)}
.login-btn:hover::before{width:300px;height:300px}
.login-btn:active{transform:translateY(0) scale(0.98)}
.login-btn:active::before{width:0;height:0;transition:width .1s,height .1s}

.error-msg{background:var(--error-bg);border:1px solid rgba(99,102,241,0.15);color:var(--error);padding:10px 14px;border-radius:10px;font-size:13px;display:none;margin-bottom:20px;text-align:center;font-weight:500;animation:shake .4s ease}
.error-msg.show{display:block}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}

.particles{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.particle{position:absolute;width:2px;height:2px;background:var(--primary);border-radius:50%;opacity:0;animation:particleFall linear infinite}
@keyframes particleFall{0%{opacity:0;transform:translateY(-10px) scale(0)}10%{opacity:0.6;transform:translateY(0) scale(1)}90%{opacity:0.3;transform:translateY(calc(100vh - 20px)) scale(0.5)}100%{opacity:0;transform:translateY(100vh) scale(0)}}
body,.main,.sidebar,.page,.card,.form-input,.btn,.table,.modal,.nav-item,.page-title,.page-sub{font-family:'Vazirmatn',Tahoma,sans-serif!important}
</style>
</head>
<body>
<div class="bg-canvas">
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>
  <div class="orb orb-3"></div>
</div>
<div class="grid-bg"></div>
<div class="particles" id="particles"></div>

<div class="toolbar">
  <button id="lang-toggle" onclick="cycleLang()" title="Language">EN</button>
  <button id="theme-toggle" onclick="toggleTheme()" title="Theme">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
</div>
<div class="login-page">
  <div class="login-card" id="login-card">
    <div class="brand">
      <svg width="60" height="60" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#logo-grad)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3">
          <animateTransform attributeName="transform" type="rotate" from="0 28 28" to="360 28 28" dur="20s" repeatCount="indefinite"/>
        </circle>
        <circle cx="28" cy="18" r="3.5" fill="#fff">
          <animate attributeName="r" values="3.5;4;3.5" dur="3s" repeatCount="indefinite"/>
        </circle>
        <circle cx="19" cy="33" r="3.5" fill="#fff">
          <animate attributeName="r" values="3.5;4;3.5" dur="3s" begin="1s" repeatCount="indefinite"/>
        </circle>
        <circle cx="37" cy="33" r="3.5" fill="#fff">
          <animate attributeName="r" values="3.5;4;3.5" dur="3s" begin="2s" repeatCount="indefinite"/>
        </circle>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8">
          <animate attributeName="opacity" values="0.8;0.4;0.8" dur="2s" repeatCount="indefinite"/>
        </line>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8">
          <animate attributeName="opacity" values="0.8;0.4;0.8" dur="2s" begin="0.5s" repeatCount="indefinite"/>
        </line>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8">
          <animate attributeName="opacity" values="0.8;0.4;0.8" dur="2s" begin="1s" repeatCount="indefinite"/>
        </line>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9">
          <animate attributeName="r" values="2;2.5;2" dur="2s" repeatCount="indefinite"/>
          <animate attributeName="opacity" values="0.9;0.6;0.9" dur="2s" repeatCount="indefinite"/>
        </circle>
        <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#6366f1"/><stop offset="1" stop-color="#a855f7"/></linearGradient></defs>
      </svg>
      <h1>REN</h1>
      <p>v1.0</p>
    </div>
    <div class="error-msg" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <input type="password" id="password" placeholder="Enter password" autofocus>
      </div>
      <button type="submit" class="login-btn" data-en="Sign In" data-fa="ورود">Sign In</button>
    </form>
  </div>
</div>
<script>
let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
function setLang(l){lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-toggle').textContent=l.toUpperCase();localStorage.setItem('ren_lang',l)}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
applyTheme(theme);setLang(lang);

const card=document.getElementById('login-card');
card.addEventListener('mousemove',e=>{const r=card.getBoundingClientRect();card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');card.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%')});

const pc=document.getElementById('particles');
for(let i=0;i<20;i++){const p=document.createElement('div');p.className='particle';p.style.left=Math.random()*100+'%';p.style.animationDuration=(8+Math.random()*12)+'s';p.style.animationDelay=Math.random()*10+'s';p.style.width=p.style.height=(1+Math.random()*2)+'px';pc.appendChild(p)}

document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err-box');err.classList.remove('show');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message;err.classList.add('show')}
});
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#090d16;--surface:#111827;--surface2:#1f2937;--surface3:#374151;--border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.15);--text:rgba(255,255,255,0.95);--text2:rgba(156,163,175,0.8);--text3:rgba(156,163,175,0.4);--primary:#6366f1;--primary-glow:rgba(99,102,241,0.15);--primary-dim:rgba(99,102,241,0.1);--accent:#4f46e5;--green:#10b981;--green-dim:rgba(16,185,129,0.1);--red:#ef4444;--red-dim:rgba(239,68,68,0.1);--yellow:#f59e0b;--sidebar-bg:#0b0f19;--shadow:0 4px 20px rgba(0,0,0,0.25)}
html[data-theme="light"]{--bg:#f3f4f6;--surface:#ffffff;--surface2:#f9fafb;--surface3:#e5e7eb;--border:rgba(0,0,0,0.06);--border2:rgba(0,0,0,0.12);--text:#111827;--text2:#4b5563;--text3:#9ca3af;--primary:#4f46e5;--primary-glow:rgba(79,70,229,0.1);--primary-dim:rgba(79,70,229,0.06);--accent:#4338ca;--green:#10b981;--green-dim:rgba(16,185,129,0.06);--red:#dc2626;--red-dim:rgba(220,38,38,0.06);--yellow:#d97706;--sidebar-bg:#ffffff;--shadow:0 4px 15px rgba(0,0,0,0.05)}
html,body{height:100%}

/* یکسان‌سازی فونت کل سیستم برای برطرف کردن تفاوت فونت بخش main با سایر بخش‌ها */
body, .main, .sidebar, .page, .card, .form-input, .btn, .table, .modal, .nav-item, .page-title, .page-sub, .stat-label, .stat-value, .card-title, .form-label {
    font-family: 'Vazirmatn', -apple-system, BlinkMacSystemFont, sans-serif !important;
}

body{background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:background .3s,color .3s}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:3px}

.sidebar{width:220px;background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:background .3s}
body[dir="rtl"] .sidebar {border-right:none;border-left:1px solid var(--border);left:auto;right:0}
.sidebar-brand{padding:16px 16px 14px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);position:relative;overflow:hidden}
.sidebar-brand::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 4s ease-in-out infinite}
@keyframes shimmer{0%,100%{opacity:0.3;transform:scaleX(0.3)}50%{opacity:0.8;transform:scaleX(1)}}
.sidebar-brand-left{display:flex;align-items:center;gap:10px}
.sidebar-brand-left .brand-name{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.sidebar-brand-right{display:flex;gap:4px}
.sidebar-brand-right button{width:28px;height:28px;border-radius:7px;border:1px solid var(--border);background:var(--surface);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:12px;transition:all .2s}
.sidebar-brand-right button:hover{border-color:var(--primary);color:var(--primary)}
.sidebar-nav{flex:1;padding:8px;overflow-y:auto}
.nav-section{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;padding:14px 12px 6px}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 12px;margin:1px 0;border-radius:8px;color:var(--text2);font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;text-decoration:none;border:none;background:none;width:100%;text-align:left}
body[dir="rtl"] .nav-item {text-align:right}
.nav-item:hover{background:var(--primary-dim);color:var(--text)}
.nav-item.active{background:var(--primary-dim);color:var(--primary);font-weight:600;}
body[dir="ltr"] .nav-item.active{box-shadow:inset 3px 0 0 var(--primary)}
body[dir="rtl"] .nav-item.active{box-shadow:inset -3px 0 0 var(--primary)}
.nav-icon{width:18px;height:18px;flex-shrink:0;opacity:0.7}
.nav-item.active .nav-icon{opacity:1}
body[dir="ltr"] .nav-badge{margin-left:auto}
body[dir="rtl"] .nav-badge{margin-right:auto}
.nav-badge{background:var(--surface3);color:var(--text3);font-size:10px;padding:2px 7px;border-radius:8px;font-weight:600}
.sidebar-footer{padding:12px;border-top:1px solid var(--border)}
.sidebar-footer .footer-row{display:flex;gap:4px;margin-bottom:8px}
.sidebar-footer .footer-btn{flex:1;padding:6px;border:1px solid var(--border);border-radius:7px;background:var(--surface);color:var(--text3);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;text-align:center}
.sidebar-footer .footer-btn.active{background:var(--primary);color:#fff;border-color:var(--primary)}
.sidebar-footer .footer-btn:hover:not(.active){border-color:var(--border2);color:var(--text2)}
.sidebar-footer .logout-btn{width:100%;padding:7px;border:1px solid var(--border);border-radius:7px;background:none;color:var(--text3);font-family:inherit;font-size:11px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:6px}
.sidebar-footer .logout-btn:hover{background:var(--red-dim);border-color:rgba(239,68,68,0.2);color:var(--red)}
.sidebar-footer .version{text-align:center;font-size:10px;color:var(--text3);margin-top:8px;letter-spacing:0.02em}

.main{flex:1;padding:24px 28px 48px;min-height:100vh}
body[dir="ltr"] .main {margin-left:220px}
body[dir="rtl"] .main {margin-right:220px}

.page{display:none;animation:pageIn .4s ease}
.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:20px;display:flex;align-items:center;justify-content:space-between}
.page-title{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-0.01em}
.page-sub{font-size:12px;color:var(--text3);margin-top:3px}

.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;transition:all .3s cubic-bezier(0.4,0,0.2,1);animation:cardIn .5s ease both}
.stat-card:nth-child(1){animation-delay:.1s}.stat-card:nth-child(2){animation-delay:.2s}.stat-card:nth-child(3){animation-delay:.3s}.stat-card:nth-child(4){animation-delay:.4s}
@keyframes cardIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.stat-card:hover{box-shadow:var(--shadow);transform:translateY(-2px)}
.stat-label{font-size:11px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:0.04em;margin-bottom:8px}
.stat-value{font-size:22px;font-weight:700;color:var(--text);letter-spacing:-0.02em}
.stat-unit{font-size:12px;font-weight:400;color:var(--text3)}

.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:12px;transition:all .3s cubic-bezier(0.4,0,0.2,1);animation:cardIn .5s ease both}
.card:nth-child(1){animation-delay:.2s}.card:nth-child(2){animation-delay:.3s}
.card:hover{box-shadow:var(--shadow);transform:translateY(-1px)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.card-title{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--text)}

.btn{font-family:inherit;font-size:12px;font-weight:600;border-radius:8px;padding:7px 14px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:all .15s}
.btn-primary{background:var(--primary);color:#fff}
.btn-primary:hover{filter:brightness(1.1);box-shadow:0 0 15px var(--primary-glow)}
.btn-secondary{background:var(--surface3);color:var(--text2);border:1px solid var(--border);position:relative;overflow:hidden}
.btn-secondary:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-1px);box-shadow:0 2px 8px var(--primary-glow)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(239,68,68,0.12)}
.btn-danger:hover{background:rgba(239,68,68,0.2)}
.btn-sm{padding:5px 10px;font-size:11px}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.table-wrap{overflow-x:auto}
.table{width:100%;border-collapse:collapse}
.table th{text-align:left;font-size:11px;font-weight:600;color:var(--text3);padding:10px 12px;text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid var(--border);background:var(--surface2)}
body[dir="rtl"] .table th {text-align:right}
.table td{padding:10px 12px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
.table tr:last-child td{border-bottom:none}
.table tbody tr:hover td{background:var(--primary-dim)}

.tag{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:10px;font-weight:700;letter-spacing:0.03em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary)}
.tag-active{background:var(--green-dim);color:var(--green)}
.tag-disabled{background:var(--red-dim);color:var(--red)}

.usage-pill{display:flex;align-items:center;gap:8px;padding:3px 10px;border-radius:999px;background:var(--surface3);font-size:11px;color:var(--text2)}
.usage-pill .used{color:var(--text);font-weight:600}
.usage-pill .bar{flex:1;height:4px;background:var(--bg);border-radius:2px;min-width:50px}
.usage-pill .fill{height:100%;border-radius:2px;transition:width .3s}
.usage-pill .limit{color:var(--text3)}

.toggle{width:34px;height:18px;border-radius:10px;background:var(--surface3);position:relative;cursor:pointer;transition:all .3s cubic-bezier(0.4,0,0.2,1);border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:12px;height:12px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .3s cubic-bezier(0.4,0,0.2,1)}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 12px rgba(16,185,129,0.3)}
body[dir="ltr"] .toggle.on::after{left:18px;background:#fff}
body[dir="rtl"] .toggle.on::after{left:2px;background:#fff}
body[dir="rtl"] .toggle::after{right:2px;left:auto}
body[dir="rtl"] .toggle.on::after{right:18px;left:auto;background:#fff}

.sys-bar{height:6px;background:var(--surface3);border-radius:3px;overflow:hidden}
.sys-bar-fill{height:100%;border-radius:3px;transition:width .4s}

.status-item{display:flex;align-items:center;justify-content:space-between;padding:11px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:8px}
.status-val{color:var(--text);font-weight:600;font-size:12px}

.form-group{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.form-label{font-size:11px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:0.04em}
.form-input,.form-select{padding:8px 12px;border-radius:8px;border:1px solid var(--border);font-family:inherit;font-size:13px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.form-select option{background:var(--surface2);color:var(--text)}
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-row .form-group{margin-bottom:0;flex:1;min-width:100px}

.empty{text-align:center;padding:40px 16px;color:var(--text3)}
.empty-icon{font-size:32px;margin-bottom:10px;opacity:0.3}

.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 20px;font-size:12px;font-weight:500;opacity:0;transition:all .3s cubic-bezier(0.4,0,0.2,1);z-index:999;display:flex;align-items:center;gap:8px;box-shadow:0 8px 24px rgba(0,0,0,0.2);backdrop-filter:blur(20px)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{border-color:var(--red-dim);color:var(--red)}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(6px)}
.modal-overlay.show{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;width:100%;max-width:460px;position:relative;box-shadow:0 20px 60px rgba(0,0,0,0.3),0 0 40px var(--primary-glow);transform:scale(0.9);opacity:0;transition:all .4s cubic-bezier(0.34,1.56,0.64,1)}
.modal-overlay.show .modal{transform:scale(1);opacity:1}
.modal-title{font-size:15px;font-weight:700;margin-bottom:18px;color:var(--text)}
.modal-close{position:absolute;top:12px;background:var(--surface3);border:1px solid var(--border);color:var(--text3);width:28px;height:28px;border-radius:7px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;transition:all .2s}
body[dir="ltr"] .modal-close {right:12px}
body[dir="rtl"] .modal-close {left:12px}
.modal-close:hover{background:var(--red-dim);color:var(--red);border-color:rgba(239,68,68,0.2)}
.qr-box{text-align:center;padding:24px;background:var(--surface2);border-radius:14px;margin-top:14px;border:1px solid var(--border);transition:all .3s}
.qr-box:hover{border-color:var(--primary);box-shadow:0 0 20px var(--primary-glow)}
.qr-box img{max-width:220px;border-radius:10px;border:3px solid var(--surface);box-shadow:0 4px 16px rgba(0,0,0,0.1);transition:transform .3s}
.qr-box img:hover{transform:scale(1.05)}

.btn-copy,.btn-qr{position:relative;overflow:hidden;font-family:inherit;font-size:11px;font-weight:600;border-radius:8px;padding:5px 10px;cursor:pointer;border:none;display:inline-flex;align-items:center;gap:4px;transition:all .25s cubic-bezier(0.34,1.56,0.64,1)}
.btn-copy{background:var(--primary-dim);color:var(--primary);border:1px solid rgba(99,102,241,0.15)}
.btn-copy:hover{background:var(--primary);color:#fff;transform:translateY(-2px);box-shadow:0 4px 12px var(--primary-glow)}
.btn-copy:active{transform:translateY(0) scale(0.96)}
.btn-qr{background:var(--green-dim);color:var(--green);border:1px solid rgba(16,185,129,0.15)}
.btn-qr:hover{background:var(--green);color:#fff;transform:translateY(-2px);box-shadow:0 4px 12px rgba(16,185,129,0.2)}
.btn-qr:active{transform:translateY(0) scale(0.96)}

.detail-label{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:5px}
.detail-value{padding:8px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;font-size:12px;color:var(--text2);word-break:break-all;font-family:'SF Mono',Monaco,Consolas,monospace;line-height:1.6}
.detail-row{display:flex;gap:12px;margin-bottom:12px}
.detail-row .detail-col{flex:1}
.detail-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:14px}

.inbounds-toolbar{display:flex;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.search-box{flex:1;min-width:180px;position:relative}
.search-box input{width:100%;background:var(--surface2);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:12px;font-family:inherit;outline:none;transition:all .2s}
body[dir="ltr"] .search-box input {padding:8px 12px 8px 32px;}
body[dir="rtl"] .search-box input {padding:8px 32px 8px 12px;}
.search-box input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow)}
.search-box svg{position:absolute;top:50%;transform:translateY(-50%);color:var(--text3)}
body[dir="ltr"] .search-box svg {left:10px}
body[dir="rtl"] .search-box svg {right:10px}
.filter-chips{display:flex;gap:3px;padding:3px 5px;background:var(--surface2);border:1px solid var(--border);border-radius:8px}
.chip{padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;color:var(--text3);cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:var(--primary);color:#fff}
.chip:hover:not(.active){background:var(--surface3);color:var(--text2)}

.inbound-cards{display:none;flex-direction:column;gap:8px;padding:0 4px}
.inbound-card{border:1px solid var(--border);border-radius:10px;padding:12px;background:var(--surface2);display:flex;flex-direction:column;gap:8px}
.inbound-card-header{display:flex;align-items:center;justify-content:space-between}
.inbound-card-id{font-size:10px;color:var(--text3);font-weight:600}
.inbound-card-name{font-size:13px;font-weight:600;color:var(--text)}
.inbound-card-actions{display:flex;gap:4px;}
body[dir="ltr"] .inbound-card-actions {justify-content:flex-end}
body[dir="rtl"] .inbound-card-actions {justify-content:flex-start}

.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:44px;background:var(--sidebar-bg);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 14px}
.menu-toggle{width:32px;height:32px;border-radius:8px;border:1px solid var(--border);background:var(--surface);color:var(--text2);display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:14px}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:99}
.sidebar-overlay.show{display:block}

@media(max-width:768px){
  .sidebar{transform:translateX(-100%);width:220px;z-index:200}
  body[dir="rtl"] .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0) !important;}
  body[dir="ltr"] .sidebar.open{box-shadow:4px 0 20px rgba(0,0,0,0.4)}
  body[dir="rtl"] .sidebar.open{box-shadow:-4px 0 20px rgba(0,0,0,0.4)}
  .main{padding-top:60px;padding-left:12px;padding-right:12px}
  body[dir="ltr"] .main {margin-left:0}
  body[dir="rtl"] .main {margin-right:0}
  .mobile-header{display:flex}
  .stats-row{grid-template-columns:1fr 1fr}
  .grid-2{grid-template-columns:1fr}
  .inbounds-toolbar{flex-direction:column;align-items:stretch}
  .search-box{min-width:unset}
  .filter-chips{justify-content:center}
  .table-wrap{display:none}
  .inbound-cards{display:flex}
}
@media(max-width:480px){
  .stats-row{grid-template-columns:1fr}
}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<div class="mobile-header">
  <span style="font-weight:700;font-size:13px">REN</span>
  <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.toggle('open');document.getElementById('sidebar-overlay').classList.toggle('show')">&#9776;</button>
</div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>

<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-left">
      <svg width="28" height="28" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="14" fill="url(#lg)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
        <circle cx="28" cy="18" r="3.5" fill="#fff"/>
        <circle cx="19" cy="33" r="3.5" fill="#fff"/>
        <circle cx="37" cy="33" r="3.5" fill="#fff"/>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
        <defs><linearGradient id="lg" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#6366f1"/><stop offset="1" stop-color="#a855f7"/></linearGradient></defs>
      </svg>
      <span class="brand-name">REN</span>
    </div>
    <div class="sidebar-brand-right">
      <button onclick="toggleTheme()" id="theme-btn" title="Toggle theme">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      </button>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section" data-en="MAIN" data-fa="اصلی">اصلی</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">داشبورد</span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">اینباندها</span>
      <span class="nav-badge" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <span data-en="Traffic" data-fa="ترافیک">ترافیک</span>
    </button>
    
    <div class="nav-section" data-en="SYSTEM" data-fa="سیستم">سیستم</div>
    <button class="nav-item" data-page="security">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      <span data-en="Security" data-fa="امنیت">امنیت</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="footer-row">
      <button class="footer-btn active" onclick="setLang('en')" id="lang-en">EN</button>
      <button class="footer-btn" onclick="setLang('fa')" id="lang-fa">FA</button>
    </div>
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
    <div class="version">v1.0</div>
  </div>
</aside>

<main class="main">
  <!-- صفحه داشبورد -->
  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Dashboard" data-fa="داشبورد">داشبورد</div>
        <div class="page-sub" id="last-update">بروزرسانی شد: --</div>
      </div>
      <div style="display:flex;gap:6px">
        <button class="btn btn-secondary" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary" onclick="quickCreate(1,'GB')">+ 1 GB</button>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-label" data-en="Traffic" data-fa="ترافیک">ترافیک</div>
        <div class="stat-value" id="s-traffic">--<span class="stat-unit"> MB</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Inbounds" data-fa="اینباندها">اینباندها</div>
        <div class="stat-value" id="s-links">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div>
        <div class="stat-value" id="s-uptime" style="font-size:16px">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="stat-value" id="s-domain" style="font-size:11px;word-break:break-all;font-weight:500">--</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><div class="card-title" data-en="CPU Usage" data-fa="میزان مصرف پردازنده (CPU)">CPU Usage</div><span id="s-cpu-val" style="font-size:18px;font-weight:700;color:var(--primary)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title" data-en="Memory" data-fa="میزان مصرف حافظه (Memory)">Memory</div><span id="s-mem-val" style="font-size:18px;font-weight:700;color:var(--green)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--green)"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title" data-en="Traffic Chart" data-fa="نمودار ترافیک">Traffic Chart</div></div>
      <div style="height:180px"><canvas id="trafficChart"></canvas></div>
    </div>
  </section>

  <!-- صفحه اینباندها -->
  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Inbounds" data-fa="اینباندها">اینباندها</div>
        <div class="page-sub">VLESS over WebSocket</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()" data-en="+ Add" data-fa="+ افزودن">+ Add</button>
    </div>
    <div class="inbounds-toolbar">
      <div class="search-box">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="inbound-search" placeholder="Search by name or UUID..." data-placeholder-en="Search by name or UUID..." data-placeholder-fa="جستجو بر اساس نام یا UUID..." oninput="filterInbounds()">
      </div>
      <div class="filter-chips">
        <button class="chip active" onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</button>
        <button class="chip" onclick="setFilter('active',this)" data-en="Active" data-fa="فعال">Active</button>
        <button class="chip" onclick="setFilter('disabled',this)" data-en="Disabled" data-fa="غیرفعال">Disabled</button>
      </div>
    </div>
    <div class="card" style="border-radius:12px;overflow:hidden;padding:0">
      <div class="table-wrap">
        <table class="table">
          <thead><tr>
            <th style="width:32px" data-en="ID" data-fa="شناسه">ID</th>
            <th data-en="Remark" data-fa="نام کاربر">Remark</th>
            <th style="width:56px" data-en="Type" data-fa="نوع">Type</th>
            <th data-en="Traffic" data-fa="ترافیک">ترافیک</th>
            <th style="width:80px" data-en="IPs" data-fa="اتصال‌ها">IPs</th>
            <th style="width:64px" data-en="Status" data-fa="وضعیت">Status</th>
            <th style="width:100px" data-en="Actions" data-fa="عملیات">Actions</th>
          </tr></thead>
          <tbody id="links-tbody"></tbody>
        </table>
      </div>
      <div class="inbound-cards" id="inbound-cards"></div>
      <div class="empty" id="links-empty" style="display:none">
        <div class="empty-icon">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>
        </div>
        <div data-en="No inbounds found" data-fa="هیچ اینباندی یافت نشد">No inbounds found</div>
      </div>
    </div>
  </section>

  <!-- صفحه ترافیک -->
  <section class="page" id="page-traffic">
    <div class="page-header"><div><div class="page-title" data-en="Traffic" data-fa="ترافیک">ترافیک</div><div class="page-sub" data-en="Traffic statistics" data-fa="آمار و گزارشات مصارف ترافیک">Traffic statistics</div></div></div>
    <div class="card">
      <div class="card-header"><div class="card-title" data-en="Overview" data-fa="مرور کلی">Overview</div></div>
      <div class="status-item"><span class="status-key" data-en="Total Traffic" data-fa="ترافیک کل">Total Traffic</span><span class="status-val" id="t-traffic">-- MB</span></div>
      <div class="status-item"><span class="status-key" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="status-val" id="t-reqs">--</span></div>
      <div class="status-item"><span class="status-key" data-en="Uptime" data-fa="مدت زمان فعالیت (آپتایم)">Uptime</span><span class="status-val" id="t-uptime">--</span></div>
    </div>
  </section>

  <!-- صفحه امنیت -->
  <section class="page" id="page-security">
    <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">امنیت</div><div class="page-sub" data-en="Change Panel Password" data-fa="تغییر رمز عبور پنل مدیریتی">تغییر رمز پنل</div></div></div>
    <div class="card" style="max-width:400px">
      <div class="form-group">
        <label class="form-label" data-en="Current Password" data-fa="رمز عبور فعلی">رمز فعلی</label>
        <input class="form-input" type="password" id="cur-pw" placeholder="رمز فعلی را وارد کنید" data-placeholder-en="Enter current password" data-placeholder-fa="رمز فعلی را وارد کنید">
      </div>
      <div class="form-group">
        <label class="form-label" data-en="New Password" data-fa="رمز عبور جدید">رمز جدید</label>
        <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters" data-placeholder-en="Min 4 characters" data-placeholder-fa="حداقل ۴ کاراکتر">
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="margin-top:4px" data-en="Update Password" data-fa="بروزرسانی رمز عبور">بروزرسانی رمز</button>
    </div>
  </section>
</main>

<!-- مودال افزودن اینباند -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#add-modal').classList.remove('show')">x</button>
    <div class="modal-title" data-en="Add Inbound" data-fa="افزودن اینباند">افزودن اینباند</div>
    <div class="form-group">
      <label class="form-label" data-en="Username" data-fa="نام کاربر">نام کاربر</label>
      <input class="form-input" id="new-label" placeholder="مثال: کاربر ۱" data-placeholder-en="e.g. User 1" data-placeholder-fa="مثال: کاربر ۱">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label" data-en="Allowed Volume" data-fa="حجم مجاز">حجم مجاز</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="۰ = نامحدود" data-placeholder-en="0 = Unlimited" data-placeholder-fa="۰ = نامحدود">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label" data-en="Unit" data-fa="واحد">واحد</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label" data-en="Max Connections" data-fa="حداکثر اتصال">حداکثر اتصال</label>
      <input class="form-input" id="new-maxconn" type="number" min="0" step="1" placeholder="۰ = نامحدود" data-placeholder-en="0 = Unlimited" data-placeholder-fa="۰ = نامحدود">
    </div>
    <!-- انتخاب پورت -->
    <div class="form-group">
      <label class="form-label" data-en="Connection Port" data-fa="پورت اتصال">پورت اتصال</label>
      <select class="form-select" id="new-port-select" onchange="toggleCustomPort(this, 'new')">
        <optgroup label="پورت‌های امن (TLS)">
          <option value="443">443</option>
          <option value="8443">8443</option>
          <option value="2096">2096</option>
        </optgroup>
        <optgroup label="پورت‌های معمولی (Non-TLS)">
          <option value="80">80</option>
          <option value="2082">2082</option>
          <option value="2086">2086</option>
          <option value="2095">2095</option>
          <option value="8880">8880</option>
          <option value="2052">2052</option>
          <option value="2087">2087</option>
          <option value="2053">2053</option>
          <option value="8443">8443</option>
        </optgroup>
        <option value="custom">سفارشی (Custom)</option>
      </select>
      <input id="new-port-custom" type="number" placeholder="مثلاً 8443" style="display:none; margin-top:5px; width:100%; padding:8px; border-radius:8px; border:1px solid var(--border); background:var(--surface2); color:var(--text);" />
    </div>
    <!-- انتخاب Fingerprint -->
    <div class="form-group">
      <label class="form-label" data-en="Fingerprint" data-fa="اثر انگشت">Fingerprint</label>
      <select class="form-select" id="new-fingerprint">
        <option value="chrome">Chrome</option>
        <option value="firefox">Firefox</option>
        <option value="safari">Safari</option>
        <option value="ios" selected>iOS Device (پیش‌فرض)</option>
        <option value="android">Android Device</option>
        <option value="edge">Microsoft Edge</option>
        <option value="360">Browser 360</option>
        <option value="qq">QQ Browser</option>
        <option value="random">Random (اتفاقی)</option>
        <option value="randomized">Randomized</option>
      </select>
    </div>
    <div class="form-group">
      <label class="form-label" data-en="Dedicated IP" data-fa="آی‌پی اختصاصی">آی‌پی اختصاصی</label>
      <textarea class="form-input" id="new-addresses" placeholder="هر مورد در یک خط" data-placeholder-en="One per line" data-placeholder-fa="هر مورد در یک خط"></textarea>
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:8px;justify-content:center" data-en="Create Inbound" data-fa="ساخت اینباند">ساخت اینباند</button>
  </div>
</div>

<!-- مودال جزئیات -->
<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative;max-width:540px">
    <button class="modal-close" onclick="$('#detail-modal').classList.remove('show')">x</button>
    <div class="modal-title" id="detail-title" data-en="Inbound Details" data-fa="جزئیات اینباند">جزئیات اینباند</div>
    <div id="detail-content"></div>
  </div>
</div>

<!-- مودال کیوآرکد -->
<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#qr-modal').classList.remove('show')">x</button>
    <div class="modal-title" data-en="QR Code" data-fa="کد QR">کد QR</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="margin-top:14px;text-align:center;display:flex;gap:8px;justify-content:center">
      <button class="btn btn-primary btn-sm" onclick="downloadQR()" style="padding:8px 20px" data-en="Download" data-fa="دانلود">دانلود</button>
      <button class="btn btn-secondary btn-sm" onclick="$('#qr-modal').classList.remove('show')" style="padding:8px 20px" data-en="Close" data-fa="بستن">بستن</button>
    </div>
  </div>
</div>

<!-- مودال ویرایش -->
<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#edit-modal').classList.remove('show')">x</button>
    <div class="modal-title" id="edit-title" data-en="Edit Inbound" data-fa="ویرایش اینباند">Edit Inbound</div>
    <input type="hidden" id="edit-uid">
    <div class="form-group">
      <label class="form-label" data-en="Name" data-fa="نام">Name</label>
      <input class="form-input" id="edit-name" readonly style="opacity:0.6;cursor:not-allowed">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label" data-en="Allowed Volume" data-fa="حجم مجاز">حجم مجاز</label>
        <input class="form-input" id="edit-limit" type="number" min="0" step="0.1" placeholder="۰ = نامحدود" data-placeholder-en="0 = Unlimited" data-placeholder-fa="۰ = نامحدود">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label" data-en="Unit" data-fa="واحد">واحد</label>
        <select class="form-select" id="edit-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label" data-en="Max Connections" data-fa="حداکثر اتصال">حداکثر اتصال</label>
      <input class="form-input" id="edit-maxconn" type="number" min="0" step="1" placeholder="۰ = نامحدود" data-placeholder-en="0 = Unlimited" data-placeholder-fa="۰ = نامحدود">
    </div>
    <!-- ویرایش پورت -->
    <div class="form-group">
      <label class="form-label" data-en="Connection Port" data-fa="پورت اتصال">پورت اتصال</label>
      <select class="form-select" id="edit-port-select" onchange="toggleCustomPort(this, 'edit')">
        <optgroup label="پورت‌های امن (TLS)">
          <option value="443">443</option>
          <option value="8443">8443</option>
          <option value="2096">2096</option>
        </optgroup>
        <optgroup label="پورت‌های معمولی (Non-TLS)">
          <option value="80">80</option>
          <option value="2082">2082</option>
          <option value="2086">2086</option>
          <option value="2095">2095</option>
          <option value="8880">8880</option>
          <option value="2052">2052</option>
          <option value="2087">2087</option>
          <option value="2053">2053</option>
          <option value="8443">8443</option>
        </optgroup>
        <option value="custom">سفارشی (Custom)</option>
      </select>
      <input id="edit-port-custom" type="number" placeholder="مثلاً 8443" style="display:none; margin-top:5px; width:100%; padding:8px; border-radius:8px; border:1px solid var(--border); background:var(--surface2); color:var(--text);" />
    </div>
    <!-- ویرایش Fingerprint -->
    <div class="form-group">
      <label class="form-label" data-en="Fingerprint" data-fa="اثر انگشت">Fingerprint</label>
      <select class="form-select" id="edit-fingerprint">
        <option value="chrome">Chrome</option>
        <option value="firefox">Firefox</option>
        <option value="safari">Safari</option>
        <option value="ios">iOS Device (پیش‌فرض)</option>
        <option value="android">Android Device</option>
        <option value="edge">Microsoft Edge</option>
        <option value="360">Browser 360</option>
        <option value="qq">QQ Browser</option>
        <option value="random">Random (اتفاقی)</option>
        <option value="randomized">Randomized</option>
      </select>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="btn btn-primary" onclick="saveEdit()" style="flex:1;justify-content:center" data-en="Save" data-fa="ذخیره">Save</button>
      <button class="btn btn-danger" onclick="resetEditTraffic()" style="justify-content:center" data-en="Reset Traffic" data-fa="ریست ترافیک">ریست ترافیک</button>
    </div>
  </div>
</div>

<!-- مودال افزودن آی پی تمیز -->
<div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" style="position:relative">
    <button class="modal-close" onclick="$('#add-address-modal').classList.remove('show')">x</button>
    <div class="modal-title" data-en="Add Clean IP" data-fa="افزودن آی‌پی تمیز">Add Clean IP</div>
    <div class="form-group">
      <label class="form-label" data-en="IPs or Domains (one per line)" data-fa="آی‌پی یا دامنه (هر خط یکی)">IPs or Domains (one per line)</label>
      <textarea class="form-input" id="new-address" rows="5" placeholder="8.8.8.8&#10;example.com&#10;1.0.0.1" style="resize:vertical;font-family:monospace"></textarea>
    </div>
    <button class="btn btn-primary" onclick="addAddresses()" style="width:100%;margin-top:8px;justify-content:center" data-en="Add All" data-fa="افزودن همه">Add All</button>
  </div>
</div>

<script>
let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
let allLinks=[];let currentFilter='all';let statsData={};let trafficChart=null;

function setLang(l){
  lang=l;
  document.getElementById('lang-en').classList.toggle('active',l==='en');
  document.getElementById('lang-fa').classList.toggle('active',l==='fa');
  document.body.dir=l==='fa'?'rtl':'ltr';
  
  // ترجمه متون معمولی درون المان‌ها
  document.querySelectorAll('[data-en]').forEach(el=>{
    const v=el.getAttribute('data-'+l);
    if(v) el.textContent=v;
  });

  // ترجمه پِلیس‌هولدرها (Placeholder) درون اینپوت‌ها برای فارسی‌سازی کامل فیلدها
  document.querySelectorAll('[data-placeholder-en]').forEach(el=>{
    const p=el.getAttribute('data-placeholder-'+l);
    if(p) el.setAttribute('placeholder', p);
  });

  localStorage.setItem('ren_lang',l);
}

function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t);const btn=$('#theme-btn');if(btn)btn.innerHTML=t==='dark'?'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>':'<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>'}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
function showAddModal(){
  // reset fields
  ['new-label','new-limit','new-maxconn','new-addresses'].forEach(id=>{const el=document.getElementById(id);if(el) el.value='';});
  document.getElementById('new-port-select').value='443';
  document.getElementById('new-port-custom').style.display='none';
  document.getElementById('new-fingerprint').value='ios';
  document.getElementById('add-modal').classList.add('show');
}
function setFilter(f,el){currentFilter=f;document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterInbounds()}
function filterInbounds(){const q=($('#inbound-search')?.value||'').toLowerCase();let filtered=allLinks;if(currentFilter==='active')filtered=filtered.filter(l=>l.active);if(currentFilter==='disabled')filtered=filtered.filter(l=>!l.active);if(q)filtered=filtered.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(filtered)}
function fmtBytes(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}
function fmtLimit(b){if(b===0)return lang==='fa'?'نامحدود':'Unlimited';const gb=b/1073741824;return(gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB'}

const $=s=>document.querySelector(s);
const $$=s=>document.querySelectorAll(s);
$$('.nav-item').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){$$('.page').forEach(p=>p.classList.remove('active'));$(`#page-${id}`)?.classList.add('active');$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));$('#sidebar').classList.remove('open');$('#sidebar-overlay').classList.remove('open')}
function toast(msg,err=false){const t=$('#toast');t.textContent=msg;t.className='toast'+(err?' error':'')+' show';setTimeout(()=>t.classList.remove('show'),3000)}
function esc(s){return s.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

async function loadStats(){
  try{
    const r=await fetch('/stats');if(!r.ok)throw new Error();statsData=await r.json();
    const pulse=(el,val)=>{if(el.textContent!==val){el.style.transition='color .2s';el.style.color='var(--primary)';el.textContent=val;setTimeout(()=>el.style.color='',400)}};
    pulse($('#s-traffic'),statsData.total_traffic_mb+' MB');$('#s-traffic').innerHTML=statsData.total_traffic_mb+'<span class="stat-unit"> MB</span>';
    pulse($('#s-links'),statsData.links_count);
    pulse($('#s-uptime'),statsData.uptime);
    pulse($('#s-domain'),statsData.domain);
    $('#links-badge').textContent=statsData.links_count;
    $('#last-update').textContent=(lang==='fa'?'آخرین بروزرسانی: ':'بروزرسانی شد: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
    if($('#t-traffic'))$('#t-traffic').textContent=statsData.total_traffic_mb+' MB';
    if($('#t-reqs'))$('#t-reqs').textContent=statsData.total_requests.toLocaleString();
    if($('#t-uptime'))$('#t-uptime').textContent=statsData.uptime;
    if(statsData.cpu_percent!==undefined){const c=statsData.cpu_percent;const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';$('#s-cpu-val').textContent=c.toFixed(1)+'%';$('#s-cpu-val').style.color=cc;$('#s-cpu-bar').style.width=c+'%';$('#s-cpu-bar').style.background=cc}
    if(statsData.memory_percent!==undefined){const m=statsData.memory_percent;const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';$('#s-mem-val').textContent=m.toFixed(1)+'%';$('#s-mem-val').style.color=mc;$('#s-mem-bar').style.width=m+'%';$('#s-mem-bar').style.background=mc}
    updateChart();
  }catch(e){}
}

async function loadLinks(){try{const r=await fetch('/api/links');if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterInbounds();}catch(e){}}

function renderLinks(links){
  const tbody=$('#links-tbody');const empty=$('#links-empty');const cards=$('#inbound-cards');
  if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='block';return;}
  empty.style.display='none';
  let idx=links.length;
  const rows=links.map(l=>{
    const u=l.used_bytes,lim=l.limit_bytes;
    const uF=fmtBytes(u);const lF=fmtLimit(lim);
    const pct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const i=idx--;
    return {l,uF,lF,pct,col,i,maxConn:l.max_connections||0,curConn:l.current_connections||0};
  });
  tbody.innerHTML=rows.map(r=>`<tr>
    <td style="color:var(--text3);font-size:11px">${r.i}</td>
    <td style="font-weight:600;font-size:13px">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">VLESS</span></td>
    <td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td>
    <td style="font-size:12px;font-weight:600;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text2)'}">${r.curConn}/${r.maxConn||'∞'}</td>
    <td><span class="tag ${r.l.active?'tag-active':'tag-disabled'}">${r.l.active ? (lang==='fa'?'روشن':'On') : (lang==='fa'?'خاموش':'Off')}</span></td>
    <td><div style="display:flex;gap:3px;align-items:center">
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" title="Toggle"></button>
      <button class="btn btn-secondary btn-sm" onclick="showEditModal('${r.l.uuid}')" title="Edit" style="background:rgba(251,191,36,0.1);color:var(--yellow);border:1px solid rgba(251,191,36,0.2)">e</button>
      <button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')" title="Copy">c</button>
      <button class="btn-copy" onclick="copySubLink('${r.l.uuid}')" title="Sub" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(16,185,129,0.15)">s</button>
      <button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')" title="QR">qr</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')" title="Delete">x</button>
    </div></td>
  </tr>`).join('');

  cards.innerHTML=rows.map(r=>`<div class="inbound-card">
    <div class="inbound-card-header">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="inbound-card-id">#${r.i}</span>
        <span class="inbound-card-name">${esc(r.l.label)}</span>
        <span class="tag tag-vless">VLESS</span>
      </div>
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
    </div>
    <div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div>
    <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2)"><span style="font-weight:600;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text)'}">${r.curConn}/${r.maxConn||'∞'}</span> <span>IPs</span></div>
    <div class="inbound-card-actions">
      <button class="btn btn-secondary btn-sm" onclick="showEditModal('${r.l.uuid}')" style="background:rgba(251,191,36,0.1);color:var(--yellow);border:1px solid rgba(251,191,36,0.2)">e</button>
      <button class="btn-copy" onclick="copyLinkText('${esc(r.l.vless_link)}')">c</button>
      <button class="btn-copy" onclick="copySubLink('${r.l.uuid}')" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(16,185,129,0.15)">s</button>
      <button class="btn-qr" onclick="showQRText('${esc(r.l.vless_link)}')">qr</button>
      <button class="btn btn-danger btn-sm" onclick="deleteLink('${r.l.uuid}')">x</button>
    </div>
  </div>`).join('');
}

async function toggleLink(el){
  const uid=el.dataset.uid;
  const link=allLinks.find(l=>l.uuid===uid);
  if(!link)return;
  const newActive=!link.active;
  try{
    await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});
    link.active=newActive;
    filterInbounds();
    loadStats();
  }catch(e){}
}

async function quickCreate(limit,unit){
  const names=['Ali','Sara','Reza','Nima','Mina','Arash','Yalda','Dariush','Cyrus','Shirin'];
  const name=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*100);
  try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:limit,limit_unit:unit,port:443,security:'tls',fingerprint:'chrome'})});if(!r.ok)throw new Error();toast((lang==='fa'?'ساخته شد: ':'Created: ')+name);await loadLinks();await loadStats();}catch(e){toast('Error',true)}
}

function toggleCustomPort(select, prefix) {
  const customInput = document.getElementById(prefix + '-port-custom');
  if (select.value === 'custom') {
    customInput.style.display = 'block';
  } else {
    customInput.style.display = 'none';
  }
}

async function createLink(){
  const label=$('#new-label').value.trim()||'New Link';const val=parseFloat($('#new-limit').value)||0;const unit='GB';const maxconn=parseInt($('#new-maxconn').value)||0;
  const addresses=$("#new-addresses").value.split("\n").map(v=>v.trim()).filter(Boolean);
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){toast(lang==='fa'?'فقط حروف و اعداد انگلیسی مجاز است':'Only English letters allowed',true);return;}
  
  // پورت
  let portSelect = document.getElementById('new-port-select');
  let portValue = portSelect.value;
  let port, security;
  if (portValue === 'custom') {
    port = parseInt(document.getElementById('new-port-custom').value) || 443;
    // فرض می‌کنیم کاربر می‌داند امن است یا نه، ولی برای امنیت پیش‌فرض TLS می‌گیریم
    security = 'tls';
  } else {
    port = parseInt(portValue);
    const tlsPorts = [443, 8443, 2096];
    security = tlsPorts.includes(port) ? 'tls' : 'none';
  }
  const fingerprint = document.getElementById('new-fingerprint').value;
  
  try{
    const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:val,limit_unit:unit,max_connections:maxconn,addresses,port,security,fingerprint})});
    if(!r.ok)throw new Error();
    toast(lang==='fa'?'ایجاد شد':'Created');
    $('#new-label').value='';$('#new-limit').value='';$('#new-maxconn').value='';$('#new-addresses').value='';
    $('#add-modal').classList.remove('show');
    await loadLinks();await loadStats();
  }catch(e){toast('Error',true)}
}

async function resetUsage(uid){try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('ریست شد');await loadLinks();}catch(e){}}
async function deleteLink(uid){if(!confirm(lang==='fa'?'آیا از حذف این اینباند اطمینان دارید؟':'Delete this inbound?'))return;try{await fetch(`/api/links/${uid}`,{method:'DELETE'});toast(lang==='fa'?'حذف شد':'Deleted');await loadLinks();await loadStats();}catch(e){}}

function showEditModal(uid){
  const l=allLinks.find(x=>x.uuid===uid);if(!l)return;
  $('#edit-uid').value=uid;
  $('#edit-name').value=l.label;
  const gb=l.limit_bytes/1073741824;
  $('#edit-limit').value=l.limit_bytes>0?gb:'';
  $('#edit-unit').value='GB';
  $('#edit-maxconn').value=l.max_connections>0?l.max_connections:'';
  
  // تنظیم پورت
  const portSelect = document.getElementById('edit-port-select');
  const portCustom = document.getElementById('edit-port-custom');
  const presetPorts = [443,8443,2096,80,2082,2086,2095,8880,2052,2087,2053];
  if (presetPorts.includes(l.port)) {
    portSelect.value = String(l.port);
    portCustom.style.display = 'none';
  } else {
    portSelect.value = 'custom';
    portCustom.style.display = 'block';
    portCustom.value = l.port;
  }
  // تنظیم fingerprint
  document.getElementById('edit-fingerprint').value = l.fingerprint || 'ios';
  
  $('#edit-title').textContent=(lang==='fa'?'ویرایش: ':'Edit: ')+l.label;
  $('#edit-modal').classList.add('show');
}

async function saveEdit(){
  const uid=$('#edit-uid').value;
  const val=parseFloat($('#edit-limit').value)||0;
  const unit=$('#edit-unit').value;
  const maxconn=parseInt($('#edit-maxconn').value)||0;
  
  // پورت
  let portSelect = document.getElementById('edit-port-select');
  let portValue = portSelect.value;
  let port, security;
  if (portValue === 'custom') {
    port = parseInt(document.getElementById('edit-port-custom').value) || 443;
    security = 'tls';
  } else {
    port = parseInt(portValue);
    const tlsPorts = [443, 8443, 2096];
    security = tlsPorts.includes(port) ? 'tls' : 'none';
  }
  const fingerprint = document.getElementById('edit-fingerprint').value;
  
  try{
    const r=await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({limit_value:val,limit_unit:unit,max_connections:maxconn,port,security,fingerprint})});
    if(!r.ok)throw new Error();
    toast(lang==='fa'?'بروزرسانی شد':'Updated');
    $('#edit-modal').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error',true)}
}

async function resetEditTraffic(){
  const uid=$('#edit-uid').value;
  if(!confirm(lang==='fa'?'آیا می‌خواهید مصرف ترافیک صفر شود؟':'Reset traffic usage to zero?'))return;
  try{
    const r=await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});
    if(!r.ok)throw new Error();
    toast(lang==='fa'?'ترافیک ریست شد':'Traffic reset');
    await loadLinks();
  }catch(e){toast('Error',true)}
}

function copyLinkText(txt){navigator.clipboard.writeText(txt).then(()=>toast(lang==='fa'?'در کلیپ‌بورد کپی شد':'Copied to clipboard')).catch(()=>toast('کپی ناموفق',true))}
function showQRText(txt){if(!txt)return;const box=document.querySelector('.qr-box');$('#qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(txt);$('#qr-modal').classList.add('show');}
function downloadQR(){const img=$('#qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='ren-qr.png';a.click()}
async function copySubLink(uid){
  try{
    const domain=location.host;
    const subUrl=`https://${domain}/sub/${uid}`;
    await navigator.clipboard.writeText(subUrl);
    toast(lang==='fa'?'لینک سابسکریپشن کپی شد':'Subscription link copied');
  }catch(e){toast('کپی ناموفق',true)}
}

async function changePassword(){
  const cur=$('#cur-pw').value;const nw=$('#new-pw').value;
  if(!cur||!nw){toast(lang==='fa'?'لطفا تمام فیلدها را پر کنید':'Fill all fields',true);return;}
  try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}toast(lang==='fa'?'بروزرسانی شد':'Updated');$('#cur-pw').value='';$('#new-pw').value='';}catch(e){toast(e.message,true)}
}

applyTheme(theme);setLang(lang);
loadStats();loadLinks();loadAddresses();
setInterval(()=>{loadStats()},10000);

let allAddresses=[];

async function loadAddresses(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddresses=d.addresses||[];
    renderAddresses();
  }catch(e){}
}

function renderAddresses(){
  const list=$('#address-list');if(!list)return;
  if(!allAddresses.length){list.innerHTML=`<div style="color:var(--text3);font-size:12px;padding:8px 0">${lang==='fa'?'هیچ آی‌پی اضافه نشده است':'No addresses added'}</div>`;return;}
  list.innerHTML=allAddresses.map((a,i)=>`
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px">
      <div style="display:flex;align-items:center;gap:10px">
        <span style="font-size:14px">🌐</span>
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--text)">${esc(a)}</div>
          <div style="font-size:10px;color:var(--text3)">${lang==='fa'?'آدرس شماره':'Address #'} ${i+1}</div>
        </div>
      </div>
      <button class="btn btn-danger btn-sm" onclick="deleteAddress(${i})" style="padding:4px 10px">x</button>
    </div>
  `).join('');
}

function showAddModal(){const ids=["new-label","new-limit","new-maxconn","new-addresses"];ids.forEach(i=>{const e=document.getElementById(i);if(e)e.value=""});document.getElementById("add-modal").classList.add("show");}

async function addAddresses(){
  const text=$('#new-address').value.trim();
  if(!text){toast(lang==='fa'?'حداقل یک آی‌پی یا دامنه وارد کنید':'Enter at least one IP or domain',true);return;}
  const lines=text.split('\n').map(l=>l.trim()).filter(l=>l);
  let added=0;let errors=0;
  for(const addr of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr)){errors++;continue;}
    try{
      const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});
      if(r.ok)added++;else errors++;
    }catch(e){errors++;}
  }
  if(added>0)toast(lang==='fa'?`تعداد ${added} آدرس اضافه شد`:`Added ${added} address(es)`);
  if(errors>0)toast(`${errors} failed`,true);
  if(added>0){$('#add-address-modal').classList.remove('show');await loadAddresses();}
}

async function deleteAddress(index){
  if(!confirm(lang==='fa'?'آیا از حذف این آدرس اطمینان دارید؟':'Delete this address?'))return;
  try{
    const r=await fetch(`/api/addresses/${index}`,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast(lang==='fa'?'حذف شد':'Deleted');
    await loadAddresses();
  }catch(e){toast('Error',true)}
}

async function deleteAllAddresses(){
  const msg = lang === 'fa' ? 'آیا از حذف تمام آی‌پی‌ها اطمینان دارید؟' : 'Are you sure you want to delete all addresses?';
  if(!confirm(msg)) return;
  try{
    const r = await fetch('/api/addresses', {method: 'DELETE'});
    if(!r.ok) throw new Error();
    toast(lang === 'fa' ? 'تمامی آی‌پی‌ها حذف شدند' : 'All addresses deleted');
    await loadAddresses();
  }catch(e){toast('Error',true)}
}

let chartLabels=[];let chartData=[];
function initChart(){
  const ctx=document.getElementById('trafficChart');if(!ctx)return;
  trafficChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(99,102,241,0.7)',borderColor:'#6366f1',borderWidth:1,borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false},ticks:{color:'rgba(255,255,255,0.3)',font:{size:10}}},y:{grid:{color:'rgba(255,255,255,0.05)'},ticks:{color:'rgba(255,255,255,0.3)',font:{size:10},callback:v=>v+' MB'},beginAtZero:true}}}});
}
initChart();
function updateChart(){
  if(!trafficChart||!statsData.hourly_traffic)return;
  const ht=statsData.hourly_traffic;
  const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
  const labels=sorted.map(e=>e[0]);
  const data=sorted.map(e=>Math.round(e[1]/1048576));
  trafficChart.data.labels=labels;trafficChart.data.datasets[0].data=data;
  trafficChart.update();
}
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
