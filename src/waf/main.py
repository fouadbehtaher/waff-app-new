import structlog
import asyncio
import json
import os
from pathlib import Path
from pydantic import BaseModel
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

from config import settings
from proxy import WAFProxy
from models.request import WAFMetrics
from request_log import request_logger
from ai_engine.ip_blacklist import ip_blacklist
from strategies.rate_limiter import rate_limiter
from waf_config import waf_config
from database import waf_db
from async_database import async_waf_db
from redis_cache import redis_cache
from ml_model import waf_ml_model
from auto_signatures import auto_signature_generator
from tls_config import TLSConfig, generate_self_signed_cert

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        0 if settings.DEBUG else 20
    ),
)

logger = structlog.get_logger()

BASE_DIR = Path(__file__).parent.resolve()

tls_config = TLSConfig(
    cert_path=settings.TLS_CERT_PATH,
    key_path=settings.TLS_KEY_PATH,
    ca_path=settings.TLS_CA_PATH
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.USE_ASYNC_DB:
        await async_waf_db.initialize()
    if settings.USE_REDIS and settings.REDIS_URL:
        await redis_cache.connect()
    logger.info("waf_startup_complete", async_db=settings.USE_ASYNC_DB, redis=settings.USE_REDIS)
    yield
    if settings.USE_ASYNC_DB:
        await async_waf_db.close()
    if redis_cache.is_connected():
        await redis_cache.close()
    for ws in active_websockets:
        await ws.close()
    active_websockets.clear()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Based Web Application Firewall - Reverse Proxy with AI-powered threat analysis",
    lifespan=lifespan
)

static_dir = BASE_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

waf_proxy = WAFProxy()

active_websockets: set = set()


class BanRequest(BaseModel):
    ip: str
    reason: str = "manual"
    permanent: bool = False


class WAFConfigUpdate(BaseModel):
    updates: dict


class CustomPatternRequest(BaseModel):
    category: str
    pattern: str
    name: str
    threat_level: str = "high"


class WhitelistRequest(BaseModel):
    ip: str = ""
    path: str = ""


class MLTrainRequest(BaseModel):
    epochs: int = 100
    learning_rate: float = 0.01


class TLSCertRequest(BaseModel):
    days: int = 365


@app.get("/")
async def dashboard():
    dashboard_file = BASE_DIR / "static" / "dashboard.html"
    with open(dashboard_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/health")
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION}


@app.get("/waf/health")
async def waf_health():
    return await waf_proxy.health_check()


@app.get("/waf/metrics")
async def waf_metrics():
    return waf_proxy.get_metrics()


@app.get("/waf/stats")
async def waf_stats():
    return waf_proxy.get_analysis_stats()


@app.get("/dashboard/summary")
async def dashboard_summary():
    if settings.USE_ASYNC_DB:
        return await async_waf_db.get_summary()
    return waf_db.get_summary()


@app.get("/dashboard/logs")
async def dashboard_logs(limit: int = 50, offset: int = 0, decision: str = None, threat: str = None, ip: str = None):
    if settings.USE_ASYNC_DB:
        return await async_waf_db.get_logs(limit=limit, offset=offset, decision_filter=decision, threat_filter=threat, ip_filter=ip)
    return waf_db.get_logs(limit=limit, offset=offset, decision_filter=decision, threat_filter=threat, ip_filter=ip)


@app.get("/dashboard/timeline")
async def dashboard_timeline(minutes: int = 60):
    if settings.USE_ASYNC_DB:
        return await async_waf_db.get_timeline(minutes=minutes)
    return waf_db.get_timeline(minutes=minutes)


@app.get("/dashboard/strategies")
async def dashboard_strategies():
    if settings.USE_ASYNC_DB:
        return await async_waf_db.get_strategy_stats()
    return waf_db.get_strategy_stats()


@app.post("/dashboard/seed")
async def dashboard_seed():
    return request_logger.seed_sample_data()


@app.get("/security/blacklist")
async def get_blacklist():
    if settings.USE_REDIS and redis_cache.is_connected():
        return await redis_cache.blacklist_get_all()
    return waf_db.blacklist_get_all()


@app.get("/security/blacklist/stats")
async def blacklist_stats():
    if settings.USE_REDIS and redis_cache.is_connected():
        return await redis_cache.blacklist_get_stats()
    return waf_db.blacklist_get_stats()


@app.post("/security/blacklist")
async def ban_ip(req: BanRequest):
    if settings.USE_REDIS and redis_cache.is_connected():
        await redis_cache.blacklist_ban(req.ip, req.reason, req.permanent)
    waf_db.blacklist_ban(req.ip, req.reason, req.permanent)
    ip_blacklist.ban_ip(req.ip, req.reason, req.permanent)
    return {"status": "banned", "ip": req.ip, "permanent": req.permanent}


@app.delete("/security/blacklist/{ip}")
async def unban_ip(ip: str):
    if settings.USE_REDIS and redis_cache.is_connected():
        await redis_cache.blacklist_unban(ip)
    waf_db.blacklist_unban(ip)
    ip_blacklist.unban_ip(ip)
    return {"status": "unbanned", "ip": ip}


@app.post("/security/blacklist/{ip}/whitelist")
async def whitelist_ip(ip: str):
    ip_blacklist.whitelist_ip(ip)
    return {"status": "whitelisted", "ip": ip}


@app.get("/security/blacklist/{ip}")
async def ip_history(ip: str):
    return ip_blacklist.get_ip_history(ip)


@app.get("/security/rate-limits")
async def rate_limit_stats():
    if settings.USE_REDIS and redis_cache.is_connected():
        return await redis_cache.rate_limit_get_stats()
    return rate_limiter.get_stats()


@app.get("/security/rate-limits/top-ips")
async def rate_limit_top_ips(limit: int = 10):
    if settings.USE_REDIS and redis_cache.is_connected():
        return await redis_cache.rate_limit_top_ips(limit=limit)
    return rate_limiter.get_top_ips(limit)


@app.get("/security/rate-limits/{ip}")
async def ip_rate_info(ip: str):
    return {
        "ip": ip,
        "requests": rate_limiter.get_request_count(ip),
        "remaining": rate_limiter.get_remaining_requests(ip),
        "reset_seconds": rate_limiter.get_reset_time(ip)
    }


@app.get("/security/overview")
async def security_overview():
    bl_stats = await redis_cache.blacklist_get_stats() if (settings.USE_REDIS and redis_cache.is_connected()) else waf_db.blacklist_get_stats()
    rl_stats = await redis_cache.rate_limit_get_stats() if (settings.USE_REDIS and redis_cache.is_connected()) else rate_limiter.get_stats()
    return {
        "blacklist": bl_stats,
        "rate_limiter": rl_stats,
        "waf_metrics": waf_proxy.get_metrics(),
        "redis_connected": redis_cache.is_connected(),
        "async_db_enabled": settings.USE_ASYNC_DB
    }


@app.get("/ml/model")
async def get_ml_model():
    return waf_ml_model.get_model_info()


@app.post("/ml/train")
async def train_ml_model(req: MLTrainRequest = None):
    epochs = req.epochs if req else 100
    lr = req.learning_rate if req else 0.01
    if settings.USE_ASYNC_DB:
        training_data = await async_waf_db.get_ml_training_data(limit=10000)
    else:
        training_data = []
    if not training_data:
        return {"status": "no_data", "message": "No training data available. Process some traffic first."}
    result = waf_ml_model.train(training_data, epochs=epochs, learning_rate=lr)
    return result


@app.post("/ml/predict")
async def predict_request(request: Request):
    body = await request.body()
    body_preview = body[:500].decode("utf-8", errors="ignore") if body else ""
    features = waf_ml_model.extract_features(
        method=request.method,
        path=str(request.url.path),
        query_string=str(request.url.query) if request.url.query else "",
        body_preview=body_preview
    )
    prediction = waf_ml_model.predict(features)
    return {"features": features, "prediction": prediction}


@app.get("/auto-signatures")
async def get_auto_signatures(status: str = None):
    return auto_signature_generator.get_rules(status=status)


@app.get("/auto-signatures/stats")
async def auto_signature_stats():
    return auto_signature_generator.get_stats()


@app.post("/auto-signatures/analyze")
async def analyze_for_signatures():
    logs = await async_waf_db.get_logs(limit=500, decision_filter="block") if settings.USE_ASYNC_DB else waf_db.get_logs(limit=500, decision_filter="block")
    new_patterns = auto_signature_generator.analyze_and_generate(logs)
    return {"status": "analysis_complete", "new_patterns": len(new_patterns), "patterns": new_patterns}


@app.post("/auto-signatures/{index}/approve")
async def approve_signature(index: int):
    return auto_signature_generator.approve_rule(index)


@app.post("/auto-signatures/{index}/reject")
async def reject_signature(index: int):
    return auto_signature_generator.reject_rule(index)


@app.delete("/auto-signatures/{index}")
async def delete_signature(index: int):
    return auto_signature_generator.delete_rule(index)


@app.get("/tls/info")
async def tls_info():
    return tls_config.get_info()


@app.post("/tls/generate-cert")
async def generate_cert(req: TLSCertRequest = None):
    days = req.days if req else 365
    cert_path = str(BASE_DIR / "certs" / "waf.crt")
    key_path = str(BASE_DIR / "certs" / "waf.key")
    success = generate_self_signed_cert(cert_path, key_path, days=days)
    if success:
        return {"status": "generated", "cert_path": cert_path, "key_path": key_path, "days": days}
    return {"status": "failed", "message": "cryptography package not installed"}


@app.get("/waf/config")
async def get_waf_config():
    return waf_config.get()


@app.post("/waf/config")
async def update_waf_config(req: WAFConfigUpdate):
    return waf_config.update(req.updates)


@app.post("/waf/config/reset")
async def reset_waf_config():
    waf_proxy.reload_strategies()
    return waf_config.reset()


@app.post("/waf/config/strategy/{name}/toggle")
async def toggle_strategy(name: str, enabled: bool = True):
    waf_config.toggle_strategy(name, enabled)
    waf_proxy.reload_strategies()
    return waf_config.get()


@app.post("/waf/config/patterns")
async def add_pattern(req: CustomPatternRequest):
    return waf_config.add_custom_pattern(req.category, req.pattern, req.name, req.threat_level)


@app.delete("/waf/config/patterns/{index}")
async def remove_pattern(index: int):
    return waf_config.remove_custom_pattern(index)


@app.get("/waf/config/patterns")
async def get_patterns():
    return waf_config.get_custom_patterns()


@app.post("/waf/config/whitelist/ip/{ip}")
async def whitelist_ip(ip: str):
    return waf_config.add_whitelist_ip(ip)


@app.delete("/waf/config/whitelist/ip/{ip}")
async def remove_whitelist_ip(ip: str):
    return waf_config.remove_whitelist_ip(ip)


@app.post("/waf/config/whitelist/path")
async def whitelist_path(req: WhitelistRequest):
    return waf_config.add_whitelist_path(req.path)


@app.delete("/waf/config/whitelist/path")
async def remove_whitelist_path(req: WhitelistRequest):
    return waf_config.remove_whitelist_path(req.path)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": asyncio.get_event_loop().time()})
    except WebSocketDisconnect:
        active_websockets.remove(websocket)


def broadcast_update(data: dict):
    disconnected = set()
    for ws in active_websockets:
        try:
            asyncio.create_task(ws.send_json(data))
        except Exception:
            disconnected.add(ws)
    active_websockets.difference_update(disconnected)


request_logger.subscribe(broadcast_update)


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def waf_proxy_handler(request: Request):
    client_ip = request.client.host if request.client else "unknown"
    forwarded_for = request.headers.get("x-forwarded-for", "")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()

    path = str(request.url.path)
    if waf_config.is_path_whitelisted(path):
        return await waf_proxy.forward_request(request)

    block_response = waf_proxy.check_ip_blacklist(client_ip)
    if block_response:
        return block_response

    rate_limit_response = waf_proxy.check_rate_limit(client_ip)
    if rate_limit_response:
        return rate_limit_response

    analysis = await waf_proxy.analyze_request(request)

    if analysis.overall_decision.value == "block":
        return waf_proxy.get_block_response(analysis)

    return await waf_proxy.forward_request(request)


if __name__ == "__main__":
    import uvicorn
    ssl_ctx = tls_config.create_ssl_context()
    kwargs = {"app": "main:app", "host": "0.0.0.0", "port": 8443 if ssl_ctx else 8000, "reload": settings.DEBUG}
    if ssl_ctx and settings.TLS_CERT_PATH and settings.TLS_KEY_PATH:
        kwargs["ssl_keyfile"] = settings.TLS_KEY_PATH
        kwargs["ssl_certfile"] = settings.TLS_CERT_PATH
    uvicorn.run(**kwargs)
