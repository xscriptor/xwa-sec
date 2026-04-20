import os
import json
from typing import Optional

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, joinedload
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler

from . import models, database, scanner, crawler
from .recon import perform_web_recon
from .auth.router import router as auth_router
from .auth.users_router import router as users_router
from .auth.deps import get_current_user, require_roles, get_current_user_ws
from .validators import validate_host_target, validate_url_target, InvalidTargetError
from .rate_limit import limiter

app = FastAPI(title="Samurai API", description="Deep Cybersecurity Analysis API", version="2.6.0")

_cors_origins_env = os.getenv("FRONTEND_ORIGIN", "http://localhost:4200")
ALLOWED_ORIGINS = [origin.strip() for origin in _cors_origins_env.split(",") if origin.strip()]


@app.on_event("startup")
def init_database():
    database.wait_for_db()


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(users_router)


@app.get("/")
def read_root():
    return {"status": "ok", "message": "Samurai Engine Running with WebSockets enabled"}


@app.websocket("/api/scan/live")
async def websocket_scan(
    websocket: WebSocket,
    target: str,
    profile: str = "quick",
    timeout: int = 180,
    web_scan: bool = False,
    collect_contacts: bool = False,
    scan_unsanitized: bool = False,
    max_pages: int = 10,
    token: Optional[str] = Query(default=None),
    db: Session = Depends(database.get_db),
):
    await websocket.accept()
    user = await get_current_user_ws(websocket, token, db)
    if user is None:
        return
    if user.role not in ("admin", "operator"):
        await websocket.close(code=1008, reason="Insufficient role")
        return
    try:
        target = validate_host_target(target)
    except InvalidTargetError as exc:
        await websocket.send_text(f"[!] {exc.detail}")
        await websocket.close(code=1008, reason="Invalid target")
        return
    try:
        await scanner.perform_nmap_scan(
            target,
            websocket,
            db,
            profile=profile,
            timeout_seconds=timeout,
            web_scan=web_scan,
            collect_contacts=collect_contacts,
            scan_unsanitized=scan_unsanitized,
            max_pages=max_pages,
        )
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_text(f"[!] CRITICAL ERROR: {str(e)}")
        await websocket.close()


@app.websocket("/api/vuln/live")
async def websocket_vuln_crawler(
    websocket: WebSocket,
    target: str,
    modules: str = "all",
    auth_mode: str = "bearer_first",
    auth_bearer: str = "",
    auth_user: str = "",
    auth_pass: str = "",
    auth_cookie: str = "",
    token: Optional[str] = Query(default=None),
    db: Session = Depends(database.get_db),
):
    await websocket.accept()
    user = await get_current_user_ws(websocket, token, db)
    if user is None:
        return
    if user.role not in ("admin", "operator"):
        await websocket.close(code=1008, reason="Insufficient role")
        return
    try:
        target = validate_url_target(target)
    except InvalidTargetError as exc:
        await websocket.send_text(f"[!] {exc.detail}")
        await websocket.close(code=1008, reason="Invalid target")
        return
    try:
        auth_context = {
            "mode": auth_mode,
            "bearer": auth_bearer,
            "user": auth_user,
            "password": auth_pass,
            "cookie": auth_cookie,
        }
        await crawler.perform_crawl(target, modules, websocket, db, auth_context)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_text(f"[!] CRITICAL ERROR: {str(e)}")
        await websocket.close()


@app.websocket("/api/recon/live")
async def websocket_recon(
    websocket: WebSocket,
    target: str,
    recon_types: str = "all",
    timeout: int = 300,
    token: Optional[str] = Query(default=None),
    db: Session = Depends(database.get_db),
):
    await websocket.accept()
    user = await get_current_user_ws(websocket, token, db)
    if user is None:
        return
    if user.role not in ("admin", "operator"):
        await websocket.close(code=1008, reason="Insufficient role")
        return

    try:
        target = validate_host_target(target)
    except InvalidTargetError as exc:
        await websocket.send_text(f"[LOG] [error] {exc.detail}")
        await websocket.close(code=1008, reason="Invalid target")
        return

    scan_record = None

    try:
        await websocket.send_text("[LOG] [init] recon session established")

        scan_record = models.Scan(
            domain_target=target,
            status="RUNNING",
            scan_type="web_recon",
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        await websocket.send_text(f"[SCAN_META] scan_id={scan_record.id}")

        recon_list = recon_types.split(",") if recon_types != "all" else ["all"]
        results = await perform_web_recon(
            target,
            recon_list,
            websocket,
            timeout_seconds=timeout,
        )

        if results:
            results_json = json.dumps(results, indent=2)
            finding = models.Finding(
                scan_id=scan_record.id,
                severity="info",
                finding_type="web_recon_results",
                description=f"Web reconnaissance results for {target}",
                poc_payload=results_json,
            )
            db.add(finding)

        scan_record.status = "COMPLETED"
        db.commit()
        await websocket.send_text("[done] scan completed and saved to history")

    except WebSocketDisconnect:
        if scan_record:
            scan_record.status = "CANCELLED"
            db.commit()
    except Exception as e:
        if scan_record:
            scan_record.status = "ERROR"
            db.commit()
        try:
            await websocket.send_text(f"[!] CRITICAL ERROR: {str(e)}")
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


# --- CRUD para historial de analisis (protegido) ---

@app.get("/api/scans")
def list_scans(
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(get_current_user),
):
    scans = db.query(models.Scan).order_by(models.Scan.id.desc()).all()
    return scans


@app.get("/api/scans/{scan_id}")
def get_scan_details(
    scan_id: int,
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(get_current_user),
):
    scan = (
        db.query(models.Scan)
        .options(
            joinedload(models.Scan.findings),
            joinedload(models.Scan.discovered_links).joinedload(models.DiscoveredLink.findings),
        )
        .filter(models.Scan.id == scan_id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.delete("/api/scans/{scan_id}")
def delete_scan(
    scan_id: int,
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(require_roles("admin", "operator")),
):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}


@app.post("/api/scan/cancel/{scan_id}")
def cancel_scan(
    scan_id: int,
    db: Session = Depends(database.get_db),
    _user: models.User = Depends(require_roles("admin", "operator")),
):
    cancelled = scanner.request_cancel_scan(scan_id, db)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Running scan not found")
    return {"status": "cancellation-requested", "scan_id": scan_id}
