from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, joinedload
from . import models, database, scanner, crawler

app = FastAPI(title="XWA Sec API", description="Deep Cybersecurity Analysis API", version="2.5.0")

@app.on_event("startup")
def init_database():
    database.wait_for_db()
    models.Base.metadata.create_all(bind=database.engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "ok", "message": "XWA Sec Engine Running with WebSockets enabled"}

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
    db: Session = Depends(database.get_db)
):
    await websocket.accept()
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
    db: Session = Depends(database.get_db)
):
    await websocket.accept()
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


# --- CRUD PARA HISTORIAL DE ANALISIS ---

@app.get("/api/scans")
def list_scans(db: Session = Depends(database.get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.id.desc()).all()
    return scans

@app.get("/api/scans/{scan_id}")
def get_scan_details(scan_id: int, db: Session = Depends(database.get_db)):
    scan = db.query(models.Scan)\
             .options(joinedload(models.Scan.findings),\
                      joinedload(models.Scan.discovered_links).joinedload(models.DiscoveredLink.findings))\
             .filter(models.Scan.id == scan_id)\
             .first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(database.get_db)):
    scan = db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}


@app.post("/api/scan/cancel/{scan_id}")
def cancel_scan(scan_id: int, db: Session = Depends(database.get_db)):
    cancelled = scanner.request_cancel_scan(scan_id, db)
    if not cancelled:
        raise HTTPException(status_code=404, detail="Running scan not found")
    return {"status": "cancellation-requested", "scan_id": scan_id}
