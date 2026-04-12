from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from . import models, database, scanner
import os

app = FastAPI(title="XWA Sec API", description="Deep Cybersecurity Analysis API", version="2.0.0")

# Auto-crear base de datos al inicio
models.Base.metadata.create_all(bind=database.engine)

# CORS config
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
async def websocket_scan(websocket: WebSocket, target: str, db: Session = Depends(database.get_db)):
    await websocket.accept()
    try:
        # Llamar a la rutina asíncrona de nmap pasando el websocket y bd sincronos para guardar logs
        await scanner.perform_nmap_scan(target, websocket, db)
    except WebSocketDisconnect:
        print(f"User disconnected from socket before scan finished.")
    except Exception as e:
        await websocket.send_text(f"[!] CRITICAL ERROR: {str(e)}")
        await websocket.close()

# Keep compatibility with old dashboard
@app.get("/api/scan/status/history")
def get_recent_scans(db: Session = Depends(database.get_db)):
    scans = db.query(models.Scan).order_by(models.Scan.id.desc()).limit(10).all()
    return scans
