import asyncio
from fastapi import WebSocket
from sqlalchemy.orm import Session
from . import models

async def perform_nmap_scan(target: str, websocket: WebSocket, db: Session):
    """
    Ejecuta un escaneo de Nmap superficial (Top 100 ports y versiones) 
    y transmite el progreso crudo línea a línea vía WebSocket.
    """
    # 1. Crear el registro MOCK en BD
    # (Para no ralentizar el test con un worker asíncrono puro, inyectaremos directo)
    scan_record = models.Scan(domain_target=target, status="RUNNING")
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    await websocket.send_text(f"[+] Starting nmap scan on target: {target}")
    
    # 2. Ejecutar nmap a nivel de OS
    process = await asyncio.create_subprocess_exec(
        "nmap", "-F", "-sV", target, # Fast scan, Service Detection
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )

    # 3. Leer la salida estándar en vivo
    open_ports_found = []
    
    if process.stdout:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text_line = line.decode('utf-8').rstrip()
            
            # Streaming crudo a la terminal Frontend
            await websocket.send_text(text_line)
            
            # Simple heurística para sacar info básica superficialmente como "hallazgo"
            if "/tcp" in text_line and "open" in text_line:
                open_ports_found.append(text_line)

    await process.wait()
    
    # 4. Guardar resultados y marcar como finalizado
    scan_record.status = "COMPLETED" if process.returncode == 0 else "ERROR"
    
    for port in open_ports_found:
        finding = models.Finding(
            scan_id=scan_record.id,
            severity="info",
            finding_type="OPEN_PORT",
            description=port
        )
        db.add(finding)
        
    db.commit()

    await websocket.send_text(f"[+] Scan #ID:{scan_record.id} COMPLETED. ({len(open_ports_found)} ports saved).")
    await websocket.close()
