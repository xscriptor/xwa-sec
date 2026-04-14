import asyncio
import re
from fastapi import WebSocket
from sqlalchemy.orm import Session
from . import models

PORT_OPEN_PATTERN = re.compile(r"^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.*))?$", re.IGNORECASE)

NMAP_PROFILES = {
    "quick": ["-F", "-sV", "-T3"],
    "balanced": ["-sV", "--top-ports", "1000", "-T3"],
    "deep": ["-sV", "-sC", "--top-ports", "2000", "-T4"],
    "udp": ["-sU", "--top-ports", "200", "-T3"],
}

async def perform_nmap_scan(target: str, websocket: WebSocket, db: Session, profile: str = "quick", timeout_seconds: int = 180):
    """
    Ejecuta un escaneo de Nmap superficial (Top 100 ports y versiones) 
    y transmite el progreso crudo línea a línea vía WebSocket.
    """
    # 1. Crear el registro MOCK en BD
    # (Para no ralentizar el test con un worker asíncrono puro, inyectaremos directo)
    selected_profile = profile if profile in NMAP_PROFILES else "quick"
    selected_args = NMAP_PROFILES[selected_profile]
    effective_timeout = max(30, min(timeout_seconds, 900))

    scan_record = models.Scan(domain_target=target, status="RUNNING", scan_type=f"port_scan:{selected_profile}")
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    await websocket.send_text(f"[+] Starting nmap scan on target: {target}")
    await websocket.send_text(f"[i] Profile: {selected_profile} | Timeout: {effective_timeout}s")
    
    # 2. Ejecutar nmap a nivel de OS
    try:
        process = await asyncio.create_subprocess_exec(
            "nmap", *selected_args, target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
    except FileNotFoundError:
        scan_record.status = "ERROR"
        db.commit()
        await websocket.send_text("[!] Nmap binary not found in runtime environment.")
        await websocket.close()
        return

    # 3. Leer la salida estándar en vivo
    open_ports_found = {}
    timed_out = False
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    
    if process.stdout:
        while True:
            if loop.time() - start_ts > effective_timeout:
                timed_out = True
                await websocket.send_text(f"[!] Scan timeout reached ({effective_timeout}s). Stopping nmap process...")
                process.terminate()
                break

            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if not line:
                break
            text_line = line.decode('utf-8').rstrip()
            
            # Streaming crudo a la terminal Frontend
            await websocket.send_text(text_line)
            
            # Simple heurística para sacar info básica superficialmente como "hallazgo"
            match = PORT_OPEN_PATTERN.match(text_line.strip())
            if match:
                port = match.group(1)
                proto = match.group(2).lower()
                service = (match.group(3) or "unknown").strip()
                version = (match.group(4) or "").strip()
                open_ports_found[f"{port}/{proto}"] = {
                    "port": port,
                    "proto": proto,
                    "service": service,
                    "version": version,
                    "raw": text_line,
                }

    try:
        await asyncio.wait_for(process.wait(), timeout=8)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
    
    # 4. Guardar resultados y marcar como finalizado
    if timed_out:
        scan_record.status = "ERROR"
    else:
        scan_record.status = "COMPLETED" if process.returncode == 0 else "ERROR"
    
    for key in sorted(open_ports_found.keys()):
        parsed = open_ports_found[key]
        finding = models.Finding(
            scan_id=scan_record.id,
            severity="info",
            finding_type="OPEN_PORT",
            description=parsed["raw"],
            poc_payload=f"port={parsed['port']}\nprotocol={parsed['proto']}\nservice={parsed['service']}\nversion={parsed['version']}"
        )
        db.add(finding)
        
    db.commit()

    status_label = "TIMEOUT" if timed_out else scan_record.status
    await websocket.send_text(f"[+] Scan #ID:{scan_record.id} {status_label}. ({len(open_ports_found)} open ports saved).")
    await websocket.close()
