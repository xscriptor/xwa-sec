import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from fastapi import WebSocket
from sqlalchemy.orm import Session
from . import models

async def perform_crawl(target_url: str, websocket: WebSocket, db: Session):
    """
    Simula un Crawler asíncrono que navega recursivamente descubriendo sub-enlaces,
    emitiéndolos por WebSocket y grabándolos en la DB.
    """
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    parsed_target = urlparse(target_url)
    domain = parsed_target.netloc

    scan_record = models.Scan(domain_target=target_url, status="RUNNING", scan_type="crawler")
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    await websocket.send_text(f"[+] Initiating deep crawler on: {target_url}")
    
    visited = set()
    to_visit = [target_url]
    max_pages = 15 # Limit para la demostración
    
    links_discovered = 0
    vulns_found = 0

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
            
        visited.add(current_url)
        await websocket.send_text(f"[*] Scanning DOM: {current_url} ...")
        
        try:
            # Uso de to_thread para no bloquear el loop principal de FastAPI
            response = await asyncio.to_thread(requests.get, current_url, timeout=5)
            status_code = response.status_code
            
            # Guardamos el link descubierto
            db_link = models.DiscoveredLink(
                scan_id=scan_record.id,
                url=current_url,
                status_code=status_code,
                content_type=response.headers.get("Content-Type", "Unknown")
            )
            db.add(db_link)
            db.commit()
            db.refresh(db_link)
            
            links_discovered += 1

            # Busqueda de Vulnerabilidades Superficiales en este Link
            if "text/html" in db_link.content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check 1: Formularios con contraseña
                forms = soup.find_all("form")
                for form in forms:
                    password_inputs = form.find_all("input", type="password")
                    if password_inputs and not current_url.startswith("https"):
                        vulns_found += 1
                        finding = models.Finding(
                            scan_id=scan_record.id,
                            link_id=db_link.id,
                            severity="high",
                            finding_type="INSECURE_LOGIN",
                            description="Password prompt served over unencrypted HTTP"
                        )
                        db.add(finding)
                        await websocket.send_text(f"    [!] VULNERABILITY DETECTED: Insecure login form")

                # Parsear sub-enlaces para alimentar el Crawler
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    full_url = urljoin(current_url, href)
                    
                    if urlparse(full_url).netloc == domain and full_url not in visited:
                        to_visit.append(full_url)
                        await websocket.send_text(f"    [+] Discovered Link (Added to queue): {href}")
            
        except Exception as e:
            await websocket.send_text(f"    [-] Request Error: {str(e)}")

    db.commit()
    
    # Finalizar
    scan_record.status = "COMPLETED"
    db.commit()

    await websocket.send_text(f"")
    await websocket.send_text(f"[+] Crawler #ID:{scan_record.id} COMPLETED.")
    await websocket.send_text(f"- Total Links Scanned: {links_discovered}")
    await websocket.send_text(f"- Issues Detected: {vulns_found}")
    await websocket.close()
