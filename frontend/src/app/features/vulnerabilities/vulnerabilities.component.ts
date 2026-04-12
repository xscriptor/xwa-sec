import { Component, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './vulnerabilities.component.html',
  styleUrls: ['./vulnerabilities.component.scss']
})
export class VulnerabilitiesComponent implements OnDestroy {
  targetUrl = 'http://scanme.nmap.org';
  isScanning = false;
  socket: WebSocket | null = null;
  terminalLogs: string[] = ['[ SYSTEM READY ] Waiting for target config...'];
  
  activeModules = {
      tls: true,
      headers: true,
      cors: true,
      brute: true,
      sqli: true,
      xss: true,
      lfi: true
  };
  
  // Para mostrar los resultados como acordeón después
  completedScanDetails: any = null;

  constructor(private http: HttpClient, private cdr: ChangeDetectorRef) {}

  initiateCrawl() {
    if (this.isScanning) return;
    if (!this.targetUrl) return;

    this.isScanning = true;
    this.completedScanDetails = null; // Reset
    this.terminalLogs = [`[+] CONNECTING TO DAST ENGINE...`, `[*] Target: ${this.targetUrl}`];
    this.cdr.detectChanges();

    const activeKeys = Object.entries(this.activeModules).filter(([k,v]) => v).map(([k,v]) => k).join(',');
    const wsUrl = `ws://${window.location.hostname}:8000/api/vuln/live?target=${encodeURIComponent(this.targetUrl)}&modules=${activeKeys}`;
    this.socket = new WebSocket(wsUrl);

    this.socket.onmessage = (event) => {
      console.log("WS MESSAGE:", event.data);
      this.terminalLogs.push(event.data);
      this.cdr.detectChanges(); // Force UI update
    };

    this.socket.onclose = () => {
      console.log("WS CLOSED");
      this.terminalLogs.push('[!] CRAWLER FINISHED. Fetching database structure...');
      this.isScanning = false;
      this.cdr.detectChanges(); // Force UI update
      this.fetchLatestScan();
    };

    this.socket.onerror = (err) => {
      console.log("WS ERROR:", err);
      this.terminalLogs.push('[!] WEBSOCKET CONNECTION ERROR.');
      this.isScanning = false;
      this.cdr.detectChanges(); // Force update
    };
  }

  fetchLatestScan() {
    // Buscamos el último escaneo en el sistema para renderizar el árbol inmediatamente
    this.http.get<any[]>(`http://${window.location.hostname}:8000/api/scans`).subscribe({
      next: (scans) => {
        if (scans && scans.length > 0) {
            // Fetch detallado del último
            this.http.get<any>(`http://${window.location.hostname}:8000/api/scans/${scans[0].id}`).subscribe({
                next: (detail) => {
                    this.completedScanDetails = detail;
                    this.cdr.detectChanges();
                }
            });
        }
      }
    });
  }

  get scanStats() {
    if (!this.completedScanDetails || !this.completedScanDetails.discovered_links) return null;
    
    let critical = 0, high = 0, medium = 0, low = 0;
    let totalLinks = this.completedScanDetails.discovered_links.length;
    
    this.completedScanDetails.discovered_links.forEach((l: any) => {
       if (l.findings && l.findings.length) {
           l.findings.forEach((f: any) => {
               if(f.severity === 'critical') critical++;
               else if(f.severity === 'high') high++;
               else if(f.severity === 'medium') medium++;
               else low++;
           });
       }
    });

    return { 
        critical, high, medium, low, 
        totalLinks, 
        total: critical + high + medium + low 
    };
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.close();
    }
  }
}
