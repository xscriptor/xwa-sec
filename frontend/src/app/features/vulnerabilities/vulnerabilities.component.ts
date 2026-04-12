import { Component, OnDestroy } from '@angular/core';
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
  
  // Para mostrar los resultados como acordeón después
  completedScanDetails: any = null;

  constructor(private http: HttpClient) {}

  initiateCrawl() {
    if (this.isScanning) return;
    if (!this.targetUrl) return;

    this.isScanning = true;
    this.completedScanDetails = null; // Reset
    this.terminalLogs = [`[+] CONNECTING TO VULNERABILITY CRAWLER...`, `[*] Target: ${this.targetUrl}`];

    const wsUrl = `ws://127.0.0.1:8000/api/vuln/live?target=${encodeURIComponent(this.targetUrl)}`;
    this.socket = new WebSocket(wsUrl);

    this.socket.onmessage = (event) => {
      this.terminalLogs.push(event.data);
      // Auto scroll logic would naturally be in CSS/JS but we push to array.
    };

    this.socket.onclose = () => {
      this.terminalLogs.push('[!] CRAWLER FINISHED. Fetching database structure...');
      this.isScanning = false;
      this.fetchLatestScan();
    };

    this.socket.onerror = (err) => {
      this.terminalLogs.push('[!] WEBSOCKET CONNECTION ERROR.');
      console.error('WS Error:', err);
      this.isScanning = false;
    };
  }

  fetchLatestScan() {
    // Buscamos el último escaneo en el sistema para renderizar el árbol inmediatamente
    this.http.get<any[]>('http://127.0.0.1:8000/api/scans').subscribe({
      next: (scans) => {
        if (scans && scans.length > 0) {
            // Fetch detallado del último
            this.http.get<any>(`http://127.0.0.1:8000/api/scans/${scans[0].id}`).subscribe({
                next: (detail) => {
                    this.completedScanDetails = detail;
                }
            });
        }
      }
    });
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.close();
    }
  }
}
