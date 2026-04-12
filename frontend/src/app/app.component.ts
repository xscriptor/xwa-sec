import { Component, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnDestroy {
  targetDomain = 'scanme.nmap.org';
  isScanning = false;
  socket: WebSocket | null = null;
  terminalLogs: string[] = ['[ SYSTEM READY ] Waiting for target config...'];

  vulnerabilitiesFound = 0;

  initiateScan() {
    if (this.isScanning) return;
    if (!this.targetDomain) return;

    this.isScanning = true;
    this.terminalLogs = [`[+] CONNECTING TO ENGINE FOR SCANNING: ${this.targetDomain}...`];
    this.vulnerabilitiesFound = 0;

    const wsUrl = `ws://127.0.0.1:8000/api/scan/live?target=${encodeURIComponent(this.targetDomain)}`;
    this.socket = new WebSocket(wsUrl);

    this.socket.onmessage = (event) => {
      this.terminalLogs.push(event.data);
      // Auto-extract metrics basically
      if (event.data.includes('open')) {
        this.vulnerabilitiesFound++;
      }
    };

    this.socket.onclose = () => {
      this.terminalLogs.push('[!] CONNECTION CLOSED. Scan finished.');
      this.isScanning = false;
    };

    this.socket.onerror = (err) => {
      this.terminalLogs.push('[!] WEBSOCKET CONNECTION ERROR.');
      console.error('WS Error:', err);
      this.isScanning = false;
    };
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.close();
    }
  }
}
