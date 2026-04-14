import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-scanner-terminal',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './scanner-terminal.component.html',
  styleUrls: ['./scanner-terminal.component.scss']
})
export class ScannerTerminalComponent {
  @Input() terminalLogs: string[] = [];
  @Input() isScanning = false;
}
