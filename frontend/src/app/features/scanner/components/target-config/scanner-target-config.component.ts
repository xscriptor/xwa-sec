import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-scanner-target-config',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scanner-target-config.component.html',
  styleUrls: ['./scanner-target-config.component.scss']
})
export class ScannerTargetConfigComponent {
  @Input() targetDomain = '';
  @Input() scanProfile: 'quick' | 'balanced' | 'deep' | 'udp' = 'quick';
  @Input() scanTimeout = 180;
  @Input() webAppSurfaceScan = true;
  @Input() collectContactIntel = true;
  @Input() detectUnsanitizedInputs = true;
  @Input() webMaxPages = 12;
  @Input() isScanning = false;
  @Input() currentScanId: number | null = null;

  @Output() targetDomainChange = new EventEmitter<string>();
  @Output() scanProfileChange = new EventEmitter<'quick' | 'balanced' | 'deep' | 'udp'>();
  @Output() scanTimeoutChange = new EventEmitter<number>();
  @Output() webAppSurfaceScanChange = new EventEmitter<boolean>();
  @Output() collectContactIntelChange = new EventEmitter<boolean>();
  @Output() detectUnsanitizedInputsChange = new EventEmitter<boolean>();
  @Output() webMaxPagesChange = new EventEmitter<number>();
  @Output() initiate = new EventEmitter<void>();
  @Output() cancel = new EventEmitter<void>();
}
