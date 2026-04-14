import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-scanner-export-actions',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './scanner-export-actions.component.html',
  styleUrls: ['./scanner-export-actions.component.scss']
})
export class ScannerExportActionsComponent {
  @Input() hasExports = false;

  @Output() exportCsv = new EventEmitter<void>();
  @Output() exportJson = new EventEmitter<void>();
  @Output() exportPdf = new EventEmitter<void>();
  @Output() exportBinary = new EventEmitter<void>();
}
