import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-scanner-metrics',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './scanner-metrics.component.html',
  styleUrls: ['./scanner-metrics.component.scss']
})
export class ScannerMetricsComponent {
  @Input() vulnerabilitiesFound = 0;
  @Input() contactsFound = 0;
  @Input() unsanitizedFindings = 0;
  @Input() latestOpenPortDelta: number | null = null;
  @Input() openPortsDetailed: Array<{ token: string; service: string; version: string }> = [];
}
