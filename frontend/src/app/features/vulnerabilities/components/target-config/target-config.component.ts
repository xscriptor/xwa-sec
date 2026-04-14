import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-vuln-target-config',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './target-config.component.html',
  styleUrls: ['./target-config.component.scss']
})
export class VulnerabilitiesTargetConfigComponent {
  @Input() isScanning = false;
  @Input() targetUrl = '';
  @Input() activeModules: Record<string, boolean> = {};
  @Input() allModulesActive = false;
  @Input() authScanConfig: { authMode: string; bearerToken: string; basicUser: string; basicPass: string; cookieHeader: string } = {
    authMode: 'bearer_first',
    bearerToken: '',
    basicUser: '',
    basicPass: '',
    cookieHeader: ''
  };
  @Input() moduleOptions: Array<{ key: string; label: string; description: string }> = [];

  @Output() targetUrlChange = new EventEmitter<string>();
  @Output() initiate = new EventEmitter<void>();
  @Output() moduleToggle = new EventEmitter<string>();
  @Output() activateAllModules = new EventEmitter<void>();
  @Output() authScanConfigChange = new EventEmitter<{ authMode: string; bearerToken: string; basicUser: string; basicPass: string; cookieHeader: string }>();

  patchAuthScanConfig(changes: Partial<{ authMode: string; bearerToken: string; basicUser: string; basicPass: string; cookieHeader: string }>) {
    this.authScanConfigChange.emit({
      ...this.authScanConfig,
      ...changes
    });
  }

  maskSensitive(value: string) {
    if (!value) return 'Not set';
    if (value.length <= 8) return '********';
    return `${value.slice(0, 4)}...${value.slice(-4)}`;
  }
}
