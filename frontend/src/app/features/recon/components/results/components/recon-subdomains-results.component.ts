import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-recon-subdomains-results',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './recon-subdomains-results.component.html',
  styleUrl: './recon-subdomains-results.component.scss'
})
export class ReconSubdomainsResultsComponent {
  @Input() subdomains:
    | {
        active: Record<string, string[]>;
        discovered_count: number;
        total_found: number;
        active_count?: number;
        discovered_hosts?: string[];
      }
    | undefined;

  activeEntries(): Array<[string, string[]]> {
    return Object.entries(this.subdomains?.active || {});
  }

  discoveredHosts(): string[] {
    return this.subdomains?.discovered_hosts || [];
  }

  activeCount(): number {
    if (!this.subdomains) {
      return 0;
    }

    return this.subdomains.active_count ?? this.activeEntries().length;
  }

  totalDiscovered(): number {
    return this.subdomains?.total_found || this.subdomains?.discovered_count || 0;
  }

  isActive(host: string): boolean {
    return !!this.subdomains?.active?.[host];
  }
}
