import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { ReconResults } from '../../models/recon.models';
import { ReconApiResultsComponent } from './components/recon-api-results.component';
import { ReconDnsResultsComponent } from './components/recon-dns-results.component';
import { ReconHeadersResultsComponent } from './components/recon-headers-results.component';
import { ReconSubdomainsResultsComponent } from './components/recon-subdomains-results.component';
import { ReconTechResultsComponent } from './components/recon-tech-results.component';

@Component({
  selector: 'app-recon-results',
  standalone: true,
  imports: [
    CommonModule,
    ReconDnsResultsComponent,
    ReconSubdomainsResultsComponent,
    ReconApiResultsComponent,
    ReconHeadersResultsComponent,
    ReconTechResultsComponent
  ],
  templateUrl: './recon-results.component.html',
  styleUrl: './recon-results.component.scss'
})
export class ReconResultsComponent {
  @Input() results: ReconResults | null = null;

  hasAnyResults(): boolean {
    return !!this.results && Object.values(this.results).some((section) => this.hasContent(section));
  }

  availableSections(): number {
    if (!this.results) {
      return 0;
    }

    return Object.values(this.results).filter((section) => this.hasContent(section)).length;
  }

  dnsTotal(): number {
    return Object.values(this.results?.dns || {}).reduce((total, records) => total + records.length, 0);
  }

  subdomainTotal(): number {
    const subdomains = this.results?.subdomains;
    if (!subdomains) {
      return 0;
    }

    return subdomains.total_found || subdomains.discovered_count || 0;
  }

  subdomainActiveTotal(): number {
    const subdomains = this.results?.subdomains;
    if (!subdomains) {
      return 0;
    }

    return subdomains.active_count ?? Object.keys(subdomains.active || {}).length;
  }

  apiTotal(): number {
    return this.results?.apis?.apis_found.length || 0;
  }

  apiProbeTotal(): number {
    return this.results?.apis?.probed_paths || 0;
  }

  documentationTotal(): number {
    return this.results?.apis?.documentation.length || 0;
  }

  headerPresentTotal(): number {
    return Object.keys(this.results?.headers?.present || {}).length;
  }

  headerMissingTotal(): number {
    return this.results?.headers?.missing.length || 0;
  }

  techSignalTotal(): number {
    const tech = this.results?.technology;
    if (!tech) {
      return 0;
    }

    return tech.frontend.length + tech.backend.length + (tech.cdn ? 1 : 0) + tech.interesting_findings.length;
  }

  private hasContent(section: unknown): boolean {
    if (!section) {
      return false;
    }

    if (Array.isArray(section)) {
      return section.length > 0;
    }

    if (typeof section === 'object') {
      return Object.values(section as Record<string, unknown>).some((value) => {
        if (Array.isArray(value)) {
          return value.length > 0;
        }

        if (value && typeof value === 'object') {
          return Object.keys(value as Record<string, unknown>).length > 0;
        }

        return value !== null && value !== undefined && value !== '';
      });
    }

    return true;
  }
}
