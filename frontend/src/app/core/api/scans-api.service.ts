import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ApiConfigService } from './api-config.service';

export interface ScanListItem {
  id: number;
  scan_type?: string;
  created_at?: string;
  domain_target?: string;
  status?: string;
}

export interface ScanFinding {
  id?: number;
  scan_id?: number;
  link_id?: number | null;
  severity: string;
  finding_type: string;
  description: string;
  poc_payload?: string | null;
  cvss_score?: string | null;
}

export interface ScanDiscoveredLink {
  id: number;
  url: string;
  status_code: number;
  content_type: string;
  findings: ScanFinding[];
}

export interface ScanDetail {
  id: number;
  domain_target: string;
  status: string;
  scan_type: string;
  created_at?: string;
  findings?: ScanFinding[];
  discovered_links: ScanDiscoveredLink[];
}

@Injectable({ providedIn: 'root' })
export class ScansApiService {
  private readonly http = inject(HttpClient);
  private readonly api = inject(ApiConfigService);

  list(): Observable<ScanListItem[]> {
    return this.http.get<ScanListItem[]>(this.api.http('/api/scans'));
  }

  get<T = ScanDetail>(scanId: number): Observable<T> {
    return this.http.get<T>(this.api.http(`/api/scans/${scanId}`));
  }

  delete(scanId: number): Observable<unknown> {
    return this.http.delete(this.api.http(`/api/scans/${scanId}`));
  }

  cancel(scanId: number): Observable<unknown> {
    return this.http.post(this.api.http(`/api/scan/cancel/${scanId}`), {});
  }
}
