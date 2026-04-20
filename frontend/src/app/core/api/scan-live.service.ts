import { Injectable, inject } from '@angular/core';
import { ApiConfigService } from './api-config.service';
import { AuthService } from '../auth/auth.service';

export interface ScanLiveParams {
  target: string;
  profile: 'quick' | 'balanced' | 'deep' | 'udp';
  timeout: number;
  web_scan: boolean;
  collect_contacts: boolean;
  scan_unsanitized: boolean;
  max_pages: number;
}

@Injectable({ providedIn: 'root' })
export class ScanLiveService {
  private readonly api = inject(ApiConfigService);
  private readonly auth = inject(AuthService);

  buildUrl(params: ScanLiveParams): string {
    const query = new URLSearchParams({
      target: params.target,
      profile: params.profile,
      timeout: String(params.timeout),
      web_scan: String(params.web_scan),
      collect_contacts: String(params.collect_contacts),
      scan_unsanitized: String(params.scan_unsanitized),
      max_pages: String(params.max_pages)
    });
    const token = this.auth.getToken();
    if (token) query.set('token', token);
    return this.api.ws('/api/scan/live', query);
  }
}
