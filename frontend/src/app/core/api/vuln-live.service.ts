import { Injectable, inject } from '@angular/core';
import { ApiConfigService } from './api-config.service';
import { AuthService } from '../auth/auth.service';

export interface VulnLiveAuth {
  authMode: string;
  bearerToken: string;
  basicUser: string;
  basicPass: string;
  cookieHeader: string;
}

export interface VulnLiveParams {
  target: string;
  modules: string;
  auth?: VulnLiveAuth;
}

@Injectable({ providedIn: 'root' })
export class VulnLiveService {
  private readonly api = inject(ApiConfigService);
  private readonly authService = inject(AuthService);

  buildUrl(params: VulnLiveParams): string {
    const query = new URLSearchParams({
      target: params.target,
      modules: params.modules
    });

    const auth = params.auth;
    if (auth) {
      if (auth.bearerToken.trim()) query.set('auth_bearer', auth.bearerToken.trim());
      if (auth.basicUser.trim()) query.set('auth_user', auth.basicUser.trim());
      if (auth.basicPass.trim()) query.set('auth_pass', auth.basicPass);
      if (auth.cookieHeader.trim()) query.set('auth_cookie', auth.cookieHeader.trim());
      query.set('auth_mode', auth.authMode);
    }

    const token = this.authService.getToken();
    if (token) query.set('token', token);

    return this.api.ws('/api/vuln/live', query);
  }
}
