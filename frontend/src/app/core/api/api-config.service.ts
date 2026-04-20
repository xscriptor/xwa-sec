import { Injectable } from '@angular/core';
import { environment } from '../../../environments/environment';

@Injectable({ providedIn: 'root' })
export class ApiConfigService {
  get httpBase(): string {
    if (environment.apiBaseUrl) {
      return environment.apiBaseUrl.replace(/\/$/, '');
    }
    const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
    return `${protocol}//${window.location.hostname}:${environment.backendPort}`;
  }

  get wsBase(): string {
    if (environment.wsBaseUrl) {
      return environment.wsBaseUrl.replace(/\/$/, '');
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.hostname}:${environment.backendPort}`;
  }

  get sameOriginWsBase(): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}`;
  }

  http(path: string): string {
    return `${this.httpBase}${this.normalizePath(path)}`;
  }

  ws(path: string, params?: URLSearchParams): string {
    const query = params && params.toString() ? `?${params.toString()}` : '';
    return `${this.wsBase}${this.normalizePath(path)}${query}`;
  }

  wsFallbackChain(path: string, params?: URLSearchParams): string[] {
    const query = params && params.toString() ? `?${params.toString()}` : '';
    const normalized = this.normalizePath(path);
    const direct = `${this.wsBase}${normalized}${query}`;
    const sameOrigin = `${this.sameOriginWsBase}${normalized}${query}`;
    return Array.from(new Set([direct, sameOrigin]));
  }

  private normalizePath(path: string): string {
    return path.startsWith('/') ? path : `/${path}`;
  }
}
