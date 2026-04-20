import { Injectable, inject } from '@angular/core';
import { ReconEnvelope, ReconModuleId } from '../models/recon.models';
import { ApiConfigService } from '../../../core/api/api-config.service';
import { AuthService } from '../../../core/auth/auth.service';

interface ReconStreamHandlers {
  onLog: (line: string) => void;
  onComplete: (message: ReconEnvelope) => void;
  onError: (message: string) => void;
  onUnexpectedClose: () => void;
}

@Injectable({ providedIn: 'root' })
export class ReconLiveService {
  private readonly apiConfig = inject(ApiConfigService);
  private readonly auth = inject(AuthService);
  private ws: WebSocket | null = null;
  private inactivityTimer: number | null = null;
  private readonly inactivityTimeoutMs = 45000;

  private clearInactivityTimer(): void {
    if (this.inactivityTimer !== null) {
      window.clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }
  }

  private armInactivityTimer(handlers: ReconStreamHandlers): void {
    this.clearInactivityTimer();
    this.inactivityTimer = window.setTimeout(() => {
      this.disconnect();
      handlers.onError('No response from recon engine. Check backend logs or restart the scan.');
    }, this.inactivityTimeoutMs);
  }

  private buildReconWsUrls(query: URLSearchParams): string[] {
    return this.apiConfig.wsFallbackChain('/api/recon/live', query);
  }

  private openSocket(wsUrls: string[], index: number, handlers: ReconStreamHandlers): void {
    const wsUrl = wsUrls[index];
    this.ws = new WebSocket(wsUrl);
    const socket = this.ws;
    let hasOpened = false;

    socket.onopen = () => {
      if (this.ws !== socket) {
        return;
      }

      hasOpened = true;
      handlers.onLog(index === 0 ? '[ws] connected to recon backend' : '[ws] connected to recon backend via proxy');
      this.armInactivityTimer(handlers);
    };

    socket.onmessage = (event) => {
      if (this.ws !== socket) {
        return;
      }

      this.armInactivityTimer(handlers);

      const payload = typeof event.data === 'string' ? event.data : String(event.data);
      try {
        const parsed = JSON.parse(payload) as ReconEnvelope;
        if (parsed.type === 'RECON_COMPLETE') {
          this.clearInactivityTimer();
          handlers.onComplete(parsed);
          return;
        }
        if (parsed.type === 'RECON_ERROR') {
          this.clearInactivityTimer();
          handlers.onError(parsed.error || 'Unknown recon error');
          return;
        }
      } catch {
        if (payload.startsWith('[LOG]')) {
          handlers.onLog(payload.slice(5).trimEnd());
          return;
        }
        handlers.onLog(payload);
      }
    };

    socket.onerror = () => {
      if (this.ws !== socket) {
        return;
      }

      this.clearInactivityTimer();

      if (!hasOpened && index + 1 < wsUrls.length) {
        handlers.onLog('[ws] direct backend failed, retrying via same-origin proxy');
        this.openSocket(wsUrls, index + 1, handlers);
        return;
      }

      handlers.onError('WebSocket connection error');
    };

    socket.onclose = () => {
      if (this.ws !== socket) {
        return;
      }

      this.clearInactivityTimer();

      if (!hasOpened && index + 1 < wsUrls.length) {
        this.openSocket(wsUrls, index + 1, handlers);
        return;
      }

      handlers.onUnexpectedClose();
    };
  }

  connect(target: string, modules: ReconModuleId[], handlers: ReconStreamHandlers): void {
    this.disconnect();

    const reconTypes = modules.join(',');
    const query = new URLSearchParams({
      target,
      recon_types: reconTypes,
      timeout: '300'
    });

    const token = this.auth.getToken();
    if (token) query.set('token', token);

    const wsUrls = this.buildReconWsUrls(query);
    this.openSocket(wsUrls, 0, handlers);
  }

  disconnect(): void {
    this.clearInactivityTimer();
    if (this.ws) {
      const socket = this.ws;
      this.ws = null;
      socket.close();
    }
  }
}
