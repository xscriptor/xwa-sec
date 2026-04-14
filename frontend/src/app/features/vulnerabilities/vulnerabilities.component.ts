import { Component, OnDestroy, ChangeDetectorRef, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { forkJoin } from 'rxjs';
import { ActivatedRoute } from '@angular/router';
import {
  VulnerabilitiesAnalysisSummaryComponent
} from './components/analysis-summary/analysis-summary.component';
import { VulnerabilitiesFindingsReportComponent } from './components/findings-report/findings-report.component';
import { VulnerabilitiesTargetConfigComponent } from './components/target-config/target-config.component';
import { VulnerabilitiesTerminalOutputComponent } from './components/terminal-output/terminal-output.component';
import {
  AnalysisSummary,
  ScanDetail,
  ScanListItem,
  TrendSnapshot
} from './models/vulnerabilities.models';

@Component({
  selector: 'app-vulnerabilities',
  standalone: true,
  imports: [
    CommonModule,
    VulnerabilitiesTargetConfigComponent,
    VulnerabilitiesTerminalOutputComponent,
    VulnerabilitiesAnalysisSummaryComponent,
    VulnerabilitiesFindingsReportComponent
  ],
  templateUrl: './vulnerabilities.component.html',
  styleUrls: ['./vulnerabilities.component.scss']
})
export class VulnerabilitiesComponent implements OnInit, OnDestroy {
  targetUrl = 'http://scanme.nmap.org';
  isScanning = false;
  socket: WebSocket | null = null;
  terminalLogs: string[] = ['[ SYSTEM READY ] Waiting for target config...'];

  authScanConfig = {
    authMode: 'bearer_first',
    bearerToken: '',
    basicUser: '',
    basicPass: '',
    cookieHeader: ''
  };

  private readonly authScanStorageKey = 'xwa-sec-auth-scan-config';
  
  activeModules: Record<string, boolean> = {
    tls: true,
    headers: true,
    cors: true,
    brute: true,
    sqli: true,
    sqlmap: true,
    xss: true,
    lfi: true,
    nuclei: true,
    playwright: true,
    api_security: true,
    auth_scan: true,
    js_secret: true
  };

  moduleOptions = [
    { key: 'tls', label: 'TLS', description: 'SSL/TLS protocol audit' },
    { key: 'headers', label: 'HEADERS', description: 'Security headers inspection' },
    { key: 'cors', label: 'CORS', description: 'Cross-origin policy validation' },
    { key: 'brute', label: 'PATH BRUTE', description: 'Sensitive path exposure checks' },
    { key: 'sqli', label: 'SQLI', description: 'Injection payloads against forms' },
    { key: 'sqlmap', label: 'SQLMAP', description: 'Automated SQLi verification via SQLMap' },
    { key: 'xss', label: 'XSS', description: 'Reflected script execution checks' },
    { key: 'lfi', label: 'LFI', description: 'Traversal/local file inclusion tests' },
    { key: 'nuclei', label: 'NUCLEI', description: 'Template-based web vulnerability matching' },
    { key: 'playwright', label: 'PLAYWRIGHT', description: 'JS surface and endpoint exposure analysis' },
    { key: 'api_security', label: 'API SECURITY', description: 'API docs/schema/method exposure and endpoint hygiene audit' },
    { key: 'auth_scan', label: 'AUTH SCAN', description: 'Authorization boundary probing on sensitive routes' },
    { key: 'js_secret', label: 'JS SECRET', description: 'Client-side JavaScript secret and token leakage analysis' }
  ];
  
  // Para mostrar los resultados como acordeón después
  completedScanDetails: ScanDetail | null = null;
  trendSnapshots: TrendSnapshot[] = [];

  constructor(private http: HttpClient, private cdr: ChangeDetectorRef, private route: ActivatedRoute) {}

  ngOnInit() {
    this.loadAuthScanConfigFromStorage();

    this.route.queryParamMap.subscribe((params) => {
      const scanId = Number(params.get('scanId'));
      if (Number.isInteger(scanId) && scanId > 0) {
        this.loadScanById(scanId);
      }

      const authModeParam = (params.get('authMode') || '').toLowerCase();
      if (authModeParam === 'basic_first' || authModeParam === 'bearer_first') {
        this.authScanConfig = {
          ...this.authScanConfig,
          authMode: authModeParam
        };
      }
    });
  }

  initiateCrawl() {
    if (this.isScanning) return;
    if (!this.targetUrl) return;

    this.isScanning = true;
    this.completedScanDetails = null; // Reset
    this.terminalLogs = [`[+] CONNECTING TO DAST ENGINE...`, `[*] Target: ${this.targetUrl}`];
    this.cdr.detectChanges();

    const activeKeys = this.allModulesActive
      ? 'all'
      : (Object.entries(this.activeModules).filter(([, v]) => v).map(([k]) => k).join(',') || 'all');

    const wsParams = new URLSearchParams({
      target: this.targetUrl,
      modules: activeKeys
    });

    if (this.authScanConfig.bearerToken.trim()) {
      wsParams.set('auth_bearer', this.authScanConfig.bearerToken.trim());
    }
    if (this.authScanConfig.basicUser.trim()) {
      wsParams.set('auth_user', this.authScanConfig.basicUser.trim());
    }
    if (this.authScanConfig.basicPass.trim()) {
      wsParams.set('auth_pass', this.authScanConfig.basicPass);
    }
    if (this.authScanConfig.cookieHeader.trim()) {
      wsParams.set('auth_cookie', this.authScanConfig.cookieHeader.trim());
    }
    wsParams.set('auth_mode', this.authScanConfig.authMode);

    const wsUrl = `ws://${window.location.hostname}:8000/api/vuln/live?${wsParams.toString()}`;
    this.socket = new WebSocket(wsUrl);

    this.socket.onmessage = (event) => {
      console.log("WS MESSAGE:", event.data);
      this.terminalLogs.push(event.data);
      this.cdr.detectChanges(); // Force UI update
    };

    this.socket.onclose = () => {
      console.log("WS CLOSED");
      this.terminalLogs.push('[!] CRAWLER FINISHED. Fetching database structure...');
      this.isScanning = false;
      this.cdr.detectChanges(); // Force UI update
      this.fetchLatestScan();
    };

    this.socket.onerror = (err) => {
      console.log("WS ERROR:", err);
      this.terminalLogs.push('[!] WEBSOCKET CONNECTION ERROR.');
      this.isScanning = false;
      this.cdr.detectChanges(); // Force update
    };
  }

  onAuthScanConfigChange(nextConfig: { authMode: string; bearerToken: string; basicUser: string; basicPass: string; cookieHeader: string }) {
    const normalizedMode = nextConfig.authMode === 'basic_first' ? 'basic_first' : 'bearer_first';

    this.authScanConfig = {
      ...nextConfig,
      authMode: normalizedMode
    };

    this.persistAuthScanConfig();
  }

  private persistAuthScanConfig() {
    try {
      localStorage.setItem(this.authScanStorageKey, JSON.stringify(this.authScanConfig));
    } catch {
      // Storage may be unavailable in restrictive browser contexts.
    }
  }

  private loadAuthScanConfigFromStorage() {
    try {
      const raw = localStorage.getItem(this.authScanStorageKey);
      if (!raw) return;

      const parsed = JSON.parse(raw) as Partial<{ authMode: string; bearerToken: string; basicUser: string; basicPass: string; cookieHeader: string }>;
      this.authScanConfig = {
        authMode: parsed.authMode === 'basic_first' ? 'basic_first' : 'bearer_first',
        bearerToken: parsed.bearerToken || '',
        basicUser: parsed.basicUser || '',
        basicPass: parsed.basicPass || '',
        cookieHeader: parsed.cookieHeader || ''
      };
    } catch {
      this.authScanConfig = {
        authMode: 'bearer_first',
        bearerToken: '',
        basicUser: '',
        basicPass: '',
        cookieHeader: ''
      };
    }
  }

  fetchLatestScan() {
    // Buscamos el último escaneo en el sistema para renderizar el árbol inmediatamente
    this.http.get<ScanListItem[]>(`http://${window.location.hostname}:8000/api/scans`).subscribe({
      next: (scans) => {
        if (scans && scans.length > 0) {
            this.fetchTrendFromRecentScans(scans);
            // Fetch detallado del último
              this.http.get<ScanDetail>(`http://${window.location.hostname}:8000/api/scans/${scans[0].id}`).subscribe({
                next: (detail) => {
                    this.completedScanDetails = detail;
                    this.cdr.detectChanges();
                }
            });
        }
      }
    });
  }

  private loadScanById(scanId: number) {
    this.http.get<ScanListItem[]>(`http://${window.location.hostname}:8000/api/scans`).subscribe({
      next: (scans) => {
        this.fetchTrendFromRecentScans(scans || []);
      }
    });

    this.http.get<ScanDetail>(`http://${window.location.hostname}:8000/api/scans/${scanId}`).subscribe({
      next: (detail) => {
        this.completedScanDetails = detail;
        this.targetUrl = detail.domain_target || this.targetUrl;
        this.isScanning = false;
        this.cdr.detectChanges();
      }
    });
  }

  toggleModule(moduleKey: string) {
    this.activeModules[moduleKey] = !this.activeModules[moduleKey];

    if (!Object.values(this.activeModules).some(Boolean)) {
      this.activeModules[moduleKey] = true;
    }
  }

  activateAllModules() {
    Object.keys(this.activeModules).forEach((key) => {
      this.activeModules[key] = true;
    });
  }

  get allModulesActive() {
    return Object.values(this.activeModules).every(Boolean);
  }

  get analysisSummary() {
    return this.buildSummary(this.completedScanDetails, this.terminalLogs.length);
  }

  get trendPolylinePoints() {
    if (!this.trendSnapshots.length) return '';

    const width = 320;
    const height = 64;
    const maxY = Math.max(...this.trendSnapshots.map(s => s.riskScore), 1);

    return this.trendSnapshots.map((snap, idx) => {
      const x = this.trendSnapshots.length === 1 ? width / 2 : (idx / (this.trendSnapshots.length - 1)) * width;
      const y = height - ((snap.riskScore / maxY) * height);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  }

  get trendLatestDelta() {
    if (this.trendSnapshots.length < 2) return null;
    const current = this.trendSnapshots[0].riskScore;
    const previous = this.trendSnapshots[1].riskScore;
    return current - previous;
  }

  private fetchTrendFromRecentScans(scans: ScanListItem[]) {
    const recent = scans.slice(0, 8).filter(s => s?.id);
    if (!recent.length) {
      this.trendSnapshots = [];
      return;
    }

    const requests = recent.map((scan) =>
      this.http.get<ScanDetail>(`http://${window.location.hostname}:8000/api/scans/${scan.id}`)
    );

    forkJoin(requests).subscribe({
      next: (details) => {
        this.trendSnapshots = details.map((detail, index) => {
          const summary = this.buildSummary(detail, 0);
          const label = recent[index]?.created_at ? String(recent[index].created_at).slice(5, 10) : `#${recent[index]?.id}`;
          return {
            id: recent[index].id,
            riskScore: summary?.riskScore ?? 0,
            totalFindings: summary?.totalFindings ?? 0,
            label
          };
        });
        this.cdr.detectChanges();
      },
      error: () => {
        this.trendSnapshots = [];
      }
    });
  }

  private buildSummary(scanDetails: ScanDetail | null, terminalEvents: number): AnalysisSummary | null {
    if (!scanDetails) return null;

    const links = scanDetails.discovered_links || [];
    const totalLinks = links.length;

    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let vulnerableLinks = 0;

    links.forEach((link) => {
      const findings = link.findings || [];
      if (findings.length > 0) {
        vulnerableLinks++;
      }

      findings.forEach((finding) => {
        if (finding.severity === 'critical') critical++;
        else if (finding.severity === 'high') high++;
        else if (finding.severity === 'medium') medium++;
        else low++;
      });
    });

    const totalFindings = critical + high + medium + low;
    const cleanLinks = Math.max(totalLinks - vulnerableLinks, 0);
    const coveragePct = totalLinks > 0 ? Math.round((vulnerableLinks / totalLinks) * 100) : 0;

    const weightedRisk = (critical * 4) + (high * 3) + (medium * 2) + low;
    const riskDenominator = Math.max(totalLinks * 4, 1);
    const riskScore = Math.min(100, Math.round((weightedRisk / riskDenominator) * 100));

    const avgFindingsPerLink = totalLinks > 0 ? (totalFindings / totalLinks).toFixed(1) : '0.0';

    return {
      totalLinks,
      vulnerableLinks,
      cleanLinks,
      totalFindings,
      critical,
      high,
      medium,
      low,
      coveragePct,
      riskScore,
      avgFindingsPerLink,
      terminalEvents
    };
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.close();
    }
  }
}
