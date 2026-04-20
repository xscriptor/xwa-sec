import { Component, OnDestroy, ChangeDetectorRef, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute } from '@angular/router';
import { forkJoin } from 'rxjs';
import { ScansApiService } from '../../core/api/scans-api.service';
import { ScanLiveService } from '../../core/api/scan-live.service';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { gzip } from 'pako';
import { ScannerTargetConfigComponent } from './components/target-config/scanner-target-config.component';
import { ScannerMetricsComponent } from './components/metrics/scanner-metrics.component';
import { ScannerHistoryComponent } from './components/history/scanner-history.component';
import { ScannerTerminalComponent } from './components/terminal/scanner-terminal.component';
import { ScannerExportActionsComponent } from './components/export-actions/scanner-export-actions.component';
import { ScannerReportComponent } from './components/report/scanner-report.component';

interface ScanListItem {
  id: number;
  scan_type?: string;
  created_at?: string;
  domain_target?: string;
  status?: string;
}

interface FindingItem {
  id?: number;
  scan_id?: number;
  link_id?: number | null;
  severity: string;
  finding_type: string;
  description: string;
  poc_payload?: string | null;
  cvss_score?: string | null;
}

interface ScanDetailItem {
  id: number;
  domain_target: string;
  status: string;
  scan_type: string;
  created_at?: string;
  findings?: FindingItem[];
  discovered_links: Array<{
    id: number;
    url: string;
    status_code: number;
    content_type: string;
    findings: FindingItem[];
  }>;
}

interface ScannerHistoryItem {
  id: number;
  target: string;
  status: string;
  openPorts: number;
  contacts: number;
  unsanitized: number;
  createdAt: string;
}

interface ScannerOpenPortItem {
  token: string;
  service: string;
  version: string;
}

interface ScannerExportRow {
  node_type: 'global' | 'link';
  host: string;
  url: string;
  status_code: number;
  content_type: string;
  finding_type: string;
  severity: string;
  cvss_score: string;
  description: string;
  poc_payload: string;
}

interface ScannerReportExportSnapshot {
  rows: ScannerExportRow[];
  hasActiveFilters: boolean;
  filters: {
    searchText: string;
    severity: 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
    scope: 'all' | 'global' | 'link';
    findingType: string;
  };
}

@Component({
  selector: 'app-scanner',
  standalone: true,
  imports: [
    CommonModule,
    ScannerTargetConfigComponent,
    ScannerMetricsComponent,
    ScannerHistoryComponent,
    ScannerTerminalComponent,
    ScannerExportActionsComponent,
    ScannerReportComponent
  ],
  templateUrl: './scanner.component.html',
  styleUrls: ['./scanner.component.scss']
})
export class ScannerComponent implements OnInit, OnDestroy {
  targetDomain = 'scanme.nmap.org';
  scanProfile: 'quick' | 'balanced' | 'deep' | 'udp' = 'quick';
  scanTimeout = 180;
  webAppSurfaceScan = true;
  collectContactIntel = true;
  detectUnsanitizedInputs = true;
  webMaxPages = 12;
  isScanning = false;
  socket: WebSocket | null = null;
  terminalLogs: string[] = ['[ SYSTEM READY ] Waiting for target config...'];

  vulnerabilitiesFound = 0;
  contactsFound = 0;
  unsanitizedFindings = 0;
  currentScanId: number | null = null;
  latestOpenPortDelta: number | null = null;
  scannerHistory: ScannerHistoryItem[] = [];
  openPortsDetailed: ScannerOpenPortItem[] = [];
  currentScanDetail: ScanDetailItem | null = null;
  filteredExportRows: ScannerExportRow[] | null = null;
  reportFilterSnapshot: ScannerReportExportSnapshot['filters'] | null = null;
  reportHasActiveFilters = false;
  private openPortsSet = new Set<string>();
  private readonly maxTerminalLines = 1200;

  constructor(
    private cdr: ChangeDetectorRef,
    private scansApi: ScansApiService,
    private scanLive: ScanLiveService,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    this.loadScannerHistory();
    this.route.queryParams.subscribe((params) => {
      const scanId = Number(params['scanId']);
      if (Number.isFinite(scanId) && scanId > 0) {
        this.currentScanId = scanId;
        this.loadCurrentScanDetail(scanId);
      }
    });
  }

  initiateScan() {
    if (this.isScanning) return;
    if (!this.targetDomain) return;

    this.isScanning = true;
    this.terminalLogs = [
      `[+] CONNECTING TO ENGINE FOR SCANNING: ${this.targetDomain}...`,
      `[i] PROFILE=${this.scanProfile} | TIMEOUT=${this.scanTimeout}s | WEB_SCAN=${this.webAppSurfaceScan}`,
      `[i] CONTACT_INTEL=${this.collectContactIntel} | UNSANITIZED_INPUTS=${this.detectUnsanitizedInputs} | MAX_WEB_PAGES=${this.webMaxPages}`,
      '[i] Open ports will be listed with service/version details as they are discovered.'
    ];
    this.vulnerabilitiesFound = 0;
    this.contactsFound = 0;
    this.unsanitizedFindings = 0;
    this.currentScanId = null;
    this.currentScanDetail = null;
    this.openPortsSet.clear();
    this.openPortsDetailed = [];
    this.cdr.detectChanges();

    const wsUrl = this.scanLive.buildUrl({
      target: this.targetDomain,
      profile: this.scanProfile,
      timeout: this.scanTimeout,
      web_scan: this.webAppSurfaceScan,
      collect_contacts: this.collectContactIntel,
      scan_unsanitized: this.detectUnsanitizedInputs,
      max_pages: this.webMaxPages
    });
    this.socket = new WebSocket(wsUrl);

    this.socket.onmessage = (event) => {
      console.log("WS SCAN MESSAGE:", event.data);
      this.terminalLogs.push(event.data);

      if (this.terminalLogs.length > this.maxTerminalLines) {
        this.terminalLogs = this.terminalLogs.slice(-this.maxTerminalLines);
      }

      this.captureScanMetadata(event.data);
      this.captureWebFindings(event.data);
      this.captureOpenPortDetails(event.data);

      const parsedPort = this.extractOpenPortToken(event.data);
      if (parsedPort) {
        this.openPortsSet.add(parsedPort);
        this.vulnerabilitiesFound = this.openPortsSet.size;
      }
      this.cdr.detectChanges();
    };

    this.socket.onclose = () => {
      console.log("WS SCAN CLOSED");
      this.terminalLogs.push('[!] CONNECTION CLOSED. Scan finished.');
      this.isScanning = false;
      if (this.currentScanId) {
        this.loadCurrentScanDetail(this.currentScanId);
      }
      this.loadScannerHistory();
      this.cdr.detectChanges();
    };

    this.socket.onerror = (err) => {
      console.log("WS SCAN ERROR:", err);
      this.terminalLogs.push('[!] WEBSOCKET CONNECTION ERROR.');
      this.isScanning = false;
      this.cdr.detectChanges();
    };
  }

  selectScannerHistoryRun(scanId: number) {
    this.currentScanId = scanId;
    this.loadCurrentScanDetail(scanId);
  }

  cancelScan() {
    if (!this.currentScanId || !this.isScanning) return;

    this.scansApi.cancel(this.currentScanId).subscribe({
      next: () => {
        this.terminalLogs.push(`[!] Cancellation requested for scan #${this.currentScanId}`);
        this.cdr.detectChanges();
      },
      error: () => {
        this.terminalLogs.push('[!] Failed to cancel scan.');
        this.cdr.detectChanges();
      }
    });
  }

  onReportExportSnapshot(snapshot: ScannerReportExportSnapshot) {
    this.filteredExportRows = snapshot.rows;
    this.reportFilterSnapshot = snapshot.filters;
    this.reportHasActiveFilters = snapshot.hasActiveFilters;
  }

  exportScannerAsJson() {
    const payload = this.buildScannerExportPayload();
    this.downloadTextFile(
      `samurai-scanner-${payload.currentScanId ?? 'latest'}.json`,
      JSON.stringify(payload, null, 2),
      'application/json'
    );
  }

  exportScannerAsCsv() {
    const rows = this.flattenScannerExportRows();
    const headers = ['node_type', 'host', 'url', 'status_code', 'content_type', 'finding_type', 'severity', 'cvss_score', 'description', 'poc_payload'];
    const csvLines = [headers.join(',')];

    rows.forEach((row) => {
      csvLines.push(headers.map((header) => this.escapeCsv(row[header as keyof ScannerExportRow])).join(','));
    });

    this.downloadTextFile(
      `samurai-scanner-${this.currentScanId ?? 'latest'}.csv`,
      csvLines.join('\n'),
      'text/csv;charset=utf-8'
    );
  }

  exportScannerAsPdf() {
    const rows = this.flattenScannerExportRows();
    const payload = this.buildScannerExportPayload();
    const doc = new jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });

    doc.setFontSize(14);
    doc.text('Samurai Scanner Report', 40, 36);
    doc.setFontSize(10);
    doc.text(`Target: ${payload.target}`, 40, 54);
    doc.text(`Profile: ${payload.profile} | Timeout: ${payload.timeout}s`, 40, 68);
    doc.text(`Exported: ${payload.exportedAt}`, 40, 82);

    autoTable(doc, {
      startY: 96,
      head: [['Node', 'Host', 'URL', 'Status', 'Content Type', 'Finding Type', 'Severity', 'CVSS', 'Description', 'PoC']],
      body: rows.map((row) => [
        row.node_type,
        row.host,
        row.url,
        String(row.status_code),
        row.content_type,
        row.finding_type,
        row.severity,
        row.cvss_score,
        row.description,
        row.poc_payload
      ]),
      styles: { fontSize: 8, cellPadding: 3, overflow: 'linebreak' },
      headStyles: { fillColor: [35, 35, 35] }
    });

    doc.save(`samurai-scanner-${this.currentScanId ?? 'latest'}.pdf`);
  }

  exportScannerAsBinary() {
    const payload = this.buildScannerExportPayload();
    const bytes = gzip(JSON.stringify(payload));
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `samurai-scanner-${this.currentScanId ?? 'latest'}.bin`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.close();
    }
  }

  private extractOpenPortToken(line: string) {
    const match = line.match(/^(\d+)\/(tcp|udp)\s+open\b/i);
    if (!match) return null;
    return `${match[1]}/${match[2].toLowerCase()}`;
  }

  private captureOpenPortDetails(line: string) {
    const detailedMatch = line.match(/^\[OPEN_PORT\]\s+(\d+)\/(tcp|udp)\s+(\S+)\s+(.+)$/i);
    if (detailedMatch) {
      const token = `${detailedMatch[1]}/${detailedMatch[2].toLowerCase()}`;
      const service = detailedMatch[3].trim();
      const version = detailedMatch[4].trim();
      if (!this.openPortsDetailed.some((item) => item.token === token)) {
        this.openPortsDetailed.push({ token, service, version });
      }
      return;
    }

    const summaryMatch = line.match(/^\s+-\s+(\d+)\/(tcp|udp)\s+\|\s+(.+?)\s+\|\s+(.+)$/i);
    if (summaryMatch) {
      const token = `${summaryMatch[1]}/${summaryMatch[2].toLowerCase()}`;
      const service = summaryMatch[3].trim();
      const version = summaryMatch[4].trim();
      if (!this.openPortsDetailed.some((item) => item.token === token)) {
        this.openPortsDetailed.push({ token, service, version });
      }
    }
  }

  private captureScanMetadata(line: string) {
    const match = line.match(/^\[SCAN_META\]\s*scan_id=(\d+)/i);
    if (!match) return;
    this.currentScanId = Number(match[1]);
  }

  private loadCurrentScanDetail(scanId: number) {
    this.scansApi.get<ScanDetailItem>(scanId).subscribe({
      next: (detail) => {
        this.currentScanDetail = detail;
        this.currentScanId = detail.id;
        const findings = detail.findings || [];
        this.vulnerabilitiesFound = findings.filter((finding) => finding.finding_type === 'OPEN_PORT').length;
        this.contactsFound = findings.filter((finding) => finding.finding_type === 'CONTACT_INFO_DISCLOSURE').length;
        this.unsanitizedFindings = findings.filter((finding) => finding.finding_type === 'UNSANITIZED_INPUT_CANDIDATE' || finding.finding_type === 'REFLECTED_INPUT_ECHO').length;
        this.openPortsDetailed = (detail.findings || [])
          .filter((finding) => finding.finding_type === 'OPEN_PORT')
          .map((finding) => ({
            token: this.getPortTokenFromPayload(finding.poc_payload),
            service: this.getServiceFromPayload(finding.poc_payload),
            version: this.getVersionFromPayload(finding.poc_payload)
          }));
        this.terminalLogs.push(`[REPORT] Detailed report loaded: links=${detail.discovered_links.length} | findings=${(detail.findings || []).length}`);
        this.cdr.detectChanges();
      },
      error: () => {
        this.terminalLogs.push('[!] Unable to load detailed scan report.');
        this.cdr.detectChanges();
      }
    });
  }

  private getPortTokenFromPayload(payload: string | null | undefined) {
    if (!payload) return 'n/a';
    const portMatch = payload.match(/port=(\d+)/i);
    const protoMatch = payload.match(/protocol=(tcp|udp)/i);
    if (portMatch && protoMatch) {
      return `${portMatch[1]}/${protoMatch[1].toLowerCase()}`;
    }
    return 'n/a';
  }

  private getServiceFromPayload(payload: string | null | undefined) {
    if (!payload) return 'n/a';
    const serviceMatch = payload.match(/service=([^\n]+)/i);
    return serviceMatch ? serviceMatch[1].trim() : 'n/a';
  }

  private getVersionFromPayload(payload: string | null | undefined) {
    if (!payload) return 'n/a';
    const versionMatch = payload.match(/version=([^\n]+)/i);
    return versionMatch ? versionMatch[1].trim() : 'n/a';
  }

  private captureWebFindings(line: string) {
    if (line.includes('[WEB_CONTACT]')) {
      const emails = Number((line.match(/emails=(\d+)/i) || [])[1] || '0');
      const phones = Number((line.match(/phones=(\d+)/i) || [])[1] || '0');
      this.contactsFound += emails + phones;
    }

    if (line.includes('[WEB_UNSANITIZED]')) {
      const forms = Number((line.match(/forms=(\d+)/i) || [])[1] || '0');
      const reflected = /reflected=true/i.test(line) ? 1 : 0;
      this.unsanitizedFindings += forms + reflected;
    }
  }

  private loadScannerHistory() {
    this.scansApi.list().subscribe({
      next: (scans) => {
        const scannerRuns = ((scans as ScanListItem[]) || []).filter((s) => (s.scan_type || '').startsWith('port_scan')).slice(0, 6);
        if (!scannerRuns.length) {
          this.scannerHistory = [];
          this.latestOpenPortDelta = null;
          this.cdr.detectChanges();
          return;
        }

        const requests = scannerRuns.map((s) => this.scansApi.get<ScanDetailItem>(s.id));
        forkJoin(requests).subscribe({
          next: (details) => {
            this.scannerHistory = details.map((detail) => {
              const findings = detail.findings || [];
              const openPorts = findings.filter((f) => f.finding_type === 'OPEN_PORT').length;
              const contacts = findings.filter((f) => f.finding_type === 'CONTACT_INFO_DISCLOSURE').length;
              const unsanitized = findings.filter((f) => f.finding_type === 'UNSANITIZED_INPUT_CANDIDATE' || f.finding_type === 'REFLECTED_INPUT_ECHO').length;
              return {
                id: detail.id,
                target: detail.domain_target,
                status: detail.status,
                openPorts,
                contacts,
                unsanitized,
                createdAt: detail.created_at || ''
              };
            });

            if (this.scannerHistory.length > 1) {
              this.latestOpenPortDelta = this.scannerHistory[0].openPorts - this.scannerHistory[1].openPorts;
            } else {
              this.latestOpenPortDelta = null;
            }

            this.cdr.detectChanges();
          },
          error: () => {
            this.scannerHistory = [];
            this.latestOpenPortDelta = null;
            this.cdr.detectChanges();
          }
        });
      },
      error: () => {
        this.scannerHistory = [];
        this.latestOpenPortDelta = null;
        this.cdr.detectChanges();
      }
    });
  }

  private buildScannerExportPayload() {
    const detail = this.currentScanDetail;
    return {
      currentScanId: this.currentScanId,
      target: this.targetDomain,
      profile: this.scanProfile,
      timeout: this.scanTimeout,
      webAppSurfaceScan: this.webAppSurfaceScan,
      collectContactIntel: this.collectContactIntel,
      detectUnsanitizedInputs: this.detectUnsanitizedInputs,
      webMaxPages: this.webMaxPages,
      exportedAt: new Date().toISOString(),
      metrics: {
        portsFound: this.vulnerabilitiesFound,
        contactsFound: this.contactsFound,
        unsanitizedFindings: this.unsanitizedFindings,
        latestOpenPortDelta: this.latestOpenPortDelta
      },
      exportScope: this.reportHasActiveFilters ? 'filtered-view' : 'full-report',
      activeFilters: this.reportFilterSnapshot,
      detailedReport: detail,
      flattenedFindings: this.flattenScannerExportRows(),
      terminalLogs: this.terminalLogs
    };
  }

  private flattenScannerExportRows(): ScannerExportRow[] {
    if (this.filteredExportRows) {
      return [...this.filteredExportRows];
    }

    const detail = this.currentScanDetail;
    if (!detail) return [];

    const rows: ScannerExportRow[] = [];

    (detail.findings || []).forEach((finding) => {
      if (finding.link_id === null || finding.link_id === undefined) {
        rows.push({
          node_type: 'global',
          host: this.targetDomain,
          url: detail.domain_target,
          status_code: 200,
          content_type: 'SCAN_SCOPE',
          finding_type: finding.finding_type,
          severity: finding.severity,
          cvss_score: finding.cvss_score || '',
          description: finding.description,
          poc_payload: finding.poc_payload || ''
        });
      }
    });

    (detail.discovered_links || []).forEach((link) => {
      link.findings.forEach((finding) => {
        rows.push({
          node_type: 'link',
          host: this.getHost(link.url),
          url: link.url,
          status_code: link.status_code,
          content_type: link.content_type,
          finding_type: finding.finding_type,
          severity: finding.severity,
          cvss_score: finding.cvss_score || '',
          description: finding.description,
          poc_payload: finding.poc_payload || ''
        });
      });
    });

    return rows;
  }

  private getHost(url: string) {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  private escapeCsv(value: string | number | null | undefined) {
    const normalized = value === null || value === undefined ? '' : String(value);
    return `"${normalized.replace(/"/g, '""')}"`;
  }

  private downloadTextFile(fileName: string, content: string, mimeType: string) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }
}
