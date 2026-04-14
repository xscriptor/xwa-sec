import { Component, EventEmitter, Input, OnChanges, Output, SimpleChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

interface ScannerFindingDetail {
  id?: number;
  scan_id?: number;
  link_id?: number | null;
  severity: string;
  finding_type: string;
  description: string;
  poc_payload?: string | null;
  cvss_score?: string | null;
}

interface ScannerDiscoveredLinkDetail {
  id: number;
  url: string;
  status_code: number;
  content_type: string;
  findings: ScannerFindingDetail[];
}

interface ScannerScanDetail {
  id: number;
  domain_target: string;
  status: string;
  scan_type: string;
  created_at?: string;
  findings?: ScannerFindingDetail[];
  discovered_links: ScannerDiscoveredLinkDetail[];
}

type ScannerSeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type ScannerScopeFilter = 'all' | 'global' | 'link';

interface ScannerReportExportRow {
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
  rows: ScannerReportExportRow[];
  hasActiveFilters: boolean;
  filters: {
    searchText: string;
    severity: ScannerSeverityFilter;
    scope: ScannerScopeFilter;
    findingType: string;
  };
}

@Component({
  selector: 'app-scanner-report',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scanner-report.component.html',
  styleUrls: ['./scanner-report.component.scss']
})
export class ScannerReportComponent implements OnChanges {
  @Input() scanDetail: ScannerScanDetail | null = null;
  @Input() openPortsDetailed: Array<{ token: string; service: string; version: string }> = [];
  @Output() exportSnapshotChange = new EventEmitter<ScannerReportExportSnapshot>();

  searchText = '';
  severityFilter: ScannerSeverityFilter = 'all';
  scopeFilter: ScannerScopeFilter = 'all';
  findingTypeFilter = 'all';

  get availableFindingTypes() {
    const types = new Set<string>();
    (this.scanDetail?.findings || []).forEach((finding) => types.add(finding.finding_type));
    (this.scanDetail?.discovered_links || []).forEach((link) => link.findings.forEach((finding) => types.add(finding.finding_type)));
    return Array.from(types).sort();
  }

  get discoveredLinks() {
    return (this.scanDetail?.discovered_links || []).map((link) => ({
      ...link,
      findings: link.findings.filter((finding) => this.matchesFindingFilters(finding, 'link', link.url))
    })).filter((link) => this.scopeFilter !== 'global' && (link.findings.length > 0 || this.scopeFilter === 'link'));
  }

  get globalFindings() {
    return (this.scanDetail?.findings || []).filter((finding) => this.matchesFindingFilters(finding, 'global', this.scanDetail?.domain_target || ''));
  }

  get totalFindings() {
    return this.globalFindings.length + this.discoveredLinks.reduce((count, link) => count + link.findings.length, 0);
  }

  get totalLinks() {
    return this.discoveredLinks.length;
  }

  get contactFindingsCount() {
    return this.globalFindings.filter((finding) => finding.finding_type === 'CONTACT_INFO_DISCLOSURE').length + this.discoveredLinks.reduce((count, link) => count + link.findings.filter((finding) => finding.finding_type === 'CONTACT_INFO_DISCLOSURE').length, 0);
  }

  get unsanitizedCount() {
    return this.globalFindings.filter((finding) => finding.finding_type === 'UNSANITIZED_INPUT_CANDIDATE' || finding.finding_type === 'REFLECTED_INPUT_ECHO').length + this.discoveredLinks.reduce((count, link) => count + link.findings.filter((finding) => finding.finding_type === 'UNSANITIZED_INPUT_CANDIDATE' || finding.finding_type === 'REFLECTED_INPUT_ECHO').length, 0);
  }

  get openPortFindings() {
    return this.globalFindings.filter((finding) => finding.finding_type === 'OPEN_PORT');
  }

  getHost(url: string) {
    try {
      return new URL(url).hostname;
    } catch {
      return url;
    }
  }

  getPortTokenFromPayload(payload: string | null | undefined) {
    if (!payload) return 'n/a';
    const portMatch = payload.match(/port=(\d+)/i);
    const protoMatch = payload.match(/protocol=(tcp|udp)/i);
    if (portMatch && protoMatch) {
      return `${portMatch[1]}/${protoMatch[1].toLowerCase()}`;
    }
    return 'n/a';
  }

  getServiceFromPayload(payload: string | null | undefined) {
    if (!payload) return 'n/a';
    const serviceMatch = payload.match(/service=([^\n]+)/i);
    return serviceMatch ? serviceMatch[1].trim() : 'n/a';
  }

  getVersionFromPayload(payload: string | null | undefined) {
    if (!payload) return 'n/a';
    const versionMatch = payload.match(/version=([^\n]+)/i);
    return versionMatch ? versionMatch[1].trim() : 'n/a';
  }

  getUnsanitizedSummary(finding: ScannerFindingDetail) {
    const lines = this.parsePayloadLines(finding.poc_payload);
    const action = lines['Action'] || lines['URL'] || 'n/a';
    const method = lines['Method'] || 'GET';
    const fields = lines['Fields'] || 'n/a';
    const url = lines['URL'] || 'n/a';
    const source = fields !== 'n/a' ? fields.split(/,\s*/).filter(Boolean) : [];
    return {
      url,
      method,
      action,
      fields,
      fieldCount: source.length,
      meaning: source.length
        ? `The scanner found form or request inputs without visible constraints. Field ${source.join(', ')} should be validated and sanitized before use.`
        : 'The scanner found a request surface that may accept unbounded input. Review server-side validation and output encoding.'
    };
  }

  matchesFindingFilters(finding: ScannerFindingDetail, scope: 'global' | 'link', textSeed: string) {
    if (this.scopeFilter !== 'all' && this.scopeFilter !== scope) {
      return false;
    }

    if (this.severityFilter !== 'all' && finding.severity !== this.severityFilter) {
      return false;
    }

    if (this.findingTypeFilter !== 'all' && finding.finding_type !== this.findingTypeFilter) {
      return false;
    }

    const haystack = [textSeed, finding.finding_type, finding.severity, finding.description, finding.poc_payload || '']
      .join(' ')
      .toLowerCase();
    return !this.searchText.trim() || haystack.includes(this.searchText.trim().toLowerCase());
  }

  clearFilters() {
    this.searchText = '';
    this.severityFilter = 'all';
    this.scopeFilter = 'all';
    this.findingTypeFilter = 'all';
    this.emitExportSnapshot();
  }

  onFilterChanged() {
    this.emitExportSnapshot();
  }

  ngOnChanges(changes: SimpleChanges) {
    if (changes['scanDetail']) {
      this.emitExportSnapshot();
    }
  }

  private parsePayloadLines(payload: string | null | undefined) {
    if (!payload) return {} as Record<string, string>;

    return payload.split('\n').reduce((accumulator, line) => {
      const [label, ...rest] = line.split(':');
      if (!label || !rest.length) return accumulator;
      accumulator[label.trim()] = rest.join(':').trim();
      return accumulator;
    }, {} as Record<string, string>);
  }

  private emitExportSnapshot() {
    this.exportSnapshotChange.emit({
      rows: this.buildFilteredExportRows(),
      hasActiveFilters: this.hasActiveFilters(),
      filters: {
        searchText: this.searchText,
        severity: this.severityFilter,
        scope: this.scopeFilter,
        findingType: this.findingTypeFilter
      }
    });
  }

  private hasActiveFilters() {
    return !!this.searchText.trim() || this.severityFilter !== 'all' || this.scopeFilter !== 'all' || this.findingTypeFilter !== 'all';
  }

  private buildFilteredExportRows(): ScannerReportExportRow[] {
    const detail = this.scanDetail;
    if (!detail) return [];

    const rows: ScannerReportExportRow[] = [];

    (detail.findings || []).forEach((finding) => {
      if (finding.link_id !== null && finding.link_id !== undefined) {
        return;
      }
      if (!this.matchesFindingFilters(finding, 'global', detail.domain_target || '')) {
        return;
      }

      rows.push({
        node_type: 'global',
        host: this.getHost(detail.domain_target),
        url: detail.domain_target,
        status_code: 200,
        content_type: 'SCAN_SCOPE',
        finding_type: finding.finding_type,
        severity: finding.severity,
        cvss_score: finding.cvss_score || '',
        description: finding.description,
        poc_payload: finding.poc_payload || ''
      });
    });

    (detail.discovered_links || []).forEach((link) => {
      link.findings.forEach((finding) => {
        if (!this.matchesFindingFilters(finding, 'link', link.url)) {
          return;
        }

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
}
