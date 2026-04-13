import { Component, Input, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { Subscription } from 'rxjs';
import { DiscoveredLink, Finding, ScanDetail, SeverityLevel } from '../../models/vulnerabilities.models';
import { FindingsFiltersComponent } from './subcomponents/findings-filters/findings-filters.component';
import { FindingsExportActionsComponent } from './subcomponents/findings-export-actions/findings-export-actions.component';
import { FindingsAccordionComponent, FindingsNode } from './subcomponents/findings-accordion/findings-accordion.component';
import { FindingsEmptyStateComponent } from './subcomponents/findings-empty-state/findings-empty-state.component';
import { FindingsNoResultsComponent } from './subcomponents/findings-no-results/findings-no-results.component';

@Component({
  selector: 'app-vuln-findings-report',
  standalone: true,
  imports: [
    CommonModule,
    FindingsFiltersComponent,
    FindingsExportActionsComponent,
    FindingsAccordionComponent,
    FindingsEmptyStateComponent,
    FindingsNoResultsComponent
  ],
  templateUrl: './findings-report.component.html',
  styleUrls: ['./findings-report.component.scss']
})
export class VulnerabilitiesFindingsReportComponent implements OnInit, OnDestroy {
  @Input() completedScanDetails: ScanDetail | null = null;

  severityFilter: 'all' | SeverityLevel = 'all';
  typeFilter = 'all';
  private querySub: Subscription | null = null;

  constructor(private route: ActivatedRoute, private router: Router) {}

  ngOnInit() {
    this.querySub = this.route.queryParamMap.subscribe((params) => {
      const severityFromQuery = (params.get('severity') || 'all').toLowerCase();
      const typeFromQuery = params.get('type') || 'all';

      const validSeverity: Array<'all' | SeverityLevel> = ['all', 'critical', 'high', 'medium', 'low', 'info'];
      this.severityFilter = validSeverity.includes(severityFromQuery as 'all' | SeverityLevel)
        ? (severityFromQuery as 'all' | SeverityLevel)
        : 'all';

      this.typeFilter = typeFromQuery;
    });
  }

  ngOnDestroy() {
    this.querySub?.unsubscribe();
  }

  private matchesFilters(finding: Finding) {
    const severityOk = this.severityFilter === 'all' || finding.severity === this.severityFilter;
    const typeOk = this.typeFilter === 'all' || finding.finding_type === this.typeFilter;
    return severityOk && typeOk;
  }

  private get globalFindings() {
    if (!this.completedScanDetails?.findings?.length) return [];
    return this.completedScanDetails.findings.filter((finding) => finding.link_id === null);
  }

  get findingsNodes(): FindingsNode[] {
    if (!this.completedScanDetails) return [];

    const linkNodes: FindingsNode[] = this.completedScanDetails.discovered_links.map((link) => ({
      ...link,
      findings: link.findings || [],
      isGlobal: false
    }));

    if (!this.globalFindings.length) {
      return linkNodes;
    }

    const globalNode: FindingsNode = {
      id: -1,
      scan_id: this.completedScanDetails.id,
      url: this.completedScanDetails.domain_target,
      status_code: 200,
      content_type: 'SCAN_SCOPE',
      findings: this.globalFindings,
      isGlobal: true
    };

    return [globalNode, ...linkNodes];
  }

  get availableTypes() {
    const types = new Set<string>();
    this.findingsNodes.forEach((node) => {
      (node.findings || []).forEach((finding) => types.add(finding.finding_type));
    });
    return Array.from(types).sort();
  }

  get filteredLinks() {
    return this.findingsNodes
      .map((link) => ({
        ...link,
        findings: (link.findings || []).filter((finding) => this.matchesFilters(finding))
      }))
      .filter((link) => link.findings.length > 0 || (this.severityFilter === 'all' && this.typeFilter === 'all'));
  }

  get hasActiveFilters() {
    return this.severityFilter !== 'all' || this.typeFilter !== 'all';
  }

  get filteredFindingsCount() {
    return this.severityCount(this.filteredLinks);
  }

  onFiltersChanged() {
    const queryParams: Record<string, string | null> = {
      severity: this.severityFilter === 'all' ? null : this.severityFilter,
      type: this.typeFilter === 'all' ? null : this.typeFilter
    };

    this.router.navigate([], {
      relativeTo: this.route,
      queryParams,
      queryParamsHandling: 'merge',
      replaceUrl: true
    });
  }

  resetFilters() {
    this.severityFilter = 'all';
    this.typeFilter = 'all';
    this.onFiltersChanged();
  }

  exportFindingsAsJson() {
    const payload = {
      scanId: this.completedScanDetails?.id ?? null,
      target: this.completedScanDetails?.domain_target ?? null,
      exportedAt: new Date().toISOString(),
      filters: {
        severity: this.severityFilter,
        type: this.typeFilter
      },
      findings: this.flattenFilteredFindings()
    };

    this.downloadTextFile(
      `xwa-sec-findings-scan-${this.completedScanDetails?.id ?? 'unknown'}.json`,
      JSON.stringify(payload, null, 2),
      'application/json'
    );
  }

  exportFindingsAsPdf() {
    const rows = this.flattenFilteredFindings();
    const printable = this.buildPrintableReport(rows);
    const printWindow = window.open('', '_blank', 'noopener,noreferrer,width=980,height=720');

    if (!printWindow) return;

    printWindow.document.write(printable);
    printWindow.document.close();
    printWindow.focus();
    printWindow.print();
  }

  exportFindingsAsBinary() {
    const payload = {
      scanId: this.completedScanDetails?.id ?? null,
      target: this.completedScanDetails?.domain_target ?? null,
      exportedAt: new Date().toISOString(),
      filters: {
        severity: this.severityFilter,
        type: this.typeFilter
      },
      findings: this.flattenFilteredFindings()
    };

    const content = JSON.stringify(payload);
    const encoder = new TextEncoder();
    const bytes = encoder.encode(content);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `xwa-sec-findings-scan-${this.completedScanDetails?.id ?? 'unknown'}.bin`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  exportFindingsAsCsv() {
    const rows = this.flattenFilteredFindings();
    const headers = [
      'scan_id',
      'node_type',
      'url',
      'status_code',
      'content_type',
      'finding_type',
      'severity',
      'cvss_score',
      'description',
      'poc_payload'
    ];

    const csvLines = [headers.join(',')];
    rows.forEach((row) => {
      const ordered = headers.map((key) => this.escapeCsv((row as Record<string, string | number | null>)[key]));
      csvLines.push(ordered.join(','));
    });

    this.downloadTextFile(
      `xwa-sec-findings-scan-${this.completedScanDetails?.id ?? 'unknown'}.csv`,
      csvLines.join('\n'),
      'text/csv;charset=utf-8'
    );
  }

  private flattenFilteredFindings() {
    const rows: Array<Record<string, string | number | null>> = [];

    this.filteredLinks.forEach((node) => {
      node.findings.forEach((finding) => {
        rows.push({
          scan_id: finding.scan_id,
          node_type: node.isGlobal ? 'global' : 'link',
          url: node.url,
          status_code: node.status_code,
          content_type: node.content_type,
          finding_type: finding.finding_type,
          severity: finding.severity,
          cvss_score: finding.cvss_score,
          description: finding.description,
          poc_payload: finding.poc_payload
        });
      });
    });

    return rows;
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

  private buildPrintableReport(rows: Array<Record<string, string | number | null>>) {
    const scanId = this.completedScanDetails?.id ?? 'unknown';
    const target = this.completedScanDetails?.domain_target ?? 'unknown';
    const header = `<h1>XWA-SEC Vulnerability Report</h1>
<p><strong>Scan ID:</strong> ${scanId}</p>
<p><strong>Target:</strong> ${target}</p>
<p><strong>Severity Filter:</strong> ${this.severityFilter.toUpperCase()} | <strong>Type Filter:</strong> ${this.typeFilter}</p>
<p><strong>Exported:</strong> ${new Date().toISOString()}</p>`;

    const tableRows = rows.map((row) => `
      <tr>
        <td>${row['node_type'] ?? ''}</td>
        <td>${row['url'] ?? ''}</td>
        <td>${row['finding_type'] ?? ''}</td>
        <td>${String(row['severity'] ?? '').toUpperCase()}</td>
        <td>${row['cvss_score'] ?? ''}</td>
        <td>${row['description'] ?? ''}</td>
      </tr>
    `).join('');

    return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>XWA-SEC Report ${scanId}</title>
    <style>
      body { font-family: Arial, sans-serif; padding: 24px; color: #111; }
      h1 { margin: 0 0 16px; }
      p { margin: 4px 0; }
      table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; }
      th, td { border: 1px solid #ccc; padding: 6px; text-align: left; vertical-align: top; }
      th { background: #f3f3f3; }
      @media print { body { padding: 0; } }
    </style>
  </head>
  <body>
    ${header}
    <table>
      <thead>
        <tr>
          <th>Node</th>
          <th>URL</th>
          <th>Type</th>
          <th>Severity</th>
          <th>CVSS</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>${tableRows}</tbody>
    </table>
  </body>
</html>`;
  }

  severityCount(links: FindingsNode[]) {
    return links.reduce((acc, link) => acc + (link.findings?.length || 0), 0);
  }
}
