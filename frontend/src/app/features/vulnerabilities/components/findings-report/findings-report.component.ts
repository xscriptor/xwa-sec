import { Component, Input, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router } from '@angular/router';
import { Subscription } from 'rxjs';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { gzip } from 'pako';
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
    const payload = this.buildExportPayload();

    this.downloadTextFile(
      `xwa-sec-findings-scan-${this.completedScanDetails?.id ?? 'unknown'}.json`,
      JSON.stringify(payload, null, 2),
      'application/json'
    );
  }

  exportFindingsAsPdf() {
    const rows = this.flattenAllFindings();
    const scanId = this.completedScanDetails?.id ?? 'unknown';
    const target = this.completedScanDetails?.domain_target ?? 'unknown';

    const doc = new jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });
    doc.setFontSize(14);
    doc.text(`XWA-SEC Vulnerability Report | Scan #${scanId}`, 40, 36);
    doc.setFontSize(10);
    doc.text(`Target: ${target}`, 40, 54);
    doc.text(`Exported: ${new Date().toISOString()}`, 40, 68);
    doc.text(
      `Current Filters: severity=${this.severityFilter} type=${this.typeFilter} | Full dataset exported`,
      40,
      82
    );

    autoTable(doc, {
      startY: 96,
      head: [['Node', 'URL', 'Type', 'Severity', 'CVSS', 'Description', 'PoC', 'Matches Filters']],
      body: rows.map((row) => [
        row['node_type'] || '',
        row['url'] || '',
        row['finding_type'] || '',
        String(row['severity'] || '').toUpperCase(),
        row['cvss_score'] || '',
        row['description'] || '',
        row['poc_payload'] || '',
        row['matches_current_filters'] ? 'YES' : 'NO'
      ]),
      styles: { fontSize: 8, cellPadding: 3, overflow: 'linebreak' },
      headStyles: { fillColor: [35, 35, 35] },
      columnStyles: {
        1: { cellWidth: 150 },
        5: { cellWidth: 180 },
        6: { cellWidth: 180 }
      }
    });

    doc.save(`xwa-sec-findings-scan-${scanId}.pdf`);
  }

  exportFindingsAsBinary() {
    const payload = this.buildExportPayload();
    const content = JSON.stringify(payload);
    const bytes = gzip(content);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `xwa-sec-findings-scan-${this.completedScanDetails?.id ?? 'unknown'}.bin`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  exportFindingsAsCsv() {
    const rows = this.flattenAllFindings();
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
      'poc_payload',
      'matches_current_filters'
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

  private flattenAllFindings() {
    const rows: Array<Record<string, string | number | null>> = [];

    this.findingsNodes.forEach((node) => {
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
          poc_payload: finding.poc_payload,
          matches_current_filters: this.matchesFilters(finding) ? 'true' : 'false'
        });
      });
    });

    return rows;
  }

  private buildExportPayload() {
    const scan = this.completedScanDetails;
    const allRows = this.flattenAllFindings();

    return {
      scanId: scan?.id ?? null,
      target: scan?.domain_target ?? null,
      scanStatus: scan?.status ?? null,
      scanType: scan?.scan_type ?? null,
      scanCreatedAt: scan?.created_at ?? null,
      exportedAt: new Date().toISOString(),
      filters: {
        severity: this.severityFilter,
        type: this.typeFilter
      },
      stats: {
        totalNodes: this.findingsNodes.length,
        totalFindings: allRows.length,
        findingsMatchingCurrentFilters: this.filteredFindingsCount,
        globalFindings: this.globalFindings.length,
        linkFindings: Math.max(allRows.length - this.globalFindings.length, 0)
      },
      globalFindings: this.globalFindings,
      discoveredLinks: scan?.discovered_links ?? [],
      flattenedFindings: allRows
    };
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

  severityCount(links: FindingsNode[]) {
    return links.reduce((acc, link) => acc + (link.findings?.length || 0), 0);
  }
}
