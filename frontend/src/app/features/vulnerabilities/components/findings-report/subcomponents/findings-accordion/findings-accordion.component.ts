import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FindingItemComponent } from '../finding-item/finding-item.component';
import { DiscoveredLink, Finding } from '../../../../models/vulnerabilities.models';

export type FindingsNode = DiscoveredLink & { isGlobal: boolean };

@Component({
  selector: 'app-findings-accordion',
  standalone: true,
  imports: [CommonModule, FindingItemComponent],
  templateUrl: './findings-accordion.component.html',
  styleUrls: ['./findings-accordion.component.scss']
})
export class FindingsAccordionComponent {
  @Input() filteredLinks: FindingsNode[] = [];

  severityCount(links: FindingsNode[]) {
    return links.reduce((acc, link) => acc + (link.findings?.length || 0), 0);
  }
}
