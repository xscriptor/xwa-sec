import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-recon-api-results',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './recon-api-results.component.html',
  styleUrl: './recon-api-results.component.scss'
})
export class ReconApiResultsComponent {
  @Input() apis:
    | {
        apis_found: Array<{ path: string; status: number; content_type: string }>;
        documentation: string[];
        framework: string | null;
        headers_analysis: Record<string, string>;
        graphql_enabled: boolean;
        base_url?: string;
        probed_paths?: number;
      }
    | undefined;

  statusTone(status: number): 'ok' | 'restricted' | 'redirect' | 'other' {
    if (status >= 200 && status < 300) {
      return 'ok';
    }

    if (status === 401 || status === 403 || status === 405) {
      return 'restricted';
    }

    if (status >= 300 && status < 400) {
      return 'redirect';
    }

    return 'other';
  }
}
