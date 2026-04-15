import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';

@Component({
  selector: 'app-recon-tech-results',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './recon-tech-results.component.html',
  styleUrl: './recon-tech-results.component.scss'
})
export class ReconTechResultsComponent {
  @Input() technology:
    | {
        frontend: string[];
        backend: string[];
        cdn: string | null;
        interesting_findings: string[];
      }
    | undefined;
}
