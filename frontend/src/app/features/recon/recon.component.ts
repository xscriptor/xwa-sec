import { ChangeDetectorRef, Component, OnDestroy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReconControlsComponent } from './components/controls/recon-controls.component';
import { ReconTerminalComponent } from './components/terminal/recon-terminal.component';
import { ReconResultsComponent } from './components/results/recon-results.component';
import { ReconEnvelope, ReconModule, ReconModuleId, ReconResults } from './models/recon.models';
import { ReconLiveService } from './services/recon-live.service';

@Component({
  selector: 'app-recon',
  standalone: true,
  imports: [CommonModule, ReconControlsComponent, ReconTerminalComponent, ReconResultsComponent],
  templateUrl: './recon.component.html',
  styleUrl: './recon.component.scss'
})
export class ReconComponent implements OnDestroy {
  targetDomain: string = '';
  isScanning: boolean = false;
  terminalLines: string[] = [];
  reconResults: ReconResults | null = null;
  selectedModules: ReconModuleId[] = ['all'];
  private destroyed = false;

  reconModules: ReconModule[] = [
    {
      id: 'dns',
      label: 'DNS',
      icon: 'D',
      description: 'DNS enumeration (A, AAAA, MX, NS, TXT, SOA)'
    },
    {
      id: 'subdomains',
      label: 'SUBDOMAINS',
      icon: 'S',
      description: 'Enumerate subdomains via Certificate Transparency'
    },
    {
      id: 'apis',
      label: 'APIs',
      icon: 'A',
      description: 'Discover API endpoints and documentation'
    },
    {
      id: 'headers',
      label: 'HEADERS',
      icon: 'H',
      description: 'Analyze security headers and configurations'
    },
    {
      id: 'tech',
      label: 'TECH STACK',
      icon: 'T',
      description: 'Identify frontend & backend technologies'
    }
  ];

  constructor(private reconLiveService: ReconLiveService, private cdr: ChangeDetectorRef) {}

  ngOnDestroy() {
    this.destroyed = true;
    this.reconLiveService.disconnect();
  }

  updateTargetDomain(value: string): void {
    this.targetDomain = value;
  }

  toggleModule(moduleId: ReconModuleId) {
    const index = this.selectedModules.indexOf(moduleId);
    if (index > -1) {
      this.selectedModules.splice(index, 1);
    } else {
      if (this.selectedModules.includes('all') && moduleId !== 'all') {
        this.selectedModules = [];
      }
      if (moduleId === 'all') {
        this.selectedModules = ['all'];
      } else {
        this.selectedModules.push(moduleId);
      }
    }

    if (this.selectedModules.length === 0) {
      this.selectedModules = ['all'];
    }
  }

  selectPreset(preset: 'all' | 'basic' | 'api') {
    if (preset === 'all') {
      this.selectedModules = ['all'];
    } else if (preset === 'basic') {
      this.selectedModules = ['dns', 'headers'];
    } else if (preset === 'api') {
      this.selectedModules = ['apis', 'tech'];
    }
  }

  clearTerminal() {
    this.terminalLines = [];
    this.reconResults = null;
  }

  startRecon() {
    if (!this.targetDomain || this.isScanning) return;

    this.isScanning = true;
    this.terminalLines = [];
    this.reconResults = null;

    this.reconLiveService.connect(this.targetDomain, this.selectedModules, {
      onLog: (line) => this.addTerminalLine(line),
      onComplete: (message: ReconEnvelope) => {
        this.reconResults = message.results || null;
        this.addTerminalLine('[done] reconnaissance complete');
        this.isScanning = false;
        this.safeDetectChanges();
      },
      onError: (message) => {
        this.addTerminalLine(`[error] ${message}`);
        this.isScanning = false;
        this.safeDetectChanges();
      },
      onUnexpectedClose: () => {
        if (this.isScanning) {
          this.addTerminalLine('[error] websocket closed unexpectedly');
          this.isScanning = false;
          this.safeDetectChanges();
        }
      }
    });
  }

  private safeDetectChanges(): void {
    if (!this.destroyed) {
      this.cdr.detectChanges();
    }
  }

  private addTerminalLine(line: string) {
    this.terminalLines.push(line);
    this.safeDetectChanges();

    setTimeout(() => {
      const terminal = document.querySelector('.terminal');
      if (terminal) {
        terminal.scrollTop = terminal.scrollHeight;
      }
    }, 0);
  }

}

