import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Input, Output } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ReconModule, ReconModuleId } from '../../models/recon.models';

@Component({
  selector: 'app-recon-controls',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './recon-controls.component.html',
  styleUrl: './recon-controls.component.scss'
})
export class ReconControlsComponent {
  @Input() targetDomain = '';
  @Input() isScanning = false;
  @Input() selectedModules: ReconModuleId[] = [];
  @Input() reconModules: ReconModule[] = [];

  @Output() targetDomainChange = new EventEmitter<string>();
  @Output() toggleModule = new EventEmitter<ReconModuleId>();
  @Output() preset = new EventEmitter<'all' | 'basic' | 'api'>();
  @Output() start = new EventEmitter<void>();
  @Output() clear = new EventEmitter<void>();

  onInput(value: string): void {
    this.targetDomainChange.emit(value);
  }
}
