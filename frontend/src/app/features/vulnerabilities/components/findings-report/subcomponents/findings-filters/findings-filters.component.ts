import { Component, Input, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { SeverityLevel } from '../../../../models/vulnerabilities.models';

@Component({
  selector: 'app-findings-filters',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './findings-filters.component.html',
  styleUrls: ['./findings-filters.component.scss']
})
export class FindingsFiltersComponent {
  @Input() severityFilter: 'all' | SeverityLevel = 'all';
  @Input() typeFilter = 'all';
  @Input() availableTypes: string[] = [];
  @Input() hasActiveFilters = false;

  @Output() severityChanged = new EventEmitter<'all' | SeverityLevel>();
  @Output() typeChanged = new EventEmitter<string>();
  @Output() resetFilters = new EventEmitter<void>();

  onSeverityChange(value: string) {
    this.severityChanged.emit(value as 'all' | SeverityLevel);
  }

  onTypeChange(value: string) {
    this.typeChanged.emit(value);
  }

  onResetClick() {
    this.resetFilters.emit();
  }
}
