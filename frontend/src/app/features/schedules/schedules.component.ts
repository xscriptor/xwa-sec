import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  CreateSchedulePayload,
  Schedule,
  ScheduleScanType,
  SchedulesApiService
} from '../../core/api/schedules-api.service';
import { AuthService } from '../../core/auth/auth.service';

interface ScanTypeOption {
  value: ScheduleScanType;
  label: string;
  description: string;
  defaultConfig: string;
}

const SCAN_TYPE_OPTIONS: ScanTypeOption[] = [
  {
    value: 'port_scan',
    label: 'PORT SCAN',
    description: 'Nmap port + service discovery',
    defaultConfig: JSON.stringify({ profile: 'quick', timeout: 180, web_scan: false }, null, 2)
  },
  {
    value: 'web_recon',
    label: 'WEB RECON',
    description: 'DNS, subdomains, headers, tech-stack',
    defaultConfig: JSON.stringify({ recon_types: 'all', timeout: 300 }, null, 2)
  },
  {
    value: 'vuln_crawl',
    label: 'VULN CRAWL',
    description: 'DAST with SQLMap, Nuclei, XSS, LFI',
    defaultConfig: JSON.stringify({ modules: 'all' }, null, 2)
  }
];

const CRON_PRESETS: Array<{ label: string; value: string; hint: string }> = [
  { label: 'EVERY HOUR', value: '0 * * * *', hint: 'at minute 0' },
  { label: 'EVERY DAY @ 02:00', value: '0 2 * * *', hint: 'nightly scan' },
  { label: 'EVERY MONDAY @ 08:00', value: '0 8 * * 1', hint: 'weekly' },
  { label: 'EVERY 15 MIN', value: '*/15 * * * *', hint: 'monitoring' }
];

interface FormState {
  name: string;
  scan_type: ScheduleScanType;
  target: string;
  cron_expression: string;
  is_enabled: boolean;
  config_json: string;
}

@Component({
  selector: 'app-schedules',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="schedules-shell">
      <header class="page-header">
        <span class="t-label">SAMURAI // AUTOMATION</span>
        <h1 class="page-title">SCHEDULED SCANS</h1>
        <p class="page-subtitle">
          Cron-driven scans. Backend runner ships in the next release — definitions persist now.
        </p>
      </header>

      <section class="create-panel">
        <h2 class="t-label">{{ editingId() ? 'EDIT SCHEDULE #' + editingId() : 'CREATE SCHEDULE' }}</h2>

        <form class="create-form" (ngSubmit)="submit()" autocomplete="off">
          <label class="field field-wide">
            <span class="t-label">NAME</span>
            <input type="text" name="name" [(ngModel)]="form.name" required minlength="1" />
          </label>

          <label class="field">
            <span class="t-label">SCAN TYPE</span>
            <select name="scan_type" [(ngModel)]="form.scan_type" (ngModelChange)="onScanTypeChange($event)" [disabled]="!!editingId()">
              <option *ngFor="let opt of scanTypeOptions" [value]="opt.value">{{ opt.label }}</option>
            </select>
          </label>

          <label class="field field-wide">
            <span class="t-label">TARGET <span class="hint">({{ selectedTypeDescription() }})</span></span>
            <input type="text" name="target" [(ngModel)]="form.target" required />
          </label>

          <label class="field">
            <span class="t-label">CRON</span>
            <input type="text" name="cron" [(ngModel)]="form.cron_expression" required placeholder="0 2 * * *" />
          </label>

          <div class="field field-wide preset-row">
            <span class="t-label">PRESETS</span>
            <div class="presets">
              <button type="button" *ngFor="let p of cronPresets" class="preset-btn" (click)="applyCronPreset(p.value)">
                {{ p.label }}
              </button>
            </div>
          </div>

          <label class="field field-full config-field">
            <span class="t-label">CONFIG (JSON)</span>
            <textarea name="config_json" [(ngModel)]="form.config_json" rows="5" spellcheck="false"></textarea>
          </label>

          <label class="field toggle-field">
            <span class="t-label">ENABLED</span>
            <label class="switch">
              <input type="checkbox" name="is_enabled" [(ngModel)]="form.is_enabled" />
              <span>{{ form.is_enabled ? 'ON' : 'OFF' }}</span>
            </label>
          </label>

          <div class="actions">
            <button type="submit" class="submit" [disabled]="busy()">
              {{ busy() ? 'SAVING...' : (editingId() ? 'UPDATE' : 'CREATE') }}
            </button>
            <button type="button" class="secondary" (click)="resetForm()" *ngIf="editingId()">
              CANCEL
            </button>
          </div>
        </form>

        <p class="error" *ngIf="formError()">[ERROR] {{ formError() }}</p>
      </section>

      <section class="list-panel">
        <h2 class="t-label">ACTIVE SCHEDULES ({{ schedules().length }})</h2>

        <table class="schedules-table" *ngIf="schedules().length; else emptyState">
          <thead>
            <tr>
              <th>ID</th>
              <th>NAME</th>
              <th>TYPE</th>
              <th>TARGET</th>
              <th>CRON</th>
              <th>NEXT RUN</th>
              <th>LAST RUN</th>
              <th>STATUS</th>
              <th>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let s of schedules()">
              <td>#{{ s.id }}</td>
              <td>{{ s.name }}</td>
              <td>{{ s.scan_type }}</td>
              <td class="truncate">{{ s.target }}</td>
              <td><code>{{ s.cron_expression }}</code></td>
              <td class="muted">{{ s.next_run_at ? (s.next_run_at | date:'yyyy-MM-dd HH:mm') : '—' }}</td>
              <td class="muted">{{ s.last_run_at ? (s.last_run_at | date:'yyyy-MM-dd HH:mm') : '—' }}</td>
              <td>
                <button
                  type="button"
                  class="status-badge"
                  [class.active]="s.is_enabled"
                  [class.inactive]="!s.is_enabled"
                  (click)="toggleEnabled(s)"
                >
                  {{ s.is_enabled ? 'ENABLED' : 'PAUSED' }}
                </button>
              </td>
              <td class="actions-cell">
                <button type="button" class="edit-btn" (click)="edit(s)">EDIT</button>
                <button type="button" class="delete-btn" (click)="deleteSchedule(s)">DELETE</button>
              </td>
            </tr>
          </tbody>
        </table>

        <ng-template #emptyState>
          <p class="empty">[ — NO SCHEDULES CONFIGURED — ]</p>
        </ng-template>

        <p class="error" *ngIf="listError()">[ERROR] {{ listError() }}</p>
      </section>
    </section>
  `,
  styles: [`
    :host { display: block; color: var(--text-primary); }

    .schedules-shell {
      display: flex;
      flex-direction: column;
      gap: var(--space-2xl);
      padding: var(--space-xl);
      max-width: 1400px;
    }

    .page-header { display: flex; flex-direction: column; gap: var(--space-sm); }

    .t-label {
      font-family: var(--font-data);
      font-size: var(--label);
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-secondary);
    }

    .page-title {
      font-family: var(--font-display);
      font-size: var(--display-md);
      font-weight: 400;
      color: var(--text-display);
      letter-spacing: 0.02em;
    }

    .page-subtitle {
      font-family: var(--font-body);
      font-size: var(--body-sm);
      color: var(--text-secondary);
    }

    .create-panel, .list-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      padding: var(--space-xl);
      display: flex;
      flex-direction: column;
      gap: var(--space-lg);
    }

    .create-form {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: var(--space-md);
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: var(--space-xs);
    }

    .field-wide { grid-column: span 2; }
    .field-full { grid-column: 1 / -1; }
    .hint { color: var(--text-disabled); text-transform: none; letter-spacing: 0; }

    .field input, .field select, .field textarea {
      background: var(--black);
      border: 1px solid var(--border-visible);
      color: var(--text-primary);
      font-family: var(--font-data);
      font-size: var(--body-sm);
      padding: var(--space-sm) var(--space-md);
      outline: none;
    }

    .field textarea {
      resize: vertical;
      min-height: 120px;
      font-size: var(--caption);
      line-height: 1.5;
    }

    .field input:focus, .field select:focus, .field textarea:focus { border-color: var(--interactive); }

    .preset-row .presets {
      display: flex;
      flex-wrap: wrap;
      gap: var(--space-xs);
    }

    .preset-btn {
      background: var(--black);
      border: 1px solid var(--border-visible);
      color: var(--text-secondary);
      padding: var(--space-xs) var(--space-sm);
      font-family: var(--font-data);
      font-size: var(--label);
      letter-spacing: 0.08em;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .preset-btn:hover { color: var(--interactive); border-color: var(--interactive); }

    .toggle-field .switch {
      display: inline-flex;
      align-items: center;
      gap: var(--space-sm);
      cursor: pointer;
      color: var(--text-primary);
      font-family: var(--font-data);
      font-size: var(--body-sm);
    }

    .toggle-field input[type="checkbox"] {
      width: 40px;
      height: 20px;
      appearance: none;
      background: var(--surface-raised);
      border: 1px solid var(--border-visible);
      position: relative;
      cursor: pointer;
      transition: background 0.2s ease;
    }

    .toggle-field input[type="checkbox"]::before {
      content: '';
      position: absolute;
      top: 2px;
      left: 2px;
      width: 14px;
      height: 14px;
      background: var(--text-secondary);
      transition: transform 0.2s ease, background 0.2s ease;
    }

    .toggle-field input[type="checkbox"]:checked { background: var(--interactive); }
    .toggle-field input[type="checkbox"]:checked::before { transform: translateX(20px); background: var(--text-display); }

    .actions {
      grid-column: 1 / -1;
      display: flex;
      gap: var(--space-md);
    }

    .submit {
      background: var(--text-display);
      color: var(--black);
      border: none;
      font-family: var(--font-data);
      font-size: var(--body-sm);
      letter-spacing: 0.08em;
      padding: var(--space-md) var(--space-lg);
      cursor: pointer;
    }

    .submit:disabled { opacity: 0.4; cursor: not-allowed; }

    .secondary {
      background: transparent;
      color: var(--text-primary);
      border: 1px solid var(--border-visible);
      font-family: var(--font-data);
      font-size: var(--body-sm);
      letter-spacing: 0.08em;
      padding: var(--space-md) var(--space-lg);
      cursor: pointer;
    }

    .schedules-table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-data);
      font-size: var(--caption);
    }

    .schedules-table th, .schedules-table td {
      padding: var(--space-sm) var(--space-md);
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }

    .schedules-table th { color: var(--text-secondary); letter-spacing: 0.08em; font-weight: 400; }
    .schedules-table td.muted { color: var(--text-disabled); }
    .schedules-table td.truncate {
      max-width: 260px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .schedules-table code {
      background: var(--black);
      padding: 2px 6px;
      border: 1px solid var(--border);
      font-family: var(--font-data);
    }

    .status-badge {
      background: transparent;
      border: 1px solid var(--border-visible);
      padding: 4px 8px;
      cursor: pointer;
      font-family: var(--font-data);
      font-size: var(--label);
      letter-spacing: 0.08em;
    }

    .status-badge.active { color: var(--success); border-color: var(--success); }
    .status-badge.inactive { color: var(--text-disabled); }

    .actions-cell { display: flex; gap: var(--space-xs); }

    .edit-btn, .delete-btn {
      background: transparent;
      padding: 4px 8px;
      cursor: pointer;
      font-family: var(--font-data);
      font-size: var(--label);
      letter-spacing: 0.08em;
    }

    .edit-btn { border: 1px solid var(--interactive); color: var(--interactive); }
    .edit-btn:hover { background: var(--interactive); color: var(--text-display); }

    .delete-btn { border: 1px solid var(--accent); color: var(--accent); }
    .delete-btn:hover { background: var(--accent); color: var(--text-display); }

    .error {
      color: var(--accent);
      font-family: var(--font-data);
      font-size: var(--caption);
    }

    .empty {
      color: var(--text-disabled);
      font-family: var(--font-data);
      letter-spacing: 0.08em;
      text-align: center;
      padding: var(--space-xl);
    }
  `]
})
export class SchedulesComponent implements OnInit {
  private readonly schedulesApi = inject(SchedulesApiService);
  readonly auth = inject(AuthService);

  readonly scanTypeOptions = SCAN_TYPE_OPTIONS;
  readonly cronPresets = CRON_PRESETS;

  readonly schedules = signal<Schedule[]>([]);
  readonly busy = signal(false);
  readonly editingId = signal<number | null>(null);
  readonly formError = signal<string | null>(null);
  readonly listError = signal<string | null>(null);

  form: FormState = this.buildInitialForm();

  readonly selectedTypeDescription = computed(() => {
    const opt = SCAN_TYPE_OPTIONS.find(o => o.value === this.form.scan_type);
    return opt?.description || '';
  });

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.listError.set(null);
    this.schedulesApi.list().subscribe({
      next: (list) => this.schedules.set(list),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  onScanTypeChange(value: ScheduleScanType): void {
    const opt = SCAN_TYPE_OPTIONS.find(o => o.value === value);
    if (opt) this.form.config_json = opt.defaultConfig;
  }

  applyCronPreset(expression: string): void {
    this.form.cron_expression = expression;
  }

  submit(): void {
    if (this.busy()) return;
    this.formError.set(null);

    let parsedConfig: Record<string, unknown>;
    try {
      parsedConfig = this.form.config_json.trim() ? JSON.parse(this.form.config_json) : {};
    } catch {
      this.formError.set('Config must be valid JSON');
      return;
    }

    this.busy.set(true);
    const id = this.editingId();

    const finish = () => {
      this.busy.set(false);
      this.resetForm();
      this.refresh();
    };
    const fail = (err: unknown) => {
      this.busy.set(false);
      this.formError.set(this.errorMessage(err));
    };

    if (id) {
      this.schedulesApi.update(id, {
        name: this.form.name,
        target: this.form.target,
        config: parsedConfig,
        cron_expression: this.form.cron_expression,
        is_enabled: this.form.is_enabled
      }).subscribe({ next: finish, error: fail });
    } else {
      const payload: CreateSchedulePayload = {
        name: this.form.name,
        scan_type: this.form.scan_type,
        target: this.form.target,
        config: parsedConfig,
        cron_expression: this.form.cron_expression,
        is_enabled: this.form.is_enabled
      };
      this.schedulesApi.create(payload).subscribe({ next: finish, error: fail });
    }
  }

  edit(schedule: Schedule): void {
    this.editingId.set(schedule.id);
    this.form = {
      name: schedule.name,
      scan_type: schedule.scan_type,
      target: schedule.target,
      cron_expression: schedule.cron_expression,
      is_enabled: schedule.is_enabled,
      config_json: JSON.stringify(schedule.config ?? {}, null, 2)
    };
    this.formError.set(null);
  }

  resetForm(): void {
    this.editingId.set(null);
    this.form = this.buildInitialForm();
    this.formError.set(null);
  }

  toggleEnabled(schedule: Schedule): void {
    this.schedulesApi.update(schedule.id, { is_enabled: !schedule.is_enabled }).subscribe({
      next: () => this.refresh(),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  deleteSchedule(schedule: Schedule): void {
    if (!confirm(`Delete schedule "${schedule.name}"? This cannot be undone.`)) return;
    this.schedulesApi.delete(schedule.id).subscribe({
      next: () => this.refresh(),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  private buildInitialForm(): FormState {
    return {
      name: '',
      scan_type: 'port_scan',
      target: '',
      cron_expression: '0 2 * * *',
      is_enabled: true,
      config_json: SCAN_TYPE_OPTIONS[0].defaultConfig
    };
  }

  private errorMessage(err: unknown): string {
    const error = err as { error?: { detail?: string | Array<{ msg?: string }> }, message?: string };
    const detail = error?.error?.detail;
    if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg;
    if (typeof detail === 'string') return detail;
    return error?.message || 'Request failed';
  }
}
