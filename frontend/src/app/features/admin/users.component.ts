import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import {
  CreateUserPayload,
  UserRecord,
  UserRole,
  UsersApiService
} from '../../core/api/users-api.service';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-admin-users',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="admin-shell">
      <header class="admin-header">
        <span class="t-label">SAMURAI // ADMIN</span>
        <h1 class="admin-title">USER MANAGEMENT</h1>
        <p class="admin-subtitle">Provision accounts, assign roles, deactivate.</p>
      </header>

      <section class="create-panel">
        <h2 class="t-label">CREATE USER</h2>
        <form class="create-form" (ngSubmit)="createUser()" autocomplete="off">
          <label class="field">
            <span class="t-label">USERNAME</span>
            <input type="text" name="username" [(ngModel)]="form.username" required minlength="3" />
          </label>
          <label class="field">
            <span class="t-label">EMAIL</span>
            <input type="email" name="email" [(ngModel)]="form.email" required />
          </label>
          <label class="field">
            <span class="t-label">PASSWORD</span>
            <input type="password" name="password" [(ngModel)]="form.password" required minlength="8" />
          </label>
          <label class="field">
            <span class="t-label">ROLE</span>
            <select name="role" [(ngModel)]="form.role">
              <option value="viewer">VIEWER</option>
              <option value="operator">OPERATOR</option>
              <option value="admin">ADMIN</option>
            </select>
          </label>
          <button type="submit" class="submit" [disabled]="busy()">
            {{ busy() ? 'CREATING...' : 'CREATE' }}
          </button>
        </form>
        <p class="error" *ngIf="createError()">[ERROR] {{ createError() }}</p>
      </section>

      <section class="list-panel">
        <h2 class="t-label">USERS ({{ users().length }})</h2>
        <table class="users-table" *ngIf="users().length; else emptyState">
          <thead>
            <tr>
              <th>ID</th>
              <th>USERNAME</th>
              <th>EMAIL</th>
              <th>ROLE</th>
              <th>STATUS</th>
              <th>CREATED</th>
              <th>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            <tr *ngFor="let u of users()" [class.self]="u.id === currentUserId()">
              <td>#{{ u.id }}</td>
              <td>{{ u.username }}</td>
              <td>{{ u.email }}</td>
              <td>
                <select
                  [ngModel]="u.role"
                  (ngModelChange)="changeRole(u, $event)"
                  [disabled]="u.id === currentUserId()"
                >
                  <option value="viewer">VIEWER</option>
                  <option value="operator">OPERATOR</option>
                  <option value="admin">ADMIN</option>
                </select>
              </td>
              <td>
                <button
                  type="button"
                  class="status-badge"
                  [class.active]="u.is_active"
                  [class.inactive]="!u.is_active"
                  [disabled]="u.id === currentUserId()"
                  (click)="toggleActive(u)"
                >
                  {{ u.is_active ? 'ACTIVE' : 'INACTIVE' }}
                </button>
              </td>
              <td class="created">{{ u.created_at | date:'yyyy-MM-dd HH:mm' }}</td>
              <td>
                <button
                  type="button"
                  class="delete-btn"
                  [disabled]="u.id === currentUserId()"
                  (click)="deleteUser(u)"
                >
                  DELETE
                </button>
              </td>
            </tr>
          </tbody>
        </table>
        <ng-template #emptyState>
          <p class="empty">[ — NO USERS FOUND — ]</p>
        </ng-template>
        <p class="error" *ngIf="listError()">[ERROR] {{ listError() }}</p>
      </section>
    </section>
  `,
  styles: [`
    :host { display: block; color: var(--text-primary); }

    .admin-shell {
      display: flex;
      flex-direction: column;
      gap: var(--space-2xl);
      padding: var(--space-xl);
      max-width: 1200px;
    }

    .admin-header {
      display: flex;
      flex-direction: column;
      gap: var(--space-sm);
    }

    .t-label {
      font-family: var(--font-data);
      font-size: var(--label);
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--text-secondary);
    }

    .admin-title {
      font-family: var(--font-display);
      font-size: var(--display-md);
      font-weight: 400;
      color: var(--text-display);
      letter-spacing: 0.02em;
    }

    .admin-subtitle {
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
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: var(--space-md);
      align-items: end;
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: var(--space-xs);
    }

    .field input, .field select {
      background: var(--black);
      border: 1px solid var(--border-visible);
      color: var(--text-primary);
      font-family: var(--font-data);
      font-size: var(--body-sm);
      padding: var(--space-sm) var(--space-md);
      outline: none;
    }

    .field input:focus, .field select:focus {
      border-color: var(--interactive);
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
      height: fit-content;
    }

    .submit:disabled { opacity: 0.4; cursor: not-allowed; }

    .users-table {
      width: 100%;
      border-collapse: collapse;
      font-family: var(--font-data);
      font-size: var(--caption);
    }

    .users-table th, .users-table td {
      padding: var(--space-sm) var(--space-md);
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    .users-table th {
      color: var(--text-secondary);
      letter-spacing: 0.08em;
      font-weight: 400;
    }

    .users-table tr.self td { background: var(--surface-raised); }

    .users-table select {
      background: var(--black);
      border: 1px solid var(--border-visible);
      color: var(--text-primary);
      padding: 4px 8px;
      font-family: var(--font-data);
      font-size: var(--caption);
    }

    .users-table .created { color: var(--text-disabled); }

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
    .status-badge:disabled { opacity: 0.5; cursor: not-allowed; }

    .delete-btn {
      background: transparent;
      border: 1px solid var(--accent);
      color: var(--accent);
      padding: 4px 8px;
      cursor: pointer;
      font-family: var(--font-data);
      font-size: var(--label);
      letter-spacing: 0.08em;
    }

    .delete-btn:disabled { opacity: 0.3; cursor: not-allowed; }
    .delete-btn:hover:not(:disabled) { background: var(--accent); color: var(--text-display); }

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
export class UsersAdminComponent implements OnInit {
  private readonly usersApi = inject(UsersApiService);
  private readonly auth = inject(AuthService);

  readonly users = signal<UserRecord[]>([]);
  readonly busy = signal(false);
  readonly createError = signal<string | null>(null);
  readonly listError = signal<string | null>(null);

  form: CreateUserPayload = {
    username: '',
    email: '',
    password: '',
    role: 'viewer'
  };

  currentUserId(): number | null {
    return this.auth.currentUser()?.id ?? null;
  }

  ngOnInit(): void {
    this.refresh();
  }

  refresh(): void {
    this.listError.set(null);
    this.usersApi.list().subscribe({
      next: (users) => this.users.set(users),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  createUser(): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.createError.set(null);
    this.usersApi.create(this.form).subscribe({
      next: () => {
        this.busy.set(false);
        this.form = { username: '', email: '', password: '', role: 'viewer' };
        this.refresh();
      },
      error: (err) => {
        this.busy.set(false);
        this.createError.set(this.errorMessage(err));
      }
    });
  }

  changeRole(user: UserRecord, role: UserRole): void {
    if (role === user.role) return;
    this.usersApi.update(user.id, { role }).subscribe({
      next: () => this.refresh(),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  toggleActive(user: UserRecord): void {
    this.usersApi.update(user.id, { is_active: !user.is_active }).subscribe({
      next: () => this.refresh(),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  deleteUser(user: UserRecord): void {
    if (!confirm(`Delete user "${user.username}"? This cannot be undone.`)) return;
    this.usersApi.delete(user.id).subscribe({
      next: () => this.refresh(),
      error: (err) => this.listError.set(this.errorMessage(err))
    });
  }

  private errorMessage(err: unknown): string {
    const error = err as { error?: { detail?: string }, message?: string };
    return error?.error?.detail || error?.message || 'Request failed';
  }
}
