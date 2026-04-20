import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../../core/auth/auth.service';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule, FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="login-shell">
      <div class="login-card">
        <header class="login-header">
          <span class="t-label">SAMURAI // ACCESS</span>
          <h1 class="login-title">AUTHENTICATE</h1>
          <p class="login-subtitle">Restricted engine. Credentials required.</p>
        </header>

        <form class="login-form" (ngSubmit)="submit()" autocomplete="off">
          <label class="field">
            <span class="t-label">USERNAME</span>
            <input
              type="text"
              name="username"
              [(ngModel)]="username"
              [disabled]="submitting()"
              required
              autocomplete="username"
            />
          </label>

          <label class="field">
            <span class="t-label">PASSWORD</span>
            <input
              type="password"
              name="password"
              [(ngModel)]="password"
              [disabled]="submitting()"
              required
              autocomplete="current-password"
            />
          </label>

          <button type="submit" class="submit" [disabled]="submitting() || !username || !password">
            {{ submitting() ? 'AUTHENTICATING...' : 'ENTER' }}
          </button>

          <p class="error" *ngIf="error()">[ERROR] {{ error() }}</p>
          <p class="hint" *ngIf="!auth.authEnabled">[ i ] Auth disabled in this environment. Any credentials pass.</p>
        </form>
      </div>
    </section>
  `,
  styles: [`
    :host {
      display: block;
      min-height: 100vh;
      background: var(--black);
    }

    .login-shell {
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: var(--space-2xl);
    }

    .login-card {
      width: 100%;
      max-width: 420px;
      background: var(--surface);
      border: 1px solid var(--border);
      padding: var(--space-2xl);
      display: flex;
      flex-direction: column;
      gap: var(--space-xl);
    }

    .login-header {
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

    .login-title {
      font-family: var(--font-display);
      font-size: var(--display-md);
      font-weight: 400;
      color: var(--text-display);
      letter-spacing: 0.02em;
    }

    .login-subtitle {
      font-family: var(--font-body);
      font-size: var(--body-sm);
      color: var(--text-secondary);
    }

    .login-form {
      display: flex;
      flex-direction: column;
      gap: var(--space-md);
    }

    .field {
      display: flex;
      flex-direction: column;
      gap: var(--space-xs);
    }

    .field input {
      background: var(--black);
      border: 1px solid var(--border-visible);
      color: var(--text-primary);
      font-family: var(--font-data);
      font-size: var(--body-sm);
      padding: var(--space-sm) var(--space-md);
      outline: none;
      transition: border-color 260ms cubic-bezier(0.16, 1, 0.3, 1);
    }

    .field input:focus {
      border-color: var(--interactive);
    }

    .field input:disabled {
      opacity: 0.5;
    }

    .submit {
      margin-top: var(--space-sm);
      background: var(--text-display);
      color: var(--black);
      border: none;
      font-family: var(--font-data);
      font-size: var(--body-sm);
      letter-spacing: 0.08em;
      padding: var(--space-md) var(--space-lg);
      cursor: pointer;
      transition: opacity 260ms cubic-bezier(0.16, 1, 0.3, 1);
    }

    .submit:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .error {
      font-family: var(--font-data);
      font-size: var(--caption);
      color: var(--accent);
      letter-spacing: 0.06em;
    }

    .hint {
      font-family: var(--font-data);
      font-size: var(--caption);
      color: var(--text-disabled);
      letter-spacing: 0.06em;
    }
  `]
})
export class LoginComponent {
  readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  username = '';
  password = '';
  readonly submitting = signal(false);
  readonly error = signal<string | null>(null);

  submit(): void {
    if (this.submitting()) return;

    const redirect = this.route.snapshot.queryParamMap.get('redirect') || '/scanner';

    if (!this.auth.authEnabled) {
      this.router.navigateByUrl(redirect);
      return;
    }

    this.submitting.set(true);
    this.error.set(null);

    this.auth.login({ username: this.username, password: this.password }).subscribe({
      next: () => {
        this.submitting.set(false);
        this.router.navigateByUrl(redirect);
      },
      error: (err) => {
        this.submitting.set(false);
        this.error.set(err?.error?.detail || err?.message || 'Authentication failed');
      }
    });
  }
}
