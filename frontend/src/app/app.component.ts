import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject } from '@angular/core';
import { NavigationEnd, Router, RouterModule } from '@angular/router';
import { toSignal } from '@angular/core/rxjs-interop';
import { filter, map, startWith } from 'rxjs';
import { ThemeService } from './services/theme.service';
import { AuthService } from './core/auth/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  readonly themeService = inject(ThemeService);
  readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  private readonly currentUrl = toSignal(
    this.router.events.pipe(
      filter((event): event is NavigationEnd => event instanceof NavigationEnd),
      map((event) => event.urlAfterRedirects),
      startWith(this.router.url)
    ),
    { initialValue: this.router.url }
  );

  readonly isAuthRoute = computed(() => {
    const url = this.currentUrl();
    return url.startsWith('/login');
  });

  readonly showShell = computed(() => {
    return !this.isAuthRoute() && (this.auth.isAuthenticated() || !this.auth.authEnabled);
  });

  readonly userLabel = computed(() => {
    const user = this.auth.currentUser();
    return user ? user.username : '—';
  });

  readonly roleLabel = computed(() => {
    const user = this.auth.currentUser();
    return user ? user.role.toUpperCase() : '';
  });

  readonly isAdmin = computed(() => this.auth.currentUser()?.role === 'admin');

  ngOnInit(): void {
    this.themeService.initTheme();
  }

  toggleTheme(): void {
    this.themeService.toggleTheme();
  }

  logout(): void {
    this.auth.logout();
    this.router.navigate(['/login']);
  }
}
