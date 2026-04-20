import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';
import { adminGuard } from './core/auth/admin.guard';

export const routes: Routes = [
    {
        path: 'login',
        loadComponent: () => import('./features/auth/login.component').then(m => m.LoginComponent)
    },
    {
        path: 'scanner',
        canActivate: [authGuard],
        loadComponent: () => import('./features/scanner/scanner.component').then(m => m.ScannerComponent)
    },
    {
        path: 'recon',
        canActivate: [authGuard],
        loadComponent: () => import('./features/recon/recon.component').then(m => m.ReconComponent)
    },
    {
        path: 'vulnerabilities',
        canActivate: [authGuard],
        loadComponent: () => import('./features/vulnerabilities/vulnerabilities.component').then(m => m.VulnerabilitiesComponent)
    },
    {
        path: 'history',
        canActivate: [authGuard],
        loadComponent: () => import('./features/history/history.component').then(m => m.HistoryComponent)
    },
    {
        path: 'admin/users',
        canActivate: [authGuard, adminGuard],
        loadComponent: () => import('./features/admin/users.component').then(m => m.UsersAdminComponent)
    },
    {
        path: '',
        redirectTo: '/scanner',
        pathMatch: 'full'
    }
];
