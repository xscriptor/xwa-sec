import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const adminGuard: CanActivateFn = () => {
  const auth = inject(AuthService);
  const router = inject(Router);

  if (!auth.authEnabled) {
    return true;
  }

  if (auth.currentUser()?.role === 'admin') {
    return true;
  }

  return router.createUrlTree(['/scanner']);
};
