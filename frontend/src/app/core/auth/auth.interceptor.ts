import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { AuthService } from './auth.service';

export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(AuthService);
  const router = inject(Router);

  const token = auth.getToken();
  const authorized = token
    ? req.clone({ setHeaders: { Authorization: `Bearer ${token}` } })
    : req;

  return next(authorized).pipe(
    catchError((error) => {
      if (error instanceof HttpErrorResponse && error.status === 401 && auth.authEnabled) {
        auth.logout();
        router.navigate(['/login'], { queryParams: { redirect: router.url } });
      }
      return throwError(() => error);
    })
  );
};
