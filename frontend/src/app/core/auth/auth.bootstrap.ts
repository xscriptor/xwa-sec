import { APP_INITIALIZER, Provider } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { AuthService } from './auth.service';

export function provideAuthBootstrap(): Provider {
  return {
    provide: APP_INITIALIZER,
    multi: true,
    deps: [AuthService],
    useFactory: (auth: AuthService) => () => {
      if (!auth.authEnabled || !auth.getToken()) {
        return Promise.resolve();
      }
      return firstValueFrom(auth.fetchCurrentUser()).catch(() => undefined);
    }
  };
}
