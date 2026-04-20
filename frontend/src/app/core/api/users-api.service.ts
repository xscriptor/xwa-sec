import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ApiConfigService } from './api-config.service';

export type UserRole = 'admin' | 'operator' | 'viewer';

export interface UserRecord {
  id: number;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
}

export interface CreateUserPayload {
  username: string;
  email: string;
  password: string;
  role: UserRole;
}

export interface UpdateUserPayload {
  email?: string;
  role?: UserRole;
  is_active?: boolean;
  password?: string;
}

@Injectable({ providedIn: 'root' })
export class UsersApiService {
  private readonly http = inject(HttpClient);
  private readonly api = inject(ApiConfigService);

  list(): Observable<UserRecord[]> {
    return this.http.get<UserRecord[]>(this.api.http('/api/users'));
  }

  create(payload: CreateUserPayload): Observable<UserRecord> {
    return this.http.post<UserRecord>(this.api.http('/api/users'), payload);
  }

  update(id: number, payload: UpdateUserPayload): Observable<UserRecord> {
    return this.http.patch<UserRecord>(this.api.http(`/api/users/${id}`), payload);
  }

  delete(id: number): Observable<unknown> {
    return this.http.delete(this.api.http(`/api/users/${id}`));
  }
}
