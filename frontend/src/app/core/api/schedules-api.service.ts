import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { ApiConfigService } from './api-config.service';

export type ScheduleScanType = 'port_scan' | 'web_recon' | 'vuln_crawl';

export interface Schedule {
  id: number;
  name: string;
  scan_type: ScheduleScanType;
  target: string;
  config: Record<string, unknown>;
  cron_expression: string;
  is_enabled: boolean;
  created_by_id: number | null;
  created_at: string;
  updated_at: string;
  last_run_at: string | null;
  next_run_at: string | null;
  last_scan_id: number | null;
}

export interface CreateSchedulePayload {
  name: string;
  scan_type: ScheduleScanType;
  target: string;
  config: Record<string, unknown>;
  cron_expression: string;
  is_enabled: boolean;
}

export interface UpdateSchedulePayload {
  name?: string;
  target?: string;
  config?: Record<string, unknown>;
  cron_expression?: string;
  is_enabled?: boolean;
}

@Injectable({ providedIn: 'root' })
export class SchedulesApiService {
  private readonly http = inject(HttpClient);
  private readonly api = inject(ApiConfigService);

  list(): Observable<Schedule[]> {
    return this.http.get<Schedule[]>(this.api.http('/api/schedules'));
  }

  create(payload: CreateSchedulePayload): Observable<Schedule> {
    return this.http.post<Schedule>(this.api.http('/api/schedules'), payload);
  }

  update(id: number, payload: UpdateSchedulePayload): Observable<Schedule> {
    return this.http.patch<Schedule>(this.api.http(`/api/schedules/${id}`), payload);
  }

  delete(id: number): Observable<unknown> {
    return this.http.delete(this.api.http(`/api/schedules/${id}`));
  }
}
