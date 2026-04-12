import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';

interface ScanItem {
  id: number;
  domain_target: string;
  status: string;
  scan_type: string;
  created_at: string;
  findings: any[];
  discovered_links?: any[];
}

@Component({
  selector: 'app-history',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './history.component.html',
  styleUrls: ['./history.component.scss']
})
export class HistoryComponent implements OnInit {
  scans: ScanItem[] = [];
  selectedScan: ScanItem | null = null;
  isLoading = true;

  constructor(private http: HttpClient) {}

  ngOnInit() {
    this.fetchHistory();
  }

  fetchHistory() {
    this.isLoading = true;
    this.http.get<ScanItem[]>('http://127.0.0.1:8000/api/scans').subscribe({
      next: (data) => {
        this.scans = data;
        this.isLoading = false;
      },
      error: (err) => {
        console.error('Error fetching history:', err);
        this.isLoading = false;
      }
    });
  }

  deleteScan(id: number, event: Event) {
    event.stopPropagation();
    if (!confirm('Are you sure you want to delete this scan and all its findings?')) return;
    
    this.http.delete(`http://127.0.0.1:8000/api/scans/${id}`).subscribe({
      next: () => {
        // Optimistic UI update
        this.scans = this.scans.filter(s => s.id !== id);
        if (this.selectedScan && this.selectedScan.id === id) {
             this.selectedScan = null;
        }
      },
      error: (err) => console.error('Delete error', err)
    });
  }

  viewDetails(id: number) {
    this.http.get<ScanItem>(`http://127.0.0.1:8000/api/scans/${id}`).subscribe({
      next: (data) => this.selectedScan = data,
      error: (err) => console.error('Detail error', err)
    });
  }
}
