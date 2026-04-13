import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Finding } from '../../../../models/vulnerabilities.models';

@Component({
  selector: 'app-finding-item',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './finding-item.component.html',
  styleUrls: ['./finding-item.component.scss']
})
export class FindingItemComponent {
  @Input() finding!: Finding;
}
