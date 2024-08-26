import { Component, OnInit } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { EventModel } from './event.model';
import { ApiResponse } from './apiResponse.model';
import { CommonModule } from '@angular/common';
import { environment } from '../../environments/environment';
import { FormsModule } from '@angular/forms'; 
import { EventCategory, EventCategoryLabels } from '../create-event/categoryOfEvent.model';

@Component({
  selector: 'app-events',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './events.component.html',
  styleUrls: ['./events.component.css'],
})
export class EventsComponent implements OnInit {
  events: EventModel[] = [];
  filteredEvents: EventModel[] = [];
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));
  totalItems: number = 0;
  currentPage: number = 1;
  totalPages: number = 1;
  itemsPerPage: number = 12;
  noData: boolean = false;
  participationCache: { [eventId: number]: boolean } = {};

  searchTitle: string = '';
  searchDate: string = '';
  filterCategory: string = '';
  filterLocation: string = '';

  constructor(private http: HttpClient) {}

  ngOnInit(): void {
    this.getEvents(this.currentPage);
  }

  getEvents(page: number): void {
    const apiUrl = `${environment.apiBaseUrl}/api/Event/geEventsByPage${page}/${this.itemsPerPage}`;
    this.http.get<ApiResponse>(apiUrl).subscribe(
      (response) => {
        this.events = response.items;
        this.filteredEvents = this.events;
        this.totalItems = response.totalItems;
        this.currentPage = response.pageNumber;
        this.applyFilters();
      },
      (error) => {
        console.log('error: ', error);
        this.noData = true;
      }
    );
  }

  applyFilters(): void {
    
    this.filteredEvents = this.events.filter((event) => {
      const matchesTitle = event.title.toLowerCase().includes(this.searchTitle.toLowerCase());
      const matchesDate = this.searchDate
        ? new Date(event.dateOfEvent).toDateString() === new Date(this.searchDate).toDateString()
        : true;
      const matchesCategory = this.filterCategory
        ? this.getCategory(event.categoryOfEvent) === this.filterCategory
        
        : true;
      const matchesLocation = event.location.toLowerCase().includes(this.filterLocation.toLowerCase());

      return matchesTitle && matchesDate && matchesCategory && matchesLocation;
    });
  }

  updateEventMembers(eventId: number): void {
    const event = this.events.find((e) => e.id === eventId);
    if (event) {
      event.currentNumberOfMember += 1;
    }
  }

  registrationToEvent(eventId: number): void {
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      Authorization: `Bearer ${token}`,
    });
    const apiUrl = `${environment.apiBaseUrl}/api/User/registerToEvent/${eventId}`;
    this.http.post(apiUrl, {}, { headers }).subscribe(
      (response) => {
        this.updateEventMembers(eventId);
      },
      (error) => {
        console.log('error: ', error);
      }
    );
  }

  onPageChange(page: number): void {
    this.getEvents(page);
  }

  getTotalPages(): number {
    return Math.ceil(this.totalItems / this.itemsPerPage);
  }

  getCategory(categoryEvent: string): string {
    const categoryId = Number(categoryEvent);
    if (!isNaN(categoryId) && categoryId >= 0 && categoryId < this.categories.length) {
      return this.categories[categoryId].value;
    } else {
      return 'Unknown Category';
    }
  }
}
