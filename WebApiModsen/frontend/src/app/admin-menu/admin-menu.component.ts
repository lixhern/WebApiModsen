import { Router } from '@angular/router';
import { Component} from '@angular/core';
import { HttpClient} from '@angular/common/http';
import { EventModel } from '../events/event.model'; 
import { CommonModule } from '@angular/common';
import { EventCategory, EventCategoryLabels } from '../create-event/categoryOfEvent.model';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-admin-menu',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './admin-menu.component.html',
  styleUrl: './admin-menu.component.css'
})
export class AdminMenuComponent {
  events: EventModel[] = [];
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));

  constructor(private router: Router, private http: HttpClient){}

  ngOnInit(): void{
    this.getAllEvents();
  }

  createEvent(): void{
    this.router.navigate(['/create-event']);
  }

  getAllEvents():void{
    const apiUrl = `${environment.apiBaseUrl}/api/Event`;
    this.http.get<EventModel[]>(apiUrl).subscribe(response =>{
      this.events = response;
    },
    (error)=>{
      console.log('error: ', error);
    }
    );
  }

  editEvent(eventId: number): void{
    this.router.navigate([`edit-event/${eventId}`]);
  }

  delteEvent(eventId: number): void{
    const apiUrl = `${environment.apiBaseUrl}/api/Event/deleteEvent/${eventId}`;
    this.http.delete<void>(apiUrl).subscribe(response =>{
      console.log(response);
      this.getAllEvents();
    },
    (error) =>{
      console.log('error: ', error);
    }
  )
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
