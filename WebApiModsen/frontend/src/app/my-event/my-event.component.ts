import { Component} from '@angular/core';
import { HttpClient,HttpHeaders } from '@angular/common/http';
import { EventModel } from '../events/event.model'; 
import { CommonModule } from '@angular/common';
import { environment } from '../../environments/environment';
import { EventCategory, EventCategoryLabels } from '../create-event/categoryOfEvent.model';

@Component({
  selector: 'app-my-event',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './my-event.component.html',
  styleUrl: './my-event.component.css'
})
export class MyEventsComponent {

  events: EventModel[] = [];
  noData: boolean = false;
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));

  constructor(private http: HttpClient) {}

  ngOnInit(): void{
    this.getEvents();
    
  }
  
  getEvents(): void{
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    console.log(headers);
    const apiUrl = `${environment.apiBaseUrl}/api/Event/getUserEvents`;
    this.http.get<EventModel[]>(apiUrl, { headers }).subscribe(response =>{
      this.events = response
    },
    (error)=>{
      console.log('error: ', error);
      this.noData = true;
    }
    );
  }

  getCategory(categoryEvent: string): string {
    const categoryId = Number(categoryEvent);
    if (!isNaN(categoryId) && categoryId >= 0 && categoryId < this.categories.length) {
      return this.categories[categoryId].value;
    } else {
      return 'Unknown Category';
    }
  }

  cancelParticipation(eventId: number):void{
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    const apiUrl = `${environment.apiBaseUrl}/api/User/removeFromParticipation/${eventId}`;
    this.http.delete<void>(apiUrl , {headers}).subscribe(response =>{
      console.log("ok");
      this.getEvents();
    },
    (error) =>{
      console.log('error: ', error);
    }
  )
  }


}
