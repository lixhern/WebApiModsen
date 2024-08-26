import { Component} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { HttpHeaders } from '@angular/common/http';
import { EventModel } from '../events/event.model';
import { CommonModule } from '@angular/common';
import { environment } from '../../environments/environment';
import { EventCategory, EventCategoryLabels } from '../create-event/categoryOfEvent.model';
import { User } from '../home/user.model';

@Component({
  selector: 'app-event',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './event.component.html',
  styleUrl: './event.component.css'
})
export class EventComponent {
  users: User[] = [];
  event: EventModel | null = null;
  eventId: number | null = null;
  isParticipan: boolean = false;
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));


  constructor(private route: ActivatedRoute, private http: HttpClient) {}

  async ngOnInit(): Promise<void> {
    this.eventId = +this.route.snapshot.paramMap.get('id')!;
    this.loadEventDetails(this.eventId);
    this.loadParticipantsOfEvent(this.eventId);
    this.isParticipan = await this.CheckForParticipan(this.eventId);
  }
  

  registrationToEvent(eventId: number):void{
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    console.log(headers);
    const apiUrl = `${environment.apiBaseUrl}/api/User/registerToEvent/${eventId}`;
    this.http.post(apiUrl,{}, {headers}).subscribe(response => {
      this.upadateEventMember();
      this.loadParticipantsOfEvent(eventId);
      this.isParticipan = true;
    },
    (error) => {
      console.log('error: ', error);
    }
  )
    console.log(eventId);
  }

  async CheckForParticipan(eventId: number): Promise<boolean> {
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    const apiUrl = `${environment.apiBaseUrl}/api/User/isUserParticipation/${eventId}`;
    
    try {
      const response = await this.http.get<boolean>(apiUrl, { headers }).toPromise();
      return response ?? false;
    } catch (error) {
      console.error('Error during HTTP request', error);
      return false;
    }
  }

  upadateEventMember(): void{
    if(this.event){
      this.event.currentNumberOfMember += 1;
    }
  }

  loadEventDetails(eventId: number): void {
    if (this.eventId !== null) {
      const url = `${environment.apiBaseUrl}/api/Event/findById/${this.eventId}`;
      this.http.get<EventModel>(url).subscribe(response => {
        this.event = response;
      }, error => {
        console.error(error);
      });
    }
  }

  loadParticipantsOfEvent(eventId: number){
    const url = `${environment.apiBaseUrl}/api/User/getMembersOfEvent/${this.eventId}`;
    this.http.get<User[]>(url).subscribe(respone => {
      this.users = respone;
    }, error => {
      if (error.status === 404) {
        this.users = [];
      }
      console.error(error);
    }
  )
  }

  cancelParticipation(eventId: number):void{
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    const apiUrl = `${environment.apiBaseUrl}/api/User/removeFromParticipation/${eventId}`;
    this.http.delete<void>(apiUrl , {headers}).subscribe(response =>{
      this.loadEventDetails(eventId);
      this.loadParticipantsOfEvent(eventId);
      this.isParticipan = false;
    },
    (error) =>{
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
