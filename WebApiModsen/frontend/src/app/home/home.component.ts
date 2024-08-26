import { Component} from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { User } from './user.model';
import { EventModel } from '../events/event.model';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';
import { environment } from '../../environments/environment';
import { EventCategory, EventCategoryLabels } from '../create-event/categoryOfEvent.model';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent {
  events: EventModel[] = [];
  users: User[] = [];
  inputValue: string = '';
  selectedUser: User | null = null;
  errorMessage: string | null = null;
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));
  isAuthenticated = false;
  userName: string | null = null;

  constructor(private http: HttpClient, private authService: AuthService, private router: Router){}

  ngOnInit(): void{
    this.isAuthenticated = this.authService.isAuthenticated();
    if (this.isAuthenticated) {
      this.userName = localStorage.getItem('userName');
    }
    this.getAllUsers();
    this.getAllEvents();
  }

  getAllUsers(): void{
    const apiUrl = `${environment.apiBaseUrl}/api/User/getAllUsers`;
    this.http.get<User[]>(apiUrl).subscribe(
      (response) => {
        this.users = response; 
      },
      (error) => {
        console.log("error: ", error);
      }
    );
  }

  getAllEvents(): void{
    const apiUrl = `${environment.apiBaseUrl}/api/Event`;
    this.http.get<EventModel[]>(apiUrl).subscribe(response =>{
      this.events = response;
    },
    (error)=>{
      console.log('error: ', error);
    }
    );
  }
  
  onInput(event: Event): void {
    const inputElement = event.target as HTMLInputElement;
    this.inputValue = inputElement.value;
  }
  
  onSubmit(): void {
    const apiUrl = "https://localhost:7029/api/User/getUserById"+this.inputValue
    this.http.get<User>(apiUrl).subscribe(
      (response) => {
        this.selectedUser = response;
      },
      (error) =>{
        console.log("error: ", error);
        this.errorMessage = error.error;
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
