import { Component} from '@angular/core';
import { HttpClient,HttpHeaders  } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { Me } from './me.model';
import { environment } from '../../environments/environment';
import { AuthService } from '../services/auth.service';


@Component({
  selector: 'app-me',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './me.component.html',
  styleUrl: './me.component.css'
})
export class MeComponent  {
  me: Me | null = null;
  userRole: string | null = null;
  isAdmin: boolean = false;

  constructor(private http: HttpClient, private authService: AuthService) {}
  

  ngOnInit():void{
    this.userRole = this.authService.gerUserRole();
    this.isAdmin = this.authService.isAdmin();
    this.getCurrentUser();
  }



  getCurrentUser(): void {
    const apiUrl = `${environment.apiBaseUrl}/api/Auth/me`;
    const token = localStorage.getItem('accessToken');

    if (token) {
      const headers = new HttpHeaders({
        'Authorization': `Bearer ${token}`
      });
      console.log(token);
      this.http.get<Me>(apiUrl, { headers }).subscribe(
        response => {
          this.me = response;
        },
        error => {
        }
      );
    } else {
      console.log('No token found');
    }
  }

}
