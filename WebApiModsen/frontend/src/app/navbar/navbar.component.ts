import { Component, Injector} from '@angular/core';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';


@Component({
  selector: 'app-navbar',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './navbar.component.html',
  styleUrl: './navbar.component.css'
})
export class NavbarComponent {
  isLoggedIn : boolean = false;
  private authService!: AuthService;
  isAdmin: boolean = false;

  constructor(private injector: Injector, private router: Router) { }

  ngOnInit(): void {
    
    
    this.authService = this.injector.get(AuthService);
    this.authService.authStatus$.subscribe(isLoggedIn => {
      this.isLoggedIn = isLoggedIn;
    });
    this.isAdmin = this.authService.isAdmin();
  }

  logout(): void {
    this.authService.logout();
    this.router.navigate(['/home']).then(() => {
      window.location.reload();
    });
  }

  toMyEvents():void{
    this.router.navigate(['/my-event']);
  }

  toAdminMenu():void{
    this.router.navigate(['/admin-menu']);
  }

  toMe():void{
    this.router.navigate(['/me']);
  }

  toLogin():void{
    this.router.navigate(['/login']);
  }

  toRegister():void{
    this.router.navigate(['/register']);
  }

  toEvents():void{
    this.router.navigate(['/events']);
  }

  toHome():void{
    this.router.navigate(['/home']);
  }
}
