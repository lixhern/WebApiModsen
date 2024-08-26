import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';


@Component({
  selector: 'app-login',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './login.component.html',
  styleUrl: './login.component.css'
})
export class LoginComponent {
  loginForm: FormGroup;
  errorMessage: string | null = null;

  constructor(private formBuilder: FormBuilder, private authService: AuthService, private router: Router) {
    this.loginForm = this.formBuilder.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required]
    });
  }

  onSubmit() {
    if (this.loginForm.valid) {
      const { email, password } = this.loginForm.value;
      this.authService.login(email, password).subscribe(
        data => {
          this.authService.saveToken(data.accessToken);
          this.authService.saveRefreshToken(data.refreshToken);
          this.authService.saveUserName(data.userName);
          this.router.navigate(['/home']);
        },
        error => {
          this.errorMessage = 'Invalid credentials. Please try again.';
        }
      );
    } else {
      this.errorMessage = 'Please fill out the form correctly.';
    }
  }
}
