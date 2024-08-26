import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import { AuthService } from '../services/auth.service';
import { Router } from '@angular/router';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']  // Убедитесь, что используете styleUrls
})
export class RegisterComponent {
  registerForm: FormGroup;
  successMessage: string | null = null;
  errorMessage: string | null = null;

  constructor(private formBuilder: FormBuilder, private authService: AuthService, private router: Router) {
    this.registerForm = this.formBuilder.group({
      name: ['', Validators.required],
      lastName: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(6)]],
      dateOfBirth: ['', Validators.required]
    });
  }

  onSubmit() {
    if (this.registerForm.valid) {
      const { name, lastName, email, password, dateOfBirth } = this.registerForm.value;
      this.authService.register(name, lastName, email, password, dateOfBirth).subscribe(
        data => {
          this.successMessage = data.message;
          this.errorMessage = null;
          this.router.navigate(['/login']);
        },
        error => {
          this.errorMessage = error.error?.message || 'Registration failed. Please try again.';
          this.successMessage = null;
        }
      );
    } else {
      this.errorMessage = 'Please fill out the form correctly.';
      this.successMessage = null;
    }
  }
}