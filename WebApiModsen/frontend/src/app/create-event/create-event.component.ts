import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';
import {HttpClient, HttpHeaders } from '@angular/common/http';
import { CommonModule } from '@angular/common';
import { EventCategory, EventCategoryLabels } from './categoryOfEvent.model';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-create-event',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './create-event.component.html',
  styleUrls: ['./create-event.component.css']
})
export class CreateEventComponent {
  imageFile: File | null = null;
  imageError: string | null = null;


  createEventForm: FormGroup;
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));
  successMessage: string | null = null;
  errorMessage: string | null = null;

  constructor(private formBuilder: FormBuilder, private http: HttpClient) {
    this.createEventForm = this.formBuilder.group({
      title: ['', Validators.required],
      description: ['', Validators.required],
      dateOfEvent: ['', Validators.required],
      location: ['', Validators.required],
      categoryOfEvent: ['', Validators.required],
      maximumOfMember: ['', Validators.required],
    });
  }
  onSubmit() {
    if (this.createEventForm.valid) {
      console.log('Form Value:', this.createEventForm.value);
  
      const token = localStorage.getItem('accessToken');
      if (!token) {
        this.errorMessage = 'Authorization token is missing.';
        this.successMessage = null;
        return;
      }
  
      const headers = new HttpHeaders({
        'Authorization': `Bearer ${token}`
      });
  
      const formData = new FormData();
      formData.append('title', this.createEventForm.get('title')?.value);
      formData.append('description', this.createEventForm.get('description')?.value);
      formData.append('dateOfEvent', this.createEventForm.get('dateOfEvent')?.value);
      formData.append('location', this.createEventForm.get('location')?.value);
      formData.append('categoryOfEvent', this.createEventForm.get('categoryOfEvent')?.value);
      formData.append('maximumOfMember', this.createEventForm.get('maximumOfMember')?.value);

      if (this.imageFile) {
        formData.append('image', this.imageFile);
      }
      const apiUrl = `${environment.apiBaseUrl}/api/Event/createEvent`;
      this.http.post(apiUrl, formData, { headers })
        .subscribe(
          response => {
            this.successMessage = 'Event created successfully!';
            this.errorMessage = null;
          },
          error => {
            console.error('Error response:', error);
            this.errorMessage = 'An error occurred while creating the event.';
            this.successMessage = null;
          }
        );
    } else {
      this.errorMessage = 'Please fill out the form correctly.';
      this.successMessage = null;
    }
  }

  onFileChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      const file = input.files[0];
      if (file.type.startsWith('image/')) {
        this.imageFile = file;
        this.imageError = null;
      } else {
        this.imageError = 'Only image files are allowed.';
        this.imageFile = null;
      }
    }
  }
  
}
