
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import { HttpHeaders } from '@angular/common/http';
import { EventModel } from '../events/event.model';
import { CommonModule } from '@angular/common';
import { environment } from '../../environments/environment';
import { EventCategory, EventCategoryLabels } from '../create-event/categoryOfEvent.model';
import { FormBuilder, FormGroup, Validators, ReactiveFormsModule } from '@angular/forms';



@Component({
  selector: 'app-edit-event',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule],
  templateUrl: './edit-event.component.html',
  styleUrl: './edit-event.component.css'
})
export class EditEventComponent {
  imageFile: File | null = null;
  imageError: string | null = null;
  event: EventModel | null = null;
  eventId: number | null = null;
  eventCategory: number = 0;
  categories = Object.keys(EventCategory).filter(key => isNaN(Number(key))).map(key => ({
    value: key,
    display: EventCategoryLabels[EventCategory[key as keyof typeof EventCategory]]
  }));
  editEventForm: FormGroup;

  constructor(private formBuilder: FormBuilder, private http: HttpClient, private route: ActivatedRoute){
    this.editEventForm = this.formBuilder.group({
    title: ['', Validators.required],
    description: ['', Validators.required],
    dateOfEvent: ['', Validators.required],
    location: ['', Validators.required],
    categoryOfEvent: ['', Validators.required],
    maximumOfMember: [0, Validators.required],
    });
  }

  

  ngOnInit():void{
    this.eventId = +this.route.snapshot.paramMap.get('id')!;
    this.loadCurrentEventData();
    
  }


  loadCurrentEventData():void{
    const apiUrl = `${environment.apiBaseUrl}/api/Event/findById/${this.eventId}`;
    this.http.get<EventModel>(apiUrl).subscribe(response =>{
      this.event = response;
      this.eventCategory = Number(this.event.categoryOfEvent) ?? 0;
      this.editEventForm.patchValue({
        title: this.event.title,
        description: this.event.description,
        dateOfEvent: this.event.dateOfEvent, 
        location: this.event.location,
        categoryOfEvent: EventCategory[this.eventCategory],
        maximumOfMember: this.event.maximumOfMember
      });
      
    }, error => {
      console.log("error load data: ", error);
    }

  )
  }

  onSubmit():void{
    if (this.editEventForm.valid) {
    const apiUrl = `${environment.apiBaseUrl}/api/Event/changeEventInfo/${this.eventId}`;
    const token = localStorage.getItem('accessToken');
    const headers = new HttpHeaders({
      'Authorization': `Bearer ${token}`
    });
    const formData = new FormData();
    formData.append('title', this.editEventForm.get('title')?.value);
    formData.append('description', this.editEventForm.get('description')?.value);
    formData.append('dateOfEvent', this.editEventForm.get('dateOfEvent')?.value);
    formData.append('location', this.editEventForm.get('location')?.value);
    formData.append('categoryOfEvent', this.editEventForm.get('categoryOfEvent')?.value);
    formData.append('maximumOfMember', this.editEventForm.get('maximumOfMember')?.value);
    formData.append('currentNumberOfMember', this.editEventForm.get('currentNumberOfMember')?.value);
    if (this.imageFile) {
      formData.append('image', this.imageFile);
    }
    this.http.patch<void>(apiUrl, formData, {headers}  ).subscribe(
      response =>{
      console.log("ok");
      console.log(response);
    }, error => {
      console.log('error: ', error);
    }
  );}
  else{
    console.log("form invalid");
  }
  }

  onFileChange(evente: Event): void {
    const input = evente.target as HTMLInputElement;
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
