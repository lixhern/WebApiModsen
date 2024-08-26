import { Component, NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home.component';
import { EventsComponent } from './events/events.component';
import { EventComponent } from './event/event.component';
import { RegisterComponent } from './register/register.component';
import { LoginComponent } from './login/login.component';
import { MeComponent } from './me/me.component';
import { CreateEventComponent } from './create-event/create-event.component';
import { MyEventsComponent } from './my-event/my-event.component';
import { NavbarComponent } from './navbar/navbar.component';
import { AdminMenuComponent } from './admin-menu/admin-menu.component';
import { EditEventComponent } from './edit-event/edit-event.component';


export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'events', component: EventsComponent },
  { path: 'event/:id', component: EventComponent},
  { path: 'register', component: RegisterComponent},
  { path: 'login', component: LoginComponent},
  { path: 'me', component: MeComponent},
  { path: 'create-event', component: CreateEventComponent},
  { path: 'my-event', component: MyEventsComponent},
  { path: 'navbar', component: NavbarComponent},
  { path: 'admin-menu', component: AdminMenuComponent},
  { path: 'edit-event/:id', component: EditEventComponent}
  
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
