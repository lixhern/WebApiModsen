import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { environment } from '../../environments/environment';
import { decodeJwt } from 'jose';
import { response } from 'express';


@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = `${environment.apiBaseUrl}`; 
  private authSubject = new BehaviorSubject<boolean>(this.isAuthenticated());
  authStatus$ = this.authSubject.asObservable(); // Observable для подписки

  constructor(private http: HttpClient) {

  }

  login(email: string, password: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/api/Auth/login`, { email, password }).pipe(
      tap(response => {
        this.authSubject.next(true);
      })
    )
  }

  register(name: string, lastName: string, email: string, password: string, dateOfBirth: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/api/Auth/register`, { name, lastName, email, password, dateOfBirth });
  }
  
  isAuthenticated(): boolean {
    const token = localStorage.getItem('accessToken');
    return !!token; // Если токен существует, возвращаем true
  }

  logout(): void {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('userName');
    this.authSubject.next(false); 
  }

  saveToken(token: string): void {
    localStorage.setItem('accessToken', token);
  }

  saveRefreshToken(refreshToken: string): void {
    localStorage.setItem('refreshToken', refreshToken);
  }

  saveUserName(userName: string): void{
    localStorage.setItem('userName', userName);
  }

  getToken(): string | null {
    return localStorage.getItem('accessToken');
  }

  getUserName(): string | null{
    return localStorage.getItem('userName');
  }

  getRefreshToken(): string | null {
    return localStorage.getItem('refreshToken');
  }

  gerUserRole(): string | null{
    const token = localStorage.getItem('accessToken');
    if(token){
      const decodedToken: any = decodeJwt(token);
      return decodedToken['role'];
    }
    return null;
  }

  isAdmin(): boolean{
    const role = this.gerUserRole();
    return role == "Admin";
  }
  
}
