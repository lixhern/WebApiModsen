import { ApplicationConfig } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, HTTP_INTERCEPTORS  } from '@angular/common/http';  // Добавьте импорт
import { provideClientHydration } from '@angular/platform-browser';
import { AuthInterceptor } from './interceptors/auth.interceptor';
import { routes } from './app.routes';


export const appConfig: ApplicationConfig = {
  providers: [
    
    provideHttpClient(),
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    },
    provideRouter(routes),
    provideClientHydration()
  ]
};
