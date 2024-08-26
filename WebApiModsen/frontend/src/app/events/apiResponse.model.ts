import { EventModel } from './event.model';

export interface ApiResponse {
    totalItems: number;
    pageNumber: number;
    pageSize: number;
    items: EventModel[];
  }