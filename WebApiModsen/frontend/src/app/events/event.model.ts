export interface EventModel {
    target: HTMLInputElement;
    id: number,
    title: string;
    description: string;
    dateOfEvent: string;
    location: string;
    categoryOfEvent: string;
    maximumOfMember: number;
    currentNumberOfMember: number;
    imageUrl: string;
  }