﻿namespace WebApiModsen.WebApiModsen.Application.Exceptions
{
    public class InvalidIdException : Exception
    {
        public InvalidIdException(string message) : base(message) { }
    }
}
