﻿namespace WebApiModsen.WebApiModsen.Application.Exceptions
{
    public class ItemNotFoundException : Exception
    {
        public ItemNotFoundException(string message) : base(message) { }
    }
}
