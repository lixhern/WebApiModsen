namespace WebApiModsen.WebApiModsen.Core.Models
{
    public class ItemPageResult<T> where T : class
    {
        public int TotalItems { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public List<T> Items { get; set; }
    }
}
