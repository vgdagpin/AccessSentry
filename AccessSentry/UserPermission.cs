namespace AccessSentry
{
    public class UserPermission
    {
        public string Source { get; set; } = null!;

        public string Action { get; set; } = null!;
        public string Resource { get; set; } = null!;
        public bool Allow { get; set; }
    }
}