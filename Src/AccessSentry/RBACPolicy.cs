namespace AccessSentry
{
    public class RBACPolicy
    {
        public string Subject { get; set; } = null!;
        public string ResourceName { get; set; } = null!;
        public string Action { get; set; } = null!;
        public bool Allow { get; set; }
    }
}