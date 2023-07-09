namespace AccessSentry.Interfaces
{
    public interface IPolicyProvider
    {
        string GetPolicy(string? subject = null);
    }
}
