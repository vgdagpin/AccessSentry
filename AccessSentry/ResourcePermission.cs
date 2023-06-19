namespace AccessSentry
{
    public class ResourcePermission
    {
        public short ResourcePermissionID { get; set; }

        public string Action { get; set; }

        public short ResourceID { get; set; }

        public string Name { get; set; }
        public string Description { get; set; }
    }
}