namespace AccessSentry
{
    public class Permission
    {
        public string Action { get; set; }
        public string Resource { get; set; }

        private Permission(string resource, string action) 
        {
            Resource = resource;
            Action = action;
        }

        public static Permission? Parse(string permission)
        {
            if (string.IsNullOrWhiteSpace(permission))
            {
                return null;
            }

            var p = permission.Split(':');

            if (p.Length != 2)
            {
                return null;
            }

            return new Permission(p[0], p[1]);
        }

        public static Permission Other(string resource, string action)
        {
            return new Permission(resource, action);
        }

        public static Permission Read(string resource)
        {
            return new Permission(resource, "Read");
        }

        public static Permission Write(string resource)
        {
            return new Permission(resource, "Write");
        }

        public static Permission Delete(string resource)
        {
            return new Permission(resource, "Delete");
        }
    }
}