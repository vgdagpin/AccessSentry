using System.Collections.Generic;

namespace AccessSentry
{
    public class Role
    {
        public short RoleID { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }

        public IEnumerable<ResourcePermission> Permissions { get; set; } = new List<ResourcePermission>();
    }
}
