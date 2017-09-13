using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace GetFileEffectiveACL
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: GetFileEffectiveACL filename");
                return;
            }
            string filename = args[0];
            WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            Console.WriteLine("WindowsPrincipal: {0}", principal.Identity.Name);
            Console.WriteLine("hasPermission: {0}\n", isInRole(filename, principal));
            getPrincipalInfo(principal);
            getFileSecurity(filename);
            EffectiveRights.ACCESS_MASK mask = (EffectiveRights.ACCESS_MASK)EffectiveRights.GetFileEffectiveRights(filename, principal.Identity.Name);
            Console.WriteLine("Access mask: {0:X}", mask);
            if ((mask & EffectiveRights.ACCESS_MASK.FILE_ALL_ACCESS) == EffectiveRights.ACCESS_MASK.FILE_ALL_ACCESS)
                Console.WriteLine("Full access");
            else if ((mask & EffectiveRights.ACCESS_MASK.FILE_GENERIC_READ) == EffectiveRights.ACCESS_MASK.FILE_GENERIC_READ)
                Console.WriteLine("Read");
            else if ((mask & EffectiveRights.ACCESS_MASK.FILE_GENERIC_WRITE) == EffectiveRights.ACCESS_MASK.FILE_GENERIC_WRITE)
                Console.WriteLine("Write");
            else if ((mask & EffectiveRights.ACCESS_MASK.FILE_GENERIC_EXECUTE) == EffectiveRights.ACCESS_MASK.FILE_GENERIC_EXECUTE)
                Console.WriteLine("Execute");
            
        }


        private static void getPrincipalInfo(WindowsPrincipal principal)
        {
            Console.WriteLine("WindowsPrincipal: {0}", principal.Identity.Name);
            Array wbirFields = Enum.GetValues(typeof(WindowsBuiltInRole));
            foreach (object roleName in wbirFields)
            {
                try
                {
                    // Cast the role name to a RID represented by the WindowsBuildInRole value.
                    Console.WriteLine("{0} ({1}) => {2}.", roleName, ((int)roleName).ToString(),
                        principal.IsInRole((WindowsBuiltInRole)roleName));
                }
                catch (Exception)
                {
                    Console.WriteLine("{0}: Could not obtain role for this RID.", roleName);
                }
            }
            // Get the role using the string value of the role.
            Console.WriteLine("{0} => {1}.", "Administrators",
                principal.IsInRole("BUILTIN\\" + "Administrators"));
            Console.WriteLine("{0} => {1}.", "Users",
                principal.IsInRole("BUILTIN\\" + "Users"));
            // Get the role using the WindowsBuiltInRole enumeration value.
            Console.WriteLine("{0} => {1}.", WindowsBuiltInRole.Administrator,
               principal.IsInRole(WindowsBuiltInRole.Administrator));
            // Get the role using the WellKnownSidType.
            SecurityIdentifier sidAdmins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            Console.WriteLine("Administrators  {0} => {1}", sidAdmins.Value, principal.IsInRole(sidAdmins));
            SecurityIdentifier sidUsers = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            Console.WriteLine("Users  {0} => {1}.\n", sidUsers.Value, principal.IsInRole(sidUsers));
        }

        private static void getFileSecurity(string filename) {
            FileInfo info = new FileInfo(filename);
            FileSecurity security = info.GetAccessControl();
            ShowFileSecurity(security);
        }

        private static bool isInRole(string filename, WindowsPrincipal principal)
        {
            // Gets the ACL for the file
            FileSecurity acl = File.GetAccessControl(filename, AccessControlSections.Access);
            // Gets the security identifiers of the access rules
            SecurityIdentifier[] identifiers = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<AuthorizationRule>().Select(rule => rule.IdentityReference).Cast<SecurityIdentifier>().ToArray();
            // Check if the user match any role
            bool hasPermission = identifiers.Any(identifier => principal.IsInRole(identifier));
            return hasPermission;
        }
        
        private static void ShowFileSecurity(FileSecurity security)
        {
            AuthorizationRuleCollection coll =
                security.GetAccessRules(true, true, typeof(NTAccount));
            foreach (FileSystemAccessRule rule in coll)
            {
                Console.WriteLine("IdentityReference: {0}",rule.IdentityReference);

                SecurityIdentifier sid = (SecurityIdentifier)rule.IdentityReference.Translate(typeof(SecurityIdentifier));
                if (null != sid.AccountDomainSid)
                {
                    Console.WriteLine("AccountDomainSid: {0}", sid.AccountDomainSid.Value);
                }
                Console.WriteLine("Sid: {0}", sid.Value);
                Console.WriteLine("Access control type: {0}", rule.AccessControlType);
                Console.WriteLine("Rights: {0}", rule.FileSystemRights);
                Console.WriteLine("Inherited? {0}", rule.IsInherited);

                Console.WriteLine();
            }
        }
    }
}
