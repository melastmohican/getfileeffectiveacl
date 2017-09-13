using System;
using System.Runtime.InteropServices;
using System.Text;

public class EffectiveRights
{
    public const int ERROR_FILE_NOT_FOUND = 0x2;

    [Flags]
    public enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    }

    public enum SE_OBJECT_TYPE
    {
        SE_UNKNOWN_OBJECT_TYPE = 0,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT,
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY
    }

    public enum MULTIPLE_TRUSTEE_OPERATION
    {
        NO_MULTIPLE_TRUSTEE,
        TRUSTEE_IS_IMPERSONATE
    }

    public enum TRUSTEE_FORM
    {
        TRUSTEE_IS_SID,
        TRUSTEE_IS_NAME,
        TRUSTEE_BAD_FORM,
        TRUSTEE_IS_OBJECTS_AND_SID,
        TRUSTEE_IS_OBJECTS_AND_NAME
    }

    public enum TRUSTEE_TYPE
    {
        TRUSTEE_IS_UNKNOWN,
        TRUSTEE_IS_USER,
        TRUSTEE_IS_GROUP,
        TRUSTEE_IS_DOMAIN,
        TRUSTEE_IS_ALIAS,
        TRUSTEE_IS_WELL_KNOWN_GROUP,
        TRUSTEE_IS_DELETED,
        TRUSTEE_IS_INVALID,
        TRUSTEE_IS_COMPUTER
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 4)]
    public struct TRUSTEE
    {
        public IntPtr pMultipleTrustee; // must be null
        public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
        public int TrusteeForm;
        public int TrusteeType;
        public IntPtr ptstrName;
    }

    public enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    public enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,
        STANDARD_RIGHTS_REQUIRED = 0x000f0000,
        STANDARD_RIGHTS_READ = READ_CONTROL,
        STANDARD_RIGHTS_WRITE = READ_CONTROL,
        STANDARD_RIGHTS_EXECUTE = READ_CONTROL,
        STANDARD_RIGHTS_ALL = 0x001f0000,
        SPECIFIC_RIGHTS_ALL = 0x0000ffff,
        ACCESS_SYSTEM_SECURITY = 0x01000000,
        MAXIMUM_ALLOWED = 0x02000000,

        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,

        FILE_READ_DATA = 0x00000001,
        FILE_WRITE_DATA =  0x00000002,
        FILE_APPEND_DATA = 0x00000004,
        FILE_READ_EA = 0x00000008,
        FILE_WRITE_EA = 0x00000010,
        FILE_EXECUTE = 0x00000020,
        FILE_DELETE_CHILD = 0x00000040,
        FILE_READ_ATTRIBUTES = 0x00000080,
        FILE_WRITE_ATTRIBUTES = 0x00000100,
        FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE |  0x000001FF,
        FILE_GENERIC_READ = STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE,
        FILE_GENERIC_WRITE = STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE,
        FILE_GENERIC_EXECUTE = STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE
    }

    [DllImport("kernel32.dll")]
    public static extern int GetLastError();

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, PreserveSig = true)]
    public static extern bool ConvertStringSidToSid(string StringSid, out IntPtr pSid);

    [DllImport("advapi32.dll", EntryPoint = "BuildTrusteeWithSid", CharSet = CharSet.Auto)]
    static extern void BuildTrusteeWithSid(IntPtr pTrustee, IntPtr pSID);

    [DllImport("advapi32.dll", EntryPoint = "BuildTrusteeWithName", CharSet = CharSet.Auto)]
    static extern void BuildTrusteeWithName(ref TRUSTEE trustee, string pName);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    public static extern uint GetNamedSecurityInfo(string pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, out IntPtr pSidOwner, out IntPtr pSidGroup, out IntPtr pDacl, out IntPtr pSacl, out IntPtr pSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetEffectiveRightsFromAcl(IntPtr pDacl, ref TRUSTEE pTrustee, ref int pAccessRights);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool LookupAccountName(string lpSystemName, string lpAccountName, IntPtr Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

    [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
    static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

    public static int GetFileEffectiveRights(string path, string accountName)
    {
        return GetEffectiveRights(SE_OBJECT_TYPE.SE_FILE_OBJECT, path, accountName);
    }

    public static int GetRegKeyEffectiveRights(string path, string accountName)
    {
        return GetEffectiveRights(SE_OBJECT_TYPE.SE_REGISTRY_KEY, path, accountName);
    }

    public static string getSid(string accountName)
    {
        string sidString = "";
        IntPtr pSid = IntPtr.Zero;
        uint cbSid = 0;
        StringBuilder referencedDomainName = new StringBuilder();
        uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
        SID_NAME_USE sidUse;

        if (!LookupAccountName(null, accountName, pSid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
        {
                referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                pSid = Marshal.AllocHGlobal((int)cbSid);
                if (LookupAccountName(null, accountName, pSid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                {
                    IntPtr ptrSid;
                    if (ConvertSidToStringSid(pSid, out ptrSid))
                    {
                        sidString = Marshal.PtrToStringAuto(ptrSid);
                        Marshal.Release(ptrSid);
                    }
                    else
                    {
                        int errorCode = GetLastError();
                        getWin32ErrorMessage(errorCode);
                    }
                }
            
        }
        return sidString;
    }

    public static IntPtr getTrustee(string accountName)
    {
        IntPtr pSid = IntPtr.Zero;
        uint cbSid = 0;
        StringBuilder referencedDomainName = new StringBuilder();
        uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
        SID_NAME_USE sidUse;

        if (!LookupAccountName(null, accountName, pSid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
        {
            referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
            pSid = Marshal.AllocHGlobal((int)cbSid);
            if (!LookupAccountName(null, accountName, pSid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
            {
                int errorCode = GetLastError();
                getWin32ErrorMessage(errorCode);
            }
        }
        return pSid;
    }

    static int GetEffectiveRights(SE_OBJECT_TYPE type, String path, String accountName)
    {
        int mask = 0;
        IntPtr pOwner = IntPtr.Zero; // pSID
        IntPtr pGroup = IntPtr.Zero; // pSID
        IntPtr pSacl = IntPtr.Zero;
        IntPtr pDacl;// = IntPtr.Zero;
        IntPtr pSD;// = IntPtr.Zero; // pSECURITY_DESCRIPTOR
        if (GetNamedSecurityInfo(path, type, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, out pOwner, out pGroup, out pDacl, out pSacl, out pSD) == 0) {
            IntPtr pSid = getTrustee(accountName);
            
            IntPtr pTrustee = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TRUSTEE)));
            BuildTrusteeWithSid(pTrustee, pSid);
            TRUSTEE trustee = (TRUSTEE)Marshal.PtrToStructure(pTrustee, typeof(TRUSTEE));
            string tstr = Marshal.PtrToStringAuto(trustee.ptstrName);
            Marshal.Release(pSid);
            GetEffectiveRightsFromAcl(pDacl, ref trustee, ref mask);
        }
        else 
        {
            getWin32ErrorMessage(GetLastError());
        }
        return mask;
    }

    private static string getWin32ErrorMessage(int error)
    {
        string errorMessage = new System.ComponentModel.Win32Exception(error).Message;
        Console.WriteLine(errorMessage);
        return errorMessage;
    }
}