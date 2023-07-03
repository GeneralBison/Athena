using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static Athena.Commands.DynamicHandler;

namespace Athena.Commands
{
    public static class StaticHandler
    {
        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
           ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, CLIENT_ID clientId);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, SectionAccess DesiredAccess, IntPtr ObjectAttributes, ref UInt64 MaximumSize, MemoryProtection SectionPageProtection, MappingAttributes AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref UInt64 SectionOffset, ref UInt64 ViewSize, uint InheritDisposition, UInt32 AllocationType, MemoryProtection Win32Protect);
    }
}
