using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace coff.coff
{
    unsafe class NativeDeclarations
    {


        internal const uint MEM_COMMIT = 0x1000;
        internal const uint MEM_RESERVE = 0x2000;
        internal const uint MEM_RELEASE = 0x00008000;



        internal const uint PAGE_EXECUTE_READWRITE = 0x40;
        internal const uint PAGE_READWRITE = 0x04;
        internal const uint PAGE_EXECUTE_READ = 0x20;
        internal const uint PAGE_EXECUTE = 0x10;
        internal const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        internal const uint PAGE_NOACCESS = 0x01;
        internal const uint PAGE_READONLY = 0x02;
        internal const uint PAGE_WRITECOPY = 0x08;

        internal const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        internal const uint IMAGE_SCN_MEM_READ = 0x40000000;
        internal const uint IMAGE_SCN_MEM_WRITE = 0x80000000;

        [DllImport("kernel32")]
        public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("Kernel32.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        public static extern void ZeroMemory(IntPtr dest, int size);

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum HeapAllocFlags : uint
        {
            HEAP_GENERATE_EXCEPTIONS = 0x00000004,
            HEAP_NO_SERIALIZE = 0x00000001,
            HEAP_ZERO_MEMORY = 0x00000008,

        }

        public enum WaitEventEnum : uint
        {
            WAIT_ABANDONED = 0x00000080,
            WAIT_OBJECT_0 = 00000000,
            WAIT_TIMEOUT = 00000102,
            WAIT_FAILED = 0xFFFFFFFF,
        }
    }

}
