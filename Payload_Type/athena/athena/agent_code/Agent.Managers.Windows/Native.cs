﻿using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Agent.Utilities.Invoker
{
    public class Native
    {
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateProcess(
        string lpApplicationName,
           string lpCommandLine,
           SECURITY_ATTRIBUTES lpProcessAttributes,
           SECURITY_ATTRIBUTES lpThreadAttributes,
           bool bInheritHandles,
           CreateProcessFlags dwCreationFlags,
           IntPtr lpEnvironment,
           string lpCurrentDirectory,
           [In] ref STARTUPINFOEX lpStartupInfo,
           out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, HANDLE_FLAGS dwMask,
           HANDLE_FLAGS dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool PeekNamedPipe(IntPtr handle,
            IntPtr buffer, IntPtr nBufferSize, IntPtr bytesRead,
            ref uint bytesAvail, IntPtr BytesLeftThisMessage);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue,
            IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);


        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetCurrentThread();


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId
        );


        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(
            IntPtr pBuffer,
            int length
        );

        [DllImport("ntdll.dll")]
        public static extern UInt32 NtQueryInformationProcess(
            IntPtr processHandle,
            UInt32 processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref UInt32 returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, ThreadCreationFlags dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern Boolean NtReadVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr Buffer,
            UInt32 NumberOfBytesToRead,
            ref UInt32 liRet
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, CLIENT_ID clientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, SectionAccess DesiredAccess, IntPtr ObjectAttributes, ref UInt64 MaximumSize, MemoryProtection SectionPageProtection, MappingAttributes AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref UInt64 SectionOffset, ref UInt64 ViewSize, uint InheritDisposition, UInt32 AllocationType, MemoryProtection Win32Protect);

        [DllImport("kernel32.dll")]
        public static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe,
           ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            IntPtr BufferAddress,
            UInt32 nSize,
            ref UInt32 lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);
        public enum NTSTATUS : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }

        [StructLayout(LayoutKind.Explicit, Size = 18)]
        public struct CURDIR
        {
            [FieldOffset(0)]
            public UNICODE_STRING DosPath;
            [FieldOffset(16)]
            public IntPtr Handle;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum SectionAccess : UInt32
        {
            SECTION_EXTEND_SIZE = 0x0010,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
            SECTION_MAP_READ = 0x0004,
            SECTION_MAP_EXECUTE = 0x0008,
            SECTION_ALL_ACCESS = 0xe
        }


        [Flags]
        public enum ProcessParametersFlags : uint
        {
            NORMALIZED = 0x01,
            PROFILE_USER = 0x02,
            PROFILE_SERVER = 0x04,
            PROFILE_KERNEL = 0x08,
            UNKNOWN = 0x10,
            RESERVE_1MB = 0x20,
            DISABLE_HEAP_CHECKS = 0x100,
            PROCESS_OR_1 = 0x200,
            PROCESS_OR_2 = 0x400,
            PRIVATE_DLL_PATH = 0x1000,
            LOCAL_DLL_PATH = 0x2000,
            NX = 0x20000,
        }


        [Flags]
        public enum CreateProcessFlags
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        [Flags]
        public enum MappingAttributes : UInt32
        {
            SEC_COMMIT = 0x8000000,
            SEC_IMAGE = 0x1000000,
            SEC_IMAGE_NO_EXECUTE = 0x11000000,
            SEC_LARGE_PAGES = 0x80000000,
            SEC_NOCACHE = 0x10000000,
            SEC_RESERVE = 0x4000000,
            SEC_WRITECOMBINE = 0x40000000
        }

        [Flags]
        public enum AllocationType
        {
            NULL = 0x0,
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }
        public enum MemoryProtection : uint
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
        public enum ThreadCreationFlags : uint
        {
            NORMAL = 0x0,
            CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
        }



        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        /*
        [StructLayout(LayoutKind.Sequential)]
        public struct _RTL_DRIVE_LETTER_CURDIR
        {
            UInt16 Flags;
            UInt16 Length;
            UInt32 TimeStamp;
            UNICODE_STRING DosPath;
        }
        */
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        public const uint DUPLICATE_CLOSE_SOURCE = 0x00000001;
        public const uint DUPLICATE_SAME_ACCESS = 0x00000002;

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
           SafeFileHandle hSourceHandle, IntPtr hTargetProcessHandle, ref SafeFileHandle lpTargetHandle,
           uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
   IntPtr hSourceHandle, IntPtr hTargetProcessHandle, ref IntPtr lpTargetHandle,
   uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [StructLayout(LayoutKind.Explicit, Size = 136)]
        public struct RTL_USER_PROCESS_PARAMETERS
        {
            [FieldOffset(0)]
            public UInt32 MaximumLength;
            [FieldOffset(4)]
            public UInt32 Length;
            [FieldOffset(80)]
            public UNICODE_STRING DllPath;
            [FieldOffset(96)]
            public UNICODE_STRING ImagePathName;
            [FieldOffset(112)]
            public UNICODE_STRING CommandLine;
            [FieldOffset(128)]
            public IntPtr Environment; // PVOID
                                       //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
                                       //public UNICODE_STRING DLCurrentDirectory;
        };

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        struct LARGE_INTEGER
        {
            [FieldOffset(0)] public UInt32 LowPart;
            [FieldOffset(4)] public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Explicit, Size = 64)]
        public struct PEB
        {
            [FieldOffset(12)]
            public IntPtr Ldr32;
            [FieldOffset(16)]
            public IntPtr ProcessParameters32;
            [FieldOffset(24)]
            public IntPtr Ldr64;
            [FieldOffset(28)]
            public IntPtr FastPebLock32;
            [FieldOffset(32)]
            public IntPtr ProcessParameters64;
            [FieldOffset(56)]
            public IntPtr FastPebLock64;
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public struct UNICODE_STRING : IDisposable
        {
            [FieldOffset(0)]
            public ushort Length;
            [FieldOffset(2)]
            public ushort MaximumLength;
            [FieldOffset(8)]
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [Flags]
        public enum HANDLE_FLAGS : uint
        {
            None = 0,
            INHERIT = 1,
            PROTECT_FROM_CLOSE = 2
        }
        // STARTUPINFO members (dwFlags and wShowWindow)
        public const int STARTF_USESTDHANDLES = 0x00000100;
        public const int STARTF_USESHOWWINDOW = 0x00000001;
        public const short SW_HIDE = 0x0000;
    }
}