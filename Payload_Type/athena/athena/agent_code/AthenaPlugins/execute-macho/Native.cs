using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace execute_macho
{
    public static class Native
    {
        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr mmap(
            IntPtr addr,
            UIntPtr length,
            MmapProts prot,
            MmapFlags flags,
            int fd,
            long offset);
        
        [DllImport("libc", SetLastError = true)]
        public static extern int mprotect(IntPtr addr, UIntPtr len, MmapProts prot);

        // P/Invoke delegate for dl_iterate_phdr callback
        public delegate int dl_iterate_phdr_callback(dl_phdr_info info, IntPtr size, IntPtr data);

        // P/Invoke declaration for dl_iterate_phdr
        [DllImport("libc", SetLastError = true)]
        public static extern int dl_iterate_phdr(dl_iterate_phdr_callback callback, IntPtr data);

        // P/Invoke declaration for munmap
        [DllImport("libc", SetLastError = true)]
        public static extern int munmap(IntPtr addr, UIntPtr length);

        [Flags]
        public enum MmapProts
        {
            PROT_NONE = 0x00,
            PROT_READ = 0x01,
            PROT_WRITE = 0x02,
            PROT_EXEC = 0x04
        }

        [Flags]
        public enum MmapFlags
        {
            MAP_FILE = 0x0000,
            MAP_SHARED = 0x0001,
            MAP_PRIVATE = 0x0002,
            MAP_FIXED = 0x0010,
            MAP_ANONYMOUS = 0x0020,
            MAP_GROWSDOWN = 0x0100,
            MAP_LOCKED = 0x0200,
            MAP_NORESERVE = 0x0400,
            MAP_POPULATE = 0x0800,
            MAP_NONBLOCK = 0x1000,
            MAP_STACK = 0x2000,
            MAP_HUGETLB = 0x4000,
            MAP_SYNC = 0x8000
        }
        // Structure representing dl_phdr_info
        [StructLayout(LayoutKind.Sequential)]
        public struct dl_phdr_info
        {
            public IntPtr dlpi_addr;    // Base address at which shared object is loaded
            public IntPtr dlpi_name;    // Absolute file name of shared object
            public IntPtr dlpi_phdr;    // Pointer to the first program header
            public short dlpi_phnum;    // Number of program headers
        }

        // Structure representing ElfW(Phdr) (program header)
        [StructLayout(LayoutKind.Sequential)]
        public struct ElfW_Phdr
        {
            public uint p_type;   // Type of segment
            public uint p_flags;  // Segment attributes
            public long p_offset; // Offset in file
            public long p_vaddr;  // Virtual address in memory
            public long p_paddr;  // Reserved (physical address)
            public long p_filesz; // Size of segment in file
            public long p_memsz;  // Size of segment in memory
            public long p_align;  // Alignment of segment
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct mach_header
        {
            public uint magic;           // Mach-O magic number
            public int cputype;          // CPU type
            public int cpusubtype;       // CPU subtype
            public uint filetype;        // Mach-O file type
            public uint ncmds;           // Number of load commands
            public uint sizeofcmds;      // Size of load commands
            public uint flags;           // Mach-O flags
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct load_command
        {
            public uint cmd;             // Load command type
            public uint cmdsize;         // Size of load command
        }
    }
}
