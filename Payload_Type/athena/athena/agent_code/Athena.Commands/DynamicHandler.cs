using Athena.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Athena.Commands
{
    public static class DynamicHandler
    {
        //Hashes
        //Virtual Protect
        public const long VirtPro = 65467780416196; //VirtualProtect
        public const long SendArp = 3100520; //SendArp
        public const long SetThreadExecState = 8251003785770015321; //SetThreadExecutionState
        public const long SetStdHndle = 316360270081; //SetStdHandle
        public const long GetStdHndle = 116360270081; //GetStdHandle
        public const long RdFle = 21700581; //ReadFile
        public const long CrtPipe = 7417610521; //CreatePipe
        public const long NtAskProcessForInfo = 3062533379996727379; //NtQueryInformationProcess
        public const long VirtAllc = 654677858819; //VirtualAlloc
        public const long VirtForFree = 65467780411; //VirtualFree
        public const long FreeHeap = 21720411; //HeapFree
        public const long GetThisHeap = 11604191552172; //GetProcessHeap
        public const long HpAllc = 217258819; //HeapAlloc
        public const long LdLib = 61706584741; //LoadLibrary
        public const long GetProcAddr = 11604195004155; //GetProcessAddress
        public const long GetThisProc = 11677441060419155; //GetCurrentProcess
        public const long GetCmdLn = 11671997006501; //GetCommandLine
        public const long ClsHndl = 78151270081; //CloseHandle
        public const long CrtThrd = 741761444170; //CreateThread
        public const long VirtProEx = 6546778041619690; //VirtualProtectEx
        public const long VrtQryEx = 65467781714190; //VirtualQueryEx
        public const long GtMdlHndl = 116710781270081; //GetModuleHandle
        public const long WitFrObj = 7756014350381986196; //WaitForSingleObject
        public const long GetExtCd = 11690567101444170; //GetExitCodeThread

        //Virtual Protect Delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate Boolean DynamicVirtPro(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate int DynamicSendArp(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint DynamicSetThreExecSt(uint esFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool DynamicSetStdHdl(int nStdHandle, IntPtr hHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicGetStdHdl(int nStdHandle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicGetFile(IntPtr hFile, [Out] byte[] lpBuffer,
                       uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicMakePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, IntPtr lpPipeAttributes, uint nSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicNtAskProcessForInfo(IntPtr processHandle, int processInformationClass, IntPtr processInformation, uint processInformationLength, IntPtr returnLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicVirtAllc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicVirtForFree(IntPtr pAddress, uint size, uint freeType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicFreeHeap(IntPtr hHeap, uint dwFlags, IntPtr lpMem);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicGetThisHeap();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicHpAllc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicLdLib(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicGetThatAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicGetThisProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicGetCmdLne();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicClsHndl();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicCrtThrd(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicVirtProEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        //public delegate int DynamicVirQryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate IntPtr DynamicWtFrSnglObj(string lpModuleName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint DynamicWaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate bool DynamicGetExitCdeThrd(IntPtr hThread, out int lpExitCode);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        //public delegate void DynamicZeroMem(IntPtr addr, int size);

        public static Delegate findDeleg(string dll, long hash, Type t)
        {
            IntPtr ptrSA = HInvoke.GetfuncaddressbyHash(dll, hash); //Get Pointer for VirtualProtect function
            return Marshal.GetDelegateForFunctionPointer(ptrSA, t);
        }

    }
}
