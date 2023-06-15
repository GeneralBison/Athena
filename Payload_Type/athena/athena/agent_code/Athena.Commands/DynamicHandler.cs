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
        public const long VirtPro = 65467780416196;
        public const long SendArp = 3100520;
        public const long SetThreadExecState = 8251003785770015321;
        public const long SetStdHndle = 316360270081;


        //Virtual Protect Delegate
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate Boolean DynamicVirtPro(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate int DynamicSendArp(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        public delegate uint DynamicSetThreExecSt(uint esFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public delegate bool DynamicSetStdHandle(int nStdHandle, IntPtr hHandle);



        public static Delegate findDeleg(string dll, long hash, Type t)
        {
            IntPtr ptrSA = HInvoke.GetfuncaddressbyHash(dll, hash); //Get Pointer for VirtualProtect function
            return Marshal.GetDelegateForFunctionPointer(ptrSA, t);
        }

    }
}
