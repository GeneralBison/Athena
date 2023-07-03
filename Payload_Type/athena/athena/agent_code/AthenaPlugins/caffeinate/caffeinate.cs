using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Athena.Commands;
using Athena.Commands.Models;
using Athena.Utilities;

namespace Plugins
{
    public class Caffeinate : AthenaPlugin
    {
        [DllImport("user32.dll")]
        private static extern void keybd_event(byte bVk, byte bScan, int dwFlags, int dwExtraInfo);

        public override string Name => "caffeinate";
        private const int VK_F15 = 0x7E;
        private const int KEYEVENTF_EXTENDEDKEY = 0x0001;
        private const int KEYEVENTF_KEYUP = 0x0002;
        private static bool running = false;


        private static void PressKey(byte keyCode)
        {
            keybd_event(keyCode, 0, KEYEVENTF_EXTENDEDKEY, 0);
        }

        private static void ReleaseKey(byte keyCode)
        {
            keybd_event(keyCode, 0, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
        }

        public override void Execute(Dictionary<string, string> args)
        {
            try
            {
                if(dynamicSetThreExecSt == null) {
                    dynamicSetThreExecSt = (DynamicHandler.DynamicSetThreExecSt)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.SetThreadExecState, typeof(DynamicHandler.DynamicSetThreExecSt));
                }


                if (running)
                {
                    running = false;
                    TaskResponseHandler.Write("Letting computer sleep", args["task-id"], true);
                    SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
                }
                else
                {
                    TaskResponseHandler.Write("Keeping PC awake", args["task-id"], true);
                    running = true;
                    SetThreadExecutionState(EXECUTION_STATE.ES_DISPLAY_REQUIRED | EXECUTION_STATE.ES_CONTINUOUS);
                }
            }
            catch (Exception e)
            {
                TaskResponseHandler.Write(e.ToString(), args["task-id"], true, "error");
            }
        }
    }
}
