﻿using System;
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
        [FlagsAttribute]
        public enum EXECUTION_STATE : uint
        {
            ES_AWAYMODE_REQUIRED = 0x00000040,
            ES_CONTINUOUS = 0x80000000,
            ES_DISPLAY_REQUIRED = 0x00000002,
            ES_SYSTEM_REQUIRED = 0x00000001
            // Legacy flag, should not be used.
            // ES_USER_PRESENT = 0x00000004
        }

        //[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        //static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);
        public override string Name => "caffeinate";
        private static bool running = false;
        private DynamicHandler.DynamicSetThreExecSt dynamicSetThreExecSt;
        public override void Execute(Dictionary<string, string> args)
        {
            try
            {
                if(dynamicSetThreExecSt == null) {
                    dynamicSetThreExecSt = (DynamicHandler.DynamicSetThreExecSt)DynamicHandler.findDeleg("kernel32.dll", DynamicHandler.SetThreadExecState, typeof(DynamicHandler.DynamicSetThreExecSt));
                }


                if (running)
                {
                    TaskResponseHandler.Write("Letting computer sleep", args["task-id"], true);
                    dynamicSetThreExecSt((uint)EXECUTION_STATE.ES_CONTINUOUS);

                    running = false;
                }
                else
                {
                    TaskResponseHandler.Write("Keeping PC awake", args["task-id"], true);
                    running = true;
                    dynamicSetThreExecSt((uint)EXECUTION_STATE.ES_DISPLAY_REQUIRED | (uint)EXECUTION_STATE.ES_CONTINUOUS);
                }

            }
            catch (Exception e)
            {
                TaskResponseHandler.Write(e.ToString(), args["task-id"], true, "error");
            }
        }
    }
}

