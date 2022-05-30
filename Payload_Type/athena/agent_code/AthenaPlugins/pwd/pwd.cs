﻿using PluginBase;
using System;
using System.Collections.Generic;
using System.IO;

namespace Plugin
{
    public static class pwd
    {

        public static ResponseResult Execute(Dictionary<string, object> args)
        {
            return new ResponseResult
            {
                completed = "true",
                user_output = Directory.GetCurrentDirectory(),
                task_id = (string)args["task-id"],
            };
        }
    }
}
