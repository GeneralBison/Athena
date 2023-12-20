﻿
using Agent.Interfaces;
using Agent.Models;
using Agent.Utilities;

namespace mv
{
    public class Mv : IPlugin
    {
        public string Name => "mv";
        public IAgentConfig config { get; set; }
        public IMessageManager messageManager { get; set; }
        public ILogger logger { get; set; }
        public ITokenManager tokenManager { get; set; }

        public Mv(IMessageManager messageManager, IAgentConfig config, ILogger logger, ITokenManager tokenManager)
        {
            this.messageManager = messageManager;
            this.config = config;
            this.logger = logger;
            this.tokenManager = tokenManager;
        }
        public async Task Execute(ServerJob job)
        {
            if (job.task.token != 0)
            {
                tokenManager.Impersonate(job.task.token);
            }
            Dictionary<string, string> args = Misc.ConvertJsonStringToDict(job.task.parameters);
            if (args.ContainsKey("source") && args.ContainsKey("destination"))
            {
                try
                {
                    FileAttributes attr = File.GetAttributes((args["source"]).Replace("\"", ""));

                    // Check if Directory
                    if (attr.HasFlag(FileAttributes.Directory))
                    {
                        Directory.Move((args["source"]).Replace("\"", ""), (args["destination"]).Replace("\"", ""));
                    }
                    else
                    {
                        File.Move((args["source"]).Replace("\"", ""), (args["destination"]).Replace("\"", ""));
                    }

                    await messageManager.AddResponse(new ResponseResult
                    {
                        completed = true,
                        user_output = $"Moved {(args["source"]).Replace("\"", "")} to {(args["destination"]).Replace("\"", "")}",
                        task_id = job.task.id,
                    });
                }
                catch (Exception e)
                {
                    messageManager.Write(e.ToString(), job.task.id, true, "error");
                    return;
                }
            }
            else
            {
                await messageManager.AddResponse(new ResponseResult
                {
                    completed = true,
                    process_response = new Dictionary<string, string> { { "message", "0x2B" } },
                    task_id = job.task.id,
                });
            }
            if (job.task.token != 0)
            {
                tokenManager.Revert();
            }
        }
    }
}
