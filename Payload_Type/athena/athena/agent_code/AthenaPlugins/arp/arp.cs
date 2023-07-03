﻿using Athena.Commands;
using Athena.Commands.Models;
using Athena.Utilities;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using static Athena.Commands.DynamicHandler;

namespace Plugins
{
    public class Arp : AthenaPlugin
    {
        public override string Name => "arp";
        //[DllImport("iphlpapi.dll", ExactSpelling = true)]
        //private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        private static uint macAddrLen = (uint)new byte[6].Length;
        private const string separator = "|";
        private DynamicHandler.DynamicSendArp dlgSA;

        private string MacAddresstoString(byte[] macAdrr)
        {
            string macString = BitConverter.ToString(macAdrr);
            return macString.ToUpper();
        }

        private string ThreadedARPRequest(string ipString)
        {
            IPAddress ipAddress;
            byte[] macAddr = new byte[6];

            try
            {
                ipAddress = IPAddress.Parse(ipString);
                dlgSA((int)BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);

                if (MacAddresstoString(macAddr) != "00-00-00-00-00-00")
                {
                    string macString = MacAddresstoString(macAddr);
                    return $"{ipString} - {macString} - Alive";
                }
            }
            catch (Exception e)
            {
                return $"{ipString} - Invalid" + Environment.NewLine;
            }
            return "";
        }

        public void CheckStatus(IPAddressCollection ipList, int timeout, string task_id)
        {
            List<Tuple<string, string, string>> result = new List<Tuple<string, string, string>>();
            byte[] macAddr = new byte[6];
            StringBuilder sb = new StringBuilder();
            try
            {
                Task.Run(() =>
                {
                    Parallel.ForEach(ipList, ipString =>
                    {
                        TaskResponseHandler.Write(ThreadedARPRequest(ipString.ToString()), task_id, false);
                    });
                }).Wait();
            }
            catch (Exception e)
            {
                sb.AppendLine(e.ToString());
            }
            Thread.Sleep(timeout);
        }
        public override void Execute(Dictionary<string, string> args)
        {
            try
            {
                IPNetwork ipnetwork = IPNetwork.Parse(args["cidr"]);
                IPAddressCollection iac = ipnetwork.ListIPAddress();
                int timeout = int.Parse(args["timeout"]);

                if(dlgSA is null)
                {
                    dlgSA = (DynamicHandler.DynamicSendArp)DynamicHandler.findDeleg("iphlpapi.dll", DynamicHandler.SendArp, typeof(DynamicHandler.DynamicSendArp));
                }

                CheckStatus(iac, timeout * 1000, args["task-id"]);
                TaskResponseHandler.Write("Finished Executing", args["task-id"], true);


            }
            catch (Exception e)
            {
                TaskResponseHandler.Write(e.ToString(), args["task-id"], true, "error");
            }
        }
    }
}