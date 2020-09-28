using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PacketDotNet;
using SharpPcap;

namespace Example6
{
    public class DumpTCP
    {
        public static String filter = "";
        public static void Main(string[] args)
        {
            string ver = SharpPcap.Version.VersionString;
            /* Print SharpPcap version */
            Console.WriteLine("SharpPcap {0}, Example6.DumpTCP.cs", ver);
            Console.WriteLine();

            /* Retrieve the device list */
            var devices = CaptureDeviceList.Instance;

            /*If no device exists, print error */
            if(devices.Count<1)
            {
                Console.WriteLine("No device found on this machine");
                return;
            }
            
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i=0;

            /* Scan the list printing every entry */
            foreach(var dev in devices)
            {
                /* Description */
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse( Console.ReadLine() );

            var device = devices[i];

            //Register our handler function to the 'packet arrival' event
            device.OnPacketArrival += 
                new PacketArrivalEventHandler( device_OnPacketArrival );

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            //tcpdump filter to capture only TCP/IP packets
            string filter = "ip and tcp";
            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine
                ("-- The following tcpdump filter will be applied: \"{0}\"", 
                filter);
            Console.WriteLine
                ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                device.Description);

            // Start capture 'INFINTE' number of packets
            device.Capture();

            // Close the pcap device
            // (Note: this line will never be called since
            //  we're capturing infinite number of packets
            device.Close();
        }

        /// <summary>
        /// Prints the time, length, src ip, src port, dst ip and dst port
        /// for each TCP/IP packet received on the network
        /// </summary>
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {           
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var tcpPacket = PacketDotNet.TcpPacket.GetEncapsulated(packet);

            if(tcpPacket != null)
            {
                if (tcpPacket.SourcePort.Equals(65)) {

                    string ret = "";
                    PrintPacket(ref ret, packet);
                    if (!string.IsNullOrEmpty(ret))
                    {
                        string rlt = "\r\n时间 : " +
                            DateTime.Now.ToLongTimeString() +
                            "\r\n数据包: \r\n" + ret;

                        string v = byteToHexStr(packet.Bytes);
                        string v1 = hexStr2Str(v);
                        Console.WriteLine(v1);

                        using (StreamWriter streamWriter = new StreamWriter(@"F:\text.txt",true))
                        {
                            streamWriter.WriteLine(v1);
                        }
                        //Console.WriteLine(rlt);
                    }
                }

            }
        }
        private static void PrintPacket(ref string str, Packet p)
        {
            if (p != null)
            {
                string s = p.ToString();
                if (!string.IsNullOrEmpty(filter) && !s.Contains(filter))
                {
                    return;
                }

                str += "\r\n" + s + "\r\n";

                str += p.PrintHex() + "\r\n";
            }


        }
        public static String hexStr2Str(String hex)
        {
            String hexStr = "";
            String str = "0123456789ABCDEF"; //16进制能用到的所有字符 0-15
            if (hex.Length == 0) 
            {
                return "";
            }
            for (int i = 0; i < hex.Length; i++)
            {
                String s = hex.Substring(i, 1);
                if (s.Equals("a") || s.Equals("b") || s.Equals("c") || s.Equals("d") || s.Equals("e") || s.Equals("f"))
                {
                    s = s.ToUpper().Substring(0, 1);
                }
                hexStr += s;
            }

            char[] hexs = hexStr.ToCharArray();//toCharArray() 方法将字符串转换为字符数组。
            int length = (hexStr.Length / 2);//1个byte数值 -> 两个16进制字符
            byte[] bytes = new byte[length];
            int n;
            for (int i = 0; i < bytes.Length; i++)
            {
                int position = i * 2;//两个16进制字符 -> 1个byte数值
                n = str.IndexOf(hexs[position]) * 16;
                n += str.IndexOf(hexs[position + 1]);
                // 保持二进制补码的一致性 因为byte类型字符是8bit的  而int为32bit 会自动补齐高位1  所以与上0xFF之后可以保持高位一致性 
                //当byte要转化为int的时候，高的24位必然会补1，这样，其二进制补码其实已经不一致了，&0xff可以将高的24位置为0，低8位保持原样，这样做的目的就是为了保证二进制数据的一致性。
                bytes[i] = (byte)(n & 0xff);
            }
            String name = "";
            try
            {
                name = Encoding.ASCII.GetString(bytes);
            }
            catch (Exception e)
            {
                // TODO Auto-generated catch block
                Console.WriteLine(e);
            }

            return name;
        }
            public static string byteToHexStr(byte[] bytes)
        {
            string returnStr = "";
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    returnStr += bytes[i].ToString("X2");
                }
            }
            return returnStr;
        }
        ///<summary>
        /// 从16进制转换成汉字
        /// </summary>
        /// <param name="hex"></param>
        /// <param name="charset">编码,如"utf-8","gb2312"</param>
        /// <returns></returns>
        public static string UnHex(string hex, string charset)
        {
            if (hex == null)
                throw new ArgumentNullException("hex");
            hex = hex.Replace(",", "");
            hex = hex.Replace("\n", "");
            hex = hex.Replace("\\", "");
            hex = hex.Replace(" ", "");
            if (hex.Length % 2 != 0)
            {
                hex += "20";//空格
            }
            // 需要将 hex 转换成 byte 数组。 
            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                try
                {
                    // 每两个字符是一个 byte。 
                    bytes[i] = byte.Parse(hex.Substring(i * 2, 2),
                    System.Globalization.NumberStyles.HexNumber);
                }
                catch
                {
                    // Rethrow an exception with custom message. 
                    throw new ArgumentException("hex is not a valid hex number!", "hex");
                }
            }
            System.Text.Encoding chs = System.Text.Encoding.GetEncoding(charset);
            return chs.GetString(bytes);
        }

    }
}
