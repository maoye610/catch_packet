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
                        string rlt = "\r\nʱ�� : " +
                            DateTime.Now.ToLongTimeString() +
                            "\r\n���ݰ�: \r\n" + ret;

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
            String str = "0123456789ABCDEF"; //16�������õ��������ַ� 0-15
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

            char[] hexs = hexStr.ToCharArray();//toCharArray() �������ַ���ת��Ϊ�ַ����顣
            int length = (hexStr.Length / 2);//1��byte��ֵ -> ����16�����ַ�
            byte[] bytes = new byte[length];
            int n;
            for (int i = 0; i < bytes.Length; i++)
            {
                int position = i * 2;//����16�����ַ� -> 1��byte��ֵ
                n = str.IndexOf(hexs[position]) * 16;
                n += str.IndexOf(hexs[position + 1]);
                // ���ֶ����Ʋ����һ���� ��Ϊbyte�����ַ���8bit��  ��intΪ32bit ���Զ������λ1  ��������0xFF֮����Ա��ָ�λһ���� 
                //��byteҪת��Ϊint��ʱ�򣬸ߵ�24λ��Ȼ�Ჹ1��������������Ʋ�����ʵ�Ѿ���һ���ˣ�&0xff���Խ��ߵ�24λ��Ϊ0����8λ����ԭ������������Ŀ�ľ���Ϊ�˱�֤���������ݵ�һ���ԡ�
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
        /// ��16����ת���ɺ���
        /// </summary>
        /// <param name="hex"></param>
        /// <param name="charset">����,��"utf-8","gb2312"</param>
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
                hex += "20";//�ո�
            }
            // ��Ҫ�� hex ת���� byte ���顣 
            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                try
                {
                    // ÿ�����ַ���һ�� byte�� 
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
