using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

internal static class InpaAgent
{
    private const string Version = "1.0.0";
    private const string DefaultServerUrl = "https://intelligent-network-easy-production.up.railway.app";
    private const string PcapLibrary = "wpcap.dll";
    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };
    private sealed class PendingPacket
    {
        public long Id;
        public Dictionary<string, object> Data;
    }

    private static readonly LinkedList<PendingPacket> PendingPackets = new LinkedList<PendingPacket>();
    private static readonly object PendingLock = new object();
    private static long NextPacketId;
    private static int DroppedPackets;
    private static int TotalPackets;
    private static string ServerUrl;
    private static string Token;
    private static string AgentId;
    private static readonly string ProcessRunId = Guid.NewGuid().ToString("N");
    private static string CaptureInterface;
    private static string LastError;
    private static string CaptureError;
    private static volatile bool Running;
    private static volatile bool StopRequested;
    private static Thread CaptureThread;
    private static readonly object CaptureLock = new object();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct PcapDevice
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapTimeval
    {
        public int Seconds;
        public int Microseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapHeader
    {
        public PcapTimeval Timestamp;
        public uint CapturedLength;
        public uint OriginalLength;
    }

    [DllImport(PcapLibrary, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern int pcap_findalldevs(out IntPtr devices, StringBuilder errorBuffer);

    [DllImport(PcapLibrary, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_freealldevs(IntPtr devices);

    [DllImport(PcapLibrary, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr pcap_open_live(string device, int snapshotLength, int promiscuous, int timeoutMilliseconds, StringBuilder errorBuffer);

    [DllImport(PcapLibrary, CallingConvention = CallingConvention.Cdecl)]
    private static extern int pcap_next_ex(IntPtr handle, out IntPtr header, out IntPtr data);

    [DllImport(PcapLibrary, CallingConvention = CallingConvention.Cdecl)]
    private static extern void pcap_close(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetDllDirectory(string pathName);

    private static int Main(string[] args)
    {
        if (!Environment.Is64BitProcess)
        {
            Console.Error.WriteLine("INPA-Agent doit être lancé sur Windows 64 bits.");
            return 2;
        }

        if (!ReadConfiguration(args)) return 2;
        AgentId = LoadAgentId();
        string npcapDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
        if (Directory.Exists(npcapDirectory)) SetDllDirectory(npcapDirectory);
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

        Console.WriteLine("INPA-Agent " + Version);
        Console.WriteLine("Serveur : " + ServerUrl);
        Console.WriteLine("Arrêt : Ctrl+C");
        Console.WriteLine("La capture démarre uniquement après une commande depuis le tableau de bord.");

        Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs eventArgs)
        {
            eventArgs.Cancel = true;
            StopCapture();
            Environment.Exit(0);
        };

        int failures = 0;
        while (true)
        {
            try
            {
                Dictionary<string, object> response = SendHeartbeat();
                failures = 0;
                LastError = null;

                object commandValue;
                if (response.TryGetValue("command", out commandValue) && commandValue is Dictionary<string, object>)
                    HandleCommand((Dictionary<string, object>)commandValue);
                Thread.Sleep(2000);
            }
            catch (Exception exception)
            {
                LastError = FriendlyError(exception);
                failures = Math.Min(failures + 1, 6);
                Console.Error.WriteLine("Connexion interrompue : " + LastError);
                Thread.Sleep(Math.Min(30000, 1000 * (1 << failures)));
            }
        }
    }

    private static bool ReadConfiguration(string[] args)
    {
        string suppliedServer = ReadArgument(args, "--server");
        string suppliedToken = ReadArgument(args, "--token");
        ServerUrl = String.IsNullOrWhiteSpace(suppliedServer) ? DefaultServerUrl : suppliedServer;
        if (String.IsNullOrWhiteSpace(ServerUrl)) return false;
        ServerUrl = ServerUrl.Trim().TrimEnd('/');

        Uri server;
        if (!Uri.TryCreate(ServerUrl, UriKind.Absolute, out server) ||
            (server.Scheme != Uri.UriSchemeHttps && !server.IsLoopback))
        {
            Console.Error.WriteLine("Utilise une URL HTTPS. HTTP est autorisé uniquement sur localhost.");
            return false;
        }

        Token = suppliedToken;
        if (String.IsNullOrWhiteSpace(Token))
        {
            Console.Write("Code individuel INPA (saisie visible) : ");
            Token = ReadVisibleLine();
        }
        if (String.IsNullOrWhiteSpace(Token))
        {
            Console.Error.WriteLine("La clé API INPA est obligatoire.");
            return false;
        }
        return true;
    }

    private static string ReadVisibleLine()
    {
        return Console.ReadLine() ?? String.Empty;
    }
    private static string ReadArgument(string[] args, string name)
    {
        for (int i = 0; i + 1 < args.Length; i++) if (String.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    private static Dictionary<string, object> SendHeartbeat()
    {
        List<PendingPacket> batch = ReadPacketBatch(500);
        List<Dictionary<string, object>> packetData = batch.Select(item => item.Data).ToList();
        int pendingCount;
        lock (PendingLock) pendingCount = PendingPackets.Count;
        List<Dictionary<string, object>> interfaces;
        try { interfaces = GetInterfaces(); }
        catch (Exception exception) { LastError = FriendlyError(exception); interfaces = new List<Dictionary<string, object>>(); }
        Dictionary<string, object> body = new Dictionary<string, object>
        {
            { "agent_id", AgentId }, { "name", Environment.MachineName }, { "version", Version },
            { "interfaces", interfaces }, { "running", Running }, { "interface", CaptureInterface },
            { "last_error", CaptureError ?? LastError }, { "packets", packetData }, { "pending_packets", pendingCount },
            { "dropped_packets", Volatile.Read(ref DroppedPackets) }
        };

        byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(body));
        HttpWebRequest request = (HttpWebRequest)WebRequest.Create(ServerUrl + "/api/remote-agent/heartbeat");
        request.Method = "POST";
        request.ContentType = "application/json; charset=utf-8";
        request.Accept = "application/json";
        request.Headers["X-INPA-Agent-Token"] = Token;
        request.Timeout = 10000;
        request.ReadWriteTimeout = 10000;
        request.ContentLength = bytes.Length;
        using (Stream stream = request.GetRequestStream()) stream.Write(bytes, 0, bytes.Length);
        using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
        using (StreamReader reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
        {
            Dictionary<string, object> result = Json.Deserialize<Dictionary<string, object>>(reader.ReadToEnd());
            AcknowledgePackets(batch.Select(item => item.Id));
            return result ?? new Dictionary<string, object>();
        }
    }

    private static List<PendingPacket> ReadPacketBatch(int limit)
    {
        lock (PendingLock) return PendingPackets.Take(limit).ToList();
    }

    private static void AcknowledgePackets(IEnumerable<long> ids)
    {
        HashSet<long> sent = new HashSet<long>(ids);
        lock (PendingLock)
        {
            LinkedListNode<PendingPacket> node = PendingPackets.First;
            while (node != null)
            {
                LinkedListNode<PendingPacket> next = node.Next;
                if (sent.Contains(node.Value.Id)) PendingPackets.Remove(node);
                node = next;
            }
        }
    }

    private static void HandleCommand(Dictionary<string, object> command)
    {
        object actionValue;
        if (!command.TryGetValue("action", out actionValue)) return;
        string action = Convert.ToString(actionValue);
        if (action == "start")
        {
            object interfaceValue;
            if (command.TryGetValue("interface", out interfaceValue)) StartCapture(Convert.ToString(interfaceValue));
        }
        else if (action == "stop") StopCapture();
    }

    private static void StartCapture(string device)
    {
        lock (CaptureLock)
        {
            if (Running) return;
            if (String.IsNullOrWhiteSpace(device)) { LastError = "L'interface demandée est vide."; return; }
            StopRequested = false;
            CaptureInterface = device;
            Running = true;
            LastError = null;
            CaptureError = null;
            CaptureThread = new Thread(delegate() { CaptureLoop(device); });
            CaptureThread.IsBackground = true;
            CaptureThread.Start();
            Console.WriteLine("Capture démarrée sur " + device);
        }
    }

    private static void StopCapture()
    {
        StopRequested = true;
        Thread thread = CaptureThread;
        if (thread != null && thread != Thread.CurrentThread) thread.Join(3000);
        Running = false;
        Console.WriteLine("Capture arrêtée.");
    }

    private static void CaptureLoop(string device)
    {
        IntPtr handle = IntPtr.Zero;
        try
        {
            StringBuilder error = new StringBuilder(512);
            handle = pcap_open_live(device, 65535, 1, 500, error);
            if (handle == IntPtr.Zero) throw new InvalidOperationException(error.ToString());
            CaptureError = null;

            while (!StopRequested)
            {
                IntPtr headerPointer, packetPointer;
                int result = pcap_next_ex(handle, out headerPointer, out packetPointer);
                if (result == 0) continue;
                if (result == -2) break;
                if (result < 0) throw new InvalidOperationException("Npcap ne peut plus lire l'interface réseau.");
                PcapHeader header = (PcapHeader)Marshal.PtrToStructure(headerPointer, typeof(PcapHeader));
                int length = (int)Math.Min(header.CapturedLength, 65535U);
                byte[] bytes = new byte[length];
                Marshal.Copy(packetPointer, bytes, 0, length);
                Dictionary<string, object> packet = ParsePacket(bytes, length, header);
                if (packet != null) EnqueuePacket(packet);
            }
        }
        catch (Exception exception)
        {
            LastError = FriendlyError(exception);
            CaptureError = LastError;
        }
        finally
        {
            if (handle != IntPtr.Zero) pcap_close(handle);
            Running = false;
        }
    }

    private static Dictionary<string, object> ParsePacket(byte[] data, int length, PcapHeader header)
    {
        if (length < 14) return null;
        string source = FormatMac(data, 6), destination = FormatMac(data, 0);
        int offset = 14;
        int etherType = ReadUInt16(data, 12);
        while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100)
        {
            if (length < offset + 4) return null;
            etherType = ReadUInt16(data, offset + 2);
            offset += 4;
        }

        string protocol = "ETHERNET", transport = null, networkLayer = "Ethernet", src = source, dst = destination;
        object sourcePort = null, destinationPort = null;
        int ipVersion = 0;
        if (etherType == 0x0800 && length >= offset + 20 && (data[offset] >> 4) == 4)
        {
            ipVersion = 4; networkLayer = "IPv4";
            int headerLength = (data[offset] & 15) * 4;
            int ipProtocol = data[offset + 9];
            src = new IPAddress(new byte[] { data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15] }).ToString();
            dst = new IPAddress(new byte[] { data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19] }).ToString();
            protocol = ipProtocol == 6 ? "TCP" : ipProtocol == 17 ? "UDP" : ipProtocol == 1 ? "ICMP" : "IPv4";
            if ((ipProtocol == 6 || ipProtocol == 17) && length >= offset + headerLength + 4 && (ReadUInt16(data, offset + 6) & 0x1FFF) == 0)
            {
                sourcePort = ReadUInt16(data, offset + headerLength);
                destinationPort = ReadUInt16(data, offset + headerLength + 2);
                transport = protocol;
            }
            else if (ipProtocol == 1) transport = "ICMP";
        }
        else if (etherType == 0x86DD && length >= offset + 40 && (data[offset] >> 4) == 6)
        {
            ipVersion = 6; networkLayer = "IPv6";
            byte[] sourceAddress = new byte[16], destinationAddress = new byte[16];
            Buffer.BlockCopy(data, offset + 8, sourceAddress, 0, 16);
            Buffer.BlockCopy(data, offset + 24, destinationAddress, 0, 16);
            src = new IPAddress(sourceAddress).ToString(); dst = new IPAddress(destinationAddress).ToString();
            int nextHeader = data[offset + 6];
            protocol = nextHeader == 6 ? "TCP" : nextHeader == 17 ? "UDP" : nextHeader == 58 ? "ICMPv6" : "IPv6";
            if ((nextHeader == 6 || nextHeader == 17) && length >= offset + 44)
            {
                sourcePort = ReadUInt16(data, offset + 40);
                destinationPort = ReadUInt16(data, offset + 42);
                transport = protocol;
            }
            else if (nextHeader == 58) transport = "ICMPv6";
        }
        else if (etherType == 0x0806 && length >= offset + 28)
        {
            int hardwareLength = data[offset + 4];
            int protocolLength = data[offset + 5];
            int senderProtocolOffset = offset + 8 + hardwareLength;
            int targetProtocolOffset = senderProtocolOffset + protocolLength + hardwareLength;
            if (protocolLength == 4 && length >= targetProtocolOffset + protocolLength)
            {
                protocol = "ARP";
                networkLayer = "ARP";
                ipVersion = 4;
                src = new IPAddress(new byte[] { data[senderProtocolOffset], data[senderProtocolOffset + 1], data[senderProtocolOffset + 2], data[senderProtocolOffset + 3] }).ToString();
                dst = new IPAddress(new byte[] { data[targetProtocolOffset], data[targetProtocolOffset + 1], data[targetProtocolOffset + 2], data[targetProtocolOffset + 3] }).ToString();
            }
        }

        bool multicast = IsMulticast(dst), broadcast = dst == "255.255.255.255";
        bool linkLocal = IsLinkLocal(src) || IsLinkLocal(dst);
        string timestamp = DateTimeOffset.FromUnixTimeSeconds(header.Timestamp.Seconds)
            .AddMilliseconds(header.Timestamp.Microseconds / 1000.0).UtcDateTime.ToString("o");
        Dictionary<string, object> context = new Dictionary<string, object>
        {
            { "is_multicast", multicast }, { "is_broadcast", broadcast }, { "is_link_local", linkLocal },
            { "ip_version", ipVersion == 0 ? (object)null : ipVersion }, { "network_layer", networkLayer }, { "transport_protocol", transport }
        };
        return new Dictionary<string, object>
        {
            { "timestamp", timestamp }, { "source", src }, { "destination", dst }, { "protocol", protocol },
            { "transport_protocol", transport }, { "source_port", sourcePort }, { "destination_port", destinationPort },
            { "size", length }, { "ip_version", ipVersion == 0 ? (object)null : ipVersion }, { "network_layer", networkLayer },
            { "is_multicast", multicast }, { "is_broadcast", broadcast }, { "is_link_local", linkLocal }, { "context", context }
        };
    }

    private static int ReadUInt16(byte[] bytes, int offset) { return (bytes[offset] << 8) | bytes[offset + 1]; }
    private static string FormatMac(byte[] bytes, int offset) { return String.Join(":", Enumerable.Range(offset, 6).Select(i => bytes[i].ToString("x2"))); }

    private static bool IsMulticast(string address)
    {
        IPAddress ip; if (!IPAddress.TryParse(address, out ip)) return false;
        byte[] bytes = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetworkV6 ? bytes[0] == 0xFF : bytes[0] >= 224 && bytes[0] <= 239;
    }

    private static bool IsLinkLocal(string address)
    {
        IPAddress ip; if (!IPAddress.TryParse(address, out ip)) return false;
        byte[] bytes = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetworkV6
            ? bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80
            : bytes[0] == 169 && bytes[1] == 254;
    }

    private static void EnqueuePacket(Dictionary<string, object> packet)
    {
        lock (PendingLock)
        {
            long id = Interlocked.Increment(ref NextPacketId);
            packet["agent_packet_id"] = AgentId + ":" + ProcessRunId + ":" + id.ToString();
            PendingPackets.AddLast(new PendingPacket { Id = id, Data = packet });
            while (PendingPackets.Count > 5000)
            {
                PendingPackets.RemoveFirst();
                Interlocked.Increment(ref DroppedPackets);
            }
        }
        Interlocked.Increment(ref TotalPackets);
    }

    private static List<Dictionary<string, object>> GetInterfaces()
    {
        List<Dictionary<string, object>> result = new List<Dictionary<string, object>>();
        IntPtr devices = IntPtr.Zero;
        StringBuilder error = new StringBuilder(512);
        int code = pcap_findalldevs(out devices, error);
        if (code != 0) { LastError = error.ToString(); return result; }
        try
        {
            IntPtr current = devices;
            while (current != IntPtr.Zero)
            {
                PcapDevice device = (PcapDevice)Marshal.PtrToStructure(current, typeof(PcapDevice));
                string name = Marshal.PtrToStringAnsi(device.Name);
                string description = Marshal.PtrToStringAnsi(device.Description) ?? name;
                if (!String.IsNullOrWhiteSpace(name))
                {
                    string type = description.IndexOf("wi-fi", StringComparison.OrdinalIgnoreCase) >= 0 || description.IndexOf("wireless", StringComparison.OrdinalIgnoreCase) >= 0 ? "wifi" : description.IndexOf("ethernet", StringComparison.OrdinalIgnoreCase) >= 0 ? "ethernet" : "other";
                    result.Add(new Dictionary<string, object>
                    {
                        { "id", result.Count }, { "name", description }, { "description", description }, { "type", type },
                        { "capture_available", true }, { "scapy_name", name }, { "npcap_device", name }
                    });
                }
                current = device.Next;
            }
        }
        finally { if (devices != IntPtr.Zero) pcap_freealldevs(devices); }
        return result;
    }

    private static string LoadAgentId()
    {
        string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "INPA");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "agent.id");
        if (File.Exists(path)) return File.ReadAllText(path).Trim();
        string id = Guid.NewGuid().ToString("N");
        File.WriteAllText(path, id);
        return id;
    }

    private static string FriendlyError(Exception exception)
    {
        WebException web = exception as WebException;
        if (web != null && web.Response is HttpWebResponse)
        {
            using (StreamReader reader = new StreamReader(web.Response.GetResponseStream()))
                return "Serveur INPA : " + (int)((HttpWebResponse)web.Response).StatusCode + " " + reader.ReadToEnd();
        }
        if (exception is DllNotFoundException) return "Npcap est absent. Installe Npcap puis redémarre INPA-Agent.";
        return exception.Message;
    }
}
