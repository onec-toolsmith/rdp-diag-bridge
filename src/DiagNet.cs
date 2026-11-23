using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace RdpDiagBridge;

// 10.11.2026 Сетевые настройки: адаптеры, соединения TCP, слушающие порты, прокси, hosts, брандмауэр.
public static class NetworkDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var result = new JObj();
        context.Progress = "адаптеры";
        result["adapters"] = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .Select(n =>
            {
                var ip = n.GetIPProperties();
                var item = new JObj
                {
                    { "name", n.Name },
                    { "description", n.Description },
                    { "status", n.OperationalStatus.ToString() },
                    { "speedMbit", n.Speed > 0 ? n.Speed / 1000000 : 0 },
                    { "mac", FormatMac(n.GetPhysicalAddress()) },
                    { "addresses", ip.UnicastAddresses.Select(a => a.Address.ToString()).ToList() },
                    { "gateways", ip.GatewayAddresses.Select(g => g.Address.ToString()).ToList() },
                    { "dns", ip.DnsAddresses.Select(d => d.ToString()).ToList() },
                    { "dnsSuffix", ip.DnsSuffix },
                };
                try
                {
                    var v4 = ip.GetIPv4Properties();
                    if (v4 != null)
                        item["dhcp"] = v4.IsDhcpEnabled;
                }
                catch (Exception)
                {
                }
                return item;
            })
            .OrderBy(n => n.Str("status") == "Up" ? 0 : 1).ToList();
        context.Progress = "соединения";
        var rows = TcpTable.Read();
        var names = TcpTable.ProcessNames();
        string ProcessName(int pid) => names.TryGetValue(pid, out var n) ? n : "?";
        var range = TcpTable.DynamicRange();
        result["tcp"] = new JObj
        {
            { "total", rows.Count },
            { "byState", rows.GroupBy(r => r.State).OrderByDescending(g => g.Count()).ToDictionary(g => g.Key, g => (object)g.Count()) },
            { "dynamicPorts", range[0] + "-" + (range[0] + range[1] - 1) },
            { "dynamicUsed", rows.Count(r => r.State != "LISTEN" && r.LocalPort >= range[0] && r.LocalPort < range[0] + range[1]) },
            {
                "topProcesses", rows.Where(r => r.State != "LISTEN").GroupBy(r => r.Pid).OrderByDescending(g => g.Count()).Take(10)
                    .Select(g => new JObj { { "pid", g.Key }, { "name", ProcessName(g.Key) }, { "connections", g.Count() } }).ToList()
            },
        };
        result["listening"] = rows.Where(r => r.State == "LISTEN")
            .GroupBy(r => r.LocalPort + "|" + r.Pid)
            .Select(g => new JObj
            {
                { "port", g.First().LocalPort },
                { "address", string.Join(", ", g.Select(r => r.Local).Distinct()) },
                { "pid", g.First().Pid },
                { "process", ProcessName(g.First().Pid) },
            })
            .OrderBy(x => (int)(x.Num("port") ?? 0)).ToList();
        if (p.Bool("connections", false))
        {
            var filter = p.Str("filter");
            result["connections"] = rows.Where(r => r.State != "LISTEN")
                .Where(r => filter == "" || ProcessName(r.Pid).IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0
                                         || r.Remote.Contains(filter) || r.RemotePort.ToString(CultureInfo.InvariantCulture) == filter
                                         || r.LocalPort.ToString(CultureInfo.InvariantCulture) == filter)
                .Take(p.Int("max", 300, 1, 5000))
                .Select(r => new JObj
                {
                    { "local", r.Local + ":" + r.LocalPort }, { "remote", r.Remote + ":" + r.RemotePort }, { "state", r.State },
                    { "pid", r.Pid }, { "process", ProcessName(r.Pid) },
                }).ToList();
        }
        context.Progress = "прокси";
        result["proxy"] = ProxyInfo();
        result["hosts"] = Linq2.Safe(() => File.ReadAllLines(Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts"))
            .Select(l => l.Trim()).Where(l => l != "" && !l.StartsWith("#")));
        result["firewall"] = FirewallProfiles();
        context.Progress = "";
        return result;
    }

    static string FormatMac(PhysicalAddress address)
    {
        var bytes = address?.GetAddressBytes() ?? new byte[0];
        return string.Join("-", bytes.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    static JObj ProxyInfo()
    {
        var result = new JObj();
        try
        {
            using var user = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
            result["userProxyEnabled"] = Convert.ToInt32(user?.GetValue("ProxyEnable") ?? 0) == 1;
            result["userProxy"] = user?.GetValue("ProxyServer") as string ?? "";
            result["userAutoConfig"] = user?.GetValue("AutoConfigURL") as string ?? "";
        }
        catch (Exception)
        {
        }
        try
        {
            var system = WebRequest.GetSystemWebProxy();
            var target = new Uri("https://www.microsoft.com/");
            var proxy = system.GetProxy(target);
            result["effectiveForHttps"] = proxy == target ? "напрямую" : proxy.ToString();
        }
        catch (Exception)
        {
        }
        result["winHttp"] = Txt.OneLine(SafeRun("netsh.exe", "winhttp show proxy"), 300);
        return result;
    }

    static string SafeRun(string file, string arguments)
    {
        try
        {
            return Env.RunConsole(file, arguments, 10000);
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    static JObj FirewallProfiles()
    {
        var result = new JObj();
        using var lm = Reg.Lm();
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
        {
            var local = Reg.Value(lm, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\" + profile, "EnableFirewall");
            var policy = Reg.Value(lm, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\" + profile, "EnableFirewall");
            var enabled = Convert.ToInt32(policy ?? local ?? 0) == 1;
            result[profile.Replace("Profile", "").Replace("Standard", "Private")] = (enabled ? "включен" : "выключен") + (policy != null ? " (политикой)" : "");
        }
        return result;
    }
}

// 10.11.2026 Проверка доступности узлов: DNS, ping, TCP-порт, HTTP(S) с сертификатом.
public static class NetTest
{
    public static JObj Run(Params p, DiagContext context)
    {
        var targets = p.List("targets");
        if (targets.Count == 0)
            throw new RejectedException("Не указаны targets: узлы, узел:порт или URL.");
        var timeout = p.Int("timeoutMs", 3000, 200, 30000);
        var pings = p.Int("pingCount", 2, 0, 10);
        var results = new List<JObj>();
        foreach (var target in targets.Take(30))
        {
            context.CheckCancel();
            context.Progress = target;
            results.Add(Test(target, timeout, pings));
        }
        context.Progress = "";
        return new JObj { { "from", Environment.MachineName }, { "results", results } };
    }

    static JObj Test(string target, int timeout, int pings)
    {
        var result = new JObj { { "target", target } };
        try
        {
            if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                var uri = new Uri(target);
                Resolve(uri.Host, result);
                TestHttp(uri, timeout, result);
                return result;
            }
            var host = target;
            int? port = null;
            // 10.11.2026 Узел:порт или [IPv6]:порт; голый IPv6-адрес двоеточий имеет несколько.
            var match = Regex.Match(target, @"^\[(.+)\]:(\d+)$");
            if (!match.Success && target.Count(c => c == ':') == 1)
                match = Regex.Match(target, @"^(.+):(\d+)$");
            if (match.Success)
            {
                host = match.Groups[1].Value;
                port = int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
            }
            var addresses = Resolve(host, result);
            if (pings > 0 && addresses.Count > 0)
                Ping(addresses[0], timeout, pings, result);
            if (port.HasValue && addresses.Count > 0)
                TestTcp(addresses[0], port.Value, timeout, result);
        }
        catch (Exception ex)
        {
            result["error"] = ex.Message;
        }
        return result;
    }

    static List<IPAddress> Resolve(string host, JObj result)
    {
        if (IPAddress.TryParse(host, out var literal))
            return new List<IPAddress> { literal };
        var watch = Stopwatch.StartNew();
        try
        {
            var addresses = Dns.GetHostAddresses(host)
                .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToList();
            result["dns"] = string.Join(", ", addresses.Select(a => a.ToString())) + " (" + watch.ElapsedMilliseconds + " мс)";
            return addresses;
        }
        catch (Exception ex)
        {
            result["dns"] = "не разрешается: " + ex.Message;
            return new List<IPAddress>();
        }
    }

    static void Ping(IPAddress address, int timeout, int count, JObj result)
    {
        using var ping = new Ping();
        var replies = new List<string>();
        for (var i = 0; i < count; i++)
        {
            try
            {
                var reply = ping.Send(address, timeout);
                replies.Add(reply.Status == IPStatus.Success ? reply.RoundtripTime + " мс" : reply.Status.ToString());
            }
            catch (Exception ex)
            {
                replies.Add(ex.GetBaseException().Message);
            }
        }
        result["ping"] = string.Join(", ", replies);
    }

    static void TestTcp(IPAddress address, int port, int timeout, JObj result)
    {
        var watch = Stopwatch.StartNew();
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            var pending = socket.BeginConnect(address, port, null, null);
            if (!pending.AsyncWaitHandle.WaitOne(timeout))
            {
                result["tcp"] = "порт " + port + ": нет ответа за " + timeout + " мс (фильтруется или узел недоступен)";
                return;
            }
            socket.EndConnect(pending);
            result["tcp"] = "порт " + port + ": открыт (" + watch.ElapsedMilliseconds + " мс)";
        }
        catch (SocketException ex)
        {
            result["tcp"] = "порт " + port + ": " + (ex.SocketErrorCode == SocketError.ConnectionRefused ? "закрыт (отказ в соединении)" : ex.Message);
        }
    }

    static void TestHttp(Uri uri, int timeout, JObj result)
    {
        try
        {
            ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072 | (SecurityProtocolType)768;
        }
        catch (Exception)
        {
        }
        var watch = Stopwatch.StartNew();
        var request = (HttpWebRequest)WebRequest.Create(uri);
        request.Method = "GET";
        request.Timeout = timeout;
        request.ReadWriteTimeout = timeout;
        request.AllowAutoRedirect = false;
        request.UserAgent = "RdpDiagBridge/" + Proto.AppVersion;
        try
        {
            var proxy = request.Proxy?.GetProxy(uri);
            if (proxy != null && proxy != uri)
                result["proxy"] = proxy.ToString();
        }
        catch (Exception)
        {
        }
        HttpWebResponse response = null;
        try
        {
            response = (HttpWebResponse)request.GetResponse();
        }
        catch (WebException ex)
        {
            response = ex.Response as HttpWebResponse;
            if (response == null)
                result["http"] = ex.Status + ": " + ex.Message + (ex.InnerException != null ? " / " + ex.InnerException.Message : "");
        }
        if (response != null)
        {
            using (response)
            {
                result["http"] = (int)response.StatusCode + " " + response.StatusDescription + " (" + watch.ElapsedMilliseconds + " мс)";
                if (!string.IsNullOrEmpty(response.Headers["Location"]))
                    result["location"] = response.Headers["Location"];
                if (!string.IsNullOrEmpty(response.Server))
                    result["server"] = response.Server;
            }
        }
        var certificate = request.ServicePoint?.Certificate;
        if (certificate != null)
        {
            var cert = new X509Certificate2(certificate);
            result["certificate"] = cert.Subject + "; выдан: " + cert.Issuer + "; действует до " + cert.NotAfter.ToString("dd.MM.yyyy")
                                    + (cert.NotAfter < DateTime.Now ? " – ИСТЕК" : cert.NotAfter < DateTime.Now.AddDays(30) ? " – истекает меньше чем через 30 дн." : "");
        }
    }
}
