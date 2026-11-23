using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace RdpDiagBridge;

// 10.11.2026 Выполнение команды агентом: разбор типа, вызов проверки, ответ по протоколу.
public static class Diag
{
    public static JObj Execute(Command command, AgentCore agent)
    {
        var watch = Stopwatch.StartNew();
        var context = command.Context;
        var response = AgentCore.Response(command, "ok", null);
        try
        {
            var p = new Params(command.Params);
            object result = command.Type switch
            {
                "ping" => Ping(agent),
                "health" => Health.Run(p, context),
                "sysinfo" => SysInfo.Run(context),
                "events" => EventsDiag.Run(p, context),
                "processes" => ProcessesDiag.Run(p, context),
                "services" => ServicesDiag.Run(p, context),
                "disks" => DisksDiag.Run(p, context),
                "network" => NetworkDiag.Run(p, context),
                "nettest" => NetTest.Run(p, context),
                "perf" => PerfDiag.Run(p, context),
                "software" => SoftwareDiag.Run(p, context),
                "tasks" => TasksDiag.Run(p, context),
                "files" => FilesDiag.Run(p, context),
                "onec" => OneCDiag.Run(p, context),
                "powershell" => PowerShellRunner.Run(p, context, agent),
                _ => throw new RejectedException("Агент не знает команду «" + command.Type + "» (версия агента "
                                                 + Proto.AppVersion + ")."),
            };
            response["result"] = result;
        }
        catch (RejectedException ex)
        {
            response["status"] = "rejected";
            response["error"] = ex.Message;
        }
        catch (OperationCanceledException)
        {
            response["status"] = "cancelled";
            response["error"] = "Команда прервана";
        }
        catch (UnauthorizedAccessException ex)
        {
            response["status"] = "error";
            response["error"] = NoRights(ex.Message);
        }
        catch (Exception ex)
        {
            response["status"] = "error";
            response["error"] = ex.Message;
            response["errorDetails"] = ex.ToString();
        }
        lock (context.Warnings)
            if (context.Warnings.Count > 0)
                response["warnings"] = context.Warnings.ToList();
        response["durationMs"] = watch.ElapsedMilliseconds;
        response["finishedUtc"] = Proto.UtcStamp(DateTime.UtcNow);
        return response;
    }

    public static string NoRights(string message)
    {
        return message + (Env.Elevated ? "" : " (агент запущен без прав администратора: в окне агента – «Перезапустить от администратора»)");
    }

    static JObj Ping(AgentCore agent)
    {
        var bootTime = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount & int.MaxValue);
        return new JObj
        {
            { "computer", Environment.MachineName },
            { "user", Env.UserName },
            { "elevated", Env.Elevated },
            { "agentVersion", Proto.AppVersion },
            { "localTime", DateTime.Now },
            { "timeZone", TimeZoneInfo.Local.DisplayName },
            { "uptime", Txt.Duration(DateTime.Now - Uptime.LastBoot(bootTime)) },
            { "allowCode", agent.AllowCode },
            { "confirm", agent.ConfirmMode },
        };
    }
}

// 10.11.2026 Время последней загрузки: Environment.TickCount переполняется через 24,9 сут – берем из WMI.
public static class Uptime
{
    public static DateTime LastBoot(DateTime fallback)
    {
        try
        {
            var os = Wmi.Query("SELECT LastBootUpTime FROM Win32_OperatingSystem").FirstOrDefault();
            return Wmi.Date(os, "LastBootUpTime") ?? fallback;
        }
        catch (Exception)
        {
            return fallback;
        }
    }
}

// 10.11.2026 Запросы WMI с понятными ошибками и приведением типов.
public static class Wmi
{
    public static List<ManagementBaseObject> Query(string wql, string ns = @"root\cimv2", int timeoutSec = 60)
    {
        var options = new EnumerationOptions
        {
            ReturnImmediately = true,
            Rewindable = false,
            Timeout = TimeSpan.FromSeconds(timeoutSec),
        };
        var result = new List<ManagementBaseObject>();
        try
        {
            using var searcher = new ManagementObjectSearcher(new ManagementScope(ns), new ObjectQuery(wql), options);
            foreach (var item in searcher.Get())
                result.Add(item);
        }
        catch (ManagementException ex) when (ex.ErrorCode == ManagementStatus.AccessDenied)
        {
            throw new UnauthorizedAccessException("WMI " + ns + ": нет прав");
        }
        return result;
    }

    public static bool IsMissing(Exception ex)
    {
        return ex is ManagementException management
               && (management.ErrorCode == ManagementStatus.InvalidNamespace
                   || management.ErrorCode == ManagementStatus.InvalidClass
                   || management.ErrorCode == ManagementStatus.NotSupported);
    }

    public static object Val(ManagementBaseObject item, string name)
    {
        if (item == null)
            return null;
        try
        {
            return item[name];
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static string Str(ManagementBaseObject item, string name)
    {
        var value = Val(item, name);
        if (value is Array list)
            return string.Join(", ", list.Cast<object>().Select(x => Convert.ToString(x, CultureInfo.InvariantCulture)));
        return value == null ? "" : Convert.ToString(value, CultureInfo.InvariantCulture);
    }

    public static long? Long(ManagementBaseObject item, string name)
    {
        var value = Val(item, name);
        if (value == null)
            return null;
        try
        {
            return Convert.ToInt64(value, CultureInfo.InvariantCulture);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static ulong ULong(ManagementBaseObject item, string name)
    {
        var value = Val(item, name);
        if (value == null)
            return 0;
        try
        {
            return Convert.ToUInt64(value, CultureInfo.InvariantCulture);
        }
        catch (Exception)
        {
            return 0;
        }
    }

    public static bool Bool(ManagementBaseObject item, string name)
    {
        return Val(item, name) is bool flag && flag;
    }

    public static DateTime? Date(ManagementBaseObject item, string name)
    {
        var text = Str(item, name);
        if (text.Length < 14)
            return null;
        try
        {
            return ManagementDateTimeConverter.ToDateTime(text);
        }
        catch (Exception)
        {
            return null;
        }
    }
}

// 10.11.2026 Чтение журналов событий через EventLogReader с отбором XPath на стороне службы журнала.
public static class Ev
{
    public static string XPath(IEnumerable<int> levels, double hours, IEnumerable<int> ids, IEnumerable<string> providers)
    {
        var parts = new List<string>();
        var providerList = providers?.Where(p => !string.IsNullOrWhiteSpace(p)).ToList() ?? new List<string>();
        if (providerList.Count > 0)
            parts.Add("Provider[" + string.Join(" or ", providerList.Select(p => "@Name='" + p.Replace("'", "") + "'")) + "]");
        var levelList = levels?.ToList() ?? new List<int>();
        if (levelList.Count > 0)
            parts.Add("(" + string.Join(" or ", levelList.Select(l => "Level=" + l)) + ")");
        var idList = ids?.ToList() ?? new List<int>();
        if (idList.Count > 0)
            parts.Add("(" + string.Join(" or ", idList.Select(i => "EventID=" + i)) + ")");
        if (hours > 0)
            parts.Add("TimeCreated[timediff(@SystemTime) <= " + ((long)(hours * 3600000)).ToString(CultureInfo.InvariantCulture) + "]");
        return parts.Count == 0 ? "*" : "*[System[" + string.Join(" and ", parts) + "]]";
    }

    // 10.11.2026 Новые события первыми; запись события освобождается сразу после разбора.
    public static List<T> Read<T>(string log, string xpath, int max, Func<EventRecord, T> map, DiagContext context = null)
    {
        var result = new List<T>();
        var query = new EventLogQuery(log, PathType.LogName, xpath) { ReverseDirection = true };
        try
        {
            using var reader = new EventLogReader(query);
            while (result.Count < max)
            {
                context?.CheckCancel();
                using var record = reader.ReadEvent();
                if (record == null)
                    break;
                result.Add(map(record));
            }
        }
        catch (EventLogNotFoundException)
        {
            throw new LogMissingException(log);
        }
        catch (UnauthorizedAccessException)
        {
            throw new UnauthorizedAccessException("Журнал «" + log + "»: нет прав на чтение");
        }
        catch (EventLogException ex) when (ex.Message.IndexOf("access", StringComparison.OrdinalIgnoreCase) >= 0
                                           || ex.Message.IndexOf("доступ", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            throw new UnauthorizedAccessException("Журнал «" + log + "»: нет прав на чтение");
        }
        return result;
    }

    public static string Message(EventRecord record, int max)
    {
        string text = null;
        try
        {
            text = record.FormatDescription();
        }
        catch (Exception)
        {
        }
        if (string.IsNullOrWhiteSpace(text))
        {
            try
            {
                text = "(нет текста события; параметры: "
                       + string.Join("; ", record.Properties.Select(p => Convert.ToString(p.Value, CultureInfo.InvariantCulture))) + ")";
            }
            catch (Exception)
            {
                text = "";
            }
        }
        return Txt.OneLine(text, max);
    }

    public static string Prop(EventRecord record, int index)
    {
        try
        {
            return record.Properties.Count > index
                ? Convert.ToString(record.Properties[index].Value, CultureInfo.InvariantCulture) ?? ""
                : "";
        }
        catch (Exception)
        {
            return "";
        }
    }

    public static string LevelName(EventRecord record)
    {
        var keywords = record.Keywords ?? 0;
        if ((keywords & 0x10000000000000L) != 0)
            return "audit-failure";
        if ((keywords & 0x20000000000000L) != 0)
            return "audit-success";
        return LevelName(record.Level ?? 4);
    }

    public static string LevelName(int level)
    {
        switch (level)
        {
            case 1: return "critical";
            case 2: return "error";
            case 3: return "warning";
            case 5: return "verbose";
            default: return "info";
        }
    }

    public static int[] LevelCodes(IEnumerable<string> names)
    {
        var codes = new List<int>();
        foreach (var name in names)
        {
            switch (name.ToLowerInvariant())
            {
                case "critical": codes.Add(1); break;
                case "error": codes.Add(2); break;
                case "warning": codes.Add(3); break;
                case "info":
                case "information":
                    codes.Add(4);
                    codes.Add(0);
                    break;
                case "verbose": codes.Add(5); break;
                case "all": return new int[0];
            }
        }
        return codes.Distinct().ToArray();
    }

    public static JObj ToObj(EventRecord record, int maxMessage)
    {
        return new JObj
        {
            { "time", record.TimeCreated },
            { "level", LevelName(record) },
            { "log", record.LogName },
            { "provider", record.ProviderName },
            { "id", record.Id },
            { "message", Message(record, maxMessage) },
        };
    }
}

public sealed class LogMissingException : Exception
{
    public LogMissingException(string log) : base("Журнал «" + log + "» не найден") { }
}

// 10.11.2026 Загрузка процессора по процессам: два снимка сырых счетчиков WMI (не зависят от языка Windows,
// в отличие от имен счетчиков производительности).
public static class CpuSampler
{
    public sealed class Sample
    {
        public double Total;
        public Dictionary<int, double> ByPid = new Dictionary<int, double>();
        public Dictionary<int, string> Names = new Dictionary<int, string>();
    }

    const string Wql = "SELECT Name, IDProcess, PercentProcessorTime, Timestamp_Sys100NS FROM Win32_PerfRawData_PerfProc_Process";

    public static Dictionary<string, ManagementBaseObject> Snapshot()
    {
        var result = new Dictionary<string, ManagementBaseObject>(StringComparer.Ordinal);
        foreach (var item in Wmi.Query(Wql))
            result[Wmi.Str(item, "Name") + "|" + Wmi.Str(item, "IDProcess")] = item;
        return result;
    }

    public static Sample Measure(int milliseconds, DiagContext context)
    {
        var first = Snapshot();
        var waited = 0;
        while (waited < milliseconds)
        {
            context?.CheckCancel();
            Thread.Sleep(Math.Min(250, milliseconds - waited));
            waited += 250;
        }
        return Compare(first, Snapshot());
    }

    public static Sample Compare(Dictionary<string, ManagementBaseObject> first, Dictionary<string, ManagementBaseObject> second)
    {
        var sample = new Sample();
        var cores = Math.Max(1, Environment.ProcessorCount);
        foreach (var pair in second)
        {
            if (!first.TryGetValue(pair.Key, out var before))
                continue;
            var time = (double)Wmi.ULong(pair.Value, "Timestamp_Sys100NS") - Wmi.ULong(before, "Timestamp_Sys100NS");
            if (time <= 0)
                continue;
            var busy = (double)Wmi.ULong(pair.Value, "PercentProcessorTime") - Wmi.ULong(before, "PercentProcessorTime");
            var percent = Math.Max(0, 100.0 * busy / time / cores);
            var name = Wmi.Str(pair.Value, "Name");
            var pid = (int)(Wmi.Long(pair.Value, "IDProcess") ?? 0);
            if (name == "_Total")
                continue;
            if (name == "Idle")
            {
                sample.Total = Txt.Round(Math.Max(0, 100 - percent));
                continue;
            }
            sample.ByPid[pid] = Txt.Round(percent);
            var baseName = name.Contains("#") ? name.Substring(0, name.IndexOf('#')) : name;
            sample.Names[pid] = baseName;
        }
        return sample;
    }
}

// 10.11.2026 Таблица TCP-соединений с PID владельца (GetExtendedTcpTable), IPv4 и IPv6.
public static class TcpTable
{
    public sealed class Row
    {
        public string State = "";
        public string Local = "";
        public int LocalPort;
        public string Remote = "";
        public int RemotePort;
        public int Pid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int family, int tableClass, uint reserved);

    static readonly string[] states =
    {
        "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
    };

    public static List<Row> Read()
    {
        var rows = new List<Row>();
        rows.AddRange(ReadFamily(2));
        try
        {
            rows.AddRange(ReadFamily(23));
        }
        catch (Exception)
        {
        }
        return rows;
    }

    static List<Row> ReadFamily(int family)
    {
        var rows = new List<Row>();
        var size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 5, 0);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            size += 4096;
            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                var code = GetExtendedTcpTable(buffer, ref size, false, family, 5, 0);
                if (code == 122)
                    continue;
                if (code != 0)
                    throw new InvalidOperationException("GetExtendedTcpTable: код " + code);
                var count = Marshal.ReadInt32(buffer);
                var rowSize = family == 2 ? 24 : 56;
                for (var i = 0; i < count; i++)
                {
                    var row = buffer + 4 + i * rowSize;
                    rows.Add(family == 2 ? ParseV4(row) : ParseV6(row));
                }
                return rows;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        return rows;
    }

    static Row ParseV4(IntPtr row)
    {
        return new Row
        {
            State = StateName(Marshal.ReadInt32(row)),
            Local = new IPAddress((uint)Marshal.ReadInt32(row, 4)).ToString(),
            LocalPort = Port(Marshal.ReadInt32(row, 8)),
            Remote = new IPAddress((uint)Marshal.ReadInt32(row, 12)).ToString(),
            RemotePort = Port(Marshal.ReadInt32(row, 16)),
            Pid = Marshal.ReadInt32(row, 20),
        };
    }

    static Row ParseV6(IntPtr row)
    {
        var local = new byte[16];
        var remote = new byte[16];
        Marshal.Copy(row, local, 0, 16);
        Marshal.Copy(row + 24, remote, 0, 16);
        return new Row
        {
            Local = new IPAddress(local).ToString(),
            LocalPort = Port(Marshal.ReadInt32(row, 20)),
            Remote = new IPAddress(remote).ToString(),
            RemotePort = Port(Marshal.ReadInt32(row, 44)),
            State = StateName(Marshal.ReadInt32(row, 48)),
            Pid = Marshal.ReadInt32(row, 52),
        };
    }

    static int Port(int raw)
    {
        return ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);
    }

    static string StateName(int state)
    {
        return state > 0 && state < states.Length ? states[state] : state.ToString(CultureInfo.InvariantCulture);
    }

    // 10.11.2026 Диапазон динамических портов TCP (netsh, числа не зависят от языка вывода).
    public static int[] DynamicRange()
    {
        try
        {
            var text = Env.RunConsole("netsh.exe", "int ipv4 show dynamicport tcp", 10000);
            var numbers = System.Text.RegularExpressions.Regex.Matches(text, @"\d+")
                .Cast<System.Text.RegularExpressions.Match>()
                .Select(m => int.Parse(m.Value, CultureInfo.InvariantCulture))
                .Where(n => n > 0)
                .ToList();
            if (numbers.Count >= 2)
                return new[] { numbers[numbers.Count - 2], numbers[numbers.Count - 1] };
        }
        catch (Exception)
        {
        }
        return new[] { 49152, 16384 };
    }

    public static Dictionary<int, string> ProcessNames()
    {
        var names = new Dictionary<int, string>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                names[process.Id] = process.ProcessName;
            }
            catch (Exception)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
        return names;
    }
}
