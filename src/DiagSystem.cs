using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace RdpDiagBridge;

// 10.11.2026 Сведения о компьютере: Windows, железо, память, диски, пользователи, агент.
public static class SysInfo
{
    public static JObj Run(DiagContext context)
    {
        var result = new JObj();
        context.Progress = "Windows";
        var os = Wmi.Query("SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory, OSLanguage FROM Win32_OperatingSystem").First();
        var boot = Wmi.Date(os, "LastBootUpTime");
        using (var lm = Reg.Lm())
        {
            const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            result["windows"] = new JObj
            {
                { "caption", Wmi.Str(os, "Caption") },
                { "version", Wmi.Str(os, "Version") + "." + Convert.ToString(Reg.Value(lm, path, "UBR") ?? "", CultureInfo.InvariantCulture) },
                { "release", Convert.ToString(Reg.Value(lm, path, "DisplayVersion") ?? Reg.Value(lm, path, "ReleaseId") ?? "", CultureInfo.InvariantCulture) },
                { "architecture", Wmi.Str(os, "OSArchitecture") },
                { "installed", Wmi.Date(os, "InstallDate") },
                { "lastBoot", boot },
                { "uptime", boot.HasValue ? Txt.Duration(DateTime.Now - boot.Value) : "" },
                { "localTime", DateTime.Now },
                { "timeZone", TimeZoneInfo.Local.DisplayName },
                { "uiLanguage", CultureInfo.InstalledUICulture.Name },
            };
        }
        context.Progress = "компьютер";
        var cs = Wmi.Query("SELECT Name, Domain, PartOfDomain, Manufacturer, Model, NumberOfProcessors, NumberOfLogicalProcessors, UserName FROM Win32_ComputerSystem").First();
        var model = Wmi.Str(cs, "Manufacturer") + " " + Wmi.Str(cs, "Model");
        var bios = Wmi.Query("SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS").FirstOrDefault();
        result["computer"] = new JObj
        {
            { "name", Environment.MachineName },
            { "domain", Wmi.Str(cs, "Domain") },
            { "partOfDomain", Wmi.Bool(cs, "PartOfDomain") },
            { "model", model.Trim() },
            { "virtual", IsVirtual(model) },
            { "bios", Wmi.Str(bios, "SMBIOSBIOSVersion") + " " + (Wmi.Date(bios, "ReleaseDate")?.ToString("dd.MM.yyyy") ?? "") },
            { "consoleUser", Wmi.Str(cs, "UserName") },
        };
        var cpus = Wmi.Query("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, LoadPercentage FROM Win32_Processor");
        result["cpu"] = new JObj
        {
            { "name", Txt.OneLine(Wmi.Str(cpus.FirstOrDefault(), "Name"), 100) },
            { "sockets", cpus.Count },
            { "cores", cpus.Sum(c => Wmi.Long(c, "NumberOfCores") ?? 0) },
            { "logical", Environment.ProcessorCount },
            { "maxMHz", Wmi.Long(cpus.FirstOrDefault(), "MaxClockSpeed") },
            { "loadPercent", cpus.Count > 0 ? (int)cpus.Average(c => Wmi.Long(c, "LoadPercentage") ?? 0) : 0 },
        };
        var total = (double)Wmi.ULong(os, "TotalVisibleMemorySize") * 1024;
        var free = (double)Wmi.ULong(os, "FreePhysicalMemory") * 1024;
        var commitTotal = (double)Wmi.ULong(os, "TotalVirtualMemorySize") * 1024;
        var commitFree = (double)Wmi.ULong(os, "FreeVirtualMemory") * 1024;
        result["memory"] = new JObj
        {
            { "totalGb", Txt.Gb(total) },
            { "freeGb", Txt.Gb(free) },
            { "freePercent", total > 0 ? Txt.Round(100 * free / total) : 0 },
            { "commitUsedGb", Txt.Gb(commitTotal - commitFree) },
            { "commitLimitGb", Txt.Gb(commitTotal) },
            {
                "pageFiles", Wmi.Query("SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage").Select(p => new JObj
                {
                    { "file", Wmi.Str(p, "Name") }, { "sizeMb", Wmi.Long(p, "AllocatedBaseSize") },
                    { "usedMb", Wmi.Long(p, "CurrentUsage") }, { "peakMb", Wmi.Long(p, "PeakUsage") },
                }).ToList()
            },
        };
        context.Progress = "диски";
        result["disks"] = DisksDiag.Volumes();
        context.Progress = "пользователи";
        result["sessions"] = Linq2.Safe(() => Env.RunConsole("quser.exe", "", 10000).Split('\n').Select(l => l.TrimEnd()).Where(l => l != ""));
        result["network"] = Linq2.Safe(() => NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(n => n.Name + ": " + string.Join(", ", n.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Select(a => a.Address.ToString()))));
        result["agent"] = new JObj
        {
            { "version", Proto.AppVersion },
            { "user", Env.UserName },
            { "elevated", Env.Elevated },
            { "process", Environment.Is64BitProcess ? "64-bit" : "32-bit" },
            { "path", Process.GetCurrentProcess().MainModule?.FileName ?? "" },
            { "dotNet", DotNetVersion() },
            { "powerShell", PowerShellVersion() },
            { "rdpClient", Environment.GetEnvironmentVariable("CLIENTNAME") ?? "" },
            { "rdpSession", Environment.GetEnvironmentVariable("SESSIONNAME") ?? "" },
        };
        context.Progress = "сервер терминалов";
        try
        {
            var ts = Wmi.Query("SELECT TerminalServerMode, LicensingName FROM Win32_TerminalServiceSetting", @"root\cimv2\TerminalServices").FirstOrDefault();
            if (ts != null)
                result["remoteDesktop"] = new JObj
                {
                    { "terminalServer", (Wmi.Long(ts, "TerminalServerMode") ?? 0) == 1 },
                    { "licensing", Wmi.Str(ts, "LicensingName") },
                };
        }
        catch (Exception)
        {
        }
        try
        {
            var av = Wmi.Query("SELECT displayName, productState FROM AntiVirusProduct", @"root\SecurityCenter2");
            result["antivirus"] = av.Select(a => Wmi.Str(a, "displayName")
                + ((((Wmi.Long(a, "productState") ?? 0) >> 12) & 0xF) == 1 ? " (включен)" : " (выключен)")).ToList();
        }
        catch (Exception)
        {
        }
        context.Progress = "";
        return result;
    }

    static bool IsVirtual(string model)
    {
        var text = model.ToLowerInvariant();
        return text.Contains("virtual") || text.Contains("vmware") || text.Contains("kvm") || text.Contains("qemu")
               || text.Contains("xen") || text.Contains("hyper-v") || text.Contains("bochs") || text.Contains("parallels");
    }

    static string DotNetVersion()
    {
        using var lm = Reg.Lm();
        var release = Convert.ToInt32(Reg.Value(lm, @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", "Release") ?? 0);
        var versions = new[]
        {
            new KeyValuePair<int, string>(533320, "4.8.1"), new KeyValuePair<int, string>(528040, "4.8"),
            new KeyValuePair<int, string>(461808, "4.7.2"), new KeyValuePair<int, string>(461308, "4.7.1"),
            new KeyValuePair<int, string>(460798, "4.7"), new KeyValuePair<int, string>(394802, "4.6.2"),
            new KeyValuePair<int, string>(394254, "4.6.1"), new KeyValuePair<int, string>(393295, "4.6"),
            new KeyValuePair<int, string>(379893, "4.5.2"), new KeyValuePair<int, string>(378675, "4.5.1"),
            new KeyValuePair<int, string>(378389, "4.5"),
        };
        foreach (var version in versions)
            if (release >= version.Key)
                return version.Value + " (release " + release + ")";
        return Environment.Version.ToString();
    }

    static string PowerShellVersion()
    {
        using var lm = Reg.Lm();
        return Convert.ToString(Reg.Value(lm, @"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine", "PowerShellVersion")
                                ?? Reg.Value(lm, @"SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine", "PowerShellVersion") ?? "нет",
            CultureInfo.InvariantCulture);
    }
}

// 10.11.2026 Процессы: загрузка процессора (замер), память, дескрипторы; с details – командная строка и владелец.
public static class ProcessesDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var sort = p.Str("sort", "cpu").ToLowerInvariant();
        var top = p.Int("top", 30, 1, 1000);
        var filter = Txt.Wildcard(p.Str("name"));
        var details = p.Bool("details", false);
        var sampleMs = p.Int("sampleMs", 1000, 0, 10000);
        context.Progress = "замер процессора";
        var cpu = sampleMs > 0 ? CpuSampler.Measure(sampleMs, context) : new CpuSampler.Sample();
        context.Progress = "список процессов";
        var rows = new List<JObj>();
        long totalWorkingSet = 0;
        var count = 0;
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                count++;
                long workingSet = 0;
                try
                {
                    workingSet = process.WorkingSet64;
                }
                catch (Exception)
                {
                }
                totalWorkingSet += workingSet;
                var name = Safe(() => process.ProcessName) ?? "?";
                if (filter != null && !filter.IsMatch(name) && !filter.IsMatch(name + ".exe"))
                    continue;
                rows.Add(new JObj
                {
                    { "pid", process.Id },
                    { "name", name },
                    { "cpu", cpu.ByPid.TryGetValue(process.Id, out var percent) ? percent : (object)null },
                    { "wsMb", Txt.Mb(workingSet) },
                    { "privateMb", Txt.Mb(SafeLong(() => process.PrivateMemorySize64)) },
                    { "handles", SafeLong(() => process.HandleCount) },
                    { "threads", SafeLong(() => process.Threads.Count) },
                    { "session", SafeLong(() => process.SessionId) },
                    { "started", SafeDate(() => process.StartTime) },
                });
            }
        }
        IEnumerable<JObj> ordered = sort switch
        {
            "memory" => rows.OrderByDescending(r => r.Num("wsMb") ?? 0),
            "handles" => rows.OrderByDescending(r => r.Num("handles") ?? 0),
            "name" => rows.OrderBy(r => r.Str("name"), StringComparer.OrdinalIgnoreCase),
            "start" => rows.OrderByDescending(r => r.Get("started") as DateTime? ?? DateTime.MinValue),
            _ => rows.OrderByDescending(r => r.Num("cpu") ?? 0).ThenByDescending(r => r.Num("wsMb") ?? 0),
        };
        var list = ordered.Take(top).ToList();
        if (details && list.Count > 0)
        {
            context.Progress = "командные строки";
            AddDetails(list, context);
        }
        context.Progress = "";
        return new JObj
        {
            { "processes", count },
            { "cpuTotal", sampleMs > 0 ? cpu.Total : (object)null },
            { "workingSetTotalGb", Txt.Gb(totalWorkingSet) },
            { "matched", rows.Count },
            { "sort", sort },
            { "items", list },
        };
    }

    static void AddDetails(List<JObj> list, DiagContext context)
    {
        var byPid = list.ToDictionary(r => (int)(r.Num("pid") ?? 0));
        foreach (var chunk in byPid.Keys.Select((pid, index) => new { pid, index }).GroupBy(x => x.index / 40))
        {
            var where = string.Join(" OR ", chunk.Select(x => "ProcessId=" + x.pid));
            foreach (var item in Wmi.Query("SELECT ProcessId, CommandLine, ExecutablePath FROM Win32_Process WHERE " + where))
            {
                context.CheckCancel();
                var pid = (int)(Wmi.Long(item, "ProcessId") ?? 0);
                if (!byPid.TryGetValue(pid, out var row))
                    continue;
                row["commandLine"] = Txt.Clip(Wmi.Str(item, "CommandLine"), 1000);
                row["path"] = Wmi.Str(item, "ExecutablePath");
                try
                {
                    if (item is ManagementObject managed)
                    {
                        var owner = managed.InvokeMethod("GetOwner", null, null);
                        if (owner != null && Convert.ToInt32(owner["ReturnValue"], CultureInfo.InvariantCulture) == 0)
                            row["owner"] = owner["Domain"] + "\\" + owner["User"];
                    }
                }
                catch (Exception)
                {
                }
            }
        }
    }

    static string Safe(Func<string> getter)
    {
        try
        {
            return getter();
        }
        catch (Exception)
        {
            return null;
        }
    }

    static long SafeLong(Func<long> getter)
    {
        try
        {
            return getter();
        }
        catch (Exception)
        {
            return 0;
        }
    }

    static object SafeDate(Func<DateTime> getter)
    {
        try
        {
            return getter();
        }
        catch (Exception)
        {
            return null;
        }
    }
}

// 10.11.2026 Службы с отбором: problem – автозапускаемые и не работающие, зависшие в Start/Stop Pending.
public static class ServicesDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var filter = p.Str("filter", "problem").ToLowerInvariant();
        var name = Txt.Wildcard(p.Str("name"));
        var items = new List<JObj>();
        using var lm = Reg.Lm();
        foreach (var service in Wmi.Query("SELECT Name, DisplayName, State, StartMode, StartName, ProcessId, ExitCode, ServiceSpecificExitCode, PathName FROM Win32_Service"))
        {
            context.CheckCancel();
            var serviceName = Wmi.Str(service, "Name");
            var display = Wmi.Str(service, "DisplayName");
            var path = Wmi.Str(service, "PathName");
            var state = Wmi.Str(service, "State");
            var mode = Wmi.Str(service, "StartMode");
            if (name != null && !name.IsMatch(serviceName) && !name.IsMatch(display) && !name.IsMatch(path))
                continue;
            var key = @"SYSTEM\CurrentControlSet\Services\" + serviceName;
            var trigger = Reg.KeyExists(lm, key + @"\TriggerInfo");
            var delayed = Convert.ToInt32(Reg.Value(lm, key, "DelayedAutostart") ?? 0) == 1;
            var pending = state.EndsWith("Pending", StringComparison.OrdinalIgnoreCase);
            var match = filter switch
            {
                "all" => true,
                "running" => state == "Running",
                "stopped" => state == "Stopped",
                "auto" => mode == "Auto",
                _ => pending || (mode == "Auto" && state != "Running" && !trigger),
            };
            if (!match)
                continue;
            items.Add(new JObj
            {
                { "name", serviceName },
                { "display", display },
                { "state", state },
                { "start", mode + (delayed ? " (отложенный)" : "") + (trigger ? " (по триггеру)" : "") },
                { "account", Wmi.Str(service, "StartName") },
                { "pid", Wmi.Long(service, "ProcessId") },
                { "exitCode", Wmi.Long(service, "ExitCode") },
                { "serviceExitCode", Wmi.Long(service, "ServiceSpecificExitCode") },
                { "important", Health.ImportantService.IsMatch(serviceName + " " + display + " " + path) },
                { "path", Txt.Clip(path, 300) },
            });
        }
        return new JObj
        {
            { "filter", filter },
            { "count", items.Count },
            { "items", items.OrderBy(i => i.Str("display"), StringComparer.CurrentCultureIgnoreCase).ToList() },
        };
    }
}

// 10.11.2026 Диски: тома, физические диски, SMART, задержки и очередь по замеру, ошибки в журнале.
public static class DisksDiag
{
    public static List<JObj> Volumes()
    {
        var result = Wmi.Query("SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3")
            .Select(d =>
            {
                var size = (double)Wmi.ULong(d, "Size");
                var free = (double)Wmi.ULong(d, "FreeSpace");
                return new JObj
                {
                    { "drive", Wmi.Str(d, "DeviceID") },
                    { "type", "локальный" },
                    { "label", Wmi.Str(d, "VolumeName") },
                    { "fs", Wmi.Str(d, "FileSystem") },
                    { "sizeGb", Txt.Gb(size) },
                    { "freeGb", Txt.Gb(free) },
                    { "freePercent", size > 0 ? Txt.Round(100 * free / size) : (object)null },
                };
            }).ToList();
        // 10.11.2026 Размер сетевого диска без связи и пустого картридера WMI ждет минутами – спрашиваем
        // отдельно с пределом 2 с.
        foreach (var d in Wmi.Query("SELECT DeviceID, DriveType, ProviderName FROM Win32_LogicalDisk WHERE DriveType=2 OR DriveType=4"))
        {
            var drive = Wmi.Str(d, "DeviceID");
            var network = (Wmi.Long(d, "DriveType") ?? 0) == 4;
            var item = new JObj { { "drive", drive }, { "type", network ? "сетевой" : "съемный" } };
            if (network)
                item["network"] = Wmi.Str(d, "ProviderName");
            long size = -1;
            long free = -1;
            var probe = new Thread(() =>
            {
                try
                {
                    var info = new DriveInfo(drive);
                    if (info.IsReady)
                    {
                        size = info.TotalSize;
                        free = info.AvailableFreeSpace;
                    }
                }
                catch (Exception)
                {
                }
            }) { IsBackground = true };
            probe.Start();
            if (!probe.Join(2000))
                item["state"] = "нет ответа за 2 с";
            else if (size <= 0)
                item["state"] = network ? "недоступен" : "нет носителя";
            else
            {
                item["sizeGb"] = Txt.Gb(size);
                item["freeGb"] = Txt.Gb(free);
                item["freePercent"] = Txt.Round(100.0 * free / size);
            }
            result.Add(item);
        }
        return result;
    }

    public static JObj Run(Params p, DiagContext context)
    {
        var result = new JObj();
        context.Progress = "тома";
        result["volumes"] = Volumes();
        context.Progress = "физические диски";
        try
        {
            result["physical"] = Wmi.Query("SELECT FriendlyName, MediaType, BusType, Size, HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk", @"root\Microsoft\Windows\Storage")
                .Select(d => new JObj
                {
                    { "name", Wmi.Str(d, "FriendlyName") },
                    { "media", (Wmi.Long(d, "MediaType") ?? 0) switch { 3 => "HDD", 4 => "SSD", 5 => "SCM", _ => "?" } },
                    { "bus", BusType(Wmi.Long(d, "BusType") ?? 0) },
                    { "sizeGb", Txt.Gb(Wmi.ULong(d, "Size")) },
                    { "health", (Wmi.Long(d, "HealthStatus") ?? 5) switch { 0 => "Healthy", 1 => "Warning", 2 => "Unhealthy", _ => "Unknown" } },
                    { "operational", Wmi.Str(d, "OperationalStatus") },
                }).ToList();
        }
        catch (Exception)
        {
            result["physical"] = Wmi.Query("SELECT Model, InterfaceType, MediaType, Size, Status FROM Win32_DiskDrive")
                .Select(d => new JObj
                {
                    { "name", Wmi.Str(d, "Model") }, { "bus", Wmi.Str(d, "InterfaceType") }, { "media", Wmi.Str(d, "MediaType") },
                    { "sizeGb", Txt.Gb(Wmi.ULong(d, "Size")) }, { "health", Wmi.Str(d, "Status") },
                }).ToList();
        }
        context.Progress = "SMART";
        try
        {
            result["smart"] = Wmi.Query("SELECT InstanceName, PredictFailure, Reason FROM MSStorageDriver_FailurePredictStatus", @"root\wmi")
                .Select(s => new JObj
                {
                    { "disk", Wmi.Str(s, "InstanceName") }, { "predictFailure", Wmi.Bool(s, "PredictFailure") }, { "reason", Wmi.Long(s, "Reason") },
                }).ToList();
        }
        catch (UnauthorizedAccessException)
        {
            result["smart"] = "нет прав: нужен агент от администратора";
        }
        catch (Exception ex)
        {
            result["smart"] = "недоступно: " + ex.Message;
        }
        context.Progress = "замер задержек";
        result["io"] = MeasureIo(p.Int("sampleMs", 2000, 500, 10000), context);
        context.Progress = "ошибки в журнале";
        try
        {
            result["errors"] = Health.DiskErrorGroups(p.Int("days", 7, 1, 90));
        }
        catch (Exception ex)
        {
            result["errors"] = "не прочитаны: " + ex.Message;
        }
        context.Progress = "";
        return result;
    }

    static string BusType(long code)
    {
        switch (code)
        {
            case 1: return "SCSI";
            case 3: return "ATA";
            case 6: return "FibreChannel";
            case 7: return "USB";
            case 8: return "RAID";
            case 9: return "iSCSI";
            case 10: return "SAS";
            case 11: return "SATA";
            case 12: return "SD";
            case 13: return "MMC";
            case 14: return "Virtual";
            case 15: return "FileBackedVirtual";
            case 16: return "Spaces";
            case 17: return "NVMe";
            default: return code.ToString(CultureInfo.InvariantCulture);
        }
    }

    const string IoWql = "SELECT Name, AvgDisksecPerRead, AvgDisksecPerRead_Base, AvgDisksecPerWrite, AvgDisksecPerWrite_Base, "
                         + "PercentIdleTime, PercentIdleTime_Base, CurrentDiskQueueLength, DiskReadBytesPersec, DiskWriteBytesPersec, "
                         + "DiskReadsPersec, DiskWritesPersec, Frequency_PerfTime, Timestamp_PerfTime FROM Win32_PerfRawData_PerfDisk_PhysicalDisk";

    // 10.11.2026 Задержки дисков по двум снимкам сырых счетчиков: форматированный класс WMI округляет
    // секунды до целого и показывает 0 мс.
    public static List<JObj> MeasureIo(int milliseconds, DiagContext context)
    {
        var first = Wmi.Query(IoWql).ToDictionary(d => Wmi.Str(d, "Name"));
        var waited = 0;
        while (waited < milliseconds)
        {
            context.CheckCancel();
            Thread.Sleep(Math.Min(250, milliseconds - waited));
            waited += 250;
        }
        var result = new List<JObj>();
        foreach (var second in Wmi.Query(IoWql))
        {
            var name = Wmi.Str(second, "Name");
            if (name == "_Total" || !first.TryGetValue(name, out var before))
                continue;
            var frequency = (double)Math.Max(1UL, Wmi.ULong(second, "Frequency_PerfTime"));
            var seconds = ((double)Wmi.ULong(second, "Timestamp_PerfTime") - Wmi.ULong(before, "Timestamp_PerfTime")) / frequency;
            if (seconds <= 0)
                continue;
            double Delta(string counter) => (double)unchecked((uint)Wmi.ULong(second, counter) - (uint)Wmi.ULong(before, counter));
            double Delta64(string counter) => (double)Wmi.ULong(second, counter) - Wmi.ULong(before, counter);
            var reads = Delta64("DiskReadsPersec");
            var writes = Delta64("DiskWritesPersec");
            var readBase = Delta("AvgDisksecPerRead_Base");
            var writeBase = Delta("AvgDisksecPerWrite_Base");
            var idleBase = Delta64("PercentIdleTime_Base");
            result.Add(new JObj
            {
                { "disk", name },
                { "readMs", readBase > 0 ? Txt.Round(1000 * Delta("AvgDisksecPerRead") / frequency / readBase) : 0 },
                { "writeMs", writeBase > 0 ? Txt.Round(1000 * Delta("AvgDisksecPerWrite") / frequency / writeBase) : 0 },
                { "busyPercent", idleBase > 0 ? Txt.Round(Math.Max(0, 100 - 100 * Delta64("PercentIdleTime") / idleBase)) : (object)null },
                { "queue", Wmi.Long(second, "CurrentDiskQueueLength") },
                { "readsPerSec", Txt.Round(reads / seconds) },
                { "writesPerSec", Txt.Round(writes / seconds) },
                { "readMBps", Txt.Mb(Delta64("DiskReadBytesPersec") / seconds) },
                { "writeMBps", Txt.Mb(Delta64("DiskWriteBytesPersec") / seconds) },
            });
        }
        return result;
    }
}

// 10.11.2026 Замер производительности за несколько секунд: процессор, память, диски, сеть, верхние процессы.
public static class PerfDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var seconds = p.Int("seconds", 5, 1, 60);
        var top = p.Int("top", 10, 1, 50);
        var cpuValues = new List<double>();
        var queueValues = new List<double>();
        var availableMb = new List<double>();
        var pages = new List<double>();
        var commit = new List<double>();
        var network = new Dictionary<string, List<double>>();
        var bandwidth = new Dictionary<string, double>();
        // 10.11.2026 Первый запрос к форматированным классам «прогревает» расчет скоростей.
        Wmi.Query("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'");
        Wmi.Query("SELECT BytesTotalPersec FROM Win32_PerfFormattedData_Tcpip_NetworkInterface");
        var processStart = CpuSampler.Snapshot();
        var ioStart = DateTime.UtcNow;
        for (var i = 0; i < seconds; i++)
        {
            context.CheckCancel();
            context.Progress = "замер " + (i + 1) + " из " + seconds + " с";
            Thread.Sleep(1000);
            var cpu = Wmi.Query("SELECT PercentProcessorTime FROM Win32_PerfFormattedData_PerfOS_Processor WHERE Name='_Total'").FirstOrDefault();
            cpuValues.Add(Wmi.Long(cpu, "PercentProcessorTime") ?? 0);
            var system = Wmi.Query("SELECT ProcessorQueueLength FROM Win32_PerfFormattedData_PerfOS_System").FirstOrDefault();
            queueValues.Add(Wmi.Long(system, "ProcessorQueueLength") ?? 0);
            var memory = Wmi.Query("SELECT AvailableMBytes, PagesPersec, PercentCommittedBytesInUse FROM Win32_PerfFormattedData_PerfOS_Memory").FirstOrDefault();
            availableMb.Add(Wmi.Long(memory, "AvailableMBytes") ?? 0);
            pages.Add(Wmi.Long(memory, "PagesPersec") ?? 0);
            commit.Add(Wmi.Long(memory, "PercentCommittedBytesInUse") ?? 0);
            foreach (var nic in Wmi.Query("SELECT Name, BytesTotalPersec, CurrentBandwidth FROM Win32_PerfFormattedData_Tcpip_NetworkInterface"))
            {
                var name = Wmi.Str(nic, "Name");
                if (!network.TryGetValue(name, out var list))
                    network[name] = list = new List<double>();
                list.Add(Wmi.ULong(nic, "BytesTotalPersec"));
                bandwidth[name] = Wmi.ULong(nic, "CurrentBandwidth");
            }
        }
        context.Progress = "диски и процессы";
        var cpuByProcess = CpuSampler.Compare(processStart, CpuSampler.Snapshot());
        var io = DisksDiag.MeasureIo(1000, context);
        context.Progress = "";
        JObj Stat(List<double> values, string unit) => new JObj
        {
            { "avg", values.Count > 0 ? Txt.Round(values.Average()) : 0 },
            { "max", values.Count > 0 ? Txt.Round(values.Max()) : 0 },
            { "unit", unit },
        };
        return new JObj
        {
            { "seconds", seconds },
            { "cpuPercent", Stat(cpuValues, "%") },
            { "cpuQueue", Stat(queueValues, "потоков") },
            { "logicalProcessors", Environment.ProcessorCount },
            { "memoryAvailableMb", Stat(availableMb, "МБ") },
            { "pagesPerSec", Stat(pages, "стр/с") },
            { "commitPercent", Stat(commit, "%") },
            {
                "network", network.Where(n => n.Value.Any(v => v > 0) || bandwidth[n.Key] > 0).Select(n => new JObj
                {
                    { "adapter", n.Key },
                    { "avgMbit", Txt.Round(n.Value.Average() * 8 / 1000000, 2) },
                    { "maxMbit", Txt.Round(n.Value.Max() * 8 / 1000000, 2) },
                    { "linkMbit", Txt.Round(bandwidth[n.Key] / 1000000, 0) },
                }).ToList()
            },
            { "disks", io },
            {
                "topCpu", cpuByProcess.ByPid.OrderByDescending(x => x.Value).Take(top).Select(x => new JObj
                {
                    { "pid", x.Key }, { "name", cpuByProcess.Names.TryGetValue(x.Key, out var n) ? n : "?" }, { "cpu", x.Value },
                }).ToList()
            },
            { "measuredSeconds", Txt.Round((DateTime.UtcNow - ioStart).TotalSeconds) },
        };
    }
}
