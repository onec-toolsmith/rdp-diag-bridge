using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Text.RegularExpressions;

namespace RdpDiagBridge;

// 10.11.2026 Общая проверка компьютера: набор независимых проверок, каждая дает находки с уровнем важности.
public static class Health
{
    // 10.11.2026 Службы, остановка которых почти всегда означает неисправность (1С, лицензии, СУБД, веб-публикация).
    public static readonly Regex ImportantService = new Regex(
        @"1C:|1С:|ragent|rphost|rmngr|\bras\.exe|crserver|hasplms|aksusbd|Sentinel|MSSQL|SQLAgent|SQLServer|postgres|pgsql|Apache|httpd|W3SVC|nginx",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    static readonly HashSet<string> criticalServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "Dnscache", "LanmanServer", "LanmanWorkstation", "Netlogon", "W32Time", "EventLog", "Winmgmt", "RpcSs",
        "Dhcp", "BFE", "MpsSvc", "TermService", "Schedule", "ProfSvc", "gpsvc", "SamSs", "CryptSvc",
    };

    static readonly Regex oneCProcess = new Regex(@"^(1cv8|1cv8c|1cv8s|rphost|ragent|rmngr|ras|crserver|ibsrv|ibcmd)\.exe$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    sealed class Findings
    {
        public readonly List<JObj> Items = new List<JObj>();

        public void Add(string level, string area, string title, IEnumerable<string> details = null)
        {
            var item = new JObj { { "level", level }, { "area", area }, { "title", title } };
            var list = details?.Where(d => !string.IsNullOrWhiteSpace(d)).ToList();
            if (list != null && list.Count > 0)
                item["details"] = list;
            Items.Add(item);
        }
    }

    public static JObj Run(Params p, DiagContext context)
    {
        var hours = p.Int("hours", 24, 1, 720);
        var days = p.Int("days", 7, 1, 90);
        var findings = new Findings();
        var checks = new JArr();

        void Check(string name, Func<string> action)
        {
            context.CheckCancel();
            context.Progress = name;
            var watch = Stopwatch.StartNew();
            string status;
            try
            {
                var note = action();
                status = string.IsNullOrEmpty(note) ? "ok" : note;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (UnauthorizedAccessException ex)
            {
                status = "нет прав: " + ex.Message;
            }
            catch (Exception ex)
            {
                status = "ошибка: " + ex.Message;
            }
            checks.Add(new JObj { { "check", name }, { "status", status }, { "ms", watch.ElapsedMilliseconds } });
        }

        Check("Система и перезагрузка", () => CheckSystem(findings));
        Check("Аварийные выключения и BSOD", () => CheckShutdowns(findings, days));
        Check("Место на дисках", () => CheckDiskSpace(findings));
        Check("Ошибки дисков в журнале", () => CheckDiskErrors(findings, days));
        Check("Здоровье дисков (SMART)", () => CheckSmart(findings));
        Check("Память", () => CheckMemory(findings, days));
        Check("Процессор", () => CheckCpu(findings, context));
        Check("Службы", () => CheckServices(findings));
        Check("Сбои служб", () => CheckServiceCrashes(findings, hours));
        Check("Падения программ", () => CheckAppCrashes(findings, hours));
        Check("Ошибки в журналах", () => CheckLogErrors(findings, hours, context));
        Check("Устройства", () => CheckDevices(findings));
        Check("Обновления Windows", () => CheckUpdates(findings, days));
        Check("Антивирус", () => CheckAntivirus(findings, days));
        Check("Сеть, домен, время", () => CheckNetworkEvents(findings, hours));
        Check("TCP-порты", () => CheckTcp(findings));
        Check("Сервер терминалов", () => CheckRds(findings));
        context.Progress = "";

        var order = new Dictionary<string, int> { { "critical", 0 }, { "warning", 1 }, { "info", 2 } };
        var sorted = findings.Items.OrderBy(f => order.TryGetValue(f.Str("level"), out var rank) ? rank : 3).ToList();
        return new JObj
        {
            { "computer", Environment.MachineName },
            { "checkedAt", DateTime.Now },
            { "hours", hours },
            { "days", days },
            { "elevated", Env.Elevated },
            {
                "summary", new JObj
                {
                    { "critical", sorted.Count(f => f.Str("level") == "critical") },
                    { "warning", sorted.Count(f => f.Str("level") == "warning") },
                    { "info", sorted.Count(f => f.Str("level") == "info") },
                }
            },
            { "findings", sorted },
            { "checks", checks },
        };
    }

    static string CheckSystem(Findings f)
    {
        var os = Wmi.Query("SELECT LastBootUpTime FROM Win32_OperatingSystem").FirstOrDefault();
        var boot = Wmi.Date(os, "LastBootUpTime");
        if (boot.HasValue && (DateTime.Now - boot.Value).TotalDays > 60)
            f.Add("info", "Система", "Компьютер не перезагружался " + (int)(DateTime.Now - boot.Value).TotalDays + " дн.",
                new[] { "Последняя загрузка: " + boot.Value.ToString("dd.MM.yyyy HH:mm") + ". Обновления, которым нужна перезагрузка, не применены." });
        var reasons = new List<string>();
        using var lm = Reg.Lm();
        if (Reg.KeyExists(lm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"))
            reasons.Add("обслуживание компонентов Windows (CBS)");
        if (Reg.KeyExists(lm, @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"))
            reasons.Add("Windows Update");
        var rename = Reg.Value(lm, @"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations") as string[];
        var renameOnly = reasons.Count == 0 && rename != null && rename.Length > 0;
        if (rename != null && rename.Length > 0)
            reasons.Add("отложенная замена файлов (PendingFileRenameOperations, " + rename.Length / 2 + " шт.)");
        if (reasons.Count > 0)
            f.Add(renameOnly ? "info" : "warning", "Система", "Ожидается перезагрузка", reasons);
        return "";
    }

    static string CheckShutdowns(Findings f, int days)
    {
        var events = Ev.Read("System", Ev.XPath(null, days * 24, new[] { 41, 6008, 1001, 1074 }, null), 300,
            e => new { e.Id, Provider = e.ProviderName ?? "", Time = e.TimeCreated ?? DateTime.MinValue, Message = Ev.Message(e, 400) });
        var crashes = events.Where(e => (e.Id == 41 && e.Provider.EndsWith("Kernel-Power")) || (e.Id == 6008 && e.Provider == "EventLog")).ToList();
        var bsod = events.Where(e => e.Id == 1001 && e.Provider.IndexOf("WER-SystemErrorReporting", StringComparison.OrdinalIgnoreCase) >= 0).ToList();
        var planned = events.Where(e => e.Id == 1074 && e.Provider.Equals("User32", StringComparison.OrdinalIgnoreCase)).ToList();
        if (crashes.Count > 0)
            f.Add("critical", "Сбои", "Аварийные выключения или зависания: " + crashes.Count + " за " + days + " дн.",
                crashes.Take(8).Select(e => e.Time.ToString("dd.MM.yyyy HH:mm") + " " + (e.Id == 41
                    ? "Kernel-Power 41: перезагрузка без корректного завершения (питание, зависание, BSOD)"
                    : "EventLog 6008: " + Txt.Clip(e.Message, 160))));
        if (bsod.Count > 0)
            f.Add("critical", "Сбои", "Синий экран (BSOD): " + bsod.Count + " за " + days + " дн.",
                bsod.Take(5).Select(e => e.Time.ToString("dd.MM.yyyy HH:mm") + " " + Txt.Clip(e.Message, 300)));
        if (planned.Count > 0)
            f.Add("info", "Сбои", "Плановые выключения и перезагрузки: " + planned.Count + " за " + days + " дн.",
                planned.Take(5).Select(e => e.Time.ToString("dd.MM.yyyy HH:mm") + " " + Txt.Clip(e.Message, 220)));
        return "";
    }

    static string CheckDiskSpace(Findings f)
    {
        foreach (var disk in Wmi.Query("SELECT DeviceID, VolumeName, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=3"))
        {
            var size = (double)Wmi.ULong(disk, "Size");
            var free = (double)Wmi.ULong(disk, "FreeSpace");
            if (size <= 0)
                continue;
            var percent = 100 * free / size;
            var freeGb = free / 1073741824.0;
            var text = string.Format(CultureInfo.InvariantCulture, "Диск {0} свободно {1} ГБ из {2} ГБ ({3}%)",
                Wmi.Str(disk, "DeviceID"), Txt.Gb(free), Txt.Gb(size), Txt.Round(percent));
            if (percent < 3 || freeGb < 2)
                f.Add("critical", "Диски", "Почти нет места: " + text);
            else if ((percent < 10 && freeGb < 50) || freeGb < 5)
                f.Add("warning", "Диски", "Мало места: " + text);
        }
        return "";
    }

    static readonly Regex storageProvider = new Regex(
        @"^(disk|Ntfs|Microsoft-Windows-Ntfs|volmgr|stor|iaStor|nvme|LSI|megasas|percsas|HpCISSs|arcsas|mpio|msdsm|Microsoft-Windows-StorPort|vhdmp|Microsoft-Windows-Disk|ReFS)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static List<JObj> DiskErrorGroups(int days)
    {
        var ids = new[] { 7, 11, 15, 50, 51, 52, 55, 57, 98, 129, 140, 153, 154, 157 };
        var events = Ev.Read("System", Ev.XPath(new[] { 1, 2, 3 }, days * 24, ids, null), 2000,
            e => new { e.Id, Provider = e.ProviderName ?? "", Time = e.TimeCreated ?? DateTime.MinValue })
            .Where(e => storageProvider.IsMatch(e.Provider)).ToList();
        // 10.11.2026 Текст берем у первой (самой новой) записи группы – сами записи уже освобождены, поэтому
        // перечитываем одну запись группы по провайдеру и коду.
        return events.GroupBy(e => e.Provider + "|" + e.Id).Select(g =>
        {
            var first = g.First();
            var message = "";
            try
            {
                message = Ev.Read("System", Ev.XPath(null, days * 24, new[] { first.Id }, new[] { first.Provider }), 1,
                    r => Ev.Message(r, 300)).FirstOrDefault() ?? "";
            }
            catch (Exception)
            {
            }
            return new JObj
            {
                { "provider", first.Provider }, { "id", first.Id }, { "count", g.Count() }, { "last", first.Time },
                { "message", message },
            };
        }).ToList();
    }

    static string CheckDiskErrors(Findings f, int days)
    {
        foreach (var group in DiskErrorGroups(days))
        {
            var id = (int)(group.Num("id") ?? 0);
            var provider = group.Str("provider");
            var level = id == 7 || id == 11 || id == 55 || id == 98 ? "critical" : id == 157 ? "info" : "warning";
            f.Add(level, "Диски", provider + " " + id + ": " + group.Str("count") + " раз за " + days + " дн.",
                new[] { "Последний раз: " + ((DateTime)group["last"]).ToString("dd.MM.yyyy HH:mm"), group.Str("message") });
        }
        return "";
    }

    static string CheckSmart(Findings f)
    {
        var note = "";
        try
        {
            foreach (var item in Wmi.Query("SELECT InstanceName, PredictFailure, Reason FROM MSStorageDriver_FailurePredictStatus", @"root\wmi"))
                if (Wmi.Bool(item, "PredictFailure"))
                    f.Add("critical", "Диски", "SMART предсказывает отказ диска", new[] { Wmi.Str(item, "InstanceName"), "Код причины: " + Wmi.Str(item, "Reason") });
        }
        catch (UnauthorizedAccessException)
        {
            note = "SMART не проверен: нужны права администратора";
        }
        catch (Exception ex) when (Wmi.IsMissing(ex) || ex is ManagementException)
        {
        }
        try
        {
            foreach (var disk in Wmi.Query("SELECT FriendlyName, HealthStatus, OperationalStatus, MediaType, BusType, Size FROM MSFT_PhysicalDisk",
                         @"root\Microsoft\Windows\Storage"))
            {
                var health = Wmi.Long(disk, "HealthStatus") ?? 0;
                if (health == 0 || health == 5)
                    continue;
                f.Add(health == 2 ? "critical" : "warning", "Диски",
                    "Физический диск «" + Wmi.Str(disk, "FriendlyName") + "»: состояние " + (health == 1 ? "Warning" : "Unhealthy"),
                    new[] { "Размер " + Txt.Gb(Wmi.ULong(disk, "Size")) + " ГБ, OperationalStatus " + Wmi.Str(disk, "OperationalStatus") });
            }
        }
        catch (Exception ex) when (Wmi.IsMissing(ex) || ex is ManagementException || ex is UnauthorizedAccessException)
        {
        }
        return note;
    }

    static string CheckMemory(Findings f, int days)
    {
        var os = Wmi.Query("SELECT TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory FROM Win32_OperatingSystem").First();
        var total = (double)Wmi.ULong(os, "TotalVisibleMemorySize");
        var free = (double)Wmi.ULong(os, "FreePhysicalMemory");
        var commitTotal = (double)Wmi.ULong(os, "TotalVirtualMemorySize");
        var commitFree = (double)Wmi.ULong(os, "FreeVirtualMemory");
        var freePercent = total > 0 ? 100 * free / total : 100;
        var commitPercent = commitTotal > 0 ? 100 * (commitTotal - commitFree) / commitTotal : 0;
        var top = TopMemory(5);
        if (freePercent < 5)
            f.Add("critical", "Память", "Свободно " + Txt.Round(freePercent) + "% оперативной памяти (" + Txt.Gb(free * 1024) + " из " + Txt.Gb(total * 1024) + " ГБ)", top);
        else if (freePercent < 10)
            f.Add("warning", "Память", "Свободно " + Txt.Round(freePercent) + "% оперативной памяти (" + Txt.Gb(free * 1024) + " из " + Txt.Gb(total * 1024) + " ГБ)", top);
        if (commitPercent > 97)
            f.Add("critical", "Память", "Выделенная память (commit) занята на " + Txt.Round(commitPercent) + "%: программы получат отказ в памяти", top);
        else if (commitPercent > 90)
            f.Add("warning", "Память", "Выделенная память (commit) занята на " + Txt.Round(commitPercent) + "%", top);
        var exhaustion = Ev.Read("System", Ev.XPath(null, days * 24, new[] { 2004 }, new[] { "Microsoft-Windows-Resource-Exhaustion-Detector" }), 50,
            e => new { Time = e.TimeCreated ?? DateTime.MinValue, Message = Ev.Message(e, 500) });
        if (exhaustion.Count > 0)
            f.Add("warning", "Память", "Нехватка виртуальной памяти (событие 2004): " + exhaustion.Count + " раз за " + days + " дн.",
                new[] { "Последний раз " + exhaustion[0].Time.ToString("dd.MM.yyyy HH:mm") + ": " + exhaustion[0].Message });
        foreach (var page in Wmi.Query("SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage"))
        {
            var allocated = (double)Wmi.ULong(page, "AllocatedBaseSize");
            var used = (double)Wmi.ULong(page, "CurrentUsage");
            if (allocated > 0 && used / allocated > 0.8)
                f.Add("warning", "Память", "Файл подкачки " + Wmi.Str(page, "Name") + " занят на " + Txt.Round(100 * used / allocated) + "% (" + used + " из " + allocated + " МБ)");
        }
        return "";
    }

    public static List<string> TopMemory(int count)
    {
        var list = new List<KeyValuePair<string, long>>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                list.Add(new KeyValuePair<string, long>(process.ProcessName + " (PID " + process.Id + ")", process.WorkingSet64));
            }
            catch (Exception)
            {
            }
            finally
            {
                process.Dispose();
            }
        }
        return list.OrderByDescending(x => x.Value).Take(count)
            .Select(x => x.Key + ": " + Txt.Mb(x.Value) + " МБ").ToList();
    }

    static string CheckCpu(Findings f, DiagContext context)
    {
        var sample = CpuSampler.Measure(2000, context);
        var top = sample.ByPid.OrderByDescending(x => x.Value).Take(5)
            .Select(x => (sample.Names.TryGetValue(x.Key, out var n) ? n : "?") + " (PID " + x.Key + "): " + Txt.Num(x.Value) + "%").ToList();
        if (sample.Total >= 90)
            f.Add("warning", "Процессор", "Процессор загружен на " + Txt.Num(sample.Total) + "% (замер 2 с)", top);
        var system = Wmi.Query("SELECT ProcessorQueueLength FROM Win32_PerfFormattedData_PerfOS_System").FirstOrDefault();
        var queue = Wmi.Long(system, "ProcessorQueueLength") ?? 0;
        if (queue > 2 * Environment.ProcessorCount)
            f.Add("warning", "Процессор", "Очередь к процессору " + queue + " при " + Environment.ProcessorCount + " логических процессорах", top);
        return "";
    }

    static string CheckServices(Findings f)
    {
        var quiet = new List<string>();
        using var lm = Reg.Lm();
        foreach (var service in Wmi.Query("SELECT Name, DisplayName, State, StartMode, ExitCode, ServiceSpecificExitCode, PathName FROM Win32_Service WHERE StartMode='Auto' AND State<>'Running'"))
        {
            var name = Wmi.Str(service, "Name");
            var display = Wmi.Str(service, "DisplayName");
            var exit = Wmi.Long(service, "ExitCode") ?? 0;
            var key = @"SYSTEM\CurrentControlSet\Services\" + name;
            var trigger = Reg.KeyExists(lm, key + @"\TriggerInfo");
            var delayed = Convert.ToInt32(Reg.Value(lm, key, "DelayedAutostart") ?? 0) == 1;
            var important = ImportantService.IsMatch(name + " " + display + " " + Wmi.Str(service, "PathName")) || criticalServices.Contains(name);
            var text = "«" + display + "» (" + name + "): " + Wmi.Str(service, "State") + ", код выхода " + exit
                       + (exit == 1066 ? ", код службы " + Wmi.Str(service, "ServiceSpecificExitCode") : "");
            // 10.11.2026 Служба с запуском по триггеру штатно останавливается без ошибки (например, gpsvc в Windows 10).
            if (trigger && (exit == 0 || exit == 1077))
                continue;
            if (important)
                f.Add("critical", "Службы", "Не работает служба " + text);
            else if (trigger)
                continue;
            else if (exit != 0 && exit != 1077)
                f.Add("warning", "Службы", "Автозапускаемая служба остановлена с ошибкой: " + text);
            else if (!delayed)
                quiet.Add(display + " (" + name + ")");
        }
        if (quiet.Count > 0)
            f.Add("info", "Службы", "Автозапускаемые службы не работают, ошибок нет: " + quiet.Count, quiet.Take(20));
        foreach (var service in Wmi.Query("SELECT Name, DisplayName, State FROM Win32_Service WHERE State='Start Pending' OR State='Stop Pending'"))
            f.Add("warning", "Службы", "Служба зависла в состоянии " + Wmi.Str(service, "State") + ": «" + Wmi.Str(service, "DisplayName") + "» (" + Wmi.Str(service, "Name") + ")");
        return "";
    }

    static string CheckServiceCrashes(Findings f, int hours)
    {
        var ids = new[] { 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7031, 7034, 7038, 7043 };
        var events = Ev.Read("System", Ev.XPath(null, hours, ids, new[] { "Service Control Manager" }), 1000,
            e => new { e.Id, Service = Ev.Prop(e, 0), Time = e.TimeCreated ?? DateTime.MinValue, Message = Ev.Message(e, 300) });
        foreach (var group in events.GroupBy(e => e.Service + "|" + Kind(e.Id)))
        {
            var first = group.First();
            var level = ImportantService.IsMatch(first.Service) ? "critical" : "warning";
            f.Add(level, "Службы", "«" + first.Service + "» " + Kind(first.Id) + ": " + group.Count() + " раз за " + hours + " ч",
                new[] { "Последний раз " + first.Time.ToString("dd.MM.yyyy HH:mm") + ": " + first.Message });
        }
        return "";
    }

    static string Kind(int id)
    {
        switch (id)
        {
            case 7031:
            case 7034: return "аварийно завершалась";
            case 7023:
            case 7024: return "завершалась с ошибкой";
            case 7026: return "драйверы не загрузились";
            case 7001: return "не запускалась из-за зависимостей";
            default: return "не запускалась";
        }
    }

    static readonly Regex dotNetApp = new Regex(@"(?:Application|Приложение):\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    static string CheckAppCrashes(Findings f, int hours)
    {
        var events = Ev.Read("Application", Ev.XPath(null, hours, new[] { 1000, 1002, 1026 }, new[] { "Application Error", "Application Hang", ".NET Runtime" }), 500,
            e =>
            {
                var message = Ev.Message(e, 400);
                var app = e.Id == 1026 ? dotNetApp.Match(message).Groups[1].Value : Ev.Prop(e, 0);
                return new
                {
                    e.Id,
                    App = string.IsNullOrEmpty(app) ? "?" : app,
                    Module = e.Id == 1000 ? Ev.Prop(e, 3) : "",
                    Code = e.Id == 1000 ? Ev.Prop(e, 6) : "",
                    Time = e.TimeCreated ?? DateTime.MinValue,
                    Message = message,
                };
            });
        foreach (var group in events.GroupBy(e => e.App.ToLowerInvariant()))
        {
            var first = group.First();
            var crashes = group.Count(e => e.Id != 1002);
            var hangs = group.Count(e => e.Id == 1002);
            var level = oneCProcess.IsMatch(first.App) ? "critical" : "warning";
            var parts = new List<string>();
            if (crashes > 0)
                parts.Add("падений " + crashes);
            if (hangs > 0)
                parts.Add("зависаний " + hangs);
            var details = new List<string> { "Последний раз " + first.Time.ToString("dd.MM.yyyy HH:mm") };
            var crash = group.FirstOrDefault(e => e.Id == 1000);
            if (crash != null)
                details.Add("Модуль: " + crash.Module + ", код исключения: " + crash.Code);
            else
                details.Add(Txt.Clip(first.Message, 300));
            f.Add(level, "Программы", first.App + ": " + string.Join(", ", parts) + " за " + hours + " ч", details);
        }
        return "";
    }

    static string CheckLogErrors(Findings f, int hours, DiagContext context)
    {
        var groups = new Dictionary<string, JObj>();
        var totals = new Dictionary<string, int>();
        foreach (var log in new[] { "System", "Application" })
        {
            var list = Ev.Read(log, Ev.XPath(new[] { 1, 2 }, hours, null, null), 3000, e =>
            {
                var key = log + "|" + e.ProviderName + "|" + e.Id;
                if (!groups.TryGetValue(key, out var group))
                {
                    group = new JObj
                    {
                        { "log", log }, { "provider", e.ProviderName }, { "id", e.Id }, { "count", 0 },
                        { "message", Ev.Message(e, 140) },
                    };
                    groups[key] = group;
                }
                group["count"] = (int)group["count"] + 1;
                return 0;
            }, context);
            totals[log] = list.Count;
        }
        if (totals.Values.Sum() == 0)
            return "";
        var top = groups.Values.OrderByDescending(g => (int)g["count"]).Take(12)
            .Select(g => g.Str("count") + " × " + g.Str("log") + " / " + g.Str("provider") + " " + g.Str("id") + ": " + g.Str("message"));
        f.Add("info", "Журналы", "Ошибок и критических событий за " + hours + " ч: System " + totals["System"] + ", Application " + totals["Application"]
                                 + (totals.Values.Any(v => v >= 3000) ? " (подсчет остановлен на 3000)" : ""), top);
        return "";
    }

    static string CheckDevices(Findings f)
    {
        var broken = new List<string>();
        var disabled = new List<string>();
        foreach (var device in Wmi.Query("SELECT Name, ConfigManagerErrorCode, DeviceID FROM Win32_PnPEntity WHERE ConfigManagerErrorCode<>0"))
        {
            var code = Wmi.Long(device, "ConfigManagerErrorCode") ?? 0;
            var name = Wmi.Str(device, "Name");
            if (name == "")
                name = Wmi.Str(device, "DeviceID");
            if (code == 45)
                continue;
            if (code == 22)
                disabled.Add(name);
            else
                broken.Add(name + " – код " + code + DeviceCode(code));
        }
        if (broken.Count > 0)
            f.Add("warning", "Устройства", "Устройства с ошибками: " + broken.Count, broken.Take(15));
        if (disabled.Count > 0)
            f.Add("info", "Устройства", "Отключенные устройства: " + disabled.Count, disabled.Take(10));
        return "";
    }

    static string DeviceCode(long code)
    {
        switch (code)
        {
            case 1: return " (не настроено)";
            case 3: return " (драйвер поврежден или не хватает памяти)";
            case 10: return " (не запускается)";
            case 12: return " (не хватает ресурсов)";
            case 18:
            case 28: return " (драйвер не установлен)";
            case 19: return " (повреждены сведения в реестре)";
            case 24: return " (устройство отсутствует или работает неправильно)";
            case 31: return " (драйвер не загружается)";
            case 39: return " (драйвер поврежден или отсутствует)";
            case 43: return " (устройство сообщило о сбое)";
            case 52: return " (нет цифровой подписи драйвера)";
            default: return "";
        }
    }

    static string CheckUpdates(Findings f, int days)
    {
        var failed = Ev.Read("System", Ev.XPath(null, days * 24, new[] { 20 }, new[] { "Microsoft-Windows-WindowsUpdateClient" }), 100,
            e => new { Time = e.TimeCreated ?? DateTime.MinValue, Message = Ev.Message(e, 300) });
        if (failed.Count > 0)
            f.Add("warning", "Обновления", "Обновления Windows не установились: " + failed.Count + " раз за " + days + " дн.",
                failed.Select(e => e.Message).Distinct().Take(6));
        DateTime? last = null;
        var lastId = "";
        foreach (var fix in Wmi.Query("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering"))
        {
            var installed = ParseHotfixDate(Wmi.Str(fix, "InstalledOn"));
            if (installed.HasValue && (!last.HasValue || installed > last))
            {
                last = installed;
                lastId = Wmi.Str(fix, "HotFixID");
            }
        }
        if (last.HasValue && (DateTime.Now - last.Value).TotalDays > 90)
            f.Add("info", "Обновления", "Обновления не устанавливались " + (int)(DateTime.Now - last.Value).TotalDays + " дн.",
                new[] { "Последнее: " + lastId + " от " + last.Value.ToString("dd.MM.yyyy") });
        return "";
    }

    public static DateTime? ParseHotfixDate(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        var formats = new[] { "M/d/yyyy", "MM/dd/yyyy", "yyyyMMdd", "d.M.yyyy", "dd.MM.yyyy" };
        if (DateTime.TryParseExact(text.Trim(), formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
            return value;
        // 10.11.2026 В старых Windows дата хранится шестнадцатеричным FILETIME.
        if (long.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var fileTime) && fileTime > 0)
        {
            try
            {
                return DateTime.FromFileTime(fileTime);
            }
            catch (Exception)
            {
            }
        }
        return null;
    }

    static string CheckAntivirus(Findings f, int days)
    {
        try
        {
            var events = Ev.Read("Microsoft-Windows-Windows Defender/Operational",
                Ev.XPath(null, days * 24, new[] { 1006, 1116, 1117, 1118, 1119, 5001, 5010, 5012 }, null), 200,
                e => new { e.Id, Time = e.TimeCreated ?? DateTime.MinValue, Message = Ev.Message(e, 300) });
            var threats = events.Where(e => e.Id == 1006 || e.Id == 1116).ToList();
            if (threats.Count > 0)
                f.Add("warning", "Антивирус", "Защитник Windows обнаружил угрозы: " + threats.Count + " за " + days + " дн.",
                    threats.Take(5).Select(e => e.Time.ToString("dd.MM.yyyy HH:mm") + " " + e.Message));
            var off = events.Where(e => e.Id >= 5001).ToList();
            if (off.Count > 0)
                f.Add("warning", "Антивирус", "Защита Защитника Windows отключалась: " + off.Count + " раз за " + days + " дн.",
                    off.Take(3).Select(e => e.Time.ToString("dd.MM.yyyy HH:mm") + " " + e.Message));
        }
        catch (LogMissingException)
        {
        }
        try
        {
            var products = Wmi.Query("SELECT displayName, productState FROM AntiVirusProduct", @"root\SecurityCenter2");
            if (products.Count > 0)
            {
                var enabled = products.Where(p => ((Wmi.Long(p, "productState") ?? 0) >> 12 & 0xF) == 1).ToList();
                if (enabled.Count == 0)
                    f.Add("warning", "Антивирус", "Ни один антивирус не включен",
                        products.Select(p => Wmi.Str(p, "displayName") + ": productState " + Txt.Hex(Wmi.Long(p, "productState") ?? 0)));
                foreach (var product in enabled.Where(p => ((Wmi.Long(p, "productState") ?? 0) >> 4 & 0xF) != 0))
                    f.Add("warning", "Антивирус", "Антивирус «" + Wmi.Str(product, "displayName") + "»: базы устарели");
            }
        }
        catch (Exception ex) when (Wmi.IsMissing(ex) || ex is ManagementException)
        {
            // 10.11.2026 На серверных Windows центра безопасности нет.
        }
        return "";
    }

    static string CheckNetworkEvents(Findings f, int hours)
    {
        var providers = new[] { "NETLOGON", "Microsoft-Windows-Time-Service", "Microsoft-Windows-GroupPolicy", "Microsoft-Windows-DNS-Client", "Tcpip" };
        var ids = new[] { 5719, 5722, 5723, 5805, 3210, 129, 134, 36, 24, 1129, 1053, 1055, 1058, 1030, 1014, 4227, 4231 };
        var events = Ev.Read("System", Ev.XPath(new[] { 1, 2, 3 }, hours, ids, providers), 1000,
            e => new { e.Id, Provider = e.ProviderName ?? "", Time = e.TimeCreated ?? DateTime.MinValue, Message = Ev.Message(e, 300) });
        foreach (var group in events.GroupBy(e => e.Provider + "|" + e.Id))
        {
            var first = group.First();
            string title;
            var level = "warning";
            switch (first.Provider)
            {
                case "NETLOGON": title = "Связь с контроллером домена"; break;
                case "Microsoft-Windows-Time-Service": title = "Синхронизация времени"; break;
                case "Microsoft-Windows-GroupPolicy": title = "Групповые политики не применяются"; break;
                case "Microsoft-Windows-DNS-Client": title = "Таймауты разрешения имен DNS"; break;
                default:
                    title = "Исчерпание портов TCP";
                    level = "critical";
                    break;
            }
            f.Add(level, "Сеть", title + " (" + first.Provider + " " + first.Id + "): " + group.Count() + " раз за " + hours + " ч",
                new[] { "Последний раз " + first.Time.ToString("dd.MM.yyyy HH:mm") + ": " + first.Message });
        }
        return "";
    }

    static string CheckTcp(Findings f)
    {
        var rows = TcpTable.Read();
        var range = TcpTable.DynamicRange();
        var dynamicUsed = rows.Count(r => r.State != "LISTEN" && r.LocalPort >= range[0] && r.LocalPort < range[0] + range[1]);
        var timeWait = rows.Count(r => r.State == "TIME_WAIT");
        var usage = range[1] > 0 ? 100.0 * dynamicUsed / range[1] : 0;
        if (usage > 70 || timeWait > 10000)
        {
            var names = TcpTable.ProcessNames();
            var top = rows.Where(r => r.State != "LISTEN").GroupBy(r => r.Pid).OrderByDescending(g => g.Count()).Take(5)
                .Select(g => (names.TryGetValue(g.Key, out var n) ? n : "?") + " (PID " + g.Key + "): " + g.Count() + " соединений");
            f.Add(usage > 85 ? "critical" : "warning", "Сеть",
                "Занято " + Txt.Round(usage) + "% динамических портов TCP (" + dynamicUsed + " из " + range[1] + "), TIME_WAIT: " + timeWait, top);
        }
        return "";
    }

    static string CheckRds(Findings f)
    {
        List<ManagementBaseObject> settings;
        try
        {
            settings = Wmi.Query("SELECT * FROM Win32_TerminalServiceSetting", @"root\cimv2\TerminalServices");
        }
        catch (Exception ex) when (Wmi.IsMissing(ex) || ex is ManagementException)
        {
            return "";
        }
        var setting = settings.FirstOrDefault();
        if (setting == null || (Wmi.Long(setting, "TerminalServerMode") ?? 0) != 1)
            return "не сервер терминалов";
        var details = new List<string> { "Лицензирование: " + Wmi.Str(setting, "LicensingName") + " (LicensingType " + Wmi.Str(setting, "LicensingType") + ")" };
        var level = "info";
        try
        {
            if (setting is ManagementObject managed)
            {
                var servers = managed.InvokeMethod("GetSpecifiedLicenseServerList", null, null);
                var list = servers?["SpecifiedLSList"] as string[];
                details.Add("Серверы лицензирования: " + (list != null && list.Length > 0 ? string.Join(", ", list) : "не указаны"));
                if (list == null || list.Length == 0)
                    level = "warning";
                var grace = managed.InvokeMethod("GetGracePeriodDays", null, null);
                if (grace != null)
                    details.Add("Льготный период: осталось " + Convert.ToString(grace["DaysLeft"], CultureInfo.InvariantCulture) + " дн.");
            }
        }
        catch (Exception ex)
        {
            details.Add("Подробности лицензирования не получены: " + ex.Message);
        }
        f.Add(level, "RDS", level == "warning" ? "Сервер терминалов: не указан сервер лицензирования" : "Сервер терминалов", details);
        return "";
    }
}
