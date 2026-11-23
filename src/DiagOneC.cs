using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace RdpDiagBridge;

// 10.11.2026 1С на компьютере: платформы, службы и их порты, процессы rphost/rmngr, каталог кластера srvinfo,
// техжурнал (logcfg.xml), дампы, лицензии, список баз пользователя, события 1С в журнале Application.
public static class OneCDiag
{
    static readonly string[] processNames = { "ragent", "rmngr", "rphost", "ras", "ibsrv", "crserver", "1cv8", "1cv8c", "1cv8s", "1cestart", "hasplms" };
    static readonly Regex argPort = new Regex(@"-port\s+(\d+)", RegexOptions.IgnoreCase);
    static readonly Regex argRegPort = new Regex(@"-regport\s+(\d+)", RegexOptions.IgnoreCase);
    static readonly Regex argRange = new Regex(@"-range\s+([\d:,\-]+)", RegexOptions.IgnoreCase);
    static readonly Regex argDir = new Regex(@"-d\s+""([^""]+)""|-d\s+(\S+)", RegexOptions.IgnoreCase);

    public static JObj Run(Params p, DiagContext context)
    {
        var hours = p.Int("hours", 24, 1, 720);
        var budget = p.Int("budgetSec", 20, 0, 200);
        var watch = Stopwatch.StartNew();
        var result = new JObj();
        context.Progress = "платформы";
        result["platforms"] = Platforms();
        context.Progress = "службы";
        var services = Services();
        result["services"] = services;
        context.Progress = "процессы";
        result["processes"] = Processes(context);
        context.Progress = "порты";
        result["listening"] = Listening();
        context.Progress = "srvinfo";
        var srvinfoDirs = services.Select(s => s.Str("clusterDir")).Where(d => d != "").ToList();
        foreach (var programFiles in ProgramFilesDirs())
            srvinfoDirs.Add(Path.Combine(programFiles, @"1cv8\srvinfo"));
        result["srvinfo"] = srvinfoDirs.Distinct(StringComparer.OrdinalIgnoreCase).Where(Directory.Exists)
            .Select(d => Srvinfo(d, watch, budget, context)).ToList();
        context.Progress = "техжурнал";
        result["techLog"] = TechLog(watch, budget, context);
        context.Progress = "дампы";
        result["dumps"] = Dumps();
        context.Progress = "лицензии";
        var licenses = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"1C\licenses");
        result["licenses"] = Directory.Exists(licenses)
            ? new DirectoryInfo(licenses).GetFiles("*.lic").Select(f => f.Name + " (" + f.LastWriteTime.ToString("dd.MM.yyyy") + ")").ToList()
            : new List<string>();
        context.Progress = "список баз";
        result["infobases"] = Infobases();
        result["startConfig"] = StartConfig();
        context.Progress = "события 1С";
        try
        {
            result["events"] = Events(hours, context);
        }
        catch (Exception ex)
        {
            result["events"] = "не прочитаны: " + ex.Message;
        }
        context.Progress = "";
        return result;
    }

    static IEnumerable<string> ProgramFilesDirs()
    {
        var list = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) };
        var x86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrEmpty(x86) && !list.Contains(x86, StringComparer.OrdinalIgnoreCase))
            list.Add(x86);
        return list.Where(d => !string.IsNullOrEmpty(d));
    }

    static List<JObj> Platforms()
    {
        var list = new List<JObj>();
        foreach (var programFiles in ProgramFilesDirs())
        foreach (var folder in new[] { "1cv8", "1cv82" })
        {
            var root = Path.Combine(programFiles, folder);
            if (!Directory.Exists(root))
                continue;
            foreach (var dir in Directory.GetDirectories(root))
            {
                var version = Path.GetFileName(dir);
                if (!Regex.IsMatch(version, @"^\d+\.\d+\.\d+\.\d+$"))
                    continue;
                var bin = Path.Combine(dir, "bin");
                var parts = new[] { "1cv8.exe", "1cv8c.exe", "ragent.exe", "ras.exe", "ibsrv.exe", "crserver.exe", "ibcmd.exe" }
                    .Where(f => File.Exists(Path.Combine(bin, f))).ToList();
                list.Add(new JObj
                {
                    { "version", version },
                    { "path", dir },
                    { "components", parts },
                    { "logcfg", File.Exists(Path.Combine(bin, @"conf\logcfg.xml")) },
                });
            }
        }
        return list.OrderBy(x => new Version(x.Str("version"))).ToList();
    }

    static List<JObj> Services()
    {
        const string wql = "SELECT Name, DisplayName, State, StartMode, StartName, ProcessId, PathName FROM Win32_Service WHERE "
                           + "PathName LIKE '%ragent%' OR PathName LIKE '%ras.exe%' OR PathName LIKE '%crserver%' OR PathName LIKE '%ibsrv%' "
                           + "OR PathName LIKE '%hasplms%' OR PathName LIKE '%1cv8%' OR Name LIKE '%1C%' OR Name LIKE 'postgresql%' "
                           + "OR Name LIKE 'MSSQL%' OR Name LIKE 'Apache%' OR Name = 'W3SVC'";
        return Wmi.Query(wql).Select(s =>
        {
            var path = Wmi.Str(s, "PathName");
            var dir = argDir.Match(path);
            return new JObj
            {
                { "name", Wmi.Str(s, "Name") },
                { "display", Wmi.Str(s, "DisplayName") },
                { "state", Wmi.Str(s, "State") },
                { "start", Wmi.Str(s, "StartMode") },
                { "account", Wmi.Str(s, "StartName") },
                { "pid", Wmi.Long(s, "ProcessId") },
                { "port", argPort.Match(path).Groups[1].Value },
                { "regport", argRegPort.Match(path).Groups[1].Value },
                { "range", argRange.Match(path).Groups[1].Value },
                { "clusterDir", dir.Success ? (dir.Groups[1].Value != "" ? dir.Groups[1].Value : dir.Groups[2].Value) : "" },
                { "path", Txt.Clip(path, 400) },
            };
        }).ToList();
    }

    static JObj Processes(DiagContext context)
    {
        var cpu = CpuSampler.Measure(1000, context);
        var groups = new List<JObj>();
        var hosts = new List<JObj>();
        foreach (var name in processNames)
        {
            var list = Process.GetProcessesByName(name);
            if (list.Length == 0)
                continue;
            long total = 0;
            long max = 0;
            double cpuTotal = 0;
            foreach (var process in list)
            {
                using (process)
                {
                    long ws = 0;
                    try
                    {
                        ws = process.WorkingSet64;
                    }
                    catch (Exception)
                    {
                    }
                    total += ws;
                    max = Math.Max(max, ws);
                    var processCpu = cpu.ByPid.TryGetValue(process.Id, out var c) ? c : 0;
                    cpuTotal += processCpu;
                    if (name == "rphost" || name == "rmngr" || name == "ragent")
                    {
                        long privateBytes = 0;
                        long handles = 0;
                        DateTime? started = null;
                        try
                        {
                            privateBytes = process.PrivateMemorySize64;
                            handles = process.HandleCount;
                            started = process.StartTime;
                        }
                        catch (Exception)
                        {
                        }
                        hosts.Add(new JObj
                        {
                            { "name", name }, { "pid", process.Id }, { "cpu", processCpu }, { "wsMb", Txt.Mb(ws) },
                            { "privateMb", Txt.Mb(privateBytes) }, { "handles", handles }, { "started", started },
                        });
                    }
                }
            }
            groups.Add(new JObj
            {
                { "name", name }, { "count", list.Length }, { "wsTotalMb", Txt.Mb(total) }, { "wsMaxMb", Txt.Mb(max) },
                { "cpu", Txt.Round(cpuTotal) },
            });
        }
        if (hosts.Count > 0)
        {
            var byPid = hosts.ToDictionary(h => (int)(h.Num("pid") ?? 0));
            var where = string.Join(" OR ", byPid.Keys.Take(60).Select(pid => "ProcessId=" + pid));
            try
            {
                foreach (var item in Wmi.Query("SELECT ProcessId, CommandLine FROM Win32_Process WHERE " + where))
                    if (byPid.TryGetValue((int)(Wmi.Long(item, "ProcessId") ?? 0), out var host))
                        host["commandLine"] = Txt.Clip(Wmi.Str(item, "CommandLine"), 300);
            }
            catch (Exception)
            {
            }
        }
        return new JObj
        {
            { "summary", groups },
            { "serverProcesses", hosts.OrderByDescending(h => h.Num("wsMb") ?? 0).ToList() },
        };
    }

    static List<JObj> Listening()
    {
        var names = TcpTable.ProcessNames();
        var oneC = new HashSet<string>(new[] { "ragent", "rmngr", "rphost", "ras", "ibsrv", "crserver", "hasplms", "postgres", "sqlservr", "httpd", "nginx" },
            StringComparer.OrdinalIgnoreCase);
        return TcpTable.Read().Where(r => r.State == "LISTEN" && names.TryGetValue(r.Pid, out var n) && oneC.Contains(n))
            .GroupBy(r => r.LocalPort + "|" + r.Pid)
            .Select(g => new JObj { { "port", g.First().LocalPort }, { "process", names[g.First().Pid] }, { "pid", g.First().Pid } })
            .OrderBy(x => (int)(x.Num("port") ?? 0)).ToList();
    }

    static JObj Srvinfo(string dir, Stopwatch watch, int budget, DiagContext context)
    {
        var result = new JObj { { "path", dir } };
        var clusters = new List<JObj>();
        foreach (var reg in Directory.GetDirectories(dir, "reg_*"))
        {
            var cluster = new JObj { { "folder", Path.GetFileName(reg) } };
            var lst = new FileInfo(Path.Combine(reg, "1CV8Clst.lst"));
            if (lst.Exists)
                cluster["clusterList"] = Txt.Round(lst.Length / 1024.0) + " КБ, " + lst.LastWriteTime.ToString("dd.MM.yyyy HH:mm");
            var infobases = Directory.GetDirectories(reg).Where(d => Regex.IsMatch(Path.GetFileName(d), "^[0-9a-f-]{36}$")).ToList();
            cluster["infobaseDirs"] = infobases.Count;
            var snccntx = Directory.GetDirectories(reg, "snccntx*", SearchOption.TopDirectoryOnly).ToList();
            cluster["snccntxDirs"] = snccntx.Count;
            if (budget > 0)
            {
                var size = FilesDiag.FolderSize(reg, watch, budget, context);
                cluster["sizeGb"] = Txt.Round(size.Bytes / 1073741824.0, 2);
                cluster["files"] = size.Files;
                cluster["sizeComplete"] = size.Complete;
                // 10.11.2026 Самые большие папки баз: сеансовые данные и кэши разрастаются при сбоях.
                cluster["largestInfobaseDirs"] = infobases.Select(d => new
                    {
                        Dir = d,
                        Size = FilesDiag.FolderSize(d, watch, budget, context),
                    })
                    .OrderByDescending(x => x.Size.Bytes).Take(5)
                    .Select(x => Path.GetFileName(x.Dir) + ": " + Txt.Round(x.Size.Bytes / 1073741824.0, 2) + " ГБ").ToList();
            }
            clusters.Add(cluster);
        }
        result["clusters"] = clusters;
        return result;
    }

    static List<JObj> TechLog(Stopwatch watch, int budget, DiagContext context)
    {
        var candidates = new List<string>();
        foreach (var programFiles in ProgramFilesDirs())
        {
            candidates.Add(Path.Combine(programFiles, @"1cv8\conf\logcfg.xml"));
            var root = Path.Combine(programFiles, "1cv8");
            if (Directory.Exists(root))
                candidates.AddRange(Directory.GetDirectories(root).Select(d => Path.Combine(d, @"bin\conf\logcfg.xml")));
        }
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"1C\1cv8\logcfg.xml"));
        var result = new List<JObj>();
        foreach (var file in candidates.Distinct(StringComparer.OrdinalIgnoreCase).Where(File.Exists))
        {
            var text = File.ReadAllText(file);
            var logs = Regex.Matches(text, @"<log\b[^>]*>", RegexOptions.IgnoreCase).Cast<Match>().Select(m => m.Value).ToList();
            var item = new JObj
            {
                { "file", file },
                { "modified", File.GetLastWriteTime(file) },
                { "dump", Attr(Regex.Match(text, @"<dump\b[^>]*>", RegexOptions.IgnoreCase).Value, "location") },
            };
            var logList = new List<JObj>();
            foreach (var log in logs)
            {
                var location = Attr(log, "location");
                var entry = new JObj { { "location", location }, { "history", Attr(log, "history") } };
                if (location != "" && Directory.Exists(location) && budget > 0)
                {
                    var size = FilesDiag.FolderSize(location, watch, budget, context);
                    entry["sizeGb"] = Txt.Round(size.Bytes / 1073741824.0, 2);
                    entry["files"] = size.Files;
                    entry["sizeComplete"] = size.Complete;
                }
                logList.Add(entry);
            }
            item["logs"] = logList;
            item["events"] = Regex.Matches(text, @"<eq\b[^>]*property\s*=\s*""name""[^>]*value\s*=\s*""([^""]+)""", RegexOptions.IgnoreCase)
                .Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
            result.Add(item);
        }
        return result;
    }

    static string Attr(string tag, string name)
    {
        var match = Regex.Match(tag ?? "", name + @"\s*=\s*""([^""]*)""", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : "";
    }

    static List<JObj> Dumps()
    {
        var dirs = new List<string>
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"1C\1cv8\dumps"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"1C\1cv8\dumps"),
        };
        try
        {
            var users = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            if (users != null)
                foreach (var profile in Directory.GetDirectories(users))
                    dirs.Add(Path.Combine(profile, @"AppData\Local\1C\1cv8\dumps"));
        }
        catch (Exception)
        {
        }
        var since = DateTime.Now.AddDays(-30);
        var result = new List<JObj>();
        foreach (var dir in dirs.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                if (!Directory.Exists(dir))
                    continue;
                var files = new DirectoryInfo(dir).GetFiles("*.*dmp");
                if (files.Length == 0)
                    continue;
                var recent = files.Where(f => f.LastWriteTime >= since).OrderByDescending(f => f.LastWriteTime).ToList();
                result.Add(new JObj
                {
                    { "dir", dir }, { "total", files.Length }, { "last30days", recent.Count },
                    { "latest", recent.Take(5).Select(f => f.Name + " " + f.LastWriteTime.ToString("dd.MM.yyyy HH:mm") + " " + Txt.Mb(f.Length) + " МБ").ToList() },
                });
            }
            catch (Exception)
            {
            }
        }
        return result;
    }

    static List<JObj> Infobases()
    {
        var file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"1C\1CEStart\ibases.v8i");
        var result = new List<JObj>();
        if (!File.Exists(file))
            return result;
        string name = null;
        foreach (var raw in File.ReadAllLines(file))
        {
            var line = raw.Trim().TrimStart('﻿');
            if (line.StartsWith("[") && line.EndsWith("]"))
                name = line.Substring(1, line.Length - 2);
            else if (name != null && line.StartsWith("Connect=", StringComparison.OrdinalIgnoreCase))
                result.Add(new JObj { { "name", name }, { "connect", line.Substring(8) } });
            if (result.Count >= 200)
                break;
        }
        return result;
    }

    static List<string> StartConfig()
    {
        var files = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"1C\1CEStart\1CEStart.cfg"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"1C\1CEStart\1CEStart.cfg"),
        };
        var result = new List<string>();
        foreach (var file in files.Where(File.Exists))
            result.AddRange(File.ReadAllLines(file).Select(l => l.Trim().TrimStart('﻿')).Where(l => l != "")
                .Take(40).Select(l => Path.GetFileName(Path.GetDirectoryName(Path.GetDirectoryName(file))) + ": " + l));
        return result;
    }

    static List<JObj> Events(int hours, DiagContext context)
    {
        var groups = new Dictionary<string, JObj>();
        Ev.Read("Application", Ev.XPath(new[] { 1, 2, 3 }, hours, null, null), 20000, e =>
        {
            var provider = e.ProviderName ?? "";
            if (!provider.StartsWith("1C", StringComparison.OrdinalIgnoreCase) && !provider.StartsWith("1С", StringComparison.OrdinalIgnoreCase))
                return 0;
            var key = provider + "|" + e.Id + "|" + e.Level;
            if (!groups.TryGetValue(key, out var group))
                groups[key] = group = new JObj
                {
                    { "provider", provider }, { "id", e.Id }, { "level", Ev.LevelName(e) }, { "count", 0 },
                    { "last", e.TimeCreated }, { "message", Ev.Message(e, 400) },
                };
            group["count"] = (int)group["count"] + 1;
            return 0;
        }, context);
        return groups.Values.OrderByDescending(g => (int)g["count"]).Take(20).ToList();
    }
}
