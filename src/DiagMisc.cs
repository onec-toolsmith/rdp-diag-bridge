using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace RdpDiagBridge;

// 10.11.2026 События журналов с отбором по журналу, уровню, времени, источнику, кодам и тексту; группировка.
public static class EventsDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        if (p.Bool("listLogs", false))
            return ListLogs(p, context);
        var logs = p.List("log");
        if (logs.Count == 0)
            logs.Add("System");
        var levels = p.List("level");
        if (levels.Count == 0)
            levels.AddRange(new[] { "critical", "error" });
        var hours = p.Dbl("hours", 24, 0.01, 24 * 366);
        var ids = p.IntList("ids");
        var providers = p.List("providers");
        var contains = p.Str("contains");
        var max = p.Int("max", 50, 1, 2000);
        var group = p.Bool("group", false);
        var maxMessage = p.Int("maxMessage", 500, 50, 20000);
        var scan = contains != "" || group ? p.Int("scanLimit", 5000, 100, 50000) : max;
        var xpath = Ev.XPath(Ev.LevelCodes(levels), hours, ids, providers);
        var events = new List<JObj>();
        var groups = new Dictionary<string, JObj>();
        var scanned = 0;
        foreach (var log in logs)
        {
            context.Progress = log;
            var read = Ev.Read(log, xpath, scan, e =>
            {
                if (group && contains == "")
                {
                    AddToGroup(groups, e, null, maxMessage);
                    return 0;
                }
                var item = Ev.ToObj(e, contains != "" ? 20000 : maxMessage);
                if (contains != "" && item.Str("message").IndexOf(contains, StringComparison.OrdinalIgnoreCase) < 0)
                    return 0;
                if (contains != "")
                    item["message"] = Txt.Clip(item.Str("message"), maxMessage);
                if (group)
                    AddToGroup(groups, e, item, maxMessage);
                else
                    events.Add(item);
                return 0;
            }, context);
            scanned += read.Count;
        }
        context.Progress = "";
        var result = new JObj
        {
            { "logs", logs },
            { "since", DateTime.Now.AddHours(-hours) },
            { "levels", levels },
            { "scanned", scanned },
            { "scanLimitReached", (contains != "" || group) && scanned >= scan * logs.Count },
        };
        if (group)
        {
            var list = groups.Values.OrderByDescending(g => (int)g["count"]).ToList();
            result["groups"] = list.Take(max).ToList();
            result["groupCount"] = list.Count;
        }
        else
        {
            var list = events.OrderByDescending(e => e.Get("time") as DateTime? ?? DateTime.MinValue).ToList();
            result["matched"] = list.Count;
            result["events"] = list.Take(max).ToList();
        }
        return result;
    }

    static void AddToGroup(Dictionary<string, JObj> groups, EventRecord record, JObj item, int maxMessage)
    {
        var key = record.LogName + "|" + record.ProviderName + "|" + record.Id;
        var time = record.TimeCreated ?? DateTime.MinValue;
        if (!groups.TryGetValue(key, out var group))
        {
            groups[key] = new JObj
            {
                { "log", record.LogName }, { "provider", record.ProviderName }, { "id", record.Id }, { "level", Ev.LevelName(record) },
                { "count", 1 }, { "last", time }, { "first", time },
                { "message", item != null ? item.Str("message") : Ev.Message(record, maxMessage) },
            };
            return;
        }
        group["count"] = (int)group["count"] + 1;
        group["first"] = time;
    }

    static JObj ListLogs(Params p, DiagContext context)
    {
        var filter = Txt.Wildcard(p.Str("contains"));
        var session = EventLogSession.GlobalSession;
        var list = new List<JObj>();
        foreach (var name in session.GetLogNames())
        {
            context.CheckCancel();
            if (filter != null && !filter.IsMatch(name))
                continue;
            try
            {
                var info = session.GetLogInformation(name, PathType.LogName);
                if ((info.RecordCount ?? 0) == 0)
                    continue;
                list.Add(new JObj
                {
                    { "log", name }, { "records", info.RecordCount }, { "lastWrite", info.LastWriteTime },
                    { "sizeMb", Txt.Mb(info.FileSize ?? 0) },
                });
            }
            catch (Exception)
            {
            }
        }
        return new JObj
        {
            { "count", list.Count },
            { "logs", list.OrderByDescending(l => l.Get("lastWrite") as DateTime? ?? DateTime.MinValue).Take(p.Int("max", 150, 1, 2000)).ToList() },
        };
    }
}

// 10.11.2026 Установленные программы, обновления Windows и журнал Windows Update.
public static class SoftwareDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var filter = Txt.Wildcard(p.Str("name"));
        var max = p.Int("max", 200, 1, 5000);
        var result = new JObj();
        context.Progress = "программы";
        var programs = new List<JObj>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void Scan(RegistryKey root, string path, string scope)
        {
            using var key = root.OpenSubKey(path);
            if (key == null)
                return;
            foreach (var sub in key.GetSubKeyNames())
            {
                using var item = key.OpenSubKey(sub);
                var name = item?.GetValue("DisplayName") as string;
                if (string.IsNullOrWhiteSpace(name) || Convert.ToInt32(item.GetValue("SystemComponent") ?? 0) == 1
                    || item.GetValue("ParentKeyName") != null)
                    continue;
                if (filter != null && !filter.IsMatch(name) && !filter.IsMatch(item.GetValue("Publisher") as string ?? ""))
                    continue;
                var version = item.GetValue("DisplayVersion") as string ?? "";
                if (!seen.Add(name + "|" + version))
                    continue;
                var date = item.GetValue("InstallDate") as string ?? "";
                programs.Add(new JObj
                {
                    { "name", name.Trim() }, { "version", version }, { "publisher", item.GetValue("Publisher") as string ?? "" },
                    { "installed", DateTime.TryParseExact(date, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d.ToString("yyyy-MM-dd") : date },
                    { "scope", scope },
                });
            }
        }
        const string uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        using (var lm = Reg.Lm())
            Scan(lm, uninstall, "x64");
        if (Environment.Is64BitOperatingSystem)
            using (var lm32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
                Scan(lm32, uninstall, "x86");
        Scan(Registry.CurrentUser, uninstall, "user");
        var recent = p.Bool("recent", false);
        result["programs"] = (recent
                ? programs.OrderByDescending(x => x.Str("installed"))
                : programs.OrderBy(x => x.Str("name"), StringComparer.CurrentCultureIgnoreCase))
            .Take(max).ToList();
        result["programCount"] = programs.Count;
        if (p.Bool("updates", false))
        {
            context.Progress = "обновления (QFE)";
            result["updates"] = Wmi.Query("SELECT HotFixID, Description, InstalledOn, InstalledBy FROM Win32_QuickFixEngineering")
                .Select(f => new JObj
                {
                    { "id", Wmi.Str(f, "HotFixID") }, { "type", Wmi.Str(f, "Description") },
                    { "installed", Health.ParseHotfixDate(Wmi.Str(f, "InstalledOn")) }, { "by", Wmi.Str(f, "InstalledBy") },
                })
                .OrderByDescending(f => f.Get("installed") as DateTime? ?? DateTime.MinValue).Take(max).ToList();
        }
        var history = p.Int("history", 0, 0, 1000);
        if (history > 0)
        {
            context.Progress = "журнал Windows Update";
            result["updateHistory"] = UpdateHistory(history);
        }
        context.Progress = "";
        return result;
    }

    static object UpdateHistory(int count)
    {
        try
        {
            dynamic session = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session"));
            dynamic searcher = session.CreateUpdateSearcher();
            int total = searcher.GetTotalHistoryCount();
            var list = new List<JObj>();
            if (total == 0)
                return list;
            dynamic entries = searcher.QueryHistory(0, Math.Min(count, total));
            foreach (dynamic entry in entries)
            {
                int code = entry.ResultCode;
                int hresult = entry.HResult;
                list.Add(new JObj
                {
                    { "date", ((DateTime)entry.Date).ToLocalTime() },
                    { "title", (string)entry.Title },
                    { "operation", (int)entry.Operation == 2 ? "удаление" : "установка" },
                    { "result", code switch { 1 => "выполняется", 2 => "успешно", 3 => "успешно с ошибками", 4 => "ошибка", 5 => "прервано", _ => code.ToString(CultureInfo.InvariantCulture) } },
                    { "hresult", hresult == 0 ? "" : Txt.Hex(hresult) },
                });
            }
            return list;
        }
        catch (Exception ex)
        {
            return "не прочитан: " + ex.Message;
        }
    }
}

// 10.11.2026 Задания планировщика через COM Schedule.Service: не зависит от языка Windows, в отличие от schtasks.
public static class TasksDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var filter = Txt.Wildcard(p.Str("name"));
        var failedOnly = p.Bool("failedOnly", true);
        var includeMicrosoft = p.Bool("includeMicrosoft", false);
        var max = p.Int("max", 200, 1, 5000);
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service"));
        service.Connect();
        var list = new List<JObj>();
        var total = 0;
        void Walk(dynamic folder)
        {
            context.CheckCancel();
            string folderPath = folder.Path;
            if (!includeMicrosoft && folderPath.StartsWith(@"\Microsoft", StringComparison.OrdinalIgnoreCase))
                return;
            foreach (dynamic task in folder.GetTasks(1))
            {
                total++;
                string path = task.Path;
                if (filter != null && !filter.IsMatch(path) && !filter.IsMatch((string)task.Name))
                    continue;
                int result = task.LastTaskResult;
                DateTime lastRun = task.LastRunTime;
                var neverRan = lastRun.Year < 2000;
                if (failedOnly && (IsOk(result) || neverRan))
                    continue;
                var item = new JObj
                {
                    { "path", path },
                    { "enabled", (bool)task.Enabled },
                    { "state", StateName((int)task.State) },
                    { "lastRun", neverRan ? null : lastRun },
                    { "lastResult", Txt.Hex(result) + ResultText(result) },
                    { "nextRun", ((DateTime)task.NextRunTime).Year < 2000 ? null : (object)(DateTime)task.NextRunTime },
                    { "missedRuns", (int)task.NumberOfMissedRuns },
                };
                try
                {
                    dynamic definition = task.Definition;
                    item["runAs"] = (string)definition.Principal.UserId ?? "";
                    var actions = new List<string>();
                    foreach (dynamic action in definition.Actions)
                        if ((int)action.Type == 0)
                            actions.Add(Txt.Clip(((string)action.Path + " " + (string)action.Arguments).Trim(), 300));
                    item["actions"] = actions;
                }
                catch (Exception)
                {
                }
                list.Add(item);
                if (list.Count >= max)
                    return;
            }
            foreach (dynamic sub in folder.GetFolders(0))
            {
                if (list.Count >= max)
                    return;
                Walk(sub);
            }
        }
        Walk(service.GetFolder("\\"));
        return new JObj
        {
            { "tasksSeen", total },
            { "failedOnly", failedOnly },
            { "includeMicrosoft", includeMicrosoft },
            { "items", list },
        };
    }

    static bool IsOk(int code)
    {
        // 10.11.2026 0 – успешно; 0x41301 выполняется; 0x41303 еще не запускалось; 0x41325 в очереди.
        return code == 0 || code == 0x41301 || code == 0x41303 || code == 0x41325;
    }

    static string StateName(int state)
    {
        switch (state)
        {
            case 1: return "отключено";
            case 2: return "в очереди";
            case 3: return "готово";
            case 4: return "выполняется";
            default: return "неизвестно";
        }
    }

    static string ResultText(int code)
    {
        switch ((uint)code)
        {
            case 0: return " (успешно)";
            case 1: return " (неверная функция: программа завершилась с кодом 1)";
            case 2: return " (файл не найден: программа завершилась с кодом 2)";
            case 0x41301: return " (выполняется)";
            case 0x41303: return " (еще не запускалось)";
            case 0x41306: return " (прервано пользователем или по времени)";
            case 0x8004131F: return " (уже запущен экземпляр)";
            case 0x80070002: return " (файл не найден)";
            case 0x80070005: return " (отказано в доступе)";
            case 0x8007052E: return " (неверное имя пользователя или пароль)";
            case 0x800710E0: return " (оператор или администратор отклонил запрос: условие входа пользователя)";
            case 0xC000013A: return " (прервано: Ctrl+C или завершение)";
            default: return "";
        }
    }
}

// 10.11.2026 Файлы: список каталога, конец файла, поиск строк в файле, поиск файлов, размеры папок.
public static class FilesDiag
{
    public static JObj Run(Params p, DiagContext context)
    {
        var action = p.Str("action", "list").ToLowerInvariant();
        var path = Environment.ExpandEnvironmentVariables(p.Str("path"));
        if (path == "")
            throw new RejectedException("Не указан path.");
        switch (action)
        {
            case "list": return List(path, p);
            case "tail": return Tail(path, p);
            case "grep": return Grep(path, p, context);
            case "find": return Find(path, p, context);
            case "sizes": return Sizes(path, p, context);
            default: throw new RejectedException("action: list, tail, grep, find или sizes.");
        }
    }

    static JObj List(string path, Params p)
    {
        var directory = new DirectoryInfo(path);
        if (!directory.Exists)
            throw new DirectoryNotFoundException("Каталог не найден: " + path);
        var pattern = p.Str("pattern", "*");
        var entries = directory.GetFileSystemInfos(pattern);
        var sort = p.Str("sort", "time");
        IEnumerable<FileSystemInfo> ordered = sort switch
        {
            "name" => entries.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase),
            "size" => entries.OrderByDescending(e => (e as FileInfo)?.Length ?? -1),
            _ => entries.OrderByDescending(e => e.LastWriteTime),
        };
        var max = p.Int("max", 200, 1, 10000);
        return new JObj
        {
            { "path", directory.FullName },
            { "count", entries.Length },
            {
                "items", ordered.Take(max).Select(e => new JObj
                {
                    { "name", e.Name + (e is DirectoryInfo ? "\\" : "") },
                    { "sizeMb", e is FileInfo f ? Txt.Round(f.Length / 1048576.0, 3) : (object)null },
                    { "modified", e.LastWriteTime },
                }).ToList()
            },
        };
    }

    static JObj Tail(string path, Params p)
    {
        var lines = p.Int("lines", 100, 1, 10000);
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new FileNotFoundException("Файл не найден: " + path);
        var bytesWanted = Math.Min(info.Length, Math.Max(65536L, lines * 400L));
        bytesWanted = Math.Min(bytesWanted, 16L * 1048576);
        byte[] buffer;
        byte[] head;
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            head = new byte[Math.Min(4, info.Length)];
            stream.Read(head, 0, head.Length);
            var start = info.Length - bytesWanted;
            var encodingProbe = DetectEncoding(head, null);
            if (encodingProbe is UnicodeEncoding && start % 2 == 1)
                start++;
            stream.Seek(Math.Max(0, start), SeekOrigin.Begin);
            buffer = new byte[info.Length - Math.Max(0, start)];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = stream.Read(buffer, read, buffer.Length - read);
                if (n <= 0)
                    break;
                read += n;
            }
        }
        var encoding = DetectEncoding(head, buffer);
        var text = encoding.GetString(buffer).TrimStart('﻿');
        var all = text.Replace("\r\n", "\n").Split('\n').ToList();
        if (bytesWanted < info.Length && all.Count > 1)
            all.RemoveAt(0);
        if (all.Count > 0 && all[all.Count - 1] == "")
            all.RemoveAt(all.Count - 1);
        var contains = p.Str("contains");
        if (contains != "")
            all = all.Where(l => l.IndexOf(contains, StringComparison.OrdinalIgnoreCase) >= 0).ToList();
        var maxLine = p.Int("maxLine", 2000, 50, 100000);
        return new JObj
        {
            { "path", info.FullName },
            { "sizeMb", Txt.Round(info.Length / 1048576.0, 3) },
            { "modified", info.LastWriteTime },
            { "encoding", encoding.WebName },
            { "lines", all.Skip(Math.Max(0, all.Count - lines)).Select(l => Txt.Clip(l, maxLine)).ToList() },
        };
    }

    public static Encoding DetectEncoding(byte[] head, byte[] sample)
    {
        if (head.Length >= 3 && head[0] == 0xEF && head[1] == 0xBB && head[2] == 0xBF)
            return Encoding.UTF8;
        if (head.Length >= 2 && head[0] == 0xFF && head[1] == 0xFE)
            return Encoding.Unicode;
        if (head.Length >= 2 && head[0] == 0xFE && head[1] == 0xFF)
            return Encoding.BigEndianUnicode;
        if (sample == null)
            return Encoding.Default;
        try
        {
            // 10.11.2026 Начало куска может попасть в середину символа UTF-8 – пропускаем до 3 байт.
            var offset = 0;
            while (offset < 3 && offset < sample.Length && (sample[offset] & 0xC0) == 0x80)
                offset++;
            new UTF8Encoding(false, true).GetString(sample, offset, Math.Max(0, sample.Length - offset - 4));
            return Encoding.UTF8;
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Default;
        }
    }

    static JObj Grep(string path, Params p, DiagContext context)
    {
        var text = p.Str("text");
        if (text == "")
            throw new RejectedException("Для grep укажите text – подстроку или регулярное выражение (regex=true).");
        var regex = p.Bool("regex", false)
            ? new Regex(text, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)
            : new Regex(Regex.Escape(text), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var max = p.Int("max", 200, 1, 10000);
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new FileNotFoundException("Файл не найден: " + path);
        var head = new byte[4];
        var sample = new byte[65536];
        int sampleLength;
        using (var probe = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            sampleLength = probe.Read(sample, 0, sample.Length);
        }
        Array.Copy(sample, head, Math.Min(4, sampleLength));
        Array.Resize(ref sample, sampleLength);
        var encoding = DetectEncoding(head, sample);
        var matches = new Queue<JObj>();
        long number = 0;
        long found = 0;
        var watch = Stopwatch.StartNew();
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        using (var reader = new StreamReader(stream, encoding, true))
        {
            string line;
            while ((line = reader.ReadLine()) != null)
            {
                number++;
                if (number % 20000 == 0)
                {
                    context.CheckCancel();
                    context.Progress = "строка " + number;
                }
                if (!regex.IsMatch(line))
                    continue;
                found++;
                matches.Enqueue(new JObj { { "line", number }, { "text", Txt.Clip(line, 1000) } });
                // 10.11.2026 Храним последние совпадения: в журналах важнее свежие строки.
                if (matches.Count > max)
                    matches.Dequeue();
            }
        }
        context.Progress = "";
        return new JObj
        {
            { "path", info.FullName },
            { "sizeMb", Txt.Round(info.Length / 1048576.0, 3) },
            { "linesRead", number },
            { "found", found },
            { "shown", "последние " + matches.Count },
            { "seconds", Txt.Round(watch.Elapsed.TotalSeconds) },
            { "matches", matches.ToList() },
        };
    }

    static JObj Find(string path, Params p, DiagContext context)
    {
        var pattern = p.Str("pattern", "*");
        var days = p.Dbl("days", 0, 0, 36500);
        var max = p.Int("max", 200, 1, 10000);
        var budget = p.Int("budgetSec", 30, 1, 250);
        var since = days > 0 ? DateTime.Now.AddDays(-days) : DateTime.MinValue;
        var found = new List<FileInfo>();
        var watch = Stopwatch.StartNew();
        var stack = new Stack<string>();
        stack.Push(path);
        var dirs = 0;
        var denied = 0;
        var complete = true;
        while (stack.Count > 0)
        {
            if (watch.Elapsed.TotalSeconds > budget)
            {
                complete = false;
                break;
            }
            context.CheckCancel();
            var dir = stack.Pop();
            dirs++;
            try
            {
                var info = new DirectoryInfo(dir);
                foreach (var file in info.GetFiles(pattern))
                    if (file.LastWriteTime >= since)
                        found.Add(file);
                foreach (var sub in info.GetDirectories())
                    if ((sub.Attributes & FileAttributes.ReparsePoint) == 0)
                        stack.Push(sub.FullName);
            }
            catch (UnauthorizedAccessException)
            {
                denied++;
            }
            catch (IOException)
            {
                denied++;
            }
            if (dirs % 200 == 0)
                context.Progress = "просмотрено папок: " + dirs;
        }
        context.Progress = "";
        return new JObj
        {
            { "path", path },
            { "pattern", pattern },
            { "complete", complete },
            { "dirsScanned", dirs },
            { "dirsDenied", denied },
            { "found", found.Count },
            { "totalMb", Txt.Mb(found.Sum(f => f.Length)) },
            {
                "items", found.OrderByDescending(f => f.LastWriteTime).Take(max).Select(f => new JObj
                {
                    { "file", f.FullName }, { "sizeMb", Txt.Round(f.Length / 1048576.0, 3) }, { "modified", f.LastWriteTime },
                }).ToList()
            },
        };
    }

    public sealed class SizeResult
    {
        public long Bytes;
        public long Files;
        public bool Complete = true;
    }

    // 10.11.2026 Размер папки обходом с бюджетом времени; точки повторной обработки (junction) не раскрываем.
    public static SizeResult FolderSize(string path, Stopwatch watch, double budgetSec, DiagContext context)
    {
        var result = new SizeResult();
        var stack = new Stack<string>();
        stack.Push(path);
        while (stack.Count > 0)
        {
            if (watch.Elapsed.TotalSeconds > budgetSec)
            {
                result.Complete = false;
                break;
            }
            context?.CheckCancel();
            var dir = stack.Pop();
            try
            {
                var info = new DirectoryInfo(dir);
                foreach (var file in info.GetFiles())
                {
                    result.Bytes += file.Length;
                    result.Files++;
                }
                foreach (var sub in info.GetDirectories())
                    if ((sub.Attributes & FileAttributes.ReparsePoint) == 0)
                        stack.Push(sub.FullName);
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (IOException)
            {
            }
        }
        return result;
    }

    static JObj Sizes(string path, Params p, DiagContext context)
    {
        var budget = p.Int("budgetSec", 60, 1, 250);
        var watch = Stopwatch.StartNew();
        var root = new DirectoryInfo(path);
        if (!root.Exists)
            throw new DirectoryNotFoundException("Каталог не найден: " + path);
        var items = new List<JObj>();
        var complete = true;
        foreach (var sub in root.GetDirectories())
        {
            if ((sub.Attributes & FileAttributes.ReparsePoint) != 0)
                continue;
            context.Progress = sub.Name;
            var size = FolderSize(sub.FullName, watch, budget, context);
            complete &= size.Complete;
            items.Add(new JObj
            {
                { "folder", sub.Name }, { "sizeGb", Txt.Round(size.Bytes / 1073741824.0, 2) }, { "files", size.Files },
                { "complete", size.Complete },
            });
        }
        var rootFiles = root.GetFiles();
        context.Progress = "";
        return new JObj
        {
            { "path", root.FullName },
            { "complete", complete },
            { "seconds", Txt.Round(watch.Elapsed.TotalSeconds) },
            { "filesInRootGb", Txt.Round(rootFiles.Sum(f => f.Length) / 1073741824.0, 2) },
            { "items", items.OrderByDescending(i => i.Num("sizeGb") ?? 0).ToList() },
        };
    }
}

// 10.11.2026 Код PowerShell от агента Claude: отдельный процесс powershell.exe, вывод в UTF-8, прерывание – снятием процесса.
public static class PowerShellRunner
{
    public static JObj Run(Params p, DiagContext context, AgentCore agent)
    {
        if (!agent.AllowCode)
            throw new RejectedException("Команды PowerShell не разрешены в окне агента.");
        var code = p.Str("code");
        if (code.Trim() == "")
            throw new RejectedException("Пустой код.");
        var json = p.Str("output", "text") == "json";
        var maxChars = p.Int("maxChars", 200000, 1000, 5000000);
        var temp = Path.Combine(Path.GetTempPath(), "rdp-diag-bridge");
        Directory.CreateDirectory(temp);
        var file = Path.Combine(temp, "cmd-" + Guid.NewGuid().ToString("N").Substring(0, 12) + ".ps1");
        File.WriteAllText(file, code, new UTF8Encoding(true));
        var run = json
            ? "$__rdpResult = & $__rdpBlock; ConvertTo-Json -InputObject @($__rdpResult) -Depth 4"
            : "& $__rdpBlock *>&1 | Out-String -Stream -Width 220";
        var wrapper = string.Join("\n",
            "$ProgressPreference = 'SilentlyContinue'",
            "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false",
            "$OutputEncoding = [Console]::OutputEncoding",
            "$__rdpCode = [IO.File]::ReadAllText('" + file.Replace("'", "''") + "', [Text.Encoding]::UTF8)",
            "try { $__rdpBlock = [scriptblock]::Create($__rdpCode) } catch { [Console]::Error.WriteLine('Ошибка разбора кода: ' + $_.Exception.Message); exit 2 }",
            "try { " + run + " } catch { [Console]::Error.WriteLine('Выполнение прервано ошибкой: ' + ($_ | Out-String)); exit 1 }");
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(wrapper));
        var powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var info = new ProcessStartInfo(powershell, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = temp,
        };
        var output = new StringBuilder();
        var errors = new StringBuilder();
        var truncated = false;
        var watch = Stopwatch.StartNew();
        context.Progress = "PowerShell";
        try
        {
            using var process = new Process { StartInfo = info };
            process.OutputDataReceived += (_, e) => Append(output, e.Data, maxChars, ref truncated);
            process.ErrorDataReceived += (_, e) => Append(errors, e.Data, maxChars / 4, ref truncated);
            process.Start();
            process.StandardInput.Close();
            context.Attach(process);
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            while (!process.WaitForExit(200))
            {
                if (context.Cancelled)
                {
                    try
                    {
                        process.Kill();
                    }
                    catch (Exception)
                    {
                    }
                    throw new OperationCanceledException();
                }
                context.Progress = "PowerShell, " + (int)watch.Elapsed.TotalSeconds + " с";
            }
            process.WaitForExit();
            context.Progress = "";
            lock (output)
            lock (errors)
                return new JObj
                {
                    { "exitCode", process.ExitCode },
                    { "seconds", Txt.Round(watch.Elapsed.TotalSeconds) },
                    { "output", output.ToString().TrimEnd() },
                    { "errors", errors.ToString().TrimEnd() },
                    { "truncated", truncated },
                    { "format", json ? "json" : "text" },
                    { "user", Env.UserName + (Env.Elevated ? " (администратор)" : "") },
                };
        }
        finally
        {
            Proto.TryDelete(file);
        }
    }

    static void Append(StringBuilder target, string line, int max, ref bool truncated)
    {
        if (line == null)
            return;
        lock (target)
        {
            if (target.Length + line.Length + 1 > max)
            {
                truncated = true;
                return;
            }
            target.Append(line).Append('\n');
        }
    }
}
