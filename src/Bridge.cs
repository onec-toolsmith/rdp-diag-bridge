using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace RdpDiagBridge;

// 10.11.2026 Сеанс агента, найденный в каталоге обмена.
public sealed class SessionInfo
{
    public string Sid = "";
    public string Path = "";
    public JObj Info = new JObj();
    public double Age;
    public DateTime MtimeUtc;

    public string State => Age > Bridge.AliveSec ? "silent" : Info.Str("state", "ready");
    public bool Responsive => State != "silent";

    // 10.11.2026 Расхождение часов: время агента в session.json против времени записи файла по часам этого компьютера.
    public double? SkewSec
    {
        get
        {
            var heartbeat = Proto.ParseUtc(Info.Str("heartbeat"));
            return heartbeat.HasValue ? (heartbeat.Value - MtimeUtc).TotalSeconds : null;
        }
    }
}

// 10.11.2026 Сторона MCP-сервера: поиск сеансов, постановка команд, ожидание ответов.
public static class Bridge
{
    public const double AliveSec = 10;
    const double PruneSec = 24 * 3600;
    public static string RootOverride = "";
    static readonly object sync = new object();
    static readonly Dictionary<string, JObj> results = new Dictionary<string, JObj>();
    static readonly Queue<string> resultOrder = new Queue<string>();
    public static readonly Dictionary<string, string> Kinds = new Dictionary<string, string>();
    public static readonly Dictionary<string, DateTime> SentUtc = new Dictionary<string, DateTime>();
    public static readonly Dictionary<string, string> SessionOf = new Dictionary<string, string>();

    public static string Root
    {
        get
        {
            if (!string.IsNullOrEmpty(RootOverride))
                return RootOverride;
            var env = Environment.GetEnvironmentVariable("RDP_DIAG_BRIDGE_DIR");
            return string.IsNullOrEmpty(env) ? Proto.DefaultRoot : env;
        }
    }

    public static string ResultsDir
    {
        get
        {
            var env = Environment.GetEnvironmentVariable("RDP_DIAG_BRIDGE_RESULTS");
            return string.IsNullOrEmpty(env)
                ? System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "rdp-diag-bridge", "results")
                : env;
        }
    }

    // 10.11.2026 Текущее время по часам файловой системы обмена: сердцебиение – mtime session.json, его ставят те же часы.
    static DateTime WindowsNow(string root)
    {
        Directory.CreateDirectory(root);
        var probe = System.IO.Path.Combine(root, ".clock");
        File.WriteAllText(probe, DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture));
        return File.GetLastWriteTimeUtc(probe);
    }

    public static List<SessionInfo> List(bool prune = true)
    {
        var root = Root;
        var sessions = new List<SessionInfo>();
        if (!Directory.Exists(root))
            return sessions;
        var now = WindowsNow(root);
        foreach (var dir in Directory.GetDirectories(root).OrderBy(d => d, StringComparer.Ordinal))
        {
            var name = System.IO.Path.GetFileName(dir);
            if (!Proto.SessionName.IsMatch(name))
                continue;
            var file = System.IO.Path.Combine(dir, "session.json");
            if (!File.Exists(file))
            {
                if (prune && (now - Directory.GetLastWriteTimeUtc(dir)).TotalSeconds > PruneSec)
                    Proto.RemoveSessionDir(dir);
                continue;
            }
            var mtime = File.GetLastWriteTimeUtc(file);
            var session = new SessionInfo
            {
                Sid = name,
                Path = dir,
                Info = Proto.ReadJson(file, 5) ?? new JObj(),
                MtimeUtc = mtime,
                Age = Math.Max(0, (now - mtime).TotalSeconds),
            };
            if (prune && session.Age > PruneSec)
            {
                Proto.RemoveSessionDir(dir);
                continue;
            }
            sessions.Add(session);
        }
        return sessions;
    }

    public static SessionInfo Find(string selector)
    {
        var sessions = List();
        var responsive = sessions.Where(s => s.Responsive).ToList();
        if (!string.IsNullOrWhiteSpace(selector))
        {
            var wanted = selector.Trim().ToLowerInvariant();
            var exact = sessions.FirstOrDefault(s => s.Sid == wanted);
            if (exact != null)
                return exact;
            var matched = sessions.Where(s => SearchText(s).Contains(wanted)).ToList();
            var candidates = matched.Where(s => s.Responsive).ToList();
            if (candidates.Count == 0)
                candidates = matched;
            if (candidates.Count == 1)
                return candidates[0];
            if (candidates.Count == 0)
                throw new ToolError("Сеанс «" + selector + "» не найден.\n\n" + Describe(sessions));
            throw new ToolError("Под «" + selector + "» подходит несколько сеансов, укажите идентификатор.\n\n" + Describe(candidates));
        }
        if (responsive.Count == 1)
            return responsive[0];
        if (responsive.Count == 0)
            throw new ToolError("Нет работающих агентов. В RDP-сеансе на удаленном компьютере запустите "
                                + Proto.TsclientRoot + "\\agent\\" + Proto.ExeName + ".\n\n" + Describe(sessions));
        throw new ToolError("Работает несколько агентов, укажите session.\n\n" + Describe(responsive));
    }

    static string SearchText(SessionInfo session)
    {
        var info = session.Info;
        return string.Join(" ", info.Str("computer"), info.Str("domain"), info.Str("user"), info.Str("clientName"), info.Str("os"))
            .ToLowerInvariant();
    }

    public static string Describe(List<SessionInfo> sessions)
    {
        if (sessions.Count == 0)
            return "Сеансов нет (каталог обмена " + Root + "). Агент: в RDP-сеансе запустить "
                   + Proto.TsclientRoot + "\\agent\\" + Proto.ExeName
                   + " (диск C этого компьютера должен быть подключен в RDP: «Локальные ресурсы – Подробнее – Диски»).";
        return string.Join("\n\n", sessions.Select(DescribeOne));
    }

    public static string DescribeOne(SessionInfo session)
    {
        var info = session.Info;
        var lines = new List<string> { session.Sid + ": " + StateText(session) };
        var computer = info.Str("computer");
        if (computer != "")
            lines.Add("  Компьютер: " + computer + (info.Str("domain") != "" ? " (домен " + info.Str("domain") + ")" : "")
                      + ", пользователь " + info.Str("user") + (info.Bool("elevated") ? ", агент от администратора" : ", агент без прав администратора"));
        if (info.Str("os") != "")
            lines.Add("  Windows: " + info.Str("os"));
        if (info.Str("clientName") != "" || info.Str("rdpSession") != "")
            lines.Add("  RDP: клиент " + info.Str("clientName") + ", сеанс " + info.Str("rdpSession"));
        lines.Add("  Разрешено: PowerShell – " + (info.Bool("allowCode") ? "да" : "нет") + "; подтверждение – "
                  + ConfirmText(info.Str("confirm")) + (info.Bool("headless") ? "; агент без окна" : ""));
        var skew = session.SkewSec;
        if (skew.HasValue && Math.Abs(skew.Value) >= 5)
            lines.Add("  Часы удаленного компьютера: " + (skew.Value > 0 ? "+" : "") + Txt.Num(Math.Round(skew.Value)) + " с относительно этого компьютера");
        lines.Add("  Агент " + info.Str("agentVersion") + ", команд выполнено: " + info.Str("commandsDone", "0"));
        return string.Join("\n", lines);
    }

    public static string ConfirmText(string mode)
    {
        switch (mode)
        {
            case "all": return "каждая команда";
            case "none": return "без подтверждения";
            default: return "только код PowerShell";
        }
    }

    public static string StateText(SessionInfo session)
    {
        var info = session.Info;
        switch (session.State)
        {
            case "silent":
                return "не отвечает " + Txt.Num(Math.Round(session.Age)) + " с: окно агента закрыто без уборки, агент завис или разорвано RDP-подключение";
            case "busy":
                var progress = info.Str("progress");
                return "выполняет " + info.Str("busyType") + " (" + info.Str("busyCommand") + ")" + (progress != "" ? ": " + progress : "");
            case "awaiting":
                return "команда " + info.Str("busyType") + " (" + info.Str("busyCommand") + ") ждет решения пользователя в окне агента";
            case "paused":
                return "приостановлен пользователем";
            default:
                return "готов (сердцебиение " + Txt.Num(Math.Round(session.Age)) + " с назад)";
        }
    }

    public static string Submit(SessionInfo session, string type, JObj parameters, int ttlSec)
    {
        var inbox = System.IO.Path.Combine(session.Path, "in");
        if (!Directory.Exists(inbox))
            throw new ToolError("Каталог сеанса " + session.Sid + " неполный или удален: агент закрыт?");
        var id = Proto.NewCommandId();
        var command = new JObj
        {
            { "protocol", Proto.Version }, { "id", id }, { "type", type }, { "ttlSec", ttlSec },
            { "sentUtc", Proto.UtcStamp(DateTime.UtcNow) }, { "params", parameters ?? new JObj() },
        };
        var temporary = System.IO.Path.Combine(inbox, id + ".tmp");
        File.WriteAllText(temporary, Json.Write(command), Proto.Utf8);
        File.Move(temporary, System.IO.Path.Combine(inbox, id + ".json"));
        lock (sync)
        {
            Kinds[id] = type;
            SentUtc[id] = DateTime.UtcNow;
            SessionOf[id] = session.Path;
        }
        return id;
    }

    // 10.11.2026 Ждет ответ: "done", "closed" (каталог сеанса удален) или "timeout".
    public static string Wait(string sessionPath, string id, int timeoutSec, out JObj response)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSec);
        var delay = 50;
        while (true)
        {
            response = Take(sessionPath, id);
            if (response != null)
                return "done";
            if (!Directory.Exists(sessionPath))
                return "closed";
            if (DateTime.UtcNow >= deadline)
                return "timeout";
            Thread.Sleep(delay);
            delay = Math.Min(delay * 3 / 2, 300);
        }
    }

    public static string KindOf(string id)
    {
        lock (sync)
            return Kinds.TryGetValue(id, out var kind) ? kind : "";
    }

    public static DateTime? SentOf(string id)
    {
        lock (sync)
            return SentUtc.TryGetValue(id, out var sent) ? sent : null;
    }

    public static JObj Cached(string id)
    {
        lock (sync)
            return results.TryGetValue(id, out var response) ? response : null;
    }

    public static JObj Take(string sessionPath, string id)
    {
        var cached = Cached(id);
        if (cached != null)
            return cached;
        var file = System.IO.Path.Combine(sessionPath, "out", id + ".json");
        if (!File.Exists(file))
            return null;
        var response = Proto.ReadJson(file, 10) ?? throw new ToolError("Файл ответа не читается как JSON: " + file);
        Proto.TryDelete(file);
        lock (sync)
        {
            results[id] = response;
            resultOrder.Enqueue(id);
            while (resultOrder.Count > 100)
                results.Remove(resultOrder.Dequeue());
        }
        return response;
    }

    public static bool Withdraw(string sessionPath, string id)
    {
        var file = System.IO.Path.Combine(sessionPath, "in", id + ".json");
        try
        {
            if (!File.Exists(file))
                return false;
            File.Delete(file);
            return !File.Exists(file);
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static void RequestCancel(string sessionPath, string id)
    {
        File.WriteAllText(System.IO.Path.Combine(sessionPath, "work", id + ".cancel"), "cancel");
    }

    public static string State(string sessionPath, string id)
    {
        if (Cached(id) != null || File.Exists(System.IO.Path.Combine(sessionPath, "out", id + ".json")))
            return "done";
        if (File.Exists(System.IO.Path.Combine(sessionPath, "work", id + ".json")))
            return "running";
        if (File.Exists(System.IO.Path.Combine(sessionPath, "in", id + ".json")))
            return "queued";
        return Directory.Exists(sessionPath) ? "unknown" : "closed";
    }

    public static string Locate(string id)
    {
        lock (sync)
            if (SessionOf.TryGetValue(id, out var known))
                return known;
        var root = Root;
        if (!Directory.Exists(root))
            return null;
        foreach (var dir in Directory.GetDirectories(root))
        {
            if (!Proto.SessionName.IsMatch(System.IO.Path.GetFileName(dir)))
                continue;
            if (new[] { "in", "work", "out" }.Any(box => File.Exists(System.IO.Path.Combine(dir, box, id + ".json"))))
                return dir;
        }
        return null;
    }

    public static SessionInfo Current(string sessionPath)
    {
        return List(false).FirstOrDefault(s => string.Equals(s.Path, sessionPath, StringComparison.OrdinalIgnoreCase));
    }

    // 10.11.2026 Копия EXE в <корень>\agent: оттуда агент запускают в RDP-сеансе по \\tsclient. Обновляется,
    // когда собран новый выпуск; занятый файл (агент запущен прямо оттуда) пропускаем.
    public static string EnsureAgentCopy()
    {
        try
        {
            var self = System.Reflection.Assembly.GetExecutingAssembly().Location;
            var dir = System.IO.Path.Combine(Root, "agent");
            Directory.CreateDirectory(dir);
            var target = System.IO.Path.Combine(dir, Proto.ExeName);
            if (string.Equals(System.IO.Path.GetFullPath(self), System.IO.Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
                return "";
            if (File.Exists(target) && Hash(target) == Hash(self))
                return "";
            File.Copy(self, target, true);
            return "";
        }
        catch (Exception ex)
        {
            return "Копия агента в каталоге обмена не обновлена: " + ex.Message;
        }
    }

    static string Hash(string file)
    {
        using var sha = SHA256.Create();
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToBase64String(sha.ComputeHash(stream));
    }
}
