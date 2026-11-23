using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;

namespace RdpDiagBridge;

// 10.11.2026 Команда, взятая агентом из каталога in.
public sealed class Command
{
    public string Id = "";
    public string Type = "";
    public string WorkFile = "";
    public JObj Params = new JObj();
    public int TtlSec = 60;
    public DateTime ReceivedUtc;
    public DiagContext Context = new DiagContext();
    public string Result;

    public string Describe()
    {
        if (Type == "powershell")
            return "Код PowerShell (вывод: " + Params.Str("output", "text") + "):\r\n\r\n"
                + Params.Str("code").Replace("\r\n", "\n").Replace("\n", "\r\n");
        var text = "Команда: " + Type;
        if (Params.Count > 0)
            text += "\r\nПараметры: " + Json.Write(Params);
        return text;
    }
}

// 10.11.2026 Ход команды: прогресс, предупреждения, прерывание (дочерний процесс PowerShell снимается).
public sealed class DiagContext
{
    public volatile bool Cancelled;
    public volatile string Progress = "";
    public readonly List<string> Warnings = new List<string>();
    Process process;

    public void Warn(string text)
    {
        lock (Warnings)
            Warnings.Add(text);
    }

    public void CheckCancel()
    {
        if (Cancelled)
            throw new OperationCanceledException();
    }

    public void Attach(Process child)
    {
        process = child;
        if (Cancelled)
            Cancel();
    }

    public void Cancel()
    {
        Cancelled = true;
        try
        {
            var child = process;
            if (child != null && !child.HasExited)
                child.Kill();
        }
        catch (Exception)
        {
        }
    }
}

// 23.11.2026 Запись журнала для окна агента. У команды одна строка на все ее состояния: окно находит строку по
// CommandId и обновляет ее. Status: info, waiting, running, ok, error, rejected, denied, cancelled, expired.
public sealed class LogEntry
{
    public DateTime Time = DateTime.Now;
    public string CommandId = "";
    public string Command = "";
    public string Status = "info";
    public string Text = "";
    public double Seconds = -1;
}

// 10.11.2026 Агент на удаленном компьютере: опрашивает каталог сеанса, выполняет команды в отдельном потоке,
// пишет ответы и сердцебиение. Окно агента (AgentForm) только показывает состояние и передает решения пользователя.
public sealed class AgentCore
{
    public string Root { get; private set; } = "";
    public string SessionId { get; private set; } = "";
    public string SessionDir { get; private set; } = "";
    public volatile bool AllowCode;
    public volatile string ConfirmMode = "code";
    public volatile bool Paused;
    public bool Headless;
    public volatile string LastError = "";
    public int CommandsDone;
    public readonly DateTime StartedUtc = DateTime.UtcNow;
    public readonly ConcurrentQueue<LogEntry> LogQueue = new ConcurrentQueue<LogEntry>();
    public volatile bool StopRequested;

    readonly object sync = new object();
    readonly Dictionary<string, long> firstSeen = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
    readonly Stopwatch clock = Stopwatch.StartNew();
    readonly string osName;
    readonly string computerDomain;
    Thread loop;
    Command busy;
    Command pending;
    bool decided;
    bool decisionAllow;
    string decisionComment = "";
    bool cancelFromUi;
    long lastHeartbeat = -100000;
    bool stateChanged;

    public AgentCore()
    {
        osName = SafeOsName();
        try
        {
            computerDomain = IPGlobalProperties.GetIPGlobalProperties().DomainName ?? "";
        }
        catch (Exception)
        {
            computerDomain = "";
        }
    }

    public Command Busy => busy;
    public Command Pending => pending;

    public string State
    {
        get
        {
            if (string.IsNullOrEmpty(SessionDir))
                return "nodir";
            if (pending != null)
                return "awaiting";
            if (busy != null)
                return "busy";
            return Paused ? "paused" : "ready";
        }
    }

    public string StateText()
    {
        if (string.IsNullOrEmpty(SessionDir))
            return "Каталог обмена не задан или недоступен" + (LastError != "" ? ": " + LastError : "");
        if (LastError != "")
            return "Нет доступа к каталогу обмена: " + LastError;
        var current = busy;
        if (pending != null)
            return "Ждет вашего решения: " + pending.Type;
        if (current != null)
        {
            var progress = current.Context.Progress;
            return "Выполняет " + current.Type + (progress != "" ? " – " + progress : "");
        }
        return Paused ? "Приостановлен: команды ждут в очереди" : "Готов, ждет команды";
    }

    public void Log(string text)
    {
        Write(new LogEntry { Text = text });
    }

    void LogCommand(Command command, string status, string text, double seconds = -1)
    {
        Write(new LogEntry { CommandId = command.Id, Command = command.Type, Status = status, Text = text, Seconds = seconds });
    }

    // 23.11.2026 Без окна очередь никто не читает – туда не пишем.
    void Write(LogEntry entry)
    {
        if (Headless)
            Trace.WriteLine((entry.Command != "" ? entry.Command + ": " : "") + entry.Text);
        else
            LogQueue.Enqueue(entry);
    }

    public void Start(string root)
    {
        Root = root ?? "";
        if (!string.IsNullOrEmpty(root))
        {
            try
            {
                lock (sync)
                    OpenSession(root);
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                Log("Сеанс не открыт: " + ex.Message);
            }
        }
        loop = new Thread(Loop) { IsBackground = true, Name = "agent-loop" };
        loop.Start();
    }

    public void Stop()
    {
        StopRequested = true;
        loop?.Join(3000);
        busy?.Context.Cancel();
        lock (sync)
        {
            Proto.RemoveSessionDir(SessionDir);
            SessionDir = "";
        }
    }

    // 10.11.2026 Смена каталога обмена – новый сеанс; прежний каталог сеанса удаляется.
    public string ChangeRoot(string root)
    {
        lock (sync)
        {
            if (busy != null || pending != null)
                return "Дождитесь окончания команды.";
            Proto.RemoveSessionDir(SessionDir);
            SessionDir = "";
            SessionId = "";
            try
            {
                OpenSession(root);
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }
        return "";
    }

    void OpenSession(string root)
    {
        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException("Каталог обмена не найден: " + root);
        var id = Proto.NewSessionId();
        var dir = Path.Combine(root, id);
        Directory.CreateDirectory(Path.Combine(dir, "in"));
        Directory.CreateDirectory(Path.Combine(dir, "work"));
        Directory.CreateDirectory(Path.Combine(dir, "out"));
        Root = root;
        SessionId = id;
        SessionDir = dir;
        LastError = "";
        firstSeen.Clear();
        WriteSession();
        Log("Сеанс " + id + " открыт в " + root);
    }

    public void Decide(bool allow, string comment)
    {
        lock (sync)
        {
            if (pending == null)
                return;
            decided = true;
            decisionAllow = allow;
            decisionComment = comment ?? "";
        }
    }

    public void CancelCurrent()
    {
        lock (sync)
            cancelFromUi = true;
    }

    void Loop()
    {
        long lastReopen = 0;
        while (!StopRequested)
        {
            try
            {
                lock (sync)
                {
                    // 10.11.2026 Каталог обмена был недоступен при запуске или каталог сеанса удалили – новый сеанс,
                    // попытка раз в 5 с.
                    var lost = string.IsNullOrEmpty(SessionDir) || (busy == null && pending == null && !Directory.Exists(SessionDir));
                    if (lost && Root != "" && clock.ElapsedMilliseconds - lastReopen > 5000)
                    {
                        lastReopen = clock.ElapsedMilliseconds;
                        if (Directory.Exists(Root))
                            OpenSession(Root);
                    }
                    if (!string.IsNullOrEmpty(SessionDir) && Directory.Exists(SessionDir))
                    {
                        ProcessOnce();
                        if (clock.ElapsedMilliseconds - lastHeartbeat >= 2000 || stateChanged)
                            WriteSession();
                        if (Headless && File.Exists(Path.Combine(SessionDir, "stop")))
                            StopRequested = true;
                        LastError = "";
                    }
                    else if (Root != "")
                    {
                        LastError = "каталог " + Root + " недоступен";
                    }
                }
            }
            catch (Exception ex)
            {
                // 10.11.2026 Каталог \\tsclient пропадает при разрыве RDP – ждем восстановления связи.
                LastError = ex.Message;
            }
            Thread.Sleep(300);
        }
    }

    void ProcessOnce()
    {
        var inbox = ScanInbox();
        if (busy != null)
        {
            CheckBusy();
            return;
        }
        if (pending != null)
        {
            CheckPending();
            return;
        }
        if (Paused)
            return;
        foreach (var file in inbox)
        {
            if (TakeCommand(file))
                return;
        }
    }

    List<string> ScanInbox()
    {
        var files = Directory.GetFiles(Path.Combine(SessionDir, "in"), "*.json").ToList();
        files.Sort(StringComparer.Ordinal);
        var now = clock.ElapsedMilliseconds;
        var names = new HashSet<string>(files, StringComparer.OrdinalIgnoreCase);
        foreach (var known in firstSeen.Keys.ToList())
            if (!names.Contains(known))
                firstSeen.Remove(known);
        foreach (var file in files)
            if (!firstSeen.ContainsKey(file))
                firstSeen[file] = now;
        return files;
    }

    bool TakeCommand(string file)
    {
        var name = Path.GetFileName(file);
        var work = Path.Combine(SessionDir, "work", name);
        var seenAt = firstSeen.TryGetValue(file, out var seen) ? seen : clock.ElapsedMilliseconds;
        try
        {
            File.Move(file, work);
        }
        catch (Exception)
        {
            // 10.11.2026 Команду уже снял MCP-сервер (истек его срок ожидания).
            return false;
        }
        firstSeen.Remove(file);
        var command = new Command
        {
            Id = Path.GetFileNameWithoutExtension(name),
            WorkFile = work,
            ReceivedUtc = DateTime.UtcNow,
        };
        try
        {
            var raw = Proto.ReadJson(work, 5) ?? throw new FormatException("файл команды не читается");
            command.Id = raw.Str("id", command.Id);
            command.Type = raw.Str("type");
            command.Params = raw.Obj("params") ?? new JObj();
            command.TtlSec = (int)(raw.Num("ttlSec") ?? 60);
        }
        catch (Exception ex)
        {
            Finish(command, Response(command, "error", "Команда не разобрана: " + ex.Message));
            return true;
        }
        // 10.11.2026 Срок считаем по своим часам от момента, когда файл впервые появился во входящих: часы
        // удаленного компьютера и компьютера с MCP могут расходиться на минуты.
        var waitedSec = (clock.ElapsedMilliseconds - seenAt) / 1000.0;
        if (waitedSec > command.TtlSec + 5)
        {
            Finish(command, Response(command, "expired", "Команда ждала в очереди дольше срока"));
            return true;
        }
        if (command.Type == "powershell" && !AllowCode)
        {
            Finish(command, Response(command, "rejected",
                "На удаленном компьютере не разрешены команды PowerShell: пользователь включает это в окне агента "
                + "(«Разрешить команды PowerShell»)."));
            return true;
        }
        var mode = ConfirmMode;
        var ask = !Headless && (mode == "all" || (mode == "code" && command.Type == "powershell"));
        if (ask)
        {
            pending = command;
            decided = false;
            stateChanged = true;
            LogCommand(command, "waiting", "ждет вашего решения");
            return true;
        }
        StartBusy(command);
        return true;
    }

    void StartBusy(Command command)
    {
        busy = command;
        cancelFromUi = false;
        stateChanged = true;
        LogCommand(command, "running", "выполняется");
        var thread = new Thread(() =>
        {
            string text;
            try
            {
                text = Json.Write(Diag.Execute(command, this));
            }
            catch (Exception ex)
            {
                text = Json.Write(Response(command, "error", ex.Message));
            }
            command.Result = text;
        }) { IsBackground = true, Name = "diag-" + command.Type };
        thread.Start();
    }

    void CheckBusy()
    {
        var command = busy;
        if (command.Result != null)
        {
            Finish(command, command.Result);
            return;
        }
        if (cancelFromUi || File.Exists(command.WorkFile + ".cancel") || File.Exists(CancelFile(command)))
        {
            command.Context.Cancel();
            Finish(command, Response(command, "cancelled",
                cancelFromUi ? "Команду прервал пользователь в окне агента" : "Команда прервана по запросу MCP"));
        }
    }

    void CheckPending()
    {
        var command = pending;
        if (File.Exists(CancelFile(command)))
        {
            pending = null;
            Finish(command, Response(command, "cancelled", "Запрос отозван до решения пользователя"));
            return;
        }
        if (!decided)
            return;
        pending = null;
        if (decisionAllow)
        {
            StartBusy(command);
            if (decisionComment.Trim() != "")
                command.Context.Warn("Комментарий пользователя: " + decisionComment.Trim());
            return;
        }
        var response = Response(command, "denied", "Пользователь отклонил команду");
        if (decisionComment.Trim() != "")
            response["comment"] = decisionComment.Trim();
        Finish(command, response);
    }

    string CancelFile(Command command)
    {
        return Path.Combine(SessionDir, "work", command.Id + ".cancel");
    }

    void Finish(Command command, JObj response)
    {
        Finish(command, Json.Write(response));
    }

    void Finish(Command command, string text)
    {
        var outFile = Path.Combine(SessionDir, "out", command.Id + ".json");
        Proto.WriteAtomic(outFile, text);
        Proto.TryDelete(command.WorkFile);
        Proto.TryDelete(CancelFile(command));
        if (busy == command)
            busy = null;
        if (pending == command)
            pending = null;
        CommandsDone++;
        stateChanged = true;
        var status = "ok";
        var error = "";
        try
        {
            var parsed = Json.ParseObject(text);
            status = parsed.Str("status", "ok");
            error = parsed.Str("error");
        }
        catch (Exception)
        {
        }
        // 23.11.2026 У ошибки в журнале виден ее текст; у отказов и прерываний хватает названия состояния.
        var line = StatusName(status);
        if (status == "error" && error != "")
            line += ": " + error.Replace("\r", " ").Replace("\n", " ");
        LogCommand(command, status, line, Math.Max(0, (DateTime.UtcNow - command.ReceivedUtc).TotalSeconds));
    }

    static string StatusName(string status)
    {
        switch (status)
        {
            case "ok": return "выполнено";
            case "error": return "ошибка";
            case "rejected": return "отклонено агентом";
            case "denied": return "отклонено вами";
            case "cancelled": return "прервано";
            case "expired": return "просрочено";
            default: return status;
        }
    }

    public static JObj Response(Command command, string status, string error)
    {
        var response = new JObj
        {
            { "protocol", Proto.Version },
            { "id", command.Id },
            { "type", command.Type },
            { "status", status },
            { "receivedUtc", Proto.UtcStamp(command.ReceivedUtc == default ? DateTime.UtcNow : command.ReceivedUtc) },
            { "finishedUtc", Proto.UtcStamp(DateTime.UtcNow) },
        };
        if (!string.IsNullOrEmpty(error))
            response["error"] = error;
        return response;
    }

    void WriteSession()
    {
        var current = busy ?? pending;
        var info = new JObj
        {
            { "protocol", Proto.Version },
            { "agentVersion", Proto.AppVersion },
            { "session", SessionId },
            { "path", SessionDir },
            { "computer", Environment.MachineName },
            { "domain", computerDomain },
            { "user", Env.UserName },
            { "elevated", Env.Elevated },
            { "os", osName },
            { "clientName", Environment.GetEnvironmentVariable("CLIENTNAME") ?? "" },
            { "rdpSession", Environment.GetEnvironmentVariable("SESSIONNAME") ?? "" },
            { "started", Proto.UtcStamp(StartedUtc) },
            { "heartbeat", Proto.UtcStamp(DateTime.UtcNow) },
            { "state", State },
            { "busyCommand", current?.Id ?? "" },
            { "busyType", current?.Type ?? "" },
            { "progress", busy?.Context.Progress ?? "" },
            { "allowCode", AllowCode },
            { "confirm", ConfirmMode },
            { "headless", Headless },
            { "commandsDone", CommandsDone },
            { "pid", Process.GetCurrentProcess().Id },
        };
        File.WriteAllText(Path.Combine(SessionDir, "session.json"), Json.Write(info), Proto.Utf8);
        lastHeartbeat = clock.ElapsedMilliseconds;
        stateChanged = false;
    }

    static string SafeOsName()
    {
        try
        {
            return Env.OsName();
        }
        catch (Exception)
        {
            return Environment.OSVersion.VersionString;
        }
    }
}
