using System;
using System.Collections.Generic;
using System.Linq;

namespace RdpDiagBridge;

// 10.11.2026 Инструменты MCP: описание для агента Claude и выполнение через агента на удаленном компьютере.
public static class Tools
{
    public const string Instructions =
        "Мост диагностики удаленного компьютера через RDP. На удаленном компьютере в RDP-сеансе пользователь запускает агент "
        + "RdpDiagBridge.exe (\\\\tsclient\\C\\RdpDiagBridge\\agent), обмен идет файлами через диск C этого компьютера, "
        + "подключенный в RDP. Начинай с sessions: там видно, какой компьютер, под каким пользователем, есть ли права "
        + "администратора и что разрешено в окне агента. Для общего осмотра – health (сбои, BSOD, диски, SMART, память, "
        + "процессор, службы, падения программ, ошибки журналов, устройства, обновления, антивирус, сеть и домен, порты TCP, "
        + "RDS); дальше уточняй профильными инструментами: events, processes, services, disks, perf, network, nettest, software, "
        + "tasks, files, onec (1С: платформы, службы, rphost, srvinfo, техжурнал, дампы). Все они только читают. "
        + "powershell выполняет произвольный код и работает, только если пользователь включил это в окне агента; по умолчанию "
        + "каждый такой код пользователь видит и подтверждает – давай таким командам timeout побольше, а ответ без решения "
        + "забирай инструментом result. Изменения на удаленном компьютере (перезапуск служб, удаление файлов, настройки) – "
        + "только по явной просьбе пользователя на конкретное действие. Отказ без комментария – тот же запрос не повторяй, спроси "
        + "пользователя. Команда занимает агента: следующие ждут в очереди; долгие – с большим timeout или через result.";

    sealed class ToolDef
    {
        public string Name = "";
        public string Description = "";
        public JObj Properties = new JObj();
        public List<string> Required = new List<string>();
        public int Timeout = 60;
        public Func<JObj, string> Handler;
    }

    static readonly List<ToolDef> tools = Build();

    static JObj P(string type, string description, object def = null, object[] values = null, int? min = null, int? max = null)
    {
        var schema = new JObj { { "type", type }, { "description", description } };
        if (def != null)
            schema["default"] = def;
        if (values != null)
            schema["enum"] = values.ToList();
        if (min.HasValue)
            schema["minimum"] = min.Value;
        if (max.HasValue)
            schema["maximum"] = max.Value;
        return schema;
    }

    static JObj StrList(string description)
    {
        return new JObj { { "type", "array" }, { "items", new JObj { { "type", "string" } } }, { "description", description } };
    }

    static JObj IntList(string description)
    {
        return new JObj { { "type", "array" }, { "items", new JObj { { "type", "integer" } } }, { "description", description } };
    }

    static void Common(ToolDef tool, bool format = true)
    {
        tool.Properties["session"] = P("string", "Сеанс агента: идентификатор из sessions или часть имени компьютера, пользователя, RDP-клиента. "
                                                 + "Не указан – единственный работающий агент.");
        tool.Properties["timeout"] = P("integer", "Сколько секунд ждать ответ. Команда, которую агент не взял за это время, снимается; "
                                                  + "начатая выполняется дальше, ее результат – инструментом result.", tool.Timeout, null, 1, 280);
        if (format)
            tool.Properties["format"] = P("string", "text – сводки и таблицы; json – ответ агента как есть.", "text", new object[] { "text", "json" });
    }

    static ToolDef Remote(string name, string description, int timeout, Func<JObj, JObj> parameters, params KeyValuePair<string, JObj>[] properties)
    {
        var tool = new ToolDef { Name = name, Description = description, Timeout = timeout };
        foreach (var property in properties)
            tool.Properties[property.Key] = property.Value;
        Common(tool);
        tool.Handler = args => RunRemote(name, parameters(args), args, timeout);
        return tool;
    }

    static KeyValuePair<string, JObj> Arg(string name, JObj schema)
    {
        return new KeyValuePair<string, JObj>(name, schema);
    }

    // 10.11.2026 Параметры MCP (snake_case) – в параметры команды агента (camelCase), только переданные.
    static Func<JObj, JObj> Map(params string[] pairs)
    {
        return args =>
        {
            var result = new JObj();
            foreach (var pair in pairs)
            {
                var parts = pair.Split('=');
                var from = parts[0];
                var to = parts.Length > 1 ? parts[1] : parts[0];
                if (args.TryGetValue(from, out var value) && value != null)
                    result[to] = value;
            }
            return result;
        };
    }

    static List<ToolDef> Build()
    {
        var list = new List<ToolDef>();
        list.Add(new ToolDef
        {
            Name = "sessions",
            Description = "Работающие агенты моста: компьютер, пользователь, права администратора, Windows, RDP-клиент, состояние, "
                          + "разрешения в окне агента, расхождение часов. Агент пользователь запускает в RDP-сеансе на удаленном компьютере: "
                          + "\\\\tsclient\\C\\RdpDiagBridge\\agent\\RdpDiagBridge.exe.",
            Handler = _ =>
            {
                var note = Bridge.EnsureAgentCopy();
                return Bridge.Describe(Bridge.List()) + (note != "" ? "\n\n" + note : "");
            },
        });
        list.Add(Remote("ping", "Проверка связи с агентом: компьютер, пользователь, время, аптайм, расхождение часов.", 20, Map()));
        list.Add(Remote("health",
            "Общая проверка компьютера с находками по важности: аварийные выключения и BSOD, место и ошибки дисков, SMART, память и commit, "
            + "процессор, автозапускаемые службы, сбои служб, падения и зависания программ (1С отдельно), сводка ошибок журналов, "
            + "устройства с ошибками, неустановленные обновления, антивирус, домен/DNS/время, исчерпание портов TCP, лицензирование RDS. "
            + "Занимает 10-60 с.", 180,
            Map("hours", "days"),
            Arg("hours", P("integer", "За сколько часов смотреть ошибки журналов, сбои служб и программ.", 24, null, 1, 720)),
            Arg("days", P("integer", "За сколько дней смотреть аварийные выключения, ошибки дисков, обновления, антивирус.", 7, null, 1, 90))));
        list.Add(Remote("sysinfo", "Сведения о компьютере: Windows и сборка, аптайм, модель и виртуализация, процессор, память и файлы подкачки, "
                                   + "диски, пользователи (quser), адреса, версии .NET и PowerShell, сервер терминалов, антивирус, права агента.", 60, Map()));
        list.Add(Remote("events",
            "События журналов Windows с отбором. Уровни: critical, error, warning, info, all. group=true – сводка по источнику и коду "
            + "с числом, первым и последним временем. list_logs=true – список непустых журналов (contains – отбор по имени). Журнал Security "
            + "читается только агентом от администратора.", 90,
            Map("log", "level", "hours", "providers", "ids", "contains", "max", "group", "max_message=maxMessage", "scan_limit=scanLimit", "list_logs=listLogs"),
            Arg("log", StrList("Журналы: System, Application, Security, Setup или полное имя (Microsoft-Windows-TerminalServices-LocalSessionManager/Operational). По умолчанию System.")),
            Arg("level", StrList("Уровни: critical, error, warning, info, all. По умолчанию critical и error.")),
            Arg("hours", P("number", "За сколько часов.", 24)),
            Arg("providers", StrList("Источники (точное имя провайдера).")),
            Arg("ids", IntList("Коды событий.")),
            Arg("contains", P("string", "Подстрока в тексте события (без учета регистра); с list_logs – отбор по имени журнала.")),
            Arg("max", P("integer", "Сколько событий или групп вернуть.", 50, null, 1, 2000)),
            Arg("group", P("boolean", "Сгруппировать по журналу, источнику и коду.", false)),
            Arg("max_message", P("integer", "Предел длины текста события.", 500, null, 50, 20000)),
            Arg("scan_limit", P("integer", "Сколько событий просмотреть при contains или group.", 5000, null, 100, 50000)),
            Arg("list_logs", P("boolean", "Вместо событий – список журналов.", false))));
        list.Add(Remote("processes",
            "Процессы: загрузка процессора за замер, рабочий набор и частная память, дескрипторы, потоки, сеанс, время запуска. "
            + "details=true – командная строка, путь и владелец (для показанных строк).", 60,
            Map("sort", "top", "name", "details", "sample_ms=sampleMs"),
            Arg("sort", P("string", "Сортировка.", "cpu", new object[] { "cpu", "memory", "handles", "name", "start" })),
            Arg("top", P("integer", "Сколько процессов показать.", 30, null, 1, 1000)),
            Arg("name", P("string", "Отбор по имени: подстрока или шаблон с * и ?.")),
            Arg("details", P("boolean", "Командная строка, путь, владелец.", false)),
            Arg("sample_ms", P("integer", "Длительность замера процессора, мс (0 – без замера).", 1000, null, 0, 10000))));
        list.Add(Remote("services",
            "Службы Windows. filter: problem (по умолчанию – автозапускаемые, но не работающие, кроме запуска по триггеру, и зависшие в "
            + "Start/Stop Pending), all, running, stopped, auto. name – подстрока или шаблон по имени, отображаемому имени или пути.", 60,
            Map("filter", "name"),
            Arg("filter", P("string", "Отбор.", "problem", new object[] { "problem", "all", "running", "stopped", "auto" })),
            Arg("name", P("string", "Подстрока или шаблон с * и ?."))));
        list.Add(Remote("disks",
            "Диски: тома и свободное место, физические диски и их состояние, SMART (нужны права администратора), замер задержек "
            + "чтения/записи, загрузки и очереди, ошибки дисков в журнале System за days.", 60,
            Map("days", "sample_ms=sampleMs"),
            Arg("days", P("integer", "За сколько дней ошибки дисков.", 7, null, 1, 90)),
            Arg("sample_ms", P("integer", "Длительность замера задержек, мс.", 2000, null, 500, 10000))));
        list.Add(Remote("perf",
            "Замер производительности за seconds: процессор и очередь, доступная память, подкачка, commit, сеть по адаптерам, "
            + "задержки и загрузка дисков, процессы с наибольшей загрузкой процессора за замер.", 90,
            Map("seconds", "top"),
            Arg("seconds", P("integer", "Длительность замера.", 5, null, 1, 60)),
            Arg("top", P("integer", "Сколько процессов показать.", 10, null, 1, 50))));
        list.Add(Remote("network",
            "Сеть: адаптеры (адреса, шлюзы, DNS, DHCP), соединения TCP по состояниям и процессам, занятость динамических портов, "
            + "слушающие порты с процессами, прокси (пользователя, WinHTTP, фактический), hosts, профили брандмауэра. connections=true – "
            + "список соединений (filter – процесс, адрес или порт).", 60,
            Map("connections", "filter", "max"),
            Arg("connections", P("boolean", "Добавить список соединений.", false)),
            Arg("filter", P("string", "Отбор соединений: имя процесса, адрес или порт.")),
            Arg("max", P("integer", "Предел списка соединений.", 300, null, 1, 5000))));
        list.Add(Remote("nettest",
            "Проверка доступности с удаленного компьютера: для каждого узла – DNS и ping; узел:порт – еще TCP-подключение; "
            + "http(s)://… – запрос с кодом ответа, временем, прокси и сертификатом. Пример: [\"srv1c:1541\", \"10.0.0.5\", \"https://ofd.ru\"].", 90,
            Map("targets", "timeout_ms=timeoutMs", "ping_count=pingCount"),
            Arg("targets", StrList("Узлы, узел:порт или URL, до 30.")),
            Arg("timeout_ms", P("integer", "Таймаут каждой проверки, мс.", 3000, null, 200, 30000)),
            Arg("ping_count", P("integer", "Сколько ping (0 – без ping).", 2, null, 0, 10))));
        list.Add(Remote("software",
            "Установленные программы (отбор name, recent=true – последние установленные первыми); updates=true – обновления Windows "
            + "(Win32_QuickFixEngineering); history=N – последние N записей журнала Windows Update с результатом.", 90,
            Map("name", "recent", "updates", "history", "max"),
            Arg("name", P("string", "Подстрока или шаблон по названию или издателю.")),
            Arg("recent", P("boolean", "Сортировать по дате установки.", false)),
            Arg("updates", P("boolean", "Список установленных обновлений.", false)),
            Arg("history", P("integer", "Записей журнала Windows Update.", 0, null, 0, 1000)),
            Arg("max", P("integer", "Предел списков.", 200, null, 1, 5000))));
        list.Add(Remote("tasks",
            "Задания планировщика: по умолчанию только с ошибкой последнего запуска и без папки \\Microsoft – резервные копии, обмены, "
            + "регламенты. Время, код результата с расшифровкой, учетная запись, действие.", 60,
            Map("name", "failed_only=failedOnly", "include_microsoft=includeMicrosoft", "max"),
            Arg("name", P("string", "Отбор по пути задания.")),
            Arg("failed_only", P("boolean", "Только с ошибкой последнего запуска.", true)),
            Arg("include_microsoft", P("boolean", "Включить задания \\Microsoft.", false)),
            Arg("max", P("integer", "Предел списка.", 200, null, 1, 5000))));
        list.Add(Remote("files",
            "Файлы на удаленном компьютере (только чтение). action: list – содержимое каталога (pattern, sort time/name/size); tail – "
            + "последние lines строк текстового файла (кодировка определяется, contains – отбор); grep – строки файла с text "
            + "(regex=true – регулярное выражение), последние max совпадений; find – поиск файлов pattern в path рекурсивно (days – "
            + "изменены за N дней); sizes – размеры вложенных папок. Переменные среды в path раскрываются (%TEMP%).", 120,
            Map("action", "path", "pattern", "sort", "max", "lines", "contains", "text", "regex", "days", "budget_sec=budgetSec", "max_line=maxLine"),
            Arg("action", P("string", "Действие.", "list", new object[] { "list", "tail", "grep", "find", "sizes" })),
            Arg("path", P("string", "Каталог или файл.")),
            Arg("pattern", P("string", "Шаблон имен для list и find.", "*")),
            Arg("sort", P("string", "Сортировка list.", "time", new object[] { "time", "name", "size" })),
            Arg("max", P("integer", "Предел списка или совпадений.", 200, null, 1, 10000)),
            Arg("lines", P("integer", "Строк для tail.", 100, null, 1, 10000)),
            Arg("contains", P("string", "Отбор строк tail по подстроке.")),
            Arg("text", P("string", "Что искать в grep.")),
            Arg("regex", P("boolean", "text – регулярное выражение.", false)),
            Arg("days", P("number", "find: изменены за N дней (0 – любые).", 0)),
            Arg("budget_sec", P("integer", "Предел времени обхода для find и sizes, с.", 30, null, 1, 250)),
            Arg("max_line", P("integer", "Предел длины строки tail.", 2000, null, 50, 100000))));
        list.Add(Remote("onec",
            "1С на удаленном компьютере: установленные платформы, службы (агент сервера, RAS, хранилище, HASP, СУБД, веб-сервер) "
            + "с портами и каталогом кластера, процессы ragent/rmngr/rphost (память, процессор, дескрипторы), слушающие порты, srvinfo "
            + "(размер, крупнейшие папки баз, snccntx), техжурнал (logcfg.xml и размер логов), дампы, файлы лицензий, список баз "
            + "пользователя (ibases.v8i), 1CEStart.cfg, события 1С в журнале Application.", 120,
            Map("hours", "budget_sec=budgetSec"),
            Arg("hours", P("integer", "За сколько часов события 1С.", 24, null, 1, 720)),
            Arg("budget_sec", P("integer", "Предел времени подсчета размеров папок (0 – не считать).", 20, null, 0, 200))));
        list.Add(Remote("powershell",
            "Выполняет код Windows PowerShell 5.1 на удаленном компьютере отдельным процессом от имени пользователя агента. Работает, "
            + "только если в окне агента включено «Разрешить команды PowerShell»; по умолчанию пользователь видит код и подтверждает "
            + "его, поэтому timeout бери с запасом. output=text – вывод как в консоли (ошибки тоже), json – результат через "
            + "ConvertTo-Json -Depth 4. Код, меняющий систему, – только по явной просьбе пользователя.", 120,
            Map("code", "output", "max_chars=maxChars"),
            Arg("code", P("string", "Код PowerShell.")),
            Arg("output", P("string", "Формат вывода.", "text", new object[] { "text", "json" })),
            Arg("max_chars", P("integer", "Предел вывода, символов.", 200000, null, 1000, 5000000))));
        list.Last().Required.Add("code");
        list.First(t => t.Name == "nettest").Required.Add("targets");
        list.First(t => t.Name == "files").Required.Add("path");
        list.Add(new ToolDef
        {
            Name = "result",
            Description = "Результат команды, которая не уложилась в свой timeout или ждала решения пользователя в окне агента.",
            Properties = new JObj
            {
                { "command_id", P("string", "Идентификатор команды.") },
                { "wait", P("integer", "Сколько секунд подождать, если команда еще идет.", 30, null, 0, 280) },
                { "format", P("string", "text или json.", "text", new object[] { "text", "json" }) },
            },
            Required = new List<string> { "command_id" },
            Handler = ResultTool,
        });
        list.Add(new ToolDef
        {
            Name = "cancel",
            Description = "Снимает команду из очереди или прерывает выполняемую (для powershell процесс снимается) и отзывает запрос, "
                          + "ждущий решения пользователя.",
            Properties = new JObj { { "command_id", P("string", "Идентификатор команды.") } },
            Required = new List<string> { "command_id" },
            Handler = CancelTool,
        });
        return list;
    }

    public static List<object> ListForMcp()
    {
        return tools.Select(t =>
        {
            var schema = new JObj { { "type", "object" }, { "properties", t.Properties } };
            if (t.Required.Count > 0)
                schema["required"] = t.Required;
            return (object)new JObj { { "name", t.Name }, { "description", t.Description }, { "inputSchema", schema } };
        }).ToList();
    }

    public static string Call(string name, JObj args)
    {
        var tool = tools.FirstOrDefault(t => t.Name == name) ?? throw new ToolError("Нет инструмента " + name);
        return tool.Handler(args ?? new JObj());
    }

    static string RunRemote(string kind, JObj parameters, JObj args, int defaultTimeout)
    {
        var timeout = (int)Math.Max(1, Math.Min(280, args.Num("timeout") ?? defaultTimeout));
        var format = args.Str("format", "text");
        var target = Bridge.Find(args.Str("session"));
        var id = Bridge.Submit(target, kind, parameters, timeout);
        var status = Bridge.Wait(target.Path, id, timeout, out var response);
        if (status == "timeout")
        {
            if (Bridge.Withdraw(target.Path, id))
            {
                var current = Bridge.Current(target.Path);
                throw new ToolError("Агент не взял команду за " + timeout + " с, команда снята и выполняться не будет. Сеанс "
                                    + target.Sid + ": " + (current != null ? Bridge.StateText(current) : "каталог сеанса удален") + ".");
            }
            response = Bridge.Take(target.Path, id);
            if (response == null)
            {
                var current = Bridge.Current(target.Path);
                if (current != null && current.State == "awaiting" && current.Info.Str("busyCommand") == id)
                    return "Команда " + id + " ждет решения пользователя в окне агента на удаленном компьютере. Ответ – инструментом "
                           + "result(command_id=\"" + id + "\").";
                return "Команда " + id + " выполняется дольше " + timeout + " с. Результат – инструментом result(command_id=\"" + id
                       + "\"), прервать – cancel.";
            }
        }
        else if (status == "closed")
        {
            throw new ToolError("Агент закрыт во время ожидания (каталог сеанса " + target.Sid + " удален). Команда " + id
                                + " могла выполниться без ответа.");
        }
        return Render.Response(kind, response, format, id);
    }

    static string ResultTool(JObj args)
    {
        var id = args.Str("command_id").Trim();
        var wait = (int)Math.Max(0, Math.Min(280, args.Num("wait") ?? 30));
        var kind = Bridge.KindOf(id);
        var format = args.Str("format", "text");
        var cached = Bridge.Cached(id);
        if (cached != null)
            return Render.Response(kind != "" ? kind : cached.Str("type"), cached, format, id);
        var path = Bridge.Locate(id) ?? throw new ToolError("Команда " + id + " не найдена: ответ уже забран и забыт или агент закрыт.");
        var status = Bridge.Wait(path, id, wait, out var response);
        if (status == "done")
            return Render.Response(kind != "" ? kind : response.Str("type"), response, format, id);
        var state = Bridge.State(path, id);
        if (state == "closed")
            throw new ToolError("Агент закрыт: каталог сеанса удален, результата не будет.");
        if (state == "queued")
            return "Команда " + id + " еще в очереди: агент занят другой командой или приостановлен.";
        var current = Bridge.Current(path);
        if (current != null && current.State == "awaiting" && current.Info.Str("busyCommand") == id)
            return "Команда " + id + " еще ждет решения пользователя в окне агента.";
        return "Команда " + id + " еще выполняется" + (current != null && current.Info.Str("progress") != "" ? ": " + current.Info.Str("progress") : "") + ".";
    }

    static string CancelTool(JObj args)
    {
        var id = args.Str("command_id").Trim();
        var path = Bridge.Locate(id);
        if (path == null)
            return "Команда " + id + " не найдена.";
        if (Bridge.Withdraw(path, id))
            return "Команда " + id + " снята из очереди и выполняться не будет.";
        var state = Bridge.State(path, id);
        if (state == "running")
        {
            Bridge.RequestCancel(path, id);
            var status = Bridge.Wait(path, id, 10, out var response);
            if (status == "done")
                return "Команда " + id + ": " + (response.Str("status") == "cancelled" ? "прервана" : "успела завершиться, результат – инструментом result") + ".";
            return "Запрос на прерывание команды " + id + " отправлен, агент пока не ответил.";
        }
        return state == "done" ? "Команда " + id + " уже выполнена, результат – инструментом result." : "Команда " + id + ": " + state + ".";
    }
}
