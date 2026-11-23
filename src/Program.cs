using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: AssemblyTitle("Мост диагностики RDP")]
[assembly: AssemblyDescription("Агент диагностики удаленного компьютера через RDP и MCP-сервер для Claude")]
[assembly: AssemblyProduct("RdpDiagBridge")]
[assembly: AssemblyVersion("1.0.1.0")]
[assembly: AssemblyFileVersion("1.0.1.0")]

namespace RdpDiagBridge;

// 10.11.2026 Точка входа. Без ключей – агент с окном (на удаленном компьютере); --mcp – MCP-сервер по stdio
// (на компьютере с Claude); --call – один вызов инструмента из командной строки; --headless – агент без окна.
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var options = ParseOptions(args);
        if (options.TryGetValue("--dir", out var dir) && dir != "")
            Bridge.RootOverride = dir;
        if (options.ContainsKey("--mcp"))
            return McpServer.Run();
        if (options.ContainsKey("--call"))
            return CallFromCommandLine(options);
        if (options.ContainsKey("--version"))
        {
            Console.Out.WriteLine(Proto.AppVersion);
            return 0;
        }
        var core = new AgentCore
        {
            AllowCode = options.ContainsKey("--allow-code"),
            ConfirmMode = options.TryGetValue("--confirm", out var confirm) && (confirm == "all" || confirm == "none") ? confirm : "code",
            Headless = options.ContainsKey("--headless"),
        };
        var root = string.IsNullOrEmpty(dir) ? DefaultAgentRoot() : dir;
        if (core.Headless)
        {
            core.Start(root);
            while (!core.StopRequested)
                Thread.Sleep(300);
            core.Stop();
            return 0;
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.ThreadException += (_, e) => MessageBox.Show(e.Exception.ToString(), "Мост диагностики RDP", MessageBoxButtons.OK, MessageBoxIcon.Error);
        core.Start(root);
        Application.Run(new AgentForm(core));
        return 0;
    }

    public static string AgentArguments(string root, bool allowCode, string confirm)
    {
        var text = "--dir \"" + root.TrimEnd('\\') + "\"";
        if (allowCode)
            text += " --allow-code";
        if (confirm != "code")
            text += " --confirm " + confirm;
        return text;
    }

    // 10.11.2026 Агент лежит в <корень>\agent – корень обмена рядом; иначе диск C компьютера с Claude через RDP.
    static string DefaultAgentRoot()
    {
        try
        {
            var exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) ?? "";
            if (string.Equals(Path.GetFileName(exeDir), "agent", StringComparison.OrdinalIgnoreCase))
            {
                var parent = Path.GetDirectoryName(exeDir);
                if (parent != null && Directory.Exists(parent))
                    return parent;
            }
            if (Directory.Exists(Proto.TsclientRoot))
                return Proto.TsclientRoot;
        }
        catch (Exception)
        {
        }
        return "";
    }

    static int CallFromCommandLine(Dictionary<string, string> options)
    {
        var name = options["--call"];
        JObj args;
        if (options.TryGetValue("--args-file", out var argsFile))
            args = Json.ParseObject(File.ReadAllText(argsFile, Encoding.UTF8));
        else if (options.TryGetValue("--args", out var argsText))
            args = Json.ParseObject(argsText);
        else
            args = new JObj();
        var result = McpServer.CallTool(new JObj { { "name", name }, { "arguments", args } });
        var content = (List<object>)result["content"];
        var text = ((JObj)content[0]).Str("text");
        var isError = result.Bool("isError");
        if (isError)
            text = "ОШИБКА: " + text;
        if (options.TryGetValue("--out", out var outFile))
            File.WriteAllText(outFile, text, new UTF8Encoding(true));
        else
            Console.Out.WriteLine(text);
        return isError ? 1 : 0;
    }

    static Dictionary<string, string> ParseOptions(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i++)
        {
            var key = args[i];
            if (!key.StartsWith("--", StringComparison.Ordinal))
                continue;
            var value = i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal) ? args[++i] : "";
            options[key] = value;
        }
        return options;
    }
}
