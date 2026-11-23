using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace RdpDiagBridge;

// 10.11.2026 MCP-сервер по stdio: JSON-RPC 2.0, сообщение – одна строка JSON. Вызовы инструментов идут параллельно
// (ожидание ответа агента длится до 280 с), запись в stdout – под блокировкой.
public static class McpServer
{
    static readonly object writeLock = new object();
    static StreamWriter output;
    static readonly string[] knownVersions = { "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25" };

    public static int Run()
    {
        var input = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
        output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };
        ThreadPool.QueueUserWorkItem(_ => Bridge.EnsureAgentCopy());
        string line;
        while ((line = input.ReadLine()) != null)
        {
            if (line.Trim() == "")
                continue;
            JObj message;
            try
            {
                message = Json.ParseObject(line);
            }
            catch (Exception ex)
            {
                SendError(null, -32700, "Parse error: " + ex.Message);
                continue;
            }
            try
            {
                Handle(message);
            }
            catch (Exception ex)
            {
                if (message.ContainsKey("id"))
                    SendError(message.Get("id"), -32603, ex.Message);
            }
        }
        return 0;
    }

    static void Handle(JObj message)
    {
        var method = message.Str("method");
        var hasId = message.ContainsKey("id");
        var id = message.Get("id");
        if (method == "")
            return;
        var parameters = message.Obj("params") ?? new JObj();
        switch (method)
        {
            case "initialize":
                var requested = parameters.Str("protocolVersion");
                Send(id, new JObj
                {
                    { "protocolVersion", Array.IndexOf(knownVersions, requested) >= 0 ? requested : "2025-06-18" },
                    { "capabilities", new JObj { { "tools", new JObj { { "listChanged", false } } } } },
                    { "serverInfo", new JObj { { "name", "rdp-diag-bridge" }, { "version", Proto.AppVersion } } },
                    { "instructions", Tools.Instructions },
                });
                return;
            case "ping":
                Send(id, new JObj());
                return;
            case "tools/list":
                Send(id, new JObj { { "tools", Tools.ListForMcp() } });
                return;
            case "tools/call":
                ThreadPool.QueueUserWorkItem(_ => Send(id, CallTool(parameters)));
                return;
            default:
                if (method.StartsWith("notifications/", StringComparison.Ordinal) || !hasId)
                    return;
                SendError(id, -32601, "Method not found: " + method);
                return;
        }
    }

    public static JObj CallTool(JObj parameters)
    {
        var name = parameters.Str("name");
        var args = parameters.Obj("arguments") ?? new JObj();
        string text;
        var isError = false;
        try
        {
            text = Tools.Call(name, args);
        }
        catch (ToolError ex)
        {
            text = ex.Message;
            isError = true;
        }
        catch (Exception ex)
        {
            text = "Ошибка моста: " + ex;
            isError = true;
        }
        return new JObj
        {
            { "content", new List<object> { new JObj { { "type", "text" }, { "text", text } } } },
            { "isError", isError },
        };
    }

    static void Send(object id, JObj result)
    {
        Write(new JObj { { "jsonrpc", "2.0" }, { "id", id }, { "result", result } });
    }

    static void SendError(object id, int code, string text)
    {
        Write(new JObj { { "jsonrpc", "2.0" }, { "id", id }, { "error", new JObj { { "code", code }, { "message", text } } } });
    }

    static void Write(JObj message)
    {
        var text = Json.Write(message);
        lock (writeLock)
            output.WriteLine(text);
    }
}
