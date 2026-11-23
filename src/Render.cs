using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace RdpDiagBridge;

// 10.11.2026 Ответ агента – в текст для агента Claude: таблицы и сводки вместо сырого JSON.
public static class Render
{
    const int MaxChars = 40000;
    static readonly Regex isoDate = new Regex(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", RegexOptions.CultureInvariant);

    public static string Response(string kind, JObj response, string format, string commandId)
    {
        if (format == "json")
            return Fit(Json.Write(response), commandId);
        var status = response.Str("status");
        var error = response.Str("error");
        var comment = response.Str("comment");
        switch (status)
        {
            case "ok":
                break;
            case "denied":
                return "Пользователь отклонил команду в окне агента."
                       + (comment != "" ? "\nКомментарий пользователя: " + comment
                           : " Комментария нет: тот же запрос не повторяй, спроси пользователя.");
            case "rejected":
                return "Агент отказал: " + error;
            case "cancelled":
                return "Команда прервана: " + error;
            case "expired":
                return "Агент не выполнил команду: она ждала в очереди дольше срока (" + error + ").";
            default:
                var details = response.Str("errorDetails");
                return "Ошибка на удаленном компьютере: " + error
                       + (details != "" ? "\n\n" + Txt.Clip(details, 3000) : "");
        }
        var sb = new StringBuilder();
        var result = response.Get("result");
        var resultObj = result as JObj;
        switch (kind)
        {
            case "health":
                HealthText(sb, resultObj);
                break;
            case "events":
                EventsText(sb, resultObj);
                break;
            case "powershell":
                PowerShellText(sb, resultObj);
                break;
            case "files" when resultObj != null && (resultObj.Get("lines") != null || resultObj.Get("matches") != null):
                FileLinesText(sb, resultObj);
                break;
            default:
                Value(sb, null, result, 0);
                break;
        }
        foreach (var warning in response.Arr("warnings") ?? new List<object>())
            sb.Append("\nВнимание: ").Append(warning);
        if (kind == "health" || kind == "ping")
            sb.Append(SkewLine(response, commandId));
        return Fit(sb.ToString().TrimEnd(), commandId);
    }

    // 10.11.2026 Расхождение часов по времени передачи команды: агент берет команду в пределах 0,5 с.
    static string SkewLine(JObj response, string commandId)
    {
        var sent = Bridge.SentOf(commandId);
        var received = Proto.ParseUtc(response.Str("receivedUtc"));
        if (!sent.HasValue || !received.HasValue)
            return "";
        var skew = (received.Value - sent.Value).TotalSeconds;
        if (Math.Abs(skew) < 3)
            return "\nЧасы удаленного компьютера совпадают с этим компьютером (расхождение меньше 3 с).";
        return "\nЧасы удаленного компьютера: " + (skew > 0 ? "+" : "") + Txt.Num(Math.Round(skew)) + " с относительно этого компьютера (оценка по времени передачи команды, ±1 с).";
    }

    public static string Fit(string text, string commandId)
    {
        if (text.Length <= MaxChars)
            return text;
        try
        {
            Directory.CreateDirectory(Bridge.ResultsDir);
            var file = Path.Combine(Bridge.ResultsDir, (commandId ?? DateTime.Now.ToString("yyyyMMddHHmmss")) + ".txt");
            File.WriteAllText(file, text, Encoding.UTF8);
            return text.Substring(0, MaxChars) + "\n…\nОтвет обрезан: " + text.Length + " символов. Полностью – в файле " + file;
        }
        catch (Exception ex)
        {
            return text.Substring(0, MaxChars) + "\n…\nОтвет обрезан (" + text.Length + " символов), файл не записан: " + ex.Message;
        }
    }

    static void HealthText(StringBuilder sb, JObj result)
    {
        if (result == null)
            return;
        var summary = result.Obj("summary") ?? new JObj();
        sb.Append("Компьютер ").Append(result.Str("computer")).Append(", проверка ").Append(Scalar(result.Get("checkedAt")))
            .Append(" (журналы за ").Append(result.Str("hours")).Append(" ч, сбои и обновления за ").Append(result.Str("days")).Append(" дн.)")
            .Append(result.Bool("elevated") ? "" : ", агент без прав администратора").Append('\n');
        sb.Append("Итог: критично ").Append(summary.Str("critical", "0")).Append(", внимание ").Append(summary.Str("warning", "0"))
            .Append(", сведения ").Append(summary.Str("info", "0")).Append("\n");
        foreach (var item in (result.Arr("findings") ?? new List<object>()).OfType<JObj>())
        {
            var level = item.Str("level") switch { "critical" => "КРИТИЧНО", "warning" => "ВНИМАНИЕ", _ => "сведения" };
            sb.Append('\n').Append('[').Append(level).Append("] ").Append(item.Str("area")).Append(": ").Append(item.Str("title")).Append('\n');
            foreach (var detail in item.Arr("details") ?? new List<object>())
                sb.Append("    ").Append(detail).Append('\n');
        }
        var checks = (result.Arr("checks") ?? new List<object>()).OfType<JObj>().ToList();
        var notes = checks.Where(c => c.Str("status") != "ok").Select(c => c.Str("check") + " – " + c.Str("status")).ToList();
        var totalMs = checks.Sum(c => c.Num("ms") ?? 0);
        sb.Append("\nПроверок: ").Append(checks.Count).Append(", ").Append(Txt.Num(Txt.Round(totalMs / 1000))).Append(" с");
        if (notes.Count > 0)
            sb.Append("\nНе все проверено: ").Append(string.Join("; ", notes));
        sb.Append('\n');
    }

    static void EventsText(StringBuilder sb, JObj result)
    {
        if (result == null)
            return;
        if (result.Get("logs") is List<object> logList && logList.Count > 0 && logList[0] is JObj)
        {
            Value(sb, null, result, 0);
            return;
        }
        sb.Append("Журналы: ").Append(string.Join(", ", (result.Arr("logs") ?? new List<object>()).Select(x => x.ToString())))
            .Append("; уровни: ").Append(string.Join(", ", (result.Arr("levels") ?? new List<object>()).Select(x => x.ToString())))
            .Append("; с ").Append(Scalar(result.Get("since"))).Append("; просмотрено событий: ").Append(result.Str("scanned"))
            .Append(result.Bool("scanLimitReached") ? " (достигнут предел просмотра, scanLimit)" : "").Append('\n');
        if (result.Get("groups") is List<object> groups)
        {
            sb.Append("Групп: ").Append(result.Str("groupCount")).Append(groups.Count < (int)(result.Num("groupCount") ?? 0) ? ", показаны первые " + groups.Count : "").Append('\n');
            foreach (var group in groups.OfType<JObj>())
                sb.Append('\n').Append(group.Str("count")).Append(" × ").Append(group.Str("log")).Append(" / ").Append(group.Str("provider"))
                    .Append(' ').Append(group.Str("id")).Append(" (").Append(group.Str("level")).Append("), последнее ")
                    .Append(Scalar(group.Get("last"))).Append(", первое ").Append(Scalar(group.Get("first"))).Append("\n    ")
                    .Append(group.Str("message")).Append('\n');
            return;
        }
        var events = result.Arr("events") ?? new List<object>();
        sb.Append("Найдено: ").Append(result.Str("matched")).Append(events.Count < (int)(result.Num("matched") ?? 0) ? ", показаны последние " + events.Count : "").Append('\n');
        foreach (var item in events.OfType<JObj>())
            sb.Append('\n').Append(Scalar(item.Get("time"))).Append(' ').Append(item.Str("level")).Append(' ').Append(item.Str("log"))
                .Append(" / ").Append(item.Str("provider")).Append(' ').Append(item.Str("id")).Append("\n    ").Append(item.Str("message")).Append('\n');
    }

    static void PowerShellText(StringBuilder sb, JObj result)
    {
        if (result == null)
            return;
        sb.Append("Код выхода ").Append(result.Str("exitCode")).Append(", ").Append(result.Str("seconds")).Append(" с, от имени ")
            .Append(result.Str("user")).Append(result.Bool("truncated") ? ", вывод обрезан (maxChars)" : "").Append('\n');
        var output = result.Str("output");
        sb.Append(output == "" ? "(вывода нет)" : output).Append('\n');
        var errors = result.Str("errors");
        if (errors != "")
            sb.Append("\nПоток ошибок (stderr):\n").Append(errors).Append('\n');
    }

    static void FileLinesText(StringBuilder sb, JObj result)
    {
        foreach (var pair in result)
            if (pair.Key != "lines" && pair.Key != "matches")
                sb.Append(pair.Key).Append(": ").Append(Scalar(pair.Value)).Append('\n');
        sb.Append('\n');
        foreach (var line in result.Arr("lines") ?? new List<object>())
            sb.Append(line).Append('\n');
        foreach (var match in (result.Arr("matches") ?? new List<object>()).OfType<JObj>())
            sb.Append(match.Str("line")).Append(": ").Append(match.Str("text")).Append('\n');
    }

    public static string Scalar(object value)
    {
        switch (value)
        {
            case null:
                return "–";
            case bool flag:
                return flag ? "да" : "нет";
            case double number:
                return number.ToString("0.##", CultureInfo.InvariantCulture);
            case string text when isoDate.IsMatch(text):
                return text.Replace('T', ' ');
            case JObj or IList:
                return Txt.Clip(Json.Write(value), 300);
            default:
                return Convert.ToString(value, CultureInfo.InvariantCulture);
        }
    }

    static bool IsScalar(object value)
    {
        return value is not JObj && value is not IList;
    }

    public static void Value(StringBuilder sb, string key, object value, int indent)
    {
        var pad = new string(' ', indent);
        if (value is JObj obj)
        {
            if (key != null)
                sb.Append(pad).Append(key).Append(":\n");
            foreach (var pair in obj)
                Value(sb, pair.Key, pair.Value, key != null ? indent + 2 : indent);
            return;
        }
        if (value is IList list)
        {
            var label = key ?? "";
            if (list.Count == 0)
            {
                sb.Append(pad).Append(label).Append(": (нет)\n");
                return;
            }
            if (list.Cast<object>().All(x => x is JObj))
            {
                sb.Append(pad).Append(label).Append(" (").Append(list.Count).Append("):\n");
                Table(sb, list.Cast<JObj>().ToList(), indent + 2);
                return;
            }
            if (list.Cast<object>().All(IsScalar))
            {
                var items = list.Cast<object>().Select(Scalar).ToList();
                var joined = string.Join(", ", items);
                if (joined.Length <= 120 && items.All(i => !i.Contains(", ")))
                {
                    sb.Append(pad).Append(label).Append(": ").Append(joined).Append('\n');
                    return;
                }
                sb.Append(pad).Append(label).Append(":\n");
                foreach (var item in items)
                    sb.Append(pad).Append("  ").Append(item).Append('\n');
                return;
            }
            sb.Append(pad).Append(label).Append(":\n");
            foreach (var item in list)
                Value(sb, "-", item, indent + 2);
            return;
        }
        sb.Append(pad).Append(key ?? "").Append(key != null ? ": " : "").Append(Scalar(value)).Append('\n');
    }

    // 10.11.2026 Однородные записи: короткие – таблицей, с длинными полями – блоками.
    static void Table(StringBuilder sb, List<JObj> rows, int indent)
    {
        var pad = new string(' ', indent);
        // 10.11.2026 Вложенные таблицы в ячейку не помещаются – каждую запись выводим отдельным блоком.
        if (rows.Any(r => r.Values.Any(v => v is IList nested && nested.Cast<object>().Any(x => x is JObj))))
        {
            foreach (var row in rows)
                Value(sb, "-", row, indent);
            return;
        }
        var columns = new List<string>();
        foreach (var row in rows)
        foreach (var key in row.Keys)
            if (!columns.Contains(key))
                columns.Add(key);
        var cells = rows.Select(r => columns.Select(c => Cell(r.Get(c))).ToArray()).ToList();
        var widths = columns.Select((c, i) => Math.Max(c.Length, cells.Max(row => row[i].Length))).ToArray();
        if (widths.Max() <= 60 && widths.Sum() + 3 * columns.Count <= 200)
        {
            sb.Append(pad).Append(string.Join(" | ", columns.Select((c, i) => c.PadRight(widths[i]))).TrimEnd()).Append('\n');
            foreach (var row in cells)
                sb.Append(pad).Append(string.Join(" | ", row.Select((c, i) => c.PadRight(widths[i]))).TrimEnd()).Append('\n');
            return;
        }
        foreach (var row in cells)
        {
            var shortParts = new List<string>();
            var longParts = new List<string>();
            for (var i = 0; i < columns.Count; i++)
            {
                if (row[i] == "" || row[i] == "–")
                    continue;
                if (row[i].Length <= 80)
                    shortParts.Add(columns[i] + ": " + row[i]);
                else
                    longParts.Add(columns[i] + ": " + row[i]);
            }
            sb.Append(pad).Append("- ").Append(string.Join("; ", shortParts)).Append('\n');
            foreach (var part in longParts)
                sb.Append(pad).Append("    ").Append(part).Append('\n');
        }
    }

    static string Cell(object value)
    {
        if (value is IList list && list.Cast<object>().All(IsScalar))
            return Txt.OneLine(string.Join(", ", list.Cast<object>().Select(Scalar)), 2000);
        if (value is JObj obj && obj.Values.All(IsScalar))
            return Txt.OneLine(string.Join(", ", obj.Select(p => p.Key + "=" + Scalar(p.Value))), 2000);
        return Txt.OneLine(Scalar(value), 2000);
    }
}
