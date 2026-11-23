using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace RdpDiagBridge;

// 10.11.2026 Общее для агента и MCP-сервера: протокол обмена файлами, см. docs\protocol.md.
public static class Proto
{
    public const int Version = 1;
    public const string AppVersion = "1.0.2";
    public const string ExeName = "RdpDiagBridge.exe";
    // 10.11.2026 Каталог обмена на компьютере с Claude; из RDP-сеанса он виден как \\tsclient\C\RdpDiagBridge.
    public const string DefaultRoot = @"C:\RdpDiagBridge";
    public const string TsclientRoot = @"\\tsclient\C\RdpDiagBridge";
    public static readonly Encoding Utf8 = new UTF8Encoding(false);
    public static readonly Regex SessionName = new Regex("^[0-9a-f]{8}$", RegexOptions.CultureInvariant);
    static readonly Random random = new Random();

    public static string NewSessionId()
    {
        lock (random)
            return random.Next(0x10000000, int.MaxValue).ToString("x8", CultureInfo.InvariantCulture);
    }

    public static string NewCommandId()
    {
        int suffix;
        lock (random)
            suffix = random.Next(0, 0x10000);
        return DateTime.UtcNow.ToString("yyyyMMdd'T'HHmmssfff", CultureInfo.InvariantCulture) + "-"
            + suffix.ToString("x4", CultureInfo.InvariantCulture);
    }

    public static string UtcStamp(DateTime utc)
    {
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
    }

    public static DateTime? ParseUtc(string text)
    {
        if (string.IsNullOrEmpty(text))
            return null;
        if (DateTime.TryParse(text, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var value))
            return value;
        return null;
    }

    // 10.11.2026 Запись без промежуточного состояния: читатель видит либо старый файл, либо новый целиком.
    public static void WriteAtomic(string path, string text)
    {
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, text, Utf8);
        if (File.Exists(path))
            File.Delete(path);
        File.Move(temporary, path);
    }

    // 10.11.2026 Файл может быть занят или переписываться другой стороной – несколько попыток.
    public static string ReadText(string path, int attempts)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return File.ReadAllText(path, Encoding.UTF8);
            }
            catch (FileNotFoundException)
            {
                return null;
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (Exception) when (attempt < attempts)
            {
                Thread.Sleep(50);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    public static JObj ReadJson(string path, int attempts)
    {
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            var text = ReadText(path, 3);
            if (text == null)
                return null;
            try
            {
                return Json.ParseObject(text);
            }
            catch (FormatException)
            {
                // 10.11.2026 Попали на файл, который другая сторона переписывает на месте.
                Thread.Sleep(50);
            }
        }
        return null;
    }

    // 10.11.2026 Удаляет только каталог сеанса с именем из 8 hex и только известные файлы в нем, без рекурсивного
    // удаления: корень обмена может быть общим с другими программами.
    public static void RemoveSessionDir(string dir)
    {
        if (string.IsNullOrEmpty(dir))
            return;
        var name = Path.GetFileName(dir.TrimEnd('\\', '/'));
        if (!SessionName.IsMatch(name) || !Directory.Exists(dir))
            return;
        foreach (var box in new[] { "in", "work", "out" })
        {
            var boxDir = Path.Combine(dir, box);
            if (!Directory.Exists(boxDir))
                continue;
            foreach (var file in SafeFiles(boxDir))
            {
                var extension = Path.GetExtension(file).ToLowerInvariant();
                if (extension == ".json" || extension == ".tmp" || extension == ".cancel")
                    TryDelete(file);
            }
            TryRemoveDir(boxDir);
        }
        foreach (var file in new[] { "session.json", "session.json.tmp", "stop" })
            TryDelete(Path.Combine(dir, file));
        TryRemoveDir(dir);
    }

    static string[] SafeFiles(string dir)
    {
        try
        {
            return Directory.GetFiles(dir);
        }
        catch (Exception)
        {
            return new string[0];
        }
    }

    public static void TryDelete(string file)
    {
        try
        {
            if (File.Exists(file))
                File.Delete(file);
        }
        catch (Exception)
        {
        }
    }

    static void TryRemoveDir(string dir)
    {
        try
        {
            Directory.Delete(dir, false);
        }
        catch (Exception)
        {
        }
    }
}

// 10.11.2026 Форматирование текста и чисел для ответов.
public static class Txt
{
    static readonly Regex spaces = new Regex(@"\s+", RegexOptions.CultureInvariant);

    public static string OneLine(string text, int max)
    {
        if (string.IsNullOrEmpty(text))
            return "";
        return Clip(spaces.Replace(text, " ").Trim(), max);
    }

    public static string Clip(string text, int max)
    {
        if (string.IsNullOrEmpty(text) || max <= 0 || text.Length <= max)
            return text ?? "";
        return text.Substring(0, max) + "…";
    }

    public static double Round(double value, int digits = 1)
    {
        return Math.Round(value, digits, MidpointRounding.AwayFromZero);
    }

    public static double Gb(double bytes)
    {
        return Round(bytes / 1073741824.0, 1);
    }

    public static double Mb(double bytes)
    {
        return Round(bytes / 1048576.0, 1);
    }

    public static string Duration(TimeSpan span)
    {
        if (span.TotalDays >= 1)
            return string.Format(CultureInfo.InvariantCulture, "{0} дн. {1} ч", (int)span.TotalDays, span.Hours);
        if (span.TotalHours >= 1)
            return string.Format(CultureInfo.InvariantCulture, "{0} ч {1} мин", (int)span.TotalHours, span.Minutes);
        return string.Format(CultureInfo.InvariantCulture, "{0} мин", (int)span.TotalMinutes);
    }

    public static string Hex(long code)
    {
        return "0x" + ((uint)code).ToString("X8", CultureInfo.InvariantCulture);
    }

    public static string Num(double value)
    {
        return value.ToString("0.#", CultureInfo.InvariantCulture);
    }

    // 10.11.2026 Шаблон с * и ? или подстрока – в регулярное выражение без учета регистра.
    public static Regex Wildcard(string pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return null;
        pattern = pattern.Trim();
        if (pattern.IndexOfAny(new[] { '*', '?' }) < 0)
            return new Regex(Regex.Escape(pattern), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var expression = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
        return new Regex(expression, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}

// 10.11.2026 Параметры команды из JSON с проверкой границ.
public sealed class Params
{
    readonly JObj data;

    public Params(JObj data)
    {
        this.data = data ?? new JObj();
    }

    public string Str(string key, string def = "")
    {
        var value = data.Get(key);
        return value == null ? def : Convert.ToString(value, CultureInfo.InvariantCulture);
    }

    public int Int(string key, int def, int min, int max)
    {
        var number = data.Num(key);
        var value = number.HasValue ? (int)Math.Round(number.Value) : def;
        return Math.Max(min, Math.Min(max, value));
    }

    public double Dbl(string key, double def, double min, double max)
    {
        var number = data.Num(key) ?? def;
        return Math.Max(min, Math.Min(max, number));
    }

    public bool Bool(string key, bool def)
    {
        return data.Bool(key, def);
    }

    public List<string> List(string key)
    {
        var value = data.Get(key);
        var result = new List<string>();
        if (value is List<object> items)
        {
            foreach (var item in items)
                if (item != null && Convert.ToString(item, CultureInfo.InvariantCulture).Trim().Length > 0)
                    result.Add(Convert.ToString(item, CultureInfo.InvariantCulture).Trim());
        }
        else if (value != null)
        {
            foreach (var part in Convert.ToString(value, CultureInfo.InvariantCulture).Split(',', ';'))
                if (part.Trim().Length > 0)
                    result.Add(part.Trim());
        }
        return result;
    }

    public List<int> IntList(string key)
    {
        var result = new List<int>();
        foreach (var item in List(key))
            if (int.TryParse(item, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number))
                result.Add(number);
        return result;
    }
}

// 10.11.2026 Реестр: 64-битное представление на 64-битной Windows независимо от разрядности процесса.
public static class Reg
{
    public static RegistryKey Lm()
    {
        return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,
            Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Default);
    }

    public static object Value(RegistryKey baseKey, string path, string name)
    {
        try
        {
            using var key = baseKey.OpenSubKey(path);
            return key?.GetValue(name);
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static bool KeyExists(RegistryKey baseKey, string path)
    {
        try
        {
            using var key = baseKey.OpenSubKey(path);
            return key != null;
        }
        catch (Exception)
        {
            return false;
        }
    }
}

// 10.11.2026 Сведения о процессе агента и учетной записи.
public static class Env
{
    public static readonly bool Elevated = DetectElevated();
    public static readonly string UserName = DetectUser();

    static bool DetectElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception)
        {
            return false;
        }
    }

    static string DetectUser()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.Name;
        }
        catch (Exception)
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }
    }

    public static string OsName()
    {
        using var lm = Reg.Lm();
        var product = Reg.Value(lm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName") as string ?? "Windows";
        var build = Reg.Value(lm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild") as string ?? "";
        var ubr = Reg.Value(lm, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
        // 10.11.2026 Windows 11 в реестре по-прежнему называет себя Windows 10 – уточняем по номеру сборки.
        if (int.TryParse(build, out var buildNumber) && buildNumber >= 22000 && product.StartsWith("Windows 10"))
            product = "Windows 11" + product.Substring("Windows 10".Length);
        return product + " (сборка " + build + (ubr != null ? "." + ubr : "") + ")";
    }

    // 10.11.2026 Запуск консольной программы с захватом вывода в кодировке OEM (quser, netsh).
    public static string RunConsole(string file, string arguments, int timeoutMs)
    {
        var info = new ProcessStartInfo(file, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = OemEncoding(),
            StandardErrorEncoding = OemEncoding(),
        };
        using var process = Process.Start(info);
        var output = process.StandardOutput.ReadToEndAsyncSafe();
        var error = process.StandardError.ReadToEndAsyncSafe();
        if (!process.WaitForExit(timeoutMs))
        {
            try
            {
                process.Kill();
            }
            catch (Exception)
            {
            }
            return output.Result + error.Result + "\n(прервано по времени)";
        }
        return (output.Result + error.Result).Trim();
    }

    public static Encoding OemEncoding()
    {
        try
        {
            return Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        }
        catch (Exception)
        {
            return Encoding.Default;
        }
    }
}

// 10.11.2026 Чтение потока целиком в отдельном потоке: Task.Run и ReadToEndAsync из .NET 4.5 не используем.
public sealed class PendingText
{
    readonly Thread thread;
    string text = "";

    public PendingText(StreamReader reader)
    {
        thread = new Thread(() =>
        {
            try
            {
                text = reader.ReadToEnd();
            }
            catch (Exception)
            {
            }
        }) { IsBackground = true };
        thread.Start();
    }

    public string Result
    {
        get
        {
            thread.Join(5000);
            return text;
        }
    }
}

public static class StreamReaderExtensions
{
    public static PendingText ReadToEndAsyncSafe(this StreamReader reader)
    {
        return new PendingText(reader);
    }
}

// 10.11.2026 Отказ выполнять команду (не ошибка выполнения): неизвестная команда, нет разрешения.
public sealed class RejectedException : Exception
{
    public RejectedException(string message) : base(message) { }
}

// 10.11.2026 Ошибка, текст которой отдается агенту Claude как есть.
public sealed class ToolError : Exception
{
    public ToolError(string message) : base(message) { }
}

public static class Linq2
{
    public static IEnumerable<T> Safe<T>(Func<IEnumerable<T>> source)
    {
        try
        {
            return source().ToList();
        }
        catch (Exception)
        {
            return Enumerable.Empty<T>();
        }
    }
}
