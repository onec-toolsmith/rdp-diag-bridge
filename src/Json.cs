using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace RdpDiagBridge;

// 10.11.2026 Объект JSON: поля выводятся в порядке добавления.
public sealed class JObj : Dictionary<string, object>
{
    public JObj() : base(StringComparer.Ordinal) { }

    public object Get(string key)
    {
        return TryGetValue(key, out var value) ? value : null;
    }

    public string Str(string key, string def = "")
    {
        var value = Get(key);
        return value == null ? def : Convert.ToString(value, CultureInfo.InvariantCulture);
    }

    public JObj Obj(string key)
    {
        return Get(key) as JObj;
    }

    public List<object> Arr(string key)
    {
        return Get(key) as List<object>;
    }

    public bool Bool(string key, bool def = false)
    {
        var value = Get(key);
        if (value is bool flag)
            return flag;
        if (value is string text && bool.TryParse(text, out var parsed))
            return parsed;
        return def;
    }

    public double? Num(string key)
    {
        var value = Get(key);
        if (value == null || value is bool)
            return null;
        if (value is string text)
            return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;
        try
        {
            return Convert.ToDouble(value, CultureInfo.InvariantCulture);
        }
        catch (Exception)
        {
            return null;
        }
    }
}

// 10.11.2026 Массив JSON.
public sealed class JArr : List<object>
{
}

// 10.11.2026 Разбор и запись JSON без внешних библиотек: .NET Framework 4.5 есть в любой поддерживаемой Windows.
public static class Json
{
    public static object Parse(string text)
    {
        var parser = new Parser(text ?? "");
        parser.SkipSpace();
        var value = parser.ReadValue();
        parser.SkipSpace();
        if (!parser.AtEnd)
            throw new FormatException("Лишние символы после JSON в позиции " + parser.Position);
        return value;
    }

    public static JObj ParseObject(string text)
    {
        return Parse(text) as JObj ?? throw new FormatException("Ожидался объект JSON");
    }

    public static string Write(object value)
    {
        var builder = new StringBuilder(1024);
        WriteValue(builder, value, 0);
        return builder.ToString();
    }

    static void WriteValue(StringBuilder sb, object value, int depth)
    {
        switch (value)
        {
            case null:
            case DBNull:
                sb.Append("null");
                return;
            case string text:
                WriteString(sb, text);
                return;
            case bool flag:
                sb.Append(flag ? "true" : "false");
                return;
            case int or long or short or byte or sbyte or uint or ulong or ushort:
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            case double number:
                WriteDouble(sb, number);
                return;
            case float number:
                WriteDouble(sb, number);
                return;
            case decimal number:
                sb.Append(number.ToString(CultureInfo.InvariantCulture));
                return;
            case DateTime moment:
                WriteString(sb, moment.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture));
                return;
            case TimeSpan span:
                WriteString(sb, span.ToString());
                return;
            case Enum or Guid or Version or char:
                WriteString(sb, value.ToString());
                return;
        }
        if (depth > 40)
        {
            WriteString(sb, value.ToString());
            return;
        }
        if (value is IDictionary dictionary)
        {
            sb.Append('{');
            var first = true;
            foreach (DictionaryEntry entry in dictionary)
            {
                if (!first)
                    sb.Append(',');
                first = false;
                WriteString(sb, Convert.ToString(entry.Key, CultureInfo.InvariantCulture));
                sb.Append(':');
                WriteValue(sb, entry.Value, depth + 1);
            }
            sb.Append('}');
            return;
        }
        if (value is IEnumerable sequence)
        {
            sb.Append('[');
            var first = true;
            foreach (var item in sequence)
            {
                if (!first)
                    sb.Append(',');
                first = false;
                WriteValue(sb, item, depth + 1);
            }
            sb.Append(']');
            return;
        }
        WriteString(sb, value.ToString());
    }

    static void WriteDouble(StringBuilder sb, double number)
    {
        if (double.IsNaN(number) || double.IsInfinity(number))
            sb.Append("null");
        else
            sb.Append(number.ToString("R", CultureInfo.InvariantCulture));
    }

    static void WriteString(StringBuilder sb, string text)
    {
        sb.Append('"');
        foreach (var ch in text)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                default:
                    if (ch < 0x20 || ch == (char)0x2028 || ch == (char)0x2029)
                        sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else
                        sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
    }

    sealed class Parser
    {
        readonly string s;
        int i;

        public Parser(string text)
        {
            s = text;
            // 10.11.2026 Файл с BOM прочитан как текст – отбрасываем метку.
            if (s.Length > 0 && s[0] == '﻿')
                i = 1;
        }

        public bool AtEnd => i >= s.Length;
        public int Position => i;

        public void SkipSpace()
        {
            while (i < s.Length && char.IsWhiteSpace(s[i]))
                i++;
        }

        public object ReadValue()
        {
            if (i >= s.Length)
                throw new FormatException("Неожиданный конец JSON");
            var ch = s[i];
            switch (ch)
            {
                case '{': return ReadObject();
                case '[': return ReadArray();
                case '"': return ReadString();
                case 't': Expect("true"); return true;
                case 'f': Expect("false"); return false;
                case 'n': Expect("null"); return null;
                default: return ReadNumber();
            }
        }

        void Expect(string word)
        {
            if (string.CompareOrdinal(s, i, word, 0, word.Length) != 0)
                throw new FormatException("Ошибка JSON в позиции " + i);
            i += word.Length;
        }

        JObj ReadObject()
        {
            var result = new JObj();
            i++;
            SkipSpace();
            if (i < s.Length && s[i] == '}')
            {
                i++;
                return result;
            }
            while (true)
            {
                SkipSpace();
                if (i >= s.Length || s[i] != '"')
                    throw new FormatException("Ожидалось имя поля в позиции " + i);
                var key = ReadString();
                SkipSpace();
                if (i >= s.Length || s[i] != ':')
                    throw new FormatException("Ожидалось «:» в позиции " + i);
                i++;
                SkipSpace();
                result[key] = ReadValue();
                SkipSpace();
                if (i < s.Length && s[i] == ',')
                {
                    i++;
                    continue;
                }
                if (i < s.Length && s[i] == '}')
                {
                    i++;
                    return result;
                }
                throw new FormatException("Ожидалось «,» или «}» в позиции " + i);
            }
        }

        List<object> ReadArray()
        {
            var result = new List<object>();
            i++;
            SkipSpace();
            if (i < s.Length && s[i] == ']')
            {
                i++;
                return result;
            }
            while (true)
            {
                SkipSpace();
                result.Add(ReadValue());
                SkipSpace();
                if (i < s.Length && s[i] == ',')
                {
                    i++;
                    continue;
                }
                if (i < s.Length && s[i] == ']')
                {
                    i++;
                    return result;
                }
                throw new FormatException("Ожидалось «,» или «]» в позиции " + i);
            }
        }

        string ReadString()
        {
            i++;
            var sb = new StringBuilder();
            while (i < s.Length)
            {
                var ch = s[i++];
                if (ch == '"')
                    return sb.ToString();
                if (ch != '\\')
                {
                    sb.Append(ch);
                    continue;
                }
                if (i >= s.Length)
                    break;
                var esc = s[i++];
                switch (esc)
                {
                    case '"': sb.Append('"'); break;
                    case '\\': sb.Append('\\'); break;
                    case '/': sb.Append('/'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case 'u':
                        if (i + 4 > s.Length)
                            throw new FormatException("Обрезанная последовательность \\u");
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default:
                        throw new FormatException("Неизвестная escape-последовательность в позиции " + i);
                }
            }
            throw new FormatException("Незакрытая строка JSON");
        }

        object ReadNumber()
        {
            var start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0)
                i++;
            if (start == i)
                throw new FormatException("Неожиданный символ «" + s[i] + "» в позиции " + i);
            var token = s.Substring(start, i - start);
            if (token.IndexOfAny(new[] { '.', 'e', 'E' }) < 0
                && long.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out var whole))
                return whole;
            return double.Parse(token, NumberStyles.Float, CultureInfo.InvariantCulture);
        }
    }
}
