using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace RdpDiagBridge;

// 10.11.2026 Окно агента: сеанс и каталог обмена, разрешения, решение по запросам, журнал команд.
// 23.11.2026 Переделано: состояние и номер сеанса вверху, журнал таблицей (одна строка на команду), запрос на
// выполнение кода – отдельной панелью. Размеры заданы для 96 точек на дюйм, форма сама пересчитывает их под экран.
public sealed class AgentForm : Form
{
    const float DesignDpi = 96F;

    static readonly bool Contrast = SystemInformation.HighContrast;
    static readonly Color Muted = Contrast ? SystemColors.GrayText : Color.FromArgb(100, 100, 100);
    static readonly Color Hairline = Contrast ? SystemColors.ControlDark : Color.FromArgb(222, 222, 222);
    static readonly Color LinkBlue = Contrast ? SystemColors.HotTrack : Color.FromArgb(0, 102, 204);
    static readonly Color NoticeBack = Contrast ? SystemColors.Info : Color.FromArgb(255, 244, 206);
    static readonly Color NoticeEdge = Contrast ? SystemColors.ControlDark : Color.FromArgb(232, 200, 112);
    static readonly Color ErrorText = Contrast ? SystemColors.WindowText : Color.FromArgb(176, 32, 32);
    static readonly Color Green = Color.FromArgb(46, 160, 67);
    static readonly Color Blue = Color.FromArgb(30, 127, 214);
    static readonly Color Amber = Color.FromArgb(230, 160, 0);
    static readonly Color Red = Color.FromArgb(209, 52, 56);
    static readonly Color Gray = Color.FromArgb(150, 150, 150);
    static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    // 23.11.2026 Значки строк журнала – по порядку в списке изображений.
    static readonly string[] RowIcons = { "none", "running", "ok", "error", "waiting", "stopped" };
    static readonly Color[] RowColors = { Color.Transparent, Blue, Green, Red, Amber, Gray };

    // 23.11.2026 Во сколько раз экран плотнее расчетных 96 точек на дюйм.
    static readonly float ScreenScale = MeasureScreenScale();

    readonly AgentCore core;
    readonly ToolTip tips = new ToolTip();
    readonly Dictionary<string, ListViewItem> rows = new Dictionary<string, ListViewItem>();
    readonly Timer timer = new Timer { Interval = 500 };
    readonly StatusDot dot = new StatusDot { Size = new Size(12, 12), Anchor = AnchorStyles.None, Margin = new Padding(0, 1, 9, 0) };
    readonly Label stateLabel = EllipsisLabel(6);
    readonly Label whoLabel = EllipsisLabel(4);
    readonly Label sessionValue = new Label
    {
        AutoSize = true, UseMnemonic = false, Margin = Padding.Empty, Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
    };
    readonly LinkLabel copyLink = Link("Копировать номер");
    readonly Label dirValue = EllipsisLabel(12);
    readonly LinkLabel dirLink = Link("Изменить…");
    readonly Label adminValue = EllipsisLabel(12);
    readonly Button elevateButton = Push("Перезапустить от администратора");
    readonly CheckBox codeCheck = new CheckBox { Text = "Разрешить команды PowerShell", AutoSize = true, Margin = new Padding(0, 2, 0, 0) };
    readonly ComboBox confirmBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 230, Margin = new Padding(6, 3, 0, 3) };
    readonly CheckBox pauseCheck = new CheckBox
    {
        Text = "Пауза – новые команды ждут в очереди", AutoSize = true, Margin = new Padding(0, 4, 0, 0),
    };
    readonly Panel pendingPanel = new Panel
    {
        Dock = DockStyle.Fill, Margin = new Padding(16, 14, 16, 0), Padding = new Padding(1), Visible = false,
    };
    readonly Label pendingTitle = new Label
    {
        AutoSize = false, Dock = DockStyle.Fill, Height = 30, Margin = Padding.Empty, Padding = new Padding(9, 0, 0, 0),
        TextAlign = ContentAlignment.MiddleLeft, UseMnemonic = false,
    };
    readonly TextBox pendingText = new TextBox
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill,
        BorderStyle = BorderStyle.None, Margin = new Padding(10, 8, 2, 2), Font = new Font("Consolas", 9.75F),
    };
    readonly TextBox commentBox = new TextBox { Anchor = AnchorStyles.Left | AnchorStyles.Right, Margin = new Padding(2, 3, 10, 3) };
    readonly Button allowButton = Push("Выполнить");
    readonly Button denyButton = Push("Отклонить");
    readonly BufferedListView logView = new BufferedListView
    {
        Dock = DockStyle.Fill, Margin = new Padding(16, 0, 16, 0), View = View.Details, FullRowSelect = true,
        MultiSelect = false, HideSelection = true, HeaderStyle = ColumnHeaderStyle.Nonclickable, ShowItemToolTips = true,
        BorderStyle = BorderStyle.FixedSingle,
    };
    readonly Label countLabel = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = Padding.Empty };
    readonly Button cancelButton = Push("Прервать команду");
    readonly Button closeButton = Push("Закрыть");
    TableLayoutPanel root;
    SectionHeader logHeader;
    Command shownPending;
    bool closingWithoutQuestion;
    bool fittingColumns;
    int copiedUntil;

    public AgentForm(AgentCore core)
    {
        this.core = core;

        // 23.11.2026 Пересчет размеров под экран срабатывает на ResumeLayout, поэтому масштаб задается после
        // SuspendLayout: иначе форма пересчитает себя пустой, а добавленные позже элементы останутся как есть.
        SuspendLayout();
        AutoScaleDimensions = new SizeF(DesignDpi, DesignDpi);
        AutoScaleMode = AutoScaleMode.Dpi;
        Text = "Мост диагностики RDP";
        Font = SystemFonts.MessageBoxFont;
        BackColor = SystemColors.Window;
        ForeColor = SystemColors.WindowText;
        ClientSize = new Size(760, 660);
        MinimumSize = new Size(640, 580);
        StartPosition = FormStartPosition.CenterScreen;
        var icon = LoadIcon();
        if (icon != null)
            Icon = icon;
        BuildLayout();
        ResumeLayout(true);

        codeCheck.Checked = core.AllowCode;
        confirmBox.Items.AddRange(new object[] { "перед кодом PowerShell", "перед каждой командой", "не спрашивать" });
        confirmBox.SelectedIndex = core.ConfirmMode == "all" ? 1 : core.ConfirmMode == "none" ? 2 : 0;
        adminValue.Text = Env.Elevated
            ? "Администратор"
            : "Обычные: журнал Security и SMART недоступны";
        tips.SetToolTip(adminValue, Env.Elevated
            ? "Доступны журнал Security, SMART и данные всех процессов."
            : "Без прав администратора недоступны журнал Security, SMART и часть сведений о процессах.");
        elevateButton.Visible = !Env.Elevated;
        cancelButton.Enabled = false;

        codeCheck.CheckedChanged += (_, _) =>
        {
            core.AllowCode = codeCheck.Checked;
            core.Log(codeCheck.Checked ? "Команды PowerShell разрешены" : "Команды PowerShell запрещены");
        };
        confirmBox.SelectedIndexChanged += (_, _) =>
        {
            core.ConfirmMode = confirmBox.SelectedIndex == 1 ? "all" : confirmBox.SelectedIndex == 2 ? "none" : "code";
            core.Log("Спрашивать разрешение: " + confirmBox.Text);
        };
        pauseCheck.CheckedChanged += (_, _) => core.Paused = pauseCheck.Checked;
        copyLink.LinkClicked += (_, _) => CopySession();
        dirLink.LinkClicked += (_, _) => ChangeDir();
        elevateButton.Click += (_, _) => Elevate();
        allowButton.Click += (_, _) => Decide(true);
        denyButton.Click += (_, _) => Decide(false);
        cancelButton.Click += (_, _) => core.CancelCurrent();
        closeButton.Click += (_, _) => Close();
        logView.ClientSizeChanged += (_, _) => FitColumns();
        // 23.11.2026 Щит UAC на кнопке и подсказка в пустом поле комментария – сообщениями Windows.
        elevateButton.HandleCreated += (_, _) => Native.SendMessage(elevateButton.Handle, Native.BCM_SETSHIELD, IntPtr.Zero, (IntPtr)1);
        commentBox.HandleCreated += (_, _) =>
            Native.SendMessage(commentBox.Handle, Native.EM_SETCUEBANNER, (IntPtr)1, "Комментарий для Claude, необязательно");
        timer.Tick += (_, _) => RefreshView();
        timer.Start();
        RefreshView();
    }

    // 23.11.2026 Высота надписи – высота шрифта плюс запас; явную высоту у растянутой по ячейке надписи задавать
    // нельзя: при пересчете под масштаб экрана она умножается несколько раз.
    static Label EllipsisLabel(int extraHeight)
    {
        return new OneLineLabel
        {
            AutoSize = true, Dock = DockStyle.Fill, Margin = Padding.Empty, UseMnemonic = false, ExtraHeight = Px(extraHeight),
        };
    }

    static LinkLabel Link(string text)
    {
        return new LinkLabel
        {
            Text = text, AutoSize = true, Anchor = AnchorStyles.Right, Margin = new Padding(12, 0, 0, 0),
            LinkColor = LinkBlue, ActiveLinkColor = LinkBlue, VisitedLinkColor = LinkBlue,
            DisabledLinkColor = SystemColors.GrayText, LinkBehavior = LinkBehavior.HoverUnderline,
        };
    }

    static Button Push(string text)
    {
        return new Button
        {
            Text = text, FlatStyle = FlatStyle.System, AutoSize = true, MinimumSize = new Size(92, 26),
            Anchor = AnchorStyles.Right, Margin = new Padding(8, 0, 0, 0),
        };
    }

    static TableLayoutPanel Grid(int columns, int rows, Padding margin)
    {
        var grid = new TableLayoutPanel
        {
            ColumnCount = columns, RowCount = rows, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill, Margin = margin,
        };
        for (var i = 0; i < rows; i++)
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        return grid;
    }

    static void Columns(TableLayoutPanel grid, params int[] percents)
    {
        // 23.11.2026 Ноль – столбец по содержимому, иначе доля ширины.
        foreach (var percent in percents)
            grid.ColumnStyles.Add(percent == 0 ? new ColumnStyle(SizeType.AutoSize) : new ColumnStyle(SizeType.Percent, percent));
    }

    static Panel Rule(Padding margin)
    {
        return new Panel { Height = 1, Dock = DockStyle.Fill, Margin = margin, BackColor = Hairline };
    }

    static Label Caption(string text)
    {
        return new Label { Text = text, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 0, 18, 0), ForeColor = Muted };
    }

    // 23.11.2026 Полужирного Segoe UI нет в очень старых Windows – тогда обычный жирный.
    static Font Semibold(float size)
    {
        var font = new Font("Segoe UI Semibold", size);
        if (font.Name == "Segoe UI Semibold")
            return font;
        font.Dispose();
        return new Font(SystemFonts.MessageBoxFont.FontFamily, size, FontStyle.Bold);
    }

    static Icon LoadIcon()
    {
        try
        {
            using var stream = typeof(AgentForm).Assembly.GetManifestResourceStream("app.ico");
            return stream != null ? new Icon(stream) : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    static float MeasureScreenScale()
    {
        using var g = Graphics.FromHwnd(IntPtr.Zero);
        return g.DpiX / DesignDpi;
    }

    static int Px(int designPixels)
    {
        return (int)Math.Round(designPixels * ScreenScale);
    }

    void BuildLayout()
    {
        root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 10, Margin = Padding.Empty };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 10; i++)
            root.RowStyles.Add(i == 7 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
        Controls.Add(root);
        var heading = Semibold(9F);
        root.Controls.Add(BuildHeader(), 0, 0);
        root.Controls.Add(Rule(new Padding(16, 0, 16, 0)), 0, 1);
        root.Controls.Add(BuildProperties(), 0, 2);
        root.Controls.Add(new SectionHeader("Разрешения", heading, Hairline) { Margin = new Padding(16, 12, 16, 4) }, 0, 3);
        root.Controls.Add(BuildPermissions(), 0, 4);
        root.Controls.Add(BuildPending(heading), 0, 5);
        logHeader = new SectionHeader("Журнал", heading, Hairline) { Margin = new Padding(16, 14, 16, 6) };
        root.Controls.Add(logHeader, 0, 6);
        BuildLog();
        root.Controls.Add(logView, 0, 7);
        root.Controls.Add(Rule(new Padding(0, 14, 0, 0)), 0, 8);
        root.Controls.Add(BuildFooter(), 0, 9);
    }

    Control BuildHeader()
    {
        var header = Grid(3, 2, new Padding(16, 14, 16, 12));
        Columns(header, 0, 100, 0);
        stateLabel.Font = new Font("Segoe UI", 12F);
        whoLabel.ForeColor = Muted;
        header.Controls.Add(dot, 0, 0);
        header.Controls.Add(stateLabel, 1, 0);
        header.Controls.Add(whoLabel, 1, 1);

        var session = Grid(2, 2, new Padding(16, 0, 0, 0));
        session.Dock = DockStyle.None;
        session.Anchor = AnchorStyles.Right;
        Columns(session, 0, 0);
        sessionValue.Font = new Font("Consolas", 15F);
        session.Controls.Add(new Label
        {
            Text = "Сеанс", AutoSize = true, ForeColor = Muted, Anchor = AnchorStyles.Bottom | AnchorStyles.Right,
            Margin = new Padding(0, 0, 4, 5),
        }, 0, 0);
        session.Controls.Add(sessionValue, 1, 0);
        copyLink.Margin = new Padding(0, 0, 3, 0);
        session.Controls.Add(copyLink, 0, 1);
        session.SetColumnSpan(copyLink, 2);
        header.Controls.Add(session, 2, 0);
        header.SetRowSpan(session, 2);
        return header;
    }

    Control BuildProperties()
    {
        var properties = Grid(3, 2, new Padding(16, 8, 16, 0));
        Columns(properties, 0, 100, 0);
        properties.Controls.Add(Caption("Каталог обмена"), 0, 0);
        properties.Controls.Add(dirValue, 1, 0);
        properties.Controls.Add(dirLink, 2, 0);
        properties.Controls.Add(Caption("Права"), 0, 1);
        properties.Controls.Add(adminValue, 1, 1);
        elevateButton.AutoSize = false;
        elevateButton.Size = new Size(250, 26);
        properties.Controls.Add(elevateButton, 2, 1);
        return properties;
    }

    Control BuildPermissions()
    {
        var permissions = Grid(1, 4, new Padding(16, 0, 16, 0));
        Columns(permissions, 100);
        var hint = new Label
        {
            AutoSize = true, Dock = DockStyle.Fill, ForeColor = Muted, UseMnemonic = false, Margin = new Padding(17, 0, 0, 8),
            Text = "Код запускается от имени " + Env.UserName + ". Остальные команды только читают и ничего не меняют.",
        };
        var confirmRow = new FlowLayoutPanel
        {
            AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false, Margin = Padding.Empty,
        };
        confirmRow.Controls.Add(new Label { Text = "Спрашивать разрешение", AutoSize = true, Margin = new Padding(0, 7, 0, 0) });
        confirmRow.Controls.Add(confirmBox);
        permissions.Controls.Add(codeCheck, 0, 0);
        permissions.Controls.Add(hint, 0, 1);
        permissions.Controls.Add(confirmRow, 0, 2);
        permissions.Controls.Add(pauseCheck, 0, 3);
        return permissions;
    }

    // 23.11.2026 Рамка панели запроса – фон самой панели, видный через отступ в одну точку.
    Control BuildPending(Font heading)
    {
        pendingPanel.BackColor = NoticeEdge;
        var inner = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = Padding.Empty, BackColor = SystemColors.Window,
        };
        inner.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        inner.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        inner.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        inner.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        inner.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pendingTitle.Font = heading;
        pendingTitle.BackColor = NoticeBack;
        pendingTitle.ForeColor = Contrast ? SystemColors.InfoText : Color.FromArgb(60, 45, 0);
        pendingText.BackColor = SystemColors.Window;
        inner.Controls.Add(pendingTitle, 0, 0);
        inner.Controls.Add(pendingText, 0, 1);
        inner.Controls.Add(Rule(Padding.Empty), 0, 2);
        var answer = Grid(3, 1, new Padding(8));
        Columns(answer, 100, 0, 0);
        answer.Controls.Add(commentBox, 0, 0);
        allowButton.Margin = Padding.Empty;
        answer.Controls.Add(allowButton, 1, 0);
        answer.Controls.Add(denyButton, 2, 0);
        inner.Controls.Add(answer, 0, 3);
        pendingPanel.Controls.Add(inner);
        return pendingPanel;
    }

    void BuildLog()
    {
        logView.Columns.Add("Время", 96);
        logView.Columns.Add("Команда", 120);
        logView.Columns.Add("Событие", 300);
        logView.Columns.Add("Длилась", 96, HorizontalAlignment.Right);
        var side = Px(16);
        var images = new ImageList { ImageSize = new Size(side, side), ColorDepth = ColorDepth.Depth32Bit };
        foreach (var color in RowColors)
        {
            var bitmap = new Bitmap(side, side);
            if (color != Color.Transparent)
            {
                using var g = Graphics.FromImage(bitmap);
                using var brush = new SolidBrush(color);
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                var d = side / 2F;
                g.FillEllipse(brush, (side - d) / 2F, (side - d) / 2F, d, d);
            }
            images.Images.Add(bitmap);
        }
        logView.SmallImageList = images;
    }

    Control BuildFooter()
    {
        var footer = Grid(3, 1, Padding.Empty);
        footer.Padding = new Padding(16, 10, 16, 10);
        footer.BackColor = SystemColors.Control;
        Columns(footer, 100, 0, 0);
        countLabel.ForeColor = Muted;
        footer.Controls.Add(countLabel, 0, 0);
        footer.Controls.Add(cancelButton, 1, 0);
        footer.Controls.Add(closeButton, 2, 0);
        return footer;
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        // 23.11.2026 Ширина столбцов и кнопки со щитом считается уже в точках экрана: сами они не масштабируются.
        logView.Columns[0].Width = Px(88);
        logView.Columns[1].Width = Px(120);
        logView.Columns[3].Width = Px(96);
        FitColumns();
        elevateButton.Width = TextRenderer.MeasureText(elevateButton.Text, elevateButton.Font).Width + Px(44);
        ActiveControl = logView;
    }

    // 23.11.2026 Столбец «Событие» занимает всю свободную ширину списка.
    void FitColumns()
    {
        if (fittingColumns || logView.Columns.Count < 4)
            return;
        fittingColumns = true;
        var width = logView.ClientSize.Width - logView.Columns[0].Width - logView.Columns[1].Width - logView.Columns[3].Width;
        width = Math.Max(width, Px(140));
        if (logView.Columns[2].Width != width)
            logView.Columns[2].Width = width;
        fittingColumns = false;
    }

    void SetText(Control control, string text)
    {
        if (control.Text == text)
            return;
        control.Text = text;
        tips.SetToolTip(control, text);
    }

    void RefreshView()
    {
        var state = core.State;
        SetText(stateLabel, core.StateText());
        dot.Color = core.LastError != "" || state == "nodir" ? Red
            : state == "awaiting" ? Amber
            : state == "busy" ? Blue
            : state == "paused" ? Gray
            : Green;
        SetText(whoLabel, "Компьютер " + Environment.MachineName + ", пользователь " + Env.UserName);
        sessionValue.Text = core.SessionId != "" ? core.SessionId : "–";
        copyLink.Enabled = core.SessionId != "";
        if (copiedUntil != 0 && Environment.TickCount - copiedUntil > 0)
        {
            copiedUntil = 0;
            copyLink.Text = "Копировать номер";
        }
        SetText(dirValue, (core.Root != "" ? core.Root : "не задан"));
        countLabel.Text = "Версия " + Proto.AppVersion + ". Выполнено команд: " + core.CommandsDone;

        while (core.LogQueue.TryDequeue(out var entry))
            ShowEntry(entry);
        var busy = core.Busy;
        if (busy != null && rows.TryGetValue(busy.Id, out var running))
        {
            var elapsed = Duration((DateTime.UtcNow - busy.ReceivedUtc).TotalSeconds, true);
            if (running.SubItems[3].Text != elapsed)
                running.SubItems[3].Text = elapsed;
        }

        var pending = core.Pending;
        if (pending != shownPending)
        {
            shownPending = pending;
            if (pending != null)
            {
                var isCode = pending.Type == "powershell";
                pendingTitle.Text = isCode ? "Выполнить этот код PowerShell?" : "Выполнить команду " + pending.Type + "?";
                pendingText.Text = isCode
                    ? pending.Params.Str("code").Replace("\r\n", "\n").Replace("\n", "\r\n")
                    : pending.Describe();
                pendingText.Select(0, 0);
                commentBox.Text = "";
                ShowPending(true);
                allowButton.Enabled = denyButton.Enabled = true;
                // 23.11.2026 Фокус – на тексте запроса, а не на кнопке: окно всплывает само, и случайный Enter или
                // пробел не должен ничего разрешить.
                ActiveControl = pendingText;
                Attention();
            }
            else
            {
                ShowPending(false);
            }
        }
        cancelButton.Enabled = busy != null;
    }

    // 23.11.2026 Пока запрос ждет решения, панель с кодом занимает место журнала: код нужно прочитать целиком,
    // а журнал для решения не нужен.
    void ShowPending(bool show)
    {
        root.SuspendLayout();
        pendingPanel.Visible = show;
        logHeader.Visible = !show;
        logView.Visible = !show;
        root.RowStyles[5] = show ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize);
        root.RowStyles[7] = show ? new RowStyle(SizeType.AutoSize) : new RowStyle(SizeType.Percent, 100);
        root.ResumeLayout(true);
    }

    // 23.11.2026 Новые строки – сверху. Команда, которая уже есть в журнале, обновляет свою строку.
    void ShowEntry(LogEntry entry)
    {
        ListViewItem item = null;
        if (entry.CommandId != "")
            rows.TryGetValue(entry.CommandId, out item);
        if (item == null)
        {
            item = new ListViewItem(entry.Time.ToString("HH:mm:ss", CultureInfo.InvariantCulture));
            item.SubItems.Add(entry.Command);
            item.SubItems.Add("");
            item.SubItems.Add("");
            logView.Items.Insert(0, item);
            while (logView.Items.Count > 500)
            {
                var last = logView.Items[logView.Items.Count - 1];
                foreach (var key in rows.Where(pair => pair.Value == last).Select(pair => pair.Key).ToList())
                    rows.Remove(key);
                logView.Items.RemoveAt(logView.Items.Count - 1);
            }
        }
        var finished = entry.Status != "waiting" && entry.Status != "running";
        if (entry.CommandId != "")
        {
            if (finished)
                rows.Remove(entry.CommandId);
            else
                rows[entry.CommandId] = item;
        }
        item.ImageIndex = Array.IndexOf(RowIcons, IconName(entry.Status));
        item.ForeColor = entry.Status == "error" ? ErrorText : entry.Status == "info" ? Muted : SystemColors.WindowText;
        item.SubItems[2].Text = entry.Text;
        item.SubItems[3].Text = entry.Seconds >= 0 ? Duration(entry.Seconds, false) : "";
        item.ToolTipText = entry.Text.Length > 60 ? entry.Text : "";
    }

    static string IconName(string status)
    {
        switch (status)
        {
            case "running": return "running";
            case "ok": return "ok";
            case "error": return "error";
            case "waiting": return "waiting";
            case "info": return "none";
            default: return "stopped";
        }
    }

    static string Duration(double seconds, bool whole)
    {
        if (seconds >= 60)
        {
            var total = (int)Math.Round(seconds);
            return total / 60 + " мин " + (total % 60).ToString("00", CultureInfo.InvariantCulture) + " с";
        }
        return (whole ? Math.Floor(seconds).ToString("0", Ru) : seconds.ToString("0.0", Ru)) + " с";
    }

    void CopySession()
    {
        if (core.SessionId == "")
            return;
        try
        {
            Clipboard.SetText(core.SessionId);
        }
        catch (ExternalException)
        {
            // 23.11.2026 Буфер обмена в RDP бывает занят – номер виден в окне, перепечатать недолго.
            return;
        }
        copyLink.Text = "Скопировано";
        copiedUntil = unchecked(Environment.TickCount + 1500);
        if (copiedUntil == 0)
            copiedUntil = 1;
    }

    void Attention()
    {
        if (WindowState == FormWindowState.Minimized)
            WindowState = FormWindowState.Normal;
        TopMost = true;
        TopMost = false;
        Activate();
    }

    void Decide(bool allow)
    {
        allowButton.Enabled = denyButton.Enabled = false;
        core.Decide(allow, commentBox.Text);
    }

    void ChangeDir()
    {
        using var dialog = new Form
        {
            Text = "Каталог обмена", FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent,
            MinimizeBox = false, MaximizeBox = false, ShowInTaskbar = false, Font = Font,
        };
        dialog.SuspendLayout();
        dialog.AutoScaleDimensions = new SizeF(DesignDpi, DesignDpi);
        dialog.AutoScaleMode = AutoScaleMode.Dpi;
        dialog.ClientSize = new Size(600, 128);
        var label = new Label
        {
            Text = "Каталог на компьютере с Claude, подключенный в RDP. Обычно " + Proto.TsclientRoot,
            AutoSize = true, Location = new Point(12, 14), UseMnemonic = false,
        };
        var box = new TextBox { Text = core.Root != "" ? core.Root : Proto.TsclientRoot, Location = new Point(12, 42), Width = 476 };
        var browse = new Button { Text = "Обзор…", FlatStyle = FlatStyle.System, Location = new Point(496, 40), Size = new Size(92, 26) };
        var ok = new Button
        {
            Text = "OK", FlatStyle = FlatStyle.System, DialogResult = DialogResult.OK, Location = new Point(396, 88), Size = new Size(92, 26),
        };
        var cancel = new Button
        {
            Text = "Отмена", FlatStyle = FlatStyle.System, DialogResult = DialogResult.Cancel, Location = new Point(496, 88),
            Size = new Size(92, 26),
        };
        browse.Click += (_, _) =>
        {
            using var folder = new FolderBrowserDialog { SelectedPath = box.Text };
            if (folder.ShowDialog(dialog) == DialogResult.OK)
                box.Text = folder.SelectedPath;
        };
        dialog.Controls.AddRange(new Control[] { label, box, browse, ok, cancel });
        dialog.ResumeLayout(true);
        dialog.AcceptButton = ok;
        dialog.CancelButton = cancel;
        if (dialog.ShowDialog(this) != DialogResult.OK || box.Text.Trim() == "")
            return;
        var error = core.ChangeRoot(box.Text.Trim());
        if (error != "")
            MessageBox.Show(this, error, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
    }

    void Elevate()
    {
        var info = new ProcessStartInfo(Application.ExecutablePath, Program.AgentArguments(core.Root, core.AllowCode, core.ConfirmMode))
        {
            UseShellExecute = true,
            Verb = "runas",
        };
        try
        {
            Process.Start(info);
        }
        catch (Win32Exception)
        {
            // 10.11.2026 Пользователь отказался в окне UAC – остаемся как есть.
            return;
        }
        closingWithoutQuestion = true;
        Close();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!closingWithoutQuestion && (core.Busy != null || core.Pending != null)
            && MessageBox.Show(this, "Агент выполняет команду или ждет решения. Закрыть?", Text, MessageBoxButtons.YesNo,
                MessageBoxIcon.Question) != DialogResult.Yes)
        {
            e.Cancel = true;
            return;
        }
        timer.Stop();
        core.Stop();
        base.OnFormClosing(e);
    }
}

// 23.11.2026 Надпись в одну строку: что не поместилось, обрезается многоточием (обычная Label переносит по словам).
sealed class OneLineLabel : Label
{
    public int ExtraHeight;

    public override Size GetPreferredSize(Size proposedSize)
    {
        return new Size(1, FontHeight + ExtraHeight);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        const TextFormatFlags flags = TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis | TextFormatFlags.VerticalCenter
                                      | TextFormatFlags.NoPrefix;
        TextRenderer.DrawText(e.Graphics, Text, Font, ClientRectangle, Enabled ? ForeColor : SystemColors.GrayText, flags);
    }
}

// 23.11.2026 Цветной кружок состояния агента.
sealed class StatusDot : Control
{
    Color color = Color.Gray;

    public StatusDot()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                 | ControlStyles.ResizeRedraw, true);
        TabStop = false;
    }

    public Color Color
    {
        get => color;
        set
        {
            if (color == value)
                return;
            color = value;
            Invalidate();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        e.Graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
        var d = Math.Min(Width, Height) - 1F;
        using var brush = new SolidBrush(color);
        e.Graphics.FillEllipse(brush, (Width - d) / 2F, (Height - d) / 2F, d, d);
    }
}

// 23.11.2026 Заголовок раздела: текст и тонкая линия до правого края.
sealed class SectionHeader : Control
{
    readonly Color line;

    public SectionHeader(string text, Font font, Color line)
    {
        this.line = line;
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                 | ControlStyles.ResizeRedraw, true);
        TabStop = false;
        Text = text;
        Font = font;
        Height = 20;
        Dock = DockStyle.Fill;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        const TextFormatFlags flags = TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine;
        var size = TextRenderer.MeasureText(e.Graphics, Text, Font, Size.Empty, flags);
        TextRenderer.DrawText(e.Graphics, Text, Font, new Point(0, (Height - size.Height) / 2), ForeColor, flags);
        var y = Height / 2 + 1;
        using var pen = new Pen(line);
        e.Graphics.DrawLine(pen, size.Width + Height / 2, y, Width, y);
    }
}

// 23.11.2026 Список журнала: без мерцания при обновлении строк, выделение как в проводнике.
sealed class BufferedListView : ListView
{
    public BufferedListView()
    {
        DoubleBuffered = true;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        Native.SetWindowTheme(Handle, "explorer", null);
    }
}

static class Native
{
    public const int BCM_SETSHIELD = 0x160C;
    public const int EM_SETCUEBANNER = 0x1501;

    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, string lParam);

    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
    public static extern int SetWindowTheme(IntPtr window, string appName, string idList);
}
