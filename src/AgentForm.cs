using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace RdpDiagBridge;

// 10.11.2026 Окно агента: сеанс и каталог обмена, разрешения, решение по запросам, журнал команд.
public sealed class AgentForm : Form
{
    readonly AgentCore core;
    readonly Label sessionLabel = new Label { AutoSize = true, Anchor = AnchorStyles.Left };
    readonly Label dirLabel = new Label { AutoSize = true, Anchor = AnchorStyles.Left };
    readonly Label adminLabel = new Label { AutoSize = true, Anchor = AnchorStyles.Left };
    readonly Label stateLabel = new Label { AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 3, 3) };
    readonly Button copyButton = new Button { Text = "Копировать номер", AutoSize = true };
    readonly Button dirButton = new Button { Text = "Изменить…", AutoSize = true };
    readonly Button elevateButton = new Button { Text = "Перезапустить от администратора", AutoSize = true };
    readonly CheckBox codeCheck = new CheckBox { AutoSize = true };
    readonly ComboBox confirmBox = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 330 };
    readonly CheckBox pauseCheck = new CheckBox { Text = "Пауза: новые команды ждут в очереди", AutoSize = true };
    readonly GroupBox pendingGroup = new GroupBox { Text = "Запрос ждет вашего решения", Dock = DockStyle.Fill, Height = 260, Visible = false };
    readonly TextBox pendingText = new TextBox
    {
        Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill,
        Font = new Font("Consolas", 9F), BackColor = SystemColors.Window,
    };
    readonly TextBox commentBox = new TextBox { Dock = DockStyle.Fill };
    readonly Button allowButton = new Button { Text = "Выполнить", AutoSize = true };
    readonly Button denyButton = new Button { Text = "Отклонить", AutoSize = true };
    readonly ListBox logList = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false, HorizontalScrollbar = true };
    readonly Button cancelButton = new Button { Text = "Прервать команду", AutoSize = true, Enabled = false };
    readonly Button closeButton = new Button { Text = "Закрыть", AutoSize = true };
    readonly Timer timer = new Timer { Interval = 500 };
    Command shownPending;
    bool closingWithoutQuestion;

    public AgentForm(AgentCore core)
    {
        this.core = core;
        Text = "Мост диагностики RDP – агент " + Proto.AppVersion;
        Font = new Font("Segoe UI", 9F);
        ClientSize = new Size(820, 700);
        MinimumSize = new Size(640, 560);
        StartPosition = FormStartPosition.CenterScreen;
        BuildLayout();
        codeCheck.Text = "Разрешить команды PowerShell (произвольный код от имени " + Env.UserName + ")";
        codeCheck.Checked = core.AllowCode;
        confirmBox.Items.AddRange(new object[] { "спрашивать перед кодом PowerShell", "спрашивать перед каждой командой", "не спрашивать" });
        confirmBox.SelectedIndex = core.ConfirmMode == "all" ? 1 : core.ConfirmMode == "none" ? 2 : 0;
        adminLabel.Text = Env.Elevated
            ? "Агент запущен от администратора: доступны журнал Security, SMART и данные всех процессов."
            : "Агент без прав администратора: журнал Security, SMART и часть сведений о процессах недоступны.";
        elevateButton.Visible = !Env.Elevated;
        codeCheck.CheckedChanged += (_, _) =>
        {
            core.AllowCode = codeCheck.Checked;
            core.Log(codeCheck.Checked ? "Команды PowerShell разрешены" : "Команды PowerShell запрещены");
        };
        confirmBox.SelectedIndexChanged += (_, _) =>
        {
            core.ConfirmMode = confirmBox.SelectedIndex == 1 ? "all" : confirmBox.SelectedIndex == 2 ? "none" : "code";
            core.Log("Подтверждение: " + confirmBox.Text);
        };
        pauseCheck.CheckedChanged += (_, _) => core.Paused = pauseCheck.Checked;
        copyButton.Click += (_, _) =>
        {
            if (core.SessionId != "")
                Clipboard.SetText(core.SessionId);
        };
        dirButton.Click += (_, _) => ChangeDir();
        elevateButton.Click += (_, _) => Elevate();
        allowButton.Click += (_, _) => Decide(true);
        denyButton.Click += (_, _) => Decide(false);
        cancelButton.Click += (_, _) => core.CancelCurrent();
        closeButton.Click += (_, _) => Close();
        timer.Tick += (_, _) => RefreshView();
        timer.Start();
        RefreshView();
    }

    void BuildLayout()
    {
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 5, Padding = new Padding(10) };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        Controls.Add(layout);

        var info = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
        info.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        info.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        info.Controls.Add(sessionLabel, 0, 0);
        info.Controls.Add(copyButton, 1, 0);
        info.Controls.Add(dirLabel, 0, 1);
        info.Controls.Add(dirButton, 1, 1);
        info.Controls.Add(adminLabel, 0, 2);
        info.Controls.Add(elevateButton, 1, 2);
        info.Controls.Add(stateLabel, 0, 3);
        info.SetColumnSpan(stateLabel, 2);
        stateLabel.Font = new Font(Font, FontStyle.Bold);
        layout.Controls.Add(info, 0, 0);

        var permissions = new GroupBox { Text = "Разрешения", Dock = DockStyle.Fill, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink };
        var flow = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(4) };
        var confirmRow = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = new Padding(0) };
        confirmRow.Controls.Add(new Label { Text = "Подтверждение:", AutoSize = true, Margin = new Padding(3, 7, 3, 3) });
        confirmRow.Controls.Add(confirmBox);
        flow.Controls.Add(new Label
        {
            AutoSize = true, MaximumSize = new Size(760, 0),
            Text = "Диагностика (журналы, службы, процессы, диски, сеть, 1С, чтение файлов) выполняется без вопросов и ничего не меняет. "
                   + "Произвольный код PowerShell – только с разрешением ниже.",
        });
        flow.Controls.Add(codeCheck);
        flow.Controls.Add(confirmRow);
        flow.Controls.Add(pauseCheck);
        permissions.Controls.Add(flow);
        layout.Controls.Add(permissions, 0, 1);

        var pendingLayout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4 };
        pendingLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        pendingLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pendingLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pendingLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        pendingLayout.Controls.Add(pendingText, 0, 0);
        pendingLayout.Controls.Add(new Label { Text = "Комментарий для Claude (необязательно, уйдет вместе с решением):", AutoSize = true }, 0, 1);
        pendingLayout.Controls.Add(commentBox, 0, 2);
        var decision = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill };
        decision.Controls.Add(allowButton);
        decision.Controls.Add(denyButton);
        pendingLayout.Controls.Add(decision, 0, 3);
        pendingGroup.Controls.Add(pendingLayout);
        layout.Controls.Add(pendingGroup, 0, 2);

        var logGroup = new GroupBox { Text = "Журнал команд", Dock = DockStyle.Fill };
        logGroup.Controls.Add(logList);
        layout.Controls.Add(logGroup, 0, 3);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        buttons.Controls.Add(closeButton);
        buttons.Controls.Add(cancelButton);
        layout.Controls.Add(buttons, 0, 4);
    }

    void RefreshView()
    {
        sessionLabel.Text = "Сеанс: " + (core.SessionId != "" ? core.SessionId : "–") + "    Компьютер: " + Environment.MachineName
                            + ", пользователь " + Env.UserName;
        dirLabel.Text = "Каталог обмена: " + (core.Root != "" ? core.Root : "не задан");
        var state = core.State;
        stateLabel.Text = core.StateText();
        stateLabel.ForeColor = core.LastError != "" || state == "nodir" ? Color.Firebrick
            : state == "awaiting" ? Color.DarkOrange
            : state == "busy" ? Color.RoyalBlue
            : Color.ForestGreen;
        var added = false;
        while (core.LogQueue.TryDequeue(out var line))
        {
            logList.Items.Insert(0, line);
            added = true;
        }
        if (added)
            while (logList.Items.Count > 500)
                logList.Items.RemoveAt(logList.Items.Count - 1);
        var pending = core.Pending;
        if (pending != shownPending)
        {
            shownPending = pending;
            if (pending != null)
            {
                pendingText.Text = pending.Describe();
                commentBox.Text = "";
                pendingGroup.Visible = true;
                allowButton.Enabled = denyButton.Enabled = true;
                Attention();
            }
            else
            {
                pendingGroup.Visible = false;
            }
        }
        cancelButton.Enabled = core.Busy != null;
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
            MinimizeBox = false, MaximizeBox = false, ClientSize = new Size(620, 130), Font = Font,
        };
        var label = new Label
        {
            Text = "Каталог на компьютере с Claude, подключенный в RDP. Обычно " + Proto.TsclientRoot,
            AutoSize = true, Location = new Point(10, 12),
        };
        var box = new TextBox { Text = core.Root != "" ? core.Root : Proto.TsclientRoot, Location = new Point(10, 40), Width = 500 };
        var browse = new Button { Text = "Обзор…", Location = new Point(520, 38), AutoSize = true };
        var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, Location = new Point(430, 90), AutoSize = true };
        var cancel = new Button { Text = "Отмена", DialogResult = DialogResult.Cancel, Location = new Point(520, 90), AutoSize = true };
        browse.Click += (_, _) =>
        {
            using var folder = new FolderBrowserDialog { SelectedPath = box.Text };
            if (folder.ShowDialog(dialog) == DialogResult.OK)
                box.Text = folder.SelectedPath;
        };
        dialog.Controls.AddRange(new Control[] { label, box, browse, ok, cancel });
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
