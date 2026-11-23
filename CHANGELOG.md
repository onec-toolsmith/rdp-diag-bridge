# История версий

## 1.0.1 – 23.11.2026

- Каталог обмена по умолчанию – `C:\RdpDiagBridge` (из RDP-сеанса `\\tsclient\C\RdpDiagBridge`). Свой каталог
  задается переменной `RDP_DIAG_BRIDGE_DIR` и ключом `--dir`.

## 1.0.0 – 22.11.2026

Первый выпуск.

- Один EXE: агент с окном для удаленного компьютера и MCP-сервер (`--mcp`).
- Обмен файлами через `\\tsclient\C`, протокол версии 1.
- 18 инструментов: `sessions`, `ping`, `health`, `sysinfo`, `events`, `processes`, `services`, `disks`, `perf`,
  `network`, `nettest`, `software`, `tasks`, `files`, `onec`, `powershell`, `result`, `cancel`.
- Код PowerShell выполняется только с разрешения в окне агента, по умолчанию с подтверждением каждой команды.
