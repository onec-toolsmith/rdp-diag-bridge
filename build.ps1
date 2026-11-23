# 10.11.2026 Сборка RdpDiagBridge.exe компилятором Roslyn из .NET SDK под .NET Framework 4.x (есть в любой Windows).
# Результат – bin\RdpDiagBridge.exe. Запущенный exe (MCP-сервер в сессии Claude) не перезаписывается, а
# переименовывается в .old-<время>: Windows разрешает переименовать работающий exe.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$sdk = Get-ChildItem 'C:\Program Files\dotnet\sdk' -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'Roslyn\bincore\csc.dll') } |
    Sort-Object { [version]($_.Name -replace '-.*$', '') } -Descending | Select-Object -First 1
if (-not $sdk) { throw 'Не найден .NET SDK с Roslyn (C:\Program Files\dotnet\sdk\*\Roslyn\bincore\csc.dll)' }
$csc = Join-Path $sdk.FullName 'Roslyn\bincore\csc.dll'
$fw = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
$refs = 'mscorlib', 'System', 'System.Core', 'System.Management', 'System.Windows.Forms', 'System.Drawing',
    'System.Xml', 'Microsoft.CSharp' | ForEach-Object { '-r:' + (Join-Path $fw "$_.dll") }
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
$out = Join-Path $bin 'RdpDiagBridge.exe'
$new = Join-Path $bin 'RdpDiagBridge.new.exe'
$sources = Get-ChildItem (Join-Path $root 'src') -Filter *.cs | ForEach-Object { $_.FullName }
$arguments = @($csc, '-nologo', '-noconfig', '-nostdlib+', '-target:winexe', '-platform:anycpu', '-optimize+',
    '-langversion:10', '-utf8output', '-warn:4', '-nowarn:1701,1702', "-out:$new") + $refs + $sources
& dotnet @arguments
if ($LASTEXITCODE -ne 0) { throw "Компиляция завершилась с кодом $LASTEXITCODE" }
if (Test-Path $out) {
    try { [IO.File]::Delete($out) }
    catch { Rename-Item $out ("RdpDiagBridge.exe.old-" + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
}
Rename-Item $new 'RdpDiagBridge.exe'
Get-Item $out | Select-Object FullName, Length, LastWriteTime
