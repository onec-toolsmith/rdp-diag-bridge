# 22.11.2026 Проверка моста на этом компьютере: агент без окна в тестовом каталоге обмена, каждый инструмент через
# --call (тот же код, что у MCP), затем протокол MCP по stdio. Итоги – в %TEMP%\rdp-diag-bridge\test-<время>.
param([string]$Only = '')
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $repo 'bin\RdpDiagBridge.exe'
if (-not (Test-Path $exe)) { throw "Нет $exe – сначала build.ps1" }
$work = Join-Path $env:TEMP ('rdp-diag-bridge\test-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$root = Join-Path $work 'root'
New-Item -ItemType Directory -Force $root | Out-Null
$utf8 = New-Object Text.UTF8Encoding $false
# 22.11.2026 Пути в JSON – с удвоенной обратной чертой.
$repoJson = $repo.Replace('\', '\\')
$sample = $repoJson + '\\src\\Json.cs'

$agent = Start-Process $exe -ArgumentList "--headless --dir `"$root`" --allow-code --confirm none" -PassThru
$session = $null
for ($i = 0; $i -lt 50 -and -not $session; $i++) {
    Start-Sleep -Milliseconds 200
    $session = Get-ChildItem $root -Directory | Where-Object { $_.Name -match '^[0-9a-f]{8}$' } | Select-Object -First 1
}
if (-not $session) { throw 'Агент не открыл сеанс' }
"Агент PID $($agent.Id), сеанс $($session.Name)"

$cases = [ordered]@{
    'sessions'        = @('sessions', '{}')
    'ping'            = @('ping', '{}')
    'health'          = @('health', '{"hours":24,"days":7,"timeout":200}')
    'sysinfo'         = @('sysinfo', '{}')
    'events'          = @('events', '{"log":["System"],"level":["critical","error"],"hours":72,"max":5}')
    'events-group'    = @('events', '{"log":["Application","System"],"group":true,"hours":168,"max":8}')
    'events-contains' = @('events', '{"log":["System"],"level":["all"],"hours":168,"contains":"служб","max":3}')
    'events-logs'     = @('events', '{"list_logs":true,"max":8}')
    'processes'       = @('processes', '{"top":8,"details":true}')
    'services'        = @('services', '{"filter":"problem"}')
    'services-1c'     = @('services', '{"filter":"all","name":"1C"}')
    'disks'           = @('disks', '{}')
    'perf'            = @('perf', '{"seconds":3}')
    'network'         = @('network', '{}')
    'nettest'         = @('nettest', '{"targets":["127.0.0.1:445","localhost:1","nonexistent.invalid","https://www.microsoft.com"],"timeout_ms":2000}')
    'software'        = @('software', '{"name":"1C","updates":true,"history":5,"max":10}')
    'tasks'           = @('tasks', '{}')
    'files-list'      = @('files', '{"action":"list","path":"%TEMP%","max":5}')
    'files-tail'      = @('files', ('{"action":"tail","path":"' + $sample + '","lines":5}'))
    'files-grep'      = @('files', ('{"action":"grep","path":"' + $sample + '","text":"Разбор","max":3}'))
    'files-find'      = @('files', ('{"action":"find","path":"' + $repoJson + '","pattern":"*.cs","max":5}'))
    'files-sizes'     = @('files', ('{"action":"sizes","path":"' + $repoJson + '"}'))
    'onec'            = @('onec', '{"budget_sec":5,"timeout":200}')
    'powershell'      = @('powershell', '{"code":"Get-Date -Format yyyy-MM-dd; $PSVersionTable.PSVersion.ToString(); Write-Host ''привет''; Get-Item C:\\nope"}')
    'powershell-json' = @('powershell', '{"code":"Get-Service | Select-Object -First 2 Name, Status","output":"json"}')
    'result-missing'  = @('result', '{"command_id":"20000101T000000000-0000","wait":0}')
}
$summary = @()
foreach ($name in $cases.Keys) {
    if ($Only -and $name -notlike $Only) { continue }
    $tool = $cases[$name][0]
    $argsFile = Join-Path $work "$name.args.json"
    $outFile = Join-Path $work "$name.txt"
    [IO.File]::WriteAllText($argsFile, $cases[$name][1], $utf8)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process $exe -ArgumentList "--call $tool --args-file `"$argsFile`" --out `"$outFile`" --dir `"$root`"" -Wait -PassThru -WindowStyle Hidden
    $text = if (Test-Path $outFile) { [IO.File]::ReadAllText($outFile) } else { '(нет вывода)' }
    $summary += [pscustomobject]@{ Case = $name; Exit = $p.ExitCode; Sec = [math]::Round($watch.Elapsed.TotalSeconds, 1); Chars = $text.Length; First = ($text -split "`n")[0].Trim() }
}
$summary | Format-Table -AutoSize | Out-String -Width 220

# 22.11.2026 Протокол MCP: initialize, tools/list, tools/call ping.
$psi = New-Object Diagnostics.ProcessStartInfo $exe, "--mcp --dir `"$root`""
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.StandardOutputEncoding = $utf8
$mcp = [Diagnostics.Process]::Start($psi)
$writer = New-Object IO.StreamWriter($mcp.StandardInput.BaseStream, $utf8)
$writer.AutoFlush = $true
$writer.WriteLine('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}')
$init = $mcp.StandardOutput.ReadLine()
$writer.WriteLine('{"jsonrpc":"2.0","method":"notifications/initialized"}')
$writer.WriteLine('{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
$list = $mcp.StandardOutput.ReadLine()
$writer.WriteLine('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}')
$call = $mcp.StandardOutput.ReadLine()
$writer.Close()
$mcp.WaitForExit(5000) | Out-Null
"MCP initialize: " + $init.Substring(0, [Math]::Min(160, $init.Length))
"MCP tools/list: " + (($list | ConvertFrom-Json).result.tools.name -join ', ')
"MCP tools/call ping: " + $call.Substring(0, [Math]::Min(300, $call.Length))
"MCP завершился: $($mcp.HasExited)"

New-Item -ItemType File (Join-Path $session.FullName 'stop') | Out-Null
$agent.WaitForExit(10000) | Out-Null
"Агент завершился: $($agent.HasExited); каталог сеанса удален: $(-not (Test-Path $session.FullName))"
"Ответы: $work"
