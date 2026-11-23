# 23.11.2026 Рисует значок программы res\app.ico: синий квадрат со скругленными углами и белая линия пульса.
# Размеры 16-64 лежат в файле несжатыми (32 бита с альфа-каналом), 256 – в PNG. Запускать после правки рисунка;
# готовый app.ico хранится рядом, сборке этот скрипт не нужен.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-IconBitmap([int]$Size) {
    $bitmap = New-Object Drawing.Bitmap $Size, $Size, ([Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bitmap)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([Drawing.Color]::Transparent)

    # 23.11.2026 Фон: скругление 22% стороны, сверху чуть светлее.
    $r = [single]($Size * 0.22)
    $d = 2 * $r
    $edge = [single]($Size - 0.5)
    $path = New-Object Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0.5, 0.5, $d, $d, 180, 90)
    $path.AddArc($edge - $d, 0.5, $d, $d, 270, 90)
    $path.AddArc($edge - $d, $edge - $d, $d, $d, 0, 90)
    $path.AddArc(0.5, $edge - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    $rect = New-Object Drawing.RectangleF 0, 0, $Size, $Size
    $top = [Drawing.Color]::FromArgb(45, 125, 210)
    $bottom = [Drawing.Color]::FromArgb(22, 84, 160)
    $brush = New-Object Drawing.Drawing2D.LinearGradientBrush $rect, $top, $bottom, 90
    $g.FillPath($brush, $path)

    # 23.11.2026 Линия пульса: толщина не меньше 1,7 точки, иначе на 16 пикселях ее не видно.
    $width = [single][Math]::Max(1.7, $Size * 0.085)
    $pen = New-Object Drawing.Pen ([Drawing.Color]::White), $width
    $pen.LineJoin = 'Round'
    $pen.StartCap = 'Round'
    $pen.EndCap = 'Round'
    $points = @(
        @(0.14, 0.55), @(0.33, 0.55), @(0.43, 0.27), @(0.56, 0.77), @(0.66, 0.55), @(0.86, 0.55)
    ) | ForEach-Object { New-Object Drawing.PointF ([single]($_[0] * $Size)), ([single]($_[1] * $Size)) }
    $g.DrawLines($pen, [Drawing.PointF[]]$points)

    $pen.Dispose(); $brush.Dispose(); $path.Dispose(); $g.Dispose()
    return $bitmap
}

function Get-DibBytes([Drawing.Bitmap]$Bitmap) {
    $n = $Bitmap.Width
    $rect = New-Object Drawing.Rectangle 0, 0, $n, $n
    $data = $Bitmap.LockBits($rect, 'ReadOnly', 'Format32bppArgb')
    $pixels = New-Object byte[] ($n * $n * 4)
    for ($y = 0; $y -lt $n; $y++) {
        # 23.11.2026 В значке строки идут снизу вверх.
        $source = [IntPtr]::Add($data.Scan0, ($n - 1 - $y) * $data.Stride)
        [Runtime.InteropServices.Marshal]::Copy($source, $pixels, $y * $n * 4, $n * 4)
    }
    $Bitmap.UnlockBits($data)
    $maskRow = [int]([Math]::Floor(($n + 31) / 32) * 4)
    $stream = New-Object IO.MemoryStream
    $w = New-Object IO.BinaryWriter $stream
    $w.Write([int]40); $w.Write([int]$n); $w.Write([int]($n * 2)); $w.Write([int16]1); $w.Write([int16]32)
    $w.Write([int]0); $w.Write([int]($pixels.Length + $maskRow * $n)); $w.Write([int]0); $w.Write([int]0)
    $w.Write([int]0); $w.Write([int]0)
    $w.Write($pixels)
    $w.Write((New-Object byte[] ($maskRow * $n)))
    $w.Flush()
    return , $stream.ToArray()
}

$images = @()
foreach ($size in 16, 20, 24, 32, 40, 48, 64, 256) {
    $bitmap = New-IconBitmap $size
    if ($size -eq 256) {
        $stream = New-Object IO.MemoryStream
        $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
        $bytes = $stream.ToArray()
    }
    else {
        $bytes = Get-DibBytes $bitmap
    }
    $images += [pscustomobject]@{ Size = $size; Bytes = $bytes }
    $bitmap.Dispose()
}

$out = Join-Path $PSScriptRoot 'app.ico'
$file = New-Object IO.MemoryStream
$w = New-Object IO.BinaryWriter $file
$w.Write([int16]0); $w.Write([int16]1); $w.Write([int16]$images.Count)
$offset = 6 + 16 * $images.Count
foreach ($image in $images) {
    $side = [byte]($image.Size % 256)
    $w.Write($side); $w.Write($side); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([int16]1); $w.Write([int16]32); $w.Write([int]$image.Bytes.Length); $w.Write([int]$offset)
    $offset += $image.Bytes.Length
}
foreach ($image in $images) { $w.Write([byte[]]$image.Bytes) }
$w.Flush()
[IO.File]::WriteAllBytes($out, $file.ToArray())
Get-Item $out | Select-Object FullName, Length
