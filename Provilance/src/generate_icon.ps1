Add-Type -AssemblyName System.Drawing

$size = 64
$bmp = New-Object System.Drawing.Bitmap($size, $size)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Background rounded rect / circle
$rect = New-Object System.Drawing.Rectangle(2, 2, ($size - 5), ($size - 5))
$brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, [System.Drawing.Color]::FromArgb(15, 32, 67), [System.Drawing.Color]::FromArgb(33, 147, 176), 45.0)
$g.FillEllipse($brush, $rect)

# Border ring
$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(100, 200, 255), [float]2)
$g.DrawEllipse($pen, $rect)

# Draw letter 'P'
$font = New-Object System.Drawing.Font("Segoe UI", [float]30, [System.Drawing.FontStyle]::Bold)
$textBrush = [System.Drawing.Brushes]::White
$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center
$sf.LineAlignment = [System.Drawing.StringAlignment]::Center

$textRect = New-Object System.Drawing.RectangleF(0, 0, [float]$size, [float]$size)
$g.DrawString("P", $font, $textBrush, $textRect, $sf)

# Save as ICO
$hIcon = $bmp.GetHicon()
$icon = [System.Drawing.Icon]::FromHandle($hIcon)
$fs = [System.IO.File]::Create("G:\elastic Search\Provilance\assets\provilance.ico")
$icon.Save($fs)
$fs.Close()
$g.Dispose()
$bmp.Dispose()

Write-Output "Icon created successfully"
