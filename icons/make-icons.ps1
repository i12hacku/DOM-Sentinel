# Regenerates the extension icons from a source logo (JPEG/JFIF/PNG).
# Usage (from the project folder):
#   powershell -ExecutionPolicy Bypass -File icons\make-icons.ps1 -Source logo.jfif
# Uses only built-in Windows .NET imaging (System.Drawing); nothing to install.
param(
  [string]$Source = "logo.jfif",
  # Where the rounded app tile sits inside the source image (pixels).
  [int]$TileX = 252, [int]$TileY = 252, [int]$TileSize = 520, [double]$TileRadius = 0.2,
  # Square around the shield emblem, used for the small (16/32 px) icons.
  [int]$EmblemX = 382, [int]$EmblemY = 292, [int]$EmblemSize = 272
)

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$src = [System.Drawing.Bitmap]::FromFile((Resolve-Path (Join-Path $root $Source)))

function New-RoundedPath([float]$x, [float]$y, [float]$w, [float]$r) {
  $p = New-Object System.Drawing.Drawing2D.GraphicsPath
  $d = $r * 2
  $p.AddArc($x, $y, $d, $d, 180, 90)
  $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
  $p.AddArc($x + $w - $d, $y + $w - $d, $d, $d, 0, 90)
  $p.AddArc($x, $y + $w - $d, $d, $d, 90, 90)
  $p.CloseFigure()
  return $p
}

# Crop a square region of the source into a rounded, transparent-cornered PNG.
function Save-Icon([int]$size, [int]$cx, [int]$cy, [int]$csize, [double]$radius, [int]$pad, [string]$out) {
  # Draw at 4x then downscale once for smooth anti-aliased corners.
  $big = $size * 4
  $tile = New-Object System.Drawing.Bitmap $big, $big, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $g = [System.Drawing.Graphics]::FromImage($tile)
  $g.SmoothingMode = "AntiAlias"; $g.InterpolationMode = "HighQualityBicubic"; $g.PixelOffsetMode = "HighQuality"
  $g.Clear([System.Drawing.Color]::Transparent)
  $inner = $big - 2 * $pad * 4
  $crop = New-Object System.Drawing.Bitmap $inner, $inner, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $cg = [System.Drawing.Graphics]::FromImage($crop)
  $cg.InterpolationMode = "HighQualityBicubic"; $cg.PixelOffsetMode = "HighQuality"
  $cg.DrawImage($src, (New-Object System.Drawing.Rectangle 0, 0, $inner, $inner), (New-Object System.Drawing.Rectangle $cx, $cy, $csize, $csize), [System.Drawing.GraphicsUnit]::Pixel)
  $cg.Dispose()
  $brush = New-Object System.Drawing.TextureBrush $crop
  $brush.TranslateTransform($pad * 4, $pad * 4)
  $path = New-RoundedPath ($pad * 4) ($pad * 4) $inner ($inner * $radius)
  $g.FillPath($brush, $path)
  $g.Dispose(); $brush.Dispose(); $crop.Dispose()

  $final = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $fg = [System.Drawing.Graphics]::FromImage($final)
  $fg.InterpolationMode = "HighQualityBicubic"; $fg.PixelOffsetMode = "HighQuality"; $fg.SmoothingMode = "AntiAlias"
  $fg.Clear([System.Drawing.Color]::Transparent)
  $fg.DrawImage($tile, 0, 0, $size, $size)
  $fg.Dispose(); $tile.Dispose()
  $final.Save((Join-Path $PSScriptRoot $out), [System.Drawing.Imaging.ImageFormat]::Png)
  $final.Dispose()
  "wrote icons/$out"
}

# Small sizes: shield emblem only (the wordmark is unreadable below ~48 px).
Save-Icon 16  $EmblemX $EmblemY $EmblemSize 0.22 0 "icon-16.png"
Save-Icon 32  $EmblemX $EmblemY $EmblemSize 0.22 0 "icon-32.png"
# Larger sizes: the full tile. 128 px keeps a small transparent margin, as Chrome recommends.
Save-Icon 48  $TileX $TileY $TileSize $TileRadius 1 "icon-48.png"
Save-Icon 128 $TileX $TileY $TileSize $TileRadius 6 "icon-128.png"

$src.Dispose()
