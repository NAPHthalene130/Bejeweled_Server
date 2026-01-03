# This script exports .drawio files to PNG images
# Requirement: Draw.io Desktop application must be installed

# Try to automatically detect Draw.io installation path
$possiblePaths = @(
    "C:\Program Files\draw.io\draw.io.exe",
    "C:\Program Files (x86)\draw.io\draw.io.exe",
    "$env:LOCALAPPDATA\Programs\draw.io\draw.io.exe",
    "$env:LOCALAPPDATA\draw.io\draw.io.exe"
)

$drawioPath = $null
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $drawioPath = $path
        break
    }
}

if ($null -eq $drawioPath) {
    Write-Warning "Draw.io executable not found."
    Write-Warning "Please ensure Draw.io Desktop is installed (https://get.diagrams.net/)"
    Write-Warning "Or manually update the path in this script."
    exit 1
}

Write-Host "Found Draw.io: $drawioPath" -ForegroundColor Cyan

$sourceDir = $PSScriptRoot
$destDir = Join-Path $sourceDir "ServerPng"

# Ensure output directory exists
if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

# Get all .drawio files
$files = Get-ChildItem -Path $sourceDir -Filter "*.drawio"

if ($files.Count -eq 0) {
    Write-Warning "No .drawio files found in $sourceDir"
    exit
}

Write-Host "Starting export..." -ForegroundColor Cyan

foreach ($file in $files) {
    $outFile = Join-Path $destDir ($file.BaseName + ".png")
    Write-Host "Exporting: $($file.Name) -> ServerPng\$($file.BaseName).png"
    
    # Call draw.io command line to export
    # -x: export
    # -f png: format
    # -o: output file
    # --transparent: transparent background (optional)
    $process = Start-Process -FilePath $drawioPath -ArgumentList "-x", "-f", "png", "-o", "`"$outFile`"", "`"$($file.FullName)`"" -PassThru -Wait -WindowStyle Hidden
    
    if ($process.ExitCode -eq 0) {
        Write-Host "  Success" -ForegroundColor Green
    } else {
        Write-Error "  Failed (Exit Code: $($process.ExitCode))"
    }
}

Write-Host "Batch export completed!" -ForegroundColor Cyan
