# Build script for ShellExec.exe - All architectures
param(
    [string]$Configuration = "Release",
    [switch]$FrameworkOnly = $false,
    [switch]$SelfContainedOnly = $false
)

$ErrorActionPreference = "Stop"

Write-Host "Building exec.exe for all architectures..." -ForegroundColor Green

# Build framework-dependent version (smaller, requires .NET runtime)
if (!$SelfContainedOnly) {
    Write-Host "`nBuilding framework-dependent version..." -ForegroundColor Yellow
    dotnet build -c $Configuration -p:Optimize=true -p:DebugType=none -p:DebugSymbols=false
    
    if ($LASTEXITCODE -eq 0) {
        $FileSize = (Get-Item "bin\$Configuration\net6.0-windows\ShellExec.exe").Length
        Write-Host "✓ Framework-dependent build successful! ($FileSize bytes)" -ForegroundColor Green
        Write-Host "  Location: $((Get-Item "bin\$Configuration\net6.0-windows\ShellExec.exe").FullName)" -ForegroundColor Cyan
    } else {
        Write-Host "✗ Framework-dependent build failed!" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

# Build self-contained versions (standalone, no dependencies)
if (!$FrameworkOnly) {
    Write-Host "`nBuilding self-contained versions..." -ForegroundColor Yellow
    
    # x64 version
    Write-Host "  Building x64 version..." -ForegroundColor Yellow
    dotnet publish -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true
    
    if ($LASTEXITCODE -eq 0) {
        $FileSize = (Get-Item "bin\$Configuration\net6.0-windows\win-x64\publish\ShellExec.exe").Length
        Write-Host "  ✓ x64 build successful! ($FileSize bytes)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ x64 build failed!" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    
    # x86 version
    Write-Host "  Building x86 version..." -ForegroundColor Yellow
    dotnet publish -c $Configuration -r win-x86 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true
    
    if ($LASTEXITCODE -eq 0) {
        $FileSize = (Get-Item "bin\$Configuration\net6.0-windows\win-x86\publish\ShellExec.exe").Length
        Write-Host "  ✓ x86 build successful! ($FileSize bytes)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ x86 build failed!" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Write-Host "`nBuild Summary:" -ForegroundColor Green
Write-Host "==============" -ForegroundColor Green

if (!$SelfContainedOnly) {
    $FrameworkSize = (Get-Item "bin\$Configuration\net6.0-windows\ShellExec.exe").Length
    Write-Host "Framework-dependent: $FrameworkSize bytes" -ForegroundColor Cyan
}

if (!$FrameworkOnly) {
    $x64Size = (Get-Item "bin\$Configuration\net6.0-windows\win-x64\publish\ShellExec.exe").Length
    $x86Size = (Get-Item "bin\$Configuration\net6.0-windows\win-x86\publish\ShellExec.exe").Length
    Write-Host "Self-contained x64:  $x64Size bytes" -ForegroundColor Cyan
    Write-Host "Self-contained x86:  $x86Size bytes" -ForegroundColor Cyan
}

Write-Host "`nAll builds completed successfully!" -ForegroundColor Green 