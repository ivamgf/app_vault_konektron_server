<#
.SYNOPSIS
    Gera o executavel e o instalador do App Vault Protection.

.DESCRIPTION
    1. Cria/usa o ambiente virtual .venv-build e instala requirements-build.txt
    2. Roda os testes
    3. Gera dist\AppVaultProtection\AppVaultProtection.exe (PyInstaller)
    4. Gera dist\installer\AppVaultProtection-Setup-<versao>.exe (Inno Setup 6)
    5. Assina os executaveis, se houver certificado configurado
    6. Grava dist\installer\SHA256SUMS.txt

    Assinatura de codigo (opcional), por variaveis de ambiente:
      CODESIGN_PFX_PATH     caminho do certificado .pfx      (uso local)
      CODESIGN_PFX_BASE64   conteudo do .pfx em base64      (uso no CI)
      CODESIGN_PFX_PASSWORD senha do .pfx

.EXAMPLE
    .\build.ps1
    .\build.ps1 -SkipTests
    .\build.ps1 -Python "py -3.13"
#>
[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipTests,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    # Ferramentas como pip/unittest/PyInstaller escrevem progresso no stderr; no
    # PowerShell 5.1 isso viraria erro fatal. O sucesso e decidido pelo exit code.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Exe @Arguments 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "Falhou ($LASTEXITCODE): $Exe" }
}

function Find-Tool {
    param([string]$Name, [string[]]$Candidates)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($c in $Candidates) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

function Find-SignTool {
    $found = Find-Tool "signtool.exe" @()
    if ($found) { return $found }
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path $kits) {
        $tool = Get-ChildItem $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\" } |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($tool) { return $tool.FullName }
    }
    return $null
}

function Invoke-Sign {
    param([string[]]$Files)
    if (-not $script:SignPfx) { return }
    foreach ($f in $Files) {
        Write-Host "Assinando $f"
        Invoke-Checked $script:SignTool @("sign", "/fd", "SHA256", "/tr", "http://timestamp.digicert.com",
            "/td", "SHA256", "/f", $script:SignPfx, "/p", $env:CODESIGN_PFX_PASSWORD, $f)
    }
}

# ---- versao (fonte unica: version.py)
$match = Select-String -Path version.py -Pattern '__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"'
if (-not $match) { throw "Nao encontrei __version__ em version.py" }
$version = $match.Matches[0].Groups[1].Value
Write-Host "== App Vault Protection $version"

# ---- certificado de assinatura (opcional)
$script:SignPfx = $null
$tempPfx = $null
if ($env:CODESIGN_PFX_BASE64) {
    $tempPfx = Join-Path ([IO.Path]::GetTempPath()) ("codesign-" + [guid]::NewGuid() + ".pfx")
    [IO.File]::WriteAllBytes($tempPfx, [Convert]::FromBase64String($env:CODESIGN_PFX_BASE64))
    $script:SignPfx = $tempPfx
} elseif ($env:CODESIGN_PFX_PATH) {
    $script:SignPfx = $env:CODESIGN_PFX_PATH
}
if ($script:SignPfx) {
    $script:SignTool = Find-SignTool
    if (-not $script:SignTool) { throw "Certificado configurado, mas signtool.exe nao foi encontrado (Windows SDK)." }
} else {
    Write-Warning "Sem certificado de assinatura: os executaveis NAO serao assinados."
}

try {
    # ---- ambiente de build isolado
    $venv = Join-Path $PSScriptRoot ".venv-build"
    $py = Join-Path $venv "Scripts\python.exe"
    if (-not (Test-Path $py)) {
        Write-Host "== Criando ambiente virtual de build"
        $parts = $Python -split " "
        $pyArgs = @()
        if ($parts.Count -gt 1) { $pyArgs = $parts[1..($parts.Count - 1)] }
        Invoke-Checked $parts[0] ($pyArgs + @("-m", "venv", $venv))
    }
    Invoke-Checked $py @("-m", "pip", "install", "--disable-pip-version-check", "-q", "-r", "requirements-build.txt")

    if (-not $SkipTests) {
        Write-Host "== Testes"
        Invoke-Checked $py @("-m", "unittest", "discover", "-s", "tests")
    }

    if (-not (Test-Path "assets\app.ico")) {
        Invoke-Checked $py @("tools\make_icon.py")
    }

    Write-Host "== PyInstaller"
    Invoke-Checked $py @("-m", "PyInstaller", "--noconfirm", "--clean", "app_vault.spec")
    $exe = "dist\AppVaultProtection\AppVaultProtection.exe"
    if (-not (Test-Path $exe)) { throw "Executavel nao gerado: $exe" }
    Invoke-Sign @($exe)

    if ($SkipInstaller) { Write-Host "Pronto: $exe"; return }

    Write-Host "== Inno Setup"
    $iscc = Find-Tool "ISCC.exe" @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"))
    if (-not $iscc) {
        throw "Inno Setup 6 nao encontrado. Instale com: winget install JRSoftware.InnoSetup"
    }
    $outDir = "dist\installer"
    if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
    Invoke-Checked $iscc @("/Q", "/DAppVersion=$version", "installer\app_vault.iss")
    $setup = Join-Path $outDir "AppVaultProtection-Setup-$version.exe"
    if (-not (Test-Path $setup)) { throw "Instalador nao gerado: $setup" }
    Invoke-Sign @($setup)

    $hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLower()
    $sums = Join-Path $outDir "SHA256SUMS.txt"
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot $sums), "$hash  $(Split-Path $setup -Leaf)`n")
    Write-Host ""
    Write-Host "Pronto:"
    Write-Host "  Instalador: $setup"
    Write-Host "  SHA-256:    $hash"
}
finally {
    if ($tempPfx -and (Test-Path $tempPfx)) { Remove-Item -Force $tempPfx }
}
