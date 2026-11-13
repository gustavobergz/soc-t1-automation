param([switch]$Setup, [string]$Model = 'qwen2.5:1.5b')

$ErrorActionPreference = 'Stop'
if ($Model -notmatch '^[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+$' -or $Model -match 'cloud') {
    throw 'Informe uma tag de modelo local, como qwen2.5:1.5b.'
}
$taskRoot = Join-Path $env:LOCALAPPDATA 'SOC-Tier1'
$taskTool = Join-Path $taskRoot 'ollama'
$taskExe = Join-Path $taskTool 'ollama.exe'
$taskModels = Join-Path $taskRoot 'models'
New-Item -ItemType Directory -Force -Path $taskRoot | Out-Null

if (!(Test-Path -LiteralPath $taskExe)) {
    if (!$Setup) { throw 'Execute CONFIGURAR IA LOCAL.cmd para baixar o Ollama e o modelo.' }
    $taskBuild = Join-Path $env:TEMP 'soc-n1-build'
    New-Item -ItemType Directory -Force -Path $taskBuild | Out-Null
    $taskPackage = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'lab\ollama-cpu.json') -Raw | ConvertFrom-Json
    $taskRange = Join-Path $taskBuild 'ollama-cpu-range.bin'
    $taskChunk = Join-Path $taskBuild 'ollama-cpu-chunk.bin'
    if (!(Test-Path -LiteralPath $taskRange)) { [IO.File]::WriteAllBytes($taskRange, [byte[]]@()) }
    Write-Host 'Preparando o Ollama oficial para CPU. O download pode ser retomado ao executar novamente.'
    while ((Get-Item -LiteralPath $taskRange).Length -lt $taskPackage.range_bytes) {
        $taskLength = (Get-Item -LiteralPath $taskRange).Length
        $taskSize = [Math]::Min(4194304, $taskPackage.range_bytes - $taskLength)
        $taskFrom = $taskPackage.range_start + $taskLength
        $taskTo = $taskFrom + $taskSize - 1
        & curl.exe --fail --location --retry 3 --silent --show-error --max-time 180 --range "$taskFrom-$taskTo" --output $taskChunk $taskPackage.url
        if ($LASTEXITCODE -ne 0 -or (Get-Item -LiteralPath $taskChunk).Length -ne $taskSize) {
            throw 'O download foi interrompido. Execute CONFIGURAR IA LOCAL.cmd novamente para retomar.'
        }
        $taskOutput = [IO.File]::Open($taskRange, [IO.FileMode]::Append)
        $taskInput = [IO.File]::OpenRead($taskChunk)
        try { $taskInput.CopyTo($taskOutput) } finally { $taskInput.Dispose(); $taskOutput.Dispose() }
    }
    if ((Get-Item -LiteralPath $taskRange).Length -ne $taskPackage.range_bytes -or (Get-FileHash -Algorithm SHA256 -LiteralPath $taskRange).Hash -ne $taskPackage.sha256) {
        throw 'A verificacao SHA256 do pacote CPU falhou.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $taskArchive = Join-Path $taskBuild 'ollama-cpu-extract.zip'
    $taskZipFile = [IO.File]::Open($taskArchive, [IO.FileMode]::Create)
    $taskInput = [IO.File]::OpenRead($taskRange)
    try {
        $taskZipFile.SetLength($taskPackage.archive_bytes)
        $taskZipFile.Position = $taskPackage.range_start
        $taskInput.CopyTo($taskZipFile)
    } finally { $taskInput.Dispose(); $taskZipFile.Dispose() }
    $taskZip = [IO.Compression.ZipFile]::OpenRead($taskArchive)
    try {
        foreach ($taskEntry in $taskZip.Entries) {
            if ($taskEntry.FullName -notmatch '^(ollama\.exe|lib/ollama/[^/]+\.(dll|exe)|lib/ollama/(GO_LICENSE|LLAMA_CPP_LICENSE|LLAMA_CPP_VENDORS_LICENSE))$') { continue }
            $taskDestination = [IO.Path]::GetFullPath((Join-Path $taskTool $taskEntry.FullName))
            if (!$taskDestination.StartsWith([IO.Path]::GetFullPath($taskTool) + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Caminho de instalacao invalido.'
            }
            New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($taskDestination)) | Out-Null
            [IO.Compression.ZipFileExtensions]::ExtractToFile($taskEntry, $taskDestination, $true)
        }
    } finally { $taskZip.Dispose(); Remove-Item -LiteralPath $taskArchive }
    if (!(Test-Path -LiteralPath $taskExe)) { throw 'O executavel do Ollama nao foi extraido.' }
}

$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_MODELS = $taskModels
$env:OLLAMA_CONTEXT_LENGTH = '4096'
$env:OLLAMA_NUM_PARALLEL = '1'
$taskListener = Get-NetTCPConnection -LocalPort 11434 -State Listen -ErrorAction SilentlyContinue
if (!$taskListener) {
    Start-Process -FilePath $taskExe -ArgumentList 'serve' -WindowStyle Hidden -RedirectStandardOutput (Join-Path $taskRoot 'ollama-out.log') -RedirectStandardError (Join-Path $taskRoot 'ollama-err.log') | Out-Null
}
$taskAvailable = $false
for ($taskAttempt = 0; $taskAttempt -lt 30; $taskAttempt++) {
    try {
        $taskTags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2
        $taskAvailable = $true
        break
    } catch { Start-Sleep -Milliseconds 500 }
}
if (!$taskAvailable) { throw 'O servidor local do Ollama nao respondeu. Consulte os logs em LOCALAPPDATA\SOC-Tier1.' }
if (!($taskTags.models | Where-Object { $_.name -eq $Model -and !$_.remote_model -and !$_.remote_host -and $_.size -gt 0 })) {
    if (!$Setup) { throw 'O modelo ainda precisa ser baixado. Execute CONFIGURAR IA LOCAL.cmd.' }
    Write-Host "Baixando o modelo local $Model. A inferencia subsequente usa o computador."
    & $taskExe pull $Model
    if ($LASTEXITCODE -ne 0) { throw 'O download do modelo falhou.' }
}
$env:SOC_OLLAMA_MODEL = $Model
Write-Host "IA local pronta em 127.0.0.1:11434. Modelo $Model."
