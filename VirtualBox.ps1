param([ValidateSet('Start', 'Install', 'Stop')][string]$Mode = 'Start', [switch]$NoOpen, [switch]$LocalAI)

$ErrorActionPreference = 'Stop'
$installDir = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Oracle\VirtualBox' -ErrorAction SilentlyContinue).InstallDir
$vbox = if ($installDir) { Join-Path $installDir 'VBoxManage.exe' } else { (Get-Command VBoxManage -ErrorAction Stop).Source }
$image = Join-Path $PSScriptRoot 'lab\runtime\SOC-Tier1.iso'
$machines = @(
    @{ Name = 'SOC Tier 1 - SIEM'; Role = 'manager'; Suffix = '10' },
    @{ Name = 'SOC Tier 1 - Endpoint'; Role = 'victim'; Suffix = '20' },
    @{ Name = 'SOC Tier 1 - Atacante'; Role = 'attacker'; Suffix = '30' },
    @{ Name = 'SOC Tier 1 - SOAR'; Role = 'soar'; Suffix = '40' }
)
$key = 'SOC-Tier1/Demo'
$marker = 'guide-v2'
$imageKey = 'SOC-Tier1/RuntimeHash'

function Invoke-VBox {
    & $vbox @args
    if ($LASTEXITCODE -ne 0) { throw "Falha no VirtualBox em $($args[0])." }
}

function Test-OwnedVM($name) {
    (Invoke-VBox getextradata $name $key) -eq "Value: $marker"
}

function Get-VMState($name) {
    (Invoke-VBox showvminfo $name --machinereadable | Select-String '^VMState=').Line
}

$registered = (Invoke-VBox list vms) -join "`n"
if ($Mode -ne 'Stop' -and !(Test-Path -LiteralPath $image -PathType Leaf)) {
    throw 'Mantenha lab/runtime/SOC-Tier1.iso na pasta do projeto.'
}

foreach ($machine in $machines) {
    $name = $machine.Name
    $exists = $registered -match ('(?m)^"' + [regex]::Escape($name) + '"\s')
    if ($exists -and !(Test-OwnedVM $name)) { throw "Ja existe outra VM chamada '$name'." }
    if ($Mode -eq 'Stop') {
        if ($exists -and (Get-VMState $name) -eq 'VMState="running"') { Invoke-VBox controlvm $name poweroff }
        continue
    }
    if (!$exists) {
        Invoke-VBox createvm --name $name --ostype Linux_64 --groups '/SOC Tier 1 Demo' --register
        Invoke-VBox setextradata $name $key $marker
        Invoke-VBox modifyvm $name --memory 384 --cpus 1 --boot1 dvd --boot2 none --boot3 none --boot4 none `
            --firmware bios --rtc-use-utc on --graphicscontroller vmsvga --audio-enabled off `
            --nic1 intnet --intnet1 'SOC-TIER1-DEMO' --nic-type1 82540EM --cable-connected1 on `
            --mac-address1 ('0800277600' + $machine.Suffix) --uart1 0x3F8 4 `
            --uart-mode1 server ('\\.\pipe\SOC-TIER1-' + $machine.Role)
        Invoke-VBox storagectl $name --name 'DVD' --add ide --controller PIIX4 --bootable on
        Invoke-VBox storageattach $name --storagectl 'DVD' --port 0 --device 0 --type dvddrive --medium $image
        Invoke-VBox snapshot $name take 'Base isolada'
    }
}

if ($Mode -ne 'Start') { exit }
if ($LocalAI) { . (Join-Path $PSScriptRoot 'LocalAI.ps1') }

$node = Get-Command node -ErrorAction Stop
$bridge = Join-Path $PSScriptRoot 'lab\virtualbox.cjs'
$listener = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 8771 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $owner = Get-CimInstance Win32_Process -Filter "ProcessId=$($listener.OwningProcess)"
    if ($owner.Name -ne 'node.exe' -or $owner.CommandLine.IndexOf($bridge, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw 'A porta 8771 esta em uso por outro programa.'
    }
    if ($LocalAI) {
        Stop-Process -Id $listener.OwningProcess
        $listener = $null
    }
}
$imageHash = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash
foreach ($machine in $machines) {
    $name = $machine.Name
    $state = Get-VMState $name
    if ($state -eq 'VMState="running"' -and (Invoke-VBox getextradata $name $imageKey) -ne "Value: $imageHash") {
        Invoke-VBox controlvm $name poweroff
        $state = Get-VMState $name
    }
    if ($state -ne 'VMState="running"') {
        Invoke-VBox startvm $name --type headless
        Invoke-VBox setextradata $name $imageKey $imageHash
    }
}

if ($listener) {
    Write-Host 'Painel VirtualBox ja disponivel em http://127.0.0.1:8771/'
    if (!$NoOpen) { Start-Process 'http://127.0.0.1:8771/' }
    exit 0
}
if ($NoOpen) { & $node.Source $bridge } else { & $node.Source $bridge --open }
