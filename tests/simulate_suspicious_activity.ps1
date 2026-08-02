# ==============================================================
# MALGUARD SAFE THREAT SIMULATOR
# Generates harmless Windows activity for Sysmon testing.
# ==============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " MALGUARD SAFE THREAT SIMULATOR"
Write-Host "============================================"
Write-Host ""

$TestDir = "$env:TEMP\MalGuardSimulation"
$RegistryPath = "HKCU:\Software\MalGuardSimulation"

New-Item -ItemType Directory -Force -Path $TestDir | Out-Null

Write-Host "[1/5] Generating process activity..."

for ($i = 1; $i -le 15; $i++) {

    Start-Process powershell.exe `
        -ArgumentList "-NoProfile -Command `"Write-Output 'MalGuard test process $i'`"" `
        -WindowStyle Hidden `
        -Wait
}

Write-Host "      Process activity generated."


Write-Host ""
Write-Host "[2/5] Generating file activity..."

for ($i = 1; $i -le 20; $i++) {

    $File = Join-Path $TestDir "telemetry_$i.txt"

    "MALGUARD harmless telemetry test $i" |
        Out-File -FilePath $File
}

Write-Host "      File activity generated."


Write-Host ""
Write-Host "[3/5] Generating registry activity..."

New-Item -Path $RegistryPath -Force | Out-Null

for ($i = 1; $i -le 20; $i++) {

    New-ItemProperty `
        -Path $RegistryPath `
        -Name "Telemetry$i" `
        -Value "MalGuardTest$i" `
        -PropertyType String `
        -Force | Out-Null
}

Write-Host "      Registry activity generated."


Write-Host ""
Write-Host "[4/5] Generating DNS activity..."

$Domains = @(
    "example.com",
    "example.org",
    "example.net",
    "iana.org",
    "microsoft.com"
)

foreach ($Domain in $Domains) {

    try {
        Resolve-DnsName $Domain -ErrorAction SilentlyContinue |
            Out-Null
    }
    catch {
        # Ignore DNS errors during simulation.
    }
}

Write-Host "      DNS activity generated."


Write-Host ""
Write-Host "[5/5] Generating network activity..."

$Urls = @(
    "https://example.com",
    "https://example.org",
    "https://www.iana.org"
)

foreach ($Url in $Urls) {

    try {
        Invoke-WebRequest `
            -Uri $Url `
            -Method Head `
            -TimeoutSec 5 `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue |
            Out-Null
    }
    catch {
        # Network failure does not affect the simulator.
    }
}

Write-Host "      Network activity generated."


Write-Host ""
Write-Host "============================================"
Write-Host " SIMULATION COMPLETE"
Write-Host "============================================"

Write-Host ""
Write-Host "Generated harmless:"
Write-Host "  - Process activity"
Write-Host "  - File activity"
Write-Host "  - Registry activity"
Write-Host "  - DNS activity"
Write-Host "  - Network activity"

Write-Host ""
Write-Host "Watch MALGUARD Live Events / Threats now."
Write-Host ""
Write-Host "Waiting 10 seconds for Sysmon collection..."

Start-Sleep -Seconds 10


# ==============================================================
# CLEANUP
# ==============================================================

Write-Host ""
Write-Host "Cleaning temporary test artifacts..."

Remove-Item `
    -Path $TestDir `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Remove-Item `
    -Path $RegistryPath `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Write-Host "Cleanup complete."
Write-Host ""
Write-Host "MALGUARD simulation finished."