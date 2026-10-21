# Rol php2shell-shield uit naar alle servers in servers.txt, vanuit Windows PowerShell.
#
#   .\uitrollen.ps1                                  -> install (strict) op alle servers
#   .\uitrollen.ps1 "install --dry-run"              -> eerst kijken wat er zou gebeuren
#   .\uitrollen.ps1 "install --mode strict --trust 203.0.113.5"
#   .\uitrollen.ps1 status   |   .\uitrollen.ps1 test   |   .\uitrollen.ps1 "uninstall"
#
# Gebruikt de ingebouwde OpenSSH-client van Windows. Het script gaat via stdin
# (cat >) naar /root/php2shell-shield.sh, dus SFTP/scp hoeft niet te werken.
param(
    [string]$Opdracht = "install",
    [string]$Servers  = (Join-Path $PSScriptRoot "servers.txt")
)
$script = Join-Path $PSScriptRoot "php2shell-shield.sh"
if (-not (Test-Path $Servers)) { Write-Error "servers.txt ontbreekt: $Servers (zie servers.txt.voorbeeld)"; exit 1 }
if (-not (Test-Path $script))  { Write-Error "php2shell-shield.sh ontbreekt naast dit script"; exit 1 }
if ((Get-Content -Raw $script) -match "`r`n") { Write-Error "php2shell-shield.sh heeft Windows-regeleinden; sla het op met LF-regeleinden."; exit 1 }
$log = Join-Path $PSScriptRoot ("uitrol-{0:yyyyMMdd-HHmm}.log" -f (Get-Date))

foreach ($regel in Get-Content $Servers) {
    $regel = ($regel -split '#')[0].Trim()
    if (-not $regel) { continue }
    $server = $regel; $poort = 22
    if ($server -match '^(.*):(\d+)$') { $server = $Matches[1]; $poort = [int]$Matches[2] }
    if ($server -notmatch '@') { $server = "root@$server" }
    $kop = "=== $server (poort $poort): php2shell-shield $Opdracht"
    Write-Host $kop -ForegroundColor Cyan
    Add-Content -Path $log -Value $kop
    $remote = "cat > /root/php2shell-shield.sh && chmod 700 /root/php2shell-shield.sh && bash /root/php2shell-shield.sh $Opdracht"
    # via cmd.exe zodat stdin het bestand byte-voor-byte doorgeeft (geen PowerShell-tekstconversie)
    $cmd = "ssh -p $poort -o ConnectTimeout=20 $server `"$remote`" < `"$script`""
    cmd /c $cmd 2>&1 | Tee-Object -FilePath $log -Append
    Add-Content -Path $log -Value "--- exitstatus: $LASTEXITCODE"
    Write-Host ""
}
Write-Host "Log: $log"
