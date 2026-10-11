#!/usr/bin/env python3
"""Prepare the existing owned Windows host for scheduled-task evidence.

Run inside the configured range bridge (whose private SSH tunnel is ready):
docker exec -i artex-local-range-bridge-1 python - --apply < lab/attack-range/prepare_chain_telemetry.py
Without --apply this only reads the host's telemetry configuration.
The original settings are retained on Windows; no credentials are printed.
"""
import argparse
import base64
import gzip
import json
import sys

sys.path.insert(0, '/app')
from runtime import load_config
import winrm

INSPECT = r"""$ErrorActionPreference='Stop'
$channel='Microsoft-Windows-TaskScheduler/Operational'
$inputPath='C:\Program Files\SplunkUniversalForwarder\etc\apps\aegis_chain_inputs\local\inputs.conf'
$audit=[string](& auditpol /get /subcategory:'{0CCE9227-69AE-11D9-BED3-505054503030}' /r | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Audit policy inspection failed' }
[pscustomobject]@{
  task_channel_enabled=[bool](Get-WinEvent -ListLog $channel).IsEnabled
  script_block_enabled=((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1)
  task_module_logging=((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1)
  task_input_present=[bool](Test-Path -LiteralPath $inputPath)
  forwarder_running=((Get-Service SplunkForwarder).Status -eq 'Running')
  sysmon_json_configuration_present=[bool](Test-Path 'C:\AegisLoop\telemetry\sysmon-chain.xml')
  audit_policy=$audit
} | ConvertTo-Json -Depth 3 -Compress
"""

APPLY = r"""$ErrorActionPreference='Stop'
$channel='Microsoft-Windows-TaskScheduler/Operational'
$inputPath='C:\Program Files\SplunkUniversalForwarder\etc\apps\aegis_chain_inputs\local\inputs.conf'
$backup='C:\AegisLoop\telemetry\chain-preparation.json'
$previousInput=if(Test-Path -LiteralPath $inputPath){[string](Get-Content -Raw -LiteralPath $inputPath)}else{$null}
if ($previousInput -and !$previousInput.StartsWith('# AegisLoop owned chain telemetry')) { throw 'Input ownership mismatch' }
$audit=[string](& auditpol /get /subcategory:'{0CCE9227-69AE-11D9-BED3-505054503030}' /r | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Audit policy inspection failed' }
if (!(Test-Path -LiteralPath $backup)) {
  New-Item -ItemType Directory -Force -Path (Split-Path $backup) | Out-Null
  [IO.File]::WriteAllText($backup,([pscustomobject]@{task_channel_enabled=[bool](Get-WinEvent -ListLog $channel).IsEnabled;audit_policy=$audit;previous_input=$previousInput;prepared_at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json -Depth 3),[Text.UTF8Encoding]::new($false))
}
$moduleBase='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$moduleNames=Join-Path $moduleBase 'ModuleNames'
$moduleBackup='C:\AegisLoop\telemetry\chain-module-logging.json'
if (!(Test-Path -LiteralPath $moduleBackup)) {
  [IO.File]::WriteAllText($moduleBackup,([pscustomobject]@{enabled=(Get-ItemProperty $moduleBase -ErrorAction SilentlyContinue).EnableModuleLogging;scheduled_tasks=(Get-ItemProperty $moduleNames -ErrorAction SilentlyContinue).ScheduledTasks} | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
if (!(Test-Path -LiteralPath $moduleNames)) { New-Item -Path $moduleNames -Force | Out-Null }
New-ItemProperty -Path $moduleBase -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $moduleNames -Name ScheduledTasks -Value ScheduledTasks -PropertyType String -Force | Out-Null
& wevtutil sl $channel /e:true
if ($LASTEXITCODE -ne 0) { throw 'Task Scheduler channel enable failed' }
& auditpol /set /subcategory:'{0CCE9227-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Task audit enable failed' }
$content=@'
# AegisLoop owned chain telemetry
[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
renderXml = 1
source = XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational
sourcetype = XmlWinEventLog
index = win
start_from = oldest
current_only = 0
checkpointInterval = 5
'@
if ($previousInput -ne $content) {
  New-Item -ItemType Directory -Force -Path (Split-Path $inputPath) | Out-Null
  [IO.File]::WriteAllText($inputPath,$content,[Text.UTF8Encoding]::new($false))
  Restart-Service SplunkForwarder
  (Get-Service SplunkForwarder).WaitForStatus('Running',[TimeSpan]::FromSeconds(45))
}
# Extend the active Sysmon XML instead of replacing its existing filters.
# A generic PowerShell + JSON FileCreate rule provides independent outcome
# evidence for attack and normal tasks alike; it is not a detection rule.
$sysmon='C:\Windows\sysmon64.exe'
$active=([string](& $sysmon -c | Out-String)).Replace([string][char]0,'')
if ($LASTEXITCODE -ne 0) { throw 'Sysmon configuration inspection failed' }
$pathMatch=[regex]::Match($active,'(?m)Config file:\s+([^\r\n]+)')
$hashMatch=[regex]::Match($active,'Config hash:\s+SHA256=([A-Fa-f0-9]{64})')
if (!$pathMatch.Success -or !$hashMatch.Success) { throw 'Active Sysmon source cannot be verified' }
$source=$pathMatch.Groups[1].Value.Trim()
if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $hashMatch.Groups[1].Value) { throw 'Sysmon source differs from active configuration' }
$original='C:\AegisLoop\telemetry\sysmon-before-chain.xml'
if (!(Test-Path -LiteralPath $original)) { Copy-Item -LiteralPath $source -Destination $original }
$xml=New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace=$true
$xml.Load($source)
if (!$xml.SelectSingleNode('/Sysmon/EventFiltering')) { throw 'Unsupported Sysmon configuration' }
if (!$xml.SelectSingleNode('/Sysmon/EventFiltering/RuleGroup[@name="AegisLoop PowerShell JSON telemetry"]')) {
  if (!$xml.SelectSingleNode('/Sysmon/EventFiltering//FileCreate[@onmatch="include"]')) { throw 'Review exclude-only FileCreate policy manually before adding an include filter' }
  $fragment=$xml.CreateDocumentFragment()
  $fragment.InnerXml='<RuleGroup name="AegisLoop PowerShell JSON telemetry" groupRelation="or"><FileCreate onmatch="include"><Rule name="PowerShell JSON output" groupRelation="and"><Image condition="end with">\powershell.exe</Image><TargetFilename condition="end with">.json</TargetFilename></Rule></FileCreate></RuleGroup>'
  $xml.SelectSingleNode('/Sysmon/EventFiltering').AppendChild($fragment) | Out-Null
  $destination='C:\AegisLoop\telemetry\sysmon-chain.xml'
  $xml.Save($destination)
  & $sysmon -c $destination | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Sysmon additive telemetry update failed' }
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    config = load_config('/run/range/config.json')
    session = winrm.Session('http://127.0.0.1:15985/wsman',
                            auth=(config['windows_user'], config['windows_password']),
                            transport='ntlm', message_encryption='always',
                            read_timeout_sec=100, operation_timeout_sec=80)
    script = (APPLY if args.apply else '') + INSPECT
    packed = base64.b64encode(gzip.compress(script.encode('utf-8'))).decode('ascii')
    command = ("$b=[Convert]::FromBase64String('" + packed + "');"
               "$m=[IO.MemoryStream]::new($b,0,$b.Length);"
               "$g=[IO.Compression.GzipStream]::new($m,[IO.Compression.CompressionMode]::Decompress);"
               "$r=[IO.StreamReader]::new($g,[Text.Encoding]::UTF8);"
               "& ([scriptblock]::Create($r.ReadToEnd()))")
    # The wrapper is ASCII and contains no double quotes. Avoid run_ps's
    # UTF-16/base64 expansion, which can exceed cmd.exe's 8191-character limit.
    if '"' in command or len(command) > 7000:
        raise RuntimeError('Telemetry preparation wrapper exceeds its transport bound.')
    response = session.run_cmd('powershell.exe', ['-NoProfile', '-NonInteractive',
                                                '-Command', '"' + command + '"'])
    if response.status_code:
        raise RuntimeError('Windows telemetry preparation failed; no credentials or raw transport errors are shown.')
    print(json.dumps(json.loads(response.std_out.decode('utf-8-sig')), ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Telemetry preparation failed. Check the configured bridge tunnel and owned Windows host.') from None
