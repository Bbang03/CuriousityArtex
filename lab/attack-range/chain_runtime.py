"""Fixed, harmless scheduled-task chain and native multi-source correlation.

Execution labels/nonces are ground truth and attribution only. Detection
profiles contain no run UUIDs, filenames, task names, or test labels.
"""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
import time
import xml.etree.ElementTree as ET

from runtime import (RangeError, epoch, json_read, literal, process_guid,
                     rule_digest, sysmon_extract, utcnow, uuid_string,
                     NATIVE_SETTLE_SECONDS)

CHAIN_PACK_ID = 'ps_task_chain'
KIND = 'scheduled_task_chain'
CASES = {
    'chain_attack': {'label': '스크립트 → 예약 작업 → 지연 실행', 'expected': 'attack', 'variant': False},
    'chain_benign': {'label': '정상 정기 관리 작업', 'expected': 'benign', 'variant': False},
    'chain_variant': {'label': '별도 경로·실행 형태의 변형 공격', 'expected': 'attack', 'variant': True},
}
SOURCES = {
    'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational': ('Microsoft-Windows-Sysmon', 'Microsoft-Windows-Sysmon/Operational', 'Sysmon'),
    'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational': ('Microsoft-Windows-PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'PowerShell'),
    'XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational': ('Microsoft-Windows-TaskScheduler', 'Microsoft-Windows-TaskScheduler/Operational', 'TaskScheduler'),
    'XmlWinEventLog:Security': ('Microsoft-Windows-Security-Auditing', 'Security', 'Security'),
}


def validate_chain_rule(rule):
    if not isinstance(rule, dict) or set(rule) != {'kind', 'name', 'profile'} or rule['kind'] != KIND or rule['profile'] not in ('powershell_broad', 'task_behavior'):
        raise RangeError('체인 규칙은 고정된 PowerShell 기준 또는 작업 행위 프로파일만 사용할 수 있습니다.')
    if not isinstance(rule['name'], str) or not 1 <= len(rule['name']) <= 120 or any(ord(c) < 32 for c in rule['name']):
        raise RangeError('체인 규칙 이름은 1~120자여야 합니다.')
    return copy.deepcopy(rule)


def baseline():
    return {'kind': KIND, 'name': 'PowerShell 실행 기준 규칙', 'profile': 'powershell_broad'}


def candidate():
    return {'kind': KIND, 'name': '스크립트·예약 등록·지연 실행 상관 규칙', 'profile': 'task_behavior'}


def data_rex(name, field=None):
    return ' | rex field=_raw ' + literal("(?s)<Data\\s+Name=['\"]" + name + "['\"]>(?<" + (field or name) + ">.*?)</Data>")


def decode_xml(field):
    expression = field
    for old, new in (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&apos;', "'"), ('&amp;', '&')):
        expression = 'replace(' + expression + ',' + literal(old) + ',' + literal(new) + ')'
    return ' | eval ' + field + '=' + expression


def system_rex():
    return (' | rex field=_raw "<EventID>(?<EventCode>[0-9]+)</EventID>"'
            ' | rex field=_raw "<Computer>(?<Computer>[^<]+)</Computer>"'
            ' | rex field=_raw ' + literal("<Execution[^>]+ProcessID=['\"](?<SystemPID>[0-9]+)['\"]"))


def scoped(c, source):
    return 'index="win" sourcetype="XmlWinEventLog" source=' + literal(source) + ' host=' + literal(c['windows_hostname'])


def native_payload(search, rule, name):
    # The alert is emitted by Splunk logevent, from an actual native ProcessGuid.
    return (search + ' | eval audit_process_guid=lower(trim(ProcessGuid,"{}")),alert_id=' + literal(name + ':') + '.audit_process_guid'
            ' | where match(audit_process_guid,"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$") | dedup alert_id'
            ' | eval alert_payload=json_object("event_kind","alert","id",alert_id,"audit_process_guid",audit_process_guid,'
            '"host",Computer,"Image",Image,"event_epoch",tonumber(_time),"alert_created_at",strftime(now(),"%Y-%m-%dT%H:%M:%S.%3N%:z"),'
            '"detection_rule_id",' + literal(name) + ',"rule_sha256",' + literal(rule_digest(rule)) + ',"detection_engine","splunk_saved_search")'
            ' | fields alert_id alert_payload audit_process_guid _time')


def rule_search(c, rule, name, enabled_since):
    validate_chain_rule(rule)
    host = literal(c['windows_hostname'].lower())
    if rule['profile'] == 'powershell_broad':
        search = (scoped(c, 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational') + sysmon_extract()
                  + ' | where EventCode="1" AND lower(Computer)=' + host + ' AND _time>=' + format(enabled_since, '.6f')
                  + ' AND match(lower(Image),' + literal(r'\\powershell\.exe$') + ')')
        return native_payload(search, rule, name)
    # No script/task filenames or labels are detector conditions. The profile
    # correlates actor PID -> registration -> actual task launch PID -> Sysmon
    # child creation, with generic writable-directory + unusual argument checks.
    registration = (scoped(c, 'XmlWinEventLog:Security') + system_rex()
                    + data_rex('TaskName') + data_rex('TaskContent') + decode_xml('TaskContent')
                    + ' | rex field=TaskContent "<Command>(?<TaskCommand>[^<]+)</Command>"'
                    + ' | rex field=TaskContent "<Arguments>(?<TaskArguments>[^<]+)</Arguments>"'
                    + ' | rex field=TaskContent "<WorkingDirectory>(?<TaskDirectory>[^<]+)</WorkingDirectory>"'
                    + ' | where EventCode="4698" AND lower(Computer)=' + host + ' AND _time>=' + format(enabled_since, '.6f')
                    + ' | eval RegisteredAt=_time,Computer=lower(Computer),TaskName=lower(TaskName)'
                    + ' | where match(lower(TaskCommand),' + literal(r'\\powershell\.exe$') + ')'
                    + ' AND match(lower(TaskDirectory),' + literal(r'^c:\\(windows\\temp(?:\\|$)|users\\[^\\]+\\appdata\\(?:local|roaming)\\)') + ')'
                    + ' AND (match(lower(TaskArguments),"-(encodedcommand|enc)(\\\\s|$)") OR match(lower(TaskArguments),"-(windowstyle|w)\\\\s+(hidden|h)(\\\\s|$)"))'
                    + ' | head 5001')
    tasks = ('search ' + scoped(c, 'XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational') + system_rex()
             + data_rex('TaskName') + data_rex('ProcessId', 'TaskPIDa') + data_rex('ProcessID', 'TaskPIDb')
             + ' | where EventCode="129" AND lower(Computer)=' + host
             + ' | eval TaskName=lower(TaskName),Computer=lower(Computer),TaskProcessPID=tonumber(coalesce(TaskPIDa,TaskPIDb)),LaunchedAt=_time'
             + ' | head 5001 | fields Computer TaskName TaskProcessPID LaunchedAt')
    processes = ('search ' + scoped(c, 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational') + sysmon_extract() + data_rex('ProcessId', 'TaskProcessPID')
                 + ' | where EventCode="1" AND lower(Computer)=' + host
                 + ' | eval Computer=lower(Computer),TaskProcessPID=tonumber(TaskProcessPID),CreatedAt=_time'
                 + ' | head 5001 | fields Computer TaskProcessPID ProcessGuid Image CommandLine CreatedAt')
    scripts = ('search ' + scoped(c, 'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational') + system_rex() + data_rex('ScriptBlockText') + decode_xml('ScriptBlockText')
               + ' | where EventCode="4104" AND lower(Computer)=' + host + ' AND match(lower(ScriptBlockText),"register-scheduledtask")'
               + ' | eval Computer=lower(Computer),CreatorPID=tonumber(SystemPID),ScriptAt=_time'
               + ' | head 5001 | fields Computer CreatorPID ScriptAt')
    actions = ('search ' + scoped(c, 'XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational') + system_rex() + data_rex('TaskName') + data_rex('ActionName')
               + ' | where EventCode="200" AND lower(Computer)=' + host + ' AND match(lower(ActionName),' + literal(r'\\powershell\.exe$') + ')'
               + ' | eval Computer=lower(Computer),TaskName=lower(TaskName),ActionAt=_time | head 5001 | fields Computer TaskName ActionAt')
    module = ('search ' + scoped(c, 'XmlWinEventLog:Microsoft-Windows-PowerShell/Operational') + system_rex() + data_rex('Payload') + decode_xml('Payload')
              + ' | rex field=Payload ' + literal(r'(?is)ParameterBinding\(Register-ScheduledTask\):\s*name="TaskName";\s*value="(?<BoundTaskName>[^"]+)"')
              + ' | where EventCode="4103" AND lower(Computer)=' + host + ' AND isnotnull(BoundTaskName)'
              + ' | eval Computer=lower(Computer),TaskName=lower(' + literal('\\') + '.BoundTaskName),CreatorPID=tonumber(SystemPID),BoundAt=_time'
              + ' | head 5001 | fields Computer TaskName CreatorPID BoundAt')
    search = (registration + ' | join type=inner max=0 Computer TaskName [' + tasks + ']'
              + ' | join type=inner max=0 Computer TaskName [' + actions + ']'
              + ' | join type=inner max=0 Computer TaskProcessPID [' + processes + ']'
              + ' | join type=inner max=0 Computer TaskName [' + module + ']'
              + ' | join type=inner max=0 Computer CreatorPID [' + scripts + ']'
              + ' | where ScriptAt>=RegisteredAt-60 AND ScriptAt<=RegisteredAt+5 AND BoundAt>=RegisteredAt-10 AND BoundAt<=RegisteredAt+5 AND LaunchedAt>=RegisteredAt+5 AND LaunchedAt<=RegisteredAt+180 AND CreatedAt>=LaunchedAt-3 AND CreatedAt<=LaunchedAt+10 AND ActionAt>=LaunchedAt-3 AND ActionAt<=LaunchedAt+10'
              + ' | eval _time=CreatedAt | fields _time Computer ProcessGuid Image CommandLine')
    return native_payload(search, rule, name)


def script(case_id, phase_id, run_id):
    if case_id not in CASES:
        raise RangeError('등록된 단일 체인 시험만 실행할 수 있습니다.')
    phase_id, run_id = uuid_string(phase_id), uuid_string(run_id)
    # These generated names are private receipts, never rule feature values.
    task_name = 'AegisLoop-' + run_id
    anchor_path = 'C:\\AegisLoop\\runs\\' + phase_id + '\\' + run_id + '\\register.ps1'
    folder = '$env:TEMP' if case_id == 'chain_attack' else "(Join-Path $env:APPDATA 'cache-work')" if case_id == 'chain_variant' else "'C:\\ProgramData\\AegisLoop\\operations'"
    child = ("$ErrorActionPreference='Stop'; [IO.File]::WriteAllText($output, ('{\"run_id\":\"" + run_id + "\",\"completed_at\":\"' + [DateTime]::UtcNow.ToString('o') + '\"}'), [Text.UTF8Encoding]::new($false))")
    # $output is injected as a validated UUID-owned path in the generated wrapper.
    payload = r'''$ErrorActionPreference='Stop'
# Resolve the actual existing NTFS name, including 8.3 TEMP aliases, before
# recording paths that must equal kernel/Sysmon FileCreate originals.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class AegisLoopNativePath {
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 public static extern uint GetLongPathName(string path, StringBuilder result, uint capacity);
}
'@
function Get-AegisLongPath([string]$path) {
 if (-not (Test-Path -LiteralPath $path)) { throw 'Path does not exist for canonical receipt' }
 $resolved=(Resolve-Path -LiteralPath $path -ErrorAction Stop).ProviderPath
 $buffer=New-Object Text.StringBuilder 32768
 $length=[AegisLoopNativePath]::GetLongPathName($resolved,$buffer,[uint32]$buffer.Capacity)
 if ($length -eq 0 -or $length -ge $buffer.Capacity) { throw 'Native long path resolution failed' }
 return $buffer.ToString()
}
$taskName='TASKNAME'
$root=ROOTDIR
$work=Join-Path $root 'RUNID'
$output=Join-Path $work 'outcome.json'
$childPath=Join-Path $work 'CHILDNAME'
$registered=$false
$receipt=$null
try {
 New-Item -ItemType Directory -Force -Path $work | Out-Null
 $work=Get-AegisLongPath $work
 $output=Join-Path $work 'outcome.json'
 $childPath=Join-Path $work 'CHILDNAME'
 $child='$output = '+[char]39+$output+[char]39+'; '+[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('CHILD'))
 [IO.File]::WriteAllText($childPath,$child,[Text.UTF8Encoding]::new($false))
 $exe='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
 ARGUMENTS
 $action=New-ScheduledTaskAction -Execute $exe -Argument $arguments -WorkingDirectory $work
 $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(20)
 $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
 if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { throw 'Owned task name already exists' }
 Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
 $registered=$true
 $registeredAt=[DateTime]::UtcNow.ToString('o')
 $deadline=(Get-Date).AddSeconds(110)
 while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $output)) { Start-Sleep -Seconds 1 }
 if (-not (Test-Path -LiteralPath $output)) { throw 'Task outcome not observed' }
 $observed=Get-Content -Raw -LiteralPath $output | ConvertFrom-Json
 if ($observed.run_id -ne 'RUNID') { throw 'Task outcome mismatch' }
 $wait=(Get-Date).AddSeconds(10)
 do { $info=Get-ScheduledTaskInfo -TaskName $taskName; $task=Get-ScheduledTask -TaskName $taskName; if ($task.State -ne 'Running') { break }; Start-Sleep -Milliseconds 500 } while ((Get-Date) -lt $wait)
 if ($task.State -eq 'Running' -or $info.LastTaskResult -ne 0) { throw 'Task result not successful' }
 $receipt=[ordered]@{run_id='RUNID';task_name=$taskName;registered_at=$registeredAt;completed_at=[string]$observed.completed_at;execution_verified=$true;result_sha256=(Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant();last_task_result=[long]$info.LastTaskResult;task_directory=(Get-AegisLongPath $work);output_path=(Get-AegisLongPath $output)}
} finally {
 if ($registered) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop }
 if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop }
 $clean=($null -eq (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) -and -not (Test-Path -LiteralPath $work)
 if (-not $clean) { throw 'Cleanup verification failed' }
 if ($receipt) { $receipt['cleanup_verified']=$true; $receipt['cleaned_at']=[DateTime]::UtcNow.ToString('o') }
}
if (-not $receipt) { throw 'No verified outcome receipt' }
$receipt | ConvertTo-Json -Compress
'''
    if case_id == 'chain_attack':
        arguments = "$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($child))"
    elif case_id == 'chain_variant':
        arguments = "$arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"'+$childPath+'\"'"
    else:
        arguments = "$arguments='-NoProfile -NonInteractive -File \"'+$childPath+'\"'"
    payload = payload.replace('TASKNAME', task_name).replace('ROOTDIR', folder).replace('RUNID', run_id).replace('CHILDNAME', 'cache-check.ps1' if case_id == 'chain_variant' else 'operation.ps1').replace('CHILD', base64.b64encode(child.encode()).decode()).replace('ARGUMENTS', arguments)
    encoded = base64.b64encode(payload.encode()).decode()
    outer = ("$ErrorActionPreference='Stop';$path='" + anchor_path + "'; New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null; "
             "[IO.File]::WriteAllBytes($path,[Convert]::FromBase64String('" + encoded + "')); & 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File $path; exit $LASTEXITCODE")
    return outer, anchor_path, task_name


def execute(rt, case_id, phase_id, run_id):
    outer, anchor, task_name = script(case_id, phase_id, run_id)
    rt.tunnel.ensure()
    definition = CASES[case_id]
    started = utcnow()
    result = {'case_id': case_id, 'scenario_id': case_id, 'name': definition['label'], **definition,
              'status': 'failed', 'exit_code': None, 'summary': '체인 실행 결과를 독립 확인하지 못했습니다.',
              'correlation_id': run_id, 'anchor_path': anchor, 'task_name': task_name, 'started_at': started,
              'execution_verified': False, 'cleanup_verified': False}
    try:
        import winrm
        session = winrm.Session('http://127.0.0.1:15985/wsman', auth=(rt.config['windows_user'], rt.config['windows_password']),
                                transport='ntlm', message_encryption='always', read_timeout_sec=180, operation_timeout_sec=160)
        # pywinrm UTF-16/base64 encoding can exceed Windows' 8191-character
        # command-line limit. Upload the fixed generated wrapper in bounded
        # chunks, then launch its short literal path as a real child process.
        payload_b64 = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", outer).group(1)
        payload = base64.b64decode(payload_b64)
        setup = "$ErrorActionPreference='Stop';$p='" + anchor + "';New-Item -ItemType Directory -Force -Path (Split-Path $p)|Out-Null;[IO.File]::WriteAllBytes($p,[byte[]]@())"
        if session.run_ps(setup).status_code != 0:
            raise RangeError('실행 래퍼를 준비하지 못했습니다.')
        for offset in range(0, len(payload), 1536):
            chunk = base64.b64encode(payload[offset:offset+1536]).decode()
            upload = "$ErrorActionPreference='Stop';$p='" + anchor + "';$b=[Convert]::FromBase64String('" + chunk + "');$f=[IO.File]::Open($p,[IO.FileMode]::Append);try{$f.Write($b,0,$b.Length)}finally{$f.Dispose()}"
            if session.run_ps(upload).status_code != 0:
                raise RangeError('실행 래퍼 업로드를 완료하지 못했습니다.')
        launch = "$ErrorActionPreference='Stop';$p='" + anchor + "';try{& 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe' -NoProfile -ExecutionPolicy Bypass -File $p;$code=$LASTEXITCODE}finally{Remove-Item -LiteralPath (Split-Path $p) -Recurse -Force -ErrorAction Stop};exit $code"
        response = session.run_ps(launch)
        result.update({'exit_code': response.status_code, 'stdout_base64': base64.b64encode(response.std_out[:65536]).decode(), 'stderr_base64': base64.b64encode(response.std_err[:65536]).decode(), 'output_truncated': len(response.std_out) > 65536 or len(response.std_err) > 65536})
        if response.status_code == 0 and not result['output_truncated']:
            receipt = json_read(response.std_out.decode('utf-8-sig').strip())
            if not isinstance(receipt, dict) or receipt.get('run_id') != run_id or receipt.get('task_name') != task_name or receipt.get('execution_verified') is not True or receipt.get('cleanup_verified') is not True or receipt.get('last_task_result') != 0 or not re.fullmatch(r'[0-9a-f]{64}', receipt.get('result_sha256', '')):
                raise RangeError('실제 작업 실행·결과·정리 영수증을 확인하지 못했습니다.')
            epoch(receipt.get('registered_at')); epoch(receipt.get('completed_at')); epoch(receipt.get('cleaned_at'))
            result.update({'status': 'completed', 'summary': '예약 작업의 실제 지연 실행·무해한 결과 파일·정리를 확인했습니다.', 'execution_verified': True, 'cleanup_verified': True, 'execution_receipt': receipt})
    except Exception:
        result['summary'] = '체인 실행 연결 또는 독립 결과 확인이 실패했습니다. 자동 재실행하지 않습니다.'
    result['finished_at'] = utcnow()
    return result


def pid(value):
    try:
        text = str(value)
        result = int(text, 16 if text.lower().startswith('0x') else 10)
        if not 0 < result <= 0xffffffff:
            raise ValueError()
        return result
    except (ValueError, TypeError):
        raise RangeError('원본 프로세스 PID 형식을 확인하지 못했습니다.') from None


def task_key(value):
    if not isinstance(value, str) or not value or len(value) > 512:
        raise RangeError('원본 작업 이름을 확인하지 못했습니다.')
    return value.lstrip('\\').lower()


def parse(row, c):
    source = row.get('source')
    if source not in SOURCES or row.get('sourcetype') != 'XmlWinEventLog' or str(row.get('host', '')).lower() != c['windows_hostname'].lower():
        raise RangeError('다중 로그의 고정 출처와 호스트 범위가 다릅니다.')
    raw = row.get('_raw')
    if not isinstance(raw, str) or len(raw.encode()) > 256 << 10 or re.search(r'<!DOCTYPE|<!ENTITY', raw, re.I):
        raise RangeError('다중 로그 XML 원본을 확인하지 못했습니다.')
    def local(tag):
        return tag.split('}')[-1]
    try:
        root = ET.fromstring(raw)
        system = next(n for n in root if local(n.tag) == 'System')
        elements = {}
        for e in system:
            key = local(e.tag)
            if key in elements:
                raise RangeError('원본 시스템 XML 필드가 중복됩니다.')
            elements[key] = e
        provider, channel, title = SOURCES[source]
        if elements['Provider'].get('Name') != provider or elements['Channel'].text != channel or (elements['Computer'].text or '').lower() != c['windows_hostname'].lower():
            raise RangeError('원본 공급자·채널·호스트가 일치하지 않습니다.')
        code = elements['EventID'].text
        relevant = {'Sysmon': {'1', '11'}, 'PowerShell': {'4103', '4104'}, 'Security': {'4698'}, 'TaskScheduler': {'100', '129', '200', '201'}}
        if code not in relevant[title]:
            return None
        at = epoch(elements['TimeCreated'].get('SystemTime'))
        native_at = float(row['native_event_epoch'])
        if not math.isfinite(native_at) or abs(native_at - at) > 2:
            raise RangeError('다중 로그의 원본 시각과 Splunk 시각이 일치하지 않습니다.')
        values = {}
        data = next(n for n in root if local(n.tag) == 'EventData')
        for element in data:
            name = element.get('Name')
            if not name or name in values:
                raise RangeError('원본 이벤트 필드 이름이 없거나 중복됩니다.')
            values[name] = element.text or ''
        result = {'source': title, 'event_code': code, 'time': datetime.fromtimestamp(at, timezone.utc).isoformat().replace('+00:00', 'Z'),
                  'epoch': at, 'values': values, 'native': copy.deepcopy(row)}
        if 'Execution' in elements and elements['Execution'].get('ProcessID'):
            result['system_pid'] = pid(elements['Execution'].get('ProcessID'))
        if title == 'Sysmon':
            result['process_guid'] = process_guid(values.get('ProcessGuid'))
            result['process_pid'] = pid(values.get('ProcessId'))
            if code == '1':
                result['parent_guid'] = process_guid(values.get('ParentProcessGuid'))
                if not values.get('Image') or not values.get('CommandLine'):
                    raise RangeError('실제 프로세스 생성 필드가 없습니다.')
        if values.get('TaskName'):
            result['task_key'] = task_key(values['TaskName'])
        if title == 'TaskScheduler' and code == '129':
            result['launched_pid'] = pid(values.get('ProcessID', values.get('ProcessId')))
        if title == 'PowerShell' and code == '4103':
            payload = values.get('Payload', '')
            match = re.search(r'(?is)ParameterBinding\(Register-ScheduledTask\):\s*name="TaskName";\s*value="([^"]+)"', payload)
            if match:
                result['task_key'] = task_key(match[1])
        return result
    except (ET.ParseError, KeyError, StopIteration, ValueError, TypeError):
        raise RangeError('다중 로그 XML의 필수 원본 필드를 해석하지 못했습니다.') from None


def action_values(event):
    content = event['values'].get('TaskContent', '')
    if not content or len(content) > 65536 or re.search(r'<!DOCTYPE|<!ENTITY', content, re.I):
        raise RangeError('원본 예약 작업 XML을 확인하지 못했습니다.')
    try:
        root = ET.fromstring(content)
        values = {}
        for e in root.iter():
            name = e.tag.split('}')[-1]
            if name in ('Command', 'Arguments', 'WorkingDirectory'):
                if name in values:
                    raise RangeError('작업 실행 동작이 여러 개라 단일 시험 귀속을 확인하지 못했습니다.')
                values[name] = e.text or ''
        if set(values) != {'Command', 'Arguments', 'WorkingDirectory'} or not all(values.values()):
            raise RangeError('작업 실행 XML의 실행 파일·인자·작업 디렉터리가 빠졌습니다.')
        return values
    except ET.ParseError:
        raise RangeError('예약 작업 실행 XML을 해석하지 못했습니다.') from None


def correlate(result, events):
    """Resolve actual task entity/PID links, never proximity-only actor links."""
    identifier = result['case_id']
    key = task_key(result.get('task_name'))
    start, finish = epoch(result['started_at']) - 3, epoch(result['finished_at']) + 3
    window = [e for e in events if start <= e['epoch'] <= finish]
    roots = [e for e in window if e['source'] == 'Sysmon' and e['event_code'] == '1' and e['values'].get('Image', '').lower().endswith('\\powershell.exe') and result.get('anchor_path', '').lower() in e['values'].get('CommandLine', '').lower()]
    if not result.get('anchor_path') or len({e['process_guid'] for e in roots}) != 1:
        return {'verified': False, 'gaps': ['시나리오의 실제 PowerShell 시작 프로세스를 고유하게 확인하지 못했습니다.'], 'stages': [], 'events': [], 'guids': set()}
    root = roots[0]
    modules = [e for e in window if e['source'] == 'PowerShell' and e['event_code'] == '4103' and e.get('system_pid') == root['process_pid'] and e.get('task_key') == key]
    scripts = [e for e in window if e['source'] == 'PowerShell' and e['event_code'] == '4104' and e.get('system_pid') == root['process_pid'] and 'register-scheduledtask' in e['values'].get('ScriptBlockText', '').lower()]
    regs = [e for e in window if e['source'] == 'Security' and e['event_code'] == '4698' and e.get('task_key') == key]
    if len(regs) != 1:
        return {'verified': False, 'gaps': ['단일 예약 작업의 실제 등록 기록을 확인하지 못했습니다.'], 'stages': [], 'events': [root], 'guids': {root['process_guid']}}
    registration = regs[0]
    modules = [e for e in modules if registration['epoch'] - 10 <= e['epoch'] <= registration['epoch'] + 5]
    scripts = [e for e in scripts if registration['epoch'] - 60 <= e['epoch'] <= registration['epoch'] + 5]
    launches = [e for e in window if e['source'] == 'TaskScheduler' and e['event_code'] == '129' and e.get('task_key') == key and registration['epoch'] + 5 <= e['epoch'] <= registration['epoch'] + 180]
    children = []
    actions, completions, files = [], [], []
    for launch in launches:
        children.extend(e for e in window if e['source'] == 'Sysmon' and e['event_code'] == '1' and e['process_pid'] == launch['launched_pid'] and launch['epoch'] - 3 <= e['epoch'] <= launch['epoch'] + 10 and e['values'].get('Image', '').lower().endswith('\\powershell.exe'))
        actions.extend(e for e in window if e['source'] == 'TaskScheduler' and e['event_code'] == '200' and e.get('task_key') == key and launch['epoch'] - 3 <= e['epoch'] <= launch['epoch'] + 10 and e['values'].get('ActionName', '').lower().endswith('\\powershell.exe'))
        completions.extend(e for e in window if e['source'] == 'TaskScheduler' and e['event_code'] == '201' and e.get('task_key') == key and e['values'].get('ResultCode') == '0' and e['epoch'] >= launch['epoch'])
    child_guids = {e['process_guid'] for e in children}
    receipt = result.get('execution_receipt', {})
    files = [e for e in window if e['source'] == 'Sysmon' and e['event_code'] == '11' and e['process_guid'] in child_guids and e['values'].get('TargetFilename', '').lower() == str(receipt.get('output_path', '')).lower()]
    gaps = []
    for valid, message in ((modules and scripts, 'PowerShell 스크립트와 실제 TaskName 파라미터 바인딩이 연결되지 않았습니다.'), (launches and children and actions and completions, '예약 작업 실행과 실제 후속 프로세스·완료 기록이 모두 연결되지 않았습니다.'), (files, '후속 프로세스의 무해한 결과 파일 생성이 로그로 확인되지 않았습니다.'), (result.get('execution_verified') and result.get('cleanup_verified'), '실행 결과 및 정리의 독립 확인이 완료되지 않았습니다.')):
        if not valid:
            gaps.append(message)
    observed = [root, *scripts, *modules, registration, *launches, *actions, *children, *completions, *files]
    stages = [
        {'name': '스크립트 실행', 'status': 'observed' if scripts and modules else 'missing', 'time': root['time'], 'evidence': 'Sysmon 1과 동일 PowerShell PID의 4104·4103 등록 인자를 연결했습니다.' if scripts and modules else '원본 PowerShell 스크립트·인자 연결이 부족합니다.'},
        {'name': '작업 등록', 'status': 'observed', 'time': registration['time'], 'evidence': 'Security 4698의 실제 TaskName·TaskContent를 확인했습니다.'},
        {'name': '지연 실행', 'status': 'observed' if launches and children and actions and completions else 'missing', 'time': launches[0]['time'] if launches else None, 'evidence': 'TaskScheduler 129·200·201과 동일 ChildPID의 Sysmon 1을 연결했습니다.' if launches and children and actions and completions else '작업 실행·후속 프로세스·완료 중 일부 원본이 부족합니다.'},
        {'name': '결과·정리', 'status': 'verified' if files and result.get('execution_verified') and result.get('cleanup_verified') else 'unknown', 'time': receipt.get('cleaned_at'), 'evidence': '실제 결과 파일 SHA256·작업 종료 코드·작업 및 실행 파일 정리를 독립 확인했습니다.' if files and result.get('execution_verified') and result.get('cleanup_verified') else '독립 실행 결과와 파일 생성·정리 근거가 부족합니다.'},
    ]
    return {'verified': not gaps, 'gaps': gaps, 'stages': stages, 'events': observed, 'guids': {root['process_guid']} | child_guids, 'first_epoch': root['epoch'], 'action': action_values(registration)}


def collect(rt, phase, deployment):
    start, finish = epoch(phase['started_at']) - 3, epoch(phase['finished_at']) + 3
    if not 0 < finish - start <= 600:
        raise RangeError('체인 실행의 10분 이내 원본 수집 범위를 확인하세요.')
    query = ('search index="win" sourcetype="XmlWinEventLog" host=' + literal(rt.config['windows_hostname']) + ' (' + ' OR '.join('source=' + literal(s) for s in SOURCES) + ')'
             + ' | eval native_event_epoch=tonumber(_time) | fields _raw _time native_event_epoch host source sourcetype | head 5001')
    audit = rt.splunk.search(query, start, finish)
    alerts = rt.splunk.search('search index="aegis_range_alerts" sourcetype="aegis:range:alert" source=' + literal(deployment['rule_id']) + ' | fields _raw _time host source sourcetype | head 5001', start, time.time() + 1)
    scheduler = rt.splunk.scheduler_proof(deployment, start, finish)
    warnings = [*audit['warnings'], *alerts['warnings'], *scheduler['warnings']]
    # Native joins have a fixed 5001 row guard. Prove that every input source in
    # the actual scheduled job's full lookback remained below that bound before
    # treating a missing alert as a real miss/true negative.
    cardinality = None
    if scheduler['complete'] and scheduler.get('jobs'):
        job = scheduler['jobs'][0]
        count_query = 'search index="win" sourcetype="XmlWinEventLog" host=' + literal(rt.config['windows_hostname']) + ' (' + ' OR '.join('source=' + literal(s) for s in SOURCES) + ') | stats count by source'
        cardinality = rt.splunk.search(count_query, job['earliest_time'], job['latest_time'])
        try:
            if not cardinality['complete'] or any(row.get('source') not in SOURCES or not 0 <= int(row.get('count', -1)) <= 5000 for row in cardinality['rows']):
                raise ValueError()
        except (ValueError, TypeError):
            warnings.append('실제 예약 검색의 다중 로그 입력 한도·완전성을 확인하지 못했습니다.')
    else:
        warnings.append('네이티브 상관 검색의 입력 범위를 확인하지 못했습니다.')
    events = []
    for row in audit['rows']:
        try:
            event = parse(row, rt.config)
            if event is not None:
                if not start <= event['epoch'] <= finish:
                    raise RangeError('원본 이벤트가 실행 범위를 벗어났습니다.')
                events.append(event)
        except RangeError:
            warnings.append('일부 다중 로그 XML의 출처·시각·필수 필드 검증이 실패했습니다.')
    # One ProcessGuid must identify one actual process creation. Contradictory
    # records cannot be credited to two cases or joined to an alert.
    creations = {}
    for event in events:
        if event['source'] == 'Sysmon' and event['event_code'] == '1':
            guid = event['process_guid']
            signature = (event['process_pid'], event['parent_guid'], event['epoch'], event['values'].get('Image'), event['values'].get('CommandLine'))
            if guid in creations and creations[guid] != signature:
                warnings.append('동일 ProcessGuid의 프로세스 생성 원본이 상충합니다.')
            creations[guid] = signature
    native_alerts = []
    for row in alerts['rows']:
        try:
            value = json_read(row['_raw'])
            if row.get('source') != deployment['rule_id'] or row.get('sourcetype') != 'aegis:range:alert' or not isinstance(value, dict) or value.get('event_kind') != 'alert' or value.get('detection_engine') != 'splunk_saved_search' or value.get('detection_rule_id') != deployment['rule_id'] or value.get('rule_sha256') != deployment['rule_sha256'] or str(value.get('host', '')).lower() != rt.config['windows_hostname'].lower():
                raise ValueError()
            at, created = float(value['event_epoch']), epoch(value['alert_created_at'])
            if not math.isfinite(at) or created < at - 3 or created > time.time() + 3:
                raise ValueError()
            guid = process_guid(value['audit_process_guid'])
            if not start <= at <= finish:
                continue
            matching = next((e for e in events if e['source'] == 'Sysmon' and e['event_code'] == '1' and e['process_guid'] == guid and abs(e['epoch'] - at) <= 2), None)
            if matching:
                native_alerts.append({'guid': guid, 'created': created, 'native': copy.deepcopy(row)})
        except (RangeError, ValueError, TypeError, KeyError):
            warnings.append('네이티브 체인 경보의 규칙·해시·시각·ProcessGuid 귀속을 확인하지 못했습니다.')
    settled = time.time() >= epoch(phase['finished_at']) + NATIVE_SETTLE_SECONDS
    complete = audit['complete'] and alerts['complete'] and scheduler['complete'] and not warnings and settled
    if not settled:
        warnings.append('실제 예약 검색의 경보 대기 시간이 끝나지 않았습니다.')
    cases, timeline, analyses = [], [], []
    resolved = {}
    owners = {}
    for result in phase.get('results', []):
        identifier = result.get('case_id', result.get('scenario_id'))
        if identifier not in CASES or identifier in resolved:
            raise RangeError('체인 실행 결과 식별자가 없거나 중복됩니다.')
        try:
            links = correlate({**result, 'case_id': identifier}, events)
        except RangeError:
            links = {'verified': False, 'gaps': ['원본 작업 XML·객체 상관 관계를 확인하지 못했습니다.'], 'stages': [], 'events': [], 'guids': set()}
        for guid in links['guids']:
            if guid in owners and owners[guid] != identifier:
                warnings.append('실제 ProcessGuid가 여러 시험에 공유되어 고유 귀속이 불가능합니다.')
            owners[guid] = identifier
        resolved[identifier] = links
    if not resolved:
        warnings.append('실제 체인 실행 결과가 없어 판정할 수 없습니다.')
    complete = complete and not warnings
    metrics = {key: 0 for key in ('true_positives', 'false_negatives', 'false_positives', 'true_negatives', 'unknown', 'attack_total', 'benign_total')}
    scoped_guids = set()
    seen_timeline = set()
    for result in phase.get('results', []):
        identifier = result.get('case_id', result.get('scenario_id'))
        if identifier not in CASES:
            raise RangeError('등록되지 않은 체인 실행 결과는 판정할 수 없습니다.')
        definition = CASES[identifier]
        metrics['attack_total' if definition['expected'] == 'attack' else 'benign_total'] += 1
        links = resolved[identifier]
        matched = [a for a in native_alerts if a['guid'] in links['guids']]
        scoped_guids.update(a['guid'] for a in matched)
        detected = bool(matched)
        if not links['verified'] or not result.get('execution_verified') or not complete:
            verdict = 'unknown'
            metrics['unknown'] += 1
            reason = '실행·다중 로그 상관·수집 완전성 중 일부를 확정하지 못했습니다.'
        elif definition['expected'] == 'attack':
            verdict = 'detected' if detected else 'missed'
            metrics['true_positives' if detected else 'false_negatives'] += 1
            reason = '실제 공격 체인의 원본과 해당 규칙의 네이티브 경보가 연결됐습니다.' if detected else '독립 확인된 실제 체인 실행에 해당 규칙의 경보가 없습니다.'
        else:
            verdict = 'false_positive' if detected else 'true_negative'
            metrics['false_positives' if detected else 'true_negatives'] += 1
            reason = '정상 관리 작업에 실제 네이티브 경보가 발생했습니다.' if detected else '독립 확인된 정상 관리 작업에는 해당 규칙의 경보가 없습니다.'
        latency = max(0, round(min(a['created'] for a in matched) - links.get('first_epoch', min(a['created'] for a in matched)), 3)) if matched and links['verified'] and complete else None
        cases.append({'case_id': identifier, **definition, 'verdict': verdict, 'execution_verified': bool(result.get('execution_verified') and result.get('cleanup_verified')), 'alert_count': len({a['guid'] for a in matched}), 'latency_seconds': latency, 'reason': reason, 'stages': links['stages']})
        analyses.extend(links['gaps'])
        for e in links['events']:
            signature = (identifier, e['source'], e['event_code'], e['epoch'], e.get('process_guid', e.get('task_key', e.get('system_pid'))))
            if signature in seen_timeline:
                continue
            seen_timeline.add(signature)
            image = e['values'].get('Image', e['values'].get('ActionName', ''))
            timeline.append({'time': e['time'], 'case_id': identifier, 'source': e['source'], 'event_code': e['event_code'], 'action': {'1': '프로세스 생성', '11': '파일 생성', '4103': '실제 작업 인자', '4104': '스크립트 블록', '4698': '작업 등록', '129': '작업 프로세스 생성', '200': '작업 동작 시작', '201': '작업 동작 완료'}.get(e['event_code'], '작업 기록'), 'summary': '원본 이벤트의 객체·PID·시각을 해당 실행에 연결했습니다.', 'process_image': image.replace('/', '\\').rsplit('\\', 1)[-1] if image else ''})
    public = {'complete': complete, 'audit_count': len(seen_timeline), 'alert_count': len(scoped_guids), 'detected_scenarios': [c['case_id'] for c in cases if c['verdict'] in ('detected', 'false_positive')], 'missed_scenarios': [c['case_id'] for c in cases if c['verdict'] == 'missed'], 'unknown_scenarios': [c['case_id'] for c in cases if c['verdict'] == 'unknown'], 'events': [], 'warnings': list(dict.fromkeys(warnings)), 'metrics': metrics, 'cases': cases, 'timeline': sorted(timeline, key=lambda e: e['time'])[:500], 'analysis': {'summary': '실제 작업 실행의 독립 결과와 PowerShell·Security·TaskScheduler·Sysmon 근거를 대조했습니다.', 'gaps': list(dict.fromkeys(analyses)), 'recommendations': ['정상 관리 활동의 오탐과 별도 변형 공격의 탐지를 함께 확인하세요.', '이 제한된 실습 표본의 TP/FP 개수로 기업 전체 정확도나 오탐률을 주장하지 않습니다.']}}
    return {'public': public, 'native_audit': audit, 'native_alerts': alerts, 'scheduler_proof': scheduler, 'source_cardinality': cardinality, 'parsed_events': events, 'scoped_alerts': [a['native'] for a in native_alerts if a['guid'] in scoped_guids], 'rule_deployment': copy.deepcopy(deployment), 'collected_at': utcnow()}
