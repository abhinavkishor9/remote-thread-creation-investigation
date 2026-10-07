# Investigation Notes

## Investigation Summary

The investigation examined the visibility of remote thread creation and process-injection-related activity on a Windows endpoint. The investigation began by validating Sysmon telemetry before attempting to interpret injection-related behavior.

The endpoint had Sysmon 15.21 running through the `Sysmon64` service. Sysmon Event ID 1 was available, while initial searches for Event ID 8 and Event ID 10 returned no events.

A controlled user-mode process investigation was then performed using PowerShell 7 as the source context and Notepad as the benign target process.

## Investigation Environment

```text
Host: DESKTOP-9MMM37V
OS: Windows 11 Pro
PowerShell: 7.6.6
Sysmon: 15.21
Sysmon Service: Sysmon64
Sysmon Status: Running
Wazuh Agent: 001
Workspace: C:\RemoteThreadCreationLab\Evidence
```

## Sysmon Baseline

The Sysmon service was checked using:

```powershell
Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue |
Select-Object Name, Status, StartType
```

The result was:

```text
Name     Status   StartType
----     ------   ---------
Sysmon64 Running  Automatic
```

Sysmon version information showed:

```text
System Monitor v15.21
```

This confirmed that Sysmon was installed and actively running.

## Initial Event Availability

Sysmon Event ID 8 was queried:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 8
} -MaxEvents 10
```

Result:

```text
No events were found that match the specified selection criteria.
```

Sysmon Event ID 10 was queried:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 10
} -MaxEvents 10
```

Result:

```text
No events were found that match the specified selection criteria.
```

Event ID 1 was available and returned multiple process creation events.

This established the following telemetry state:

```text
EID 1  = Available
EID 8  = Not observed
EID 10 = Not observed
```

The result was treated as a telemetry limitation rather than proof that remote-thread activity was impossible.

## Investigation Workspace

The workspace was created at:

```text
C:\RemoteThreadCreationLab\Evidence
```

The directory was successfully created and validated:

```text
True
```

The investigation time was recorded in:

```text
Investigation-Time.txt
```

The host baseline and user context were also captured.

## Source Process

The PowerShell 7 process used for the investigation was:

```text
Process: pwsh.exe
PID: 21196
Path:
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe

StartTime:
07-10-2026 06:06:22
```

The source process information was preserved in:

```text
Source-Process.txt
```

## Target Process

A benign Notepad process was created:

```powershell
$Target = Start-Process notepad.exe -PassThru
```

The target process was:

```text
Process: notepad.exe
PID: 22348
Path: C:\Windows\notepad.exe
StartTime: 07-10-2026 06:13:08
```

The process was recorded in:

```text
Target-Process.txt
```

## Sysmon Process Creation Evidence

Sysmon Event ID 1 recorded the creation of the Notepad process.

Important fields included:

```text
Image:
C:\Windows\notepad.exe

ProcessId:
22348

CommandLine:
"C:\Windows\notepad.exe"

User:
DESKTOP-9MMM37V\Dell

IntegrityLevel:
High

ParentProcessId:
21196

ParentImage:
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe

ParentCommandLine:
"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe"
```

This provides direct evidence that Sysmon was able to observe the controlled process creation.

It does not establish process injection or remote thread creation.

## Controlled-Test Timestamp

The test timestamp was recorded using:

```powershell
$TestTime = Get-Date
$TestTimeUtc = [DateTime]::UtcNow
```

The evidence file also recorded:

```text
Source PID
Target PID
Local Test Time
UTC Test Time
```

This timestamp was used as the reference point for later event searches.

## Remote Thread Search

After the controlled activity, Sysmon Event ID 8 was searched within the investigation window.

The query returned:

```text
No events were found that match the specified selection criteria.
```

Therefore:

```text
No matching Sysmon EID 8 was observed.
```

The result does not prove that remote thread creation did not occur.

## Process Access Search

Sysmon Event ID 10 was searched using the same investigation window.

The query returned:

```text
No events were found that match the specified selection criteria.
```

Therefore:

```text
No matching Sysmon EID 10 was observed.
```

This means the investigation could not use Sysmon EID 10 to establish process-access activity.

## Process Creation During the Investigation Window

Sysmon Event ID 1 was searched around the controlled test timestamp.

The results included PowerShell process creation events associated with:

```text
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

The events showed:

```text
User:
NT AUTHORITY\SYSTEM

ParentImage:
C:\Windows\System32\wbem\WmiPrvSE.exe

ParentProcessId:
9236

CommandLine:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File
"C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"
```

These events were not attributed to the Lab 99 process relationship.

## Existing WMI Activity

The endpoint already had WMI-triggered PowerShell activity.

The process chain observed was:

```text
WmiPrvSE.exe
      |
      v
powershell.exe
      |
      v
wmi-payload.ps1
```

This activity was considered separate because:

- The parent process was `WmiPrvSE.exe`.
- The execution user was `NT AUTHORITY\SYSTEM`.
- The command line referenced the existing WMI Permanent Event lab.
- No evidence connected this activity to the controlled Notepad investigation.

This separation prevented unrelated telemetry from being incorrectly incorporated into the remote-thread investigation.

## Wazuh Investigation

Wazuh investigation should remain scoped to:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

The following event searches were used for correlation:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"1"
```

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"8"
```

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"10"
```

Additional process searches can use:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND "notepad.exe"
```

and:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND "pwsh.exe"
```

The purpose is to determine whether Wazuh received the same process telemetry and whether it provides additional evidence that is not visible through the local event log.

## Evidence Correlation

The available evidence can be represented as:

```text
Sysmon running
      |
      v
EID 1 available
      |
      v
PowerShell source identified
      |
      v
Notepad target created
      |
      v
Notepad EID 1 observed
      |
      +------------------+
      |                  |
      v                  v
EID 8 searched      EID 10 searched
      |                  |
      v                  v
No event            No event
      |                  |
      +--------+---------+
               |
               v
Remote thread creation
not independently established
```

## Evidence Assessment

| Evidence | Finding | Interpretation |
|---|---|---|
| Sysmon service | Running | Telemetry collection active |
| Sysmon EID 1 | Observed | Process creation telemetry available |
| Notepad EID 1 | Observed | Controlled target process visible |
| Sysmon EID 8 | Not observed | Remote-thread telemetry unavailable in reviewed data |
| Sysmon EID 10 | Not observed | Process-access telemetry unavailable in reviewed data |
| WMI PowerShell | Observed | Separate existing activity |
| Remote thread | Not established | Insufficient direct telemetry |
| Process injection | Not established | No sufficient evidence |

## Final Assessment

The investigation successfully validated Sysmon process creation telemetry and confirmed that the controlled Notepad process was visible through Event ID 1.

However, no Sysmon Event ID 8 or Event ID 10 events were observed. Consequently, the available evidence does not independently confirm CreateRemoteThread activity or process-access activity.

The existing WMI-triggered PowerShell activity was deliberately excluded from the remote-thread evidence chain because the available fields did not establish a relationship with the controlled test.

The strongest defensible conclusion is:

> **The endpoint provides usable Sysmon process creation telemetry, but remote thread creation and process access were not established from the available Event ID 8 and Event ID 10 telemetry.**
