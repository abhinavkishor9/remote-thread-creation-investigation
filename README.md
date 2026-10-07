# Remote Thread Creation Investigation

## Overview

This lab investigates remote thread creation as a potential process injection technique on a Windows endpoint. The investigation focuses on how process creation, process-access telemetry, remote-thread telemetry, and SIEM correlation can be used to determine whether remote thread activity can be established from available evidence.

A controlled user-mode process was used as the target to avoid interacting with sensitive system processes. PowerShell 7 was used as the investigation source context, while `notepad.exe` was created as the benign target process.

The investigation also began with a telemetry validation phase because Sysmon Event ID 8 and Event ID 10 were not observed during the initial review. Sysmon Event ID 1 was available and provided reliable process creation telemetry.

The investigation followed an evidence-driven approach. The absence of Event ID 8 or Event ID 10 was treated as a telemetry limitation rather than proof that remote thread activity could not occur.

## Environment

- Host: `DESKTOP-9MMM37V`
- Operating System: Windows 11 Pro
- PowerShell: 7.6.6
- Sysmon: 15.21
- Sysmon Service: `Sysmon64`
- Sysmon Status: Running
- Sysmon Start Type: Automatic
- Wazuh Agent: `001`
- Investigation Workspace: `C:\RemoteThreadCreationLab\Evidence`
- Source Process: PowerShell 7 (`pwsh.exe`)
- Target Process: `notepad.exe`

## Investigation Objectives

- Establish the Windows endpoint and investigation baseline.
- Verify that Sysmon is running and determine its current telemetry availability.
- Determine whether Sysmon Event ID 8 is observable.
- Determine whether Sysmon Event ID 10 is observable.
- Use Sysmon Event ID 1 as the primary available process telemetry.
- Establish a controlled source and target process relationship.
- Use a benign Notepad process as the target rather than a sensitive system process.
- Record source and target process identifiers and timestamps.
- Investigate process creation telemetry associated with the controlled activity.
- Search for remote-thread and process-access telemetry after the test.
- Correlate process identifiers and timestamps where sufficient evidence exists.
- Review the same activity through Wazuh endpoint telemetry.
- Separate unrelated WMI-triggered PowerShell activity from the current investigation.
- Document telemetry limitations encountered during the investigation.
- Distinguish process creation from process access and remote thread creation.
- Determine whether the available evidence establishes remote thread creation.
- Preserve the investigation artifacts and maintain a chronological timeline.

## Investigation Concept

Remote thread creation occurs when one process creates a thread inside another process. Attackers can abuse this capability as part of process injection to execute code inside a legitimate process.

A simplified investigation chain is:

```text
Source Process
      |
      v
Target Process
      |
      v
Process Access
      |
      v
Remote Thread Creation
      |
      v
Code Execution / Follow-on Activity
```

Remote thread creation is not automatically malicious. Legitimate applications and security tools can also interact with other processes.

The investigation therefore requires correlation between the source process, target process, requested access, thread activity, timestamps, and any subsequent behavior.

## Sysmon Telemetry

The relevant Sysmon events are:

| Event ID | Purpose |
|---|---|
| `1` | Process Create |
| `8` | CreateRemoteThread |
| `10` | Process Access |

The initial telemetry review produced:

| Event ID | Result |
|---|---|
| `1` | Available |
| `8` | No events observed |
| `10` | No events observed |

Sysmon itself was confirmed to be running:

```text
Service: Sysmon64
Status: Running
StartType: Automatic
Version: 15.21
```

The absence of Event ID 8 and Event ID 10 was treated as a visibility limitation. It was not interpreted as proof that remote thread creation did not occur.

## Controlled Process Activity

A benign Notepad process was created as the investigation target.

Observed target:

```text
Process: notepad.exe
PID: 22348
Path: C:\Windows\notepad.exe
StartTime: 07-10-2026 06:13:08
User: DESKTOP-9MMM37V\Dell
IntegrityLevel: High
ParentImage: pwsh.exe
ParentProcessId: 21196
```

The source PowerShell process was:

```text
Process: pwsh.exe
PID: 21196
Path: C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe
StartTime: 07-10-2026 06:06:22
```

The controlled test timestamp and process identifiers were recorded in the investigation evidence.

## Process Creation Evidence

Sysmon Event ID 1 successfully recorded the creation of the controlled Notepad process.

The event showed:

```text
Image:
C:\Windows\notepad.exe

ProcessId:
22348

ParentImage:
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe

ParentProcessId:
21196

User:
DESKTOP-9MMM37V\Dell

CommandLine:
"C:\Windows\notepad.exe"
```

This confirms that Sysmon process creation telemetry was available and that the controlled target process was observable.

## Remote Thread Telemetry

A search for Sysmon Event ID 8 returned:

```text
No events were found that match the specified selection criteria.
```

A search for Sysmon Event ID 10 also returned:

```text
No events were found that match the specified selection criteria.
```

Therefore, the available evidence did not independently establish a Sysmon CreateRemoteThread or Process Access event.

The correct assessment is:

```text
Sysmon EID 8: Not observed
Sysmon EID 10: Not observed
Sysmon EID 1: Available
```

This is a telemetry limitation and not proof that no remote-thread activity could occur.

## Unrelated Existing Activity

The endpoint also contained existing WMI-triggered PowerShell activity.

Example:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File
"C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"

User:
NT AUTHORITY\SYSTEM

ParentImage:
C:\Windows\System32\wbem\WmiPrvSE.exe

ParentProcessId:
9236
```

This activity was kept separate from the controlled remote-thread investigation because the available evidence did not establish a relationship between the WMI activity and the Lab 99 test.

## Wazuh Correlation

The investigation should use the endpoint-specific Wazuh filter:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V"
```

Relevant searches include:

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"1"
```

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"8"
```

```text
agent.id:"001" AND agent.name:"DESKTOP-9MMM37V" AND data.win.system.eventID:"10"
```

The endpoint filter is important because manager-side Wazuh events must not be interpreted as endpoint evidence.

## Evidence Assessment

| Finding | Assessment |
|---|---|
| Sysmon service running | Confirmed |
| Sysmon version | 15.21 |
| Sysmon EID 1 available | Confirmed |
| Sysmon EID 8 observed | No |
| Sysmon EID 10 observed | No |
| Controlled Notepad process created | Confirmed |
| Notepad PID | `22348` |
| PowerShell source PID | `21196` |
| Remote thread creation confirmed | No |
| Process access confirmed through EID 10 | No |
| WMI PowerShell activity observed | Confirmed, but separate |
| Malicious process injection established | No |

## Important Limitation

The investigation could confirm process creation telemetry but could not establish remote thread creation from Sysmon Event ID 8 or process access from Event ID 10.

Therefore, the lab does not claim that remote thread creation occurred or did not occur.

The appropriate conclusion is:

> **Remote thread creation was not established from the available telemetry. Sysmon Event ID 1 was available, while Event IDs 8 and 10 were not observed.**

## Final Assessment

The investigation demonstrated the importance of validating telemetry before interpreting process-injection activity. Sysmon was running and successfully recorded process creation, including the controlled creation of `notepad.exe` by PowerShell 7.

However, Sysmon Event ID 8 and Event ID 10 were not observed. As a result, the available evidence does not independently confirm CreateRemoteThread or process-access activity.

The existing WMI-triggered PowerShell events were kept separate because temporal or environmental proximity was insufficient to associate them with the Lab 99 investigation.

The main investigative conclusion is:

> **Process creation was confirmed, but remote thread creation and process injection were not established from the available endpoint telemetry.**
