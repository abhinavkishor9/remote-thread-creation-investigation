# remote-thread-creation-investigation
## Overview
Remote thread creation occurs when one process creates a thread inside another process.

A simplified process-injection sequence can look like:

Source Process
      |
      | Access Target Process
      v
Target Process
      |
      | Allocate / modify memory
      v
Remote Memory
      |
      | Create thread
      v
Remote Thread
      |
      v
Code execution inside Target Process

Attackers can abuse this technique for process injection, allowing code to execute inside a legitimate process.

However, remote-thread-related behavior is not automatically malicious. Legitimate software such as debuggers, profilers, accessibility applications, security products, and testing tools may interact with other processes.

Therefore, the investigation should focus on the complete evidence chain:

Source Process
      ↓
Target Process
      ↓
Process Access
      ↓
Remote Thread Activity
      ↓
Execution Context
      ↓
Follow-on Activity

Important telemetry distinction:
Windows/Sysmon can provide several useful events:

Event ID 1  → Process Creation
Event ID 8  → CreateRemoteThread
Event ID 10 → Process Access

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

## Lab Objectives

- Establish a documented baseline of the Windows endpoint, operating system, user context, and investigation environment.
- Create a dedicated evidence workspace for the remote thread creation investigation.
- Verify that Sysmon is installed, running, and writing telemetry to the expected operational event log.
- Establish a controlled source process using the current PowerShell session.
- Establish a controlled target process using `notepad.exe`.
- Record the source and target process identifiers, executable paths, and execution context before testing.
- Record an exact local and UTC timestamp for the controlled activity.
- Examine Sysmon Event ID 8 for CreateRemoteThread telemetry associated with the controlled test.
- Examine Sysmon Event ID 10 for Process Access telemetry that may provide supporting evidence around process interaction.
- Examine Sysmon Event ID 1 for process creation evidence related to the source and target processes.
- Compare Sysmon process telemetry with the controlled source and target process information.
- Determine whether the expected remote-thread telemetry is actually available on the endpoint.
- Distinguish between a confirmed remote-thread event and ordinary process creation activity.
- Document the absence of Sysmon Event ID 8 when no matching CreateRemoteThread event is generated.
- Document the absence of Sysmon Event ID 10 when no matching Process Access event is available.
- Avoid treating unrelated PowerShell or WMI process activity as evidence of remote thread creation without supporting correlation.
- Preserve the controlled test timestamps and process information as investigation evidence.
- Correlate source process, target process, timestamps, and Sysmon events only when the available telemetry supports the relationship.
- Identify Sysmon configuration or telemetry limitations that may affect detection of remote thread activity.
- Assess whether the available evidence supports confirmed remote thread creation, supporting process interaction, or insufficient telemetry.
- Apply an evidence-driven approach in which the absence of Event ID 8 is reported as a visibility finding rather than interpreted as proof that remote thread creation did not occur.

## Lab Scenario

A controlled Windows endpoint investigation is performed to examine how **remote thread creation** can be identified through endpoint telemetry. Remote thread creation is commonly associated with process injection, where one process creates a thread inside another process to execute code within the target process context. Because the technique can be abused by malware and other suspicious tooling, the investigation focuses on identifying reliable telemetry rather than assuming that process interaction automatically indicates injection.

The investigation begins by establishing a baseline of the Windows host and the current PowerShell session. A dedicated evidence directory is created, and the source PowerShell process and a controlled `notepad.exe` target process are documented with their process IDs, executable paths, start times, and user context. A controlled test timestamp is also recorded in both local and UTC time to provide a reference point for event correlation.

The primary telemetry source is **Microsoft Sysmon**. The investigation checks:
- **Event ID 1 — Process Create** to establish source and target process activity.
- **Event ID 8 — CreateRemoteThread** to identify direct remote thread creation.
- **Event ID 10 — Process Access** to identify supporting process-access activity that may be associated with injection techniques.

The investigation also checks **Wazuh** for endpoint ingestion of Sysmon telemetry. The objective is not simply to find an event, but to determine whether the available telemetry can establish a defensible relationship between the source process, target process, and suspected remote-thread activity.

During the investigation, Sysmon Event ID 1 successfully identifies the creation of the controlled `notepad.exe` process by the PowerShell session. However, no matching Event ID 8 or Event ID 10 events are observed, including during the focused time window around the controlled test. Additional PowerShell events generated by an existing WMI activity are observed near the investigation period, but they are treated as separate activity because there is no evidence linking them to the remote-thread test.

The final assessment therefore focuses on **telemetry validation and evidence limitations**. The available evidence confirms the source and target processes and their process relationship, but it does not establish that a remote thread was successfully created. The absence of Event ID 8 or Event ID 10 is documented as a visibility or detection finding rather than proof that remote thread creation did not occur.
  
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

