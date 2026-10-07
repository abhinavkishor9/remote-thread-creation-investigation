# Troubleshooting Notes

## Sysmon Event ID 8 Returned No Events

### Symptom

The following query was executed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 8
} -MaxEvents 10
```

The result was:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

Event ID 8 corresponds to CreateRemoteThread telemetry.

The absence of events does not prove that no remote thread activity occurred.

It means that no matching Event ID 8 was available in the reviewed Sysmon data.

### Correct Investigation Approach

The Sysmon configuration must be checked before concluding that EID 8 is unavailable.

The configuration can be reviewed with:

```powershell
sysmon64.exe -c
```

The result should be retained as part of the investigation evidence.

---

## Sysmon Event ID 10 Returned No Events

### Symptom

The following query was executed:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Sysmon/Operational"
    Id = 10
} -MaxEvents 10
```

The result was:

```text
Get-WinEvent: No events were found that match the specified selection criteria.
```

### Interpretation

Event ID 10 corresponds to Process Access.

No matching event was observed on the endpoint during the reviewed period.

This should not be interpreted as proof that the target process was never accessed.

The appropriate finding is:

```text
No Sysmon Event ID 10 was observed.
```

---

## Sysmon Event ID 1 Was Available

### Observation

Event ID 1 returned multiple process creation events.

For example, the controlled Notepad process generated:

```text
Image:
C:\Windows\notepad.exe

ProcessId:
22348

ParentImage:
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe

ParentProcessId:
21196
```

### Interpretation

This confirms that Sysmon was actively recording process creation events.

Therefore, the absence of EID 8 and EID 10 should not be described as:

```text
Sysmon is not working.
```

The correct statement is:

```text
Sysmon is operational and recording EID 1, while EID 8 and EID 10
were not observed in the reviewed telemetry.
```

---

## Sysmon Service Was Running

The service check returned:

```text
Name     Status   StartType
----     ------   ---------
Sysmon64 Running  Automatic
```

This confirmed:

- Sysmon was installed.
- The Sysmon service was running.
- The service was configured to start automatically.

The Sysmon version reported was:

```text
System Monitor v15.21
```

---

## Existing WMI PowerShell Activity Appeared During Investigation

### Observation

Several Event ID 1 records showed:

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File
"C:\WMIPermanentEventLab\Payload\wmi-payload.ps1"

ParentImage:
C:\Windows\System32\wbem\WmiPrvSE.exe

User:
NT AUTHORITY\SYSTEM
```

### Problem

These events occurred around the broader investigation period and could easily be mistaken for Lab 99 activity.

### Resolution

They were classified as existing WMI Permanent Event lab activity.

They were not used as evidence of remote thread creation because:

- The parent was `WmiPrvSE.exe`.
- The command line referenced `WMIPermanentEventLab`.
- The user was `NT AUTHORITY\SYSTEM`.
- No direct process-access or remote-thread relationship to the Notepad target was established.

### Lesson

> Temporal proximity does not establish an attack relationship.

---

## PowerShell Source Process Was Actually `pwsh.exe`

The investigation documentation initially described the source generically as PowerShell.

The actual source process was:

```text
ProcessName:
pwsh

Path:
C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.6.0_x64__8wekyb3d8bbwe\pwsh.exe

PID:
21196
```

The investigation evidence was therefore updated to distinguish:

```text
PowerShell 7:
pwsh.exe
```

from:

```text
Windows PowerShell:
powershell.exe
```

This distinction is important when correlating Sysmon process telemetry.

---

## Notepad Process Was Successfully Observed

The controlled target was created successfully:

```text
Process:
notepad.exe

PID:
22348

Path:
C:\Windows\notepad.exe

StartTime:
07-10-2026 06:13:08
```

Sysmon Event ID 1 recorded the process.

This confirmed that the target was visible to endpoint telemetry.

---

## No EID 8/10 Evidence After the Controlled Test

The targeted searches used the controlled test timestamp:

```powershell
$TestTime = Get-Date
```

The searches were restricted to the surrounding investigation period.

Neither Event ID 8 nor Event ID 10 was returned.

The evidence was therefore recorded as:

```text
EID 8: No matching event observed
EID 10: No matching event observed
```

The investigation did not convert these results into a negative claim about whether remote-thread activity actually occurred.

---

## Target Process Was Properly Stopped

After evidence collection:

```powershell
if (Get-Process -Id $TargetPid -ErrorAction SilentlyContinue) {
    Stop-Process -Id $TargetPid
}
```

A follow-up process lookup produced no output.

This confirmed that the controlled Notepad process was terminated after the investigation.

---

## Important Telemetry Limitation

The main limitation of this investigation is the lack of observed Sysmon Event ID 8 and Event ID 10 telemetry.

This limits the ability to directly establish:

```text
CreateRemoteThread
```

or:

```text
Process Access
```

from Sysmon.

The limitation should be documented explicitly rather than replaced with assumptions.

---

## Key Troubleshooting Lessons

- Verify Sysmon is running before investigating its telemetry.
- Verify the Sysmon configuration before assuming an event type is available.
- Event ID 1 confirms process creation telemetry but does not prove process injection.
- Event ID 8 is the relevant Sysmon event for CreateRemoteThread.
- Event ID 10 provides process-access telemetry.
- Missing EID 8 does not prove that no remote thread was created.
- Missing EID 10 does not prove that no process access occurred.
- Use source and target PIDs for stronger correlation.
- Use timestamps to narrow the investigation window.
- Do not treat every PowerShell event as part of the current investigation.
- Keep the existing WMI Permanent Event activity separate from Lab 99.
- Distinguish `pwsh.exe` from `powershell.exe`.
- Use a benign user-mode process as the controlled target.
- Do not target LSASS, Winlogon, security products, or other sensitive processes.
- Stop the controlled target process after evidence collection.
- Document telemetry limitations explicitly.
- Do not claim process injection without evidence supporting the complete relationship.

## Final Troubleshooting Principle

> **A missing injection event is a visibility finding, not proof that the injection technique did or did not occur.**
