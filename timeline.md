# Investigation Timeline

| Time / Phase | Activity | Evidence / Result | Assessment |
|---|---|---|---|
| 06:06 | PowerShell 7 source process started | `pwsh.exe`, PID `21196` | Baseline |
| 06:06 | Investigation workspace initialized | `C:\RemoteThreadCreationLab\Evidence` | Confirmed |
| Initial setup | Investigation time recorded | `Investigation-Time.txt` | Confirmed |
| Initial setup | Host and user baseline captured | Host/user context preserved | Confirmed |
| Initial telemetry review | Sysmon service checked | `Sysmon64` Running, Automatic | Confirmed |
| Initial telemetry review | Sysmon version checked | Sysmon `15.21` | Confirmed |
| Initial telemetry review | EID 8 queried | No events found | Visibility limitation |
| Initial telemetry review | EID 10 queried | No events found | Visibility limitation |
| 06:13 | Controlled target process created | `notepad.exe`, PID `22348` | Confirmed |
| 06:13 | Target process baseline recorded | `C:\Windows\notepad.exe` | Confirmed |
| 06:13 | Sysmon EID 1 observed | Notepad creation recorded | Confirmed |
| Test preparation | Controlled test timestamp recorded | Local and UTC timestamps saved | Confirmed |
| Test investigation | EID 8 searched around test window | No matching event | Not established |
| Test investigation | EID 10 searched around test window | No matching event | Not established |
| Test investigation | EID 1 reviewed around test window | Process creation telemetry available | Confirmed |
| Investigation review | Existing WMI PowerShell activity observed | `WmiPrvSE.exe` → `powershell.exe` | Separate activity |
| Wazuh review | Endpoint-specific telemetry investigated | Agent `001`, host `DESKTOP-9MMM37V` | Correlation attempt |
| Evidence review | Source/target relationship assessed | Source `pwsh.exe`, target `notepad.exe` | Controlled context |
| Evidence review | Remote thread activity assessed | EID 8 not observed | Not confirmed |
| Evidence review | Process access assessed | EID 10 not observed | Not confirmed |
| Cleanup | Notepad target terminated | No remaining target process found | Confirmed |
| Final assessment | Evidence reviewed collectively | Process creation confirmed; remote thread not established | Final finding |

## Key Evidence Points

- Sysmon 15.21 was installed and running.
- The `Sysmon64` service was in the `Running` state.
- Sysmon Event ID 1 was available.
- Sysmon Event ID 8 was not observed.
- Sysmon Event ID 10 was not observed.
- PowerShell 7 (`pwsh.exe`) was used as the controlled source context.
- Source PID was `21196`.
- Notepad was used as the benign target.
- Target PID was `22348`.
- Sysmon Event ID 1 recorded the Notepad process creation.
- The Notepad process was created by the PowerShell 7 process.
- Existing WMI-triggered PowerShell activity was observed separately.
- The WMI activity was not attributed to the Lab 99 investigation.
- No direct Sysmon evidence of CreateRemoteThread was established.
- No direct Sysmon process-access evidence was established.
- The target process was stopped after evidence collection.

## Evidence Chain

```text
PowerShell 7
PID 21196
      |
      | Controlled investigation context
      v
notepad.exe
PID 22348
      |
      | Sysmon EID 1
      v
Process creation confirmed
      |
      +----------------------+
      |                      |
      v                      v
Sysmon EID 8             Sysmon EID 10
not observed             not observed
      |                      |
      +----------+-----------+
                 |
                 v
Remote thread creation
not independently established
```

## Separate Existing Activity

The investigation also encountered:

```text
WmiPrvSE.exe
      |
      v
powershell.exe
      |
      v
C:\WMIPermanentEventLab\Payload\wmi-payload.ps1
```

This activity was kept separate because the available evidence did not establish a relationship with the controlled Notepad investigation.

## Final Timeline Assessment

The investigation confirmed that Sysmon was operational and that process creation telemetry was available. A controlled Notepad target was created and successfully observed through Sysmon Event ID 1.

However, Event ID 8 and Event ID 10 were not observed. Consequently, the investigation could not independently establish CreateRemoteThread activity or process-access activity from the available Sysmon telemetry.

The strongest defensible conclusion is:

```text
Sysmon operational
        ↓
EID 1 available
        ↓
Controlled source identified
        ↓
Controlled target identified
        ↓
Target creation observed
        ↓
EID 8 not observed
        ↓
EID 10 not observed
        ↓
Remote thread creation not established
        ↓
Process injection not established
```

> **Final conclusion: the investigation confirmed process creation telemetry and a controlled source/target relationship, but the available evidence did not establish remote thread creation or malicious process injection.**
