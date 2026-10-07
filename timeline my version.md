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

