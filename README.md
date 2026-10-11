# Windows Event Log Investigation

## Objective
Investigate synthetic Windows Security events, count successful and failed logons, and identify source IPs that deserve further review.

## Files
- `data/windows_security_events.csv` — synthetic practice data
- `analyze_windows_events.py` — Python analysis script

## Run
From this folder:
```bash
python3 analyze_windows_events.py
```

## Event IDs in this lab
- `4624`: successful logon
- `4625`: failed logon
- `4634`: logoff
- `4672`: special privileges assigned to a new logon
- `4688`: process creation (if process creation auditing is enabled)
- `4720`: user account created
- `4740`: account locked out

## Investigation hypothesis
The sample has repeated failures from `203.0.113.45`, followed by a successful logon for `administrator` and a privileged-logon event. This is a correlation worth investigating, but synthetic data alone does not prove compromise.

## Questions to answer
1. Which source IP generated the most failed logons?
2. Did a successful logon occur after the repeated failures?
3. Which related events should be checked next?
4. What additional evidence is needed before escalating?

## Exporting real events (optional, on a Windows lab you own)
Run PowerShell as Administrator:
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4634,4672,4688,4720,4740} -MaxEvents 200 |
  Select-Object TimeCreated, Id, ProviderName, MachineName, Message |
  Export-Csv "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation
```
The CSV produced by this command has a different schema from the synthetic CSV, so adapt the parser before using it. Access to the Security log may require elevated privileges and audit policies affect which events exist.

## Limitations
- Data is synthetic and not a raw EVTX export.
- Source IPs are documentation-only reserved example addresses.
- Counts do not establish malicious intent.
