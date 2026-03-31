let timeframe = 1h;

let IDEFiles =
DeviceFileEvents
| where Timestamp > ago(timeframe)
| where ActionType in~ ("FileCreated", "FileModified", "Rename")
| where FolderPath has_any (
    @"\.vscode\extensions\",
    @"\.vscode-insiders\extensions\",
    @"\.cursor\extensions\",
    @"\JetBrains\"
)
| project FileTimestamp=Timestamp, DeviceName, AccountName, FileName, FolderPath, ActionType, SHA1, InitiatingProcessId, ReportId;

let IDEProcs =
DeviceProcessEvents
| where Timestamp > ago(timeframe)
| project ProcTimestamp=Timestamp, DeviceName, InitiatingProcessId=ProcessId, ProcessFileName=FileName, ProcessCommandLine;

IDEFiles
| join kind=leftouter IDEProcs on DeviceName, InitiatingProcessId
| project
    FileTimestamp,
    DeviceName,
    AccountName,
    ActionType,
    FileName,
    FolderPath,
    SHA1,
    ProcessFileName,
    ProcessCommandLine,
    ReportId
