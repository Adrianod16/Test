let timeframe = 1h;
let SuspiciousExtensionKeywords = dynamic([
    "chatgpt",
    "copilot",
    "openai",
    "claude",
    "anthropic",
    "gemini",
    "continue",
    "codeium",
    "tabnine",
    "cody"
]);

DeviceFileEvents
| where Timestamp > ago(timeframe)
| where ActionType in~ ("FileCreated", "FileModified", "Rename")
| where
    FolderPath has @"\.vscode\extensions\"
    or FolderPath has @"\.vscode-insiders\extensions\"
    or FolderPath has @"\.cursor\extensions\"
    or FolderPath has @"\JetBrains\"
| extend LowerFolderPath = tolower(FolderPath)
| extend LowerFileName = tolower(FileName)
| where LowerFolderPath has_any (SuspiciousExtensionKeywords)
    or LowerFileName has_any (SuspiciousExtensionKeywords)
| project
    Timestamp,
    DeviceName,
    AccountName,
    ActionType,
    FileName,
    FolderPath,
    SHA1,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId




    index=* sourcetype=*sysmon* EventCode=11
| eval target_file=lower(coalesce(TargetFilename, target_filename, FileName, file_path))
| where like(target_file, "%\\.vscode\\extensions\\%")
    OR like(target_file, "%\\.vscode-insiders\\extensions\\%")
    OR like(target_file, "%\\.cursor\\extensions\\%")
    OR like(target_file, "%\\jetbrains\\%")
| where like(target_file, "%chatgpt%")
    OR like(target_file, "%copilot%")
    OR like(target_file, "%openai%")
    OR like(target_file, "%claude%")
    OR like(target_file, "%anthropic%")
    OR like(target_file, "%gemini%")
    OR like(target_file, "%continue%")
    OR like(target_file, "%codeium%")
    OR like(target_file, "%tabnine%")
    OR like(target_file, "%cody%")
| eval host_name=coalesce(host, Computer, ComputerName)
| eval username=coalesce(User, user)
| table _time host_name username Image TargetFilename ProcessGuid ProcessId
| rename _time as Time, host_name as DeviceName, username as AccountName, Image as InitiatingProcess, TargetFilename as FolderPath
