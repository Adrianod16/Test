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
