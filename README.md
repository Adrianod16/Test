let timeframe = 1h;

let SuspiciousProc =
DeviceProcessEvents
| where TimeGenerated > ago(timeframe)
| where
(
    ProcessCommandLine has "ollama run"
    or ProcessCommandLine has "ollama serve"
    or ProcessCommandLine has_any ("llama.cpp", ".gguf", "lmstudio", "anythingllm", "jan.ai", "ollama")
    or FileName has_any ("ollama.exe", "lmstudio.exe", "jan.exe", "anythingllm.exe")
)
| where not(ProcessCommandLine has_any ("visual studio", "msbuild", "azureml"))
| extend ProcRisk = case(
    ProcessCommandLine has "ollama run", 4,
    ProcessCommandLine has "ollama serve", 3,
    ProcessCommandLine has ".gguf", 3,
    ProcessCommandLine has "llama.cpp", 3,
    ProcessCommandLine has "lmstudio", 2,
    ProcessCommandLine has "anythingllm", 2,
    ProcessCommandLine has "jan.ai", 2,
    FileName in~ ("ollama.exe", "lmstudio.exe", "jan.exe", "anythingllm.exe"), 2,
    1
)
| project
    DeviceId,
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcRisk;

let ModelFiles =
DeviceFileEvents
| where TimeGenerated > ago(timeframe)
| where
    FileName endswith ".gguf"
    or FileName endswith ".safetensors"
    or FileName endswith ".bin"
    or FolderPath has_any ("\\.ollama\\", "\\Ollama\\models\\", "\\LM Studio\\", "\\Jan\\")
| extend FileRisk = case(
    FileName endswith ".gguf", 3,
    FileName endswith ".safetensors", 3,
    FolderPath has "\\.ollama\\", 3,
    FolderPath has "\\Ollama\\models\\", 3,
    FolderPath has "\\LM Studio\\", 2,
    FolderPath has "\\Jan\\", 2,
    1
)
| project
    DeviceId,
    FileTime = TimeGenerated,
    ModelFileName = FileName,
    ModelFolderPath = FolderPath,
    FileRisk;

let LocalApi =
DeviceNetworkEvents
| where TimeGenerated > ago(timeframe)
| where RemoteIP in ("127.0.0.1", "::1")
| where RemotePort in (11434, 1234, 5000, 8000)
| extend NetRisk = case(
    RemotePort == 11434, 4,
    RemotePort == 1234, 3,
    RemotePort in (5000, 8000), 2,
    1
)
| project
    DeviceId,
    NetTime = TimeGenerated,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    NetRisk;

SuspiciousProc
| join kind=leftouter ModelFiles on DeviceId
| join kind=leftouter LocalApi on DeviceId
| extend TotalRisk = ProcRisk + coalesce(FileRisk, 0) + coalesce(NetRisk, 0)
| extend Confidence = case(
    TotalRisk >= 8, "High",
    TotalRisk >= 5, "Medium",
    "Low"
)
| where Confidence in ("Medium", "High")
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ModelFileName,
    ModelFolderPath,
    RemoteIP,
    RemotePort,
    ProcRisk,
    FileRisk,
    NetRisk,
    TotalRisk,
    Confidence
| order by TotalRisk desc, TimeGenerated desc
