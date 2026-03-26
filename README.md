DeviceProcessEvents
| where Timestamp > ago(1h)
| where 
    (
        ProcessCommandLine matches regex @"(ollama\s+(run|serve))"
        or ProcessCommandLine matches regex @"(llama\.cpp|gguf)"
        or ProcessCommandLine has_any ("lmstudio", "anythingllm", "jan.ai")
    )
| where not(ProcessCommandLine has_any ("visual studio", "msbuild", "azureml"))
| extend RiskScore = case(
    ProcessCommandLine has "ollama run", 3,
    ProcessCommandLine has "gguf", 2,
    1
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, RiskScore
