DeviceProcessEvents
| where TimeGenerated > ago(1h)
| where
(
    ProcessCommandLine has "ollama run"
    or ProcessCommandLine has "ollama serve"
    or ProcessCommandLine has_any ("llama.cpp", ".gguf", "lmstudio", "anythingllm", "jan.ai")
)
| where not(ProcessCommandLine has_any ("visual studio", "msbuild", "azureml"))
| extend RiskScore = case(
    ProcessCommandLine has "ollama run", 3,
    ProcessCommandLine has ".gguf", 2,
    ProcessCommandLine has "lmstudio", 2,
    1
)
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, RiskScore
