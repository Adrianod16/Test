index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
    Image="*\\ollama.exe"
    OR Image="*\\lmstudio.exe"
    OR Image="*\\jan.exe"
    OR Image="*\\anythingllm*.exe"
    OR Image="*\\node.exe"
    OR CommandLine="*ollama run*"
    OR CommandLine="*ollama serve*"
    OR CommandLine="*llama.cpp*"
    OR CommandLine="*.gguf*"
    OR CommandLine="*lmstudio*"
    OR CommandLine="*anythingllm*"
    OR CommandLine="*jan*"
    OR CommandLine="*claude*"
)
NOT (
    CommandLine="*visual studio*"
    OR CommandLine="*msbuild*"
    OR CommandLine="*azureml*"
)
| stats count by host User Image CommandLine ParentImage
