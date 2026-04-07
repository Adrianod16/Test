index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(
    Image="*\\ollama.exe"
    OR Image="*\\lmstudio.exe"
    OR Image="*\\jan.exe"
    OR Image="*\\anythingllm*.exe"
    OR Image="*\\claude*.exe"

    OR CommandLine="*ollama run*"
    OR CommandLine="*ollama serve*"
    OR CommandLine="*llama.cpp*"
    OR CommandLine="*.gguf*"
    OR CommandLine="*anythingllm*"
    OR CommandLine="*lmstudio*"

    OR CommandLine="*@anthropic-ai/claude-code*"
    OR CommandLine="*claude-code*"
    OR CommandLine="*HKLM\\SOFTWARE\\Policies\\ClaudeCode*"

    OR CommandLine="*\\jan\\*"
    OR CommandLine="*\\Jan\\*"
)
NOT (
    CommandLine="*visual studio*"
    OR CommandLine="*msbuild*"
    OR CommandLine="*azureml*"
)
| eval ai_tool=case(
    like(lower(Image),"%\\ollama.exe"),"Ollama",
    like(lower(Image),"%\\lmstudio.exe"),"LM Studio",
    like(lower(Image),"%\\jan.exe"),"Jan AI",
    like(lower(Image),"%\\anythingllm"),"AnythingLLM",
    like(lower(Image),"%\\claude"),"Claude Code",
    like(lower(CommandLine),"%ollama run%"),"Ollama",
    like(lower(CommandLine),"%ollama serve%"),"Ollama",
    like(lower(CommandLine),"%llama.cpp%"),"llama.cpp",
    like(lower(CommandLine),"%.gguf%"),"Local Model",
    like(lower(CommandLine),"%anythingllm%"),"AnythingLLM",
    like(lower(CommandLine),"%lmstudio%"),"LM Studio",
    like(lower(CommandLine),"%@anthropic-ai/claude-code%"),"Claude Code",
    like(lower(CommandLine),"%claude-code%"),"Claude Code",
    like(lower(CommandLine),"%hklm\\software\\policies\\claudecode%"),"Claude Code",
    like(lower(CommandLine),"%\\jan\\%"),"Jan AI",
    1=1,"Unknown"
)
| stats count by host User Image CommandLine ParentImage ai_tool
| sort - count
