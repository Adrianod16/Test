This analytics rule detects the execution and usage of local Large Language Model (LLM) tools on endpoints, which may bypass enterprise security controls such as network monitoring, Data Loss Prevention (DLP), and Cloud Access Security Broker (CASB) solutions.

The rule correlates multiple telemetry sources from Microsoft Defender:

Process execution (DeviceProcessEvents)
Identifies known LLM tools and execution patterns such as:
ollama run, ollama serve
llama.cpp, .gguf
LM Studio, AnythingLLM, Jan AI
as well as associated binaries (e.g., ollama.exe, lmstudio.exe)
Model file artifacts (DeviceFileEvents)
Detects the presence of local model files and directories, including:
.gguf, .safetensors
Ollama model directories (.ollama, Ollama\models)
LM Studio and Jan-specific paths
Local inference behavior (DeviceNetworkEvents)
Identifies communication with localhost services commonly used by LLM inference engines, such as:
127.0.0.1 / ::1
Ports 11434, 1234, 5000, 8000

The rule applies a risk-based scoring model combining process, file, and network signals to determine the likelihood of actual LLM usage:

High confidence: multiple correlated indicators (e.g., execution + model file + local API)
Medium confidence: partial correlation (e.g., execution + model presence or API usage)

Only Medium and High confidence events are surfaced to reduce false positives.
