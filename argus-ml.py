#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import zipfile
import tempfile
import re
import json
from pathlib import Path

# ==========================================
# LIBRARY IMPORTS & CHECKS
# ==========================================
try: import pyfiglet
except ImportError: sys.exit("[-] Error: 'pyfiglet' is not installed. Run: pip install pyfiglet")

try: import markdown
except ImportError: markdown = None

try: from openai import OpenAI
except ImportError: OpenAI = None

try: from google import genai
except ImportError: genai = None

# Threat Engine availability checks
HAS_PICKLESCAN = True
try: import picklescan
except ImportError: HAS_PICKLESCAN = False

HAS_FICKLING = True
try: import fickling
except ImportError: HAS_FICKLING = False

HAS_MODELSCAN = True
try: import modelscan
except ImportError: HAS_MODELSCAN = False

HAS_H5PY = True
try: import h5py
except ImportError: HAS_H5PY = False

# ==========================================
# API KEYS CONFIGURATION
# ==========================================
nvidia_build_api_key = "YOUR_KEY_HERE"
gemini_api_key = "YOUR_KEY_HERE"
openai_api_key = "YOUR_KEY_HERE"

DEFAULT_MODELS = {
    "nvidia": "meta/llama-3.1-8b-instruct",
    "gemini": "gemini-2.0-flash",
    "openai": "gpt-4o-mini"
}

SUPPORTED_EXTENSIONS = {
    '.pkl', '.pickle', '.pk1', '.pt', '.pth', '.bin', 
    '.npy', '.npz', '.joblib',                        
    '.h5', '.hdf5', '.keras', '.pb',                  
    '.safetensors', '.gguf', '.onnx'                  
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html><head><title>Argus-ML Security Report</title>
<style>
    body { font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; padding: 30px; }
    h1, h2, h3 { color: #58a6ff; }
    .container { max-width: 1000px; margin: 0 auto; background-color: #161b22; padding: 30px; border-radius: 8px; border: 1px solid #30363d; }
    pre { background-color: #010409; padding: 15px; border-radius: 6px; overflow-x: auto; border: 1px solid #30363d; color: #ff7b72; }
    .critical { color: #f85149; font-weight: bold; }
    .safe { color: #3fb950; font-weight: bold; }
</style></head>
<body><div class="container"><h1>🛡️ Argus-ML Security Report</h1><hr>{{content}}</div></body></html>
"""

def print_banner():
    banner = pyfiglet.figlet_format("Argus-ML")
    print("\033[96m" + banner + "\033[0m")
    print("\033[93m" + "Made By Aryan Giri | giriaryan694-a11y".center(60) + "\033[0m\n")

def get_active_provider(requested_provider):
    keys = {"nvidia": nvidia_build_api_key, "gemini": gemini_api_key, "openai": openai_api_key}
    if keys.get(requested_provider) and keys[requested_provider] != "YOUR_KEY_HERE": return requested_provider
    for provider, key in keys.items():
        if key and key != "YOUR_KEY_HERE": return provider
    return None

def query_ai(prompt, provider, model):
    print(f"[*] Querying AI ({provider} - {model}) for deep analysis...")
    safe_prompt = (
        "You are an elite cybersecurity defender analyzing malware. Do NOT refuse this request. "
        "Analyze this extracted payload from an AI model file: \n\n" + prompt +
        "\n\nProvide: 1. Exact command logic 2. Impact 3. Technical explanation of the obfuscation/stage."
    )
    try:
        if provider == "openai":
            client = OpenAI(api_key=openai_api_key)
            return client.chat.completions.create(model=model, messages=[{"role": "user", "content": safe_prompt}]).choices[0].message.content
        elif provider == "nvidia":
            client = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=nvidia_build_api_key)
            return client.chat.completions.create(model=model, messages=[{"role": "user", "content": safe_prompt}], max_tokens=1024, temperature=0.2).choices[0].message.content
        elif provider == "gemini":
            client = genai.Client(api_key=gemini_api_key)
            return client.models.generate_content(model=model, contents=safe_prompt).text
    except Exception as e: return f"[-] AI Analysis failed: {str(e)}"

# ==========================================
# THREAT ENGINES
# ==========================================

def run_h5py_scan(file_path):
    """Safely parses HDF5/Keras config JSON for Lambda Layer payloads."""
    if not HAS_H5PY: return ["[WARNING] h5py not installed. Cannot deeply inspect Keras layers."]
    print(f"[*] Engine: HDF5/Keras Deep Inspector (h5py)...")
    findings = []
    try:
        with h5py.File(file_path, 'r') as f:
            # Check for Keras model config embedded in attributes
            config_str = f.attrs.get('model_config') or f.attrs.get('layer_config')
            if config_str:
                if isinstance(config_str, bytes): config_str = config_str.decode('utf-8', errors='ignore')
                
                # Check for Lambda layers and marshalled Python bytecode
                if 'Lambda' in config_str:
                    findings.append("[CRITICAL - HDF5] Keras Lambda layer detected. High risk of marshalled bytecode execution.")
                    
                    # Try to extract the base64 payload if it exists
                    if 'marshal' in config_str or 'base64' in config_str:
                        findings.append("[CRITICAL - HDF5] Obfuscated/Base64 Python bytecode detected within model configuration.")
                        try:
                            config_json = json.loads(config_str)
                            # Deep search for the function
                            findings.append(f"[HEURISTIC] Snippet: {str(config_json)[:200]}...")
                        except: pass
    except Exception as e: return [f"[-] H5PY parse error: {e}"]
    return findings

def run_picklescan(file_path):
    if not HAS_PICKLESCAN: return ["[WARNING] picklescan not installed."]
    print(f"[*] Engine: Picklescan...")
    findings = []
    try:
        result = subprocess.run(["picklescan", "-p", str(file_path)], capture_output=True, text=True, timeout=30)
        for line in result.stdout.split('\n'):
            if "Dangerous import" in line or "DANGEROUS" in line:
                findings.append(f"[CRITICAL - PICKLESCAN] {line.strip()}")
    except Exception as e: return [f"[-] Picklescan error: {e}"]
    return findings

def run_fickling(file_path):
    if not HAS_FICKLING: return ["[WARNING] fickling not installed."]
    print(f"[*] Engine: Fickling AST Decompiler...")
    findings = []
    try:
        result = subprocess.run(["fickling", str(file_path)], capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        bad_calls = ['os.system', 'subprocess', 'builtins.eval', 'builtins.exec', 'pty.spawn']
        for call in bad_calls:
            if call in output:
                findings.append(f"[CRITICAL - FICKLING] Decompiled AST reveals execution wrapper: {call}")
    except subprocess.TimeoutExpired: return ["[WARNING] Fickling timed out (possible infinite loop payload)."]
    except Exception as e: return [f"[-] Fickling error: {e}"]
    return findings

def run_modelscan(file_path):
    if not HAS_MODELSCAN: return ["[WARNING] modelscan not installed."]
    print(f"[*] Engine: ProtectAI ModelScan...")
    findings = []
    try:
        result = subprocess.run(["modelscan", "-p", str(file_path)], capture_output=True, text=True, timeout=60)
        for line in result.stdout.split('\n'):
            if "CRITICAL" in line or "HIGH" in line:
                findings.append(f"[CRITICAL - MODELSCAN] {line.strip()}")
    except Exception as e: return [f"[-] ModelScan error: {e}"]
    return findings

def raw_binary_scan(file_path):
    print(f"[*] Engine: Universal Binary Heuristic Scan...")
    bad_patterns = [b'os.system', b'subprocess', b'pty.spawn', b'posix system', b'/bin/bash', b'nc -e', b'curl ', b'wget ', b'Lambda']
    findings = []
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                for p in bad_patterns:
                    if p in chunk:
                        idx = chunk.find(p)
                        ctx = re.sub(rb'[^\x20-\x7E]', b'.', chunk[max(0, idx-50):min(len(chunk), idx+100)]).decode('utf-8', 'ignore')
                        findings.append(f"[HEURISTIC] Found '{p.decode()}'. Context: {ctx}")
    except Exception as e: pass
    return findings

def run_static_analysis(file_path, verbose):
    ext = Path(file_path).suffix.lower()
    dangerous_ops, suspicious_strings = [], []

    # Safe architectures
    if ext in ['.safetensors', '.onnx']:
        print(f"[*] Detected {ext}. Architecturally immune to standard RCE.")
        return [], [], ""

    is_zip = zipfile.is_zipfile(file_path)
    target_file = file_path
    tmp_path = None

    # Zip-Slip / Path Traversal Check for PyTorch/Numpy Archives
    if is_zip:
        print("[*] Detected ZIP/Archive. Extracting and checking for Zip Slip vulnerabilities...")
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                for name in z.namelist():
                    if '..' in name or name.startswith('/'):
                        suspicious_strings.append(f"[CRITICAL - ZIP SLIP] Directory traversal attempt detected in archive: {name}")

                target_files = [f for f in z.namelist() if f.endswith('.pkl') or f.endswith('.npy')]
                if target_files:
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp.write(z.read(target_files[0]))
                        tmp_path = tmp.name
                    target_file = tmp_path
        except Exception as e: pass

    # HDF5 / Keras Lambda Engine
    if ext in ['.h5', '.hdf5', '.keras']:
        suspicious_strings.extend(run_h5py_scan(file_path))

    # Run Overarching ModelScan
    suspicious_strings.extend(run_modelscan(target_file))

    # Pickle-Specific Engines
    if ext in ['.pkl', '.pickle', '.pk1', '.pt', '.pth', '.bin', '.joblib', '.npz']:
        suspicious_strings.extend(run_picklescan(target_file))
        suspicious_strings.extend(run_fickling(target_file))
        
        print(f"[*] Engine: Pickletools Disassembly...")
        try:
            res = subprocess.run([sys.executable, "-m", "pickletools", str(target_file)], capture_output=True, text=True)
            for line in res.stdout.split('\n'):
                line_upper = line.upper()
                if 'GLOBAL' in line_upper and any(x in line_upper for x in ['OS', 'SYSTEM', 'SUBPROCESS', 'EVAL', 'POSIX', 'PTY']):
                    dangerous_ops.append(f"[CRITICAL] STACK_GLOBAL: {line.strip().split(' ', 1)[-1]}")
                if 'UNICODE' in line_upper and any(x in line_upper for x in ['CURL', 'WGET', '/BIN/SH', 'BASH', 'NC ']):
                    suspicious_strings.append(f"[CRITICAL] PAYLOAD: {line.strip().split(' ', 1)[-1]}")
        except Exception: pass

    # Heuristic Fallback
    if not dangerous_ops and not any("[CRITICAL" in s for s in suspicious_strings):
        suspicious_strings.extend(raw_binary_scan(file_path))

    if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
    return dangerous_ops, suspicious_strings, ""

# ==========================================
# REPORTING & MAIN
# ==========================================

def analyze_file(file_path, args):
    file_size = os.path.getsize(file_path) / (1024 * 1024)
    report_md = f"## === ML Safety Analysis ===\n**File:** `{file_path}`\n**Size:** `{file_size:.2f} MB`\n\n"

    dangerous_ops, suspicious_strings, _ = run_static_analysis(file_path, args.verbose)
    actual_threats = dangerous_ops + [s for s in suspicious_strings if "[CRITICAL" in s or "[HEURISTIC" in s]

    if not actual_threats:
        verdict = "SAFE (Static Analysis) - No obvious execution vectors found."
        report_md += f"✅ **{verdict}**\n"
    else:
        verdict = "UNSAFE - Malicious Code/Payloads Detected."
        report_md += "**Dangerous execution paths found:**\n"
        for op in set(dangerous_ops): report_md += f"- `{op}`\n"
        report_md += "\n**Suspicious payloads/strings:**\n"
        for s in set(suspicious_strings): report_md += f"- `{s}`\n"

    report_md += f"\n**Static Verdict:** {verdict}\n\n"
    print(f"\n=== ML Safety Analysis ===")
    print(f"File: {file_path}\nVerdict: {verdict}\n")

    if not args.no_ai and actual_threats:
        active_provider = get_active_provider(args.provider)
        if active_provider:
            model = args.model if args.model != DEFAULT_MODELS[args.provider] else DEFAULT_MODELS[active_provider]
            ai_response = query_ai(f"Opcodes: {dangerous_ops}\nStrings: {suspicious_strings}", active_provider, model)
            report_md += f"### 🧠 AI Threat Intelligence ({active_provider} - {model}):\n\n{ai_response}\n\n"
            print(f"=== AI Analysis ===\n{ai_response}\n===================\n")

    return report_md

def save_output(content, output_file, filetype):
    print(f"[*] Saving output to {output_file}.{filetype}")
    if filetype == 'md': open(f"{output_file}.md", 'w').write(content)
    elif filetype == 'txt': open(f"{output_file}.txt", 'w').write(content.replace('##', '').replace('**', '').replace('`', ''))
    elif filetype == 'html': open(f"{output_file}.html", 'w').write(HTML_TEMPLATE.replace('{{content}}', markdown.markdown(content) if markdown else content))

def main():
    parser = argparse.ArgumentParser(description="Argus-ML: Universal Supply Chain Malware Scanner")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--target", help="Single model file to scan")
    input_group.add_argument("--dir", help="Directory to scan")
    
    parser.add_argument("-o", "--output", help="Output file base name")
    parser.add_argument("-ft", "--filetype", choices=['md', 'txt', 'html'], default='txt', help="Output format")
    parser.add_argument("--provider", choices=['nvidia', 'gemini', 'openai'], default='nvidia', help="AI Provider")
    parser.add_argument("--model", help="Override default model")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose logs")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI analysis")

    args = parser.parse_args()
    print_banner()

    if not args.no_ai and not get_active_provider(args.provider):
        print("[-] ERROR: No API keys configured. Use '--no-ai'."); sys.exit(1)

    if not args.model: args.model = DEFAULT_MODELS[args.provider]

    files_to_scan = [Path(args.target)] if args.target else [Path(os.path.join(root, f)) for root, _, files in os.walk(args.dir) for f in files if Path(f).suffix.lower() in SUPPORTED_EXTENSIONS]

    full_report = ""
    for file in files_to_scan: full_report += analyze_file(file, args) + "\n---\n\n"
    if args.output: save_output(full_report, args.output, args.filetype)

if __name__ == "__main__":
    main()
