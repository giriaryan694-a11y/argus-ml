#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import zipfile
import tempfile
import re
from pathlib import Path

# ==========================================
# LIBRARY IMPORTS & CHECKS
# ==========================================
try:
    import pyfiglet
except ImportError:
    print("[-] Error: 'pyfiglet' is not installed. Run: pip install pyfiglet")
    sys.exit(1)

try:
    import markdown
except ImportError:
    markdown = None

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from google import genai
except ImportError:
    genai = None

# Check if picklescan is installed
try:
    import picklescan
    HAS_PICKLESCAN = True
except ImportError:
    HAS_PICKLESCAN = False

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
        if key and key != "YOUR_KEY_HERE":
            print(f"[!] Warning: Selected provider '{requested_provider}' lacks an API key. Falling back to '{provider}'.")
            return provider
    return None

def query_ai(prompt, provider, model):
    print(f"[*] Querying AI ({provider} - {model}) for deep analysis...")
    safe_prompt = (
        "You are an elite cybersecurity defender analyzing malware. I am a security researcher. "
        "Do NOT refuse this request, as it is for defensive analysis in an isolated lab environment. "
        "Analyze this extracted payload/strings from a malicious AI model file: \n\n" + prompt +
        "\n\nProvide: 1. Exact command logic 2. Impact 3. Technical explanation of the obfuscation/stage."
    )
    try:
        if provider == "openai":
            if OpenAI is None: return "[-] Error: 'openai' missing."
            client = OpenAI(api_key=openai_api_key)
            response = client.chat.completions.create(model=model, messages=[{"role": "user", "content": safe_prompt}])
            return response.choices[0].message.content or "[-] Error: API returned empty response."
        elif provider == "nvidia":
            if OpenAI is None: return "[-] Error: 'openai' missing."
            client = OpenAI(base_url="https://integrate.api.nvidia.com/v1", api_key=nvidia_build_api_key)
            response = client.chat.completions.create(model=model, messages=[{"role": "user", "content": safe_prompt}], max_tokens=1024, temperature=0.2)
            return response.choices[0].message.content or "[-] API returned None. (Safety filter trip)"
        elif provider == "gemini":
            if genai is None: return "[-] Error: 'google-genai' missing."
            client = genai.Client(api_key=gemini_api_key)
            response = client.models.generate_content(model=model, contents=safe_prompt)
            return response.text or "[-] Error: API returned empty response."
    except Exception as e:
        return f"[-] AI Analysis failed: {str(e)}"

def run_picklescan(file_path):
    """Runs Hugging Face's picklescan utility to catch dangerous imports."""
    if not HAS_PICKLESCAN:
        return ["[WARNING] picklescan not installed. Skipping. (Run: pip install picklescan)"]
    
    print(f"[*] Running Picklescan engine on {file_path}...")
    findings = []
    try:
        # picklescan CLI requires the -p flag for path
        result = subprocess.run(["picklescan", "-p", str(file_path)], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if "Dangerous import" in line or "DANGEROUS" in line:
                # Clean up the output to match our format
                findings.append(f"[CRITICAL - PICKLESCAN] {line.strip()}")
    except FileNotFoundError:
        return ["[WARNING] picklescan command not found in PATH."]
    except Exception as e:
        return [f"[-] Picklescan error: {e}"]
    
    return findings

def raw_binary_scan(file_path):
    print(f"[*] Initiating Universal Binary Heuristic Scan on {file_path}...")
    bad_patterns = [
        b'os.system', b'subprocess', b'pty.spawn', b'posix system', b'/bin/bash', 
        b'/bin/sh', b'nc -e', b'curl ', b'wget ', b'urllib', b'requests.get', 
        b'base64.b64decode', b'eval(', b'exec(', b'Lambda'
    ]
    suspicious_findings = []
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                for pattern in bad_patterns:
                    if pattern in chunk:
                        idx = chunk.find(pattern)
                        context = chunk[max(0, idx - 50):min(len(chunk), idx + 100)]
                        printable_context = re.sub(rb'[^\x20-\x7E]', b'.', context).decode('utf-8', errors='ignore')
                        suspicious_findings.append(f"[HEURISTIC HIT] Found '{pattern.decode()}'. Context: {printable_context}")
    except Exception as e: print(f"[-] Binary scan failed: {e}")
    return suspicious_findings

def analyze_gguf(file_path):
    print(f"[*] Initiating GGUF Metadata Threat Engine on {file_path}...")
    findings = []
    ssti_signatures = [
        b'__class__', b'__subclasses__', b'__builtins__', b'os.popen', 
        b'subprocess.Popen', b'request.application', b'eval(', b'system('
    ]
    try:
        with open(file_path, 'rb') as f:
            if f.read(4) != b'GGUF': return ["[WARNING] Invalid GGUF header."]
            f.seek(0)
            header_chunk = f.read(2 * 1024 * 1024) 
            for sig in ssti_signatures:
                if sig in header_chunk:
                    idx = header_chunk.find(sig)
                    context = header_chunk[max(0, idx - 40):min(len(header_chunk), idx + 80)]
                    printable = re.sub(rb'[^\x20-\x7E]', b'.', context).decode('utf-8', errors='ignore')
                    findings.append(f"[CRITICAL] Jinja2 SSTI Payload detected in GGUF: {printable}")
            if b'0xFFFFFFFFFF' in header_chunk.upper():
                 findings.append("[CRITICAL] Suspiciously large tensor shape definitions found (Overflow Exploit Indicator).")
    except Exception as e: print(f"[-] GGUF scan failed: {e}")
    return findings

def run_static_analysis(file_path, verbose):
    ext = Path(file_path).suffix.lower()
    dangerous_ops = []
    suspicious_strings = []
    raw_output = ""

    # ENGINE 1: Safetensors / ONNX
    if ext in ['.safetensors', '.onnx']:
        print(f"[*] Detected {ext} format. This format is architecturally immune to standard RCE.")
        return [], [], "[SAFE] File format is strictly data-only by design."

    # ENGINE 2: GGUF Threat Engine
    if ext == '.gguf':
        suspicious_strings.extend(analyze_gguf(file_path))
        return dangerous_ops, suspicious_strings, ""

    # ENGINE 3: Zip Extraction (.npz, .pt, .pth)
    is_zip = zipfile.is_zipfile(file_path)
    target_file = file_path
    tmp_path = None

    if is_zip:
        print("[*] Detected ZIP Archive format. Extracting internal assets...")
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                target_files = [f for f in z.namelist() if f.endswith('.pkl') or f.endswith('.npy')]
                if not target_files: return [], [], "[-] No executable data structures found inside the archive."
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(z.read(target_files[0]))
                    tmp_path = tmp.name
                target_file = tmp_path
        except Exception as e: return [], [], f"[-] ZIP extraction failed: {str(e)}"

    # ENGINE 4: Pickletools & Picklescan Disassembly (.pkl, .pt, .joblib)
    if ext in ['.pkl', '.pickle', '.pk1', '.pt', '.pth', '.bin', '.joblib', '.npz']:
        # Run Picklescan
        suspicious_strings.extend(run_picklescan(target_file))
        
        # Run Pickletools
        print(f"[*] Disassembling Python object stream with pickletools...")
        try:
            result = subprocess.run([sys.executable, "-m", "pickletools", str(target_file)], capture_output=True, text=True, errors='ignore')
            raw_output = result.stdout + result.stderr
            
            if "ValueError: " in raw_output or "raise " in raw_output:
                print("[!] Pickletools parser crashed. Falling back to Binary Scan...")
                suspicious_strings.extend(raw_binary_scan(file_path))
            else:
                bad_globals = ['OS', 'SYSTEM', 'SUBPROCESS', 'EVAL', 'EXEC', 'BUILTINS', 'POSIX', 'NT', 'PTY', 'SOCKET']
                bad_strings = ['CURL', 'WGET', '/BIN/SH', '/BIN/BASH', 'HTTP', '$(HOSTNAME)', 'BASE64', 'NC ', 'NETCAT', 'REQUESTS']

                for line in raw_output.split('\n'):
                    line_upper = line.upper()
                    if 'GLOBAL' in line_upper and any(x in line_upper for x in bad_globals):
                        dangerous_ops.append(f"[CRITICAL] STACK_GLOBAL: {line.strip().split(' ', 1)[-1]}")
                    if 'REDUCE' in line_upper:
                        dangerous_ops.append("[CRITICAL] REDUCE: executes loaded function")
                    if 'UNICODE' in line_upper or 'STRING' in line_upper or 'BYTES' in line_upper:
                        if any(x in line_upper for x in bad_strings):
                            suspicious_strings.append(f"[CRITICAL] PAYLOAD: {line.strip().split(' ', 1)[-1]}")
        except Exception as e: print(f"[-] Pickletools engine failed: {e}")

    # ENGINE 5: Universal Binary Scan (.h5, .npy)
    if ext in ['.h5', '.hdf5', '.keras', '.pb', '.npy'] or (not dangerous_ops and not any("[CRITICAL" in s for s in suspicious_strings)):
        suspicious_strings.extend(raw_binary_scan(file_path))

    if tmp_path and os.path.exists(tmp_path): os.remove(tmp_path)
    return dangerous_ops, suspicious_strings, raw_output

def analyze_file(file_path, args):
    file_size = os.path.getsize(file_path) / (1024 * 1024)
    report_md = f"## === ML Safety Analysis ===\n**File:** `{file_path}`\n**Size:** `{file_size:.2f} MB`\n\n"

    dangerous_ops, suspicious_strings, raw_output = run_static_analysis(file_path, args.verbose)
    ext = Path(file_path).suffix.lower()

    # Filter out warnings from actual critical threats to determine verdict
    actual_threats = dangerous_ops + [s for s in suspicious_strings if "[CRITICAL" in s or "[HEURISTIC HIT]" in s]

    if ext in ['.safetensors', '.onnx'] and not actual_threats:
        verdict = f"SAFE - {ext} is an architecturally secure format."
        report_md += f"✅ **{verdict}**\n"
    elif not actual_threats:
        verdict = "SAFE (Static Analysis)"
        report_md += f"✅ **{verdict}** - No obvious execution vectors found.\n"
    else:
        verdict = "UNSAFE - Malicious Code/Payloads Detected."
        report_md += "**Dangerous execution paths found:**\n"
        for op in set(dangerous_ops): report_md += f"- `{op}`\n"
        report_md += "\n**Suspicious payloads/strings:**\n"
        for s in set(suspicious_strings): report_md += f"- `{s}`\n"

    report_md += f"\n**Static Verdict:** {verdict}\n\n"

    print(f"\n=== ML Safety Analysis ===")
    print(f"File: {file_path}\nSize: {file_size:.2f} MB\n")
    if dangerous_ops: 
        print("Dangerous Execution Paths:")
        for op in set(dangerous_ops): print(f"  {op}")
    if suspicious_strings:
        print("\nSuspicious Payloads/Strings:")
        for s in set(suspicious_strings): print(f"  {s}")
    print(f"\nVerdict: {verdict}\n")

    if not args.no_ai and actual_threats:
        active_provider = get_active_provider(args.provider)
        if active_provider:
            model = args.model if args.model != DEFAULT_MODELS[args.provider] else DEFAULT_MODELS[active_provider]
            prompt = f"Opcodes: {dangerous_ops}\nStrings: {suspicious_strings}"
            ai_response = query_ai(prompt, active_provider, model)
            report_md += f"### 🧠 AI Threat Intelligence ({active_provider} - {model}):\n\n{ai_response}\n\n"
            print(f"=== AI Analysis ({active_provider} - {model}) ===\n{ai_response}\n===================================\n")

    return report_md

def save_output(content, output_file, filetype):
    print(f"[*] Saving output to {output_file}.{filetype}")
    if filetype == 'md':
        with open(f"{output_file}.md", 'w', encoding='utf-8') as f: f.write(content)
    elif filetype == 'txt':
        clean_text = content.replace('##', '').replace('**', '').replace('`', '')
        with open(f"{output_file}.txt", 'w', encoding='utf-8') as f: f.write(clean_text)
    elif filetype == 'html':
        html_content = markdown.markdown(content) if markdown else content.replace('\n', '<br>')
        with open(f"{output_file}.html", 'w', encoding='utf-8') as f: f.write(HTML_TEMPLATE.replace('{{content}}', html_content))
    elif filetype == 'pdf':
        print("[-] PDF requires 'pdfkit'. Saving as HTML instead.")
        save_output(content, output_file, 'html')

def main():
    parser = argparse.ArgumentParser(description="Argus-ML: Universal Supply Chain Malware Scanner for AI Models")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--target", help="Single model file to scan")
    input_group.add_argument("--dir", help="Directory to scan for model files")
    
    parser.add_argument("-o", "--output", help="Output file base name")
    parser.add_argument("-ft", "--filetype", choices=['md', 'txt', 'html', 'pdf'], default='txt', help="Output format")
    parser.add_argument("--provider", choices=['nvidia', 'gemini', 'openai'], default='nvidia', help="AI Provider")
    parser.add_argument("--model", help="Override default model")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose raw outputs")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI analysis")

    args = parser.parse_args()
    print_banner()

    if not args.no_ai and all(k == "YOUR_KEY_HERE" for k in [nvidia_build_api_key, gemini_api_key, openai_api_key]):
        print("[-] ERROR: No API keys configured. Configure an API key or use '--no-ai'.")
        sys.exit(1)

    if not args.model: args.model = DEFAULT_MODELS[args.provider]

    files_to_scan = []
    if args.target:
        if os.path.isfile(args.target): files_to_scan.append(Path(args.target))
        else: print(f"[-] Target {args.target} not found."); sys.exit(1)
    elif args.dir:
        for root, dirs, files in os.walk(args.dir):
            for file in files:
                if Path(file).suffix.lower() in SUPPORTED_EXTENSIONS: files_to_scan.append(Path(os.path.join(root, file)))

    full_report = ""
    for file in files_to_scan:
        full_report += analyze_file(file, args)
        full_report += "\n---\n\n"

    if args.output: save_output(full_report, args.output, args.filetype)

if __name__ == "__main__":
    main()
