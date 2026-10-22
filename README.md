# 🛡️ Argus-ML

**Argus-ML** is a static triage CLI for suspicious AI/ML model artifacts. It combines byte-level indicators with optional PickleScan, Fickling, ModelScan, and HDF5/Keras metadata inspection. It can scan one artifact or recursively scan a directory and export TXT, Markdown, HTML, or JSON reports.

> **Important:** `NO_DETECTIONS` does not mean `SAFE`. Static scanning cannot prove that a model, its loader, or its runtime is safe. Argus-ML does not deserialize models itself, but installed third-party parsers still process untrusted files. Use an isolated, patched environment for untrusted samples.

## What changed in v2

- Removed source-code API-key placeholders. Provider keys are read from environment variables.
- Made the banner and AI libraries optional, so static scanning does not fail just because a cosmetic or cloud package is missing.
- Added timeouts for third-party scanner commands and the HDF5 metadata probe.
- Added ZIP member/path checks, symlink-entry warnings, archive/member size limits, and bounded recursive scans. Members are inspected through temporary files, not extracted using archive-controlled paths.
- Scans all relevant embedded pickle/NumPy members within configured limits instead of only the first matching entry.
- Added cross-chunk byte-pattern matching and SHA-256 output when the entire file was read.
- Added Keras Lambda-configuration indicators without claiming that a Lambda layer alone proves malware.
- Removed blanket “safe” treatment for ONNX and Safetensors. Those formats have different risk profiles, but a file extension cannot certify the safety of its parser, framework, or loading pipeline.
- Added honest `SUSPICIOUS`, `REVIEW`, `INCOMPLETE`, and `NO_DETECTIONS` statuses, JSON output, safer HTML escaping, atomic report writes, and exit codes for automation.
- Added unit tests for scanner behavior and report safety.

## Requirements

- Python 3.10 or newer for the core CLI. Python 3.10–3.12 is recommended for the complete optional scanner stack because ModelScan currently has a narrower tested Python range.
- Install optional scanning engines using `requirements.txt`. If an engine is absent, Argus-ML records the resulting coverage limitation rather than pretending the scan was comprehensive.
- AI packages are only needed when using AI-assisted triage.

```bash
git clone https://github.com/giriaryan694-a11y/argus-ml.git
cd argus-ml
python -m pip install -r requirements.txt
```

For strongest isolation, run scans in a disposable VM or a locked-down container with no network access and no sensitive host mounts. Keep Python and all scanner dependencies patched. Do not open or load a model merely because a report has no findings.

## Usage

### Scan one artifact

```bash
python argus-ml.py --target ./models/model.pt --no-ai
```

### Scan a directory and create an HTML report

```bash
python argus-ml.py --dir ./models --output reports/argus --filetype html --no-ai
```

### Generate machine-readable JSON

```bash
python argus-ml.py --dir ./models --output reports/argus --filetype json --no-ai
```

### Tune resource limits

```bash
python argus-ml.py --target ./models/model.pt \
  --max-file-size-mb 8192 \
  --max-member-size-mb 128 \
  --max-archive-size-mb 2048 \
  --max-archive-members 10000 \
  --no-ai
```

For a file larger than `--max-file-size-mb`, Argus-ML performs a capped byte scan and skips deep parsers. The default file cap is 8192 MiB. Use `--max-file-size-mb 0` to disable that cap deliberately. ZIP scanning separately limits each selected member and their combined declared uncompressed size to reduce ZIP-bomb risk; large tensor-weight entries that are not inspected do not consume the selected-member budget. Limits can cause an `INCOMPLETE` result; do not interpret that as a clean scan.

### AI-assisted triage (optional)

API keys are read from environment variables. Use the provider-specific variable, for example:

**Linux/macOS**

```bash
export ARGUS_OPENAI_API_KEY="your-key"
python argus-ml.py --target ./models/model.pt --provider openai
```

**PowerShell**

```powershell
$env:ARGUS_OPENAI_API_KEY = "your-key"
python .\argus-ml.py --target .\models\model.pt --provider openai
```

Supported variables:

| Provider | Preferred environment variable | Also accepted |
|---|---|---|
| OpenAI | `ARGUS_OPENAI_API_KEY` | `OPENAI_API_KEY` |
| Google Gemini | `ARGUS_GEMINI_API_KEY` | `GEMINI_API_KEY`, `GOOGLE_API_KEY` |
| NVIDIA | `ARGUS_NVIDIA_API_KEY` | `NVIDIA_API_KEY` |

The AI feature sends **finding metadata only**, not model bytes or extracted payload snippets. Provider requests may still incur charges and are subject to each provider's terms. Set `--no-ai` to disable cloud analysis completely. Model identifiers change over time; use `--model MODEL_ID` to override a provider's default when needed.

## Supported file families

Argus-ML can accept the following extensions; detection depth varies by format and installed engine:

- Pickle-derived: `.pkl`, `.pickle`, `.pk1`, `.pt`, `.pth`, `.bin`, `.joblib`
- NumPy: `.npy`, `.npz`
- HDF5/Keras/TensorFlow: `.h5`, `.hdf5`, `.keras`, `.pb`
- Other model formats: `.safetensors`, `.gguf`, `.onnx`

This extension list is not a promise that every engine understands every format. In particular, ONNX, GGUF, and Safetensors receive limited heuristic inspection in this version. A Safetensors file avoids the ordinary pickle deserialization path when used correctly, but downstream loaders, runtimes, custom operations, dependencies, and model provenance still matter.

## Interpreting status and exit codes

| Status | Meaning |
|---|---|
| `SUSPICIOUS` | High/critical indicators or a scanner-reported issue requires investigation. This is not automatically proof of successful exploitation. |
| `REVIEW` | Medium/low indicators were found. Validate context and benign explanations. |
| `INCOMPLETE` | Important checks were skipped, failed, timed out, or were unavailable. |
| `NO_DETECTIONS` | No indicators were found by the checks that completed. This is not a safety certification. |

CLI exit codes:

- `0`: No findings and no known scan limitations.
- `1`: At least one artifact has a `SUSPICIOUS` or `REVIEW` status.
- `2`: Input, coverage, or scan-completion problem.

Directory scans only select files with supported extensions. Single-file scans accept any regular file and report when only byte-level heuristics apply. Symbolic-link inputs are rejected to avoid silently scanning outside the requested scope.

## Detection engines and limitations

- **Binary heuristics:** looks for selected command-execution and dynamic-loading strings. These are indicators, not proof; compressed or obfuscated content may evade them, and benign files can contain matching strings.
- **PickleScan and Fickling:** analyze pickle-derived content without asking Argus-ML to load the model.
- **ModelScan:** adds format-aware detection where supported by its installed version.
- **HDF5/Keras metadata:** checks model/layer configuration attributes in a separate Python process with a timeout.
- **Keras Lambda indicator:** reported as a review item because risks depend on the serialized content and loading configuration. It is not inherently proof of malicious code.
- **AI analysis:** advisory only; it can be wrong and never overrides scanner evidence or scan limitations.

No scanner catches every malicious artifact. Review model provenance, hashes/revisions, framework loading flags, custom layers/operators, dependencies, and the environment in which the artifact will run.

## License

Licensed under the Apache License 2.0. See `LICENSE`.
