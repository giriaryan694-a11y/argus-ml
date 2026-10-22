import hashlib
import importlib.util
import json
import pickle
import sys
import zipfile
from argparse import Namespace
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "argus-ml.py"
spec = importlib.util.spec_from_file_location("argus_ml", SCRIPT)
argus = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = argus
spec.loader.exec_module(argus)


def test_binary_scan_detects_pattern_across_chunk_boundary(tmp_path):
    sample = tmp_path / "model.bin"
    chunk_size = 1024 * 1024
    payload = b"A" * (chunk_size - 3) + b"os.system('whoami')" + b"B" * 50
    sample.write_bytes(payload)
    report = argus.ScanReport(file=str(sample), size_bytes=len(payload))
    digest, bytes_read, truncated = argus.raw_binary_scan(sample, report, len(payload))
    assert bytes_read == len(payload)
    assert truncated is False
    assert digest == hashlib.sha256(payload).hexdigest()
    assert any("os.system" in f.message for f in report.findings)
    assert any(f.offset == chunk_size - 3 for f in report.findings if "os.system" in f.message)


def test_pickle_global_detection_does_not_unpickle(tmp_path):
    sample = tmp_path / "suspicious.pkl"
    # GLOBAL + STOP opcodes. The scanner may disassemble it but must never load it.
    sample.write_bytes(b"cos\nsystem\n.")
    report = argus.ScanReport(file=str(sample), size_bytes=sample.stat().st_size)
    argus.scan_pickle_opcodes(sample, report)
    assert any(f.severity == "HIGH" and "os.system" in f.message for f in report.findings)


def test_pickle_string_literal_is_not_misclassified_as_global(tmp_path):
    sample = tmp_path / "benign.pkl"
    sample.write_bytes(pickle.dumps("os.system is mentioned in documentation"))
    report = argus.ScanReport(file=str(sample), size_bytes=sample.stat().st_size)
    argus.scan_pickle_opcodes(sample, report)
    assert not any(f.severity == "HIGH" for f in report.findings)


def test_archive_path_traversal_flagged_without_extracting(tmp_path, monkeypatch):
    archive_path = tmp_path / "artifact.pt"
    outside = tmp_path / "outside.pkl"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.pkl", b"not a real pickle")
        archive.writestr("archive/data.pkl", b"cos\nsystem\n.")
    report = argus.ScanReport(file=str(archive_path), size_bytes=archive_path.stat().st_size)
    monkeypatch.setattr(argus, "run_pickle_engines", lambda *args, **kwargs: None)
    monkeypatch.setattr(argus, "run_tool", lambda *args, **kwargs: None)
    argus.scan_archive(archive_path, report, 1024 * 1024, 4 * 1024 * 1024, 100)
    assert any(f.engine == "ZIPMetadata" and "Unsafe archive member path" in f.message for f in report.findings)
    assert any(f.artifact == "artifact.pt!/archive/data.pkl" and "os.system" in f.message for f in report.findings)
    assert not outside.exists()


def test_keras_lambda_layer_is_review_not_critical():
    report = argus.ScanReport(file="model.keras", size_bytes=12)
    argus.analyze_keras_config('{"layers":[{"class_name":"Lambda","config":{}}]}', report)
    assert any(f.severity == "MEDIUM" and "Lambda layer" in f.message for f in report.findings)
    assert not any(f.severity == "CRITICAL" for f in report.findings)


def test_html_report_escapes_untrusted_strings():
    report = argus.ScanReport(file="<script>alert(1)</script>", size_bytes=1, status="SUSPICIOUS")
    report.findings.append(argus.Finding("HIGH", "test", "</pre><script>alert(1)</script>"))
    report.ai_analysis = "<img src=x onerror=alert(1)>"
    rendered = argus.report_as_html([report], [])
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered
    assert "&lt;img" in rendered


def test_safetensors_is_not_reported_as_blanket_safe(tmp_path):
    sample = tmp_path / "weights.safetensors"
    sample.write_bytes(b"tensor data")
    args = Namespace(
        max_file_size_mb=8, max_member_size_mb=1, max_archive_size_mb=4,
        max_archive_members=100, no_ai=True, provider="openai", model=None, verbose=False,
    )
    report = argus.scan_file(sample, args)
    assert report.status == "INCOMPLETE"
    assert any("does not validate its parser/runtime" in note for note in report.limitations)


def test_json_output_is_parseable_and_contains_summary(tmp_path):
    report = argus.ScanReport(file="weights.safetensors", size_bytes=3, status="NO_DETECTIONS")
    path = argus.save_output(str(tmp_path / "reports" / "argus"), "json", [report], [])
    result = json.loads(path.read_text(encoding="utf-8"))
    assert result["summary"]["artifacts"] == 1
    assert result["reports"][0]["status"] == "NO_DETECTIONS"


def test_symlink_input_is_rejected(tmp_path):
    real = tmp_path / "model.bin"
    real.write_bytes(b"data")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        return
    args = Namespace(target=str(link), dir=None, max_files=100)
    try:
        argus.collect_targets(args)
    except ValueError as exc:
        assert "symbolic-link" in str(exc)
    else:
        raise AssertionError("symbolic-link input should be rejected")


def test_markdown_report_escapes_untrusted_html():
    report = argus.ScanReport(file="<script>bad</script>", size_bytes=2)
    report.findings.append(argus.Finding("HIGH", "test", "<script>alert(1)</script>"))
    rendered = argus.report_as_markdown([report], [])
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_picklescan_zero_counts_are_not_a_detection():
    report = argus.ScanReport(file="clean.pkl", size_bytes=1)
    argus.add_external_output(report, "PickleScan", "Scanned files: 1\nInfected files: 0\nDangerous globals: 0", 0)
    assert not report.findings


def test_picklescan_nonzero_counts_are_detected():
    report = argus.ScanReport(file="suspicious.pkl", size_bytes=1)
    argus.add_external_output(report, "PickleScan", "Infected files: 2\nDangerous globals: 3", 1)
    assert any(f.severity == "HIGH" and f.engine == "PickleScan" for f in report.findings)


def test_modelscan_preserves_reported_severity():
    report = argus.ScanReport(file="model.h5", size_bytes=1)
    argus.add_external_output(report, "ModelScan", "Issue found. Severity: MEDIUM", 1)
    assert report.findings[0].severity == "MEDIUM"


def test_ai_payload_drops_raw_context_and_paths():
    report = argus.ScanReport(file="weights.pt", size_bytes=1)
    report.add("HIGH", "BinaryHeuristics", "os.system command-execution reference; context: API_KEY=secret-value", artifact="weights.pt!/private/path/data.pkl")
    payload = json.dumps(argus.ai_triage_metadata(report.findings))
    assert "secret-value" not in payload
    assert "private/path" not in payload
    assert "os.system command-execution reference" in payload


def test_scanner_environment_drops_secrets_and_python_injection(monkeypatch):
    monkeypatch.setenv("ARGUS_OPENAI_API_KEY", "secret-value")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "cloud-secret")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/modules")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = argus.sanitized_subprocess_env()
    assert "ARGUS_OPENAI_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "PYTHONPATH" not in env
    assert env["PATH"] == "/usr/bin"


def test_cli_ft_alias_maps_to_filetype():
    parsed = argus.build_parser().parse_args(["--target", "model.pt", "--ft", "html", "--no-ai"])
    assert parsed.filetype == "html"


def test_directory_limit_warns_only_if_more_files_remain(tmp_path):
    (tmp_path / "one.pt").write_bytes(b"one")
    args = Namespace(target=None, dir=str(tmp_path), max_files=1)
    targets, warnings = argus.collect_targets(args)
    assert len(targets) == 1
    assert not warnings
    (tmp_path / "two.pt").write_bytes(b"two")
    targets, warnings = argus.collect_targets(args)
    assert len(targets) == 1
    assert warnings and "additional files remain unscanned" in warnings[0]
