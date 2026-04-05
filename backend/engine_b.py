import subprocess
import json
import tempfile
import os
import re


def _looks_like_python(text):
    """Return True if the text appears to contain Python code."""
    python_indicators = [
        "def ", "import ", "class ", "return ", " = ", "if ", "for ",
        "while ", "try:", "except", "with ", "print(",
    ]
    return any(indicator in text for indicator in python_indicators)


def extract_code_from_response(response_text):
    """
    LLMs often wrap code in markdown blocks. Extract the actual Python code.
    Returns empty string if no Python code can be found.
    """
    if not response_text:
        return ""

    # Try to find ```python ... ``` block
    pattern = r"```(?:python)?\s*\n(.*?)```"
    matches = re.findall(pattern, response_text, re.DOTALL)
    if matches:
        return matches[0].strip()

    # If no code block, filter prose lines and check if remainder looks like Python
    lines = response_text.strip().split("\n")
    code_lines = [
        l for l in lines
        if not l.startswith("Here") and not l.startswith("This") and not l.startswith("Note")
    ]
    result = "\n".join(code_lines).strip()
    if not _looks_like_python(result):
        return ""
    return result


def run_semgrep(filepath):
    """Run Semgrep and return parsed findings."""
    findings = []
    try:
        result = subprocess.run(
            ["python", "-m", "semgrep", "--config=auto", "--json", "--quiet", filepath],
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            cwe_raw = meta.get("cwe", [])
            # cwe can be a list or a string
            if isinstance(cwe_raw, str):
                cwes = [cwe_raw]
            elif isinstance(cwe_raw, list):
                cwes = cwe_raw
            else:
                cwes = []

            # Extract just the CWE-XXX part
            cwe_ids = []
            for c in cwes:
                match = re.search(r"CWE-\d+", str(c))
                if match:
                    cwe_ids.append(match.group())

            findings.append({
                "tool": "semgrep",
                "rule": r.get("check_id", "unknown"),
                "cwes": cwe_ids if cwe_ids else ["unmapped"],
                "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
                "line": r.get("start", {}).get("line", 0),
                "message": r.get("extra", {}).get("message", "No description"),
            })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        findings.append({
            "tool": "semgrep",
            "rule": "error",
            "cwes": [],
            "severity": "ERROR",
            "line": 0,
            "message": f"Semgrep failed: {str(e)}",
        })
    return findings


def run_bandit(filepath):
    """Run Bandit and return parsed findings."""
    findings = []
    try:
        result = subprocess.run(
            ["python", "-m", "bandit", "-f", "json", "-ll", filepath],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout) if result.stdout.strip() else {}
        for r in data.get("results", []):
            cwe_info = r.get("issue_cwe", {})
            cwe_id = f"CWE-{cwe_info.get('id', 'unknown')}" if cwe_info.get("id") else "unmapped"

            findings.append({
                "tool": "bandit",
                "rule": r.get("test_id", "unknown"),
                "cwes": [cwe_id],
                "severity": r.get("issue_severity", "UNKNOWN"),
                "line": r.get("line_number", 0),
                "message": r.get("issue_text", "No description"),
            })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        findings.append({
            "tool": "bandit",
            "rule": "error",
            "cwes": [],
            "severity": "ERROR",
            "line": 0,
            "message": f"Bandit failed: {str(e)}",
        })
    return findings


def scan_code(code_string):
    """
    Write code to a temp file, run both scanners, return combined findings.
    Only returns MEDIUM or higher severity.
    """
    # Extract clean code from LLM response
    clean_code = extract_code_from_response(code_string)

    if not clean_code:
        return [], ""

    # Write to temp file
    with tempfile.NamedTemporaryFile(
        suffix=".py", mode="w", delete=False, dir=tempfile.gettempdir()
    ) as f:
        f.write(clean_code)
        filepath = f.name

    try:
        semgrep_findings = run_semgrep(filepath)
        bandit_findings = run_bandit(filepath)
    finally:
        os.unlink(filepath)

    all_findings = semgrep_findings + bandit_findings

    # Filter: medium+ severity only; keep scanner errors so callers can surface them
    filtered = [
        f for f in all_findings
        if f["severity"].upper() in ("MEDIUM", "HIGH", "CRITICAL", "WARNING", "ERROR")
    ]

    return filtered, clean_code
