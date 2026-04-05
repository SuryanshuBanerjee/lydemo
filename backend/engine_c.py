from engine_b import scan_code
from llm_client import call_llm


def build_repair_prompt(code, vulnerabilities, security_context=None):
    """Build a structured repair prompt from scanner findings."""
    vuln_lines = []
    for i, v in enumerate(vulnerabilities, 1):
        cwes = ", ".join(v["cwes"]) if v["cwes"] else "unknown"
        vuln_lines.append(
            f"{i}. [{cwes}] {v['severity']} at line {v['line']}: {v['message']}"
        )

    vuln_block = "\n".join(vuln_lines)

    context_block = ""
    if security_context:
        cwe_list = ", ".join(security_context)
        context_block = (
            f"SECURITY REQUIREMENTS (CWEs relevant to this code): {cwe_list}\n\n"
        )

    return (
        f"The following Python code has security vulnerabilities. "
        f"Fix ALL of them and return ONLY the corrected code in a ```python``` block.\n\n"
        f"{context_block}"
        f"VULNERABILITIES FOUND:\n{vuln_block}\n\n"
        f"CODE TO FIX:\n```python\n{code}\n```\n\n"
        f"Return ONLY the fixed Python code. No explanations."
    )


def repair_loop(code, initial_vulns, model_name, max_iterations=5, security_context=None):
    """
    Run the repair loop: send vulns to LLM, get patched code, re-scan.
    Returns a list of iteration records and the final code.
    """
    if not code:
        return {
            "final_code": "",
            "final_status": "no_code",
            "iterations": [],
            "total_iterations": 0,
        }

    iterations = []
    current_code = code
    current_vulns = initial_vulns

    for i in range(max_iterations):
        if not current_vulns:
            break

        # Build repair prompt and call LLM
        repair_prompt = build_repair_prompt(current_code, current_vulns, security_context)
        raw_response = call_llm(repair_prompt, model_name)
        new_vulns, clean_code = scan_code(raw_response)

        iteration_record = {
            "iteration": i + 1,
            "vulns_before": len(current_vulns),
            "vulns_after": len(new_vulns),
            "vulnerabilities": new_vulns,
            "code": clean_code or current_code,
        }
        iterations.append(iteration_record)

        current_code = clean_code or current_code
        current_vulns = new_vulns

    final_status = "clean" if not current_vulns else "not_converged"

    return {
        "final_code": current_code,
        "final_status": final_status,
        "iterations": iterations,
        "total_iterations": len(iterations),
    }
