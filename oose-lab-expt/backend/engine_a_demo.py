# Engine A — Prompt Enrichment (illustrative, no server)
# Scans a user prompt for security-relevant keywords and
# appends CWE-mapped warnings before the prompt is sent to an LLM.

CWE_MAPPINGS = {
    "login":    {"cwes": ["CWE-521"], "warning": "Enforce password complexity; hash with bcrypt (CWE-521)"},
    "mysql":    {"cwes": ["CWE-89"],  "warning": "Use parameterised queries; never interpolate user input into SQL (CWE-89)"},
    "password": {"cwes": ["CWE-798"], "warning": "Load secrets from environment variables; do not hard-code credentials (CWE-798)"},
    "upload":   {"cwes": ["CWE-434"], "warning": "Validate file type and size; never trust the client-supplied filename (CWE-434)"},
    "exec":     {"cwes": ["CWE-78"],  "warning": "Avoid shell=True; use subprocess with a fixed argument list (CWE-78)"},
}

def enrich_prompt(prompt: str) -> str:
    lower = prompt.lower()
    warnings, seen = [], set()

    for keyword, entry in CWE_MAPPINGS.items():
        if keyword in lower and entry["cwes"][0] not in seen:
            seen.add(entry["cwes"][0])
            warnings.append(f"- {entry['warning']}")

    if not warnings:
        return prompt

    return (
        f"{prompt}\n\n"
        f"IMPORTANT SECURITY REQUIREMENTS:\n"
        + "\n".join(warnings)
        + "\n\nWrite secure code that avoids the above vulnerabilities."
    )


if __name__ == "__main__":
    prompt = "Write a Flask endpoint for user login that checks username and password against a MySQL database"
    print(enrich_prompt(prompt))
