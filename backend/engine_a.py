import json
import os

MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "cwe_mappings.json")

def load_mappings():
    with open(MAPPINGS_PATH, "r") as f:
        return json.load(f)

def enrich_prompt(prompt):
    """
    Scans the prompt for security-relevant keywords and appends CWE warnings.
    Returns (enriched_prompt, matched_cwes, matched_keywords).
    """
    mappings = load_mappings()
    prompt_lower = prompt.lower()

    matched = {}  # keyword -> mapping entry (deduplicate by CWE)
    seen_cwes = set()

    for keyword, entry in mappings.items():
        if keyword in prompt_lower:
            for cwe in entry["cwes"]:
                if cwe not in seen_cwes:
                    seen_cwes.add(cwe)
                    matched[keyword] = entry
                    break

    if not matched:
        return prompt, [], []

    warnings = []
    all_cwes = []
    all_keywords = []

    for keyword, entry in matched.items():
        warnings.append(f"- {entry['warning']}")
        all_cwes.extend(entry["cwes"])
        all_keywords.append(keyword)

    # Deduplicate CWEs
    all_cwes = list(dict.fromkeys(all_cwes))

    warning_block = "\n".join(warnings)
    enriched = (
        f"{prompt}\n\n"
        f"IMPORTANT SECURITY REQUIREMENTS:\n"
        f"{warning_block}\n\n"
        f"Write secure code that avoids the above vulnerabilities."
    )

    return enriched, all_cwes, all_keywords
