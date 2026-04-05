import json
import os

MAPPINGS_PATH = os.path.join(os.path.dirname(__file__), "cwe_mappings.json")

def load_mappings():
    with open(MAPPINGS_PATH, "r") as f:
        return json.load(f)

def enrich_prompt(prompt):
    """
    Scans the prompt for security-relevant keywords and appends CWE warnings.
    Returns (enriched_prompt, matched_cwes, matched_keywords, keyword_cwe_pairs).
    """
    mappings = load_mappings()
    prompt_lower = prompt.lower()

    matched = {}  # keyword -> mapping entry

    for keyword, entry in mappings.items():
        if keyword in prompt_lower:
            matched[keyword] = entry

    if not matched:
        return prompt, [], [], []

    warnings = []
    seen_warnings = set()
    all_cwes = []
    all_keywords = []
    keyword_cwe_pairs = []

    for keyword, entry in matched.items():
        warning_text = f"- {entry['warning']}"
        if warning_text not in seen_warnings:
            seen_warnings.add(warning_text)
            warnings.append(warning_text)
        all_cwes.extend(entry["cwes"])
        all_keywords.append(keyword)
        keyword_cwe_pairs.append({"keyword": keyword, "cwes": entry["cwes"]})

    # Deduplicate CWEs
    all_cwes = list(dict.fromkeys(all_cwes))

    warning_block = "\n".join(warnings)
    enriched = (
        f"{prompt}\n\n"
        f"IMPORTANT SECURITY REQUIREMENTS:\n"
        f"{warning_block}\n\n"
        f"Write secure code that avoids the above vulnerabilities."
    )

    return enriched, all_cwes, all_keywords, keyword_cwe_pairs
