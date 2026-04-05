from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

from engine_a import enrich_prompt
from engine_b import scan_code
from engine_c import repair_loop
from llm_client import call_llm
from database import init_db, save_run, get_all_runs, get_db

app = Flask(__name__)
CORS(app, origins="*")

# Load demo prompts
PROMPTS_PATH = os.path.join(os.path.dirname(__file__), "prompts.json")
with open(PROMPTS_PATH, "r") as f:
    DEMO_PROMPTS = json.load(f)


@app.route("/api/prompts", methods=["GET"])
def list_prompts():
    """Return the list of demo prompts."""
    return jsonify(DEMO_PROMPTS)


@app.route("/api/run", methods=["POST"])
def run_pipeline():
    """
    Run the full pipeline for a single prompt + model + mode.

    Body: {
        "prompt": "Write a Flask login...",
        "prompt_id": "P001",       (optional)
        "model": "gemini" | "groq",
        "mode": "plain" | "enriched" | "enriched_repair"
    }
    """
    data = request.json
    prompt = data.get("prompt", "")
    prompt_id = data.get("prompt_id", "custom")
    model = data.get("model", "gemini")
    mode = data.get("mode", "enriched_repair")

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    result = {
        "prompt_id": prompt_id,
        "prompt_text": prompt,
        "model": model,
        "mode": mode,
    }

    # --- Step 1: Engine A (enrichment) ---
    if mode in ("enriched", "enriched_repair"):
        enriched, matched_cwes, matched_keywords, keyword_cwe_pairs = enrich_prompt(prompt)
    else:
        enriched = prompt
        matched_cwes = []
        matched_keywords = []
        keyword_cwe_pairs = []

    result["enriched_prompt"] = enriched
    result["matched_cwes"] = matched_cwes
    result["matched_keywords"] = matched_keywords
    result["keyword_cwe_pairs"] = keyword_cwe_pairs

    # --- Step 2: LLM call ---
    try:
        raw_response = call_llm(enriched, model)
    except Exception as e:
        return jsonify({"error": f"LLM call failed: {str(e)}"}), 500

    result["generated_code"] = raw_response

    # --- Step 3: Engine B (scan) ---
    vulnerabilities, clean_code = scan_code(raw_response)
    result["clean_code"] = clean_code
    result["scan_results"] = vulnerabilities
    result["vuln_count"] = len(vulnerabilities)

    # --- Step 4: Engine C (repair) ---
    if mode == "enriched_repair" and vulnerabilities and clean_code:
        repair_result = repair_loop(
            clean_code, vulnerabilities, model,
            max_iterations=3, security_context=matched_cwes or None
        )
        result["repair_result"] = repair_result
        result["final_status"] = repair_result["final_status"]
        result["total_iterations"] = repair_result["total_iterations"]
    else:
        result["repair_result"] = {}
        result["final_status"] = "clean" if not vulnerabilities else "not_repaired"
        result["total_iterations"] = 0

    # --- Step 5: Save to database ---
    save_run(result)

    return jsonify(result)


@app.route("/api/compare", methods=["POST"])
def compare_models():
    """
    Run the pipeline for BOTH models on the same prompt, all three modes.
    This is the main demo endpoint.

    Body: { "prompt": "...", "prompt_id": "P001" }
    """
    data = request.json
    prompt = data.get("prompt", "")
    prompt_id = data.get("prompt_id", "custom")

    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400

    results = {}

    for model in ["gemini", "groq"]:
        results[model] = {}
        for mode in ["plain", "enriched", "enriched_repair"]:
            # Engine A
            if mode in ("enriched", "enriched_repair"):
                enriched, matched_cwes, matched_keywords, keyword_cwe_pairs = enrich_prompt(prompt)
            else:
                enriched = prompt
                matched_cwes = []
                matched_keywords = []
                keyword_cwe_pairs = []

            # LLM call
            try:
                raw_response = call_llm(enriched, model)
            except Exception as e:
                error_entry = {"error": str(e)}
                results[model][mode] = error_entry
                save_run({
                    "prompt_id": prompt_id,
                    "prompt_text": prompt,
                    "enriched_prompt": enriched,
                    "matched_cwes": matched_cwes,
                    "matched_keywords": matched_keywords,
                    "keyword_cwe_pairs": keyword_cwe_pairs,
                    "model": model,
                    "mode": mode,
                    "generated_code": "",
                    "clean_code": "",
                    "scan_results": [],
                    "vuln_count": 0,
                    "repair_result": {},
                    "final_status": "llm_error",
                    "total_iterations": 0,
                })
                continue

            # Engine B
            vulns, clean_code = scan_code(raw_response)

            entry = {
                "enriched_prompt": enriched,
                "matched_cwes": matched_cwes,
                "matched_keywords": matched_keywords,
                "keyword_cwe_pairs": keyword_cwe_pairs,
                "generated_code": raw_response,
                "clean_code": clean_code,
                "scan_results": vulns,
                "vuln_count": len(vulns),
            }

            # Engine C
            if mode == "enriched_repair" and vulns and clean_code:
                repair_result = repair_loop(
                    clean_code, vulns, model,
                    max_iterations=3, security_context=matched_cwes or None
                )
                entry["repair_result"] = repair_result
                entry["final_status"] = repair_result["final_status"]
                entry["total_iterations"] = repair_result["total_iterations"]
            else:
                entry["repair_result"] = {}
                entry["final_status"] = "clean" if not vulns else "not_repaired"
                entry["total_iterations"] = 0

            results[model][mode] = entry

            # Save each run
            save_run({
                "prompt_id": prompt_id,
                "prompt_text": prompt,
                "enriched_prompt": enriched,
                "matched_cwes": matched_cwes,
                "matched_keywords": matched_keywords,
                "keyword_cwe_pairs": keyword_cwe_pairs,
                "model": model,
                "mode": mode,
                "generated_code": raw_response,
                "clean_code": clean_code,
                "scan_results": vulns,
                "vuln_count": len(vulns),
                "repair_result": entry.get("repair_result", {}),
                "final_status": entry["final_status"],
                "total_iterations": entry["total_iterations"],
            })

    return jsonify(results)


@app.route("/api/history", methods=["GET"])
def history():
    """Return all saved runs."""
    return jsonify(get_all_runs())


@app.route("/api/stats", methods=["GET"])
def stats():
    """
    Aggregate vuln reduction stats across all named demo prompt runs.
    For each (prompt_id, model, mode) group, uses the most recent run.
    Only includes runs where prompt_id is a real prompt ID (not 'custom'/'').
    """
    conn = get_db()
    rows = conn.execute("""
        SELECT prompt_id, prompt_text, model, mode, vuln_count, final_status, total_iterations
        FROM runs
        WHERE prompt_id NOT IN ('custom', '') AND prompt_id IS NOT NULL
          AND id IN (
              SELECT MAX(id) FROM runs
              WHERE prompt_id NOT IN ('custom', '') AND prompt_id IS NOT NULL
              GROUP BY prompt_id, model, mode
          )
        ORDER BY prompt_id, model, mode
    """).fetchall()
    conn.close()

    # Group: by_data[prompt_id][model][mode] = {vuln_count, final_status, ...}
    by_data = defaultdict(lambda: defaultdict(dict))
    prompt_texts = {}

    for row in rows:
        pid = row["prompt_id"]
        prompt_texts[pid] = row["prompt_text"]
        by_data[pid][row["model"]][row["mode"]] = {
            "vuln_count": row["vuln_count"],
            "final_status": row["final_status"],
            "total_iterations": row["total_iterations"],
        }

    def reduction_pct(plain, other):
        if plain is None or other is None or plain == 0:
            return None
        return round((plain - other) / plain * 100)

    def avg(lst):
        return round(sum(lst) / len(lst), 1) if lst else None

    # Per-prompt breakdown
    by_prompt = []
    for pid in sorted(by_data.keys()):
        entry = {"prompt_id": pid, "prompt_text": prompt_texts[pid]}
        for model in ["gemini", "groq"]:
            modes = by_data[pid].get(model, {})
            plain   = modes.get("plain",           {}).get("vuln_count")
            enriched = modes.get("enriched",        {}).get("vuln_count")
            repair  = modes.get("enriched_repair",  {}).get("vuln_count")
            r_status = modes.get("enriched_repair", {}).get("final_status")
            entry[model] = {
                "plain":    plain,
                "enriched": enriched,
                "repair":   repair,
                "repair_status": r_status,
                "enriched_reduction_pct": reduction_pct(plain, enriched),
                "repair_reduction_pct":   reduction_pct(plain, repair),
            }
        by_prompt.append(entry)

    # Overall per-model aggregates
    overall = {}
    for model in ["gemini", "groq"]:
        plain_vals, enriched_vals, repair_vals = [], [], []
        enriched_reds, repair_reds, repair_statuses = [], [], []

        for pid in by_data:
            modes = by_data[pid].get(model, {})
            plain   = modes.get("plain",          {}).get("vuln_count")
            enriched = modes.get("enriched",       {}).get("vuln_count")
            repair  = modes.get("enriched_repair", {}).get("vuln_count")
            r_status = modes.get("enriched_repair",{}).get("final_status")

            if plain    is not None: plain_vals.append(plain)
            if enriched is not None: enriched_vals.append(enriched)
            if repair   is not None: repair_vals.append(repair)
            if r_status is not None: repair_statuses.append(r_status)

            if plain is not None and plain > 0:
                if enriched is not None: enriched_reds.append((plain - enriched) / plain * 100)
                if repair   is not None: repair_reds.append((plain - repair)   / plain * 100)

        conv_count = sum(1 for s in repair_statuses if s == "clean")
        overall[model] = {
            "plain_avg":              avg(plain_vals),
            "enriched_avg":           avg(enriched_vals),
            "repair_avg":             avg(repair_vals),
            "enriched_reduction_pct": round(sum(enriched_reds) / len(enriched_reds)) if enriched_reds else None,
            "repair_reduction_pct":   round(sum(repair_reds)   / len(repair_reds))   if repair_reds   else None,
            "convergence_rate":       round(conv_count / len(repair_statuses) * 100)  if repair_statuses else None,
            "convergence_count":      conv_count,
            "total_repair_runs":      len(repair_statuses),
            "prompts_covered":        len([p for p in by_data if model in by_data[p]]),
        }

    return jsonify({"overall": overall, "by_prompt": by_prompt})


if __name__ == "__main__":
    init_db()
    print("\n  LeBlanc Pipeline — Demo Server")
    print("  http://localhost:5000\n")
    app.run(debug=True, port=5000)
