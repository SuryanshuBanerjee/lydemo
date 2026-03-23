from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os

from engine_a import enrich_prompt
from engine_b import scan_code
from engine_c import repair_loop
from llm_client import call_llm
from database import init_db, save_run, get_all_runs

app = Flask(__name__)
CORS(app)

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
        enriched, matched_cwes, matched_keywords = enrich_prompt(prompt)
    else:
        enriched = prompt
        matched_cwes = []
        matched_keywords = []

    result["enriched_prompt"] = enriched
    result["matched_cwes"] = matched_cwes
    result["matched_keywords"] = matched_keywords

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
    if mode == "enriched_repair" and vulnerabilities:
        repair_result = repair_loop(clean_code, vulnerabilities, model, max_iterations=3)
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
                enriched, matched_cwes, _ = enrich_prompt(prompt)
            else:
                enriched = prompt
                matched_cwes = []

            # LLM call
            try:
                raw_response = call_llm(enriched, model)
            except Exception as e:
                results[model][mode] = {"error": str(e)}
                continue

            # Engine B
            vulns, clean_code = scan_code(raw_response)

            entry = {
                "enriched_prompt": enriched,
                "matched_cwes": matched_cwes,
                "generated_code": raw_response,
                "clean_code": clean_code,
                "scan_results": vulns,
                "vuln_count": len(vulns),
            }

            # Engine C
            if mode == "enriched_repair" and vulns:
                repair_result = repair_loop(clean_code, vulns, model, max_iterations=3)
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


if __name__ == "__main__":
    init_db()
    print("\n  LeBlanc Pipeline — Demo Server")
    print("  http://localhost:5000\n")
    app.run(debug=True, port=5000)
