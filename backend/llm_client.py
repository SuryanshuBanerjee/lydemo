import os
import google.generativeai as genai
from groq import Groq

GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")
GROQ_KEY = os.environ.get("GROQ_API_KEY", "")

SYSTEM_INSTRUCTION = (
    "You are a Python code generator. Return ONLY Python code inside a single "
    "```python``` code block. No explanations, no comments outside the code, "
    "no markdown outside the code block."
)


def call_gemini(prompt):
    """Call Gemini API and return the response text."""
    if not GEMINI_KEY:
        raise ValueError("GEMINI_API_KEY not set in environment")

    genai.configure(api_key=GEMINI_KEY)
    model = genai.GenerativeModel(
        "gemini-2.5-flash",
        system_instruction=SYSTEM_INSTRUCTION,
    )
    response = model.generate_content(prompt)
    return response.text


def call_groq(prompt):
    """Call Groq API (Llama 3.1 70B) and return the response text."""
    if not GROQ_KEY:
        raise ValueError("GROQ_API_KEY not set in environment")

    client = Groq(api_key=GROQ_KEY)
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_INSTRUCTION},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=2048,
    )
    return response.choices[0].message.content


def call_llm(prompt, model_name):
    """Dispatch to the correct LLM based on model_name."""
    if model_name == "gemini":
        return call_gemini(prompt)
    elif model_name == "groq":
        return call_groq(prompt)
    else:
        raise ValueError(f"Unknown model: {model_name}. Use 'gemini' or 'groq'.")
