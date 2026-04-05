const DEMO_PROMPT = "Write a Flask endpoint for user login that checks username and password against a MySQL database";

const STEPS   = ["step1","step2","step3","step4"];
const DELAYS  = [600, 1500, 2400, 3400];
const MSGS    = [
  "Engine A — scanning prompt for security keywords…",
  "Calling LLM (plain mode)…",
  "Engine B — running static analysis…",
  "Engine C — sending repair request…",
];

function fillPrompt() {
  document.getElementById("promptInput").value = DEMO_PROMPT;
}

function runDemo() {
  const btn = document.getElementById("runBtn");
  btn.disabled = true;

  STEPS.forEach(id => document.getElementById(id).classList.remove("show"));

  const row  = document.getElementById("spinnerRow");
  const text = document.getElementById("spinnerText");
  row.style.display = "flex";

  STEPS.forEach((id, i) => {
    setTimeout(() => {
      text.textContent = MSGS[i];
      document.getElementById(id).classList.add("show");
      if (i === STEPS.length - 1) {
        setTimeout(() => { row.style.display = "none"; btn.disabled = false; }, 500);
      }
    }, DELAYS[i]);
  });
}
