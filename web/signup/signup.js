const API_BASE = "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net"; 
console.log("signup.js loaded", API_BASE);

function normalizePhone(raw) {
  const cleaned = raw.trim().replace(/[^\d+]/g, "");
  return cleaned.startsWith("+") ? cleaned : cleaned;
}

const form  = document.getElementById("signup-form");
const msgEl = document.createElement("div");
msgEl.className = "signup__msg";
form.after(msgEl);

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = form.querySelector("button[type=submit]");
  const raw = form.elements.phone.value;
  const phone = normalizePhone(raw);

  if (!/^\+\d{7,15}$/.test(phone)) {
    msgEl.textContent = "Please enter phone in +1234567890 format.";
    return;
  }

  btn.disabled = true;
  msgEl.textContent = "Submitting…";

  try {
    const res = await fetch(`${API_BASE}/api/signup`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ phone })
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok) {
      msgEl.textContent = data.msg === "already registered"
        ? "You’re already on the list ✅"
        : "Registered! You’ll get alerts when we go live ✅";
      form.reset();
    } else {
      msgEl.textContent = data.msg || "Sign-up failed. Try again.";
    }
  } catch (err) {
    msgEl.textContent = "Network error. Try again.";
  } finally {
    btn.disabled = false;
  }
});

