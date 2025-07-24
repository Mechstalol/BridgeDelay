/* ─────────────────────────────────────────────────────────────
   Reveal-on-scroll animation (original code, unchanged)
──────────────────────────────────────────────────────────────*/
document.addEventListener("DOMContentLoaded", () => {
  /* 1. assign a per-element delay */
  const revealEls = [...document.querySelectorAll(".reveal")];
  revealEls.forEach((el, i) => {
    const custom = el.dataset.delay;
    const delay  = custom ?? (i * 0.06).toFixed(2);
    el.style.setProperty("--rv-delay", `${delay}s`);
  });

  /* 2. fade + rise when scrolled into view */
  const observer = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );
  revealEls.forEach(el => observer.observe(el));
});

/* ───────── DEV-only viewport toggle (original) ──────────────*/
document
  .getElementById("dev-viewport-toggle")
  ?.addEventListener("click", e => {
    const pressed = e.currentTarget.getAttribute("aria-pressed") === "true";
    e.currentTarget.setAttribute("aria-pressed", String(!pressed));
    document.body.classList.toggle("force-mobile", !pressed);
  });

/* ─────────────────────────────────────────────────────────────
   NEW: Sign-up form → Azure API
──────────────────────────────────────────────────────────────*/
const API_BASE =
  "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net";

const form   = document.getElementById("signup-form");
const input  = document.getElementById("email");
const status = document.getElementById("signup-status");

form?.addEventListener("submit", async e => {
  e.preventDefault();
  status.textContent = "Sending…";

  try {
    const res  = await fetch(`${API_BASE}/api/signup`, {
      method : "POST",
      headers: { "Content-Type": "application/json" },
      body   : JSON.stringify({ email: input.value.trim() })
    });
    const data = await res.json();

    if (res.ok) {
      status.textContent = "✅ Thanks! Check your inbox.";
      form.reset();
    } else {
      throw new Error(data.message || res.statusText);
    }
  } catch (err) {
    status.textContent = "⚠️ " + err.message;
  }
});
