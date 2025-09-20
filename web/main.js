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

  /* 3. mobile navigation dropdown */
  const navToggle = document.querySelector(".nav-toggle");
  const navMenu   = document.getElementById("primary-nav");

  if (navToggle && navMenu) {
    const mobileQuery   = window.matchMedia("(max-width: 820px)");
    const isMobileView  = () => mobileQuery.matches;

    const closeNav = () => {
      navMenu.classList.remove("is-open");
      navToggle.setAttribute("aria-expanded", "false");
      if (isMobileView()) {
        navMenu.setAttribute("aria-hidden", "true");
      } else {
        navMenu.removeAttribute("aria-hidden");
      }
    };

    const openNav = () => {
      navMenu.classList.add("is-open");
      navToggle.setAttribute("aria-expanded", "true");
      navMenu.removeAttribute("aria-hidden");
    };

    closeNav();

    navToggle.addEventListener("click", () => {
      const expanded = navToggle.getAttribute("aria-expanded") === "true";
      expanded ? closeNav() : openNav();
    });

    navMenu.querySelectorAll("a").forEach(link => {
      link.addEventListener("click", closeNav);
    });

    const handleQueryChange = () => {
      closeNav();
    };

    if (typeof mobileQuery.addEventListener === "function") {
      mobileQuery.addEventListener("change", handleQueryChange);
    } else if (typeof mobileQuery.addListener === "function") {
      mobileQuery.addListener(handleQueryChange);
    }

    document.addEventListener("click", event => {
      if (!navMenu.classList.contains("is-open")) return;
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (navMenu.contains(target)) return;
      if (navToggle.contains(target)) return;
      closeNav();
    });

    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && navMenu.classList.contains("is-open")) {
        closeNav();
        navToggle.focus();
      }
    });
  }

  /* 4. theme toggle */
  const themeToggle = document.querySelector(".theme-toggle");
  const storageKey  = "bridge-delay-theme";
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)");

  const getStoredTheme = () => {
    try {
      return localStorage.getItem(storageKey);
    } catch (_) {
      return null;
    }
  };

  const storeTheme = theme => {
    try {
      localStorage.setItem(storageKey, theme);
    } catch (_) {
      /* no-op */
    }
  };

  const updateThemeToggle = theme => {
    if (!themeToggle) return;
    const isLight = theme === "light";
    themeToggle.innerHTML = `${isLight ? "🌙" : "☀️"} ${isLight ? "Dark mode" : "Light mode"}`;
    themeToggle.setAttribute("aria-pressed", String(isLight));
  };

  const applyTheme = theme => {
    document.body.setAttribute("data-theme", theme);
    updateThemeToggle(theme);
  };

  const storedTheme = getStoredTheme();
  const initialTheme = storedTheme || (prefersDark.matches ? "dark" : "light");
  applyTheme(initialTheme);

  themeToggle?.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme") || initialTheme;
    const next    = current === "light" ? "dark" : "light";
    applyTheme(next);
    storeTheme(next);
  });

  const handleSchemeChange = event => {
    if (!getStoredTheme()) {
      applyTheme(event.matches ? "dark" : "light");
    }
  };

  if (typeof prefersDark.addEventListener === "function") {
    prefersDark.addEventListener("change", handleSchemeChange);
  } else if (typeof prefersDark.addListener === "function") {
    prefersDark.addListener(handleSchemeChange);
  }
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
   Sign-up form → Azure API   (AJAX / fetch)
──────────────────────────────────────────────────────────────*/
const API = "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net";

const form   = document.getElementById("signup-form");
const input  = document.getElementById("email");
const status = document.getElementById("signup-status");

form?.addEventListener("submit", async e => {
  e.preventDefault();                          // stop full-page POST
  status.textContent = "Sending…";

  try {
    const res  = await fetch(`${API}/api/signup`, {
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
