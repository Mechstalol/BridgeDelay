/* Navigation + theme toggle shared across pages */

document.addEventListener("DOMContentLoaded", () => {
  /* ── Mobile navigation ─────────────────────────────────────── */
  const navToggle = document.querySelector(".nav-toggle");
  const navMenu   = document.getElementById("primary-nav");

  if (navToggle && navMenu) {
    const mobileQuery  = window.matchMedia("(max-width: 820px)");
    const isMobileView = () => mobileQuery.matches;

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

    navMenu.querySelectorAll("a, button").forEach(control => {
      control.addEventListener("click", () => {
        if (isMobileView()) closeNav();
      });
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

  /* ── Theme toggle ──────────────────────────────────────────── */
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
      /* ignore */
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

  const storedTheme  = getStoredTheme();
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
