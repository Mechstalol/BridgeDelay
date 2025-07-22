document.addEventListener("DOMContentLoaded", () => {
  /* 1. assign a per-element delay based on order in the DOM */
  const revealEls = [...document.querySelectorAll(".reveal")];
  revealEls.forEach((el, i) => {
    const custom = el.dataset.delay;            // keep manual delay if present
    const delay   = custom ?? (i * 0.06).toFixed(2);   // 60 ms cadence
    el.style.setProperty("--rv-delay", `${delay}s`);
  });

  /* 2. fade + rise when the element scrolls into view */
  const observer = new IntersectionObserver(
    entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          observer.unobserve(entry.target);     // animate once
        }
      });
    },
    { threshold: 0.15 }                         // trigger when 15 % visible
  );

  revealEls.forEach(el => observer.observe(el));
});


/* ═════════ DEV-ONLY VIEWPORT TOGGLE ═════════ */
document.getElementById("dev-viewport-toggle")?.addEventListener("click", e => {
  const pressed = e.currentTarget.getAttribute("aria-pressed") === "true";
  e.currentTarget.setAttribute("aria-pressed", String(!pressed));
  document.body.classList.toggle("force-mobile", !pressed);
});
