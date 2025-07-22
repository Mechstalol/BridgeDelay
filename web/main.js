/* Intersection Observer to toggle .in-view */
const observer = new IntersectionObserver(
  entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("in-view");
        observer.unobserve(entry.target);           // animate only once
      }
    });
  },
  {
    threshold: 0.2        // 20 % visible before firing
  }
);

/* Observe every .reveal element */
document.querySelectorAll(".reveal").forEach(el => observer.observe(el));
