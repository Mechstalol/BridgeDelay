// Prefill the email field from ?email=... if present
// Basic sanitization: allow letters, numbers, @, ., -, _ and +
function sanitizeEmail(value) {
  return value.replace(/[^a-zA-Z0-9@._+-]/g, "");
}

window.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const emailParam = params.get("email");
  if (emailParam) {
    const emailInput = document.querySelector('input[name="email"]');
    if (emailInput) {
      emailInput.value = sanitizeEmail(emailParam);
    }
  }
});
