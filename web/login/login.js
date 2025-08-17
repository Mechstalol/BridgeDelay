const API_BASE = "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net";

const phoneForm = document.getElementById('phone-form');
const codeForm  = document.getElementById('code-form');
const statusEl  = document.getElementById('login-status');

// same normalization the server expects (+1 for 10/11-digit NANP)
function normalizePhone(raw) {
  const s = (raw || "").trim();
  if (!s) return "";
  if (s.startsWith("+")) return "+" + s.replace(/\D/g, "");
  const digits = s.replace(/\D/g, "");
  if (digits.length === 10) return "+1" + digits;
  if (digits.length === 11 && digits[0] === "1") return "+1" + digits.slice(1);
  return ""; // invalid
}

// optional: if you add Cloudflare Turnstile, set window.turnstileToken when solved
function getCaptchaToken() {
  return window.turnstileToken || ""; // backend treats empty as OK when TURNSTILE_SECRET not set
}

phoneForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const phoneRaw = document.getElementById('phone').value;
  const phone = normalizePhone(phoneRaw);
  if (!phone) {
    statusEl.textContent = "Please enter a valid phone.";
    return;
  }
  statusEl.textContent = "Sending code…";

  try {
    const res = await fetch(`${API_BASE}/api/otp/start`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ phone, cf_turnstile_token: getCaptchaToken() })
    });
    const data = await res.json().catch(() => ({}));

    if (res.ok && (data.status === 'sent' || data.status === 'cooldown')) {
      // remember the exact phone we used so verify uses the same string
      sessionStorage.setItem('otpPhone', phone);
      statusEl.textContent = 'Code sent! Check your SMS.';
      phoneForm.style.display = 'none';
      codeForm.style.display = 'grid';
      document.getElementById('code').focus();
    } else {
      statusEl.textContent = data.error ? `Error: ${data.error}` : 'Failed to send code.';
    }
  } catch {
    statusEl.textContent = 'Network error. Try again.';
  }
});

codeForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = (document.getElementById('code').value || "").trim();
  const phone = sessionStorage.getItem('otpPhone') || normalizePhone(document.getElementById('phone').value);

  if (!phone || !/^\d{6}$/.test(code)) {
    statusEl.textContent = "Enter the 6-digit code.";
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/otp/verify`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ phone, code })
    });
    const data = await res.json().catch(() => ({}));

    if (res.ok && data.ok) {
      if (data.token) {
        localStorage.setItem('token', data.token);
      }
      // go to your account/settings page
      window.location.href = '../account/account.html';
    } else {
      statusEl.textContent = 'Invalid or expired code.';
    }
  } catch {
    statusEl.textContent = 'Network error. Try again.';
  }
});
