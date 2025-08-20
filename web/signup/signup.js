// 1) Set your backend URL
const API_BASE = "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net";

// 2) Grab your form and prepare a message area
const form  = document.getElementById("signup-form");
const msgEl = document.createElement("div");
msgEl.className = "signup__msg";
form.after(msgEl);

// We'll inject an OTP step container dynamically:
let otpStepEl = null;

// Small helpers
function setMsg(text, kind = "") {
  msgEl.textContent = text || "";
  msgEl.className = "signup__msg" + (kind ? " " + kind : "");
}
function disable(el, on = true) {
  if (!el) return;
  el.disabled = !!on;
}
async function postJSON(path, body) {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body || {}),
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

// Normalize phone for CA/US (let backend also validate)
function normalizePhone(raw) {
  if (!raw) return "";
  const s = raw.trim();
  if (s.startsWith("+")) {
    // Keep '+' but strip other junk
    return "+" + s.replace(/\D/g, "");
  }
  const digits = s.replace(/\D/g, "");
  if (digits.length === 10) return "+1" + digits;               // e.g. 604-555-1212
  if (digits.length === 11 && digits.startsWith("1")) return "+1" + digits.slice(1);
  // fallback - send whatever, backend will reject if bad
  return s;
}

// Build the OTP UI step (code input + buttons)
function showOtpStep(phone) {
  if (!otpStepEl) {
    otpStepEl = document.createElement("div");
    otpStepEl.className = "signup__otp";
    otpStepEl.innerHTML = `
      <div style="margin-top:12px; padding:12px; border:1px solid #e5e7eb; border-radius:10px">
        <p style="margin:0 0 10px 0">We sent a 6-digit code to <strong id="otp-phone"></strong>.</p>
        <form id="otp-form" autocomplete="one-time-code" inputmode="numeric" style="display:flex; gap:8px; align-items:center;">
          <input id="otp-code" type="text" inputmode="numeric" pattern="\\d{6}" minlength="6" maxlength="6" placeholder="123456" required
                 style="flex:1; padding:10px; border-radius:8px; border:1px solid #d1d5db" />
          <button id="otp-verify" type="submit" class="cta" style="padding:10px 14px">Verify</button>
          <button id="otp-resend" type="button" style="padding:10px 14px">Resend</button>
          <button id="otp-edit"   type="button" style="padding:10px 14px">Edit phone</button>
        </form>
        <div id="otp-msg" style="margin-top:8px; font-size:14px;"></div>
      </div>
    `;
    form.after(otpStepEl);
  }
  // Fill phone & toggle visibility
  otpStepEl.querySelector("#otp-phone").textContent = phone;
  otpStepEl.style.display = "block";
  setMsg("We sent you a code. Check your SMS.", "success");

  // Wire up buttons
  const otpForm   = otpStepEl.querySelector("#otp-form");
  const codeEl    = otpStepEl.querySelector("#otp-code");
  const verifyBtn = otpStepEl.querySelector("#otp-verify");
  const resendBtn = otpStepEl.querySelector("#otp-resend");
  const editBtn   = otpStepEl.querySelector("#otp-edit");
  const otpMsg    = otpStepEl.querySelector("#otp-msg");

  function setOtpMsg(t, color="#374151") {
    otpMsg.textContent = t || "";
    otpMsg.style.color = color;
  }

  otpForm.onsubmit = async (e) => {
    e.preventDefault();
    const code = (codeEl.value || "").trim();
    if (!/^[0-9]{6}$/.test(code)) {
      setOtpMsg("Enter the 6-digit code from the SMS.", "#b91c1c");
      return;
    }
    disable(verifyBtn, true);
    setOtpMsg("Verifying…");
    const r = await postJSON("/api/otp/verify", { phone, code });
    disable(verifyBtn, false);

    if (!r.ok) {
      setOtpMsg("Invalid or expired code. Try again.", "#b91c1c");
      return;
    }

    // Store JWT if backend returned one
    if (r.data?.token) {
      localStorage.setItem("nv_token", r.data.token);
    }
    localStorage.setItem("nv_phone", phone);

    setOtpMsg("You're in! Redirecting…", "#065f46");
    // Redirect to Setup page after successful verification
    window.location.href = "/setup/setup.html";
  };

  resendBtn.onclick = async () => {
    disable(resendBtn, true);
    setOtpMsg("Resending…");
    const r = await postJSON("/api/otp/start", { phone });
    disable(resendBtn, false);
    if (r.ok && r.data?.status === "cooldown") {
      setOtpMsg("Code was just sent — wait a minute and try again.", "#6b7280");
    } else if (r.ok) {
      setOtpMsg("New code sent.", "#065f46");
    } else {
      setOtpMsg("Couldn’t resend right now. Try later.", "#b91c1c");
    }
  };

  editBtn.onclick = () => {
    otpStepEl.style.display = "none";
    setMsg(""); // clear main message
    // let the user change the phone in the original form
  };
}

// Handle the initial form (we only require the phone right now)
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const submitBtn = form.querySelector('button[type="submit"]');
  const phoneRaw  = form.elements.phone?.value || "";
  const phone     = normalizePhone(phoneRaw);

  if (!phone) {
    setMsg("Please enter a valid phone number.", "error");
    return;
  }

  disable(submitBtn, true);
  setMsg("Submitting…");

  try {
    // 1) Ensure user exists (safe to call repeatedly)
    await postJSON("/api/signup", { phone });

    // 2) Start OTP (backend won’t reveal if user exists)
    const r = await postJSON("/api/otp/start", { phone });

    if (!r.ok && r.data?.error === "captcha") {
      setMsg("Please complete the challenge.", "error");
    } else if (r.ok && r.data?.status === "cooldown") {
      setMsg("Code already sent recently — try that SMS or wait a minute.", "success");
      showOtpStep(phone);
    } else if (r.ok) {
      setMsg("We texted you a 6-digit code.", "success");
      showOtpStep(phone);
    } else {
      setMsg("Couldn’t start verification. Try again.", "error");
    }
  } catch (err) {
    setMsg("Network error. Try again.", "error");
  } finally {
    disable(submitBtn, false);
  }
});
