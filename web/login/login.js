const API_BASE = "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net";
const phoneForm = document.getElementById('phone-form');
const codeForm = document.getElementById('code-form');
const statusEl = document.getElementById('login-status');

phoneForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const phone = document.getElementById('phone').value.trim();
  const res = await fetch(`${API_BASE}/api/otp/start`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({phone})
  });
  const data = await res.json();
  if (data.status === 'sent' || data.status === 'cooldown') {
    statusEl.textContent = 'Code sent!';
    phoneForm.style.display = 'none';
    codeForm.style.display = 'grid';
  } else {
    statusEl.textContent = 'Failed to send code.';
  }
});

codeForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const phone = document.getElementById('phone').value.trim();
  const code = document.getElementById('code').value.trim();
  const res = await fetch(`${API_BASE}/api/otp/verify`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({phone, code})
  });
  const data = await res.json();
  if (data.ok && data.token) {
    localStorage.setItem('token', data.token);
    window.location.href = '../account/account.html';
  } else {
    statusEl.textContent = 'Invalid or expired code.';
  }
});
