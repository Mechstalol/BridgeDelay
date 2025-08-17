const API_BASE = "https://bridge-delay-app-d4cfc5ercda0gqbk.westus2-01.azurewebsites.net";
const token = localStorage.getItem('token');
if (!token) {
  window.location.href = '../login/login.html';
}

const statusEl = document.getElementById('settings-status');
const form = document.getElementById('settings-form');

async function loadSettings() {
  const res = await fetch(`${API_BASE}/api/user/settings`, {
    headers: { 'Authorization': 'Bearer ' + token }
  });
  if (res.ok) {
    const data = await res.json();
    document.getElementById('threshold').value = data.threshold;
    const winStr = (data.windows || []).map(w => `${w.start}-${w.end}`).join(',');
    document.getElementById('windows').value = winStr;
  } else if (res.status === 401) {
    localStorage.removeItem('token');
    window.location.href = '../login/login.html';
  }
}

loadSettings();

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const threshold = parseInt(document.getElementById('threshold').value, 10) || 0;
  const windows = document.getElementById('windows').value.trim();
  const res = await fetch(`${API_BASE}/api/user/settings`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({threshold, windows})
  });
  if (res.ok) {
    statusEl.textContent = 'Saved!';
  } else {
    const data = await res.json().catch(() => ({}));
    statusEl.textContent = data.error || 'Error saving settings.';
  }
});

document.getElementById('logout').addEventListener('click', (e) => {
  e.preventDefault();
  localStorage.removeItem('token');
  window.location.href = '../login/login.html';
});