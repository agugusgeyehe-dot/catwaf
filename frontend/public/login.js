(function () {
  var form = document.getElementById('form');
  var btn = document.getElementById('btn');
  var errBox = document.getElementById('err');
  var title = document.getElementById('title');
  var fieldUser = document.getElementById('field-user');
  var fieldPass = document.getElementById('field-pass');
  var fieldTotp = document.getElementById('field-totp');
  var totpStage = false;

  function fail(msg) {
    errBox.textContent = msg;
    errBox.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Sign in';
  }

  function enterTotp() {
    totpStage = true;
    title.textContent = 'CatWAF Admin';
    fieldTotp.classList.remove('hidden');
    document.getElementById('totp').focus();
    errBox.style.display = 'none';
    btn.disabled = false;
    btn.textContent = 'Verify';
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    errBox.style.display = 'none';
    btn.disabled = true;
    btn.textContent = totpStage ? 'Verifying…' : 'Signing in…';

    var body = {
      username: document.getElementById('username').value,
      password: document.getElementById('password').value,
    };
    if (totpStage) body.totp = document.getElementById('totp').value.trim();

    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      var data = await res.json().catch(function () { return {}; });

      if (!res.ok) {
        if (data.code === 'TOTP_REQUIRED') return enterTotp();
        if (data.code === 'TOTP_INVALID') {
          document.getElementById('totp').value = '';
          return fail(data.detail || 'Invalid code.');
        }
        return fail(data.detail || 'Login failed (' + res.status + ').');
      }

      // Same storage keys the dashboard uses, so it picks up the session.
      try {
        localStorage.setItem('catwaf-token', data.token || '');
        if (data.sessionKey) localStorage.setItem('catwaf-session-key', data.sessionKey);
        else localStorage.removeItem('catwaf-session-key');
        if (data.api) localStorage.setItem('catwaf-gate', JSON.stringify(data.api));
        else localStorage.removeItem('catwaf-gate');
      } catch (_) {}

      window.location.href = '/';
    } catch (_) {
      fail('Cannot reach the server.');
    }
  });
})();
