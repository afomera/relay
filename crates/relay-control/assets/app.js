// Cross-cutting dashboard JS. Loaded on every page from base.html.
//
// Right now its only job is surfacing htmx response errors as a small
// toast so row-action failures (e.g. deleting an active tunnel → 409)
// don't silently do nothing.
(() => {
  const host = document.getElementById('toast-host');
  if (!host) return;

  const toast = (message) => {
    const el = document.createElement('div');
    el.className = 'toast';
    el.textContent = message;
    host.appendChild(el);
    setTimeout(() => {
      el.classList.add('leaving');
      setTimeout(() => el.remove(), 220);
    }, 4000);
  };

  document.body.addEventListener('htmx:responseError', (e) => {
    const xhr = e.detail && e.detail.xhr;
    const body = xhr && xhr.responseText ? xhr.responseText.trim() : '';
    const status = xhr ? xhr.status : 0;
    toast(body || `request failed (${status || 'network error'})`);
  });

  document.body.addEventListener('htmx:sendError', () => {
    toast('network error — could not reach the server');
  });
})();
