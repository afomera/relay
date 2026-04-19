// Captures split view — selection state, live SSE tail, keyboard nav.
//
// Rendered on the tunnel detail page and on the single-capture page (both
// use the same split layout). Looks up the tunnel id from the wrapping
// `.captures-split[data-tunnel-id]` element, so this file has no template
// interpolation — serve it verbatim as a static asset.
(() => {
  const split = document.querySelector('.captures-split');
  if (!split) return;
  const tunnelId = split.dataset.tunnelId;
  const list = document.getElementById('captures-list');
  const detail = document.getElementById('detail-pane');
  const empty = document.getElementById('captures-empty');
  const noMatches = document.getElementById('captures-no-matches');
  const count = document.getElementById('captures-count');
  const filterInput = document.getElementById('captures-filter');
  if (!list || !detail) return;

  const durationShort = ms => ms == null ? '—' : (ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`);
  const escape = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const statusClass = s => {
    if (s == null) return 'none';
    if (s >= 500) return '5xx';
    if (s >= 400) return '4xx';
    if (s >= 300) return '3xx';
    if (s >= 200) return '2xx';
    if (s >= 100) return '1xx';
    return 'none';
  };

  // Filter state — compiled on every input change so SSE-appended rows can
  // be tested against it cheaply. Glob-style: `*` matches any chars, every
  // other regex metacharacter is escaped. Case-insensitive, substring match.
  let activeFilter = null;
  const compileFilter = (raw) => {
    const trimmed = (raw || '').trim();
    if (!trimmed) return null;
    const escaped = trimmed.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    try { return new RegExp(escaped, 'i'); } catch { return null; }
  };
  // Built from `${method} ${path} ${status}` so users can filter by any of
  // those (e.g. "POST", "posts/*", "500").
  const haystackFor = (row) => {
    const m = row.querySelector('.method');
    const p = row.querySelector('.path');
    const s = row.querySelector('.status');
    return `${m ? m.textContent : ''} ${p ? p.textContent : ''} ${s ? s.textContent : ''}`;
  };
  const rowMatches = (row) => !activeFilter || activeFilter.test(haystackFor(row));
  const applyFilter = () => {
    const rows = list.querySelectorAll('.capture-row');
    let visible = 0;
    rows.forEach(row => {
      const match = rowMatches(row);
      row.hidden = !match;
      if (match) visible += 1;
    });
    if (count) count.textContent = activeFilter ? `${visible}/${rows.length}` : String(rows.length);
    if (noMatches) noMatches.hidden = !(activeFilter && rows.length > 0 && visible === 0);
  };
  if (filterInput) {
    filterInput.addEventListener('input', () => {
      activeFilter = compileFilter(filterInput.value);
      applyFilter();
    });
  }

  // Mark the row whose capture id matches the current URL. Called on load
  // and after each HTMX swap so back/forward nav keeps the list in sync.
  const syncSelection = () => {
    const match = window.location.pathname.match(/\/tunnels\/[^/]+\/captures\/([^/]+)/);
    const selectedId = match ? match[1] : null;
    list.querySelectorAll('.capture-row').forEach(row => {
      row.classList.toggle('selected', row.dataset.captureId === selectedId);
    });
    if (selectedId) {
      const el = list.querySelector(`.capture-row[data-capture-id="${CSS.escape(selectedId)}"]`);
      if (el) el.scrollIntoView({ block: 'nearest' });
    }
  };

  // Re-highlight code blocks in the detail pane after HTMX swaps them in
  // (htmx sets innerHTML, which doesn't run <script> tags, so we drive
  // hljs ourselves).
  const rehighlight = () => {
    if (window.hljs) {
      detail.querySelectorAll('pre code').forEach(block => window.hljs.highlightElement(block));
    }
  };

  syncSelection();
  rehighlight();

  // Row builder for live SSE inserts — matches the server-rendered markup
  // so clicks, selection, and keyboard nav all work uniformly.
  const buildRow = (c) => {
    const row = document.createElement('a');
    row.className = 'capture-row';
    row.dataset.captureId = c.id;
    row.href = `/tunnels/${tunnelId}/captures/${c.id}`;
    row.setAttribute('hx-get', `/tunnels/${tunnelId}/captures/${c.id}/panel`);
    row.setAttribute('hx-target', '#detail-pane');
    row.setAttribute('hx-swap', 'innerHTML');
    row.setAttribute('hx-push-url', `/tunnels/${tunnelId}/captures/${c.id}`);
    row.innerHTML =
      `<span class="method method-${escape(c.method)}">${escape(c.method)}</span>` +
      `<span class="path mono truncate">${escape(c.path)}</span>` +
      `<span class="status status-${statusClass(c.status)}">${c.status ?? '—'}</span>` +
      `<span class="duration muted">${durationShort(c.duration_ms)}</span>`;
    return row;
  };

  // Live capture tail — prepend new rows as the CLI reports them. Process
  // the new element through htmx so its hx- attributes become live.
  const es = new EventSource(`/tunnels/${tunnelId}/events`);
  const lastSeenEl = document.getElementById('tunnel-last-seen');
  es.addEventListener('capture', e => {
    const c = JSON.parse(e.data);
    const row = buildRow(c);
    if (empty && !empty.hidden) empty.hidden = true;
    list.prepend(row);
    if (window.htmx) window.htmx.process(row);
    if (!rowMatches(row)) row.hidden = true;
    applyFilter();
    if (lastSeenEl) lastSeenEl.textContent = 'last seen just now';
  });

  // Keep selection + highlights in sync on HTMX nav and back/forward.
  document.body.addEventListener('htmx:afterSwap', (e) => {
    if (e.detail.target && e.detail.target.id === 'detail-pane') {
      syncSelection();
      rehighlight();
    }
  });
  window.addEventListener('popstate', () => {
    // When the user hits back/forward we re-fetch the panel for the URL
    // they landed on (if any) rather than leaving a stale detail visible.
    const match = window.location.pathname.match(/\/tunnels\/([^/]+)\/captures\/([^/]+)/);
    if (match && window.htmx) {
      window.htmx.ajax('GET', `/tunnels/${match[1]}/captures/${match[2]}/panel`, {
        target: '#detail-pane', swap: 'innerHTML',
      });
    } else {
      // Landed back on /tunnels/:id — clear selection + show placeholder.
      detail.innerHTML = '<div class="detail-empty"><p class="muted">Select a request on the left to inspect.</p></div>';
      syncSelection();
    }
  });

  // Keyboard nav: j/k or ↑/↓ moves selection within the list, Enter
  // activates. Typing into inputs is ignored.
  const activate = (row) => {
    if (!row) return;
    if (window.htmx) window.htmx.trigger(row, 'click');
    else row.click();
  };
  const move = (delta) => {
    // Only walk visible rows so j/k skips over anything hidden by the filter.
    const rows = Array.from(list.querySelectorAll('.capture-row')).filter(r => !r.hidden);
    if (rows.length === 0) return;
    const current = rows.findIndex(r => r.classList.contains('selected'));
    const next = Math.max(0, Math.min(rows.length - 1,
      current === -1 ? (delta > 0 ? 0 : rows.length - 1) : current + delta));
    activate(rows[next]);
  };
  document.addEventListener('keydown', (e) => {
    const tag = (e.target && e.target.tagName) || '';
    if (tag === 'INPUT' || tag === 'TEXTAREA' || e.target.isContentEditable) return;
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
  });
})();
