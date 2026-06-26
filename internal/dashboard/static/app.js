// Overview page: navigate to report on row click
function openReport(tr) {
  var id = tr.getAttribute('data-pushid');
  if (id) { window.location = '/report?push_id=' + encodeURIComponent(id); return; }
  var ref = tr.getAttribute('data-ref');
  if (ref) { window.location = '/report?ref=' + encodeURIComponent(ref); }
}

(function () {
  // Overview filter toggles: reload page with query params
  var imgfilter = document.getElementById('imgfilter');
  var critOnly = document.getElementById('critOnly');
  var rejOnly = document.getElementById('rejOnly');

  if (imgfilter) {
    imgfilter.addEventListener('input', function () {
      applyFilters();
    });
  }
  if (critOnly) {
    critOnly.addEventListener('click', function () {
      critOnly.classList.toggle('on');
      applyFilters();
    });
  }
  if (rejOnly) {
    rejOnly.addEventListener('click', function () {
      rejOnly.classList.toggle('on');
      applyFilters();
    });
  }

  function applyFilters() {
    var params = new URLSearchParams(window.location.search);
    var q = imgfilter ? imgfilter.value : '';
    var crit = critOnly && critOnly.classList.contains('on');
    var rej = rejOnly && rejOnly.classList.contains('on');

    if (q) params.set('q', q);
    else params.delete('q');

    if (crit) params.set('crit', '1');
    else params.delete('crit');

    if (rej) params.set('rejected', '1');
    else params.delete('rejected');

    params.delete('page'); // reset to page 1
    window.location.search = params.toString();
  }

  // SSE live updates: prepend new rows to images table on page 1 with no filters
  var images = document.getElementById('images');
  if (images && window.EventSource) {
    var params = new URLSearchParams(window.location.search);
    var page = parseInt(params.get('page') || '1', 10);
    var hasFilters = params.get('q') || params.get('crit') || params.get('rejected');

    if (page === 1 && !hasFilters) {
      var es = new EventSource('/api/dashboard/stream');
      es.onmessage = function (e) {
        try {
          var d = JSON.parse(e.data);
          var tbody = images.querySelector('tbody');
          if (!tbody) return;

          // Remove empty state row if present
          var emptyRow = tbody.querySelector('td.empty');
          if (emptyRow) tbody.innerHTML = '';

          var tr = imageRow(d);
          tbody.insertBefore(tr, tbody.firstChild);

          // Cap at 10 rows
          while (tbody.children.length > 10) { tbody.removeChild(tbody.lastChild); }
        } catch (_) {}
      };
    }
  }

  // Build a new image row safely (no innerHTML for user-controlled data)
  // IMPORTANT: SSE payload lacks severity tallies, so show "–" until next page load
  function imageRow(d) {
    var tr = document.createElement('tr');
    tr.setAttribute('data-pushid', d.push_id || '');
    var ref = (d.repo || '') + (d.tag ? ':' + d.tag : '');
    tr.setAttribute('data-ref', ref);
    tr.setAttribute('onclick', 'openReport(this)');

    var img = document.createElement('td');
    img.className = 'img';
    img.textContent = ref; // textContent escapes HTML
    var who = document.createElement('div');
    who.className = 'who';
    who.textContent = d.identity || ''; // textContent escapes HTML
    img.appendChild(who);
    tr.appendChild(img);

    var v = document.createElement('td');
    var b = document.createElement('span');
    b.className = 'badge ' + (d.passed ? 'pass' : 'fail');
    b.textContent = d.passed ? 'PASS' : 'REJECT';
    v.appendChild(b);
    tr.appendChild(v);

    // Severity counts: show "–" (payload lacks tallies)
    for (var i = 0; i < 4; i++) {
      var c = document.createElement('td');
      c.textContent = '–';
      tr.appendChild(c);
    }

    var ts = document.createElement('td');
    ts.className = 'muted';
    ts.textContent = 'just now';
    tr.appendChild(ts);

    return tr;
  }

  // Findings filter: hide rows that don't match the query (report page only)
  var filter = document.getElementById('filter');
  var table = document.getElementById('findings');
  if (filter && table) {
    filter.addEventListener('input', function () {
      var q = filter.value.toLowerCase();
      var rows = table.querySelectorAll('tr');
      for (var i = 1; i < rows.length; i++) {
        var txt = rows[i].textContent.toLowerCase();
        rows[i].style.display = txt.indexOf(q) === -1 ? 'none' : '';
      }
    });
  }
})();
