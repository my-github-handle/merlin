// Live feed: append new decisions pushed over SSE on the Activity page.
(function () {
  var feed = document.getElementById('feed');
  if (feed && window.EventSource) {
    var es = new EventSource('/api/dashboard/stream');
    es.onmessage = function (e) {
      try {
        var d = JSON.parse(e.data);
        var row = document.createElement('div');
        row.className = 'row ' + (d.passed ? 'pass' : 'fail');
        var ref = (d.repo || '') + (d.tag ? ':' + d.tag : '');

        // Build row with DOM APIs to prevent XSS from user-controlled fields
        var led = document.createElement('span');
        led.className = 'led';

        var refLink = document.createElement('a');
        refLink.className = 'ref';
        refLink.href = '/report?ref=' + encodeURIComponent(ref);
        refLink.textContent = ref;  // textContent escapes HTML

        var who = document.createElement('span');
        who.className = 'who';
        who.textContent = d.identity || '';  // textContent escapes HTML

        var badge = document.createElement('span');
        badge.className = 'badge';
        badge.textContent = d.passed ? 'PASS' : 'REJECT';  // boolean-derived, safe

        row.appendChild(led);
        row.appendChild(refLink);
        row.appendChild(who);
        row.appendChild(badge);

        feed.insertBefore(row, feed.firstChild);
        while (feed.children.length > 100) { feed.removeChild(feed.lastChild); }
      } catch (_) {}
    };
    // On error the browser auto-reconnects; nothing else to do.
  }

  // Findings filter: hide rows that don't match the query (client-side).
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
