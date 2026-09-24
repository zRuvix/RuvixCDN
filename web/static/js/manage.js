// manage.js — progressive enhancement for /dash/manage. Vanilla JS, no
// dependencies. Every action also works as a plain form post without JS.
(function () {
  "use strict";

  // Copy-URL buttons.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    var url = btn.getAttribute("data-copy");
    function done() {
      btn.textContent = "copied!";
      setTimeout(function () { btn.textContent = "copy url"; }, 1500);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(done, function () {
        fallbackCopy(url);
        done();
      });
    } else {
      fallbackCopy(url);
      done();
    }
  });

  function fallbackCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  // Delete confirmations.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        ev.preventDefault();
      }
    });
  });

  // AJAX upload with progress bar; falls back to a normal post on error.
  var upload = document.getElementById("upload");
  if (upload) {
    var bar = document.createElement("progress");
    bar.setAttribute("max", "100");
    bar.setAttribute("value", "0");
    bar.hidden = true;
    upload.appendChild(bar);

    upload.addEventListener("submit", function (ev) {
      if (!window.XMLHttpRequest || !window.FormData) return; // let it post
      ev.preventDefault();
      bar.hidden = false;
      var xhr = new XMLHttpRequest();
      xhr.open("POST", upload.action);
      xhr.setRequestHeader("Accept", "application/json");
      xhr.upload.addEventListener("progress", function (e) {
        if (e.lengthComputable) bar.value = (e.loaded / e.total) * 100;
      });
      xhr.addEventListener("load", function () {
        var msg = "upload failed";
        try {
          var res = JSON.parse(xhr.responseText);
          if (xhr.status < 300 && res.ok) {
            window.location.reload();
            return;
          }
          if (res.error) msg = res.error;
        } catch (e) { /* fall through */ }
        bar.hidden = true;
        alert(msg);
      });
      xhr.addEventListener("error", function () {
        bar.hidden = true;
        upload.submit(); // fall back to a plain post
      });
      xhr.send(new FormData(upload));
    });
  }
})();
