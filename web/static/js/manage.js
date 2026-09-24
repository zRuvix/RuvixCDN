// manage.js — progressive enhancement for /dash/manage. Vanilla JS, no
// dependencies. Copy buttons, delete confirms and the mkdir form work as
// plain posts without JS; uploads need JS for the confirm + progress flow
// but degrade to the hidden form post.
(function () {
  "use strict";

  // Copy-URL buttons.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    var url = btn.getAttribute("data-copy");
    function done() {
      var old = btn.textContent;
      btn.textContent = "copied!";
      setTimeout(function () { btn.textContent = old; }, 1500);
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

  // Delete confirmations (native confirm is fine here).
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        ev.preventDefault();
      }
    });
  });

  // Upload flow: picker/drop -> confirm modal ("upload N file(s) to DIR?")
  // -> XHR with progress bar.
  var drop = document.getElementById("drop");
  var picker = document.getElementById("picker");
  var form = document.getElementById("upload");
  var filesInput = document.getElementById("uploadfiles");
  var bar = document.getElementById("bar");
  var modal = document.getElementById("confirm");
  var modalMsg = document.getElementById("confirmmsg");
  var yesBtn = document.getElementById("confirmyes");
  var noBtn = document.getElementById("confirmno");
  if (!drop || !picker || !form) return;

  var pending = null;
  var curDir = (document.getElementById("uploaddir") || {}).value || "";
  var dirLabel = curDir === "" ? "/" : curDir;

  function esc(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function askConfirm(files) {
    if (!window.FormData || !window.XMLHttpRequest) {
      // No XHR: stuff files into the classic form and post it.
      try {
        var dt = new DataTransfer();
        for (var i = 0; i < files.length; i++) dt.items.add(files[i]);
        filesInput.files = dt.files;
      } catch (e) { /* older browser: user can use browse instead */ }
      form.submit();
      return;
    }
    pending = files;
    var names = [];
    for (var j = 0; j < Math.min(files.length, 5); j++) names.push(esc(files[j].name));
    var more = files.length > 5 ? "<br>…and " + (files.length - 5) + " more" : "";
    modalMsg.innerHTML =
      "Upload <strong>" + files.length + " file" + (files.length === 1 ? "" : "s") +
      "</strong> to <span class=\"mono\">" + esc(dirLabel) + "</span>?<br>" +
      "<span class=\"mono\">" + names.join("<br>") + "</span>" + more;
    modal.hidden = false;
    yesBtn.focus();
  }

  picker.addEventListener("change", function () {
    if (picker.files.length) askConfirm(picker.files);
    picker.value = "";
  });

  ["dragenter", "dragover"].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      drop.classList.add("over");
    });
  });
  ["dragleave", "drop"].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      drop.classList.remove("over");
    });
  });
  drop.addEventListener("drop", function (e) {
    if (e.dataTransfer && e.dataTransfer.files.length) askConfirm(e.dataTransfer.files);
  });

  noBtn.addEventListener("click", function () {
    modal.hidden = true;
    pending = null;
  });
  modal.addEventListener("click", function (e) {
    if (e.target === modal) {
      modal.hidden = true;
      pending = null;
    }
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && !modal.hidden) {
      modal.hidden = true;
      pending = null;
    }
  });

  yesBtn.addEventListener("click", function () {
    if (!pending) return;
    var files = pending;
    pending = null;
    modal.hidden = true;
    sendFiles(files);
  });

  function sendFiles(files) {
    var fd = new FormData(form);
    fd.delete("file");
    for (var i = 0; i < files.length; i++) fd.append("file", files[i]);
    bar.hidden = false;
    bar.value = 0;
    var xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
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
      alert("upload failed (network)");
    });
    xhr.send(fd);
  }
})();
