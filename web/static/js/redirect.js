(function () {
  var m = document.querySelector('meta[name="redirect-url"]');
  if (m && m.content) window.location.replace(m.content);
})();
